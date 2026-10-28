import copy
from dataclasses import dataclass, field
import hashlib
import html
import re
from urllib.parse import quote, urljoin, urlsplit

from bs4 import BeautifulSoup, NavigableString, Tag

from .errors import AuthError, HarvestError
from .urls import canonical


def text_content(node):
    return " ".join(node.stripped_strings)


def markdown(node):
    """Preserve paragraph/list/table/code structure; never preserve active HTML."""
    if isinstance(node, NavigableString):
        value = html.escape(re.sub(r"\s+", " ", str(node)), quote=False)
        return re.sub(r"([\\`*_\[\]])", r"\\\1", value)
    if not isinstance(node, Tag) or node.name in {"script", "style", "iframe", "object", "form", "svg"}:
        return ""
    if node.name == "pre":
        raw = node.get_text()
        fence = "`" * max(3, max((len(s) + 1 for s in re.findall(r"`+", raw)), default=3))
        return f"\n\n{fence}\n{raw.rstrip()}\n{fence}\n\n"
    if node.name == "code":
        raw = node.get_text()
        fence = "`" * max(1, max((len(s) + 1 for s in re.findall(r"`+", raw)), default=1))
        return f"{fence} {raw} {fence}"
    if node.name in {"ul", "ol"}:
        lines = []
        for index, child in enumerate(node.find_all("li", recursive=False), 1):
            body = "".join(markdown(c) for c in child.children).strip()
            marker = f"{index}. " if node.name == "ol" else "- "
            lines.append(marker + body.replace("\n", "\n" + " " * len(marker)))
        return "\n\n" + "\n".join(lines) + "\n\n"
    if node.name == "table":
        rows = []
        for row in node.find_all("tr"):
            cells = ["".join(markdown(c) for c in cell.children).strip().replace("|", "\\|").replace("\n", "<br>")
                     for cell in row.find_all(["th", "td"], recursive=False)]
            if cells:
                rows.append(cells)
        if not rows:
            return ""
        width = max(map(len, rows))
        rows = [r + [""] * (width - len(r)) for r in rows]
        formatted = ["| " + " | ".join(r) + " |" for r in rows]
        formatted.insert(1, "| " + " | ".join(["---"] * width) + " |")
        return "\n\n" + "\n".join(formatted) + "\n\n"
    if node.name == "tr":
        table = node.find_parent("table")
        headings = table.select("thead th") if table else []
        cells = node.find_all(["th", "td"], recursive=False)
        return "\n\n".join((text_content(headings[i]) + ": " if i < len(headings) else "")
                              + prose(cell) for i, cell in enumerate(cells))
    body = "".join(markdown(child) for child in node.children)
    if node.name == "br":
        return "\n"
    if re.fullmatch(r"h[1-6]", node.name):
        return "\n\n" + "#" * int(node.name[1]) + " " + body.strip() + "\n\n"
    if node.name in {"p", "div", "section", "blockquote", "dl", "dt", "dd"}:
        return "\n\n" + body.strip() + "\n\n"
    if node.name in {"th", "td"}:
        return body.strip() + "\n\n"
    return body


def prose(node):
    return re.sub(r"\n[ \t]*\n(?:[ \t]*\n)+", "\n\n", markdown(node)).strip()


@dataclass
class Requirement:
    id: str
    source_id: str
    title: str
    statement: str
    url: str
    locator: str
    rule_id: str
    original_id: str = ""
    attributes: dict = field(default_factory=dict)
    references: list = field(default_factory=list)
    fetched_at: str = ""


def field_value(spec, item, page, rich=True):
    if "value" in spec:
        return spec["value"]
    root = page if spec.get("scope", "item") == "page" else item
    nodes = root.select(spec["selector"]) if "selector" in spec else [root]
    if not nodes:
        return ""
    if len(nodes) != 1 and not spec.get("many", False):
        raise HarvestError("Feldselektor ist mehrdeutig; many explizit setzen.")
    values = []
    for node in nodes:
        value = str(node.get(spec["attribute"], "")) if "attribute" in spec else (prose(node) if rich else text_content(node))
        values.append(value)
    return "\n\n".join(values).strip()


def section_for(heading):
    if not re.fullmatch(r"h[1-6]", heading.name):
        raise HarvestError("sections-Regeln müssen Überschriften auswählen.")
    result = BeautifulSoup("<section></section>", "html.parser").section
    if heading.get("id"):
        result["id"] = heading["id"]
    result.append(copy.copy(heading))
    level = int(heading.name[1])
    for sibling in heading.next_siblings:
        if isinstance(sibling, Tag) and re.fullmatch(r"h[1-6]", sibling.name) and int(sibling.name[1]) <= level:
            break
        result.append(copy.copy(sibling))
    return result


def parse_page(content, limits):
    try:
        soup = BeautifulSoup(content, "html.parser")
    except Exception:
        raise HarvestError("HTML konnte nicht verarbeitet werden.") from None
    stack = [(soup, 0)]
    count = 0
    while stack:
        node, depth = stack.pop()
        count += 1
        if count > limits["max-nodes"] or depth > 150:
            raise HarvestError("HTML-Struktur überschreitet Parser-Limits.")
        if isinstance(node, Tag):
            stack.extend((c, depth + 1) for c in node.children)
    if soup.select_one('input[type="password"]'):
        raise AuthError("Anmeldeseite statt Quellinhalt empfangen.")
    for node in soup.select("script, style, iframe, object, svg, template"):
        node.decompose()
    return soup


def extract(source, soup, page_url, fetched_at):
    config = source["extraction"]
    roots = soup.select(config["content-selector"])
    if len(roots) != 1:
        raise HarvestError("Hauptinhalt fehlt oder ist mehrdeutig; Layout prüfen.")
    root = roots[0]
    for selector in config.get("exclude-selectors", []):
        for node in list(root.select(selector)):
            node.decompose()
    context = "\n\n".join(prose(n) for n in root.select(config["context-selector"])) if config.get("context-selector") else ""
    page_title = soup.find("h1") or soup.find("title")
    title_default = text_content(page_title) if page_title else source["title"]
    results, seen_nodes = [], set()
    for rule in config["rules"]:
        if rule.get("page-selector") and not soup.select_one(rule["page-selector"]):
            continue
        items = root.select(rule["item-selector"])
        if not items and rule.get("required", True):
            raise HarvestError(f"Extraktionsregel {rule['id']} hat keinen Treffer.")
        for index, original in enumerate(items):
            if id(original) in seen_nodes:
                raise HarvestError("Mehrere Regeln erfassen denselben Inhaltsblock.")
            seen_nodes.add(id(original))
            if rule["strategy"] == "table-rows" and original.name != "tr":
                raise HarvestError("table-rows muss Tabellenzeilen auswählen.")
            item = section_for(original) if rule["strategy"] == "sections" else original
            values = {name: field_value(spec, item, soup, rich=name not in {"original-id", "title", "obligation", "category", "revision"})
                      for name, spec in rule["fields"].items()}
            for scalar in ("original-id", "title", "obligation", "category", "revision"):
                if scalar in values:
                    values[scalar] = " ".join(values[scalar].split())
            statement = values.pop("statement")
            if not statement:
                raise HarvestError(f"Leere Aussage in Regel {rule['id']}.")
            if context:
                values["context"] = "\n\n".join(dict.fromkeys(filter(None, (context, values.get("context", "")))))
            original_id = values.pop("original-id", "")
            anchor = original.get("id", "")
            locator = "#" + str(anchor) if anchor else f"{rule['id']}[{index + 1}]"
            # No positional identity: insertions do not renumber unlabelled requirements.
            identity = "id:" + original_id if original_id else canonical(page_url) + "|" + ("anchor:" + anchor if anchor else "text:" + statement)
            digest = hashlib.sha256((source["id"] + "|" + identity).encode()).hexdigest()[:24]
            requirement_id = source["id"] + "-" + digest
            title = " ".join(values.pop("title", "").split()) or (original_id or title_default)
            refs = []
            for link in item.select("a[href]"):
                try:
                    href = urljoin(page_url, link["href"])
                    clean = canonical(href)
                    if urlsplit(href).query:
                        continue  # Do not copy arbitrary remote query values into artifacts.
                    fragment = urlsplit(href).fragment
                    refs.append(clean + ("#" + quote(fragment, safe="-._~") if fragment else ""))
                except (HarvestError, ValueError):
                    continue
            results.append(Requirement(requirement_id, source["id"], title, statement,
                page_url + ("#" + quote(anchor, safe="-._~") if anchor else ""), locator, rule["id"],
                original_id, {k: v for k, v in values.items() if v}, sorted(set(refs)), fetched_at))
            if len(results) > source["limits"]["max-items"]:
                raise HarvestError("Requirement-Limit überschritten.")
    if not results and not config.get("allow-empty-pages", False):
        raise HarvestError("Seite enthält keine erkannten Requirements; Layout prüfen.")
    return results
