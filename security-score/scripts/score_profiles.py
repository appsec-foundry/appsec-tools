"""Located service and artifact endpoints from selected configuration only."""

import json
from pathlib import PurePosixPath
import re
from urllib.parse import urlsplit, unquote
from xml.etree import ElementTree
from score_design import pairs


def endpoint_url(value):
    """Preserve useful literal paths; never return userinfo, query or fragments.

    Credential-bearing URLs retain only their origin, including their path: some
    services place credentials in both locations. Dynamic expressions stay unknown.
    """
    if not isinstance(value, str) or len(value) > 4000 or re.search(r"[\x00-\x20\x7f\\]|\$\{|\{\{", value):
        return None
    try:
        parsed = urlsplit(value)
        host, port = parsed.hostname, parsed.port
        if parsed.scheme not in {"http", "https"} or not host or not re.fullmatch(r"[A-Za-z0-9.:-]+", host):
            return None
        origin = f"{parsed.scheme}://" + (f"[{host}]" if ":" in host else host)
        if port is not None:
            origin += f":{port}"
        path = parsed.path
        if (parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment
            or re.search(r"[\x00-\x1f\x7f]|(?:token|password|secret|credential)[=/]", unquote(path), re.I)):
            path = ""
        return origin + path
    except ValueError:
        return None


def scalar_settings(text, properties=False):
    """A bounded YAML scalar/property subset; duplicate fields stay unresolved."""
    stack, values = [], {}
    for number, line in enumerate(text.splitlines(), 1):
        if properties:
            match = re.fullmatch(r"\s*([A-Za-z0-9_.-]+)\s*[=:]\s*(.*)", line)
            if not match or line.rstrip().endswith("\\"):
                continue
            key, value = match.groups()
        else:
            match = re.fullmatch(r"( *)([A-Za-z0-9_.-]+):(?:[ \t]+(.*))?", line)
            if not match:
                continue
            indent, key, value = len(match[1]), match[2], match[3]
            while stack and stack[-1][0] >= indent:
                stack.pop()
            if value is None or not value.strip() or value.lstrip().startswith("#"):
                stack.append((indent, key))
                continue
            key = ".".join([*(k for _, k in stack), key])
        value = re.split(r"\s+#", value, maxsplit=1)[0].strip()
        if value[:1] in {"'", '"'}:
            value = value[1:-1] if len(value) >= 2 and value[-1] == value[0] else None
        elif value.startswith(("&", "*", "!", "|", ">", "{", "[")):
            value = None
        values[key] = (None if key in values else value, number)
    return values


def artifact_repositories(files, budget):
    rows, seen = [], set()

    def add(value, path, number, ecosystem, evidence="configured"):
        url = endpoint_url(value)
        if url is None:
            return
        parsed = urlsplit(url)
        product = "Nexus-compatible" if re.search(r"/(?:repository/|nexus/content/|content/(?:repositories|groups)/)", parsed.path) else "Artifactory-compatible" if "/artifactory/" in parsed.path else "Custom / unrecognized repository"
        if evidence == "lockfile":
            match = re.match(r"(/(?:repository/[^/]+|(?:nexus/)?content/(?:repositories|groups)/[^/]+|artifactory/[^/]+))/?", parsed.path)
            url = f"{parsed.scheme}://{parsed.netloc}" + (match[1] + "/" if match else "")
        key = (path, url, ecosystem, evidence)
        if key not in seen:
            rows.append({"url": url, "technology": product, "ecosystem": ecosystem,
                         "file": path, "line": number, "evidence": evidence})
            seen.add(key)

    for path, source in sorted(files.items()):
        budget.check()
        name, text = PurePosixPath(path).name, source.get("text", "")
        if name in {"pom.xml", "settings.xml"}:
            if re.search(r"<!\s*(?:DOCTYPE|ENTITY)", text, re.I):
                continue
            try:
                tree = ElementTree.fromstring(text)
            except (ElementTree.ParseError, RecursionError):
                continue
            def local(tag):
                return tag.rsplit("}", 1)[-1]
            properties = {}
            for parent in tree.iter():
                if local(parent.tag) == "properties":
                    for child in parent:
                        key = local(child.tag)
                        properties[key] = None if key in properties else (child.text or "").strip()
            for node in tree.iter():
                if local(node.tag) not in {"repository", "pluginRepository", "mirror", "snapshotRepository"}:
                    continue
                urls = [child for child in node if local(child.tag) == "url"]
                for child in urls if len(urls) == 1 else []:
                    value = (child.text or "").strip()
                    raw = value
                    value = re.sub(r"\$\{([\w.-]+)\}", lambda m: properties.get(m[1]) or m[0], value)
                    number = text.count("\n", 0, text.find(raw)) + 1
                    add(value, path, number, "Maven")
        elif name in {"build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"}:
            from score_core import javascript_code

            try:
                code = javascript_code(text)
            except SyntaxError:
                continue
            stack, windows = [], []
            for token in re.finditer(r"[{}]", code):
                if token[0] == "{":
                    prefix = re.search(r"([A-Za-z_]\w*)\s*$", code[max(0, token.start() - 80):token.start()])
                    stack.append((prefix[1] if prefix else "", token.end()))
                elif stack:
                    label, start = stack.pop()
                    if label in {"maven", "ivy"} and any(parent == "repositories" for parent, _ in stack):
                        windows.append((start, token.start()))
            for start, end in windows:
                for match in re.finditer(r"\burl\s*(?:=\s*)?(?:uri\s*)?\(?\s*['\"]([^'\"\n]{1,4000})['\"]", text[start:end]):
                    position = start + match.start()
                    if code[position:position + 3] == "url":
                        add(match[1], path, text.count("\n", 0, position) + 1, "Gradle")
        elif name in {"package-lock.json", "npm-shrinkwrap.json"}:
            try:
                document = json.loads(text, object_pairs_hook=pairs)
            except (ValueError, RecursionError):
                continue
            pending = [document]
            while pending:
                budget.check()
                node = pending.pop()
                if isinstance(node, dict):
                    value = node.get("resolved")
                    if isinstance(value, str):
                        add(value, path, 1, "npm", "lockfile")
                    pending.extend(v for v in node.values() if isinstance(v, (dict, list)))
                elif isinstance(node, list):
                    pending.extend(v for v in node if isinstance(v, (dict, list)))
        elif name.startswith("requirements") and name.endswith(".txt"):
            for number, line in enumerate(text.splitlines(), 1):
                match = re.match(r"\s*(?:--index-url|--extra-index-url|-i)\s*[= ]\s*(\S+)", line)
                if match:
                    add(match[1], path, number, "Python")
        elif name == "pyproject.toml":
            section, urls = "", []
            def flush():
                if len(urls) == 1:
                    add(urls[0][1], path, urls[0][0], "Python")
            for number, line in enumerate(text.splitlines(), 1):
                match = re.match(r"\s*\[\[?([^\]]+)\]\]?", line)
                if match:
                    flush()
                    urls = []
                    section = match[1]
                if section not in {"tool.poetry.source", "tool.uv.index", "tool.pdm.source"}:
                    continue
                match = re.match(r"\s*url\s*=\s*['\"]([^'\"\n]+)['\"]", line)
                if match:
                    urls.append((number, match[1]))
            flush()
    return rows
