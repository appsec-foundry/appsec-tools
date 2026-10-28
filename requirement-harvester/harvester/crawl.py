from collections import deque
import time
from urllib.parse import unquote, urljoin, urlsplit

from .auth import headers_for
from .errors import HarvestError
from .extract import extract, parse_page
from .http import Budget, Transport
from .oscal import now
from .urls import Scope, canonical, display_url


def crawl_source(source, deadline, report, transport_factory=Transport):
    limits = source["limits"]
    budget = Budget(max(0, deadline - time.monotonic()), limits["max-requests"], limits["request-interval-seconds"])
    scope = Scope(source["crawl"])
    headers = headers_for(source, budget)
    transport = transport_factory(scope, limits, budget, source.get("ca-bundle"))
    queue = deque((url, 0) for url in sorted(source["start-urls"]))
    queued = set(source["start-urls"])
    if len(queued) > limits["max-queue"]:
        raise HarvestError("Startseiten überschreiten das Linkwarteschlangen-Budget.")
    visited, requirements, anchors = set(), {}, {}
    report.update({"source-id": source["id"], "pages": [], "excluded-count": 0,
                   "excluded-sample": [], "depth-limited-count": 0, "requirements": 0, "status": "running"})
    while queue:
        budget.remaining()
        url, depth = queue.popleft()
        if url in visited:
            continue
        if len(visited) >= limits["max-pages"]:
            raise HarvestError("Seitenbudget mit offenen Seiten ausgeschöpft.")
        page_report = {"url": display_url(url), "depth": depth, "status": "fetching"}
        report["pages"].append(page_report)
        try:
            response = transport.fetch(url, headers)
            if response.url in visited:
                page_report["status"] = "duplicate-redirect"
                continue
            visited.add(response.url)
            soup = parse_page(response.content, limits)
            anchors[response.url] = {str(n["id"]) for n in soup.find_all(id=True)}
            rows = extract(source, soup, response.url, now())
            for req in rows:
                previous = requirements.get(req.id)
                if previous:
                    if (previous.statement, previous.title, previous.attributes) != (req.statement, req.title, req.attributes):
                        raise HarvestError("Widersprüchliche Requirements mit gleicher Quellidentität.")
                    previous.references = sorted(set(previous.references + req.references + [req.url]) - {previous.url})
                else:
                    requirements[req.id] = req
                if len(requirements) > limits["max-items"]:
                    raise HarvestError("Quell-Requirement-Limit überschritten.")
            page_report.update({"url": display_url(response.url), "status": "extracted" if rows else "no-requirements", "requirements": len(rows)})
            links = set()
            if source["crawl"].get("mode", "linked-pages") != "explicit-pages":
                for link in soup.select("a[href]"):
                    raw = link.get("href", "")
                    if not raw or raw.startswith("#"):
                        continue
                    try:
                        dest = canonical(urljoin(response.url, raw))
                    except (HarvestError, ValueError):
                        report["excluded-count"] += 1
                        continue
                    if not scope.allows(dest):
                        report["excluded-count"] += 1
                        if len(report["excluded-sample"]) < 100:
                            report["excluded-sample"].append(display_url(dest))
                    elif dest not in queued and dest not in visited:
                        links.add(dest)
            if limits["max-depth"] is not None and depth >= limits["max-depth"]:
                report["depth-limited-count"] += len(links)
            else:
                for dest in sorted(links):
                    if len(queued) >= limits["max-queue"]:
                        raise HarvestError("Linkwarteschlangen-Budget ausgeschöpft.")
                    queue.append((dest, depth + 1))
                    queued.add(dest)
        except HarvestError as error:
            page_report.update({"status": "failed", "error": str(error)})
            raise
    if not requirements:
        raise HarvestError("Quelle liefert keine Requirements.")
    report["unresolved-references"] = sorted({display_url(ref) for req in requirements.values()
        for ref in req.references if canonical(ref) not in visited or
        (urlsplit(ref).fragment and unquote(urlsplit(ref).fragment) not in anchors.get(canonical(ref), set()))})[:100]
    report.update({"requirements": len(requirements), "status": "complete"})
    return list(requirements.values())
