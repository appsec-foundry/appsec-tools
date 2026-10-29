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
        raise HarvestError("Start pages exceed the link queue budget.")
    visited, requirements, anchors, contents = set(), {}, {}, {}
    report.update({"source-id": source["id"], "pages": [], "excluded-count": 0,
                   "excluded-sample": [], "depth-limited-count": 0, "requirements": 0, "status": "running"})
    while queue:
        budget.remaining()
        url, depth = queue.popleft()
        if url in visited:
            continue
        if len(visited) >= limits["max-pages"]:
            raise HarvestError("Page budget exhausted with pages still pending.")
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
            # The same page under another URL, such as with and without .html, adds no entries.
            fingerprint = tuple((r.rule_id, r.locator, r.original_id, r.title, r.statement,
                                 tuple(sorted(r.attributes.items()))) for r in rows)
            first = contents.setdefault(fingerprint, response.url) if rows else response.url
            if first != response.url:
                page_report.update({"url": display_url(response.url), "status": "duplicate-content",
                                    "duplicate-of": display_url(first)})
            else:
                for req in rows:
                    previous = requirements.get(req.id)
                    if previous:
                        if (previous.statement, previous.title, previous.attributes) != (req.statement, req.title, req.attributes):
                            raise HarvestError("Conflicting requirements with the same source identity.")
                        previous.references = sorted(set(previous.references + req.references + [req.url]) - {previous.url})
                    else:
                        requirements[req.id] = req
                    if len(requirements) > limits["max-items"]:
                        raise HarvestError("Source requirement limit exceeded.")
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
                        sample = display_url(dest)
                        if len(report["excluded-sample"]) < 100 and sample not in report["excluded-sample"]:
                            report["excluded-sample"].append(sample)
                    elif dest not in queued and dest not in visited:
                        links.add(dest)
            if limits["max-depth"] is not None and depth >= limits["max-depth"]:
                report["depth-limited-count"] += len(links)
            else:
                for dest in sorted(links):
                    if len(queued) >= limits["max-queue"]:
                        raise HarvestError("Link queue budget exhausted.")
                    queue.append((dest, depth + 1))
                    queued.add(dest)
        except HarvestError as error:
            page_report.update({"status": "failed", "error": str(error)})
            raise
    if not requirements:
        raise HarvestError("Source returned no requirements.")
    # Links outside the scope are kept in the catalog but are never fetched, so they cannot be resolved.
    report["unresolved-references"] = sorted({display_url(ref) for req in requirements.values()
        for ref in req.references if scope.allows(ref) and (canonical(ref) not in visited or
        (urlsplit(ref).fragment and unquote(urlsplit(ref).fragment) not in anchors.get(canonical(ref), set())))})[:100]
    report.update({"requirements": len(requirements), "status": "complete"})
    return list(requirements.values())
