"""Read selected GitHub/GitLab HTTPS sources and host settings without executing Git."""

from __future__ import annotations

import fnmatch
from functools import lru_cache
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import threading
from urllib.parse import quote, urlsplit

from score_core import RULES
from score_sources import SourceError
from score_remote_sources import select_files


HOSTS = {
    "api.github.com",
    "raw.githubusercontent.com",
    "gitlab.com",
}
MAX_DOWNLOAD = 24 * 1024 * 1024


@lru_cache(maxsize=1)
def tls_context():
    return ssl.create_default_context()


def repository_url(value):
    if any(ord(char) < 33 or ord(char) > 126 for char in value):
        raise SourceError(
            "Repository URLs must not contain control characters or whitespace."
        )
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or parsed.netloc not in {"github.com", "gitlab.com"}
        or parsed.query
        or parsed.fragment
    ):
        raise SourceError(
            "Use a canonical HTTPS GitHub/GitLab repository URL without credentials, query, or fragment."
        )
    path = parsed.path.rstrip("/")
    path = path[:-4] if path.endswith(".git") else path
    parts = path[1:].split("/")
    if (
        len(parts) < 2
        or (parsed.netloc == "github.com" and len(parts) != 2)
        or any(
            not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", part)
            or part in {".", ".."}
            for part in parts
        )
    ):
        raise SourceError("Unsupported repository URL path.")
    return parsed.netloc, "/".join(parts)


def public_addresses(host, budget):
    complete = threading.Event()
    result = []

    def lookup():
        try:
            result.extend(socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM))
        except OSError:
            pass
        finally:
            complete.set()

    threading.Thread(target=lookup, daemon=True).start()
    if not complete.wait(timeout=budget.remaining()) or not result:
        raise SourceError(
            "Cannot resolve the selected public Git host within the time limit."
        )
    if any(not ipaddress.ip_address(row[4][0]).is_global for row in result):
        raise SourceError("Git host resolved to a non-public network destination.")
    return result


def get(
    url,
    budget,
    *,
    token=None,
    token_host=None,
    limit=MAX_DOWNLOAD,
    accept="application/json",
    connections=None,
):
    """Pin the checked IP at connect time, keep TLS host verification, and bound reads."""
    parsed = urlsplit(url)
    host = parsed.hostname
    if (
        parsed.scheme != "https"
        or host not in HOSTS
        or parsed.netloc != host
        or parsed.fragment
    ):
        raise SourceError("Rejected repository metadata or source destination.")
    connection = connections.get(host) if connections is not None else None
    raw_socket, reusable = None, False
    try:
        if connection is None or connection.sock is None:
            addresses = public_addresses(host, budget)
            address = addresses[0]
            connection = http.client.HTTPSConnection(
                host, timeout=min(5, budget.remaining()), context=tls_context()
            )
            raw_socket = socket.socket(address[0], socket.SOCK_STREAM)
            raw_socket.settimeout(min(5, budget.remaining()))
            raw_socket.connect(address[4])
            connection.sock = connection._context.wrap_socket(
                raw_socket, server_hostname=host
            )
        connection.sock.settimeout(min(5, budget.remaining()))
        headers = {
            "User-Agent": "appsec-skills-security-score/1",
            "Accept": accept,
            "Accept-Encoding": "identity",
        }
        if token and host == token_host:
            if host == "gitlab.com":
                headers["PRIVATE-TOKEN"] = token
            else:
                headers["Authorization"] = "Bearer " + token
        path = parsed.path + ("?" + parsed.query if parsed.query else "")
        connection.request("GET", path, headers=headers)
        response = connection.getresponse()
        if response.status in {301, 302, 303, 307, 308}:
            raise SourceError(
                "Repository metadata or source redirected; redirects are not followed and no score is available."
            )
        if response.status != 200:
            return None, response.status
        length = response.getheader("Content-Length")
        if length and (not length.isdigit() or int(length) > limit):
            raise SourceError(
                f"Remote response exceeds the {limit:,}-byte download limit; no score is available."
            )
        data = bytearray()
        while True:
            budget.check()
            if connection.sock:
                connection.sock.settimeout(min(5, budget.remaining()))
            chunk = response.read(16384)
            if not chunk:
                break
            if len(data) + len(chunk) > limit:
                raise SourceError(
                    f"Remote response exceeds the {limit:,}-byte download limit; no score is available."
                )
            data.extend(chunk)
        reusable = connections is not None and connection.sock is not None
        if reusable:
            connections[host] = connection
        return bytes(data), 200
    except (OSError, http.client.HTTPException, ssl.SSLError):
        budget.check()
        return None, 0
    finally:
        if not reusable:
            if connection is not None:
                connection.close()
            if connections is not None:
                connections.pop(host, None)
        if raw_socket is not None:
            raw_socket.close()


class SourceReader:
    """Reuse each worker's checked TLS connections for one bounded selection."""

    def __init__(self, budget, token, token_host):
        self.budget, self.token, self.token_host = budget, token, token_host
        self.local = threading.local()
        self.caches = []
        self.lock = threading.Lock()

    def __call__(self, url, *, limit, accept="application/json"):
        if not hasattr(self.local, "connections"):
            self.local.connections = {}
            with self.lock:
                self.caches.append(self.local.connections)
        data, status = get(
            url,
            self.budget,
            token=self.token,
            token_host=self.token_host,
            limit=limit,
            accept=accept,
            connections=self.local.connections,
        )
        if data is None:
            raise source_error(status, "Repository file listing or selected source")
        return data

    def close(self):
        for cache in self.caches:
            for connection in cache.values():
                connection.close()


def source_error(status, subject):
    if status == 404:
        reason = "not found or not accessible (HTTP 404); check the repository URL and access token"
    elif status == 401:
        reason = "authentication failed (HTTP 401); check the selected token"
    elif status in {403, 429}:
        reason = f"access denied or API rate limit reached (HTTP {status}); check token permissions or retry later"
    elif not status:
        reason = "connection failed; check network access and retry"
    else:
        reason = f"host returned HTTP {status}; retry later or check host availability"
    return SourceError(f"{subject}: {reason}. No score is available.")


def json_get(url, budget, token, token_host, expected=dict, *, required=False):
    data, status = get(url, budget, token=token, token_host=token_host)
    if data is None:
        if required:
            raise source_error(status, "Repository source")
        return (
            {},
            f"not readable (HTTP {status})" if status else "connection unavailable",
        )
    try:
        document = json.loads(data)
        if not isinstance(document, expected):
            if required:
                raise SourceError(
                    "Repository source metadata has an invalid API response; no score is available."
                )
            return {}, "invalid API response"
        return document, None
    except (ValueError, UnicodeError):
        if required:
            raise SourceError(
                "Repository source metadata has an invalid API response; no score is available."
            ) from None
        return {}, "invalid API response"


def setting(name, value=None, reason=None):
    return {
        "setting": name,
        "status": "set"
        if value is True
        else "not_set"
        if value is False
        else "unknown",
        "reason": reason
        or (
            "Observed through the repository host API."
            if type(value) is bool
            else "Not exposed by the available API response or permissions."
        ),
    }


def gitlab_reviews(api, branch, protected, budget, token):
    if not token or not isinstance(branch, str) or not branch:
        return None, "Approval policies require authenticated project-rule evidence."
    rules, error = json_get(
        api + "/approval_rules?per_page=100", budget, token, "gitlab.com", expected=list
    )
    for rule in rules if isinstance(rules, list) else []:
        if (
            not isinstance(rule, dict)
            or type(rule.get("approvals_required")) is not int
            or rule["approvals_required"] <= 0
        ):
            continue
        scoped = rule.get("protected_branches", [])
        applies = (
            protected is True and rule.get("applies_to_all_protected_branches") is True
        )
        if isinstance(scoped, list):
            applies = applies or any(
                isinstance(entry, dict)
                and isinstance(entry.get("name"), str)
                and len(entry["name"]) <= 256
                and fnmatch.fnmatchcase(branch, entry["name"])
                for entry in scoped
            )
        if applies:
            return True, None
    return (
        None,
        error
        or "No applicable positive review rule established; inherited, other-branch or further paginated rules remain unverified.",
    )


def host_settings(host, project, budget, token=None, *, require_source=False):
    """Read only named fields; missing fields and 401/403/404 remain unknown."""
    if host == "github.com":
        api = "https://api.github.com/repos/" + project
        document, error = json_get(
            api, budget, token, "api.github.com", required=require_source
        )
        branch = document.get("default_branch")
        branch_doc, branch_error = (
            json_get(
                api + "/branches/" + quote(branch, safe=""),
                budget,
                token,
                "api.github.com",
                required=require_source,
            )
            if isinstance(branch, str) and branch
            else ({}, error)
        )
        protected = branch_doc.get("protected")
        protection, protection_error = (
            json_get(
                api + "/branches/" + quote(branch, safe="") + "/protection",
                budget,
                token,
                "api.github.com",
            )
            if protected is True
            else ({}, branch_error)
        )
        reviews = protection.get("required_pull_request_reviews")
        required_reviews = (
            reviews.get("required_approving_review_count")
            if isinstance(reviews, dict)
            else None
        )
        review_value = (
            required_reviews > 0
            if type(required_reviews) is int
            else False
            if protected is False
            or ("required_pull_request_reviews" in protection and reviews is None)
            else None
        )
        analysis = document.get("security_and_analysis") or {}
        if not isinstance(analysis, dict):
            analysis = {}
        settings = [
            setting("default_branch_protection", protected, branch_error),
            setting("required_reviews", review_value, protection_error),
        ]
        for field in ("secret_scanning", "dependabot_security_updates"):
            entry = analysis.get(field)
            status = entry.get("status") if isinstance(entry, dict) else None
            settings.append(
                setting(
                    field,
                    status == "enabled" if status in {"enabled", "disabled"} else None,
                    error,
                )
            )
        revision = (
            branch_doc.get("commit", {}).get("sha")
            if isinstance(branch_doc.get("commit"), dict)
            else None
        )

    else:
        api = "https://gitlab.com/api/v4/projects/" + quote(project, safe="")
        document, error = json_get(
            api, budget, token, "gitlab.com", required=require_source
        )
        branch = document.get("default_branch")
        branch_doc, branch_error = (
            json_get(
                api + "/repository/branches/" + quote(branch, safe=""),
                budget,
                token,
                "gitlab.com",
                required=require_source,
            )
            if isinstance(branch, str) and branch
            else ({}, error)
        )
        reviews, review_error = gitlab_reviews(
            api, branch, branch_doc.get("protected"), budget, token
        )
        settings = [
            setting(
                "default_branch_protection", branch_doc.get("protected"), branch_error
            ),
            setting(
                "required_reviews",
                reviews,
                review_error,
            ),
            setting(
                "successful_pipeline_before_merge",
                document.get("only_allow_merge_if_pipeline_succeeds"),
                error,
            ),
            setting(
                "security_scanning",
                None,
                "Scanner execution cannot be established by a feature-availability flag.",
            ),
        ]
        revision = (
            branch_doc.get("commit", {}).get("id")
            if isinstance(branch_doc.get("commit"), dict)
            else None
        )

    return settings, revision


def read_token(name):
    token = None
    if name:
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            raise SourceError("Invalid token environment variable name.")
        token = os.environ.get(name)
        if not token or any(ord(c) < 33 or ord(c) > 126 for c in token):
            raise SourceError(
                "The selected token environment variable is missing or invalid."
            )
    return token


def select_remote(options, budget):
    host, project = repository_url(options.repo)
    if any(
        (
            options.patch,
            options.base,
            options.head,
            options.commit,
            options.staged,
            options.unstaged,
            options.worktree,
            options.pr,
            options.mr,
        )
    ):
        raise SourceError(
            "Use a local checkout for Git comparisons, or supply the selected PR/MR patch separately."
        )
    token = read_token(options.token_env)
    settings, revision = host_settings(
        host, project, budget, token, require_source=True
    )
    if revision is None:
        raise SourceError(
            "Repository has no readable default-branch commit (empty repository or inaccessible branch); no score is available."
        )
    token_host = "api.github.com" if host == "github.com" else "gitlab.com"

    read = SourceReader(budget, token, token_host)
    try:
        files, exclusions = select_files(
            host, project, revision, budget, read, authenticated=token is not None
        )
    finally:
        read.close()
    scope = {
        "kind": "repository",
        "selection": "git-url",
        "repository": "https://" + host + "/" + project,
        "revision": revision,
    }
    return {}, files, exclusions, scope, None, settings


def settings_checks(settings):
    checks, findings = [], []
    definitions = {rule["setting"]: rule for rule in RULES if rule["kind"] == "host"}
    for row in settings:
        definition = definitions[row["setting"]]
        rule = definition["id"]
        status = {"set": "satisfied", "not_set": "violated", "unknown": "unclear"}[
            row["status"]
        ]
        checks.append(
            {
                "rule": rule,
                "area": "repository-host",
                "file": "repository-host",
                "status": status,
            }
        )
        if status == "violated":
            findings.append(
                {
                    "rule": rule,
                    "area": "repository-host",
                    "severity": definition["severity"],
                    "title": definition["title"],
                    "file": "repository-host",
                    "line": 0,
                    "evidence": row["reason"],
                    "next_action": definition["next_action"],
                }
            )
    return findings, checks
