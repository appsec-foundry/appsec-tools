"""Read selected GitHub/GitLab HTTPS sources and host settings without executing Git."""

from __future__ import annotations

import fnmatch
from functools import lru_cache
import http.client
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import socket
import ssl
import threading
import time
from urllib.parse import quote, urlsplit

from score_core import RULES
from score_sources import RemoteError, SourceError
from score_remote_sources import select_files


HOSTS = {
    "api.github.com",
    "raw.githubusercontent.com",
    "gitlab.com",
}
MAX_DOWNLOAD = 24 * 1024 * 1024
MAX_TOKEN_CONFIG = 64 * 1024
PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        "100.64.0.0/10", "fc00::/7",
    )
)
# Alibaba ECS metadata is inside RFC 6598 shared address space.
METADATA_ADDRESSES = {ipaddress.ip_address("100.100.100.200")}


class NetworkStats:
    """Per-scan counters shared by metadata requests and source workers."""

    def __init__(self):
        self.hosts = {}
        self.lock = threading.Lock()

    def record(self, host, body_bytes):
        with self.lock:
            row = self.hosts.setdefault(host, {"requests": 0, "response_body_bytes": 0})
            row["requests"] += 1
            row["response_body_bytes"] += body_bytes

    def snapshot(self):
        with self.lock:
            hosts = [{"host": host, **row} for host, row in sorted(self.hosts.items())]
        return {
            "requests": sum(row["requests"] for row in hosts),
            "response_body_bytes": sum(row["response_body_bytes"] for row in hosts),
            "hosts": hosts,
            "measurement": (
                "HTTP GET attempts and response body bytes read, including discarded "
                "partial or oversized reads. Excludes unread bodies, HTTP headers, "
                "uploads, DNS and TLS/TCP overhead."
            ),
        }


@lru_cache(maxsize=1)
def tls_context():
    return ssl.create_default_context()


def gitlab_destination(authority):
    """Parse the exact HTTPS authority selected by an operator's repository URL."""
    try:
        parsed = urlsplit("https://" + authority)
        host, port = parsed.hostname, parsed.port or 443
    except ValueError:
        raise SourceError("Invalid GitLab host or port.") from None
    if (
        not host
        or "%" in host
        or any(ord(char) < 33 or ord(char) > 126 for char in authority)
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or not 1 <= port <= 65535
    ):
        raise SourceError("Invalid GitLab host or port.")
    try:
        address = ipaddress.ip_address(host)
        name = f"[{host}]" if address.version == 6 else host
    except ValueError:
        if not re.fullmatch(
            r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
            r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", host
        ):
            raise SourceError("Invalid GitLab host or port.") from None
        name = host
    if authority not in {name, f"{name}:{port}"}:
        raise SourceError("Use a canonical GitLab host and port.")
    return host, port


def repository_url(value):
    if any(ord(char) < 33 or ord(char) > 126 for char in value):
        raise SourceError(
            "Repository URLs must not contain control characters or whitespace."
        )
    try:
        parsed = urlsplit(value)
    except ValueError:
        raise SourceError("Invalid HTTPS repository URL.") from None
    if (
        parsed.scheme != "https"
        or parsed.query
        or parsed.fragment
    ):
        raise SourceError(
            "Use a canonical HTTPS GitHub/GitLab repository URL without credentials, query, or fragment."
        )
    host, _ = gitlab_destination(parsed.netloc)
    if host in {"github.com", "gitlab.com"} and parsed.netloc != host:
        raise SourceError("Use the canonical GitHub.com or GitLab.com HTTPS URL.")
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


def public_addresses(host, budget, *, port=443, allow_private=False):
    complete = threading.Event()
    result = []

    def lookup():
        try:
            result.extend(socket.getaddrinfo(host, port, type=socket.SOCK_STREAM))
        except OSError:
            pass
        finally:
            complete.set()

    threading.Thread(target=lookup, daemon=True).start()
    if not complete.wait(timeout=min(5, budget.remaining())) or not result:
        budget.check()
        raise SourceError(
            "Cannot resolve the selected Git host within the time limit."
        )
    for row in result:
        address = ipaddress.ip_address(row[4][0])
        address = getattr(address, "ipv4_mapped", None) or address
        private = allow_private and any(
            address in network for network in PRIVATE_NETWORKS
        )
        if (
            address in METADATA_ADDRESSES
            or address.is_multicast
            or not (address.is_global or private)
        ):
            raise SourceError("Git host resolved to a disallowed network destination.")
    return result


def interrupt_socket(sock, expired=None):
    """Interrupt header/body reads even when a peer keeps trickling bytes."""
    if expired is not None:
        expired.set()
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass


class RateLimited(RemoteError):
    pass


def header_number(headers, name):
    """Header values come from the network: accept short plain decimals only."""
    value = headers(name)
    if value and len(value) <= 16 and value.isascii() and value.isdecimal():
        return int(value)
    return None


def rate_limited(status, headers):
    remaining = headers("X-RateLimit-Remaining") or headers("RateLimit-Remaining")
    return status == 429 or (
        status == 403 and (remaining == "0" or headers("Retry-After") is not None)
    )


def rate_limit_error(host, status, headers, authenticated):
    delay = header_number(headers, "Retry-After")
    reset = header_number(headers, "X-RateLimit-Reset") or header_number(
        headers, "RateLimit-Reset"
    )
    if delay is None and reset is not None:
        delay = reset - time.time()
    if delay is None:
        wait = "Retry later"
    else:
        minutes = max(1, math.ceil(delay / 60))
        wait = f"Retry in about {minutes} minute{'' if minutes == 1 else 's'}"
    advice = (
        ""
        if authenticated
        else ", or pass a read-only token with --token-env NAME for a higher limit"
    )
    name = (
        "GitHub"
        if host in {"api.github.com", "raw.githubusercontent.com"}
        else "GitLab"
    )
    return RateLimited(
        f"{name} API rate limit reached (HTTP {status}). {wait}{advice}. "
        "No score is available.",
        status,
    )


def get(
    url,
    budget,
    *,
    token=None,
    token_host=None,
    limit=MAX_DOWNLOAD,
    accept="application/json",
    connections=None,
    gitlab_host=None,
):
    """Pin the checked IP at connect time, keep TLS host verification, and bound reads."""
    parsed = urlsplit(url)
    host = parsed.hostname
    selected_gitlab = gitlab_host is not None and parsed.netloc == gitlab_host
    if (
        parsed.scheme != "https"
        or (gitlab_host is not None and not selected_gitlab)
        or not (selected_gitlab or (host in HOSTS and parsed.netloc == host))
        or parsed.fragment
        or any(ord(char) < 33 or ord(char) > 126 for char in url)
    ):
        raise SourceError("Rejected repository metadata or source destination.")
    if selected_gitlab:
        host, port = gitlab_destination(gitlab_host)
        if not parsed.path.startswith("/api/v4/projects/"):
            raise SourceError("Rejected GitLab API destination.")
    else:
        port = 443
    authority = parsed.netloc
    connection = connections.get(authority) if connections is not None else None
    raw_socket, reusable, deadline = None, False, None
    attempted, body_bytes = False, 0
    expired = threading.Event()
    try:
        if connection is None or connection.sock is None:
            addresses = (
                public_addresses(host, budget, port=port, allow_private=True)
                if selected_gitlab
                else public_addresses(host, budget)
            )
            if connection is not None:
                connection.close()
            for address in addresses:
                connection = http.client.HTTPSConnection(
                    host,
                    port=port,
                    timeout=min(5, budget.remaining()),
                    context=tls_context(),
                )
                raw_socket = socket.socket(address[0], socket.SOCK_STREAM)
                try:
                    raw_socket.settimeout(min(5, budget.remaining()))
                    raw_socket.connect(address[4])
                    raw_socket.settimeout(min(5, budget.remaining()))
                    connection.sock = connection._context.wrap_socket(
                        raw_socket, server_hostname=host
                    )
                    break
                except OSError:
                    raw_socket.close()
                    connection.close()
            else:
                budget.check()
                return None, 0
        connection.sock.settimeout(min(5, budget.remaining()))
        deadline = threading.Timer(
            min(5, budget.remaining()), interrupt_socket, (connection.sock, expired)
        )
        deadline.daemon = True
        deadline.start()
        headers = {
            "User-Agent": "appsec-skills-security-score/1",
            "Accept": accept,
            "Accept-Encoding": "identity",
        }
        if token and authority == token_host:
            if host == "gitlab.com" or selected_gitlab:
                headers["PRIVATE-TOKEN"] = token
            else:
                headers["Authorization"] = "Bearer " + token
        path = parsed.path + ("?" + parsed.query if parsed.query else "")
        attempted = True
        connection.request("GET", path, headers=headers)
        response = connection.getresponse()
        if response.status in {301, 302, 303, 307, 308}:
            raise SourceError(
                "Repository metadata or source redirected; redirects are not followed and no score is available."
            )
        if response.status != 200:
            if rate_limited(response.status, response.getheader):
                raise rate_limit_error(
                    host,
                    response.status,
                    response.getheader,
                    bool(token and authority == token_host),
                )
            return None, response.status
        length = response.getheader("Content-Length")
        if length is not None and (
            not length
            or len(length) > 16
            or not length.isascii()
            or not length.isdecimal()
            or int(length) > limit
        ):
            raise SourceError(
                f"Remote response exceeds the {limit:,}-byte download limit; no score is available."
            )
        data = bytearray()
        while True:
            budget.check()
            if connection.sock:
                connection.sock.settimeout(min(5, budget.remaining()))
            try:
                chunk = response.read(16384)
            except http.client.IncompleteRead as error:
                body_bytes += len(error.partial)
                raise
            body_bytes += len(chunk)
            if not chunk:
                break
            if len(data) + len(chunk) > limit:
                raise SourceError(
                    f"Remote response exceeds the {limit:,}-byte download limit; no score is available."
                )
            data.extend(chunk)
        deadline.cancel()
        deadline.join()
        deadline = None
        budget.check()
        if expired.is_set():
            return None, 0
        if length is not None and len(data) != int(length):
            raise SourceError("Remote response ended before its declared length.")
        reusable = connections is not None and connection.sock is not None
        if reusable:
            connections[authority] = connection
        return bytes(data), 200
    except (OSError, http.client.HTTPException, ssl.SSLError):
        budget.check()
        return None, 0
    finally:
        if attempted and budget.network is not None:
            budget.network.record(authority, body_bytes)
        if deadline is not None:
            deadline.cancel()
            deadline.join()
        if not reusable:
            if connection is not None:
                connection.close()
            if connections is not None:
                connections.pop(authority, None)
        if raw_socket is not None:
            raw_socket.close()


class SourceReader:
    """Reuse each worker's checked TLS connections for one bounded selection."""

    def __init__(self, budget, token, token_host, *, gitlab_host=None):
        self.budget, self.token, self.token_host = budget, token, token_host
        self.destination = {"gitlab_host": gitlab_host} if gitlab_host else {}
        self.local = threading.local()
        self.caches = []
        self.lock = threading.Lock()

    def __call__(self, url, *, limit, accept="application/json"):
        if not hasattr(self.local, "connections"):
            self.local.connections = {}
            with self.lock:
                self.caches.append(self.local.connections)
        data, status = credential_get(
            url,
            self.budget,
            token=self.token,
            token_host=self.token_host,
            limit=limit,
            accept=accept,
            connections=self.local.connections,
            **self.destination,
        )
        if data is None:
            raise source_error(
                status, "Repository file listing or selected source", self.token
            )
        return data

    def close(self):
        for cache in self.caches:
            for connection in cache.values():
                connection.close()


def source_error(status, subject, token=None):
    if status == 404:
        reason = "not found or not accessible (HTTP 404); check the repository URL and access token"
    elif status == 401:
        reason = "authentication failed (HTTP 401); check the selected token"
    elif status in {403, 429}:
        advice = (
            "check token permissions or retry later"
            if token
            else "retry later, or pass a read-only token with --token-env NAME"
        )
        reason = f"access denied or API rate limit reached (HTTP {status}); {advice}"
    elif not status:
        reason = "connection failed; check network access and retry"
    else:
        reason = f"host returned HTTP {status}; retry later or check host availability"
    return RemoteError(f"{subject}: {reason}. No score is available.", status)


def json_get(
    url, budget, token, token_host, expected=dict, *, required=False, gitlab_host=None
):
    try:
        request_budget = budget if required else budget.portion(0.1)
        destination = {"gitlab_host": gitlab_host} if gitlab_host else {}
        data, status = credential_get(
            url, request_budget, token=token, token_host=token_host, **destination
        )
    except SourceError as error:
        if required:
            raise
        return {}, (
            "API rate limit reached"
            if isinstance(error, RateLimited)
            else "optional host metadata unavailable or timed out"
        )
    if data is None:
        if required:
            raise source_error(status, "Repository source", token)
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
    except (ValueError, UnicodeError, RecursionError):
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


def gitlab_reviews(api, branch, protected, budget, token, *, host="gitlab.com"):
    if not token or not isinstance(branch, str) or not branch:
        return None, "Approval policies require authenticated project-rule evidence."
    rules, error = json_get(
        api + "/approval_rules?per_page=100",
        budget,
        token,
        host,
        expected=list,
        **({"gitlab_host": host} if host != "gitlab.com" else {}),
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


def github_branch_rules(api, branch, budget, token):
    """Ruleset rules of a branch; unlike /protection this needs no admin rights."""
    rules, _ = json_get(
        api + "/rules/branches/" + quote(branch, safe="") + "?per_page=100",
        budget,
        token,
        "api.github.com",
        expected=list,
    )
    found = {}
    for rule in rules if isinstance(rules, list) else []:
        if isinstance(rule, dict) and isinstance(rule.get("type"), str):
            parameters = rule.get("parameters")
            found.setdefault(rule["type"], []).append(
                parameters if isinstance(parameters, dict) else {}
            )
    return found


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
        if protected is not True:
            protection, protection_error = {}, branch_error
        elif not token:
            # This endpoint needs admin rights, so an anonymous call only costs quota.
            protection = {}
            protection_error = "Classic protection details need a token."
        else:
            protection, protection_error = json_get(
                api + "/branches/" + quote(branch, safe="") + "/protection",
                budget,
                token,
                "api.github.com",
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
        # A ruleset can only add requirements to what classic protection reports.
        rules = (
            github_branch_rules(api, branch, budget, token) if protected is True else {}
        )
        ruleset_reviews = any(
            type(rule.get("required_approving_review_count")) is int
            and rule["required_approving_review_count"] > 0
            for rule in rules.get("pull_request", [])
        )
        analysis = document.get("security_and_analysis") or {}
        if not isinstance(analysis, dict):
            analysis = {}
        status_checks = "required_status_checks" in rules or isinstance(
            protection.get("required_status_checks"), dict
        )
        settings = [
            setting("default_branch_protection", protected, branch_error),
            setting("required_reviews", True)
            if ruleset_reviews
            else setting("required_reviews", review_value, protection_error),
            setting(
                "successful_pipeline_before_merge",
                True if status_checks else None,
            ),
            setting(
                "signed_commits",
                True if "required_signatures" in rules else None,
            ),
        ]
        for field in ("secret_scanning", "dependabot_security_updates"):
            entry = analysis.get(field)
            status = entry.get("status") if isinstance(entry, dict) else None
            settings.append(
                setting(
                    field,
                    status == "enabled"
                    if isinstance(status, str) and status in {"enabled", "disabled"}
                    else None,
                    error,
                )
            )
        revision = (
            branch_doc.get("commit", {}).get("sha")
            if isinstance(branch_doc.get("commit"), dict)
            else None
        )
        public = document.get("private") is False

    else:
        api = f"https://{host}/api/v4/projects/" + quote(project, safe="")
        destination = {"gitlab_host": host} if host != "gitlab.com" else {}
        document, error = json_get(
            api, budget, token, host, required=require_source, **destination
        )
        branch = document.get("default_branch")
        branch_doc, branch_error = (
            json_get(
                api + "/repository/branches/" + quote(branch, safe=""),
                budget,
                token,
                host,
                required=require_source,
                **destination,
            )
            if isinstance(branch, str) and branch
            else ({}, error)
        )
        reviews, review_error = gitlab_reviews(
            api, branch, branch_doc.get("protected"), budget, token, host=host
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
        public = False

    return settings, revision, public


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


def token_origin(value):
    """Normalize only an HTTPS origin, without credentials or repository paths."""
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        port = parsed.port if parsed.port is not None else 443
    except (ValueError, TypeError):
        raise SourceError(
            "Invalid HTTPS origin in user token-hosts configuration."
        ) from None
    if (
        parsed.scheme != "https"
        or not host
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or not 1 <= port <= 65535
        or any(ord(char) < 33 or ord(char) > 126 for char in value)
    ):
        raise SourceError("Invalid HTTPS origin in user token-hosts configuration.")
    gitlab_destination(parsed.netloc)
    name = f"[{host}]" if ":" in host else host
    return "https://" + name + (f":{port}" if port != 443 else "")


def token_hosts():
    """Read a bounded user-owned mapping; never discover configuration in a repo."""
    configured = os.environ.get("XDG_CONFIG_HOME", "")
    directory = Path(configured) if configured else None
    if directory is None or not directory.is_absolute():
        directory = Path.home() / ".config"
    path = directory / "security-score" / "token-hosts.json"
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_TOKEN_CONFIG + 1)
    except FileNotFoundError:
        return {}
    except OSError:
        raise SourceError("Cannot read user token-hosts.json configuration.") from None
    if len(raw) > MAX_TOKEN_CONFIG:
        raise SourceError(
            "User token-hosts.json exceeds the 64 KiB configuration limit."
        )

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate origin")
            result[key] = value
        return result

    try:
        document = json.loads(raw, object_pairs_hook=unique)
    except (ValueError, UnicodeError, RecursionError):
        raise SourceError("Invalid user token-hosts.json configuration.") from None
    if not isinstance(document, dict) or len(document) > 256:
        raise SourceError(
            "User token-hosts.json must map up to 256 HTTPS origins to environment variable names."
        )
    result = {}
    for origin, name in document.items():
        if not isinstance(name, str) or not re.fullmatch(
            r"[A-Za-z_][A-Za-z0-9_]*", name
        ):
            raise SourceError(
                "User token-hosts.json must contain environment variable names, not tokens."
            )
        normalized = token_origin(origin)
        if normalized in result:
            raise SourceError(
                "Ambiguous HTTPS origin in user token-hosts.json configuration."
            )
        result[normalized] = name
    return result


class AutomaticToken:
    """Load one configured environment variable lazily for one API authority."""

    def __init__(self, name, authority):
        self.name, self.authority = name, authority
        self._value = None
        self._lock = threading.Lock()

    def current(self, authority):
        return self._value if authority == self.authority else None

    def activate(self, authority):
        if authority != self.authority:
            return False
        with self._lock:
            if self._value is None:
                self._value = read_token(self.name)
        return True


def select_token(host, name=None):
    if name is not None:
        return read_token(name)
    authority = "api.github.com" if host == "github.com" else host
    configured = token_hosts().get(token_origin("https://" + authority))
    if configured is None:
        return None
    return AutomaticToken(configured, authority)


def credential_get(url, budget, *, token=None, token_host=None, **kwargs):
    """Retry an anonymous authentication failure once at the configured origin."""
    if not isinstance(token, AutomaticToken):
        return get(url, budget, token=token, token_host=token_host, **kwargs)
    authority = urlsplit(url).netloc
    matched = authority == token_host == token.authority
    current = token.current(authority) if matched else None
    try:
        data, status = get(url, budget, token=current, token_host=token_host, **kwargs)
    except RateLimited as error:
        if error.status != 403 or current is not None or not matched:
            raise
        token.activate(authority)
        return get(
            url, budget, token=token.current(authority), token_host=token_host, **kwargs
        )
    if data is None and status in {401, 403, 404} and current is None and matched:
        token.activate(authority)
        return get(
            url, budget, token=token.current(authority), token_host=token_host, **kwargs
        )
    return data, status


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
    token = select_token(host, options.token_env)
    options._remote_token = token
    settings, revision, public = host_settings(
        host, project, budget, token, require_source=True
    )
    if revision is None:
        raise SourceError(
            "Repository has no readable default-branch commit (empty repository or inaccessible branch); no score is available."
        )
    if not isinstance(revision, str) or not re.fullmatch(
        r"[0-9a-f]{40}(?:[0-9a-f]{24})?", revision
    ):
        raise SourceError(
            "Repository host returned an invalid commit ID; no score is available."
        )
    token_host = "api.github.com" if host == "github.com" else host
    destination = (
        {"gitlab_host": host} if host not in {"github.com", "gitlab.com"} else {}
    )

    # Stop network selection before the overall deadline, leaving time to scan
    # the sources already available and publish their observed pattern index.
    source_budget = budget.portion(0.7)
    read = SourceReader(source_budget, token, token_host, **destination)
    try:
        files, exclusions = select_files(
            host,
            project,
            revision,
            source_budget,
            read,
            # Public files come from the raw host: no API quota, no token in transit.
            authenticated=bool(token) and not public,
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
