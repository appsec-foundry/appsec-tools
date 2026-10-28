import ipaddress
import re
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit, urlunsplit

from .errors import HarvestError


def canonical(url):
    """Normalize URLs without allowing encoded separators or traversal."""
    if not isinstance(url, str) or len(url) > 8192 or re.search(r"[\x00-\x20\x7f\\]", url):
        raise HarvestError("Ungültige URL-Zeichen.")
    try:
        p = urlsplit(url)
        if p.scheme != "https" or not p.hostname or p.username is not None or p.password is not None:
            raise ValueError()
        host = p.hostname.encode("idna").decode("ascii").lower()
        if host.endswith(".") or "%" in host:
            raise ValueError()
        port = p.port or 443
        if not 1 <= port <= 65535:
            raise ValueError()
        if ":" in host:
            host = "[" + str(ipaddress.IPv6Address(host)) + "]"
        elif not re.fullmatch(r"[a-z0-9.-]+", host):
            raise ValueError()
        netloc = host + (f":{port}" if port != 443 else "")
        path = p.path or "/"
        if re.search(r"%(?![0-9a-fA-F]{2})|%(?:2f|5c|25)", path, re.I):
            raise ValueError()
        decoded = unquote(path, errors="strict")
        if (re.search(r"[\x00-\x1f\x7f\\;?#]", decoded) or "//" in decoded
                or any(x in {".", ".."} or x.endswith((".", " ")) for x in decoded.split("/") if x)):
            raise ValueError()
        path = quote(decoded, safe="/!$&'()*+,;=:@-._~")
        pairs = parse_qsl(p.query, keep_blank_values=True, max_num_fields=30, errors="strict")
        if any(re.search(r"[\x00-\x1f\x7f]", k + v) for k, v in pairs):
            raise ValueError()
        query = urlencode(sorted(pairs))
        return urlunsplit(("https", netloc, path, query, ""))
    except (ValueError, UnicodeError):
        raise HarvestError("Ungültige HTTPS-URL.") from None


def origin(url):
    p = urlsplit(canonical(url))
    return f"https://{p.netloc}"


def display_url(url):
    """Never include query values in diagnostics."""
    p = urlsplit(url)
    return urlunsplit((p.scheme, p.netloc, p.path, "", ""))


def path_matches(path, prefix):
    return prefix == "/" or path == prefix.rstrip("/") or path.startswith(prefix.rstrip("/") + "/")


class Scope:
    def __init__(self, crawl):
        self.origins = set(crawl["allowed-origins"])
        self.paths = crawl.get("allowed-path-prefixes", ["/"])
        self.excludes = crawl.get("exclude-path-prefixes", [])
        self.query_keys = set(crawl.get("allowed-query-keys", []))
        self.networks = [ipaddress.ip_network(n) for n in crawl.get("allowed-private-networks", [])]

    def allows(self, url):
        try:
            url = canonical(url)
            p = urlsplit(url)
            return (origin(url) in self.origins
                    and any(path_matches(p.path, x) for x in self.paths)
                    and not any(path_matches(p.path, x) for x in self.excludes)
                    and all(k in self.query_keys for k, _ in parse_qsl(p.query, keep_blank_values=True)))
        except HarvestError:
            return False

    def require(self, url):
        if not self.allows(url):
            raise HarvestError("URL außerhalb des konfigurierten Scopes.")

    def check_address(self, address):
        ip = ipaddress.ip_address(address)
        if getattr(ip, "ipv4_mapped", None):
            ip = ip.ipv4_mapped
        if getattr(ip, "sixtofour", None) or getattr(ip, "teredo", None):
            raise HarvestError("IPv6-Übergangsadressen sind nicht zulässig.")
        # Never permit link-local metadata, loopback or special-use ranges.
        if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
            raise HarvestError("Nicht zulässige Netzwerkadresse.")
        if not ip.is_global and not any(ip.version == n.version and ip in n for n in self.networks):
            raise HarvestError("Internes Zielnetz ist nicht freigegeben.")
