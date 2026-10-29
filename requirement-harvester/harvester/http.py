from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import http.client
import json
import socket
import ssl
import time
from urllib.parse import urljoin, urlsplit
import zlib

from .errors import AuthError, HarvestError
from .urls import canonical, origin


class Budget:
    def __init__(self, seconds, requests=400, interval=0):
        self.deadline = time.monotonic() + seconds
        self.remaining_requests = requests
        self.interval = interval
        self.last_request = None

    def remaining(self):
        value = self.deadline - time.monotonic()
        if value <= 0:
            raise HarvestError("Run time budget exhausted.")
        return value

    def pause(self, seconds):
        if seconds >= self.remaining():
            raise HarvestError("Wait time exceeds the run time budget.")
        if seconds > 0:
            time.sleep(seconds)

    def request(self):
        self.remaining()
        if self.remaining_requests <= 0:
            raise HarvestError("Request budget exhausted.")
        if self.last_request is not None:
            self.pause(max(0, self.interval - (time.monotonic() - self.last_request)))
        self.remaining_requests -= 1
        self.last_request = time.monotonic()


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, port, scope, budget, **kwargs):
        self.scope = scope
        self.budget = budget
        super().__init__(host, port, **kwargs)

    def connect(self):
        # Resolve exactly once, validate every answer, connect to the numeric sockaddr.
        addresses = socket.getaddrinfo(self.host, self.port, type=socket.SOCK_STREAM)
        if not addresses:
            raise HarvestError("DNS returned no address.")
        for _, _, _, _, sockaddr in addresses:
            self.scope.check_address(sockaddr[0])
        for family, kind, proto, _, sockaddr in addresses:
            raw = socket.socket(family, kind, proto)
            try:
                raw.settimeout(min(self.timeout, self.budget.remaining()))
                raw.connect(sockaddr)
                self.scope.check_address(raw.getpeername()[0])
                # TLS validates the configured hostname, not the numeric IP.
                self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
                return
            except ssl.SSLError:
                raw.close()
                raise
            except OSError:
                raw.close()
        raise HarvestError("Connection to the destination failed.")


@dataclass
class Response:
    status_code: int
    headers: dict
    content: bytes
    url: str

    @property
    def text(self):
        return self.content.decode("utf-8")

    def json(self):
        return json.loads(self.content)


class Transport:
    def __init__(self, scope, limits, budget, ca_bundle=None):
        self.scope, self.limits, self.budget = scope, limits, budget
        self.context = ssl.create_default_context(cafile=ca_bundle)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.response_cache = {}

    def request(self, method, url, headers=None, body=None):
        url = canonical(url)
        self.scope.require(url)
        self.budget.request()
        p = urlsplit(url)
        headers = {"User-Agent": "requirement-harvester/0.1.0", "Accept-Encoding": "identity", **(headers or {})}
        for key, value in headers.items():
            if not isinstance(value, str) or any(ord(c) < 32 or ord(c) == 127 for c in key + value):
                raise AuthError("Invalid HTTP header.")
        connection = PinnedHTTPSConnection(p.hostname, p.port or 443, self.scope, self.budget,
                    timeout=min(self.limits["connect-timeout-seconds"], self.budget.remaining()), context=self.context)
        try:
            connection.connect()
            connection.sock.settimeout(min(self.limits["read-timeout-seconds"], self.budget.remaining()))
            connection.request(method, p.path + ("?" + p.query if p.query else ""), body=body, headers=headers)
            response = connection.getresponse()
            response_headers = {k.lower(): v for k, v in response.getheaders()}
            encoding = response_headers.get("content-encoding", "identity").lower()
            if encoding not in {"identity", "gzip"}:
                raise HarvestError("Unsupported HTTP compression.")
            decoder = zlib.decompressobj(16 + zlib.MAX_WBITS) if encoding == "gzip" else None
            maximum = self.limits["max-response-bytes"]
            result = bytearray()
            wire_size = 0
            while True:
                if connection.sock:
                    connection.sock.settimeout(min(self.limits["read-timeout-seconds"], self.budget.remaining()))
                self.budget.remaining()
                chunk = response.read1(min(65536, maximum + 1))
                if not chunk:
                    break
                wire_size += len(chunk)
                if wire_size > maximum:
                    raise HarvestError("HTTP response exceeds the size limit.")
                result.extend(decoder.decompress(chunk, maximum - len(result) + 1) if decoder else chunk)
                if len(result) > maximum or (decoder and decoder.unconsumed_tail):
                    raise HarvestError("Decompressed response exceeds the size limit.")
            if decoder and (not decoder.eof or decoder.unused_data):
                raise HarvestError("Invalid or multi-member compressed response.")
            return Response(response.status, response_headers, bytes(result), url)
        except (OSError, http.client.HTTPException, UnicodeError, zlib.error, ValueError):
            raise HarvestError("HTTPS request failed (network, TLS, or response format).") from None
        finally:
            connection.close()

    def fetch(self, url, auth_headers):
        original_origin = origin(url)
        current = canonical(url)
        seen = set()
        hops = 0
        retry = 0
        while True:
            if current in self.response_cache:
                return self.response_cache[current]
            if current in seen:
                raise HarvestError("Redirect loop detected.")
            headers = {"Accept": "text/html,application/xhtml+xml"}
            if origin(current) == original_origin:
                headers.update(auth_headers)
            response = self.request("GET", current, headers)
            if response.status_code in {401, 403}:
                raise AuthError("Source denied access (401/403).")
            if response.status_code in {429, 502, 503, 504} and retry < self.limits["max-retries"]:
                delay = min(2 ** retry, 8)
                raw = response.headers.get("retry-after")
                if raw:
                    try:
                        delay = max(delay, int(raw))
                    except ValueError:
                        try:
                            delay = max(delay, (parsedate_to_datetime(raw) - datetime.now(timezone.utc)).total_seconds())
                        except (ValueError, TypeError, OverflowError):
                            raise HarvestError("Invalid Retry-After header.") from None
                self.budget.pause(max(0, delay))
                retry += 1
                continue
            if response.status_code in {301, 302, 303, 307, 308}:
                seen.add(current)
                hops += 1
                if hops > self.limits["max-redirects"]:
                    raise HarvestError("Redirect limit reached.")
                location = response.headers.get("location")
                if not location:
                    raise HarvestError("Redirect location missing.")
                current = canonical(urljoin(current, location))
                self.scope.require(current)
                retry = 0
                continue
            if response.status_code != 200:
                raise HarvestError(f"Unexpected HTTP status {response.status_code}.")
            mime = response.headers.get("content-type", "").split(";")[0].strip().lower()
            if mime not in {"text/html", "application/xhtml+xml"}:
                raise HarvestError("Response is not a supported HTML document.")
            if b"\0" in response.content or not response.content.removeprefix(b"\xef\xbb\xbf").lstrip().startswith(b"<"):
                raise HarvestError("Response content is not an HTML document.")
            self.response_cache[current] = response
            return response
