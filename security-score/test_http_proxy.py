"""REQ-25: proxy selection, CONNECT isolation and verified repository TLS."""

import contextlib
import io
import ipaddress
import json
import os
from pathlib import Path
import select
import socket
import socketserver
import sys
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent / "scripts"))
import score_remote as remote
import score_sources as sources


class ProxyTests(unittest.TestCase):
    def setUp(self):
        environment = mock.patch.dict(os.environ, {}, clear=True)
        environment.start()
        self.addCleanup(environment.stop)

    def test_proxy_variables_and_precedence(self):
        for environment, expected in (
            ({"HTTPS_PROXY": "http://proxy.internal:3128"}, ("proxy.internal", 3128)),
            ({"HTTP_PROXY": "http://proxy.internal:8080"}, ("proxy.internal", 8080)),
            ({"ALL_PROXY": "http://proxy.internal"}, ("proxy.internal", 80)),
            ({"HTTPS_PROXY": "http://upper:8080", "https_proxy": "http://lower:8081"}, ("lower", 8081)),
            ({"HTTPS_PROXY": "http://https:8443", "ALL_PROXY": "http://all:8888", "HTTP_PROXY": "http://http:8080"}, ("https", 8443)),
        ):
            with self.subTest(environment=environment), mock.patch.dict(os.environ, environment, clear=True):
                proxy = remote.proxy_for("gitlab.internal:443")
                self.assertEqual((proxy.host, proxy.port), expected)
        self.assertIsNone(remote.proxy_for("gitlab.internal"))

    def test_no_proxy_supports_hosts_suffixes_ports_and_all(self):
        for bypass, host, expected in (
            ("gitlab.internal", "gitlab.internal", True),
            (".internal", "gitlab.internal:8443", True),
            ("gitlab.internal:8443", "gitlab.internal:8443", True),
            ("gitlab.internal:8443", "gitlab.internal:9443", False),
            ("gitlab.internal", "gitlab.internal.evil", False),
            ("*", "gitlab.internal", True),
        ):
            with self.subTest(bypass=bypass, host=host), mock.patch.dict(
                os.environ, {"HTTPS_PROXY": "http://proxy:8080", "NO_PROXY": bypass}
            ):
                self.assertEqual(remote.proxy_for(host) is None, expected)

    def test_cgi_http_proxy_header_is_not_trusted(self):
        with mock.patch.dict(os.environ, {"HTTP_PROXY": "http://injected:8080", "REQUEST_METHOD": "GET"}):
            self.assertIsNone(remote.proxy_for("gitlab.internal"))

    def test_invalid_proxy_settings_fail_without_disclosing_credentials(self):
        for value in (
            "http://user:PRIVATE_PROXY_VALUE@proxy:8080", "https://proxy:8443",
            "socks5://proxy:1080", "http://proxy:0", "http://proxy:65536",
            "http://proxy:bad", "http://proxy/a", "http://proxy?token=PRIVATE_PROXY_VALUE",
            "http://proxy\r\n:8080",
        ):
            with self.subTest(value=value), mock.patch.dict(os.environ, {"HTTPS_PROXY": value}):
                with self.assertRaises(sources.SourceError) as caught:
                    remote.proxy_for("gitlab.internal")
                self.assertNotIn("PRIVATE_PROXY_VALUE", str(caught.exception))

    def request(self, *, address="100.64.1.31", connect_error=None, tunnel_error=None, cache=None):
        response = mock.Mock(status=200)
        response.getheader.return_value = None
        response.read.side_effect = [b"{}", b""]
        repository = mock.Mock()
        repository.getresponse.return_value = response
        tunnel = mock.Mock()
        tunnel._tunnel.side_effect = tunnel_error
        raw = mock.Mock()
        raw.connect.side_effect = connect_error

        def lookup(host, port, **kwargs):
            ip = address if host == "gitlab.internal" else "127.0.0.1"
            return [(socket.AF_INET, 1, 6, "", (ip, port))]

        budget = sources.Budget()
        budget.network = remote.NetworkStats()
        with (
            mock.patch.dict(os.environ, {"HTTPS_PROXY": "http://127.0.0.1:3128"}),
            mock.patch.object(remote.socket, "getaddrinfo", side_effect=lookup),
            mock.patch.object(remote.socket, "socket", return_value=raw),
            mock.patch.object(remote.http.client, "HTTPSConnection", return_value=repository),
            mock.patch.object(remote.http.client, "HTTPConnection", return_value=tunnel),
        ):
            result = remote.get(
                "https://gitlab.internal:8443/api/v4/projects/group%2Fproject",
                budget, gitlab_host="gitlab.internal:8443",
                token="ISOLATED_GIT_TOKEN", token_host="gitlab.internal:8443",
                connections=cache,
            )
        return result, raw, tunnel, repository, budget

    def test_connect_is_pinned_to_target_ip_and_has_no_repository_token(self):
        result, raw, tunnel, repository, budget = self.request()
        self.assertEqual(result, (b"{}", 200))
        raw.connect.assert_called_once_with(("127.0.0.1", 3128))
        tunnel.set_tunnel.assert_called_once_with(
            "100.64.1.31", 8443, headers={"Host": "100.64.1.31:8443"}
        )
        tunnel._tunnel.assert_called_once()
        self.assertNotIn("ISOLATED_GIT_TOKEN", repr(tunnel.mock_calls))
        repository._context.wrap_socket.assert_called_once_with(raw, server_hostname="gitlab.internal")
        self.assertEqual(repository.request.call_args.kwargs["headers"]["PRIVATE-TOKEN"], "ISOLATED_GIT_TOKEN")
        self.assertNotIn("Proxy-Authorization", repository.request.call_args.kwargs["headers"])
        self.assertEqual(budget.network.snapshot()["requests"], 2)

    def test_proxy_does_not_bypass_target_address_validation(self):
        for address in ("127.0.0.1", "169.254.169.254", "100.100.100.200"):
            with self.subTest(address=address), self.assertRaises(sources.SourceError):
                self.request(address=address)

    def test_proxy_tcp_failure_has_no_direct_fallback(self):
        with self.assertRaisesRegex(sources.SourceError, "no direct connection"):
            self.request(connect_error=OSError("PRIVATE_PROXY_DIAGNOSTIC"))

    def test_proxy_status_errors_cannot_be_mistaken_for_repository_404(self):
        for status in (404, 407):
            with self.subTest(status=status):
                with self.assertRaises(sources.SourceError) as caught:
                    self.request(tunnel_error=OSError(f"Tunnel connection failed: {status} PRIVATE_PROXY_DIAGNOSTIC"))
                message = str(caught.exception)
                self.assertIn("HTTP proxy CONNECT failed", message)
                self.assertIn(str(status), message)
                self.assertNotIn("PRIVATE_PROXY_DIAGNOSTIC", message)

    def test_connection_cache_distinguishes_proxy_from_direct_connection(self):
        direct = mock.Mock()
        cache = {"gitlab.internal:8443": direct}
        self.request(cache=cache)
        direct.request.assert_not_called()
        self.assertIn(("gitlab.internal:8443", "127.0.0.1:3128"), cache)

    def test_local_proxy_is_allowed_but_repository_loopback_is_not(self):
        rows = [(socket.AF_INET, 1, 6, "", ("127.0.0.1", 3128))]
        with mock.patch.object(remote.socket, "getaddrinfo", return_value=rows):
            self.assertEqual(
                remote.public_addresses("localhost", sources.Budget(), port=3128, allow_private=True, allow_loopback=True), rows
            )
            with self.assertRaises(sources.SourceError):
                remote.public_addresses("localhost", sources.Budget(), allow_private=True)

    def test_connect_negotiation_cannot_exceed_the_budget(self):
        client, server = socket.socketpair()
        stop = threading.Event()

        def trickle():
            try:
                server.recv(4096)
                server.sendall(b"HTTP/1.0 200 Connected\r\nX-Test: ")
                while not stop.wait(0.005):
                    server.sendall(b"x")
            except OSError:
                pass

        sender = threading.Thread(target=trickle, daemon=True)
        sender.start()
        started = time.monotonic()
        try:
            with self.assertRaises(sources.SourceError):
                remote.proxy_tunnel(client, remote.HTTPProxy("localhost", 3128), "8.8.8.8", 443, sources.Budget(0.15))
            self.assertLess(time.monotonic() - started, 2)
        finally:
            stop.set()
            client.close()
            server.close()
            sender.join(timeout=1)
        self.assertFalse(sender.is_alive())


class _TunnelHandler(socketserver.StreamRequestHandler):
    def handle(self):
        line = self.rfile.readline(4097)
        if len(line) > 4096:
            return
        parts = line.decode("ascii").strip().split()
        if len(parts) != 3 or parts[0] != "CONNECT":
            return
        count = 0
        while True:
            line = self.rfile.readline(4097)
            count += len(line)
            if len(line) > 4096 or count > 16384:
                return
            if line in (b"\r\n", b"\n", b""):
                break
        destination = parts[1]
        host, port = destination.rsplit(":", 1)
        host = host.strip("[]")
        address = ipaddress.ip_address(host)
        if not address.is_global or address.is_multicast or int(port) != 443:
            return
        with socket.create_connection((host, int(port)), timeout=10) as upstream:
            with self.server.lock:
                self.server.destinations.append(destination)
            self.wfile.write(b"HTTP/1.0 200 Connection established\r\n\r\n")
            self.wfile.flush()
            pair = (self.connection, upstream)
            while not self.server.stopping.is_set():
                readable, _, _ = select.select(pair, [], [], 0.5)
                for source in readable:
                    data = source.recv(65536)
                    if not data:
                        return
                    other = upstream if source is self.connection else self.connection
                    other.sendall(data)


class TunnelProxy(socketserver.ThreadingTCPServer):
    """Loopback-only live-test relay; never used by the installed application."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self):
        self.lock = threading.Lock()
        self.destinations = []
        self.stopping = threading.Event()
        super().__init__(("127.0.0.1", 0), _TunnelHandler)

    def __enter__(self):
        self.worker = threading.Thread(target=self.serve_forever, daemon=True)
        self.worker.start()
        return self

    def __exit__(self, *args):
        self.stopping.set()
        self.shutdown()
        self.server_close()
        self.worker.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
