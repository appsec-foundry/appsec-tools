import copy
import gzip
import json
import os
import socket
import ssl
import time

import pytest

from harvester import auth
from harvester.auth import headers_for, stored_token, binding
from harvester.config import DEFAULTS
from harvester.errors import AuthError, HarvestError
from harvester.http import Budget, PinnedHTTPSConnection, Response, Transport
from harvester.io import write_json
from harvester.urls import Scope


@pytest.mark.parametrize("address", ["127.0.0.1", "::1", "169.254.169.254", "fe80::1", "0.0.0.0", "224.0.0.1", "::ffff:127.0.0.1", "10.0.0.3", "100.64.0.1"])
def test_forbidden_addresses(address):
    with pytest.raises(HarvestError):
        Scope({"allowed-origins": ["https://example.org"]}).check_address(address)


def test_explicit_private_network():
    scope = Scope({"allowed-origins": ["https://example.org"], "allowed-private-networks": ["10.1.2.0/24"]})
    scope.check_address("10.1.2.5")
    with pytest.raises(HarvestError):
        scope.check_address("10.1.3.5")


def test_pin_numeric_address_and_hostname(monkeypatch):
    answers = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
    resolutions, connections, names = [], [], []
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **kw: resolutions.append(a) or answers)
    class Raw:
        def settimeout(self, value): pass
        def connect(self, address): connections.append(address)
        def getpeername(self): return ("93.184.216.34", 443)
        def close(self): pass
    monkeypatch.setattr(socket, "socket", lambda *a, **kw: Raw())
    class Context:
        def wrap_socket(self, sock, server_hostname):
            names.append(server_hostname)
            return sock
    conn = PinnedHTTPSConnection("example.org", 443, Scope({"allowed-origins": ["https://example.org"]}), Budget(10), timeout=2)
    conn._context = Context()
    conn.connect()
    assert len(resolutions) == 1
    assert connections == [("93.184.216.34", 443)]
    assert names == ["example.org"]


def test_rebinding_revalidated_for_every_connection(monkeypatch):
    scope = Scope({"allowed-origins": ["https://example.org"]})
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **kw: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))])
    monkeypatch.setattr(socket, "socket", lambda *a, **kw: pytest.fail("must reject before opening a socket"))
    with pytest.raises(HarvestError):
        PinnedHTTPSConnection("example.org", 443, scope, Budget(10), timeout=2).connect()


def transport(responses, origins=None):
    t = Transport(Scope({"allowed-origins": origins or ["https://example.org"]}), dict(DEFAULTS, **{"max-retries": 0}), Budget(30))
    calls = []
    def request(method, url, headers=None, body=None):
        t.scope.require(url)
        calls.append((url, headers))
        return responses[url]
    t.request = request
    return t, calls


def html_response(url):
    return Response(200, {"content-type": "text/html"}, b"<main>OK</main>", url)


def test_cross_origin_redirect_drops_credentials():
    a, b = "https://example.org/a", "https://other.example/b"
    t, calls = transport({a: Response(302, {"location": b}, b"", a), b: html_response(b)}, ["https://example.org", "https://other.example"])
    t.fetch(a, {"Authorization": "Bearer synthetic", "X-Api-Key": "synthetic"})
    assert "Authorization" in calls[0][1]
    assert "Authorization" not in calls[1][1]
    assert "X-Api-Key" not in calls[1][1]


def test_outside_redirect_never_requested():
    a = "https://example.org/a"
    t, calls = transport({a: Response(302, {"location": "https://evil.example/"}, b"", a)})
    with pytest.raises(HarvestError):
        t.fetch(a, {})
    assert len(calls) == 1


@pytest.mark.parametrize("status,error", [(401, AuthError), (403, AuthError), (500, HarvestError)])
def test_status_errors(status, error):
    a = "https://example.org/a"
    t, _ = transport({a: Response(status, {}, b"sensitive body", a)})
    with pytest.raises(error) as exc:
        t.fetch(a, {})
    assert "sensitive" not in str(exc.value)


def test_redirect_cycle():
    a = "https://example.org/a"
    t, _ = transport({a: Response(302, {"location": a}, b"", a)})
    with pytest.raises(HarvestError):
        t.fetch(a, {})


def test_tls_defaults():
    t, _ = transport({})
    assert t.context.check_hostname
    assert t.context.verify_mode == ssl.CERT_REQUIRED
    assert t.context.minimum_version >= ssl.TLSVersion.TLSv1_2


def test_compression_limit_at_transport(monkeypatch):
    import harvester.http as http
    compressed = gzip.compress(b"X" * 100000)
    class Incoming:
        status = 200
        def getheaders(self): return [("Content-Encoding", "gzip")]
        def read1(self, size):
            nonlocal compressed
            chunk, compressed = compressed[:size], compressed[size:]
            return chunk
    class Connection:
        def __init__(self, *args, **kwargs): self.sock = self
        def settimeout(self, value): pass
        def connect(self): pass
        def request(self, *args, **kwargs): pass
        def getresponse(self): return Incoming()
        def close(self): pass
    monkeypatch.setattr(http, "PinnedHTTPSConnection", Connection)
    t = Transport(Scope({"allowed-origins": ["https://example.org"]}), dict(DEFAULTS, **{"max-response-bytes": 1024}), Budget(10))
    with pytest.raises(HarvestError, match="Größenlimit"):
        t.request("GET", "https://example.org/")


def test_budget_and_retry_after():
    budget = Budget(10, requests=1)
    budget.request()
    with pytest.raises(HarvestError): budget.request()
    a = "https://example.org/a"
    t, _ = transport({a: Response(429, {"retry-after": "600"}, b"", a)})
    t.limits["max-retries"] = 1
    with pytest.raises(HarvestError): t.fetch(a, {})


def test_basic_and_token_credentials(config_factory, monkeypatch):
    source = config_factory()["sources"][0]
    source["auth"] = {"mode": "basic", "username-env": "TEST_USER", "password-env": "TEST_PASSWORD"}
    with pytest.raises(AuthError): headers_for(source, Budget(10))
    monkeypatch.setenv("TEST_USER", "test-user")
    monkeypatch.setenv("TEST_PASSWORD", "synthetic-only")
    assert headers_for(source, Budget(10))["Authorization"].startswith("Basic ")
    source["auth"] = {"mode": "token", "token-env": "TEST_TOKEN"}
    monkeypatch.setenv("TEST_TOKEN", "synthetic\r\ninjected")
    with pytest.raises(AuthError): headers_for(source, Budget(10))
    monkeypatch.setenv("TEST_TOKEN", "synthetic-only")
    assert headers_for(source, Budget(10)) == {"Authorization": "Bearer synthetic-only"}


def entra_source(source, tmp_path):
    source["auth"] = {"mode": "entra", "flow": "interactive", "client-id": "00000000-0000-4000-8000-000000000001",
        "tenant-id": "00000000-0000-4000-8000-000000000002", "scopes": ["api://example/read"],
        "credential-origin": "https://example.org", "token-file": str(tmp_path / "token.json")}
    return source


def test_session_permissions_expiry_and_binding(config_factory, tmp_path):
    source = entra_source(config_factory()["sources"][0], tmp_path)
    path = source["auth"]["token-file"]
    data = {"binding": binding(source), "access_token": "synthetic-only", "expires_at": time.time() + 3600}
    write_json(path, data)
    assert stored_token(source) == "synthetic-only"
    os.chmod(path, 0o644)
    with pytest.raises(AuthError): stored_token(source)
    write_json(path, dict(data, expires_at=0))
    with pytest.raises(AuthError): stored_token(source)
    write_json(path, data)
    source["id"] = "another-source"
    with pytest.raises(AuthError): stored_token(source)


def test_entra_client_credentials_uses_sdk(config_factory, tmp_path, monkeypatch):
    source = entra_source(config_factory()["sources"][0], tmp_path)
    source["auth"].update({"flow": "client-credentials", "client-secret-env": "TEST_CLIENT_SECRET", "scopes": ["api://example/.default"]})
    monkeypatch.setenv("TEST_CLIENT_SECRET", "synthetic-only")
    calls = []
    class Application:
        def __init__(self, **kwargs): calls.append(kwargs)
        def acquire_token_for_client(self, scopes): return {"access_token": "synthetic-token", "token_type": "Bearer"}
    monkeypatch.setattr(auth.msal, "ConfidentialClientApplication", Application)
    assert headers_for(source, Budget(10)) == {"Authorization": "Bearer synthetic-token"}
    assert calls[0]["authority"].endswith(source["auth"]["tenant-id"])
    assert calls[0]["client_credential"] == "synthetic-only"
    assert isinstance(calls[0]["http_client"], auth.EntraHTTP)


def test_interactive_login_abort_and_token_storage(config_factory, tmp_path, monkeypatch):
    source = entra_source(config_factory()["sources"][0], tmp_path)
    outcome = {"error": "access_denied", "error_description": "sensitive-description"}
    class Application:
        def __init__(self, **kwargs): pass
        def acquire_token_interactive(self, **kwargs): return outcome
    monkeypatch.setattr(auth.msal, "PublicClientApplication", Application)
    with pytest.raises(AuthError) as exc: auth.login(source)
    assert "sensitive" not in str(exc.value)
    outcome.clear()
    outcome.update({"access_token": "synthetic-only", "expires_in": 3600})
    auth.login(source)
    assert stored_token(source) == "synthetic-only"


def test_real_msal_sdk_contract_for_client_credentials(config_factory, tmp_path, monkeypatch):
    """Exercise the actual SDK and our HTTP adapter, substituting only HTTP I/O."""
    source = entra_source(config_factory()["sources"][0], tmp_path)
    source["auth"].update({"flow": "client-credentials", "client-secret-env": "TEST_CLIENT_SECRET", "scopes": ["api://example/.default"]})
    monkeypatch.setenv("TEST_CLIENT_SECRET", "synthetic-only")
    root = "https://login.microsoftonline.com/" + source["auth"]["tenant-id"]
    calls = []
    def request(self, method, url, headers=None, body=None):
        self.scope.require(url)
        calls.append((method, url, body))
        if method == "GET":
            result = {"authorization_endpoint": root + "/oauth2/v2.0/authorize", "token_endpoint": root + "/oauth2/v2.0/token",
                      "issuer": root + "/v2.0", "jwks_uri": root + "/discovery/v2.0/keys"}
        else:
            result = {"access_token": "synthetic-only", "expires_in": 3600, "token_type": "Bearer"}
        return Response(200, {"content-type": "application/json"}, json.dumps(result).encode(), url)
    monkeypatch.setattr(Transport, "request", request)
    assert headers_for(source, Budget(30)) == {"Authorization": "Bearer synthetic-only"}
    assert calls[-1][0] == "POST"
    assert b"grant_type=client_credentials" in calls[-1][2]
    assert b"client_secret=synthetic-only" in calls[-1][2]
