import base64
import json
import logging
import os
import stat
import time
from urllib.parse import urlencode

import msal

from .errors import AuthError, HarvestError
from .http import Budget, Transport
from .io import write_json
from .urls import Scope


def secret(name):
    value = os.environ.get(name, "")
    if not value or len(value) > 16384 or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise AuthError("Erforderliche Credential-Umgebungsvariable fehlt oder ist ungültig.")
    return value


class EntraHTTP:
    """MSAL HTTP adapter with bounded, pinned TLS transport and no redirects."""
    def __init__(self, limits, budget):
        scope = Scope({"allowed-origins": ["https://login.microsoftonline.com"],
                       "allowed-query-keys": ["api-version", "authorization_endpoint", "client_id"]})
        self.transport = Transport(scope, limits, budget)

    def get(self, url, params=None, headers=None, **kwargs):
        if params:
            url += ("&" if "?" in url else "?") + urlencode(params)
        return self._request("GET", url, headers)

    def post(self, url, data=None, headers=None, **kwargs):
        body = urlencode(data or {}).encode()
        return self._request("POST", url, {"Content-Type": "application/x-www-form-urlencoded", **(headers or {})}, body)

    def _request(self, method, url, headers=None, body=None):
        result = self.transport.request(method, url, headers, body)
        if result.status_code not in {200, 400, 401}:
            raise AuthError("Entra-Endpunkt lieferte keinen gültigen Token-Response.")
        return result


def application(source, budget, confidential=False):
    auth = source["auth"]
    # MSAL logs may contain remote error descriptions: never propagate them to CLI.
    msal_logger = logging.getLogger("msal")
    msal_logger.handlers = [logging.NullHandler()]
    msal_logger.propagate = False
    kwargs = dict(client_id=auth["client-id"],
        authority=f"https://login.microsoftonline.com/{auth['tenant-id']}",
        instance_discovery=False, http_client=EntraHTTP(source["limits"], budget),
        enable_pii_log=False, exclude_scopes=["offline_access"])
    if confidential:
        return msal.ConfidentialClientApplication(client_credential=secret(auth["client-secret-env"]), **kwargs)
    return msal.PublicClientApplication(**kwargs)


def binding(source):
    auth = source["auth"]
    return {"source-id": source["id"], "origin": auth["credential-origin"],
            "tenant-id": auth["tenant-id"], "client-id": auth["client-id"], "scopes": sorted(auth["scopes"])}


def checked_token(result):
    if not isinstance(result, dict) or result.get("error"):
        raise AuthError("Entra-Anmeldung fehlgeschlagen oder abgebrochen.")
    token = result.get("access_token", "")
    if (not isinstance(token, str) or not token or len(token) > 65536
            or any(ord(c) <= 32 or ord(c) >= 127 for c in token)
            or result.get("token_type", "Bearer").lower() != "bearer"):
        raise AuthError("Entra lieferte kein gültiges Bearer-Token.")
    return token


def login(source):
    auth = source["auth"]
    if auth["mode"] != "entra" or auth["flow"] != "interactive":
        raise AuthError("login benötigt eine interaktive Entra-Quelle.")
    try:
        app = application(source, Budget(300, 30))
        result = app.acquire_token_interactive(scopes=auth["scopes"], timeout=240,
                    success_template="Anmeldung abgeschlossen. Dieses Fenster kann geschlossen werden.",
                    error_template="Anmeldung fehlgeschlagen. Dieses Fenster kann geschlossen werden.")
        token = checked_token(result)
        lifetime = int(result.get("expires_in", 0))
        if not 60 < lifetime <= 86400:
            raise AuthError("Ungültige Token-Lebensdauer.")
        write_json(auth["token-file"], {"binding": binding(source), "access_token": token,
                                      "expires_at": time.time() + lifetime})
    except HarvestError:
        raise
    except Exception:
        raise AuthError("Interaktive Entra-Anmeldung fehlgeschlagen.") from None


def stored_token(source):
    try:
        fd = os.open(source["auth"]["token-file"], os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as f:
            st = os.fstat(f.fileno())
            if not stat.S_ISREG(st.st_mode) or st.st_mode & 0o077 or st.st_uid != os.getuid() or st.st_size > 100000:
                raise AuthError("Token-Datei benötigt Eigentümerzugriff mit Modus 0600.")
            data = json.load(f)
        if data.get("binding") != binding(source) or data.get("expires_at", 0) <= time.time() + 60:
            raise AuthError("Entra-Token ist abgelaufen oder gehört zu einer anderen Quelle.")
        return checked_token(data)
    except (OSError, ValueError, TypeError, AttributeError):
        raise AuthError("Entra-Token-Datei fehlt oder ist ungültig; login erneut ausführen.") from None


def headers_for(source, budget):
    auth = source["auth"]
    if auth["mode"] == "none":
        return {}
    if auth["mode"] == "token":
        token = secret(auth["token-env"])
        prefix = auth.get("prefix", "Bearer")
        return {auth.get("header", "Authorization"): (prefix + " " if prefix else "") + token}
    if auth["mode"] == "basic":
        username, password = secret(auth["username-env"]), secret(auth["password-env"])
        if ":" in username:
            raise AuthError("Basic-Benutzername enthält einen Doppelpunkt.")
        value = base64.b64encode((username + ":" + password).encode()).decode("ascii")
        return {"Authorization": "Basic " + value}
    if auth["flow"] == "interactive":
        return {"Authorization": "Bearer " + stored_token(source)}
    try:
        app = application(source, budget, confidential=True)
        result = app.acquire_token_for_client(scopes=auth["scopes"])
        return {"Authorization": "Bearer " + checked_token(result)}
    except HarvestError:
        raise
    except Exception:
        raise AuthError("Entra-Anwendungsanmeldung fehlgeschlagen.") from None
