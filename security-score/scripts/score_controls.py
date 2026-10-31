"""Narrow authentication and TLS checks over source data; no target code runs."""

import ast
import json
from bisect import bisect_right
from collections import Counter, defaultdict
from pathlib import Path
import re
from urllib.parse import parse_qs, urlsplit

from score_architecture import JS_NAME, bracket_pairs, js_arguments, js_imports
from score_core import JS_EXTENSIONS, qualified


CALL = re.compile(rf"(?<![\w$.])({JS_NAME}(?:\s*\.\s*{JS_NAME}){{0,8}})\s*\(")
OAUTH_MODULES = {
    "passport-oauth2",
    "passport-openidconnect",
    "passport-google-oauth20",
    "openid-client",
    "express-openid-connect",
    "@azure/msal-browser",
    "@azure/msal-node",
    "oidc-client-ts",
}
SAML_MODULES = {"@node-saml/node-saml", "@node-saml/passport-saml", "passport-saml"}
OAUTH_MEMBERS = {
    "Strategy",
    "auth",
    "discovery",
    "buildAuthorizationUrl",
    "authorizationCodeGrant",
    "UserManager",
    "PublicClientApplication",
    "ConfidentialClientApplication",
}
TLS_MEMBERS = {
    "https": {"createServer", "request", "get", "Agent"},
    "tls": {"createServer", "connect", "createSecureContext"},
    "http2": {"createSecureServer"},
}
GRANTS = {
    "authorization_code",
    "implicit",
    "password",
    "client_credentials",
    "refresh_token",
    "urn:ietf:params:oauth:grant-type:device_code",
    "urn:ietf:params:oauth:grant-type:jwt-bearer",
    "urn:ietf:params:oauth:grant-type:token-exchange",
}
ENDPOINTS = {
    "issuer": "issuer",
    "issuerURL": "issuer",
    "issuerBaseURL": "issuer",
    "authority": "issuer",
    "authorizationURL": "authorization",
    "authorization_endpoint": "authorization",
    "tokenURL": "token",
    "token_endpoint": "token",
    "entryPoint": "sso",
    "server_metadata_url": "discovery",
    "auth-server-url": "issuer",
}


def server_identity(value):
    """Only the origin is retained; credentials, path, query and fragment never leave."""
    if not isinstance(value, str) or len(value) > 4000 or "${" in value:
        return None, "Unresolved provider"
    try:
        url = urlsplit(value)
        host, port = url.hostname, url.port
        if (
            url.scheme not in {"http", "https"}
            or not host
            or not re.fullmatch(r"[A-Za-z0-9.:-]+", host)
        ):
            return None, "Unresolved provider"
    except ValueError:
        return None, "Unresolved provider"
    origin = (
        url.scheme
        + "://"
        + ("[" + host + "]" if ":" in host else host)
        + (":" + str(port) if port else "")
    )
    known = {
        "accounts.google.com": "Google",
        "login.microsoftonline.com": "Microsoft Entra ID",
        "github.com": "GitHub",
        "gitlab.com": "GitLab",
        "appleid.apple.com": "Apple",
    }
    label = known.get(host, "Custom / unrecognized provider")
    for domain, name in (
        ("okta.com", "Okta"),
        ("auth0.com", "Auth0"),
        ("amazoncognito.com", "Amazon Cognito"),
        ("b2clogin.com", "Microsoft Entra External ID"),
    ):
        if host.endswith("." + domain):
            label = name
    if re.match(r"/(?:auth/)?realms/[^/]+/", url.path):
        label = "Keycloak-compatible endpoint"
    return origin, label


def provider_evidence(
    value, endpoint, number, profile, protocol="OAuth/OIDC", evidence="configured"
):
    server, label = server_identity(value)
    profile["identity_providers"].append(
        {
            "technology": label,
            "protocol": protocol,
            "server": server,
            "endpoint": endpoint,
            "line": number,
            "evidence": evidence,
        }
    )
    return server


def grant_evidence(fields, number, profile, server=None, evidence="requested"):
    grant = fields.get("grant_type")
    response = fields.get("response_type")
    if isinstance(response, str) and set(response.split()) <= {
        "code",
        "token",
        "id_token",
        "none",
    }:
        grant = (
            "authorization_code"
            if "code" in response.split()
            else "implicit"
            if {"token", "id_token"} & set(response.split())
            else grant
        )
    else:
        response = None
    if "grant_type" not in fields and "response_type" not in fields:
        return
    row = {
        "grant_type": grant if grant in GRANTS else "unresolved",
        "server": server,
        "line": number,
        "evidence": evidence,
    }
    if response is not None:
        row["response_type"] = response
    method = fields.get("code_challenge_method")
    if method in {"plain", "S256"}:
        row["pkce_method"] = method
    profile["oauth_grants"].append(row)


def object_properties(text, code, span, pairs):
    """Literal top-level fields, preserving duplicate or spread uncertainty."""
    start, stop = span
    start += len(code[start:stop]) - len(code[start:stop].lstrip())
    closing = stop - (len(code[start:stop]) - len(code[start:stop].rstrip())) - 1
    if start >= stop or code[start] != "{" or pairs.get(start) != closing:
        return None
    spans = js_arguments(code, start, pairs)
    if spans is None:
        return None
    result = {}
    for a, b in spans:
        raw, active = text[a:b], code[a:b]
        if not raw.strip():
            continue
        match = re.match(r"\s*(?:([A-Za-z_$][\w$]*)|['\"]([\w-]+)['\"])\s*:", raw)
        if not match or not active[match.end() - 1 : match.end()].strip():
            return None
        key = match[1] or match[2]
        if key in result:
            return None
        result[key] = raw[match.end() :].strip()
    return result


def string_value(raw):
    match = re.fullmatch(r"(['\"])([^\n\\]*)\1", raw.strip())
    return match[2] if match else None


def oauth_parameters(fields, number, rows):
    """Explicit protocol choices only; missing fields imply no finding."""
    for key, rule, bad, good in (
        (
            "response_type",
            "AUTH-OAUTH-IMPLICIT",
            lambda v: "token" in v.split(),
            lambda v: v == "code",
        ),
        (
            "grant_type",
            "AUTH-OAUTH-PASSWORD",
            lambda v: v == "password",
            lambda v: v
            in {"authorization_code", "client_credentials", "refresh_token"},
        ),
        (
            "code_challenge_method",
            "AUTH-OAUTH-PKCE",
            lambda v: v == "plain",
            lambda v: v == "S256",
        ),
    ):
        if key not in fields:
            continue
        value = fields[key]
        status = (
            "violated"
            if value is not None and bad(value)
            else "satisfied"
            if value is not None and good(value)
            else "unclear"
        )
        rows[rule].append((number, status))


def authorization_url(raw, constants, profile=None, number=1):
    """Resolve a literal URL or one leading constant in a template, at most 4 KiB."""
    raw = raw.strip()
    if len(raw) > 4000 or len(raw) < 2 or raw[0] not in "'\"`" or raw[-1] != raw[0]:
        return None
    value = raw[1:-1]
    if raw[0] == "`":
        leading = re.match(r"\$\{([A-Za-z_$][\w$]*)\}", value)
        if leading:
            if leading[1] not in constants:
                return None
            value = constants[leading[1]] + value[leading.end() :]
        value = re.sub(r"\$\{[^{}]{1,500}\}", "__DYNAMIC__", value)
    if "${" in value or "\\" in value:
        return None
    try:
        url = urlsplit(value)
        fields = parse_qs(url.query, keep_blank_values=True, max_num_fields=100)
    except ValueError:
        return None
    if (
        url.scheme not in {"http", "https"}
        or not url.netloc
        or not {"client_id", "response_type"} <= fields.keys()
    ):
        return None
    fields = {
        key: values[0] if len(values) == 1 and values[0] != "__DYNAMIC__" else None
        for key, values in fields.items()
    }
    if profile is not None:
        server = provider_evidence(
            value, "authorization", number, profile, evidence="requested"
        )
        grant_evidence(fields, number, profile, server)
    return fields


def javascript_controls(text, code, rows, profile):
    pairs = bracket_pairs(code)
    breaks = [match.start() for match in re.finditer("\n", code)]
    bindings = {}
    discovery_calls = set()
    for local, module, member in js_imports(text, code):
        module = module.removeprefix("node:")
        members = (
            OAUTH_MEMBERS
            if module in OAUTH_MODULES
            else {"SAML", "Strategy"}
            if module in SAML_MODULES
            else TLS_MEMBERS.get(module, set())
        )
        if member in {None, "*", "="}:
            bindings.update({local + "." + method: module for method in members})
            if module == "openid-client":
                discovery_calls.add(local + ".discovery")
            if module in {
                "passport-oauth2",
                "passport-openidconnect",
                "passport-google-oauth20",
                "passport-saml",
            } and member in {None, "="}:
                bindings[local] = module
        elif member in members:
            bindings[local] = module
            if module == "openid-client" and member == "discovery":
                discovery_calls.add(local)
    constants = {}
    writes = Counter(
        match[1] for match in re.finditer(rf"(?<![\w$.])({JS_NAME})\s*=(?!=|>)", code)
    )
    for match in re.finditer(
        rf"\bconst\s+({JS_NAME})\s*=\s*(['\"])([^'\"\n]{{1,4000}})\2", text
    ):
        if code[match.start()].isspace():
            continue
        if writes[match[1]] == 1:
            constants[match[1]] = match[3]
    for call in CALL.finditer(code):
        name = re.sub(r"\s", "", call[1])
        number = bisect_right(breaks, call.start()) + 1
        module = bindings.get(name)
        args = js_arguments(code, call.end() - 1, pairs)
        if module in OAUTH_MODULES | SAML_MODULES:
            rows["AUTH-SSO"].append(
                (
                    number,
                    "satisfied",
                    "SAML call" if module in SAML_MODULES else "OAuth/OIDC call",
                )
            )
            properties = object_properties(text, code, args[0], pairs) if args else None
            if properties:
                protocol = "SAML" if module in SAML_MODULES else "OAuth/OIDC"
                servers = set()
                for key, endpoint in ENDPOINTS.items():
                    if key in properties:
                        server = provider_evidence(
                            string_value(properties[key])
                            or constants.get(properties[key]),
                            endpoint,
                            number,
                            profile,
                            protocol,
                        )
                        if server:
                            servers.add(server)
                fields = {key: string_value(value) for key, value in properties.items()}
                if module in OAUTH_MODULES:
                    oauth_parameters(fields, number, rows)
                grant_evidence(
                    fields,
                    number,
                    profile,
                    next(iter(servers)) if len(servers) == 1 else None,
                    evidence="configured",
                )
            if name in discovery_calls and args:
                raw = text[slice(*args[0])].strip()
                wrapped = re.fullmatch(r"new\s+URL\((.{1,4000})\)", raw)
                provider_evidence(
                    string_value(wrapped[1] if wrapped else raw),
                    "issuer",
                    number,
                    profile,
                    "OIDC",
                )
        if module in SAML_MODULES:
            properties = object_properties(text, code, args[0], pairs) if args else None
            if properties is None:
                rows["AUTH-SAML-VALIDATION"].append((number, "unclear"))
            else:
                for key, bad, good in (
                    ("audience", "false", lambda v: bool(string_value(v))),
                    (
                        "acceptedClockSkewMs",
                        "-1",
                        lambda v: bool(re.fullmatch(r"\d{1,9}", v)),
                    ),
                ):
                    if key in properties:
                        value = properties[key]
                        rows["AUTH-SAML-VALIDATION"].append(
                            (
                                number,
                                "violated"
                                if value == bad
                                else "satisfied"
                                if good(value)
                                else "unclear",
                            )
                        )
        if module in TLS_MEMBERS:
            rows["TLS-USAGE"].append((number, "satisfied", "Node.js TLS API"))
            properties = object_properties(text, code, args[0], pairs) if args else None
            if properties:
                for key, label in (
                    ("cert", "certificate configured"),
                    ("ca", "CA trust configured"),
                    ("pfx", "PKCS#12 configured"),
                ):
                    if key in properties and properties[key] not in {
                        "null",
                        "undefined",
                        "false",
                        "''",
                        '""',
                    }:
                        rows["TLS-CERTIFICATE"].append((number, "satisfied", label))
        if not args:
            continue
        if name.endswith(
            (".redirect", ".location.replace", ".location.assign")
        ) or name in {"location.replace", "location.assign"}:
            fields = authorization_url(
                text[slice(*args[0])], constants, profile, number
            )
            if fields is not None:
                rows["AUTH-SSO"].append(
                    (number, "satisfied", "OAuth/OIDC authorization request")
                )
                oauth_parameters(fields, number, rows)
        if name == "URLSearchParams":
            properties = object_properties(text, code, args[0], pairs)
            if properties:
                fields = {key: string_value(value) for key, value in properties.items()}
                oauth_parameters(fields, number, rows)
                grant_evidence(fields, number, profile)
    # A direct comparison of request input to a stored password field bypasses a KDF.
    incoming = r"(?:req|request)\.body\.(?:password|passwd)"
    stored = r"(?:user|account|record)\.(?:password|passwd|passwordHash)"
    for match in re.finditer(
        rf"(?:\b{incoming}\s*(?:===?|!==?)\s*{stored}\b|\b{stored}\s*(?:===?|!==?)\s*{incoming}\b)",
        code,
    ):
        rows["AUTH-PASSWORD-COMPARE"].append(
            (bisect_right(breaks, match.start()) + 1, "violated")
        )


def python_controls(text, rows, profile):
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return
    imports = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(
                {alias.asname or alias.name: alias.name for alias in node.names}
            )
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            imports.update(
                {
                    alias.asname or alias.name: node.module + "." + alias.name
                    for alias in node.names
                }
            )

    def name(node):
        value = qualified(node)
        first, _, rest = value.partition(".")
        return imports.get(first, first) + ("." + rest if rest else "")

    contexts, all_contexts, assigned = set(), set(), defaultdict(int)
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    assigned[target.id] += 1
        if (
            isinstance(node, ast.Assign)
            and isinstance(node.value, ast.Call)
            and name(node.value.func)
            in {"ssl.create_default_context", "ssl.SSLContext"}
        ):
            bound = {
                target.id for target in node.targets if isinstance(target, ast.Name)
            }
            all_contexts.update(bound)
            options = {kw.arg: kw.value for kw in node.value.keywords}
            purpose = node.value.args[0] if node.value.args else options.get("purpose")
            if (
                name(node.value.func) == "ssl.create_default_context"
                and (purpose is None or name(purpose) == "ssl.Purpose.SERVER_AUTH")
                or name(node.value.func) == "ssl.SSLContext"
                and purpose is not None
                and name(purpose) == "ssl.PROTOCOL_TLS_CLIENT"
            ):
                contexts.update(bound)
    contexts = {context for context in contexts if assigned[context] == 1}
    all_contexts = {context for context in all_contexts if assigned[context] == 1}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            called = name(node.func)
            if called in {"ssl.create_default_context", "ssl.SSLContext"}:
                rows["TLS-USAGE"].append(
                    (node.lineno, "satisfied", "Python TLS context")
                )
            if (
                called.endswith(".load_cert_chain")
                and qualified(node.func).split(".")[0] in all_contexts
            ):
                rows["TLS-CERTIFICATE"].append(
                    (node.lineno, "satisfied", "certificate chain configured")
                )
            if called.startswith(
                ("authlib.integrations.", "requests_oauthlib.", "onelogin.saml2.")
            ):
                rows["AUTH-SSO"].append(
                    (
                        node.lineno,
                        "satisfied",
                        "SAML call"
                        if called.startswith("onelogin.")
                        else "OAuth/OIDC call",
                    )
                )
                for keyword in node.keywords:
                    if keyword.arg in ENDPOINTS:
                        value = (
                            keyword.value.value
                            if isinstance(keyword.value, ast.Constant)
                            else None
                        )
                        provider_evidence(
                            value,
                            ENDPOINTS[keyword.arg],
                            node.lineno,
                            profile,
                            "SAML" if called.startswith("onelogin.") else "OAuth/OIDC",
                        )
            if called.startswith(("requests.", "httpx.")) and called.rsplit(".", 1)[
                -1
            ] in {"post", "request"}:
                for keyword in node.keywords:
                    if keyword.arg in {"data", "json"} and isinstance(
                        keyword.value, ast.Dict
                    ):
                        fields = {
                            key.value: value.value
                            if isinstance(value, ast.Constant)
                            and isinstance(value.value, str)
                            else None
                            for key, value in zip(
                                keyword.value.keys, keyword.value.values
                            )
                            if isinstance(key, ast.Constant)
                            and isinstance(key.value, str)
                        }
                        if all(key is not None for key in keyword.value.keys):
                            oauth_parameters(fields, node.lineno, rows)
                            url_index = 1 if called.endswith(".request") else 0
                            target = (
                                node.args[url_index]
                                if len(node.args) > url_index
                                else None
                            )
                            value = (
                                target.value
                                if isinstance(target, ast.Constant)
                                else None
                            )
                            server = None
                            if "grant_type" in fields:
                                server = provider_evidence(
                                    value,
                                    "token",
                                    node.lineno,
                                    profile,
                                    evidence="requested",
                                )
                            grant_evidence(fields, node.lineno, profile, server)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if (
                    isinstance(target, ast.Attribute)
                    and qualified(target.value) in contexts
                ):
                    value = node.value
                    if target.attr == "check_hostname":
                        status = (
                            "violated"
                            if isinstance(value, ast.Constant) and value.value is False
                            else "satisfied"
                            if isinstance(value, ast.Constant) and value.value is True
                            else "unclear"
                        )
                    elif target.attr == "verify_mode":
                        status = (
                            "violated"
                            if name(value) == "ssl.CERT_NONE"
                            else "satisfied"
                            if name(value) == "ssl.CERT_REQUIRED"
                            else "unclear"
                        )
                    else:
                        continue
                    rows["PY-TLS-CONTEXT"].append((node.lineno, status))
        elif (
            isinstance(node, ast.Compare)
            and len(node.ops) == 1
            and isinstance(node.ops[0], (ast.Eq, ast.NotEq))
        ):
            values = (ast.unparse(node.left), ast.unparse(node.comparators[0]))
            incoming = re.compile(
                r"request\.(?:form|POST|json)\[['\"](?:password|passwd)['\"]\]"
            )
            stored = re.compile(
                r"(?:user|account|record)\.(?:password|passwd|password_hash)"
            )
            if (
                incoming.fullmatch(values[0])
                and stored.fullmatch(values[1])
                or incoming.fullmatch(values[1])
                and stored.fullmatch(values[0])
            ):
                rows["AUTH-PASSWORD-COMPARE"].append((node.lineno, "violated"))


def json_identity(text, profile):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate configuration key")
            result[key] = value
        return result

    try:
        document = json.loads(text, object_pairs_hook=unique)
    except (ValueError, RecursionError):
        return
    if not isinstance(document, dict):
        return
    if (
        "issuer" in document
        and {"authorization_endpoint", "token_endpoint"} & document.keys()
    ):
        server = None
        for key in ("issuer", "authorization_endpoint", "token_endpoint"):
            if key in document:
                match = re.search(r'"' + key + r'"\s*:', text)
                number = text.count("\n", 0, match.start()) + 1 if match else 1
                current = provider_evidence(
                    document[key], ENDPOINTS[key], number, profile, "OIDC", "metadata"
                )
                if key == "issuer":
                    server = current
        grants = document.get("grant_types_supported", [])
        if isinstance(grants, list):
            for grant in grants:
                if isinstance(grant, str):
                    grant_evidence(
                        {"grant_type": grant}, 1, profile, server, "supported"
                    )
    elif "auth-server-url" in document:
        provider_evidence(
            document["auth-server-url"],
            "issuer",
            1,
            profile,
            "OAuth/OIDC",
            "configured",
        )


def spring_identity(text, rows, profile):
    """Selected scalar Spring OAuth2 client settings; YAML tags/merges stay unread."""
    stack, settings = [], {}
    for number, line in enumerate(text.splitlines(), 1):
        match = re.fullmatch(r"( *)([A-Za-z0-9_.-]+):(?:[ \t]+(.*))?", line)
        if not match:
            continue
        indent, key, value = len(match[1]), match[2], match[3]
        while stack and stack[-1][0] >= indent:
            stack.pop()
        path = tuple(part for _, key in stack for part in key.split(".")) + tuple(
            key.split(".")
        )
        if value is None or not value.strip() or value.lstrip().startswith("#"):
            stack.append((indent, key))
            continue
        if path[:5] != ("spring", "security", "oauth2", "client", "provider") and path[
            :5
        ] != ("spring", "security", "oauth2", "client", "registration"):
            continue
        if len(path) != 7:
            continue
        if path in settings:
            settings[path] = (None, number)
            continue
        value = re.split(r"\s+#", value, maxsplit=1)[0].strip()
        scalar = (
            string_value(value)
            if value.startswith(("'", '"'))
            else value
            if not value.startswith(("&", "*", "!", "|", ">", "{", "["))
            else None
        )
        settings[path] = (scalar, number)
    providers = {}
    for path, (value, number) in settings.items():
        if path[4] == "provider" and path[6] in {
            "issuer-uri",
            "authorization-uri",
            "token-uri",
        }:
            endpoint = {
                "issuer-uri": "issuer",
                "authorization-uri": "authorization",
                "token-uri": "token",
            }[path[6]]
            server = provider_evidence(value, endpoint, number, profile)
            providers.setdefault(path[5], set()).add(server)
    for path, (value, number) in settings.items():
        if path[4] == "registration" and path[6] == "authorization-grant-type":
            provider = settings.get((*path[:6], "provider"), (path[5], number))[0]
            servers = providers.get(provider, set()) - {None}
            server = next(iter(servers)) if len(servers) == 1 else None
            fields = {"grant_type": value}
            grant_evidence(fields, number, profile, server, "configured")
            oauth_parameters(fields, number, rows)


def inspect_controls(path, text, code, profile=None):
    rows = defaultdict(list)
    profile = {} if profile is None else profile
    profile.update(identity_providers=[], oauth_grants=[])
    suffix = Path(path).suffix.lower()
    if suffix in JS_EXTENSIONS:
        javascript_controls(text, code, rows, profile)
    elif suffix == ".py":
        python_controls(text, rows, profile)
    elif suffix == ".json":
        json_identity(text, profile)
    elif suffix in {".yaml", ".yml"}:
        spring_identity(text, rows, profile)
    elif suffix in {".conf", ".config"}:
        for number, line in enumerate(text.splitlines(), 1):
            if re.match(r"\s*listen\s+[^;#\n]*\bssl\s*;", line):
                rows["TLS-USAGE"].append((number, "satisfied", "nginx TLS listener"))
            if re.match(
                r"\s*ssl_(?:certificate|trusted_certificate|client_certificate)\s+[^;#\n]+;",
                line,
            ):
                rows["TLS-CERTIFICATE"].append(
                    (number, "satisfied", "nginx certificate configured")
                )
    if profile["identity_providers"] and not rows["AUTH-SSO"]:
        rows["AUTH-SSO"].append(
            (
                profile["identity_providers"][0]["line"],
                "satisfied",
                "Identity provider configuration",
            )
        )
    return {rule: sorted(set(locations)) for rule, locations in rows.items()}
