import copy
import ipaddress
import json
from pathlib import Path

import jsonschema
import soupsieve

from .errors import ConfigError, HarvestError
from .io import read_yaml
from .urls import Scope, canonical, origin

SCHEMAS = Path(__file__).parent / "schemas"
DEFAULTS = {
    "max-pages": 200, "max-depth": 3, "max-response-bytes": 5242880,
    "connect-timeout-seconds": 5, "read-timeout-seconds": 30,
    "max-run-seconds": 900, "max-requests": 400, "request-interval-seconds": 1,
    "max-redirects": 5, "max-retries": 2, "max-queue": 2000,
    "max-nodes": 100000, "max-items": 10000,
}


def load_config(path):
    path = Path(path).resolve()
    data = read_yaml(path)
    schema = json.loads((SCHEMAS / "config.schema.json").read_text())
    errors = sorted(jsonschema.Draft202012Validator(schema).iter_errors(data), key=lambda e: str(list(e.path)))
    if errors:
        # Schema messages can contain accidental credential literals: report path only.
        location = ".".join(str(p) for p in errors[0].path) or "root"
        raise ConfigError(f"Config-Schema verletzt bei {location} ({errors[0].validator}).")
    cfg = copy.deepcopy(data)
    cfg["defaults"] = DEFAULTS | cfg.get("defaults", {})
    ids = [s["id"] for s in cfg["sources"]]
    if len(set(ids)) != len(ids):
        raise ConfigError("Quell-IDs müssen eindeutig sein.")
    for source in cfg["sources"]:
        crawl = source["crawl"]
        source["limits"] = cfg["defaults"] | {k: v for k, v in crawl.items() if k in DEFAULTS}
        for network in crawl.get("allowed-private-networks", []):
            try:
                n = ipaddress.ip_network(network)
                private = [ipaddress.ip_network(x) for x in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")]
                if not any(n.version == p.version and n.subnet_of(p) for p in private):
                    raise ValueError()
            except ValueError:
                raise ConfigError("Private Netzfreigaben müssen innerhalb RFC1918 oder IPv6-ULA liegen.") from None
        try:
            if any(o != origin(o) for o in crawl["allowed-origins"]):
                raise ConfigError("Origins müssen exakt als https://host[:port] angegeben werden.")
            for key in ("allowed-path-prefixes", "exclude-path-prefixes"):
                for prefix in crawl.get(key, []):
                    if not prefix.startswith("/") or canonical("https://scope.example" + prefix) != "https://scope.example" + prefix:
                        raise ConfigError("Pfadbereiche müssen normalisierte absolute Pfade sein.")
            forbidden = {"token", "access_token", "id_token", "password", "secret", "api_key", "apikey", "code", "key"}
            if forbidden & {k.lower() for k in crawl.get("allowed-query-keys", [])}:
                raise ConfigError("Credential-Queryparameter sind nicht zulässig.")
            scope = Scope(crawl)
            source["start-urls"] = list(dict.fromkeys(canonical(u) for u in source["start-urls"]))
            if not all(scope.allows(u) for u in source["start-urls"]):
                raise ConfigError("Startseite liegt außerhalb ihres Scopes.")
        except HarvestError as e:
            raise ConfigError(str(e)) from None
        extraction = source["extraction"]
        selectors = [extraction["content-selector"]] + extraction.get("exclude-selectors", [])
        if extraction.get("context-selector"):
            selectors.append(extraction["context-selector"])
        rule_ids = []
        for rule in extraction["rules"]:
            rule_ids.append(rule["id"])
            selectors.append(rule["item-selector"])
            if rule.get("page-selector"):
                selectors.append(rule["page-selector"])
            selectors.extend(f["selector"] for f in rule["fields"].values() if "selector" in f)
        if len(set(rule_ids)) != len(rule_ids):
            raise ConfigError("Regel-IDs müssen pro Quelle eindeutig sein.")
        try:
            for selector in selectors:
                soupsieve.compile(selector)
        except Exception:
            raise ConfigError("Ungültiger CSS-Selektor.") from None
        auth = source.setdefault("auth", {"mode": "none"})
        if auth["mode"] != "none" and len(scope.origins) != 1:
            raise ConfigError("Authentifizierte Quellen benötigen genau eine Origin.")
        if auth["mode"] == "entra":
            if auth["flow"] == "interactive":
                if "token-file" not in auth or "client-secret-env" in auth:
                    raise ConfigError("Interaktives Entra benötigt token-file ohne Client-Secret.")
                auth["token-file"] = str((path.parent / auth["token-file"]).absolute())
            else:
                if "client-secret-env" not in auth or "token-file" in auth or len(auth["scopes"]) != 1 or not auth["scopes"][0].endswith("/.default"):
                    raise ConfigError("Entra-CI benötigt client-secret-env und einen /.default-Scope.")
            if "credential-origin" in auth and auth["credential-origin"] not in scope.origins:
                raise ConfigError("Entra-Ziel stimmt nicht mit Quell-Origin überein.")
            auth["credential-origin"] = next(iter(scope.origins))
        if "ca-bundle" in source:
            source["ca-bundle"] = str((path.parent / source["ca-bundle"]).resolve())
            if not Path(source["ca-bundle"]).is_file():
                raise ConfigError("CA-Datei ist nicht verfügbar.")
    output = cfg["output"]
    catalogs = output.get("catalogs", [{"id": "combined", "path": output.get("catalog"), "title": output.get("title"), "version": output.get("version"), "source-ids": ids}])
    if len({c["id"] for c in catalogs}) != len(catalogs):
        raise ConfigError("Katalog-IDs müssen eindeutig sein.")
    assigned = {s for c in catalogs for s in c["source-ids"]}
    if assigned != set(ids):
        raise ConfigError("Ausgabezuordnung enthält unbekannte oder fehlende Quellen.")
    targets = [output["report"]] + [c["path"] for c in catalogs]
    resolved = [(path.parent / p).resolve() for p in targets]
    inputs = {path} | {Path(s["ca-bundle"]) for s in cfg["sources"] if "ca-bundle" in s}
    token_paths = [Path(s["auth"]["token-file"]).resolve() for s in cfg["sources"] if "token-file" in s["auth"]]
    if len(set(token_paths)) != len(token_paths) or any(p in inputs or p.is_dir() for p in token_paths):
        raise ConfigError("Token-Dateipfade kollidieren miteinander oder mit Eingaben.")
    inputs |= set(token_paths)
    if len(set(resolved)) != len(resolved) or any(p in inputs or p.is_dir() for p in resolved):
        raise ConfigError("Ausgabepfade kollidieren miteinander oder mit Eingaben.")
    output["report"] = str(resolved[0])
    for c, target in zip(catalogs, resolved[1:]):
        c["path"] = str(target)
    cfg["catalogs"] = catalogs
    return cfg
