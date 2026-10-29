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
        raise ConfigError(f"Configuration violates the schema at {location} ({errors[0].validator}).")
    cfg = copy.deepcopy(data)
    cfg["defaults"] = DEFAULTS | cfg.get("defaults", {})
    ids = [s["id"] for s in cfg["sources"]]
    if len(set(ids)) != len(ids):
        raise ConfigError("Source IDs must be unique.")
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
                raise ConfigError("Allowed private networks must lie within RFC1918 or IPv6 ULA ranges.") from None
        try:
            if any(o != origin(o) for o in crawl["allowed-origins"]):
                raise ConfigError("Origins must be given exactly as https://host[:port].")
            for key in ("allowed-path-prefixes", "exclude-path-prefixes"):
                for prefix in crawl.get(key, []):
                    if not prefix.startswith("/") or canonical("https://scope.example" + prefix) != "https://scope.example" + prefix:
                        raise ConfigError("Path prefixes must be normalized absolute paths.")
            forbidden = {"token", "access_token", "id_token", "password", "secret", "api_key", "apikey", "code", "key"}
            if forbidden & {k.lower() for k in crawl.get("allowed-query-keys", [])}:
                raise ConfigError("Credential query parameters are not allowed.")
            scope = Scope(crawl)
            source["start-urls"] = list(dict.fromkeys(canonical(u) for u in source["start-urls"]))
            if not all(scope.allows(u) for u in source["start-urls"]):
                raise ConfigError("Start page is outside its scope.")
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
            raise ConfigError("Rule IDs must be unique per source.")
        try:
            for selector in selectors:
                soupsieve.compile(selector)
        except Exception:
            raise ConfigError("Invalid CSS selector.") from None
        auth = source.setdefault("auth", {"mode": "none"})
        if auth["mode"] != "none" and len(scope.origins) != 1:
            raise ConfigError("Authenticated sources need exactly one origin.")
        if auth["mode"] == "entra":
            if auth["flow"] == "interactive":
                if "token-file" not in auth or "client-secret-env" in auth:
                    raise ConfigError("Interactive Entra needs token-file and no client secret.")
                auth["token-file"] = str((path.parent / auth["token-file"]).absolute())
            else:
                if "client-secret-env" not in auth or "token-file" in auth or len(auth["scopes"]) != 1 or not auth["scopes"][0].endswith("/.default"):
                    raise ConfigError("Entra client credentials need client-secret-env and one /.default scope.")
            if "credential-origin" in auth and auth["credential-origin"] not in scope.origins:
                raise ConfigError("Entra credential origin does not match the source origin.")
            auth["credential-origin"] = next(iter(scope.origins))
        if "ca-bundle" in source:
            source["ca-bundle"] = str((path.parent / source["ca-bundle"]).resolve())
            if not Path(source["ca-bundle"]).is_file():
                raise ConfigError("CA bundle is not available.")
    output = cfg["output"]
    catalogs = output.get("catalogs", [{"id": "combined", "path": output.get("catalog"), "title": output.get("title"), "version": output.get("version"), "source-ids": ids}])
    if len({c["id"] for c in catalogs}) != len(catalogs):
        raise ConfigError("Catalog IDs must be unique.")
    assigned = {s for c in catalogs for s in c["source-ids"]}
    if assigned != set(ids):
        raise ConfigError("Output assignment contains unknown or missing sources.")
    targets = [output["report"]] + [c["path"] for c in catalogs]
    resolved = [(path.parent / p).resolve() for p in targets]
    inputs = {path} | {Path(s["ca-bundle"]) for s in cfg["sources"] if "ca-bundle" in s}
    token_paths = [Path(s["auth"]["token-file"]).resolve() for s in cfg["sources"] if "token-file" in s["auth"]]
    if len(set(token_paths)) != len(token_paths) or any(p in inputs or p.is_dir() for p in token_paths):
        raise ConfigError("Token file paths collide with each other or with inputs.")
    inputs |= set(token_paths)
    if len(set(resolved)) != len(resolved) or any(p in inputs or p.is_dir() for p in resolved):
        raise ConfigError("Output paths collide with each other or with inputs.")
    output["report"] = str(resolved[0])
    for c, target in zip(catalogs, resolved[1:]):
        c["path"] = str(target)
    cfg["catalogs"] = catalogs
    return cfg
