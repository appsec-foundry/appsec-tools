from datetime import datetime, timezone
import json
import uuid

import jsonschema
import regex

from .config import SCHEMAS
from .errors import OutputError

NAMESPACE = "https://github.com/appsec-foundry/appsec-analyzer-tools/ns/requirement-harvester"


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def prop(name, value):
    return {"name": name, "ns": NAMESPACE, "value": value}


def build_catalog(target, sources, requirements, timestamp=None):
    groups = []
    source_map = {s["id"]: s for s in sources}
    for source_id in sorted(target["source-ids"]):
        controls = []
        for req in sorted((r for r in requirements if r.source_id == source_id), key=lambda r: r.id):
            props = [prop("source-id", source_id), prop("source-locator", req.locator),
                     prop("extraction-rule", req.rule_id), prop("retrieved-at", req.fetched_at)]
            if req.original_id:
                props.append(prop("original-id", req.original_id))
            parts = [{"id": req.id + "-statement", "name": "statement", "prose": req.statement}]
            for key, value in sorted(req.attributes.items()):
                if key in {"guidance", "example"}:
                    parts.append({"name": key, "prose": value})
                elif key in {"context", "applicability", "exceptions"}:
                    parts.append({"name": key, "ns": NAMESPACE, "prose": value})
                else:
                    props.append(prop(key, value))
            links = [{"href": req.url, "rel": "reference"}]
            links.extend({"href": ref, "rel": "reference"} for ref in req.references if ref != req.url)
            controls.append({"id": req.id, "title": req.title, "props": props, "links": links, "parts": parts})
        if not controls:
            raise OutputError("An assigned source contains no requirements.")
        groups.append({"id": source_id, "title": source_map[source_id]["title"], "controls": controls})
    result = {"catalog": {"uuid": str(uuid.uuid4()), "metadata": {"title": target["title"],
                "last-modified": timestamp or now(), "version": target["version"], "oscal-version": "1.2.3"}, "groups": groups}}
    validate_catalog(result)
    return result


def validate_catalog(document):
    schema = json.loads((SCHEMAS / "oscal_catalog_schema.json").read_text())
    # NIST's unchanged schema uses Unicode properties (\p{L}, \p{N}).
    # Python re cannot evaluate these; do not remove or weaken the patterns.
    def pattern(validator, expression, instance, subschema):
        if isinstance(instance, str) and not regex.search(expression, instance, timeout=1):
            yield jsonschema.ValidationError("OSCAL character pattern violated.")
    cls = jsonschema.validators.extend(jsonschema.validators.validator_for(schema), {"pattern": pattern})
    validator = cls(schema, format_checker=jsonschema.FormatChecker())
    error = next(validator.iter_errors(document), None)
    if error:
        pending, leaves = [error], []
        while pending:
            current = pending.pop()
            if current.context:
                pending.extend(current.context)
            else:
                leaves.append(current)
        error = max(leaves, key=lambda e: len(list(e.absolute_path)))
        location = ".".join(str(x) for x in error.absolute_path)
        raise OutputError(f"Export violates the OSCAL 1.2.3 catalog schema at {location} ({error.validator}).")
    ids = set()
    for group in document["catalog"].get("groups", []):
        for control in group.get("controls", []):
            if control["id"] in ids or not control.get("title") or not any(p.get("name") == "statement" and p.get("prose", "").strip() for p in control.get("parts", [])):
                raise OutputError("Export violates catalog content rules.")
            ids.add(control["id"])
    if not ids:
        raise OutputError("An empty catalog is not published.")
