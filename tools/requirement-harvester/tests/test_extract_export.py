import copy
from dataclasses import asdict
from pathlib import Path

import pytest
import yaml

from conftest import page
from harvester.errors import AuthError, HarvestError, OutputError
from harvester.extract import extract, parse_page
from harvester.io import yaml_bytes
from harvester.oscal import build_catalog, validate_catalog


def items(cfg, content):
    source = cfg["sources"][0]
    return extract(source, parse_page(content, source["limits"]), source["start-urls"][0], "2026-10-28T00:00:00Z")


def test_blocks_context_and_schema(config_factory):
    cfg = config_factory()
    cfg["sources"][0]["extraction"]["context-selector"] = ":scope > p"
    body = page('Nur für interne Dienste: MUST NOT disclose.<ul><li>Außer bei Freigabe</li></ul><pre>if x:\n    deny()</pre>')
    body = body.replace(b"<main>", "<main><p>Gilt für Team Ä.</p>".encode())
    rows = items(cfg, body)
    assert "MUST NOT" in rows[0].statement
    assert "Außer" in rows[0].statement
    assert "    deny()" in rows[0].statement
    assert rows[0].attributes["context"] == "Gilt für Team Ä."
    assert "obligation" not in rows[0].attributes
    doc = build_catalog(cfg["catalogs"][0], cfg["sources"], rows)
    validate_catalog(yaml.safe_load(yaml_bytes(doc)))
    assert doc["catalog"]["groups"][0]["controls"][0]["links"][0]["href"].endswith("#REQ-1")
    doc["catalog"]["uuid"] = "invalid"
    with pytest.raises(OutputError):
        validate_catalog(doc)


def test_sections(config_factory):
    cfg = config_factory()
    cfg["sources"][0]["extraction"]["rules"] = [{"id": "section", "strategy": "sections", "item-selector": "h2",
        "fields": {"original-id": {"attribute": "id"}, "title": {"selector": "h2"}, "statement": {}}}]
    rows = items(cfg, b'<main><h2 id="a">One</h2><p>MUST x.</p><h3>Exception</h3><p>Unless y.</p><h2 id="b">Two</h2><p>SHOULD z.</p></main>')
    assert len(rows) == 2
    assert "Unless y" in rows[0].statement
    assert "SHOULD z" not in rows[0].statement
    assert rows[1].original_id == "b"


def test_table_rows(config_factory):
    cfg = config_factory()
    cfg["sources"][0]["extraction"]["rules"] = [{"id": "table", "strategy": "table-rows", "item-selector": "tbody tr",
        "fields": {"original-id": {"selector": "td:nth-child(1)"}, "statement": {"selector": "td:nth-child(2)"},
                   "obligation": {"selector": "td:nth-child(3)"}}}]
    rows = items(cfg, b'<main><table><tbody><tr><td>BUS-1</td><td>Deliver in 2 days.</td><td>SHOULD</td></tr></tbody></table></main>')
    assert rows[0].original_id == "BUS-1"
    assert rows[0].attributes["obligation"] == "SHOULD"


def test_identity_stable_when_statement_changes_with_original_id(config_factory):
    cfg = config_factory()
    assert items(cfg, page("Original"))[0].id == items(cfg, page("Changed"))[0].id


def test_unlabelled_identity_not_based_on_position(config_factory):
    cfg = config_factory()
    a = page("Original", "").replace(b'id=""', b'')
    b = a.replace(b"<main>", b'<main><article><h2>New</h2><div class="statement">Inserted</div></article>')
    assert items(cfg, a)[0].id == items(cfg, b)[1].id


@pytest.mark.parametrize("content", [b"<main>No matching items</main>", b"<div>Layout changed</div>",
    b'<main><article><h2>A</h2><div class="statement"></div></article></main>',
    b'<main><article><h2>A</h2><h2>B</h2><div class="statement">x</div></article></main>'])
def test_extraction_failures(config_factory, content):
    with pytest.raises(HarvestError):
        items(config_factory(), content)


def test_login_page(config_factory):
    with pytest.raises(AuthError):
        items(config_factory(), b'<main><input type="password"></main>')


def test_parser_depth(config_factory):
    with pytest.raises(HarvestError):
        items(config_factory(), b"<div>" * 200 + b"</div>" * 200)


def test_no_code_execution_or_unsafe_links(config_factory):
    rows = items(config_factory(), page('<script>fetch("evil")</script>Follow <a href="javascript:bad()">rule</a><a href="https://reference.example/r#x">ref</a>'))
    assert "fetch" not in rows[0].statement
    assert rows[0].references == ["https://reference.example/r#x"]


def test_metadata_changes_but_content_deterministic(config_factory):
    cfg = config_factory()
    rows = items(cfg, page())
    a = build_catalog(cfg["catalogs"][0], cfg["sources"], rows)
    b = build_catalog(cfg["catalogs"][0], cfg["sources"], rows)
    assert a["catalog"]["uuid"] != b["catalog"]["uuid"]
    assert a["catalog"]["groups"] == b["catalog"]["groups"]


def test_table_repeated_footnotes_are_not_requirement_ids(config_factory):
    cfg = config_factory()
    cfg["sources"][0]["extraction"]["rules"] = [{"id": "table", "strategy": "table-rows", "item-selector": "tbody tr", "fields": {"statement": {}}}]
    rows = items(cfg, b'<main><table><thead><tr><th>Rule</th><th>When</th></tr></thead><tbody><tr><td>First<sup id="footnote">1</sup></td><td>Internal</td></tr><tr><td>Second<sup id="footnote">1</sup></td><td>External</td></tr></tbody></table></main>')
    assert len({r.id for r in rows}) == 2
    assert "When: Internal" in rows[0].statement
    assert "When: External" in rows[1].statement


def test_multiline_context_exports_as_prose(config_factory):
    cfg = config_factory()
    cfg["sources"][0]["extraction"]["rules"][0]["fields"]["context"] = {"value": "First paragraph.\n\nSecond paragraph."}
    rows = items(cfg, page())
    doc = build_catalog(cfg["catalogs"][0], cfg["sources"], rows)
    validate_catalog(doc)
    parts = doc["catalog"]["groups"][0]["controls"][0]["parts"]
    assert next(p for p in parts if p["name"] == "context")["prose"].count("\n") == 2
