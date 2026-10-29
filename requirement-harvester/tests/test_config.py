import copy
from pathlib import Path

import pytest
import yaml

from harvester.config import load_config
from harvester.errors import ConfigError, HarvestError
from harvester.extract import extract, parse_page
from harvester.urls import Scope, canonical


@pytest.mark.parametrize("payload", [
    "config-version: 1\nconfig-version: 1\n", "x: &x [*x]", "!!python/object/apply:os.system ['false']",
    "42", "x: [" + "[" * 50 + "]" * 50 + "]", "? [a, b]\n: x",
])
def test_bad_yaml(tmp_path, payload):
    p = tmp_path / "bad.yaml"
    p.write_text(payload)
    with pytest.raises(ConfigError):
        load_config(p)


@pytest.mark.parametrize("change", [
    lambda c: c.update({"execute": "echo injected"}),
    lambda c: c["defaults"].update({"max-depth": -1}),
    lambda c: c["sources"][0]["crawl"].update({"allowed-private-networks": ["0.0.0.0/0"]}),
    lambda c: c["sources"][0]["crawl"].update({"allowed-query-keys": ["access_token"]}),
    lambda c: c["sources"][0].update({"start-urls": ["https://elsewhere.example/"]}),
    lambda c: c["sources"][0]["extraction"].update({"content-selector": "[broken"}),
    lambda c: c["sources"].append(copy.deepcopy(c["sources"][0])),
    lambda c: c["sources"][0]["auth"].update({"token": "not-a-real-secret"}),
    lambda c: c["output"].update({"catalog": "config.yaml"}),
    lambda c: c["output"].update({"catalog": "out/report.json"}),
    lambda c: c["sources"][0]["crawl"].update({"allowed-origins": ["https://example.org/"]}),
])
def test_invalid_config(raw_config, config_factory, change):
    change(raw_config)
    with pytest.raises(ConfigError):
        config_factory(raw_config)


def test_multiple_outputs(raw_config, config_factory):
    second = copy.deepcopy(raw_config["sources"][0])
    second["id"] = "operations"
    raw_config["sources"].append(second)
    raw_config["output"] = {"report": "out/report.json", "catalogs": [
        {"id": "all", "path": "out/all.yaml", "title": "All", "version": "1", "source-ids": ["company", "operations"]},
        {"id": "ops", "path": "out/ops.yaml", "title": "Ops", "version": "1", "source-ids": ["operations"]}]}
    cfg = config_factory(raw_config)
    assert len(cfg["catalogs"]) == 2
    raw_config["output"]["catalogs"][0]["source-ids"] = ["operations"]
    with pytest.raises(ConfigError):
        config_factory(raw_config)


@pytest.mark.parametrize("url", [
    "http://example.org/", "https://user:pass@example.org/", "https://example.org/a/../b",
    "https://example.org/%2e%2e/", "https://example.org/policies%2felse/", "https://example.org/%252e/",
    "https://example.org/\r\nHeader:bad", "https://example.org/%0a", "https://example.org./", "https://example.org:99999/",
    "https://example.org/policies/admin;ignored", "https://example.org/policies/admin%3bignored",
    "https://example.org/policies//admin", "https://example.org/policies/admin.",
])
def test_reject_bad_urls(url):
    with pytest.raises(HarvestError):
        canonical(url)


def test_scope_segments_and_query():
    scope = Scope({"allowed-origins": ["https://example.org"], "allowed-path-prefixes": ["/policies/"],
                   "exclude-path-prefixes": ["/policies/history"], "allowed-query-keys": ["page"]})
    assert scope.allows("https://example.org/policies/x?page=2")
    assert scope.allows("https://example.org/policies")
    for u in ["https://example.org/policies-old/x", "https://example.org/policies/history/x",
              "https://sub.example.org/policies/x", "https://example.org/policies/x?token=foo"]:
        assert not scope.allows(u)


def test_owasp_cheatsheets_example():
    cfg = load_config(Path(__file__).parent.parent / "examples" / "owasp-cheatsheets.yaml")
    source = cfg["sources"][0]
    sheet = b"""<html><head><link rel="canonical" href="https://cheatsheetseries.owasp.org/cheatsheets/X_Cheat_Sheet.html"></head>
    <body><article class="md-content__inner"><h1 id="x">X<a class="headerlink" href="#x">&para;</a></h1>
    <h2 id="1-intro">1 Intro<a class="headerlink" href="#1-intro">&para;</a></h2><p>Do the safe thing.</p>
    <h2 id="2-more">2 More</h2><p>Do more.</p></article></body></html>"""
    index = b"""<html><head><link rel="canonical" href="https://cheatsheetseries.owasp.org/Glossary.html"></head>
    <body><article class="md-content__inner"><h1 id="i">Index</h1><h2 id="a">A</h2><p>A Sheet</p></article></body></html>"""

    def run(content, url):
        return extract(source, parse_page(content, source["limits"]), url, "2026-10-29T00:00:00Z")

    found = run(sheet, "https://cheatsheetseries.owasp.org/cheatsheets/X_Cheat_Sheet.html")
    assert [(r.original_id, r.title) for r in found] == [("1-intro", "1 Intro"), ("2-more", "2 More")]
    assert "Do the safe thing." in found[0].statement
    assert run(index, "https://cheatsheetseries.owasp.org/Glossary.html") == []
