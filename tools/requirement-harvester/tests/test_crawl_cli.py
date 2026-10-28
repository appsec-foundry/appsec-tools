import copy
import json
from pathlib import Path
import time

import pytest
import yaml

from conftest import page
from harvester import cli, crawl
from harvester.cli import main
from harvester.crawl import crawl_source
from harvester.errors import HarvestError
from harvester.http import Response
from harvester.oscal import validate_catalog


def fixture_transport(pages, calls):
    class Transport:
        def __init__(self, scope, limits, budget, ca_bundle=None):
            self.scope, self.budget = scope, budget
        def fetch(self, url, headers):
            self.scope.require(url)
            self.budget.request()
            calls.append(url)
            if url not in pages:
                raise HarvestError("Testquelle nicht verfügbar.")
            return Response(200, {"content-type": "text/html"}, pages[url], url)
    return Transport


@pytest.mark.parametrize("depth,count", [(0, 1), (1, 2), (2, 3), (None, 3)])
def test_depth_breadth_first_and_cycles(config_factory, depth, count):
    source = config_factory()["sources"][0]
    source["limits"]["max-depth"] = depth
    base = "https://example.org/policies/"
    pages = {base + "start": page(identifier="R1", links='<a href="two">next</a><a href="https://evil.example/">skip</a>'),
             base + "two": page(identifier="R2", links='<a href="three">next</a><a href="start">cycle</a>'),
             base + "three": page(identifier="R3")}
    calls, report = [], {}
    rows = crawl_source(source, time.monotonic() + 30, report, fixture_transport(pages, calls))
    assert len(rows) == count
    assert len(calls) == len(set(calls)) == count
    assert report["excluded-count"] == 1


def test_multiple_start_pages_shortest_path(config_factory):
    source = config_factory()["sources"][0]
    base = "https://example.org/policies/"
    source["start-urls"] += [base + "three"]
    source["limits"]["max-depth"] = 1
    pages = {base + "start": page(identifier="R1", links='<a href="two">next</a>'),
             base + "two": page(identifier="R2", links='<a href="three">next</a>'),
             base + "three": page(identifier="R3", links='<a href="four">next</a>'),
             base + "four": page(identifier="R4")}
    calls, report = [], {}
    assert len(crawl_source(source, time.monotonic() + 30, report, fixture_transport(pages, calls))) == 4
    assert next(p for p in report["pages"] if p["url"].endswith("three"))["depth"] == 0


def test_conflict_and_budget(config_factory):
    source = config_factory()["sources"][0]
    a = source["start-urls"][0]
    b = a + "-next"
    pages = {a: page("First", links=f'<a href="{b}">next</a>'), b: page("Conflict")}
    with pytest.raises(HarvestError, match="Widersprüchliche"):
        crawl_source(source, time.monotonic() + 30, {}, fixture_transport(pages, []))
    source["limits"]["max-pages"] = 1
    with pytest.raises(HarvestError, match="Seitenbudget"):
        crawl_source(source, time.monotonic() + 30, {}, fixture_transport(pages, []))


def test_cli_full_run_dry_run_and_failure(raw_config, config_factory, tmp_path, monkeypatch):
    cfg = config_factory(raw_config)
    url = cfg["sources"][0]["start-urls"][0]
    pages, calls = {url: page()}, []
    factory = fixture_transport(pages, calls)
    monkeypatch.setattr(cli, "crawl_source", lambda source, deadline, report: crawl_source(source, deadline, report, factory))
    args = ["--config", str(tmp_path / "config.yaml")]
    assert main(["validate", *args]) == 0
    assert calls == []
    assert main(["run", *args, "--non-interactive"]) == 0
    output = Path(cfg["catalogs"][0]["path"])
    before = output.read_bytes()
    validate_catalog(yaml.safe_load(before))
    assert output.stat().st_mode & 0o077 == 0
    assert main(["run", *args, "--dry-run"]) == 0
    assert output.read_bytes() == before
    report = json.loads(Path(cfg["output"]["report"]).read_text())
    assert report["preview"][0]["statement"]
    pages.clear()
    assert main(["run", *args, "--non-interactive"]) == 4
    assert output.read_bytes() == before
    report = json.loads(Path(cfg["output"]["report"]).read_text())
    assert report["status"] == "failed"
    assert report["outputs"][0]["status"] == "pending"


def test_rebuild_removes_manual_and_deleted_requirements(raw_config, config_factory, tmp_path, monkeypatch):
    cfg = config_factory(raw_config)
    url = cfg["sources"][0]["start-urls"][0]
    pages = {url: page()}
    factory = fixture_transport(pages, [])
    monkeypatch.setattr(cli, "crawl_source", lambda s, d, r: crawl_source(s, d, r, factory))
    args = ["run", "--config", str(tmp_path / "config.yaml")]
    assert main(args) == 0
    output = Path(cfg["catalogs"][0]["path"])
    output.write_text("manual edit")
    pages[url] = page("New requirement", "NEW")
    assert main(args) == 0
    doc = yaml.safe_load(output.read_text())
    validate_catalog(doc)
    text = output.read_text()
    assert "manual edit" not in text and "REQ-1" not in text and "New requirement" in text


def test_multi_output_crawls_source_once(raw_config, config_factory, monkeypatch):
    raw_config["output"] = {"report": "out/report.json", "catalogs": [
        {"id": "a", "path": "out/a.yaml", "title": "A", "version": "1", "source-ids": ["company"]},
        {"id": "b", "path": "out/b.yaml", "title": "B", "version": "1", "source-ids": ["company"]}]}
    cfg = config_factory(raw_config)
    url = cfg["sources"][0]["start-urls"][0]
    calls = []
    factory = fixture_transport({url: page()}, calls)
    monkeypatch.setattr(cli, "crawl_source", lambda s, d, r: crawl_source(s, d, r, factory))
    assert cli.run(cfg) == 0
    assert calls == [url]
    for c in cfg["catalogs"]:
        validate_catalog(yaml.safe_load(Path(c["path"]).read_text()))


def test_missing_credentials_fails_noninteractive(raw_config, config_factory, tmp_path, capsys):
    raw_config["sources"][0]["auth"] = {"mode": "token", "token-env": "NONEXISTENT_TEST_CREDENTIAL"}
    config_factory(raw_config)
    assert main(["run", "--config", str(tmp_path / "config.yaml"), "--non-interactive"]) == 3
    assert "Traceback" not in capsys.readouterr().err
