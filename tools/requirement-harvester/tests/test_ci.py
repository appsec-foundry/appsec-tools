import importlib.util
import json
from pathlib import Path

import pytest
import yaml

from conftest import page
from harvester import cli
from harvester.crawl import crawl_source
from harvester.errors import OutputError
from test_crawl_cli import fixture_transport

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("ci_run", ROOT / "scripts" / "ci_run.py")
ci = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ci)


def test_templates_use_real_entrypoint_and_restrict_artifacts():
    gitlab = yaml.safe_load((ROOT / "ci/gitlab-ci.yml").read_text())
    github = yaml.load((ROOT / "ci/github-actions.yml").read_text(), Loader=yaml.BaseLoader)
    job = gitlab["harvest-requirements"]
    assert job["artifacts"]["access"] == "maintainer"
    assert job["environment"]["name"] == "requirement-harvest"
    assert all('CI_COMMIT_REF_PROTECTED' in r['if'] for r in job['rules'] if 'if' in r)
    assert "pull_request_target" not in github["on"]
    assert github["permissions"] == {"contents": "read"}
    harvest = github["jobs"]["harvest"]
    assert "repository.private" in harvest["if"] and "default_branch" in harvest["if"]
    for workflow_job in github["jobs"].values():
        for step in workflow_job["steps"]:
            if "uses" in step:
                ref = step["uses"].split("@")[1]
                assert len(ref) == 40 and all(c in "0123456789abcdef" for c in ref)
    assert any("scripts/ci_run.py" in s.get("run", "") for s in harvest["steps"])
    assert any("scripts/ci_run.py" in line for line in job["script"])


def test_ci_stages_only_successful_current_catalogs(config_factory, tmp_path, monkeypatch):
    cfg = config_factory()
    source = cfg["sources"][0]
    pages = {source["start-urls"][0]: page()}
    factory = fixture_transport(pages, [])
    monkeypatch.setattr(cli, "crawl_source", lambda s, d, r: crawl_source(s, d, r, factory))
    config_path = tmp_path / "config.yaml"
    assert ci.execute(config_path, tmp_path / "success") == 0
    assert len(list((tmp_path / "success/catalogs").glob("*.yaml"))) == 1
    # The old real output remains, but is never staged by a failed run.
    pages.clear()
    assert ci.execute(config_path, tmp_path / "failure") == 4
    assert not (tmp_path / "failure/catalogs").exists()
    assert json.loads((tmp_path / "failure/report.json").read_text())["status"] == "failed"
    assert ci.execute(config_path, tmp_path / "success") == 5


def test_no_partial_catalog_staging(config_factory, tmp_path, monkeypatch):
    cfg = config_factory()
    factory = fixture_transport({cfg["sources"][0]["start-urls"][0]: page()}, [])
    monkeypatch.setattr(cli, "crawl_source", lambda s, d, r: crawl_source(s, d, r, factory))
    monkeypatch.setattr(ci, "atomic_write", lambda *a: (_ for _ in ()).throw(OutputError("synthetic failure")))
    assert ci.execute(tmp_path / "config.yaml", tmp_path / "artifacts") == 5
    assert not (tmp_path / "artifacts/catalogs").exists()
