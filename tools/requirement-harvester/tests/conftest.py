import copy

import pytest
import yaml

from harvester.config import load_config


@pytest.fixture
def raw_config():
    return {
        "config-version": 1,
        "output": {"catalog": "out/catalog.yaml", "report": "out/report.json", "title": "Test requirements", "version": "1"},
        "defaults": {"request-interval-seconds": 0, "max-retries": 0},
        "sources": [{"id": "company", "title": "Company", "start-urls": ["https://example.org/policies/start"],
            "crawl": {"allowed-origins": ["https://example.org"], "allowed-path-prefixes": ["/policies/"]},
            "auth": {"mode": "none"},
            "extraction": {"content-selector": "main", "rules": [{"id": "items", "strategy": "blocks",
                "item-selector": "article", "fields": {"original-id": {"attribute": "id"},
                "title": {"selector": "h2"}, "statement": {"selector": ".statement"}}}]}}],
    }


@pytest.fixture
def config_factory(tmp_path, raw_config):
    def make(data=None):
        path = tmp_path / "config.yaml"
        path.write_text(yaml.safe_dump(copy.deepcopy(data or raw_config)))
        return load_config(path)
    return make


def page(text="The application MUST NOT disclose data.", identifier="REQ-1", links=""):
    return f'<html><main><article id="{identifier}"><h2>Confidentiality</h2><div class="statement">{text}</div></article>{links}</main></html>'.encode()
