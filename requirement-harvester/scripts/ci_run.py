#!/usr/bin/env python3
"""Run the real CLI and stage only this run's validated artifacts."""
import json
from pathlib import Path
import sys
import os
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from harvester.cli import main
from harvester.config import load_config
from harvester.errors import HarvestError
from harvester.io import atomic_write, write_json


def execute(config_path, stage):
    stage = Path(stage)
    # Never reuse artifact staging from another execution.
    try:
        stage.mkdir(mode=0o700)
    except OSError:
        print("CI artifact directory must be new and writable.", file=sys.stderr)
        return 5
    try:
        code = main(["run", "--config", str(config_path), "--non-interactive"])
        if code != 0:
            write_json(stage / "report.json", {"status": "failed", "exit-code": code,
                "message": "Run failed; no catalog artifacts published."})
            return code
        cfg = load_config(config_path)
        report = json.loads(Path(cfg["output"]["report"]).read_text())
        if report.get("status") != "complete" or any(o.get("status") != "written" for o in report.get("outputs", [])):
            raise HarvestError("CI run has no complete publication record.")
        # Read everything before publishing any staging file.
        catalogs = [(c["id"], Path(c["path"]).read_bytes()) for c in cfg["catalogs"]]
        with tempfile.TemporaryDirectory(prefix=".pending-", dir=stage) as temporary:
            pending = Path(temporary) / "catalogs"
            for identifier, content in catalogs:
                atomic_write(pending / (identifier + ".oscal.yaml"), content)
            write_json(stage / "report.json", report)
            os.replace(pending, stage / "catalogs")
        return 0
    except (HarvestError, OSError, ValueError):
        write_json(stage / "report.json", {"status": "failed", "message": "CI output could not be staged."})
        return 5


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python scripts/ci_run.py CONFIG")
    raise SystemExit(execute(sys.argv[1], Path.cwd() / "ci-artifacts"))
