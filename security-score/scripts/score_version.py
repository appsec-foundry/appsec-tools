"""Release identity, embedded during packaging or read from the source checkout."""

import argparse
from pathlib import Path
import re
import subprocess


def source_identity(root=None):
    root = root or Path(__file__).resolve().parent.parent
    manifest = root / "pyproject.toml"
    release = "unknown"
    if manifest.is_file():
        match = re.search(
            r'^version\s*=\s*"([0-9A-Za-z.+-]+)"\s*$', manifest.read_text(), re.M
        )
        if match:
            release = match[1]
    commit, dirty = "unknown", False
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--verify", "HEAD"],
            capture_output=True,
            text=True,
            timeout=2,
            check=True,
        )
        if re.fullmatch(r"[0-9a-f]{40}(?:[0-9a-f]{24})?", result.stdout.strip()):
            commit = result.stdout.strip()
            status = subprocess.run(
                [
                    "git",
                    "-C",
                    str(root),
                    "status",
                    "--porcelain",
                    "--untracked-files=no",
                    "--",
                    ".",
                ],
                capture_output=True,
                text=True,
                timeout=2,
                check=True,
            )
            dirty = bool(status.stdout)
    except (OSError, subprocess.SubprocessError):
        pass
    return {"version": release, "commit": commit, "dirty": dirty}


def identity():
    try:
        from _security_score_build import BUILD
    except ImportError:
        return source_identity()
    return BUILD


def version_text():
    build = identity()
    modified = "; modified checkout" if build["dirty"] else ""
    return f"security-score {build['version']} (commit {build['commit']}{modified})"


class VersionAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        print(version_text())
        parser.exit()
