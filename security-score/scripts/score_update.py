"""Self-update through the pipx installation source."""

import argparse
from importlib import metadata
import json
from pathlib import Path
import shutil
import subprocess
import sys
from urllib.parse import urlsplit
from urllib.request import url2pathname

from score_version import version_text

PACKAGE = "appsec-security-score"
# Same pip arguments as the documented forced reinstall: a new commit with an
# unchanged version number must still replace the installed copy.
PIP_ARGS = "--pip-args=--upgrade --force-reinstall --no-cache-dir"


def update_arguments():
    """Recover local sources from pip's absolute installation provenance."""
    try:
        provenance = metadata.distribution(PACKAGE).read_text("direct_url.json")
    except metadata.PackageNotFoundError:
        provenance = None
    if not provenance:
        return ["upgrade", PIP_ARGS, PACKAGE]
    direct = json.loads(provenance)
    if not isinstance(direct, dict):
        raise ValueError("invalid installation provenance")
    if "dir_info" not in direct:
        return ["upgrade", PIP_ARGS, PACKAGE]
    if not isinstance(direct["dir_info"], dict) or not isinstance(direct.get("url"), str):
        raise ValueError("invalid local installation provenance")
    url = urlsplit(direct["url"])
    source = Path(url2pathname(url.path))
    if (
        url.scheme != "file"
        or url.netloc not in ("", "localhost")
        or url.query
        or url.fragment
        or not source.is_absolute()
        or not source.is_dir()
    ):
        raise ValueError("local installation source is unavailable")
    # Older pipx versions record relative paths verbatim. Replace that source
    # with its absolute path so this and subsequent upgrades are cwd-independent.
    arguments = ["install", "--force", PIP_ARGS]
    if direct["dir_info"].get("editable"):
        arguments.append("--editable")
    return [*arguments, str(source)]


def update():
    pipx = shutil.which("pipx")
    if not pipx:
        print(
            f"pipx not found on PATH. Update manually: pipx upgrade {PACKAGE}",
            file=sys.stderr,
        )
        return 1
    print(f"Installed: {version_text()}", flush=True)
    try:
        arguments = update_arguments()
        status = subprocess.run([pipx, *arguments]).returncode
        if status:
            print(
                f"Update failed (pipx exit status {status}); the installed version is unchanged or must be repaired with the forced installation from the README.",
                file=sys.stderr,
            )
            return status
        # The running process still holds the old code: ask the new entry point.
        entry = shutil.which("security-score")
        if entry:
            print("Now installed: ", end="", flush=True)
            subprocess.run([entry, "--version"])
    except (OSError, ValueError):
        print(
            "Update failed: installation source could not be read or used. "
            "Repair with the forced installation from the README.",
            file=sys.stderr,
        )
        return 1
    except KeyboardInterrupt:
        print("Update cancelled.", file=sys.stderr)
        return 130
    return 0


class UpdateAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        parser.exit(update())
