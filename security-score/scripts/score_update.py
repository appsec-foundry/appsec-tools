"""Self-update through the pipx installation source."""

import argparse
import shutil
import subprocess
import sys

from score_version import version_text

PACKAGE = "appsec-security-score"
# Same pip arguments as the documented forced reinstall: a new commit with an
# unchanged version number must still replace the installed copy.
UPGRADE = [
    "upgrade",
    "--pip-args=--upgrade --force-reinstall --no-cache-dir",
    PACKAGE,
]


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
        status = subprocess.run([pipx, *UPGRADE]).returncode
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
    except KeyboardInterrupt:
        print("Update cancelled.", file=sys.stderr)
        return 130
    return 0


class UpdateAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        parser.exit(update())
