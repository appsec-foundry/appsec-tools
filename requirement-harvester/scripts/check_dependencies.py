#!/usr/bin/env python3
"""Check pinned versions against PyPI's published vulnerability records.

No dependency execution or installation. Network failure is a failed check.
This is a known-advisory check, not proof of absence of vulnerabilities.
"""
import json
from pathlib import Path
import re
import sys
import urllib.request


def main():
    root = Path(__file__).resolve().parents[1]
    pins = re.findall(r"^([A-Za-z0-9_.-]+)==([A-Za-z0-9.+-]+)", (root / "requirements-dev.lock").read_text(), re.M)
    failed = False
    for name, version in pins:
        try:
            with urllib.request.urlopen(f"https://pypi.org/pypi/{name}/{version}/json", timeout=30) as response:
                raw = response.read(4 * 1024 * 1024 + 1)
            if len(raw) > 4 * 1024 * 1024:
                raise ValueError()
            data = json.loads(raw)
            advisories = data.get("vulnerabilities", [])
            if advisories:
                print(f"{name}=={version}: bekannte Sicherheitsmeldung(en): {len(advisories)}")
                failed = True
        except Exception:
            print(f"{name}=={version}: Prüfung nicht möglich")
            failed = True
    if not failed:
        print(f"{len(pins)} Paketversionen geprüft; keine von PyPI gemeldeten Schwachstellen.")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
