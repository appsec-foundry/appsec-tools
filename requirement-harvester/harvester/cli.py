import argparse
from dataclasses import asdict
import json
from pathlib import Path
import signal
import sys
import time

from . import __version__
from .auth import login
from .config import load_config, SCHEMAS
from .crawl import crawl_source
from .errors import AuthError, ConfigError, HarvestError, OutputError
from .io import atomic_write, write_json, yaml_bytes
from .oscal import build_catalog, now


def _timeout(signum, frame):
    raise HarvestError("Hard run time limit reached.")


def run(cfg, dry_run=False):
    report = {"tool-version": __version__, "started": now(), "status": "running", "dry-run": dry_run,
              "sources": [], "outputs": [{"id": c["id"], "status": "pending"} for c in cfg["catalogs"]]}
    code = 0
    deadline = time.monotonic() + cfg["defaults"]["max-run-seconds"]
    try:
        requirements = []
        for source in cfg["sources"]:
            item = {"source-id": source["id"], "status": "running"}
            report["sources"].append(item)
            requirements.extend(crawl_source(source, deadline, item))
        documents = [(c, yaml_bytes(build_catalog(c, cfg["sources"], requirements))) for c in cfg["catalogs"]]
        if dry_run:
            report["preview"] = [asdict(r) for r in sorted(requirements, key=lambda r: r.id)]
            for out in report["outputs"]:
                out["status"] = "validated-not-written"
        else:
            for (catalog, data), out in zip(documents, report["outputs"]):
                atomic_write(catalog["path"], data)
                out["status"] = "written"
        report.update({"status": "complete", "requirements": len(requirements)})
    except HarvestError as error:
        code = error.code
        report.update({"status": "failed", "error": str(error), "exit-code": code})
        for source in report["sources"]:
            if source["status"] == "running":
                source["status"] = "failed"
    except KeyboardInterrupt:
        code = 130
        report.update({"status": "aborted", "error": "Cancelled by the user.", "exit-code": code})
    except (OSError, ValueError, TypeError, RecursionError):
        code = 4
        report.update({"status": "failed", "error": "Processing failed.", "exit-code": code})
    finally:
        report["finished"] = now()
        # Allow diagnostic output after a hard crawl timeout, but never further crawling.
        signal.setitimer(signal.ITIMER_REAL, 0)
        write_json(cfg["output"]["report"], report)
    if code:
        print(json.dumps({"status": "failed", "error": report["error"], "exit-code": code}, ensure_ascii=False), file=sys.stderr)
    else:
        print(json.dumps({"status": "complete", "requirements": report["requirements"], "catalogs": len(cfg["catalogs"]), "dry-run": dry_run}))
    return code


def main(argv=None):
    parser = argparse.ArgumentParser(description="Deterministically export requirements from HTTPS pages to OSCAL YAML.")
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("schema", help="Print the configuration JSON schema")
    for name in ("validate", "run", "login"):
        sub = commands.add_parser(name)
        sub.add_argument("--config", required=True, type=Path)
        if name == "run":
            sub.add_argument("--dry-run", action="store_true")
            sub.add_argument("--non-interactive", action="store_true", help="Explicit CI marker; run never prompts for input")
        if name == "login":
            sub.add_argument("--source", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "schema":
            print((SCHEMAS / "config.schema.json").read_text(), end="")
            return 0
        cfg = load_config(args.config)
        if args.command == "validate":
            print("Configuration valid; no network access made.")
            return 0
        if not hasattr(signal, "setitimer"):
            raise ConfigError("This version needs Linux or macOS for hard time limits.")
        previous = signal.signal(signal.SIGALRM, _timeout)
        signal.setitimer(signal.ITIMER_REAL, 300 if args.command == "login" else cfg["defaults"]["max-run-seconds"])
        try:
            if args.command == "login":
                if not sys.stdin.isatty():
                    raise AuthError("login needs an interactive terminal.")
                source = next((s for s in cfg["sources"] if s["id"] == args.source), None)
                if source is None:
                    raise ConfigError("Unknown source for login.")
                login(source)
                print("Sign-in saved; the token file is readable only by its owner.")
                return 0
            return run(cfg, args.dry_run)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous)
    except HarvestError as error:
        print(json.dumps({"error": str(error), "exit-code": error.code}, ensure_ascii=False), file=sys.stderr)
        return error.code
    except KeyboardInterrupt:
        print("Cancelled.", file=sys.stderr)
        return 130
    except Exception:
        print('Processing error; no diagnostic content or credentials were printed.', file=sys.stderr)
        return 4
