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
    raise HarvestError("Harte Laufzeitgrenze erreicht.")


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
        report.update({"status": "aborted", "error": "Durch Benutzer abgebrochen.", "exit-code": code})
    except (OSError, ValueError, TypeError, RecursionError):
        code = 4
        report.update({"status": "failed", "error": "Verarbeitung fehlgeschlagen.", "exit-code": code})
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
    parser = argparse.ArgumentParser(description="Requirements deterministisch aus HTTPS-Seiten nach OSCAL-YAML übertragen.")
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("schema", help="JSON-Schema für die Config ausgeben")
    for name in ("validate", "run", "login"):
        sub = commands.add_parser(name)
        sub.add_argument("--config", required=True, type=Path)
        if name == "run":
            sub.add_argument("--dry-run", action="store_true")
            sub.add_argument("--non-interactive", action="store_true", help="Explizite CI-Kennzeichnung; run fragt grundsätzlich nie nach Eingaben")
        if name == "login":
            sub.add_argument("--source", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "schema":
            print((SCHEMAS / "config.schema.json").read_text(), end="")
            return 0
        cfg = load_config(args.config)
        if args.command == "validate":
            print("Config gültig; kein Netzwerkzugriff ausgeführt.")
            return 0
        if not hasattr(signal, "setitimer"):
            raise ConfigError("Diese Version benötigt Linux/macOS für harte Zeitlimits.")
        previous = signal.signal(signal.SIGALRM, _timeout)
        signal.setitimer(signal.ITIMER_REAL, 300 if args.command == "login" else cfg["defaults"]["max-run-seconds"])
        try:
            if args.command == "login":
                if not sys.stdin.isatty():
                    raise AuthError("login benötigt ein interaktives Terminal.")
                source = next((s for s in cfg["sources"] if s["id"] == args.source), None)
                if source is None:
                    raise ConfigError("Unbekannte Quelle für login.")
                login(source)
                print("Anmeldung gespeichert; Token-Datei ist nur für ihren Eigentümer lesbar.")
                return 0
            return run(cfg, args.dry_run)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous)
    except HarvestError as error:
        print(json.dumps({"error": str(error), "exit-code": error.code}, ensure_ascii=False), file=sys.stderr)
        return error.code
    except KeyboardInterrupt:
        print("Abgebrochen.", file=sys.stderr)
        return 130
    except Exception:
        print('Fehler bei der Verarbeitung; keine Diagnoseinhalte oder Zugangsdaten ausgegeben.', file=sys.stderr)
        return 4
