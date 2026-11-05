#!/usr/bin/env python3
"""Standalone security score. Requires only Python 3.10+; Git for comparisons."""

from __future__ import annotations

import argparse
import contextlib
from collections import Counter
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import sys
import time
import threading
from urllib.parse import urlsplit
from score_update import UpdateAction
import score_version
from score_version import VersionAction

try:
    from score_core import (
        CATALOG_HASH,
        IMPLEMENTATION_HASH,
        POLICY,
        RULES,
        RULE_VERSION,
        ScanLimit,
        VERSION,
        calculate,
        check_groups,
        compare,
        grade,
        scan,
        scan_paths,
        selected_rules,
    )
except (
    OSError,
    ValueError,
    KeyError,
    TypeError,
    AttributeError,
    RecursionError,
    re.error,
):
    if not any(flag in sys.argv[1:] for flag in ("--quiet", "--quite")):
        print(
            "Invalid bundled rule catalog. Check rules.json and the scoring policy before running again.",
            file=sys.stderr,
        )
    raise SystemExit(1) from None
from score_sources import (
    Budget,
    SourceError,
    command,
    excluded,
    fingerprint,
    repository_paths,
    select,
)
from score_reporting import (
    explain as explain_observations,
    plural,
    render_repository,
    wrapped,
)
from score_style import Style, safe
from score_architecture import describe
from score_relevance import VERSION as RELEVANCE_VERSION, analyze as analyze_relevance
from score_remote import (
    NetworkStats,
    host_settings,
    select_token,
    repository_url,
    select_remote,
    settings_checks,
)


class Progress:
    """Write steps and a delayed spinner, using plain lines off a terminal."""

    def __init__(self, enabled=True):
        self.enabled = enabled
        self.timer = None
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.stream = sys.stderr
        self.terminal = self.stream.isatty() and os.environ.get("TERM") != "dumb"
        self.message = "Security checks are running..."

    def step(self, message):
        """A terminal keeps one status line that __exit__ clears; other streams log lines."""
        if self.enabled:
            with self.lock:
                self.message = message
                if self.terminal:
                    print("\r\033[K" + message, end="", file=self.stream, flush=True)
                else:
                    print(message, file=self.stream, flush=True)

    def animate(self):
        if not self.terminal:
            self.step("Security checks are running...")
            return
        index = 0
        frames = ("|", "/", "-", "\\")
        while not self.stop.is_set():
            with self.lock:
                print(
                    f"\r\033[K{frames[index % 4]} {self.message}",
                    end="",
                    file=self.stream,
                    flush=True,
                )
            index += 1
            self.stop.wait(0.1)

    def __enter__(self):
        if not self.enabled:
            return self
        self.timer = threading.Timer(1.0, self.animate)
        self.timer.daemon = True
        self.timer.start()
        return self

    def __exit__(self, *args):
        if self.timer is not None:
            self.stop.set()
            self.timer.cancel()
            self.timer.join()
            if self.terminal:
                print("\r\033[K", end="", file=self.stream, flush=True)


def announce(options, message):
    step = getattr(options, "step", None)
    if step:
        step(message)


def parser():
    result = argparse.ArgumentParser(
        prog="security-score",
        description="Repository security score (0–100) or change security relevance; no model calls."
    )
    result.add_argument(
        "--version",
        action=VersionAction,
        nargs=0,
        help="Show package version and source commit, then exit",
    )
    result.add_argument(
        "--update",
        action=UpdateAction,
        nargs=0,
        help="Reinstall the latest version from the pipx installation source, then exit",
    )
    result.add_argument(
        "repository",
        nargs="?",
        help="Local source directory or HTTPS GitHub/GitLab URL; defaults to the current directory",
    )
    result.add_argument("--repo", help="Alternative local repository selection")
    scoring = result.add_mutually_exclusive_group()
    scoring.add_argument(
        "--score", action="store_true",
        help="Compatibility alias for the default repository score",
    )
    scoring.add_argument(
        "--legacy-score", action="store_true",
        help="Show the previous single repository score (0–100/A–F)",
    )
    result.add_argument(
        "--detail",
        "--details",
        dest="details",
        action="store_true",
        help="Show category subscores, grouped findings, coverage and change relevance",
    )
    result.add_argument(
        "--token-env",
        help="Explicit read-only API token environment variable; overrides host mappings and the GIT_TOKEN fallback; URL requests only",
    )
    result.add_argument(
        "--list-rules",
        action="store_true",
        help="Show the rule catalog without scanning",
    )
    result.add_argument(
        "--list-checks",
        action="store_true",
        help="List selectable check groups and their rule IDs, then exit",
    )
    result.add_argument(
        "--checks", help="Run comma-separated check groups or rule IDs (default: all)"
    )
    result.add_argument(
        "--skip-checks",
        help="Omit comma-separated check groups or rule IDs from the selection",
    )
    result.add_argument(
        "--engine",
        choices=("internal", "analyzer"),
        default="internal",
        help="Scoring engine; the optional Analyzer must be installed separately (default: internal)",
    )
    result.add_argument(
        "--analyzer", help="Trusted operator-selected absolute Analyzer executable"
    )
    selection = result.add_mutually_exclusive_group()
    selection.add_argument(
        "--patch",
        "--diff",
        dest="patch",
        help="UTF-8 unified patch; paths are never opened",
    )
    selection.add_argument("--base", help="Base revision for a local Git comparison")
    selection.add_argument("--commit", help="Compare a commit with its first parent")
    selection.add_argument(
        "--staged", action="store_true", help="HEAD versus staged changes"
    )
    selection.add_argument(
        "--unstaged", action="store_true", help="Index versus unstaged working files"
    )
    selection.add_argument(
        "--worktree",
        action="store_true",
        help="HEAD versus working files, including untracked files",
    )
    result.add_argument(
        "--head", help="Proposed revision with --base; defaults to HEAD"
    )
    remote = result.add_mutually_exclusive_group()
    remote.add_argument(
        "--pr",
        help="Selected GitHub PR URL; supply its patch or local base/head comparison",
    )
    remote.add_argument(
        "--mr",
        help="Selected GitLab MR URL; supply its patch or local base/head comparison",
    )
    formatting = result.add_mutually_exclusive_group()
    formatting.add_argument("--json", action="store_true")
    formatting.add_argument("--yaml", action="store_true")
    formatting.add_argument(
        "--quiet",
        "--quite",
        dest="quiet",
        action="store_true",
        help="Print only the numeric index; no progress or diagnostics. Exit status retains completeness.",
    )
    result.add_argument(
        "--timeout",
        type=float,
        default=60,
        help="Total execution budget in seconds, 0.1–120 (default: 60)",
    )
    result.add_argument(
        "--verify-rules",
        action="store_true",
        help="Run the bundled positive/negative rule examples without scanning",
    )
    return result


def remote_identity(options):
    value = options.pr or options.mr
    if not value:
        return None
    parsed = urlsplit(value)
    host = "github.com" if options.pr else "gitlab.com"
    pattern = (
        r"/[\w.-]+/[\w.-]+/pull/[1-9]\d*"
        if options.pr
        else r"/(?:[\w.-]+/)+[\w.-]+/-/merge_requests/[1-9]\d*"
    )
    if (
        parsed.scheme != "https"
        or parsed.netloc != host
        or parsed.query
        or parsed.fragment
        or not re.fullmatch(pattern, parsed.path)
    ):
        raise SourceError(
            "Select a canonical HTTPS GitHub PR or GitLab MR URL without credentials or query parameters."
        )
    if not options.patch and not options.base:
        raise SourceError(
            "Retrieve the selected PR/MR through an authorized host tool and supply --patch or --base/--head. No implicit network retrieval is performed."
        )
    return value


def yaml_text(value, indent=0):
    """JSON-quoted scalars form a safe YAML 1.2 subset without dependencies."""
    space = " " * indent
    if isinstance(value, dict) and value:
        rows = []
        for key, child in value.items():
            name = json.dumps(str(key), ensure_ascii=True)
            if isinstance(child, (dict, list)) and child:
                rows.append(f"{space}{name}:\n{yaml_text(child, indent + 2)}")
            else:
                rows.append(
                    f"{space}{name}: {json.dumps(child, ensure_ascii=True, allow_nan=False)}"
                )
        return "\n".join(rows)
    if isinstance(value, list) and value:
        return "\n".join(
            f"{space}-\n{yaml_text(child, indent + 2)}"
            if isinstance(child, (dict, list)) and child
            else f"{space}- {json.dumps(child, ensure_ascii=True, allow_nan=False)}"
            for child in value
        )
    return space + json.dumps(value, ensure_ascii=True, allow_nan=False)


def render(result, details=False, style=None):
    style = style or Style()
    if result.get("analysis") == "security-assessment":
        from score_assessment import render as render_assessment

        return render_assessment(result, details, style)
    if result.get("analysis") == "change-relevance":
        return render_change(result, details, style)
    if result["score"] is None and result.get("observed_score") is not None:
        summary, shade = (
            f"{result['observed_score']}/100 (partial)",
            result["observed_score"],
        )
    elif result["score"] is not None:
        summary, shade = f"{result['score']}/100 ({result['grade']})", result["score"]
    else:
        summary, shade = result["verdict"], None
    if not details:
        return style.paint(summary, style.band(shade), "bold")
    if result["engine"] == "analyzer":
        lines = [
            f"Security score {style.dot} {result['engine']} {style.dot} version {result['scoring_version']}",
            style.paint(summary, style.band(shade), "bold"),
            "Limited scanner indication; no security approval or verified exploitability.",
        ]
        for entry in result.get("host_settings", []):
            lines.append(
                f"Host {entry['setting']}: {entry['status']} {style.dot} {entry['reason']}"
            )
        lines += [
            "Analyzer result (separate scoring policy):",
            json.dumps(result["analyzer_result"], indent=2, ensure_ascii=True),
        ]
        return "\n".join(lines)
    return render_repository(result, summary, style)


def signal_groups(signals):
    """One block per rule: the reason is stated once, locations are listed per file."""
    groups = {}
    for signal in signals:
        groups.setdefault(signal["rule"], []).append(signal)
    order = {"high": 0, "medium": 1, "low": 2}
    return sorted(
        groups.items(),
        key=lambda pair: (order.get(pair[1][0]["level"], 3), -len(pair[1]), pair[0]),
    )


def file_locations(signals, limit=4):
    """Baseline and proposed signals on one line are one location; line 0 is a whole file."""
    files = {}
    for signal in signals:
        files.setdefault(signal["file"], set()).add(signal["line"])
    rows = []
    for path, numbers in sorted(files.items()):
        numbers = sorted(number for number in numbers if number)
        shown = ", ".join(str(number) for number in numbers[:limit])
        more = f" (+{len(numbers) - limit} more)" if len(numbers) > limit else ""
        rows.append(safe(path) + (f":{shown}{more}" if numbers else ""))
    return rows


def location_count(signals):
    return len({(signal["file"], signal["line"]) for signal in signals})


def render_change(result, details=False, style=None):
    style = style or Style()
    counts = result["finding_changes"]
    status = f"incomplete {style.dot} " if result["verdict"] == "incomplete" else ""
    level = result["relevance"]
    summary = (
        f"{status}Security relevance: {style.severity(level, level)} {style.dot} "
        f"{counts.get('introduced', 0)} introduced, {counts.get('worsened', 0)} worsened findings"
    )
    if not details:
        return summary
    scope = result["scope"]
    indent = " " * 10
    lines = [
        summary,
        f"Scope: {scope['selection']} {style.dot} {safe(scope['repository'])}",
    ]
    if "base" in scope:
        lines.append(
            f"Comparison: {safe(scope['base'])[:12]} {style.arrow} {safe(scope['head'])[:12]}"
        )
    if "remote_selection" in scope:
        lines.append(f"PR/MR: {safe(scope['remote_selection'])}")
        lines.append(f"Context: {safe(scope['remote_validation'])}")
    lines += [
        style.paint(line, "dim")
        for line in wrapped(
            "Security relevance identifies review needs; finding severity is reported separately. "
            "It rates changed security behavior, not detected weaknesses.",
            style.width,
            "",
        )
    ]
    signals = result["signals"]
    if signals:
        files = len({signal["file"] for signal in signals})
        lines += [
            "",
            style.paint(
                f"Review signals ({plural(location_count(signals), 'location')} in {plural(files, 'file')})",
                "bold",
            ),
        ]
        for rule, group in signal_groups(signals):
            first = group[0]
            lines.append(
                f"{style.tag(first['level'])}  "
                f"{first['aspect'][:1].upper() + first['aspect'][1:]} "
                + style.paint(
                    f"({rule}, {plural(location_count(group), 'location')})", "dim"
                )
            )
            lines += [
                indent + line for line in wrapped(first["reason"], style.width - 10, "")
            ]
            rows = file_locations(group)
            lines += [style.paint(indent + row, "dim") for row in rows[:5]]
            if len(rows) > 5:
                lines.append(style.paint(f"{indent}+{len(rows) - 5} more files", "dim"))
    if result["findings"]:
        lines += ["", style.paint(f"Findings ({len(result['findings'])})", "bold")]
        for finding in result["findings"]:
            lines.append(
                f"{style.tag(finding['severity'])}  "
                f"{safe(finding['title'])} "
                + style.paint(f"({finding['change']}, {finding['rule']})", "dim")
            )
            lines.append(
                style.paint(f"{indent}{safe(finding['file'])}:{finding['line']}", "dim")
            )
            lines += [
                indent + line
                for line in wrapped(
                    f"Next: {finding['next_action']}", style.width - 10, ""
                )
            ]
    coverage = result["coverage"]
    outcomes = coverage.get("check_outcomes", {})
    lines += ["", style.paint("Coverage", "bold")]
    lines.append(
        f"  {plural(len(coverage.get('changed_files', [])), 'file')} changed"
        + (
            f" {style.dot} {len(coverage['nonfunctional_or_documentation'])} documentation"
            if coverage.get("nonfunctional_or_documentation")
            else ""
        )
        + (
            f" {style.dot} {len(coverage['unclassified_files'])} not classified"
            if coverage.get("unclassified_files")
            else ""
        )
    )
    if outcomes:
        lines.append(
            "  Checks: "
            + f" {style.dot} ".join(
                f"{count} {name.replace('_', ' ')}" for name, count in outcomes.items()
            )
        )
    if coverage.get("signals_truncated"):
        lines.append("  Signal list truncated; --json has the retained evidence.")
    if coverage.get("context_limited_files"):
        lines.append(
            "  Limited context: "
            + ", ".join(safe(name) for name in coverage["context_limited_files"])
        )
    lines.append("")
    for warning in result["warnings"]:
        lines += [
            style.paint(line, "dim")
            for line in wrapped(safe(warning), style.width, "  ")
        ]
    lines.append(
        style.paint(
            f"  Rule version {result['rule_version']} {style.dot} relevance version {result['relevance_version']}"
            f" {style.dot} per-signal side, relation and coverage basis: --json",
            "dim",
        )
    )
    return "\n".join(lines)


def analyzer_score(options, budget):
    if any(
        (
            options.patch,
            options.base,
            options.head,
            options.commit,
            options.staged,
            options.unstaged,
            options.worktree,
            options.pr,
            options.mr,
        )
    ):
        raise SourceError(
            "The Analyzer variant supports repository scoring only; use the internal variant for changes."
        )
    is_url = options.repo.startswith("https://")
    if is_url:
        host, project = repository_url(options.repo)
        if host not in {"github.com", "gitlab.com"}:
            raise SourceError("Self-managed GitLab URLs require the internal engine.")
        root = None
        target = "https://" + host + "/" + project + ".git"
    else:
        root = Path(options.repo).expanduser().resolve(strict=True)
        target = str(root)
        if options.token_env:
            raise SourceError("--token-env requires an explicitly selected Git URL.")
    executable = Path(options.analyzer or shutil.which("appsec-analyzer") or "")
    if (
        not executable.is_absolute()
        or not executable.is_file()
        or not os.access(executable, os.X_OK)
    ):
        raise SourceError(
            "Select an installed compatible Analyzer; it is optional and never installed automatically."
        )
    executable = executable.resolve()
    if root is not None and executable.is_relative_to(root):
        raise SourceError(
            "An analyzed repository cannot supply the Analyzer executable."
        )
    for operation in ("version", "capabilities"):
        _, raw = command([str(executable), operation], budget, limit=65536)
        document = json.loads(raw)
        if not isinstance(document, dict) or document.get("interface_version") != 1:
            raise SourceError("Analyzer public interface 1 is required.")
        if operation == "capabilities":
            capability = document.get("score", {})
            if (
                not isinstance(capability, dict)
                or capability.get("available") is not True
                or capability.get("model_calls") is not False
                or capability.get("scoring_version") != 2
            ):
                raise SourceError(
                    "Analyzer scoring version 2 without model calls is required."
                )
    announce(options, "Running the selected Analyzer variant...")
    settings = (
        host_settings(host, project, budget, select_token(host, options.token_env))[0]
        if is_url
        else []
    )
    status, raw = command(
        [str(executable), "score", target, "--json"], budget, allow_failure=True
    )
    document = json.loads(raw)
    if not isinstance(document, dict):
        raise SourceError("Analyzer returned an invalid result.")
    verdict, score = document.get("verdict"), document.get("score")
    if verdict not in {"scored", "incomplete", "undetermined"}:
        raise SourceError("Analyzer did not return a supported result status.")
    if verdict == "scored":
        if type(score) is not int or not 0 <= score <= 100 or status != 0:
            raise SourceError("Analyzer returned an invalid numeric score.")
    elif score is not None or status != (2 if verdict == "undetermined" else 1):
        raise SourceError("Analyzer status and result disagree.")
    identity = document.get("comparability")
    if not isinstance(identity, dict) or identity.get("scoring_version") != 2:
        raise SourceError("Analyzer score identity is missing or incompatible.")
    return {
        "engine": "analyzer",
        "scoring_version": 2,
        "verdict": verdict,
        "score": score,
        "grade": grade(score),
        "analyzer_result": document,
        "host_settings": settings,
    }, status


def verify_rules():
    cases = 0
    for rule in RULES:
        for example in rule["examples"]:
            if rule["kind"] == "host":
                findings, checks = settings_checks(
                    [{**example, "reason": "Isolated example."}]
                )
            elif rule["kind"] in {"path", "dependency-lock"}:
                findings, checks = scan_paths(
                    [example["file"], *example.get("paths", [])],
                    [],
                    [],
                    {example["file"]: {"text": example.get("source", "")}},
                )
                checks.append(
                    {
                        "rule": rule["id"],
                        "area": rule["area"],
                        "status": "not_applicable",
                    }
                )
            else:
                files = {
                    path: {"text": text}
                    for path, text in example.get("files", {}).items()
                }
                files[example["file"]] = {"text": example["source"]}
                findings, checks = scan(files, Budget())
            row = next(item for item in checks if item["rule"] == rule["id"])
            if row["status"] != example["outcome"]:
                raise SourceError(
                    f"Rule example failed: {rule['id']} / {example['outcome']}."
                )
            effect = calculate(
                [finding for finding in findings if finding["rule"] == rule["id"]],
                [row],
            )
            if (
                effect["score"] != example["expected_score"]
                or effect["grade"] != example["expected_grade"]
            ):
                raise SourceError(f"Rule score example failed: {rule['id']}.")
            cases += 1
    for example in POLICY["change_relevance"]["examples"]:
        filename = example["file"]
        before = {
            filename: {
                "text": example["before"],
                "executable": example.get("before_executable", False),
            }
        }
        after = {
            filename: {
                "text": example["after"],
                "executable": example.get("after_executable", False),
            }
        }
        old_findings, old_checks = scan(before, Budget())
        findings, checks = scan(after, Budget())
        checks = [
            {**row, "side": side}
            for side, rows in (("baseline", old_checks), ("proposed", checks))
            for row in rows
        ]
        assessment = analyze_relevance(
            before, after, checks, compare(old_findings, findings), [], Budget()
        )
        if assessment["relevance"] != example["expected_relevance"]:
            raise SourceError(f"Relevance example failed for {filename}.")
    return {
        "engine": "internal",
        "scoring_version": VERSION,
        "rule_version": RULE_VERSION,
        "relevance_version": RELEVANCE_VERSION,
        "rules_verified": len(RULES),
        "examples_verified": cases,
        "catalog_fingerprint": CATALOG_HASH,
        "relevance_examples_verified": len(POLICY["change_relevance"]["examples"]),
    }


def repository_context(options, scope, files, exclusions, budget):
    """What only --details shows; it runs after the score and cannot change it."""
    from score_overview import (
        history_summary,
        local_history,
        remote_history,
        repository_overview,
    )

    listed = not any(row["file"] == "repository-tree" for row in exclusions)
    paths = [
        path
        for path in repository_paths(files, exclusions)
        if path != "repository-tree"
    ]
    overview = repository_overview(files, paths, listed, budget)
    remote = scope["selection"] == "git-url"
    try:
        rows, head, branches = (
            remote_history(options, scope["revision"], budget)
            if remote
            else local_history(Path(options.repo).expanduser().resolve(), budget)
        )
        history = history_summary(
            rows, head, branches, "default branch" if remote else "HEAD"
        )
    except SourceError as error:
        history = {"unavailable": str(error)}
    overview["development"]["history"] = history
    return overview


def run(options):
    budget = Budget(options.timeout)
    if options.list_checks:
        return {"default": "all", "check_groups": check_groups()}, 0
    try:
        rules = selected_rules(options.checks, options.skip_checks)
    except ValueError as error:
        raise SourceError(str(error)) from None
    active_ids = {rule["id"] for rule in rules}
    custom_checks = active_ids != {rule["id"] for rule in RULES}
    if options.verify_rules:
        return verify_rules(), 0
    if options.list_rules:
        return {
            "scoring_version": VERSION,
            "rule_version": RULE_VERSION,
            "change_relevance": POLICY["change_relevance"],
            "scoring": POLICY["scoring"],
            "rules": RULES,
        }, 0
    if options.engine == "analyzer":
        return analyzer_score(options, budget)
    if options.analyzer:
        raise SourceError("--analyzer requires --engine analyzer.")
    if options.details and not options.quiet:
        budget.network = NetworkStats()
    remote = remote_identity(options)
    if options.details:
        announce(options, f"Preparing scan: {len(rules)} selected checks...")
    announce(options, "Reading selected sources...")
    settings = []
    if "://" in options.repo:
        before, after, exclusions, scope, verify, settings = select_remote(
            options, budget
        )
    else:
        if options.token_env:
            raise SourceError("--token-env requires an explicitly selected Git URL.")
        before, after, exclusions, scope, verify = select(options, budget)
    announce(options, "Checking source patterns...")
    old_findings, old_checks, findings, checks = [], [], [], []
    scan_error = None
    architecture = None
    try:
        progress = (
            (
                lambda current, total: announce(
                    options, f"Checking sources: {current}/{total} files..."
                )
            )
            if options.details
            else None
        )
        scan(before, budget, old_findings, old_checks, rules=rules, progress=progress)
        scan(after, budget, findings, checks, rules=rules, progress=progress)
        paths = repository_paths(after, exclusions)
        if scope["kind"] == "repository":
            # An absent lockfile proves nothing once the file listing was cut short.
            listed = not any(
                row["file"] == "repository-tree"
                and row["reason"] != "excluded or unsupported"
                for row in exclusions
            )
            if options.details:
                announce(
                    options, "Checking repository paths and dependency declarations..."
                )
            scan_paths(paths, findings, checks, after if listed else None, rules=rules)
        if options.details:
            announce(options, "Building architecture and identity-provider profiles...")
        architecture = describe(after, budget, checks, paths)
    except (SourceError, ScanLimit) as error:
        scan_error = str(error)
    change = scope["kind"] == "change"
    comparable = (
        scan_error is None
        and not any(row.get("error") for row in [*old_checks, *checks])
        and not any(
            row["reason"] in {"oversized", "link or submodule", "binary or non-UTF-8"}
            for row in exclusions
        )
    )
    if change:
        findings = (
            compare(old_findings, findings)
            if comparable
            else [
                {**finding, "change": "unresolved", "side": side}
                for side, rows in (("baseline", old_findings), ("proposed", findings))
                for finding in rows
            ]
        )
        checks = [
            {**row, "side": side}
            for side, rows in (("baseline", old_checks), ("proposed", checks))
            for row in rows
        ]
    complete = (
        scan_error is None
        and not any(row.get("error") for row in checks)
        and not any(row["reason"] != "excluded or unsupported" for row in exclusions)
    )
    host_findings, host_checks = settings_checks(settings)
    findings.extend(row for row in host_findings if row["rule"] in active_ids)
    for finding in findings:
        finding.pop("_identity", None)
    checks.extend(row for row in host_checks if row["rule"] in active_ids)
    architecture = architecture or {
        "frontend": [],
        "templates": [],
        "persistence": [],
        "authentication": [],
        "interpretation": "Architecture observation did not complete.",
    }
    if (
        "WEB-CSP" in active_ids
        and (
            architecture["frontend"]
            or any(
                row["rule"] == "FRONTEND-BINDING" and row["status"] != "not_applicable"
                for row in checks
            )
        )
        and not any(
            row["rule"] == "WEB-CSP" and row["status"] != "not_applicable"
            for row in checks
        )
    ):
        checks.append(
            {
                "rule": "WEB-CSP",
                "area": "frontend-policy",
                "file": "frontend-scope",
                "status": "unclear",
            }
        )
    if verify and scan_error is None:
        announce(options, "Verifying source consistency...")
        try:
            verify()
        except SourceError as error:
            complete = False
            scan_error = str(error)
    if change:
        try:
            result = analyze_relevance(
                before, after, checks, findings, exclusions, budget, complete=complete
            )
        except SourceError as error:
            scan_error = str(error)
            complete = False
            result = {
                "analysis": "change-relevance",
                "relevance_version": RELEVANCE_VERSION,
                "verdict": "incomplete",
                "relevance": "unclear",
                "signals": [],
                "findings": findings,
                "finding_changes": dict(
                    Counter(finding.get("change", "unresolved") for finding in findings)
                ),
                "aspects": [],
                "coverage": {
                    "check_outcomes": dict(Counter(row["status"] for row in checks)),
                    "basis": "Relevance analysis did not finish.",
                },
            }
    else:
        unsupported_code = {
            ".c",
            ".cpp",
            ".cc",
            ".h",
            ".hpp",
            ".swift",
            ".dart",
            ".lua",
            ".java",
            ".kt",
            ".scala",
            ".go",
            ".rs",
            ".cs",
            ".php",
            ".rb",
            ".vue",
            ".svelte",
            ".sh",
            ".bash",
            ".ps1",
        }
        for exclusion in exclusions:
            if (
                exclusion["reason"] == "excluded or unsupported"
                and not excluded(exclusion["file"])
                and Path(exclusion["file"]).suffix.lower() in unsupported_code
            ):
                checks.append(
                    {
                        "rule": "SOURCE-COVERAGE",
                        "area": "coverage",
                        "file": exclusion["file"],
                        "status": "unclear",
                    }
                )
        announce(options, "Calculating security score...")
        result = calculate(findings, checks, complete=complete, require_source=True)
        if custom_checks and result["verdict"] == "scored":
            result.update(score=None, grade=None, verdict="partial")
        result["analysis"] = "repository-score"
        explain_observations(result, findings, checks)
    if remote:
        scope["remote_selection"] = remote
        scope["remote_validation"] = (
            "Host-supplied source; no independent remote retrieval or freshness check."
        )
    coverage_identity = sorted(
        {(row["rule"], row["status"] != "not_applicable") for row in checks}
    )
    result.update(
        {
            "engine": "internal",
            "rule_version": RULE_VERSION,
            **({} if change else {"scoring_version": VERSION}),
            "scope": scope,
            "architecture": architecture,
            "host_settings": settings,
            "checks": checks,
            "exclusions": exclusions,
            "comparability": {
                "rule_version": RULE_VERSION,
                **(
                    {"relevance_version": RELEVANCE_VERSION}
                    if change
                    else {"scoring_version": VERSION}
                ),
                "catalog_fingerprint": CATALOG_HASH,
                "implementation_fingerprint": IMPLEMENTATION_HASH,
                "coverage_fingerprint": hashlib.sha256(
                    json.dumps(coverage_identity).encode()
                ).hexdigest(),
                "selected_checks_fingerprint": hashlib.sha256(
                    json.dumps(sorted(active_ids)).encode()
                ).hexdigest(),
                "source_policy": "bounded-static-v3",
                "subject_kind": scope["kind"],
                "host_settings_fingerprint": hashlib.sha256(
                    json.dumps(settings, sort_keys=True).encode()
                ).hexdigest(),
            },
            "sources": {
                "baseline_sha256": fingerprint(before),
                "proposed_sha256": fingerprint(after),
            },
            "warnings": [
                "Coverage is limited to the bundled rule catalog; authorization, business logic, runtime exposure and dependency vulnerabilities are not comprehensively assessed."
            ],
        }
    )
    result["coverage"]["selected_checks"] = [rule["id"] for rule in rules]
    if custom_checks:
        result["scope"]["check_selection"] = {
            "checks": options.checks or "all",
            "skip_checks": options.skip_checks,
            "count": len(rules),
        }
        result["warnings"].append(
            "Only the explicitly selected checks were assessed; the observed score is not a full repository grade."
        )
    if not change:
        result["findings"] = findings
        if scope["selection"] == "git-url":
            result["coverage"]["files_downloaded"] = len(after)
        result["coverage"]["files_checked"] = len(
            {
                row["file"]
                for row in checks
                if row["area"] != "repository-host" and row["rule"] != "SOURCE-COVERAGE"
            }
        )
        result["coverage"]["selection_limits"] = dict(
            sorted(
                Counter(
                    row["reason"]
                    for row in exclusions
                    if row["reason"] != "excluded or unsupported"
                ).items()
            )
        )
    if change:
        result["warnings"].append(
            "Relevance and finding severity are independent. Signals are deterministic indicators, not a full semantic review. Unrecognized behavior remains unclear; low relevance is not security approval."
        )
    if options.patch:
        result["warnings"].append(
            "Patch fragments omit surrounding context. Unparseable Python fragments stay unclear; unchanged findings outside the patch cannot be assessed."
        )
    if scan_error:
        result["warnings"].append(scan_error)
    if options.details and not options.quiet and not change:
        announce(options, "Collecting repository overview...")
        try:
            result["overview"] = repository_context(
                options, scope, after, exclusions, budget
            )
        except SourceError:
            result["warnings"].append("Overview skipped: the time budget ran out.")
    if budget.network is not None:
        result["network"] = budget.network.snapshot()
    if options.score and not change:
        from score_assessment import assess

        try:
            assess(result, after, budget)
        except SourceError:
            # No legacy number may escape as a successful subscore result.
            raise SourceError("The subscore assessment exceeded its processing budget.") from None
        return result, 1 if result["verdict"] == "incomplete" else 0 if result["verdict"] == "assessed" else 2
    return result, (0 if complete else 1) if change else {
        "scored": 0,
        "undetermined": 2,
        "partial": 2,
        "incomplete": 1,
    }[result["verdict"]]


def main(argv=None):
    selected = list(sys.argv[1:] if argv is None else argv)
    if "--quiet" in selected or "--quite" in selected:
        with contextlib.redirect_stderr(io.StringIO()):
            return execute(selected)
    return execute(selected)


def execute(argv):
    arguments = parser()
    options = arguments.parse_args(argv)
    if options.repository and options.repo:
        arguments.error("Choose a positional repository or --repo, not both.")
    options.repo = options.repo or options.repository or "."
    if not 0.1 <= options.timeout <= 120:
        arguments.error("--timeout must be between 0.1 and 120 seconds.")
    if options.head and not options.base:
        arguments.error("--head requires --base.")
    if options.score and (
        options.engine != "internal" or options.patch or options.base or options.commit
        or options.staged or options.unstaged or options.worktree or options.pr or options.mr
        or options.quiet or options.list_rules or options.list_checks or options.verify_rules
    ):
        arguments.error("--score supports internal repository assessments; use --json or --yaml for structured subscores.")
    if options.quiet and (
        options.list_checks
        or options.list_rules
        or options.verify_rules
        or options.patch
        or options.base
        or options.commit
        or options.staged
        or options.unstaged
        or options.worktree
    ):
        arguments.error("--quiet/--quite supports repository scores only.")
    if (options.checks or options.skip_checks) and (
        options.engine == "analyzer"
        or options.patch
        or options.base
        or options.commit
        or options.staged
        or options.unstaged
        or options.worktree
    ):
        arguments.error("Check selection supports internal repository scans only.")
    try:
        selected_rules(options.checks, options.skip_checks)
    except ValueError as error:
        arguments.error(str(error))
    if not options.legacy_score:
        options.score = options.score or not (
            options.engine != "internal" or options.quiet
            or options.patch or options.base or options.commit
            or options.staged or options.unstaged or options.worktree or options.pr or options.mr
            or options.list_rules or options.list_checks or options.verify_rules
        )
    try:
        started = time.monotonic()
        with Progress(
            enabled=not options.quiet and not options.json and not options.yaml
        ) as progress:
            options.step = progress.step
            result, status = run(options)
        if (
            options.details
            and not options.quiet
            and not (options.list_rules or options.list_checks or options.verify_rules)
        ):
            result["duration_seconds"] = round(max(0, time.monotonic() - started), 3)
        if options.quiet:
            value = result.get("score")
            if value is None:
                value = result.get("observed_score")
            if value is not None:
                print(value)
            return status
        if options.json:
            output = json.dumps(result, indent=2, ensure_ascii=True, allow_nan=False)
        elif options.yaml:
            output = yaml_text(result)
        elif options.verify_rules:
            output = f"Verified {result['rules_verified']} scanner rules, {result['examples_verified']} examples and {result['relevance_examples_verified']} relevance examples."
        elif options.list_checks:
            output = (
                "Default: all\n\n"
                + "\n".join(
                    f"{group:<16} {len(ids):>2} checks"
                    for group, ids in result["check_groups"].items()
                )
                + "\n\nUse --checks GROUP[,GROUP...] or rule IDs from --list-rules."
            )
        elif options.list_rules:
            output = "\n\n".join(
                f"{rule['id']} · {rule['severity']} · {rule['title']}\n{rule['criteria']}"
                for rule in RULES
            )
            relevance_rules = [
                *POLICY["change_relevance"]["path_rules"],
                *POLICY["change_relevance"]["code_rules"],
                *POLICY["change_relevance"]["area_rules"].values(),
                POLICY["change_relevance"]["documentation_rule"],
                POLICY["change_relevance"]["executable_rule"],
            ]
            output += "\n\n" + "\n\n".join(
                f"{rule['id']} · relevance {rule['level']} · {rule['aspect']}\n{rule['reason']}"
                for rule in relevance_rules
            )
        else:
            style = Style.detect(sys.stdout)
            output = render(result, options.details, style)
            if options.details:
                output = f"security-score {score_version.package_version()}\n\n" + output
            if options.details and "network" in result:
                network = result["network"]
                rows = [
                    f"Network: {network['requests']:,} HTTP requests "
                    f"{style.dot} {network['response_body_bytes']:,} response body bytes read"
                ]
                for row in network["hosts"]:
                    rows.append(
                        f"  {row['host']}: {row['requests']:,} requests "
                        f"{style.dot} {row['response_body_bytes']:,} bytes"
                    )
                rows.append(
                    "  Excludes unread bodies, HTTP headers, uploads, DNS and TLS/TCP overhead."
                )
                output += "\n\n" + "\n".join(rows)
            if options.details and "duration_seconds" in result:
                output += f"\n\nDuration: {result['duration_seconds']:.2f} s"
        print(output)
        return status
    except KeyboardInterrupt:
        print(
            "Security score cancelled; no complete result published.", file=sys.stderr
        )
        return 130
    except SourceError as error:
        print(str(error), file=sys.stderr)
        return 1
    except BrokenPipeError:
        return 1
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        RecursionError,
        AttributeError,
        IndexError,
        OverflowError,
        RuntimeError,
    ):
        print(
            "Security score could not complete. Check the selected sources and runtime installation.",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
