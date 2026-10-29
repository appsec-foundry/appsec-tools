"""Located observations grouped by path hints, never by assumed runtime trust."""

from collections import Counter
from pathlib import PurePosixPath

from score_calculation import calculate


def origin(path):
    parts = PurePosixPath(path).parts
    lowered = {part.lower() for part in parts}
    name = parts[-1].lower() if parts else ""
    if path == "repository-host":
        return "repository-host"
    if lowered & {"test", "tests", "__tests__", "spec", "specs", "cypress"} or any(
        token in name for token in (".spec.", ".test.")
    ):
        return "tests"
    if lowered & {
        "examples",
        "example",
        "fixtures",
        "fixture",
        "codefixes",
        "samples",
        "sample",
    }:
        return "examples"
    if lowered & {"assets", "vendor", "third_party", "third-party"} or name.endswith(
        ".min.js"
    ):
        return "assets"
    if lowered & {
        ".github",
        ".gitlab",
        "infrastructure",
        "terraform",
        "scripts",
    } or name.startswith("dockerfile"):
        return "build"
    return "source"


def source_priority(path):
    """Read declarations and application sources before tests and static assets.

    These hints affect order only: every supported source remains eligible.
    """
    name = PurePosixPath(path).name
    declaration = name in {
        "package.json",
        "package-lock.json",
        "npm-shrinkwrap.json",
        "Dockerfile",
    } or name.startswith("requirements")
    group = {"source": 0, "build": 1, "tests": 2, "examples": 3, "assets": 4}
    return (0 if declaration else 1, group.get(origin(path), 0), path)


def explain(result, findings, checks):
    for row in [*findings, *checks]:
        row["origin"] = origin(row.get("file", ""))
    for finding in findings:
        finding["certainty"] = "static-pattern"
    groups = []
    for group in sorted({row["origin"] for row in [*findings, *checks]}):
        group_findings = [row for row in findings if row["origin"] == group]
        group_checks = [row for row in checks if row["origin"] == group]
        assessment = calculate(group_findings, group_checks)
        groups.append(
            {
                "origin": group,
                "findings": len(group_findings),
                "observed_score": assessment["observed_score"],
                "check_outcomes": dict(Counter(row["status"] for row in group_checks)),
            }
        )
    errors = {}
    for row in checks:
        if row.get("error"):
            errors.setdefault(
                row["file"],
                {
                    "file": row["file"],
                    "origin": row["origin"],
                    "reason": row["error"],
                    "affected_rules": [],
                },
            )["affected_rules"].append(row["rule"])
    result["origin_groups"] = groups
    result["source_errors"] = [errors[path] for path in sorted(errors)]
    result["coverage"]["origin_basis"] = (
        "Path hints only; runtime use is unverified. All observations remain in the assessment."
    )
