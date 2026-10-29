"""Located observations grouped by path hints, never by assumed runtime trust."""

from collections import Counter
from pathlib import PurePosixPath
import textwrap

from score_calculation import calculate, has_unknown


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


def category_name(area):
    return area.replace("-", " ").capitalize()


def category_score(area):
    return area["score"] if area["score"] is not None else area.get("observed_score")


def render_repository(result, summary):
    """One category table, then located findings and concise coverage limits."""
    findings = result["findings"]
    counts = Counter(row["area"] for row in findings)
    areas = sorted(
        result["areas"],
        key=lambda row: (
            category_score(row) if category_score(row) is not None else 101,
            row["area"],
        ),
    )
    scope = result["scope"]
    revision = f" @ {scope['revision'][:12]}" if scope.get("revision") else ""
    lines = [
        "Security score",
        summary,
        f"Repository: {scope['repository']}{revision}",
        "Static pattern candidates; exploitability unverified.",
        "",
        "Categories",
    ]
    rows = [("Category", "Subscore", "Findings", "Deduction", "Cap")]
    for area in areas:
        score = category_score(area)
        rows.append(
            (
                category_name(area["area"]),
                f"{score}/100" if score is not None else "unknown",
                str(counts[area["area"]]),
                str(area["deduction"]) if score is not None else "-",
                str(area["severity_cap"]) if score is not None else "-",
            )
        )
    widths = [max(len(row[column]) for row in rows) for column in range(5)]
    for index, row in enumerate(rows):
        lines.append(
            "  ".join(value.ljust(width) for value, width in zip(row, widths)).rstrip()
        )
        if index == 0:
            lines.append("  ".join("-" * width for width in widths))
    lines.append(
        "Subscore = max(0, min(100 - deduction, cap)); overall = lowest assessed category."
    )
    if result["score"] is None:
        lines.append(
            "Partial category values are observed indices; no repository grade is available."
        )
    else:
        scores = ", ".join(
            str(row["score"]) for row in result["areas"] if row["score"] is not None
        )
        lines.append(
            f"Overall: lowest assessed category = min({scores}) = {result['score']}."
        )

    lines += ["", "Findings"]
    hidden_locations = False
    for area in areas:
        candidates = [row for row in findings if row["area"] == area["area"]]
        if not candidates:
            continue
        lines.append(category_name(area["area"]))
        groups = {}
        for finding in candidates:
            groups.setdefault(finding["rule"], []).append(finding)
        for rule, occurrences in sorted(
            groups.items(),
            key=lambda pair: (
                {"critical": 0, "high": 1, "medium": 2, "low": 3}[
                    pair[1][0]["severity"]
                ],
                pair[0],
            ),
        ):
            first = occurrences[0]
            deduction = next(row for row in area["breakdown"] if row["rule"] == rule)
            lines.append(
                textwrap.fill(
                    f"{first['severity'].upper()} {rule} - {first['title']} "
                    f"({len(occurrences)} x {deduction['points_per_instance']} = {deduction['deduction']} points)",
                    width=110,
                    initial_indent="  ",
                    subsequent_indent="    ",
                    break_long_words=False,
                    break_on_hyphens=False,
                )
            )
            by_file = {}
            for finding in occurrences:
                by_file.setdefault(finding["file"], []).append(finding["line"])
            paths = sorted(by_file, key=source_priority)
            locations = []
            for path in paths[:3]:
                numbers = sorted(set(by_file[path]))
                shown = ",".join(str(number) for number in numbers[:5])
                extra = f" (+{len(numbers) - 5} lines)" if len(numbers) > 5 else ""
                locations.append(f"{path}:{shown}{extra} [{origin(path)}]")
                hidden_locations |= len(numbers) > 5
            if len(paths) > 3:
                locations.append(f"+{len(paths) - 3} more files")
                hidden_locations = True
            lines.append(
                textwrap.fill(
                    "Locations: " + "; ".join(locations),
                    width=110,
                    initial_indent="    ",
                    subsequent_indent="    ",
                    break_long_words=False,
                    break_on_hyphens=False,
                )
            )
            lines.append(
                textwrap.fill(
                    "Review: " + first["next_action"],
                    width=110,
                    initial_indent="    ",
                    subsequent_indent="    ",
                    break_long_words=False,
                    break_on_hyphens=False,
                )
            )
    if not findings:
        lines.append(
            "  No candidates detected in recognized patterns; unknown coverage remains unknown."
        )
    if hidden_locations:
        lines.append(
            "  Showing up to 3 files and 5 lines per file per rule; --json retains every location."
        )

    lines += ["", "Coverage"]
    coverage = result["coverage"]
    lines.append(
        f"  {coverage.get('files_checked', 0)} files checked; {len(findings)} finding candidates; status: {result['verdict']}."
    )
    exclusions = {}
    for row in result["exclusions"]:
        if row["reason"] != "excluded or unsupported":
            exclusions.setdefault((row["reason"], row.get("detail")), []).append(
                row["file"]
            )
    for (reason, detail), paths in sorted(
        exclusions.items(), key=lambda pair: str(pair[0])
    ):
        description = (
            "exceeds the 512 KiB file limit" if reason == "oversized" else reason
        )
        if detail:
            description += " (" + detail + ")"
        sample = "; ".join(paths[:2]) + (
            f"; +{len(paths) - 2} more" if len(paths) > 2 else ""
        )
        lines.append(f"  {len(paths)} {description}: {sample}")
    source_errors = {}
    for error in result.get("source_errors", []):
        source_errors.setdefault(error["reason"], []).append(error["file"])
    for reason, paths in source_errors.items():
        if len(paths) == 1:
            lines.append(f"  Source processing issue: {paths[0]} - {reason}")
        else:
            sample = "; ".join(paths[:2]) + (
                f"; +{len(paths) - 2} more files" if len(paths) > 2 else ""
            )
            lines.append(f"  Source processing issues: {len(paths)} files - {reason}")
            lines.append(
                textwrap.fill(
                    sample,
                    width=110,
                    initial_indent="    ",
                    subsequent_indent="    ",
                    break_long_words=False,
                    break_on_hyphens=False,
                )
            )
    unsupported = [
        row["file"] for row in result["checks"] if row["rule"] == "SOURCE-COVERAGE"
    ]
    if unsupported:
        sample = "; ".join(unsupported[:2]) + (
            f"; +{len(unsupported) - 2} more" if len(unsupported) > 2 else ""
        )
        lines.append(f"  {len(unsupported)} unsupported source files: {sample}")
    unknown = sum(
        has_unknown(row) and row["area"] != "repository-host"
        for row in result["checks"]
    )
    if unknown:
        lines.append(
            f"  {unknown} source checks remain unclear; --json contains individual check outcomes."
        )
    for warning in result["warnings"]:
        if not warning.startswith("Coverage is limited to the bundled rule catalog;"):
            lines.append("  " + warning)
    return "\n".join(lines)
