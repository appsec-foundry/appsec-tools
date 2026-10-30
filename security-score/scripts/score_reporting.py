"""Located observations grouped by path hints, never by assumed runtime trust."""

from collections import Counter
from pathlib import PurePosixPath
import textwrap

from score_calculation import calculate, has_unknown
from score_style import Style, safe


def container_build_file(name):
    """Dockerfile, Dockerfile.<variant>, <variant>.Dockerfile and Containerfile."""
    name = name.lower()
    return not name.endswith(".dockerignore") and (
        name in {"dockerfile", "containerfile"}
        or name.startswith(("dockerfile.", "containerfile."))
        or name.endswith(".dockerfile")
    )


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
    if (
        lowered
        & {
            ".github",
            ".gitlab",
            "infrastructure",
            "terraform",
            "scripts",
        }
        or name.startswith("dockerfile")
        or container_build_file(name)
    ):
        return "build"
    return "source"


def source_priority(path):
    """Read declarations and application sources before tests and static assets.

    These hints affect order only: every supported source remains eligible.
    """
    name = PurePosixPath(path).name
    declaration = (
        name in {"package.json", "package-lock.json", "npm-shrinkwrap.json"}
        or container_build_file(name)
        or name.startswith("requirements")
    )
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


# Presentation groups only: detection, area arithmetic and the overall score stay
# unchanged. An unassessed topic must never acquire points from technology names.
SUBCATEGORIES = (
    ("repository", "Repository", ("repository-host",)),
    ("authentication", "Authentication", ("authentication", "authorization")),
    ("architecture", "Architecture", ("execution", "injection", "deserialization")),
    ("frontend", "Frontend", ("output", "frontend-policy")),
    ("dependencies", "Dependencies & CI", ("supply-chain",)),
    ("cryptography", "Cryptography", ("cryptography",)),
    ("deployment", "Deployment & transport", ("hardening", "transport")),
)

POSITIVE_REASONS = {
    "PY-EXEC": "Data-only parsing with ast.literal_eval",
    "PY-SHELL": "Process started from an argument list without a shell",
    "PY-SQL": "Literal SQL text passed to a query call",
    "PY-YAML": "Safe YAML loader used",
    "PY-DEBUG": "Debug mode explicitly disabled",
    "PY-DEPENDENCIES": "Requirement pinned with a sha256 hash",
    "JS-EVAL": "Data-only parsing with JSON.parse",
    "JS-SQL": "Literal SQL text passed to a query call",
    "NPM-SOURCES": "Git dependency pinned to a full commit",
    "IAC-ACTION": "Action pinned to a full commit or digest",
    "IAC-IMAGE": "Base image pinned by digest",
    "HOST-DEFAULT-BRANCH-PROTECTION": "Default branch protection reported enabled",
    "HOST-REQUIRED-REVIEWS": "Required reviews reported enabled",
    "HOST-SECRET-SCANNING": "Secret scanning reported enabled",
    "HOST-DEPENDABOT-SECURITY-UPDATES": "Dependency security updates reported enabled",
    "HOST-SUCCESSFUL-PIPELINE-BEFORE-MERGE": "Successful pipeline required before merge",
    "HOST-SECURITY-SCANNING": "Security scanning reported enabled",
    "IAC-USER": "Non-root container user declared",
    "PY-TLS": "Certificate verification explicitly enabled",
    "JS-TLS": "Certificate verification explicitly enabled",
    "NPM-LOCK": "Manifest matches a recognized dependency lock",
    "CI-PERMISSIONS": "Read-only workflow permissions declared",
    "WEB-CSP": "CSP declaration meets the bundled policy checks",
    "JS-HTML": "Text assigned through textContent",
    "FRONTEND-BINDING": "Framework text binding recognized",
    "PY-JWT": "Token verification restricted to listed algorithms",
    "JS-JWT": "Token verification restricted to listed algorithms",
    "PY-RANDOM": "Cryptographic random source for a named secret",
    "JS-RANDOM": "Cryptographic random source for a named secret",
    "IAC-PRIVILEGED": "Container privileges explicitly restricted",
    "IAC-ADD-URL": "Remote build input pinned by checksum or commit",
}

HOST_REASONS = {
    "HOST-DEFAULT-BRANCH-PROTECTION": "Default branch protection reported disabled",
    "HOST-REQUIRED-REVIEWS": "Required reviews reported disabled",
    "HOST-SECRET-SCANNING": "Secret scanning reported disabled",
    "HOST-DEPENDABOT-SECURITY-UPDATES": "Dependency security updates reported disabled",
    "HOST-SUCCESSFUL-PIPELINE-BEFORE-MERGE": "Successful pipeline not required before merge",
    "HOST-SECURITY-SCANNING": "Security scanning reported disabled",
}


def subcategories(result):
    """Use the lowest recognized area index in each topic, never a fresh score."""
    definitions = list(SUBCATEGORIES)
    mapped = {area for _, _, areas in definitions for area in areas}
    # Retain future catalog areas rather than silently dropping their evidence.
    definitions.extend(
        (row["area"], row["area"].replace("-", " ").capitalize(), (row["area"],))
        for row in result["areas"]
        if row["area"] not in mapped | {"coverage"}
    )
    topics = []
    for identity, title, areas in definitions:
        rows = [row for row in result["areas"] if row["area"] in areas]
        values = [
            row["score"] if row["score"] is not None else row.get("observed_score")
            for row in rows
        ]
        topics.append(
            {
                "id": identity,
                "title": title,
                "areas": areas,
                "index": min(
                    (value for value in values if value is not None), default=None
                ),
                "findings": [row for row in result["findings"] if row["area"] in areas],
                "checks": [row for row in result["checks"] if row["area"] in areas],
            }
        )
    return topics


def location(row):
    if row["file"] == "repository-host":
        return "host API"
    line = row.get("line")
    if line is None:
        line = next(
            (
                item["line"]
                for item in row.get("locations", [])
                if item["status"] == "satisfied"
            ),
            None,
        )
    return safe(row["file"]) + (f":{line}" if line is not None else "")


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
COVERAGE_STATUS = {
    "scored": "complete",
    "partial": "some checks inconclusive",
    "incomplete": "scan incomplete",
    "undetermined": "no recognized evidence",
}
LABEL_WIDTH = 8
TEXT_INDENT = " " * (2 + LABEL_WIDTH + 2)


def plural(count, noun):
    return f"{count} {noun}" + ("" if count == 1 else "s")


def wrapped(text, width, indent, first=None):
    return textwrap.wrap(
        text,
        width=width,
        initial_indent=indent if first is None else first,
        subsequent_indent=indent,
        break_long_words=False,
        break_on_hyphens=False,
    ) or [indent]


def note(style, text, indent="  "):
    """A dimmed explanatory line, wrapped to the terminal."""
    return [style.paint(line, "dim") for line in wrapped(text, style.width, indent)]


def entry(style, tag, text, detail):
    """Tag column, then a wrapped description and a dimmed rule/location line."""
    lines = wrapped(text, style.width, TEXT_INDENT)
    lines[0] = "  " + tag + "  " + lines[0][len(TEXT_INDENT) :]
    lines += [
        style.paint(line, "dim") for line in wrapped(detail, style.width, TEXT_INDENT)
    ]
    return lines


def topic_examples(style, topic):
    lines = []
    candidates = topic["findings"]
    if candidates:
        groups = {}
        for finding in candidates:
            groups.setdefault(finding["rule"], []).append(finding)
        ranked = sorted(
            groups.items(),
            key=lambda pair: (
                SEVERITY_ORDER[pair[1][0]["severity"]],
                -len(pair[1]),
                pair[0],
            ),
        )
        for rule, matches in ranked[:3]:
            first = min(
                matches, key=lambda row: (source_priority(row["file"]), row["line"])
            )
            more = f" (+{len(matches) - 1} more)" if len(matches) > 1 else ""
            lines += entry(
                style,
                style.tag(first["severity"], LABEL_WIDTH),
                safe(HOST_REASONS.get(rule, first["title"])),
                f"{rule} {style.dot} {location(first)}{more}",
            )
        if len(ranked) > 3:
            lines += note(
                style,
                f"+{len(ranked) - 3} more finding types; every occurrence is in --json.",
            )
    # Positive evidence follows the findings; it never offsets them in the index.
    positive = {}
    for row in sorted(
        (row for row in topic["checks"] if row["status"] == "satisfied"),
        key=lambda row: (source_priority(row["file"]), row["rule"]),
    ):
        positive.setdefault(row["rule"], []).append(row)
    for rule, rows in list(positive.items())[:2]:
        count = sum(
            sum(item["status"] == "satisfied" for item in row.get("locations", [])) or 1
            for row in rows
        )
        more = f" (+{count - 1} more)" if count > 1 else ""
        lines += entry(
            style,
            style.paint(f"{'OK':<{LABEL_WIDTH}}", "green"),
            POSITIVE_REASONS.get(rule, f"Positive evidence recognized by {rule}"),
            f"{rule} {style.dot} {location(rows[0])}{more}",
        )
    if not candidates and not positive:
        lines += note(
            style,
            "No token verification recognized; login, sessions and access control are not assessed."
            if topic["id"] == "authentication" and not topic["checks"]
            else "No recognized control evidence from the available checks.",
        )
    return lines


def topic_header(style, topic, width):
    title = style.paint(f"{topic['title']:<{width}}", "bold")
    index = topic["index"]
    if index is None:
        return f"{title}  " + style.paint("not assessed", "dim")
    score = style.paint(f"{index:>3}/100", style.band(index), "bold")
    count = len(topic["findings"])
    unclear = any(has_unknown(row) for row in topic["checks"])
    if count:
        summary = plural(count, "candidate")
    elif topic["checks"]:
        summary = "no candidates" + ("; some checks unclear" if unclear else "")
    else:
        summary = ""
    return f"{title}  {score}  {style.bar(index)}  " + style.paint(summary, "dim")


PROFILE_LABELS = {
    "local-password": "local passwords",
    "federated": "federated login",
    "jwt": "JWT",
    "session": "server sessions",
    "sql": "SQL",
    "document": "document store",
}


def architecture_profile(style, architecture):
    """Recognized traits as context; 'none recognized' is no proof of absence."""
    if "sql_queries" not in architecture:
        return note(
            style, "Profile unavailable: architecture observation did not complete."
        )

    def grouped(groups):
        return ", ".join(
            f"{label} ({', '.join(sorted({safe(row['technology']) for row in rows}))})"
            for label, rows in groups
            if rows
        )

    def by(trait, key):
        rows = architecture.get(trait, [])
        return [
            (label, [row for row in rows if row.get(key) == kind])
            for kind, label in PROFILE_LABELS.items()
        ]

    sql = architecture["sql_queries"]
    calls = plural(sql["calls"], "query call")
    if sql["status"] == "constructed":
        unresolved = f", {sql['unresolved']} unresolved" if sql["unresolved"] else ""
        queries = (
            f"concatenated or interpolated in {sql['constructed']} of {calls}"
            f"{unresolved} ({location(sql['example'])})"
        )
    elif sql["status"] == "unresolved":
        queries = f"query text unresolved in {sql['unresolved']} of {calls}"
    elif sql["status"] == "literal":
        queries = f"literal query text in {calls}"
    else:
        queries = ""
    rows = (
        ("Authentication", grouped(by("authentication", "mechanism"))),
        (
            "Frontend",
            grouped(
                (
                    ("single-page app", architecture.get("frontend", [])),
                    ("server-side templates", architecture.get("templates", [])),
                )
            ),
        ),
        ("Persistence", grouped(by("persistence", "kind"))),
        ("SQL queries", queries),
    )
    lines = note(style, "Profile (context only, adds no score credit):")
    for label, text in rows:
        lines += wrapped(
            text or "none recognized", style.width, " " * 20, f"    {label:<16}"
        )
    return lines


def render_repository(result, summary, style=None):
    """A subscore with a few concrete examples directly beneath each topic."""
    style = style or Style()
    scope = result["scope"]
    revision = f" @ {safe(scope['revision'][:12])}" if scope.get("revision") else ""
    partial = result["score"] is None
    band = style.band(result["score"] if not partial else result.get("observed_score"))
    lines = [
        style.paint("Security score", "bold")
        + f" {style.dot} "
        + style.paint(summary, band, "bold"),
        f"Scope: {safe(scope['repository'])}{revision}",
        *note(style, "Static pattern candidates; exploitability unverified.", ""),
    ]
    if partial:
        lines += note(
            style,
            "Partial result: subscores describe recognized evidence only; no repository grade is available.",
            "",
        )
    topics = subcategories(result)
    width = max(len(topic["title"]) for topic in topics)
    for topic in topics:
        lines += ["", topic_header(style, topic, width)]
        lines += topic_examples(style, topic)
        if topic["id"] == "architecture":
            lines += architecture_profile(style, result.get("architecture", {}))
            lines += note(
                style,
                "Basis: selected execution, SQL and deserialization patterns; no full architectural review.",
            )

    candidates = len(result["findings"])
    lines += [
        "",
        style.paint("Coverage", "bold"),
        f"  {plural(result['coverage'].get('files_checked', 0), 'file')} checked {style.dot} "
        f"{plural(candidates, 'candidate')} {style.dot} "
        f"{COVERAGE_STATUS.get(result['verdict'], result['verdict'])}",
    ]
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
            f"{plural(len(paths), 'file')} over the 512 KiB limit"
            if reason == "oversized"
            else f"{len(paths)} {safe(reason)}"
        )
        if detail:
            description += " (" + safe(detail) + ")"
        extra = f" (+{len(paths) - 1} more)" if len(paths) > 1 else ""
        lines += note(style, f"{description}: {safe(paths[0])}{extra}")
    errors = result.get("source_errors", [])
    if errors:
        extra = f" (+{len(errors) - 1} more)" if len(errors) > 1 else ""
        lines += note(
            style,
            f"{plural(len(errors), 'file')} could not be parsed: {safe(errors[0]['file'])}{extra}; "
            "affected checks stay unclear.",
        )
    unsupported = sum(row["rule"] == "SOURCE-COVERAGE" for row in result["checks"])
    unknown = sum(
        has_unknown(row) and row["area"] != "repository-host"
        for row in result["checks"]
    )
    if unknown:
        lines += note(
            style,
            f"{plural(unknown, 'check')} inconclusive; {plural(unsupported, 'unsupported source file')}.",
        )
    for warning in result["warnings"]:
        if not warning.startswith("Coverage is limited to the bundled rule catalog;"):
            lines += note(style, safe(warning))
    lines += [
        "",
        *note(
            style,
            "Topic score = lowest recognized area index. Every finding and the calculation: --json.",
            "",
        ),
    ]
    return "\n".join(lines)
