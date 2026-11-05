"""Located observations grouped by path hints, never by assumed runtime trust."""

from collections import Counter
from pathlib import PurePosixPath
import textwrap

from score_calculation import CAPS, COUNTED_INSTANCES, WEIGHTS, calculate, has_unknown
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
        "__fixtures__",
        "testdata",
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
        or name in {".gitlab-ci.yml", ".gitlab-ci.yaml"}
        or name.endswith(".tf")
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
        name
        in {
            "package.json",
            "package-lock.json",
            "npm-shrinkwrap.json",
            "pyproject.toml",
            "pom.xml",
            "Cargo.toml",
            ".gitlab-ci.yml",
        }
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
    ("secrets", "Secrets", ("secrets",)),
    ("cryptography", "Cryptography", ("cryptography",)),
    (
        "deployment",
        "Deployment & transport",
        ("hardening", "transport", "infrastructure"),
    ),
)

POSITIVE_REASONS = {
    "PY-EXEC": "Data-only parsing with ast.literal_eval",
    "PY-SHELL": "Process started from an argument list without a shell",
    "PY-SQL": "Literal SQL text passed to a query call",
    "PY-YAML": "Safe YAML loader used",
    "PY-DEBUG": "Debug mode explicitly disabled",
    "PY-DEPENDENCIES": "Requirement pinned",
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
    "WEB-HEADERS": "Security headers declared",
    "JS-HTML": "Text assigned through textContent",
    "FRONTEND-BINDING": "Framework text binding recognized",
    "PY-JWT": "Token verification restricted to listed algorithms",
    "JS-JWT": "Token verification restricted to listed algorithms",
    "PY-RANDOM": "Cryptographic random source for a named secret",
    "JS-RANDOM": "Cryptographic random source for a named secret",
    "IAC-PRIVILEGED": "Container privileges explicitly restricted",
    "IAC-ADD-URL": "Remote build input pinned by checksum or commit",
    "IAC-HARDENING": "Container hardening declared",
    "HOST-SIGNED-COMMITS": "Signed commits required by a ruleset",
    "REPO-SECURITY-POLICY": "Security policy present",
    "DEP-UPDATE-CONFIG": "Dependency update configuration present",
    "TF-LOCK": "Terraform dependency lock present",
    "CI-RELEASE-INTEGRITY": "Release integrity steps declared",
    "CI-CLOUD-OIDC": "Cloud login through OIDC without a stored key",
    "CI-FROZEN-INSTALL": "Install restricted to the lockfile",
    "CI-GITLAB-IMAGE": "CI image pinned by digest",
    "CI-GITLAB-INCLUDE": "CI include pinned to a commit",
    "NPM-LOCK-SOURCES": "Lockfile entries from the usual registry with integrity",
    "DEP-SOURCES": "Dependency source uses HTTPS or a full commit",
    "PASSWORD-HASH": "Password hashed with a recognized password hash",
    "JS-COOKIE": "Cookie flag enabled",
    "JS-CORS": "Credentialed CORS limited to HTTPS origins",
    "WEB-SETTINGS": "Session or host setting restricted",
    "TF-PUBLIC-RESOURCE": "Public access explicitly restricted",
    "TF-MODULE-PIN": "Terraform module pinned to a commit or exact version",
    "AUTH-SSO": "Federated authentication usage (configuration only)",
    "AUTH-OAUTH-IMPLICIT": "OAuth response requests an authorization code",
    "AUTH-OAUTH-PASSWORD": "OAuth grant avoids the password grant",
    "AUTH-OAUTH-PKCE": "PKCE challenge uses S256",
    "AUTH-SAML-VALIDATION": "SAML audience or time validation configured",
    "TLS-USAGE": "TLS usage (configuration only)",
    "TLS-CERTIFICATE": "TLS certificate or trust material (configuration only)",
    "PY-TLS-CONTEXT": "Client certificate or hostname verification enabled",
}

HOST_REASONS = {
    "HOST-DEFAULT-BRANCH-PROTECTION": "Default branch protection reported disabled",
    "HOST-REQUIRED-REVIEWS": "Required reviews reported disabled",
    "HOST-SECRET-SCANNING": "Secret scanning reported disabled",
    "HOST-DEPENDABOT-SECURITY-UPDATES": "Dependency security updates reported disabled",
    "HOST-SUCCESSFUL-PIPELINE-BEFORE-MERGE": "Successful pipeline not required before merge",
    "HOST-SECURITY-SCANNING": "Security scanning reported disabled",
}


def area_index(row):
    return row["score"] if row["score"] is not None else row.get("observed_score")


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
        values = [area_index(row) for row in rows]
        topics.append(
            {
                "id": identity,
                "title": title,
                "areas": areas,
                "rows": rows,
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


def arithmetic(row):
    """Spell out an area index from the breakdown that produced it."""
    deduction, index = row["deduction"], area_index(row)
    if deduction > 100:
        return f"100 - {deduction}, floored at 0"
    text = f"100 - {deduction} = {100 - deduction}"
    if index == 100 - deduction:
        return text
    severity = next(
        item["severity"] for item in row["breakdown"] if item["severity_cap"] == index
    )
    return f"{text}, capped at {index} by a {severity} finding"


def score_explanation(style, topic):
    rows = [row for row in topic["rows"] if row["breakdown"]]
    if len(rows) == 1:
        return note(style, f"Score: {arithmetic(rows[0])}")
    if not rows:
        return []
    sums = "; ".join(
        f"{row['area'].replace('-', ' ')} {arithmetic(row)}" for row in rows
    )
    return note(style, f"Score: {sums}. The lowest area counts.")


def score_legend():
    """State the formula from the same catalog values the arithmetic uses."""
    weights = ", ".join(f"{name} {points}" for name, points in WEIGHTS.items())
    caps = ", ".join(f"{name} {limit}" for name, limit in CAPS.items())
    return (
        f"Each area starts at 100 and loses points per occurrence, at most "
        f"{COUNTED_INSTANCES} per rule: {weights}. The worst severity also limits "
        f"the score: {caps}. OK lines add no points. A topic shows its lowest area, "
        "the repository score the lowest of all. "
        "Every finding and the calculation: --json."
    )


def topic_examples(style, topic):
    lines = []
    findings = topic["findings"]
    if findings:
        points = Counter()
        for row in topic["rows"]:
            for item in row["breakdown"]:
                points[item["rule"]] += item["deduction"]
        groups = {}
        for finding in findings:
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
                f"{safe(HOST_REASONS.get(rule, first['title']))} (-{points[rule]})",
                f"{rule} {style.dot} {location(first)}{more}",
            )
        if len(ranked) > 3:
            hidden = sum(points[rule] for rule, _ in ranked[3:])
            lines += note(
                style,
                f"+{len(ranked) - 3} more finding types (-{hidden}); every occurrence is in --json.",
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
        reason = POSITIVE_REASONS.get(rule, f"Positive evidence recognized by {rule}")
        details = sorted(
            {
                item["detail"]
                for row in rows
                for item in row.get("locations", [])
                if "detail" in item
            }
        )
        if details:
            reason += ": " + ", ".join(details)
        lines += entry(
            style,
            style.paint(f"{'OK':<{LABEL_WIDTH}}", "green"),
            reason,
            f"{rule} {style.dot} {location(rows[0])}{more}",
        )
    if not findings and not positive:
        lines += note(
            style,
            "No recognized token, cookie or password hash check; login flows and access control are not assessed."
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
        summary = plural(count, "finding")
    elif topic["checks"]:
        summary = "no findings" + ("; some checks unclear" if unclear else "")
    else:
        summary = ""
    return f"{title}  {score}  {style.bar(index)}  " + style.paint(summary, "dim")


PROFILE_LABELS = {
    "local-password": "local passwords",
    "federated": "SSO (OIDC/OAuth)",
    "saml": "SSO (SAML)",
    "jwt": "JWT",
    "session": "server sessions",
    "sql": "SQL",
    "document": "document store",
}
LOGIN_LABELS = {
    "both": "SSO and passwords",
    "sso": "SSO (no password login recognized)",
    "password": "passwords (no SSO recognized)",
}
CLOUD_LOGIN_LABELS = {"oidc": "OIDC", "stored-key": "stored key"}


def identity_profile(style, architecture):
    providers = architecture.get("identity_providers", [])
    grants = architecture.get("oauth_grants", [])
    if not providers and not grants:
        return []

    def limited(values):
        values = list(dict.fromkeys(values))
        return "; ".join(values[:3]) + (
            f"; +{len(values) - 3} more" if len(values) > 3 else ""
        )

    servers = limited(
        f"{safe(row['technology'])}: {safe(row.get('url') or row['server'] or 'unresolved server')} ({safe(row['endpoint'])}, {location(row)})"
        for row in providers
    )
    flows = limited(
        f"{safe(row['grant_type'])} ({safe(row['evidence'])}, {safe(row['server'] or 'server unresolved')}, {location(row)})"
        + (f", PKCE {safe(row['pkce_method'])}" if row.get("pkce_method") else "")
        for row in grants
    )
    return profile_rows(
        style,
        (("SSO servers", servers), ("OAuth grants", flows)),
        "Identity profile",
    )


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
    first_hash = {}
    for row in sorted(
        architecture.get("password_hashing", []),
        key=lambda row: row["status"] != "violated",
    ):
        first_hash.setdefault(row["technology"], row)
    password_hash = ", ".join(
        f"{safe(name)} ({location(row)})" for name, row in first_hash.items()
    )
    rows = (
        ("Login", LOGIN_LABELS.get(architecture.get("login"), "")),
        ("Password hash", password_hash),
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
        (
            "Deployment",
            ", ".join(
                sorted(
                    {
                        safe(row["technology"])
                        for row in architecture.get("deployment", [])
                    }
                )
            ),
        ),
        (
            "Cloud login",
            ", ".join(
                sorted(
                    {
                        f"{safe(row['technology'])}: {CLOUD_LOGIN_LABELS[row['method']]}"
                        for row in architecture.get("cloud_login", [])
                    }
                )
            ),
        ),
    )
    return profile_rows(style, rows)


def profile_rows(style, rows, title="Profile"):
    lines = note(style, f"{title} (context only, adds no score credit):")
    for label, text in rows:
        lines += wrapped(
            text or "none recognized", style.width, " " * 20, f"    {label:<16}"
        )
    return lines


def dependency_profile(style, architecture):
    """Lockfiles, exact versions and update tools, shown once a project has any."""

    def names(trait):
        return ", ".join(
            sorted({safe(row["technology"]) for row in architecture.get(trait, [])})
        )

    versions = ", ".join(
        f"{row['ecosystem']} {row['exact']} of {row['direct']}"
        for row in architecture.get("exact_versions", [])
    )
    rows = (
        ("Lockfile", names("lockfiles")),
        ("Exact versions", versions and f"{versions} direct dependencies"),
        ("Updates", names("dependency_updates")),
        ("Artifact repositories", "; ".join(
            f"{safe(row['url'])} ({safe(row['ecosystem'])}, {safe(row['evidence'])}, {location(row)})"
            for row in architecture.get("artifact_repositories", [])[:6]
        )),
    )
    return profile_rows(style, rows) if any(text for _, text in rows) else []


def infrastructure_profile(architecture):
    """Declared cloud/IaC context; do not promote inventory to runtime assurance."""
    lines = []
    iac = architecture.get("iac", {})
    technologies = {row["technology"] for row in architecture.get("deployment", [])}
    technologies.update(row["technology"] for row in iac.get("providers", []))
    technologies.update(row["technology"] for row in iac.get("resources", []))
    if technologies:
        lines.append("Declared deployment targets: " + ", ".join(sorted(technologies)))
    for provider in iac.get("providers", []):
        if provider["region"]:
            lines.append(f"  {safe(provider['technology'])} region: {safe(provider['region'])} ({location(provider)})")
    for row in iac.get("resources", [])[:20]:
        detail = "; ".join(f"{safe(key)}: {safe(value)}" for key, value in row["properties"].items())
        lines.append(f"  {safe(row['technology'])} {safe(row['category'])}: {safe(row['type'])} ({row['mode']}, {location(row)})" + (f" · {detail}" if detail else ""))
    if len(iac.get("resources", [])) > 20:
        lines.append(f"  +{len(iac['resources']) - 20} resource declarations in JSON/YAML")
    for row in iac.get("state_backends", []):
        lines.append(f"Terraform state backend: {safe(row['type'])} · encryption {row['encryption']} · locking {row['locking']} ({location(row)})")
    for row in architecture.get("cloud_login", []):
        lines.append(f"Cloud CI identity: {safe(row['technology'])} · {safe(row['method'])} ({location(row)})")
    return lines


RISK_LABELS = (
    ("dependency", "Dependencies"),
    ("runtime", "Runtimes"),
    ("crypto", "Crypto & TLS"),
    ("content", "Legacy content"),
)


def counted(rows, name, count, limit=6):
    """'TypeScript 412, Python 3' with the remainder as a count."""
    shown = [f"{safe(row[name])} {row[count]}" for row in rows[:limit]]
    if len(rows) > limit:
        shown.append(f"+{len(rows) - limit} more")
    return ", ".join(shown)


def file_row(files):
    origins = ", ".join(
        f"{count} {safe(name)}" for name, count in files["by_origin"].items()
    )
    text = (
        f"{files['listed']} listed ({origins}), "
        f"{files['read']} read, {files['lines']} lines read"
    )
    return text if files["listing_complete"] else text + "; listing cut short"


def history_rows(history):
    if "unavailable" in history:
        reason = f"unavailable: {safe(history['unavailable'])}"
        return (("Branches", reason), ("Commits", reason))
    summary = (
        f"last {plural(history['commits'], 'commit')} on {safe(history['ref'])}: "
        f"{history['with_request_marker']} with a pull/merge request marker, "
        f"{plural(history['other_merges'], 'other merge')}, "
        f"{history['without_marker']} without marker; "
        f"{plural(history['authors'], 'author')}"
    )
    if history["latest_commit"]:
        summary += f"; latest {safe(history['latest_commit'])}"
    branches = history["branches"]
    return (
        ("Branches", "" if branches is None else str(branches)),
        ("Commits", summary),
    )


def risk_rows(risks):
    rows = []
    for category, label in RISK_LABELS:
        entries = []
        for row in risks:
            if row["category"] == category:
                more = row["occurrences"] - 1
                extra = f", +{more} more" if more else ""
                entries.append(
                    f"{safe(row['technology'])}: {safe(row['reason'])} "
                    f"({location(row)}{extra})"
                )
        if entries:
            rows.append((label, "; ".join(entries)))
    return rows


def overview_section(style, overview):
    """Repository context above the topics; none of it reaches a score."""
    if not overview:
        return []
    development = overview["development"]

    def names(rows):
        return ", ".join(safe(name) for name in rows)

    runtimes = ", ".join(
        f"{safe(row['runtime'])} {safe(row['version'])} ({location(row)})"
        for row in overview["runtimes"][:6]
    )
    ci = ", ".join(
        f"{safe(row['system'])} ({plural(row['files'], 'file')})"
        for row in development["ci"]
    )
    if ci and development["ci_steps"]:
        ci += "; runs " + " and ".join(development["ci_steps"])
    risks = risk_rows(overview["technology_risks"])
    lines = ["", style.paint("Overview", "bold")]
    lines += profile_rows(
        style,
        (
            ("Languages", counted(overview["languages"], "language", "files")),
            ("Files", file_row(overview["files"])),
            ("Frameworks", names(overview["frameworks"])),
            ("Test tools", names(overview["test_tools"])),
            ("Runtimes", runtimes),
            ("Package tools", names(overview["package_tools"])),
        ),
        "Technology",
    )
    if risks:
        lines += profile_rows(style, risks, "Technology risks")
    else:
        lines += note(
            style,
            "Technology risks: none recognized from the bundled list; no proof of absence.",
        )
    lines += profile_rows(
        style,
        (
            *history_rows(development["history"]),
            ("Process files", names(development["process_files"])),
            ("CI", ci),
            ("Quality tools", names(development["quality_tools"])),
            ("Security tools", names(development["security_tools"])),
        ),
        "Development",
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
        *note(
            style, "Findings are static pattern matches; exploitability unverified.", ""
        ),
    ]
    if partial:
        lines += note(
            style,
            "Partial result: subscores describe recognized evidence only; no repository grade is available.",
            "",
        )
    if scope.get("check_selection"):
        selection = scope["check_selection"]
        text = f"Checks: {safe(selection['checks'])}"
        if selection.get("skip_checks"):
            text += f"; skipped: {safe(selection['skip_checks'])}"
        lines += note(
            style, text + f" ({selection['count']} selected; subset assessment).", ""
        )
    lines += overview_section(style, result.get("overview"))
    topics = subcategories(result)
    width = max(len(topic["title"]) for topic in topics)
    for topic in topics:
        lines += ["", topic_header(style, topic, width)]
        lines += score_explanation(style, topic)
        lines += topic_examples(style, topic)
        if topic["id"] == "authentication":
            lines += identity_profile(style, result.get("architecture") or {})
        if topic["id"] == "architecture":
            lines += architecture_profile(style, result.get("architecture", {}))
            lines += note(
                style,
                "Basis: selected execution, SQL and deserialization patterns; no full architectural review.",
            )
        if topic["id"] == "dependencies":
            lines += dependency_profile(style, result.get("architecture") or {})
        if topic["id"] == "deployment":
            lines += infrastructure_profile(result.get("architecture") or {})

    count = len(result["findings"])
    lines += [
        "",
        style.paint("Coverage", "bold"),
        f"  {plural(result['coverage'].get('files_checked', 0), 'file')} checked {style.dot} "
        f"{plural(count, 'finding')} {style.dot} "
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
    lines += ["", *note(style, score_legend(), "")]
    return "\n".join(lines)
