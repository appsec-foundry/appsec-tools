"""Five evidence-qualified subscores; legacy scoring is deliberately separate."""

import ast
from collections import defaultdict
from fractions import Fraction
from pathlib import PurePosixPath
import re

from score_calculation import POLICY, has_unknown
from score_design import inspect as inspect_design
from score_style import safe


CONFIG = POLICY["subscore_policy"]
SEVERITIES = ("critical", "high", "medium", "low")
RULES = {r["id"]: r for r in POLICY["rules"]}


def validate_policy():
    if type(CONFIG["version"]) is not int or CONFIG["version"] < 1:
        raise ValueError("Invalid subscore version")
    for name in ("deductions", "caps"):
        if set(CONFIG[name]) != set(SEVERITIES) or any(
            type(v) is not int or not 0 <= v <= 100 for v in CONFIG[name].values()
        ):
            raise ValueError("Invalid subscore values")
    for a, b in zip(SEVERITIES, SEVERITIES[1:]):
        if CONFIG["deductions"][a] < CONFIG["deductions"][b] or CONFIG["caps"][a] > CONFIG["caps"][b]:
            raise ValueError("Subscore severity order is inverted")
    bands = CONFIG["ratings"]
    if ([b[1] for b in bands] != ["Very good", "Good", "OK", "Needs improvement", "Bad", "Very bad"]
        or any(type(b[0]) is not int or not 0 <= b[0] <= 100 for b in bands)
        or any(a[0] <= b[0] for a, b in zip(bands, bands[1:])) or bands[-1][0] != 0):
        raise ValueError("Invalid subscore rating bands")
    if type(CONFIG["minimum_positive_criteria"]) is not int or CONFIG["minimum_positive_criteria"] < 2:
        raise ValueError("Positive ratings need independent control evidence")
    if [d["id"] for d in CONFIG["domains"]] != ["architecture", "identity", "data", "dependencies", "deployment"]:
        raise ValueError("Invalid subscore domains")
    if CONFIG["caps"]["high"] >= bands[3][0] or CONFIG["caps"]["critical"] >= bands[4][0]:
        raise ValueError("Serious weaknesses must limit the verdict")


def rating(value):
    return next(label for threshold, label in CONFIG["ratings"] if value >= threshold)


def assignment(rule, area):
    for domain in CONFIG["domains"]:
        for criterion, ids in domain["criteria"].items():
            if rule in ids:
                return domain["id"], criterion
    for domain in CONFIG["domains"]:
        if area in domain["areas"]:
            return domain["id"], CONFIG["families"].get(rule, rule)
    return None, None


class Context:
    """Read only already-selected sources; no import, evaluation or extra file reads."""

    def __init__(self, files, budget):
        self.files, self.budget, self.cache = files, budget, {}

    def at(self, finding):
        path = finding["file"]
        if path not in self.cache:
            self.budget.check()
            source = self.files.get(path, {})
            text = source.get("text", "")
            tree = None
            if PurePosixPath(path).suffix == ".py" and not source.get("fragment"):
                try:
                    tree = ast.parse(text)
                except (SyntaxError, ValueError, RecursionError):
                    pass
            calls = defaultdict(list)
            if tree is not None:
                for node in ast.walk(tree):
                    if isinstance(node, ast.Call):
                        calls[node.lineno].append(node)
            self.cache[path] = (text.splitlines(), calls)
        lines, calls = self.cache[path]
        line = finding.get("line", 0)
        return (lines[line - 1] if 0 < line <= len(lines) else ""), calls.get(line, [])

    def classify(self, finding):
        rule = finding["rule"]
        if rule in CONFIG["context_only"]:
            return "review", "Context alone does not establish a weakness in the protected flow."
        line, calls = self.at(finding)
        if rule == "JS-CORS" and re.search(r"origin\s*:\s*(['\"])\*\1", line):
            return "review", "Wildcard credentialed CORS is a browser-blocked configuration, not reflected-origin credential access."
        if rule == "JS-COOKIE" and re.search(r"\.cookie\(\s*(['\"])theme\1\s*,\s*(['\"])(?:dark|light)\2", line):
            return "neutral", "Fixed presentation cookie; no session credential is established."
        if rule not in CONFIG["candidate_rules"]:
            return "scored", "Explicit configuration or recognized control weakness."
        if rule == "PY-EXEC":
            relevant = [n for n in calls if isinstance(n.func, ast.Name) and n.func.id in {"eval", "exec"}]
            if relevant and all(n.args and isinstance(n.args[0], ast.Constant) and isinstance(n.args[0].value, str) for n in relevant):
                return "neutral", "Execution receives a fixed literal; no external input is established."
            for call in relevant:
                if call.args and any(
                    isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "input"
                    for n in ast.walk(call.args[0])
                ):
                    return "scored", "Interactive input reaches dynamic execution in the same expression."
        return "review", "Input trust, effective controls or execution context needs verification."


def deductions(issues):
    """Same criterion: full deduction, then 1/2, 1/3, ...; no three-hit cutoff."""
    groups = defaultdict(list)
    for issue in issues:
        groups[issue["criterion"]].append(issue)
    total, cap, rows = Fraction(0), 100, []
    for criterion, entries in sorted(groups.items()):
        entries.sort(key=lambda r: (SEVERITIES.index(r["severity"]), r["file"], str(r.get("pointer", r.get("line", 0)))))
        for index, entry in enumerate(entries, 1):
            points = CONFIG["deductions"][entry["severity"]]
            total += Fraction(points, index)
            cap = min(cap, CONFIG["caps"][entry["severity"]])
            rows.append({**entry, "points": points, "divisor": index, "deduction": round(points / index, 3)})
    # Round once, half upwards, using exact rational arithmetic.
    value = max(Fraction(0), min(Fraction(cap), 100 - total))
    rounded = (2 * value.numerator + value.denominator) // (2 * value.denominator)
    return rounded, rows, cap


def assess(result, files, budget):
    validate_policy()
    context = Context(files, budget)
    issues, observed, gaps, hints = defaultdict(dict), defaultdict(set), defaultdict(set), []
    subset = bool(result["scope"].get("check_selection"))
    design = [] if subset else inspect_design(files, budget)
    result["coverage"]["design_checks"] = [] if subset else ["DESIGN-CONTAINER-ISOLATION"]
    design_paths = {r["file"] for r in design}
    for finding in result["findings"]:
        budget.check()
        domain, criterion = assignment(finding["rule"], finding["area"])
        if domain is None:
            continue
        if finding["rule"] == "IAC-PRIVILEGED" and finding["file"] in design_paths:
            continue  # The structured design check owns this component evidence.
        disposition, reason = context.classify(finding)
        row = {k: finding[k] for k in ("rule", "file", "line", "severity", "title") if k in finding}
        row.update(criterion=criterion, reason=reason)
        if disposition != "scored":
            hints.append({**row, "domain": domain, "disposition": disposition})
            if disposition == "review":
                gaps[domain].add(f"{criterion}: context requires review")
            continue
        key = (criterion, row["file"], row.get("line", 0))
        if key in issues[domain]:
            current = issues[domain][key]
            current["rules"].append(row["rule"])
            if SEVERITIES.index(row["severity"]) < SEVERITIES.index(current["severity"]):
                current["severity"] = row["severity"]
        else:
            issues[domain][key] = {**row, "rules": [row["rule"]]}
    # Specific password-storage evidence owns a hash observation across domains.
    # Keep both detector IDs, but deduct for the shared operation only once.
    shared = {}
    for domain, entries in issues.items():
        for key, row in entries.items():
            if key not in shared:
                shared[key] = (domain, row)
                continue
            old_domain, old = shared[key]
            preferred = CONFIG.get("owners", {}).get(row["criterion"])
            owner = (domain, row) if preferred in row["rules"] else (old_domain, old)
            merged = {**owner[1], "rules": sorted(set(old["rules"] + row["rules"]))}
            merged["severity"] = min((old["severity"], row["severity"]), key=SEVERITIES.index)
            shared[key] = (owner[0], merged)
    issues = defaultdict(dict)
    for key, (domain, row) in shared.items():
        issues[domain][key] = row
    for check in result["checks"]:
        domain, criterion = assignment(check["rule"], check["area"])
        if domain is None:
            continue
        if has_unknown(check):
            gaps[domain].add(f"{criterion}: unresolved check")
        # Technology/presence-only evidence cannot qualify a positive score.
        if check["status"] == "satisfied" and not has_unknown(check) and not RULES.get(check["rule"], {}).get("positive_only") and criterion not in CONFIG["workflow_criteria"]:
            observed[domain].add(criterion)
    for row in design:
        if row["status"] == "violated":
            key = ("isolation", row["file"], row["pointer"])
            issues["architecture"][key] = {
                **row, "rules": [row["rule"]], "title": "Declared container breaks the host isolation boundary",
            }
        elif row["status"] == "satisfied":
            observed["architecture"].add("isolation")
        else:
            gaps["architecture"].add("isolation: unresolved container design")
    for domain in CONFIG["domains"]:
        for criterion in domain["required"]:
            gaps[domain["id"]].add(f"{criterion}: requires design or access-flow review")
    if not subset:
        for profile in result.get("architecture", {}).get("supply_chain", []):
            controls = {row["criterion"]: row for row in profile["controls"]}
            if profile["ecosystem"] == "Node.js":
                unresolved = {c["file"] for c in result["checks"] if c["rule"] == "NPM-SOURCES" and has_unknown(c)}
                resolved = set(profile["resolved_registry_manifests"])
                if unresolved and unresolved <= resolved:
                    gaps["dependencies"].discard("NPM-SOURCES: unresolved check")
                    result["coverage"]["resolved_check_gaps"] = [{
                        "rule": "NPM-SOURCES", "files": sorted(unresolved),
                        "basis": "Matching manifest constraints and located registry artifacts with integrity in the npm lockfile.",
                    }]
            install = "node-locked-install" if profile["ecosystem"] == "Node.js" else "python-locked-install"
            enforced = controls[install]["status"] == "supported"
            if not enforced:
                gaps["dependencies"].add(f"{profile['ecosystem']}: locked installation enforcement is not established")
            integrity = "node-artifact-integrity" if profile["ecosystem"] == "Node.js" else "python-artifact-hashes"
            if controls[integrity]["status"] != "supported":
                gaps["dependencies"].add(f"{profile['ecosystem']}: artifact integrity is not established")
            for criterion, row in controls.items():
                if row["status"] == "supported" and enforced:
                    observed["dependencies"].add(criterion)
                if criterion == "node-lock-consistency" and row["status"] == "weakness":
                    for location in row["locations"]:
                        if location.get("matches") is not False:
                            continue
                        key = (criterion, location["file"], location["line"])
                        issues["dependencies"][key] = {
                            **location, "criterion": criterion, "severity": "medium",
                            "rule": "SC-NODE-LOCK-CONSISTENCY", "rules": ["SC-NODE-LOCK-CONSISTENCY"],
                            "title": "Manifest constraints differ from the npm lockfile workspace entry",
                            "reason": "The captured manifest and lockfile disagree.",
                        }
    incomplete = result["verdict"] == "incomplete"
    global_unknown = any(c["area"] == "coverage" and has_unknown(c) for c in result["checks"])
    subscores = []
    for domain in CONFIG["domains"]:
        name = domain["id"]
        if incomplete:
            gaps[name].add("Required source processing did not complete")
        if subset:
            gaps[name].add("Only a subset of checks was selected")
        if global_unknown and name in {"architecture", "identity", "data"}:
            gaps[name].add("Application source coverage is unresolved")
        entries = list(issues[name].values())
        value, breakdown, cap = deductions(entries)
        positive_basis = len(observed[name]) >= CONFIG["minimum_positive_criteria"] and not gaps[name]
        serious = any(e["severity"] in {"high", "critical"} for e in entries)
        # A demonstrated serious defect can be rated despite incomplete wider coverage.
        assessable = serious or positive_basis
        if not positive_basis:
            gaps[name].add("Insufficient independent control evidence for a positive assessment")
        if positive_basis and not entries:
            reason = "Recognized controls satisfy the assessed static criteria."
        elif entries:
            strongest = min(entries, key=lambda e: (SEVERITIES.index(e["severity"]), e["file"], str(e.get("pointer", e.get("line", 0)))))
            reason = strongest["title"]
        else:
            reason = "Insufficient evidence to assess this area."
        subscores.append({
            "id": name, "title": domain["title"], "score": value if assessable else None,
            "rating": rating(value) if assessable else "Not assessed", "reason": reason,
            "coverage": "limited" if gaps[name] else "assessed static criteria",
            "controls": sorted(observed[name]), "gaps": sorted(gaps[name]),
            "breakdown": breakdown, "severity_cap": cap, "independent_weaknesses": len(entries),
        })
    bad = [s for s in subscores if s["score"] is not None and s["score"] < CONFIG["ratings"][3][0]]
    complete_basis = all(s["score"] is not None and not s["gaps"] for s in subscores)
    rated = bad or (subscores if complete_basis else [])
    if rated:
        worst = min(rated, key=lambda s: s["score"])
        overall = {"rating": worst["rating"], "reason": f"{worst['title']}: {worst['reason']}"}
    else:
        overall = {"rating": "Not assessed", "reason": "Some areas lack sufficient evidence for an overall assessment."}
    # Explicitly remove every legacy scalar/group index from this output contract.
    for key in ("score", "grade", "observed_score", "areas", "origin_groups"):
        result.pop(key, None)
    result.update(analysis="security-assessment", scoring_version=CONFIG["version"],
                  scoring_policy="five-subscores", subscores=subscores, overall=overall,
                  review_hints=hints, design_evidence=design)
    result["comparability"].update(scoring_version=CONFIG["version"], scoring_policy="five-subscores")
    result["verdict"] = "incomplete" if incomplete else "assessed" if complete_basis else "limited"
    return result


def render(result, details=False, style=None):
    lines = []
    for row in result["subscores"]:
        value = "—" if row["score"] is None else f"{row['score']}/100"
        suffix = " · limited evidence" if row["coverage"] == "limited" else ""
        lines.append(f"{row['title']:<32} {value:>7} · {row['rating']}{suffix}")
        if details:
            lines.append(f"  Reason: {safe(row['reason'])}")
            for item in row["breakdown"]:
                location = f"{safe(item['file'])}:{safe(item.get('pointer', item.get('line', '?')))}"
                lines.append(f"  {', '.join(item['rules'])} · {location} · {item['points']}/{item['divisor']} = {item['deduction']:g} points")
            if row["breakdown"]:
                lines.append(f"  Calculation: max(0, min(100 - deductions, {row['severity_cap']})); round once.")
            for gap in row["gaps"]:
                lines.append(f"  Open: {safe(gap)}")
            if row["controls"]:
                lines.append("  Supported criteria: " + ", ".join(row["controls"]))
    lines += ["", f"Overall: {result['overall']['rating']}", f"Reason: {safe(result['overall']['reason'])}"]
    if result["verdict"] == "incomplete":
        lines.append("Processing incomplete; available evidence is retained.")
    if details:
        from score_reporting import overview_section
        from score_style import Style

        lines += overview_section(style or Style(), result.get("overview"))
        architecture = result.get("architecture", {})
        for provider in architecture.get("identity_providers", []):
            lines.append(f"SSO: {safe(provider.get('url') or provider.get('server') or 'unresolved')} ({safe(provider['endpoint'])}, {safe(provider['file'])}:{provider['line']})")
        for repository in architecture.get("artifact_repositories", []):
            lines.append(f"Artifact repository: {safe(repository['url'])} ({safe(repository['ecosystem'])}, {safe(repository['evidence'])}, {safe(repository['file'])}:{repository['line']})")
        for gap in architecture.get("artifact_repository_gaps", []):
            lines.append(f"Artifact repository unresolved: {safe(gap['file'])} · {safe(gap['reason'])}")
        from score_reporting import infrastructure_profile

        lines += infrastructure_profile(architecture)
        for profile in architecture.get("supply_chain", []):
            lines.append(f"Supply chain ({profile['ecosystem']}):")
            for control in profile["controls"]:
                lines.append(f"  {control['criterion']}: {control['status']} · {control['reason']}")
                for location in control["locations"][:3]:
                    lines.append(f"    {safe(location['file'])}:{location['line']}")
        for hint in result["review_hints"]:
            lines.append(f"Review: {hint['rule']} · {safe(hint['file'])}:{hint.get('line', '?')} · {hint['reason']}")
        for error in result.get("source_errors", []):
            lines.append(f"Source: {safe(error['file'])} · {safe(error['reason'])}")
        for exclusion in result.get("exclusions", []):
            if exclusion["reason"] != "excluded or unsupported":
                lines.append(f"Excluded: {safe(exclusion['file'])} · {safe(exclusion['reason'])}")
        lines.append("Scope: recognized source/configuration criteria; runtime enforcement and wider flows remain unverified.")
        if "duration_seconds" in result:
            lines.append(f"Duration: {result['duration_seconds']:.2f} s")
    return "\n".join(lines)
