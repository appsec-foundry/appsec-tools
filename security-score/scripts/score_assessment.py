"""Evidence-qualified area subscores; legacy scoring is deliberately separate."""

import ast
from collections import defaultdict
from fractions import Fraction
from pathlib import PurePosixPath
import re

from score_calculation import POLICY, has_unknown
from score_design import inspect as inspect_design
from score_boundaries import inspect as inspect_boundaries
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
    if [d["id"] for d in CONFIG["domains"]] != ["architecture", "identity", "data", "dependencies", "deployment", "ai"]:
        raise ValueError("Invalid subscore domains")
    if any(type(d.get("optional", False)) is not bool for d in CONFIG["domains"]):
        raise ValueError("A domain's optional flag must be true or false")
    for owner, owned in CONFIG.get("location_owners", {}).items():
        if owner not in RULES or any(rule not in RULES for rule in owned):
            raise ValueError("Location owners must name catalog rules")
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
    boundaries = [] if subset else inspect_boundaries(files, budget)
    boundary_locations = {(row["file"], row["line"]): row for row in boundaries if row["status"] != "unclear"}
    result["coverage"]["design_checks"] = [] if subset else ["DESIGN-CONTAINER-ISOLATION", "DESIGN-DATA-BOUNDARY"]
    design_paths = {r["file"] for r in design}
    # A specific finding owns generic observations at its exact location, e.g.
    # model output reaching eval() owns the unresolved JS-EVAL candidate there.
    owners, related = {}, defaultdict(list)
    for owner, owned in CONFIG.get("location_owners", {}).items():
        for finding in result["findings"]:
            if finding["rule"] == owner:
                for rule in owned:
                    owners[(rule, finding["file"], finding.get("line", 0))] = owner
    for finding in result["findings"]:
        budget.check()
        domain, criterion = assignment(finding["rule"], finding["area"])
        if domain is None:
            continue
        owner = owners.get((finding["rule"], finding["file"], finding.get("line", 0)))
        if owner:
            related[(owner, finding["file"], finding.get("line", 0))].append(finding["rule"])
            continue
        if finding["rule"] == "IAC-PRIVILEGED" and finding["file"] in design_paths:
            continue  # The structured design check owns this component evidence.
        if finding["rule"] in {"JS-SQL", "PY-SQL"} and (finding["file"], finding["line"]) in boundary_locations:
            boundary_locations[(finding["file"], finding["line"])].setdefault("related_rules", []).append(finding["rule"])
            continue  # The resolved boundary owns this operation; do not deduct twice.
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
    for (owner, path, line), rules in related.items():
        domain, criterion = assignment(owner, RULES[owner]["area"])
        row = issues[domain].get((criterion, path, line))
        if row:
            row["rules"] += [rule for rule in sorted(set(rules)) if rule not in row["rules"]]
    for check in result["checks"]:
        if check["rule"] in {"JS-SQL", "PY-SQL"} and check.get("locations"):
            remaining = [item for item in check["locations"] if (check["file"], item["line"]) not in boundary_locations]
            if not remaining:
                continue
            check = {**check, "locations": remaining}
            check["status"] = "unclear" if any(item["status"] == "unclear" for item in remaining) else "violated" if any(item["status"] == "violated" for item in remaining) else "satisfied"
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
            observed["architecture"].update(row.get("supported_criteria", [row["criterion"]]))
        else:
            gaps["architecture"].add("isolation: unresolved container design")
    for row in boundaries:
        if row["status"] == "violated":
            key = (row["criterion"], row["file"], row["line"])
            issues["architecture"][key] = {
                **row, "rules": [row["rule"], *row.get("related_rules", [])], "title": row["reason"],
            }
        elif row["status"] == "satisfied":
            observed["architecture"].add(row["criterion"])
        else:
            gaps["architecture"].add("query-binding: request-to-database flow requires review")
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
        # An optional area applies only where its subject is recognized; partial
        # processing or check selection cannot establish its absence.
        if domain.get("optional") and not (
            issues[name] or incomplete or subset or global_unknown
            or any(c["area"] in domain["areas"] and c["status"] != "not_applicable" for c in result["checks"])
        ):
            subscores.append({
                "id": name, "title": domain["title"], "applicable": False, "score": None,
                "rating": "Not applicable", "reason": "No AI integration or agent configuration was recognized.",
                "coverage": "not applicable", "controls": [], "gaps": [], "breakdown": [],
                "severity_cap": 100, "independent_weaknesses": 0,
                "limitations": list(domain.get("limitations", [])),
            })
            continue
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
            "id": name, "title": domain["title"], "applicable": True, "score": value if assessable else None,
            "rating": rating(value) if assessable else "Not assessed", "reason": reason,
            "coverage": "limited" if gaps[name] else "assessed static criteria",
            "controls": sorted(observed[name]), "gaps": sorted(gaps[name]),
            "breakdown": breakdown, "severity_cap": cap, "independent_weaknesses": len(entries),
            "limitations": list(domain.get("limitations", [])),
        })
    bad = [s for s in subscores if s["score"] is not None and s["score"] < CONFIG["ratings"][3][0]]
    complete_basis = all(s["score"] is not None and not s["gaps"] for s in subscores if s["applicable"])
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
                  scoring_policy="area-subscores", subscores=subscores, overall=overall,
                  review_hints=hints, design_evidence=design)
    result["boundary_evidence"] = boundaries
    result["comparability"].update(scoring_version=CONFIG["version"], scoring_policy="area-subscores")
    result["verdict"] = "incomplete" if incomplete else "assessed" if complete_basis else "limited"
    return result


def render(result, details=False, style=None):
    from score_reporting import (
        ai_profile, architecture_profile, dependency_profile, entry, identity_profile,
        infrastructure_profile, note, overview_section, plural, source_priority,
        supply_chain_profile, compose_profile,
    )
    from score_style import Style

    style = style or Style()
    values = [row["score"] for row in result["subscores"] if row["score"] is not None]
    value = min(values) if values and result["overall"]["rating"] != "Not assessed" else None
    summary = "Not assessed" if value is None else f"{value}/100 ({rating(value)})"
    summary = style.paint(summary, style.band(value), "bold")
    if not details:
        return summary

    lines = [style.paint("Security score", "bold") + f" {style.dot} " + summary]
    scope = result["scope"]
    revision = f" @ {safe(scope['revision'][:12])}" if scope.get("revision") else ""
    lines.append(f"Scope: {safe(scope['repository'])}{revision}")
    lines += overview_section(style, result.get("overview"), concise=True)
    width = max(len(row["title"]) for row in result["subscores"])
    architecture = result.get("architecture", {})
    for row in result["subscores"]:
        if row["score"] is None:
            points = "—" if style.unicode else "-"
        else:
            points = f"{row['score']}/100"
        lines += ["", (
            style.paint(f"{row['title']:<{width}}", "bold") + "  "
            + style.paint(f"{points:>7}", style.band(row["score"]), "bold")
            + f"  {style.bar(row['score'])}  "
            + style.paint(row["rating"], style.band(row["score"]))
        )]
        groups = defaultdict(list)
        for item in row["breakdown"]:
            groups[tuple(item["rules"])].append(item)
        ranked = sorted(groups.items(), key=lambda pair: (
            min(SEVERITIES.index(item["severity"]) for item in pair[1]),
            -sum(item["deduction"] for item in pair[1]), pair[0],
        ))
        for rules, items in ranked[:3]:
            first = min(items, key=lambda item: (source_priority(item["file"]), str(item.get("pointer", item.get("line", 0)))))
            severity = min((item["severity"] for item in items), key=SEVERITIES.index)
            deduction = sum(item["deduction"] for item in items)
            location = f"{safe(first['file'])}:{safe(first.get('pointer', first.get('line', '?')))}"
            more = f" (+{len(items) - 1} more)" if len(items) > 1 else ""
            title = first["reason"] if "DESIGN-CONTAINER-ISOLATION" in rules else first["title"]
            lines += entry(style, style.tag(severity), f"{safe(title)} (-{deduction:.1f} points)",
                           f"{', '.join(rules)} {style.dot} {location}{more}")
        if len(ranked) > 3:
            hidden = sum(item["deduction"] for _, items in ranked[3:] for item in items)
            lines += note(style, f"+{len(ranked) - 3} more finding types (-{hidden:.1f} points).")
        if not row["applicable"]:
            lines += note(style, row["reason"])
        elif row["score"] is None:
            reason = {
                "architecture": "No sufficient evidence from the supported data-access and isolation checks.",
                "identity": "Access permissions need manual review.",
                "ai": "Not enough evidence to rate AI controls.",
            }.get(row["id"], "Not enough evidence to rate this area.")
            lines += note(style, reason)
        if row["id"] == "ai":
            lines += ai_profile(style, result["checks"], concise=True)
        elif row["id"] == "identity":
            lines += identity_profile(style, architecture, concise=True)
        elif row["id"] == "architecture":
            if row["score"] is not None:
                lines += note(style, "Score scope: supported static data-access, isolation and privilege checks.")
            lines += architecture_profile(style, architecture, concise=True)
            design = {}
            for item in result.get("design_evidence", []):
                if item["status"] != "violated":
                    design.setdefault((item["status"], item["reason"]), []).append(item)
            for (status, reason), items in list(design.items())[:2]:
                first = items[0]
                tag = style.paint(f"{'OK' if status == 'satisfied' else 'REVIEW':<8}", "green" if status == "satisfied" else "yellow")
                location = f"{safe(first['file'])}:{safe(first['pointer'])}"
                more = f" (+{len(items) - 1} more)" if len(items) > 1 else ""
                lines += entry(style, tag, safe(reason), location + more)
            protected = [item for item in result.get("boundary_evidence", []) if item["status"] == "satisfied"]
            for item in protected[:2]:
                lines += entry(style, style.paint(f"{'OK':<8}", "green"), safe(item["reason"]),
                               f"{safe(item['file'])}:{item['line']}")
        elif row["id"] == "dependencies":
            lines += dependency_profile(style, architecture, concise=True)
            lines += supply_chain_profile(style, architecture)
            repository_gaps = architecture.get("artifact_repository_gaps", [])
            if repository_gaps:
                paths = ", ".join(safe(gap["file"]) for gap in repository_gaps[:2])
                more = f", +{len(repository_gaps) - 2} more" if len(repository_gaps) > 2 else ""
                lines += note(style, f"Package repository settings were not inspected ({paths}{more}).")
        elif row["id"] == "deployment":
            for line in infrastructure_profile(architecture, limit=3):
                lines += note(style, line)
            lines += compose_profile(style, architecture)

    lines += ["", style.paint("Coverage", "bold")]
    count = sum(row["independent_weaknesses"] for row in result["subscores"])
    weaknesses = plural(count, "finding")
    lines += note(style, f"{plural(result['coverage'].get('files_checked', 0), 'file')} checked {style.dot} "
                  f"{weaknesses}")
    if result["verdict"] == "incomplete":
        lines += note(style, "Assessment incomplete; some files or checks could not be processed.")
    hints = [hint for hint in result["review_hints"] if hint["disposition"] == "review"]
    if hints:
        lines += note(style, f"{len(hints)} further observations need manual review.")
    errors = result.get("source_errors", [])
    if errors:
        more = f", +{len(errors) - 1} more" if len(errors) > 1 else ""
        lines += note(style, f"{plural(len(errors), 'file')} could not be parsed ({safe(errors[0]['file'])}{more}).")
    exclusions = [row for row in result.get("exclusions", []) if row["reason"] != "excluded or unsupported"]
    if exclusions:
        more = f", +{len(exclusions) - 1} more" if len(exclusions) > 1 else ""
        lines += note(style, f"{plural(len(exclusions), 'source item')} excluded ({safe(exclusions[0]['file'])}{more}).")
    if any(row["coverage"] == "limited" for row in result["subscores"]):
        lines += note(style, "Some areas lack sufficient evidence; runtime protection remains unverified.")
    lines += note(style, "All findings, calculations and check results: --json or --yaml.")
    return "\n".join(lines)
