# How Security Score works

Security Score answers two different questions:

- **Repository scan:** What did the bundled checks find in the selected repository? This produces a score from 0 to 100 and a grade from A to F when enough checks complete.
- **Change analysis:** Could the selected change affect security-related behavior? This produces `high`, `medium`, `low`, or `unclear` relevance. It does not produce a score.

The checks are deterministic and limited to the patterns in [rules.json](../rules.json). A score is not an estimate of attack probability or proof that the application is safe. The optional Analyzer engine has its own scoring policy; see [compatibility.md](compatibility.md).

## Repository scores

### How points are deducted

Findings are grouped into areas, such as execution or injection. Every finding deducts points from its area. Its severity also sets the highest score that area can receive.

| Severity | Points deducted per finding | Highest area score |
| --- | ---: | ---: |
| Critical | 50 | 39 |
| High | 25 | 59 |
| Medium | 10 | 79 |
| Low | 3 | 89 |

For each area, add all deductions, subtract them from 100, apply the strictest cap present, and stop at 0. The repository score is the **lowest assessed area score**. Findings in different areas are not added together.

```text
area score = max(0, min(100 - total deductions in area, strictest cap))
repository score = lowest assessed area score
```

For example, one high finding deducts 25 points, but the high-severity cap lowers its area's result from 75 to **59 (E)**. Two high findings in the same area deduct 50 points, giving **50 (E)**. A high finding in each of two areas gives 59 in each, so the repository score is still **59 (E)**. A recognized check with no findings can score 100; it does not cancel findings in another area. These weights and caps are a documented heuristic, not a calibrated risk model.

| Score | Grade |
| --- | --- |
| 90–100 | A |
| 80–<90 | B |
| 70–<80 | C |
| 60–<70 | D |
| 50–<60 | E |
| 0–<50 | F |

### When there is no score

A check can be `violated`, `satisfied`, `unclear`, or `not_applicable`. The scanner records a violation when it recognizes one; otherwise it records unclear evidence before a recognized control. Merely finding a technology name does not prove a control works. Indirect flows, aliases, and external configuration may remain unclear.

At least one source or dependency check must provide recognized evidence, and required processing must finish. Host settings alone cannot establish an application score. When evidence is insufficient, the verdict is `undetermined`. When required processing fails or hits a limit, it is `incomplete`. Both retain available findings but withhold score and grade. Scoring version 3 withholds the overall score whenever an application check is unclear or recognized application source files use an unsupported language. Unknown repository-host settings do not block otherwise assessable application evidence. A score still covers only the bundled checks; inspect `--details` before using it.

Detailed and JSON/YAML output show each area's deductions and cap. `areas[].breakdown` lists the rule, severity, number of findings, points per finding, deduction, and cap.

## Change relevance

Change relevance asks what the change touches, including fixes and correctly implemented security features. It is independent of finding severity. The strongest recognized indication sets the level; indications are not added or averaged.

| Level | Meaning |
| --- | --- |
| `high` | The change touches access decisions, security functions, interface exposure, persistence or network boundaries, cryptography, dependencies, build or deployment authority, agent instructions, or executable permissions. |
| `medium` | Recognized frontend input/output behavior or security-related policy and guidance changes. |
| `low` | The complete change is identified as ordinary documentation or a supported nonfunctional edit, with no security indication. |
| `unclear` | The available rules cannot classify the changed behavior or context. No findings does not imply low relevance. |

Examples:

- Changing `can_read(actor, owner)` from an ownership check to `True` indicates an access-decision change: **high**. The level alone does not prove the new behavior is exploitable.
- Changing a listener address from `127.0.0.1` to `0.0.0.0` indicates possible interface exposure: **high**. It does not prove the service is reachable from outside.
- Editing only a Python comment can be **low** when AST comparison confirms the code is unchanged. A generic code change with no recognized evidence is **unclear**.

Each reported `signal` identifies the matching rule, reason, aspect, file location, side of the comparison, and relationship to the changed lines. Both added and removed code are examined. Findings are reported separately as `introduced`, `worsened`, `pre_existing`, `resolved`, or `unresolved`; an unchanged finding appears only in affected context. These labels compare recognized observations, not whole application flows.

### Context used for changes

For a full local Git comparison, the tool examines changed lines, up to two nearby lines, and the enclosing function when it can identify one. Function context is limited to 200 lines. Python uses AST boundaries; JavaScript/TypeScript, Java, Kotlin, C#, Go, Rust, and PHP use syntax heuristics. Functions longer than 200 lines contribute their declaration and changed/nearby lines. Files over 10,000 lines skip function expansion. `coverage.context_limited_files` lists affected files. These methods do not resolve call graphs or full application behavior.

A supplied patch is narrower: each hunk is examined on its own, without inferring the full function. For PR/MR context, use a captured local base/head comparison when possible. Metadata-only changes, permission changes, symlinks, and rename/copy metadata require local Git comparison; a patch containing them is rejected. Unsupported or excluded files prevent a `low` result. Python AST and JSON structure can establish some comment/format-only changes; no such claim is made for opaque languages.

A complete change analysis exits 0 even when relevance is `unclear`; incomplete processing exits 1. Structured output uses `analysis: change-relevance`, `relevance`, `relevance_version`, `signals`, and `finding_changes`, without score or grade fields. An unclear or incomplete result is not an approval.

## What the scanner checks

The catalog recognizes selected source patterns for Python, JavaScript/TypeScript, frontend frameworks, SQL access, Content Security Policy, debug and TLS settings, dependencies, CI workflows, and containers. It records architecture hints such as React, Angular, Vue, and database libraries without awarding points for their mere presence.

CSP checks recognize literal headers and nginx `add_header`. A positive declaration restricts scripts and includes `object-src 'none'`, `base-uri 'none'`, and `frame-ancestors`. The scanner does not verify delivery through every route, proxy overrides, or dynamic policies. Dependency checks cover selected package declarations and lockfiles, lifecycle scripts, immutable Action/container references, and explicit workflow permissions. They do not establish vulnerability status or complete package integrity. No target project code, tests, hooks, package installation, build, or vulnerability-feed query runs.

For a GitHub.com or GitLab.com repository URL, the tool resolves an identified revision and reads available host settings separately. Explicitly disabled settings can produce findings; denied or missing API data remains unknown. Some GitHub security settings need additional permissions, and GitLab approval rules need authentication. A feature being available does not prove it ran. See the [GitHub repository API](https://docs.github.com/en/rest/repos/repos), [GitHub branch protection API](https://docs.github.com/en/rest/branches/branch-protection), [GitLab projects API](https://docs.gitlab.com/api/projects/), and [GitLab approval rules API](https://docs.gitlab.com/api/merge_request_approvals/).

## Maintaining the rules

[rules.json](../rules.json) is the editable catalog shipped with Security Score. The repository being scanned cannot replace it. Each rule has an ID, severity, area, criteria, next action, and examples. The `scoring` section holds point weights and caps; `change_relevance` holds change classification rules. Detector code determines what is actually recognized: changing only a rule's descriptive text does not change detection.

| To change | Edit |
| --- | --- |
| Points deducted per finding | `scoring.weights.<severity>` in `rules.json` |
| Highest score allowed for a severity | `scoring.severity_caps.<severity>` in `rules.json` |
| Severity of one rule | That rule's `severity` in `rules.json` |
| Recognition of a source pattern | The named detector in `scripts/score_core.py` or `scripts/score_architecture.py` |
| Host-setting recognition | `scripts/score_remote.py` |
| Change classification | `change_relevance` in `rules.json` and `scripts/score_relevance.py` |
| Score formula or grade calculation | `scripts/score_calculation.py` and this guide |

Weights must be whole points from 1 to 100; caps must be whole numbers from 0 to 100. Higher severities must have weights at least as large and caps no higher than lower severities. Grade bands are fixed by REQ-03 in [requirements.md](../requirements.md). The formula identifiers `aggregation` and `repetitions` are validated; editing their names alone does not change the calculation.

For example, lowering `scoring.weights.high` from 25 to 15 makes three high findings in one area deduct 45 points. The cap remains 59, so the area's result is `min(55, 59) = 55 (E)`. A single high finding still scores 59 unless its cap also changes.

When you change rules:

1. Keep existing rule IDs stable. Register new detector kinds in policy validation and source applicability.
2. Add positive, negative, and unclear examples, plus boundary tests. Use synthetic data without real credentials or personal information.
3. Update expected scores and grades in affected examples. Increase `scoring_version` when score meaning changes, `rule_version` when detection or catalog rules change, and `change_relevance.version` when relevance classification changes.
4. Run the bundled examples and tests, then compare a representative repository before and after with `--details`:

```sh
python3 scripts/score.py --verify-rules
python3 -B -m unittest test_security_score -v
```

Run the test command from the `security-score` directory. Catalog and implementation fingerprints help identify results produced under different policies. Version 1 and version 2 scores with repeated findings are not directly comparable.

## Limits

The default total time budget is 15 seconds; `--timeout` accepts 0.1–120 seconds. The scanner checks the budget between bounded operations, so a large repository may finish incomplete.

| Limit | Value |
| --- | ---: |
| Inventory or remote tree entries | 3,000 |
| Remote file-listing metadata, including all pages | 8 MiB |
| Parallel selected-source requests | 8 |
| Selected source file | 512 KiB |
| Selected source per comparison side | 20 MiB |
| Supplied patch | 4 MiB |
| Tool or download output | 24 MiB |
| Observations per side | 5,000 |
| Retained relevance signals | 1,000 |

Remote scans list files at the resolved commit and fetch only supported, non-excluded sources; no repository archive is downloaded or expanded. Requests reuse checked HTTPS connections within each worker. Public GitHub sources use `raw.githubusercontent.com` without API credentials; authenticated GitHub and GitLab sources use their respective APIs. GitHub tree truncation and incomplete GitLab pagination fail without a score. File-count, source-byte, per-file, metadata, and total-time limits still apply. Authenticated API requests may also hit host rate limits.

Excluded or unreadable files, malformed patches, and sources that change during a run can prevent a complete result. JSON/YAML keep the bounded result; compact text explains an incomplete scan and `--details` adds affected paths. Missing repositories and inaccessible private repositories may both return HTTP 404; errors do not claim to distinguish those cases. Output reports locations and explanations, without raw source snippets or credential literals.

Relevance version 3 also reflects the updated JavaScript evidence. Scoring version 3 adds the application-coverage gate; rule version 4 counts JavaScript execution calls independently of line breaks and retains template interpolation as code. Nested expressions, strings and comments are handled; ambiguous slash syntax in interpolation and unfinished templates withhold a score rather than hiding executable content. Versions with different coverage gates or detectors are not directly comparable.
