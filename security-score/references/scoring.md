# How Security Score works

For the default repository assessment, see [Security subscores](subscores.md). The repository arithmetic below describes the legacy interface selected with `--legacy-score`.

Security Score answers two different questions:

- **Repository scan:** What did the bundled checks find in the selected repository? This produces a score from 0 to 100 and a grade from A to F when enough checks complete.
- **Change analysis:** Could the selected change affect security-related behavior? This produces `high`, `medium`, `low`, or `unclear` relevance. It does not produce a score.

The checks are deterministic and limited to the patterns in [rules.json](../rules.json). With `--details`, elapsed wall time is observational metadata: text ends with `Duration: N.NN s`, and JSON/YAML contains `duration_seconds`. It includes source selection, checks and the requested overview, but does not participate in scores, fingerprints or relevance. A score is not an estimate of attack probability or proof that the application is safe. The optional Analyzer engine has its own scoring policy; see [compatibility.md](compatibility.md).

## Repository scores

### How points are deducted

Findings are grouped into areas, such as execution or injection. A finding deducts points from its area, and its severity sets the highest score that area can receive. Only the first three findings of a rule deduct points, so a pattern repeated many times does not push an area to 0 on its own. Every finding stays in the output.

| Severity | Points deducted per finding | Highest area score |
| --- | ---: | ---: |
| Critical | 50 | 39 |
| High | 25 | 59 |
| Medium | 10 | 79 |
| Low | 3 | 89 |

For each area, add all deductions, subtract them from 100, apply the strictest cap present, and stop at 0. The repository score is the **lowest assessed area score**. Findings in different areas are not added together.

```text
rule deduction = weight * min(findings of the rule, 3)
area score = max(0, min(100 - total rule deductions in area, strictest cap))
repository score = lowest assessed area score
```

For example, one high finding deducts 25 points, but the high-severity cap lowers its area's result from 75 to **59 (E)**. Two high findings in the same area deduct 50 points, giving **50 (E)**. Nine findings of one high rule deduct 75 points, giving **25 (F)**; two high rules with three findings each reach **0 (F)**. A high finding in each of two areas gives 59 in each, so the repository score is still **59 (E)**. A recognized check with no findings can score 100; it does not cancel findings in another area. These weights and caps are a documented heuristic, not a calibrated risk model.

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

At least one source or dependency check must provide recognized evidence, and required processing must finish. Host settings alone cannot establish an application score. Neither can rules marked `positive_only`: they are listed as `OK` lines, but they deduct nothing and never make an area or a repository assessable, so a single `helmet()` call does not earn a grade. No recognized evidence gives `undetermined`; recognized evidence alongside uncertain application coverage gives `partial`. Failed required processing or limits give `incomplete`. All three withhold the repository score and grade. Since scoring version 4, `observed_score` preserves the index calculated from recognized patterns even for a partial or incomplete assessment; it is not a repository grade. Unknown repository-host settings alone do not block otherwise assessable application evidence. Exit status is 0 for `scored`, 2 for `partial` or `undetermined`, and 1 for `incomplete`.

Candidates carry `certainty: static-pattern` and an `origin` path hint. `origin_groups` reports separate counts, check outcomes, and observed indices for `source`, `tests`, `examples`, `assets`, `build`, and `repository-host`. Path hints do not establish runtime relevance or trusted library ownership; all candidates remain in the selected repository assessment, so moving application code under a test or asset path cannot hide it. These indices are heuristic deductions from recognized mechanisms, not confirmed vulnerabilities, coverage percentages, or measured risk. Detailed text groups repeated candidates by rule and file; structured output retains every occurrence. `source_errors` summarizes processing failures once per file with the affected rule IDs. Other unknown evidence is summarized by origin and rule in text; JSON/YAML retain per-file checks.

Detailed and JSON/YAML output show each area's deductions and cap. `areas[].breakdown` lists the rule, severity, number of findings, points per finding, deduction, and cap.

## Selecting checks

`--checks` accepts comma-separated group names or rule IDs; `--skip-checks` removes them. `--list-checks` lists groups without reading a repository, while `--list-rules` lists individual rules. Selection applies to internal repository scans only. The enabled bundled catalog remains the default; an explicit `all` is equivalent. Selection is local to a scan and never mutates the catalog. Shared parsing can serve several selected checks; findings and check outcomes contain only the selected rules and required coverage observations.

A strict subset withholds the repository grade and reports its recognized index as partial (or undetermined/incomplete when appropriate). `coverage.selected_checks` lists the selected IDs, `scope.check_selection` describes a custom scope, and `comparability.selected_checks_fingerprint` identifies it. Default weights and severity caps still apply to every recognized finding. Detailed text shows the selection and stage/file progress; quiet and structured modes suppress progress.

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

The catalog recognizes selected source patterns for Python, JavaScript/TypeScript, frontend frameworks, SQL access, Content Security Policy, debug and TLS settings, JWT verification options, password hashing, cookie and session settings, credentials, dependencies, GitHub and GitLab CI, Dockerfiles, container YAML and Terraform. It also builds an architecture profile from declared packages, Python imports, configuration files and selected code patterns: login (SSO, passwords or both), authentication mechanisms (local passwords, SSO through OIDC/OAuth or SAML, JWT, server sessions), the hash a password reaches, frontend style (single-page app framework or server-side templates), persistence (SQL or document store), how recognized SQL query calls build their text, taken from the PY-SQL and JS-SQL checks, deployment targets, and how CI logs in to a cloud. A password read from a request body counts as local password login. The profile is context only: it awards no points, and `none recognized` does not mean the trait is absent.

Deployment targets come from file names, Terraform providers, CI steps and Kubernetes or CloudFormation manifests. A declaration does not establish that anything is deployed there. Cloud login distinguishes OIDC (AWS `role-to-assume`, Azure `tenant-id`, GCP `workload_identity_provider`, GitLab `id_tokens`) from stored keys; CI-CLOUD-OIDC records OIDC as positive evidence, and stored keys stay context because a declaration does not show how a key is scoped or rotated.

PASSWORD-HASH follows a password-named value into a hash call on the same line or through a helper function in the same file. MD5 and SHA-1 are findings; bcrypt, Argon2, scrypt, PBKDF2 and framework password hashers are positive evidence. A helper in another file is not resolved, so Juice Shop's `security.hash` stays unrecognized, and a declared package alone proves nothing: the profile's mechanism line can name bcrypt while the hash line reports MD5.

Secret checks never output a value. SECRET-TOKEN reads supported sources for AWS, GitHub, GitLab, Slack, npm, Stripe and Anthropic formats and for PEM private keys with key material; generic strings are not assessed, and documentation samples and repeated placeholder characters do not match. SECRET-FILE and TF-STATE use the file list only. Files such as `.env`, `*.pem` and `*.key` stay on the sensitive list and are neither read nor downloaded, so whether one holds a live secret is not established. `.npmrc` is on that list as well and has no rule. Git-ignored files are not listed for a local Git checkout; a directory without Git has no such filter.

Terraform checks read `.tf` files line by line within brace-delimited blocks of up to 200 lines. They recognize SSH or RDP open to any source in AWS, Azure and GCP firewall declarations, public storage ACLs and databases, wildcard IAM statements, and external modules without a fixed version. Whether a resource is deployed is not established. This is a narrow set, not a policy catalog.

CSP checks recognize literal headers and nginx `add_header`. A positive declaration restricts scripts and includes `object-src 'none'`, `base-uri 'none'`, and `frame-ancestors`. Sources that browsers ignore are not counted: `'unsafe-inline'` next to a nonce or hash, and host or scheme sources next to `'strict-dynamic'`. The scanner does not verify delivery through every route, proxy overrides, or dynamic policies.

WEB-HEADERS records other browser security headers as positive evidence only: `X-Content-Type-Options: nosniff`, `X-Frame-Options` with `DENY` or `SAMEORIGIN`, `Strict-Transport-Security` with a positive `max-age`, `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Resource-Policy` with `same-origin` or `same-site`, and a restrictive `Referrer-Policy` (`no-referrer`, `same-origin`, `strict-origin` or `strict-origin-when-cross-origin`). It reads literal values in object literals, subscript assignments, `set`/`setHeader`/`header`/`append` calls, Python header dictionaries and assignments, and nginx `add_header`, plus Express helmet for a recognized `helmet` import. `helmet()` counts all six headers unless an option names one; options of `helmet()` and its middlewares are not evaluated. A missing, weak or dynamically set header is neither a finding nor an unclear check, because a proxy or platform outside the repository may set it (REQ-11). Reading a header, as in a test assertion, is no declaration. `--details` names the recognized headers; JSON/YAML add a `detail` field to each location.

The same logic applies to other signals that can be set outside the repository (REQ-14): IAC-USER (the last `USER` of the final stage is a literal non-root identity), IAC-HARDENING (`runAsNonRoot`, `readOnlyRootFilesystem`), REPO-SECURITY-POLICY, DEP-UPDATE-CONFIG, CI-RELEASE-INTEGRITY (SBOM, signature, provenance and trusted publishing steps), TF-LOCK, CI-CLOUD-OIDC and HOST-SIGNED-COMMITS only ever report positive evidence.

Dependency checks cover selected package declarations and lockfiles, package indexes, lifecycle scripts, immutable Action/container references, and explicit workflow permissions. NPM-LOCK-SOURCES reads `package-lock.json` and `npm-shrinkwrap.json`: HTTP, a host beside the public registries and the file's most frequent host, and an entry without integrity are findings, so a private registry used throughout a lock is not. `yarn.lock` is not read, because a file over the size limit would withhold the grade of every larger Yarn project. DEP-SOURCES reads `pyproject.toml`, `Cargo.toml`, `pom.xml` and Gradle build files for HTTP repositories, extra index URLs and Git dependencies without a full commit. `go.mod` has no rule, because `go.sum` already pins module content. REPO-BINARY names compiled artifacts from the file list. These checks do not establish vulnerability status or complete package integrity. No target project code, tests, hooks, package installation, build, or vulnerability-feed query runs, and known vulnerabilities stay outside the score (REQ-13).

DEP-LOCK reports a `package.json` with dependencies, a `Pipfile`, or a `pyproject.toml` with dependencies but no build backend when no lockfile of that ecosystem sits beside it or in a directory above, so a workspace root covers its packages. The file list decides and lockfile content stays unread, which also covers `yarn.lock`. A `pyproject.toml` with a build backend may be a library and stays unassessed; an npm library is reported like an application. A present lockfile earns no credit and makes nothing assessable, and a cut-off file listing produces no finding, because an absent lockfile then proves nothing. PY-DEPENDENCIES counts an exact `==` version as pinned and names a SHA-256 hash separately. Lockfiles, the share of exact direct versions and Renovate or Dependabot appear in the Dependencies & CI profile (`architecture.lockfiles`, `exact_versions`, `dependency_updates`); they add no points. A range in `package.json` next to a lockfile is no finding, because the lockfile holds the version.

CI checks read `.github/workflows/`, `.gitlab-ci.yml` and `.gitlab/ci/` files line by line, not as a full YAML document. CI-REMOTE-SCRIPT inspects `run` values and GitLab `script`, `before_script` and `after_script` values for a download piped to an interpreter. CI-FROZEN-INSTALL compares `npm install` without named packages with `npm ci` in CI scripts and Dockerfile `RUN` instructions. CI-GITLAB-IMAGE and CI-GITLAB-INCLUDE require a digest or a full commit; a value with a variable is not assessed. CI-GITLAB-INJECTION needs `eval` or `sh -c` next to a contributor-editable variable, because a shell only expands `$CI_MERGE_REQUEST_TITLE` and does not run it. CI-SCRIPT-INJECTION looks only inside `${{ }}` expressions in `run` and `script` values, including block scalars, and only for event fields an outside contributor can edit, such as issue and pull request titles, comment bodies and head branch names. CI-PR-HEAD-CHECKOUT needs a `pull_request_target` or `workflow_run` trigger plus a `ref` that selects the pull request head, or `gh pr checkout`; whether the checked-out code runs is not established. Container checks read Dockerfile and Containerfile variants and YAML keys such as `privileged`, `hostNetwork` and Docker socket mounts in any `.yml`/`.yaml` file. Templated values remain unclear, and whether a file is deployed is not established.

JWT checks cover `jwt.decode` in Python and literal options of `jwt.verify`, `jsonwebtoken.verify` and `express-jwt` in JavaScript, including ESM and `require` aliases. Disabled signature or expiry verification and an allowed `none` algorithm are findings; a literal algorithm list is positive evidence. Missing, dynamic, spread or duplicate relevant JavaScript options remain unclear. An unrelated `algorithms` field gives no evidence. JavaScript calls that only decode a token, key handling and claim validation are not assessed.

PASSWORD-HASH follows password-named inputs into recognized hashing calls and simple local helpers. JavaScript/TypeScript also follows one relative ESM or `require` import to a named ESM export, including extensionless paths and directory `index` files, using only complete files already selected for the scan. Simple helpers take one parameter and directly return a recognized hash expression; re-exports, default exports, ambiguous paths and multi-hop flows are not resolved. MD5, SHA-1, SHA-2 and SHA-3 are findings when used for passwords. Recognized bcrypt, Argon2, scrypt, PBKDF2 and framework password hashers give positive evidence for algorithm choice only; parameters, salts and migrations remain unverified. Python helpers stay within one file.

JS-COOKIE, JS-CORS and WEB-SETTINGS recognize literal cookie flags, credentialed CORS with a wildcard or reflected origin, Django and Flask session settings and `ALLOWED_HOSTS`; computed values are not assessed. Full login-flow and access-control verification remains outside the catalog.

Authentication checks also flag direct comparisons of request passwords with stored password fields; OAuth authorization responses containing an access token, the password grant and PKCE `plain`; and Node-SAML/Passport-SAML options explicitly disabling audience or assertion-time validation. These are scoped to recognized calls and protocol parameter builders, not arbitrary matching words. Missing `state` is not a finding, because PKCE or an OIDC nonce can supply equivalent protection. An assertion-signature preference set to false does not prove that every SAML signature check is disabled. The criteria follow the [OAuth Security BCP](https://datatracker.ietf.org/doc/html/rfc9700) and [Node-SAML validation options](https://github.com/node-saml/node-saml#security-and-signatures).

The Authentication identity profile reports `architecture.identity_providers` and `architecture.oauth_grants`. It recognizes selected OAuth/OIDC and SAML API calls, browser authorization redirects (including one leading local URL constant), OIDC metadata JSON, Keycloak adapter server URLs and scalar Spring OAuth2 client YAML settings. The `server` field retains the scheme, host and explicit port. The `url` field and detailed text preserve ordinary endpoint paths, including realms; credentials, query strings and fragments are omitted, and credential-bearing URLs retain only their origin. Provider labels use known hosts or an explicitly marked Keycloak-compatible path; custom hosts are still shown without guessing the product. Test/example evidence remains in checks but does not populate this application profile. No discovery request is sent.

Grants carry `requested`, `configured` or `supported` evidence. A response type containing `code` indicates `authorization_code`; a token-only response indicates `implicit`. Supported grants in metadata are not evidence of a client using them. Standard grants, device code, JWT bearer and token exchange can be profiled; unknown or dynamic values remain `unresolved`. A grant is associated with a server only from its actual request, the same configuration call, or an explicit Spring registration/provider reference. Separate parameter builders retain an unresolved server instead of being attributed to another provider in the file.

TLS-USAGE and TLS-CERTIFICATE are positive evidence only, covering imported Node.js TLS/HTTPS APIs, Python TLS contexts and certificate-chain loading, and nginx listener/certificate directives. They establish configuration presence only. PY-TLS-CONTEXT additionally flags disabled hostname or certificate verification on recognized local client contexts and leaves server or rebound contexts unassessed. Existing PY-TLS and JS-TLS retain their verification-option checks. Certificate/key files are not opened; live handshakes, certificate expiry, chain validity, trust and TLS termination require deployment evidence. API semantics follow [Node.js TLS](https://nodejs.org/api/tls.html) and [Python ssl](https://docs.python.org/3/library/ssl.html).


For a GitHub.com or GitLab.com repository URL, the tool resolves an identified revision and reads available host settings separately. Explicitly disabled settings can produce findings; denied or missing API data remains unknown. Some GitHub security settings need additional permissions, and GitLab approval rules need authentication. For a protected GitHub branch the tool also reads the applied ruleset rules, which need no admin rights, for required reviews, status checks and signatures. A missing ruleset rule proves nothing, because classic protection may set the same control. A feature being available does not prove it ran. See the [GitHub repository API](https://docs.github.com/en/rest/repos/repos), [GitHub branch protection API](https://docs.github.com/en/rest/branches/branch-protection), [GitHub rules API](https://docs.github.com/en/rest/repos/rules), [GitLab projects API](https://docs.gitlab.com/api/projects/), and [GitLab approval rules API](https://docs.gitlab.com/api/merge_request_approvals/).

## Maintaining the rules

[rules.json](../rules.json) is the editable catalog shipped with Security Score. The repository being scanned cannot replace it. Each rule has an ID, severity, area, criteria, next action, and examples. The `scoring` section holds point weights and caps; `change_relevance` holds change classification rules. Detector code determines what is actually recognized: changing only a rule's descriptive text does not change detection.

| To change | Edit |
| --- | --- |
| Points deducted per finding | `scoring.weights.<severity>` in `rules.json` |
| Findings of one rule that deduct points | `scoring.counted_instances` in `rules.json` |
| Highest score allowed for a severity | `scoring.severity_caps.<severity>` in `rules.json` |
| Severity of one rule | That rule's `severity` in `rules.json` |
| Whether a rule runs | That rule's `enabled` in `rules.json`; `false` disables it and keeps its ID reserved |
| Whether a rule can only report positive evidence | That rule's `positive_only` in `rules.json` |
| Recognition of a file by its path | That rule's `pattern` and `exclude` in `rules.json` (kind `path`) |
| Recognition of a source pattern | The named detector in `scripts/score_core.py`, `scripts/score_architecture.py`, `scripts/score_infrastructure.py` or `scripts/score_controls.py` |
| Host-setting recognition | `scripts/score_remote.py` |
| Change classification | `change_relevance` in `rules.json` and `scripts/score_relevance.py` |
| Score formula or grade calculation | `scripts/score_calculation.py` and this guide |

Weights must be whole points from 1 to 100; caps must be whole numbers from 0 to 100; `counted_instances` must be a positive whole number. Higher severities must have weights at least as large and caps no higher than lower severities. Grade bands are fixed by REQ-03 in [requirements.md](../requirements.md). The formula identifiers `aggregation` and `repetitions` are validated; editing their names alone does not change the calculation.

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

The tables of the `--details` overview live in `scripts/score_overview.py`, not in `rules.json`, because the overview is not part of the score (REQ-15, REQ-16). `EOL_BELOW` holds the first supported version per runtime. Raise a limit when upstream support ends and never compare with the current date. `INSECURE_PACKAGES` takes only packages that are the problem in every version; a vulnerability in some versions belongs to dedicated tools (REQ-13). `score.py` imports this module only in the `--details` branch, so no other module may import it.

## Limits

The default total time budget is 60 seconds; `--timeout` accepts 0.1–120 seconds. URL scans give source selection and downloads 70% of the remaining time after host discovery, reserving the rest to analyze available sources and publish a result. The scanner checks the budget between bounded operations; active network requests can take a few seconds to settle. This is an approximate execution budget, not a hard process deadline.

| Limit | Value |
| --- | ---: |
| Local inventory entries / retained remote tree entries | 3,000 |
| Remote file-listing metadata, including all pages | 8 MiB |
| Parallel selected-source requests | 8 |
| Selected source file | 512 KiB |
| Selected source per comparison side | 20 MiB |
| Supplied patch | 4 MiB |
| Tool or download output | 24 MiB |
| Observations per side | 5,000 |
| Retained relevance signals | 1,000 |

Remote scans list files at the resolved commit and fetch only supported, non-excluded sources; no repository archive is downloaded or expanded. Requests reuse checked HTTPS connections within each worker. Public GitHub sources use `raw.githubusercontent.com` without API credentials; authenticated GitHub and GitLab sources use their respective APIs. Source selection and scanning prioritize package manifests, lockfiles and Dockerfiles, then application sources and build configuration, followed by tests, examples and assets. Ordering does not remove candidates from a complete scan.

Remote entry-count and source-byte limits retain a bounded sample. A truncated tree or GitLab pagination stopped by the time/entry limit is recorded as incomplete coverage. Download timeouts and individual request failures retain other successful sources, including requests completed while workers settle at the selection deadline. Metadata size/format errors, unsafe paths, invalid object IDs and source size mismatches still fail without a result. These changes do not raise the file, byte, request-concurrency or metadata bounds. Authenticated API requests may also hit host rate limits. `coverage.files_downloaded`, `coverage.files_checked` and `coverage.selection_limits` identify the available sample; checked files are those with at least one rule outcome. Sampling under a time limit depends on network performance, so incomplete indices are not reproducible whole-repository assessments.

Every HTTP header/body exchange has a five-second wall-clock deadline, capped by
the available budget; DNS, connection and TLS operations also use bounded waits.
Interrupted or truncated bodies never become selected sources. All resolved
addresses are checked before connection attempts; fallback keeps TLS hostname
verification and credential-origin checks. Optional host metadata uses 10% of the
remaining budget per request and becomes unknown on failure. Download exclusions
retain bounded HTTP-status diagnostics without response bodies or raw exceptions.
Parser recursion/structure errors are recorded as `SOURCE-PROCESSING` issues on
the affected file and do not erase observations from other files. Numeric
application indices require recognized source evidence, including for incomplete
results; repository-host observations alone remain insufficient. Scoring version
5 makes this requirement explicit for `observed_score`; version 4 could expose a
host-only observed index. Arithmetic and grade bands are unchanged. The source
policy is `bounded-static-v3` for the prioritized, budgeted selection.

Excluded or unreadable files, malformed patches, and sources that change during a run can prevent a complete result. Normal console mode prints one result line on stdout and progress on stderr. `--detail` (alias `--details`) shows one block per topic, with its subscore and up to three located finding types directly beneath it. Up to two kinds of satisfied checks follow as `OK` lines, each with its first location and occurrence count; they are shown next to findings but never raise an index. A topic takes the lowest recognized existing area index within it; deductions are not pooled and the overall score is unchanged. Authentication remains unassessed without matching checks, and Architecture covers selected execution, injection and deserialization patterns rather than a full design review. Technology observations never award points. The topic mappings are documented in the [usage reference](usage.md#topics). Totals and omitted finding types remain explicit; JSON/YAML preserve the original areas, full calculations and every occurrence. A short coverage summary follows the blocks. `--quiet` (alias `--quite`) emits only the numeric repository or observed pattern index, or nothing when unavailable, and suppresses progress and diagnostic text. Partial/incomplete results retain their nonzero exit status even when a number is printed. JSON/YAML retain the verdict and all bounded diagnostics without progress output. Missing repositories and inaccessible private repositories may both return HTTP 404; errors do not claim to distinguish those cases. Output reports locations and explanations, without raw source snippets or credential literals.

Scoring version 4 introduces partial evidence indices and origin summaries. Rule version 5 and relevance version 4 refine shell recognition: `exec`/`execSync` need a recognized `child_process` import binding to produce a shell candidate; unresolved bare or member calls remain unknown, and object methods such as `regex.exec` do not produce shell findings without a recognized import. Narrow ES module and CommonJS imports, including simple aliases, are recognized. Re-exports, dynamic bindings, shadowing and whole-program data flows are not resolved; a recognized import is still only static evidence. Template interpolation is retained as code. Nested expressions, strings and comments are handled; ambiguous slash syntax in interpolation and unfinished templates withhold a repository grade. Versions with different coverage gates or detectors are not directly comparable.

Rule version 6 and relevance version 5 add the JWT, CI injection, pull request checkout, container privilege, container download, Python random and JavaScript hash rules, and correct earlier detectors. The JavaScript lexer recognizes regular-expression literals from the preceding token: after an operator, an opening bracket or a keyword such as `return`, a slash starts a literal; after a value it is division. A literal must close on its line. Otherwise the slash is read as division, as before, except inside template interpolation, where it still withholds a grade. Files that version 5 could not read because of a quote inside a regular expression are now scanned, which can add findings. Changes in the affected area context of the new `authentication` area are high relevance. IAC-USER and NPM-LOCK are disabled. IAC-USER flagged every `USER root` line, including a temporary switch before a non-root user, and could not see a container without any `USER`. NPM-LOCK could not deduct points, and a missing or non-npm lockfile only withheld the grade.

Rule version 7 and relevance version 6 add WEB-HEADERS. It never deducts points. Changes to recognized header declarations are high relevance through the `frontend-policy` area, like CSP changes.

Scoring version 6, rule version 8 and relevance version 7 count at most three findings per rule and stop positive-only rules from making an area or a repository assessable; until then, WEB-HEADERS alone could earn a repository 100 (A). They add the Secrets topic, GitLab CI, CI download and install checks, lockfile and manifest source checks, committed binaries, password hashing, cookie, CORS and session settings, Terraform and further positive evidence. IAC-USER returns as a positive-only rule for the final stage. GitHub rulesets now establish required reviews, status checks and signatures. Scores from earlier versions are not comparable: repeated findings deduct less, and repositories can receive findings they did not have before.

Rule version 9 adds DEP-LOCK, counts an exact Python requirement as pinned where it was unclear before, and recognizes more Renovate configuration paths. Repositories without a lockfile can lose points, and a repository whose only unclear checks were exact requirements can now receive a grade. A provider's sign-in URL in source code now shows SSO in the profile.

Rule version 13, relevance version 8 and subscore policy version 3 add the `ai` area with the AI & agents rules, OpenAI and Hugging Face token formats in SECRET-TOKEN, and the `ai` check group. Changes to MCP or agent configuration (REL-AGENT-CONFIG) and in the affected context of AI checks are high relevance. Repositories using AI SDKs or committing agent configuration can receive new findings; others show the area as Not applicable. `scoring_policy` is now `area-subscores`.

Rule version 14 and subscore policy version 4 add AI-CLIENT-MESSAGES for request data passed as the model conversation, and name recognized model calls and tools in AI-INTEGRATION locations for the AI profile.

Rule version 15 extends AI-INTEGRATION with provider API families, declared models,
selected call options and model endpoint classes. Supported LLM configuration
declarations also make the AI area applicable; this inventory never earns credit
and does not resolve runtime configuration or change deduction criteria.
