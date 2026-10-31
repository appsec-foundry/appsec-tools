# Requirements for Security Score

Core requirements for Security Score. Usage and output are described in the
[README](README.md), the calculation in the [scoring reference](references/scoring.md).
Tests pin the exact behavior.

- **REQ-01 — Standalone and deterministic.** The default engine uses only the
  bundled rules, without AppSec Analyzer or model calls. The same sources, rules,
  and settings give the same security result, and each result names its rule and
  scoring versions; observational timing metadata is excluded from this guarantee.

- **REQ-02 — Repositories and changes.** Scan local checkouts and GitHub.com or
  GitLab.com repository URLs, including the repository-host security settings for
  URLs. Analyze changes (staged, unstaged, commits, revision ranges, patches) and
  state the compared versions. Checks cover data access, frontend output, CSP and
  other browser security headers, token verification, password hashing, session and
  CORS settings, credentials, hardening including container privileges, a narrow set
  of Terraform misconfigurations, and the dependency, CI workflow and build supply
  chain, including GitLab CI. Terraform stays a narrow set; a full policy catalog is
  left to dedicated tools.

- **REQ-03 — Score, grade, and change relevance.** A repository scan gives a score
  from 0 to 100, where 100 means no deductions, and a grade: A ≥ 90, B ≥ 80, C ≥ 70,
  D ≥ 60, E ≥ 50, F < 50. Passed checks cannot offset a serious finding. Only a
  fixed number of findings per rule deduct points, so one repeated pattern does not
  hide every other difference; all findings stay in the output. A change
  gets a security relevance of high, medium, low, or unclear instead of a score. It
  depends on the security behavior the change touches, not only on detected
  weaknesses; introduced, worsened, resolved, and pre-existing findings are
  reported separately.

- **REQ-04 — Honest limits.** Keep findings, positive evidence, unknowns, and
  exclusions apart. A detected technology is no proof of protection. Without
  enough coverage, or when required checks fail, withhold score and grade but keep
  the findings. Rules that can only report positive evidence never make an area or
  a repository assessable. No findings in a change does not mean low relevance, and
  a high score does not mean the code is safe.

- **REQ-05 — Fast and bounded.** A repository scan should finish within a default
  budget of about 60 seconds, and all processing is bounded. When a limit stops a
  scan, report the index of the evidence found so far as partial, without a grade,
  and state what was not covered.

- **REQ-06 — Analyzer only on request.** AppSec Analyzer is used only when selected
  explicitly. The internal engine stays the default, even when Analyzer is installed.

- **REQ-07 — Reproducible calculation.** A score can be recalculated by hand.
  Weights and caps are kept in one place and can be changed without touching the
  detection rules. Each rule ships with examples and expected results. JSON/YAML
  output contains every finding and every value used in the calculation.

- **REQ-08 — Three console modes.** The default text output is one result line on
  stdout; `--details` adds per-topic subscores with a few located findings each;
  `--quiet` prints only the number. Progress goes to stderr and is suppressed in
  quiet and JSON/YAML modes. The exit status is the same in every mode, so scripts
  can tell a partial result from a complete one. Redirected output contains no
  color codes, and text from the scanned repository cannot inject terminal control
  characters. Detailed text ends with the elapsed scan duration; structured output
  requested with details includes it as `duration_seconds`, without affecting the
  score, relevance, exit status or quiet output.

- **REQ-09 — End-to-end check before release.** Changes to URL scanning or console
  output need a live run of the installed CLI against
  `https://github.com/juice-shop/juice-shop` before release. Once enabled, this test
  fails on missing evidence, crashes, or a missed deadline instead of skipping.

- **REQ-10 — Architecture profile.** A repository scan reports recognized
  architecture traits with their evidence: login through SSO, passwords or both,
  authentication mechanisms, the hash a password reaches, single-page app or
  server-side templates, persistence, how SQL query text is built, deployment
  targets, how CI logs in to a cloud, lockfiles, exact dependency versions and the
  update tool. The profile is context only and never changes score or grade; a trait
  that is not recognized is reported as such, not as absent.

- **REQ-11 — Security headers as positive evidence.** Browser security headers
  other than CSP count only as positive evidence. A missing, disabled, or
  dynamically set header is neither a finding nor an unclear check, because
  proxies and platform configuration outside the repository can set it.

- **REQ-12 — Credentials stay out of results.** Credential checks report file and
  line, never the value. Files on the sensitive list are not read or downloaded;
  they are recognized by path alone. Only formats with a fixed prefix count, because
  entropy guesses would flood the score with false findings.

- **REQ-13 — Known vulnerabilities stay outside the score.** Known dependency
  vulnerabilities do not change score or grade, because feed data changes daily and
  REQ-01 requires the same sources to give the same result. A scan must not send
  dependency names to a third party unless the user selects that explicitly.

- **REQ-14 — Controls outside the repository.** Signals that can equally be set
  outside the repository, such as SBOMs, signed releases, update tooling, security
  policies, and non-root container settings, count only as positive evidence. Their
  absence is neither a finding nor an unclear check.

- **REQ-15 — Repository overview only with `--details`.** A repository scan with
  `--details` adds languages, files, technologies and development signals such as
  branches, pull or merge request markers, process files and CI. Only such a run
  collects them: any other scan does no extra file, Git or host API work and does
  not load this code. The overview never changes score, grade, findings or exit
  status, and author addresses stay out of the output.

- **REQ-16 — Technology risks are hints, not findings.** The overview names insecure
  or end-of-life technology from a bundled list. Because it runs only with
  `--details`, it cannot deduct points: a score must not depend on the output mode.
  End of life is a fixed limit in that list, never a comparison with today's date,
  so the same sources give the same result (REQ-01). Version-specific vulnerabilities
  stay outside (REQ-13).

- **REQ-17 — Authentication evidence follows recognized calls.** Password hashing
  checks follow simple JavaScript/TypeScript helpers through one relative import
  into already-selected complete source files and distinguish fast general-purpose
  hashes from password KDFs. JWT option checks apply to recognized verification
  calls; unresolved verification options remain unclear, and unrelated option
  objects never establish authentication evidence.

- **REQ-18 — Targeted authentication checks.** Recognize explicit unsafe OAuth
  flow choices, disabled SAML audience or time validation, and direct comparisons
  of request passwords with stored password fields in supported source patterns.
  Missing settings alone must not imply a vulnerability or disregard equivalent
  controls supplied by a protocol or library.

- **REQ-19 — Identity providers and grants.** Report recognized identity servers,
  endpoint roles and OAuth grants with source locations, distinguishing requested,
  configured and merely supported grants. Link a grant to a server only from
  explicit evidence, leave dynamic configuration unresolved, and omit credentials,
  paths and query parameters from reported server origins.

- **REQ-20 — TLS and certificate configuration evidence.** Report recognized TLS
  APIs/listeners and certificate or trust configuration as positive evidence only,
  without reading certificate or key material or inferring deployment protection.
  Explicitly disabled client certificate or hostname verification is a finding;
  server-side TLS semantics must not be confused with client verification.

- **REQ-21 — User-selected checks.** Allow users to list, select and omit bundled
  check groups or individual rule IDs for internal repository scans; the default
  remains the complete enabled catalog. Reject unknown or empty selections, report
  the chosen scope and withhold a full repository grade for a subset.

- **REQ-22 — Detailed scan progress.** Detailed text mode reports preparation,
  file-check progress and major scan stages on stderr. Progress must not corrupt
  structured output, quiet output, findings or exit statuses.
