# Requirements for Security Score

Core requirements for Security Score. Usage and output are described in the
[README](README.md), the calculation in the [scoring reference](references/scoring.md).
Tests pin the exact behavior.

- **REQ-01 — Standalone and deterministic.** The default engine uses only the
  bundled rules, without AppSec Analyzer or model calls. The same sources, rules,
  and settings give the same security result, and each result names its rule and
  scoring versions; observational timing and network metadata are excluded from
  this guarantee.

- **REQ-02 — Repositories and changes.** Scan local checkouts and HTTPS repository
  URLs on GitHub.com, GitLab.com, and explicitly selected self-managed GitLab
  instances, including repository-host security settings. Authenticate private
  GitLab reads through explicit or automatic token environment variable selection.
  Analyze changes (staged, unstaged, commits, revision ranges, patches) and
  state the compared versions. Checks cover data access, frontend output, CSP and
  other browser security headers, token verification, password hashing, session and
  CORS settings, credentials, hardening including container privileges, a narrow set
  of Terraform misconfigurations, and the dependency, CI workflow and build supply
  chain, including GitLab CI. Terraform stays a narrow set; a full policy catalog is
  left to dedicated tools.

- **REQ-03 — Five security subscores.** With `--score`, report five repository subscores from 0–100 with plain-language ratings: Architecture & isolation, Identity & access, Data & processing, Dependencies & supply chain, and Deployment & operations. Add an overall verdict with its main reason, without an overall numeric score; serious weaknesses, including security-design flaws, must limit that verdict. Changes retain a separate security-relevance assessment without a numeric score; direct CLI calls without `--score` retain the legacy score interface.

- **REQ-04 — Evidence and limits.** Distinguish findings, supported controls, unknowns and exclusions, and report coverage and incomplete checks separately from ratings. Leave areas without sufficient evidence unassessed; positive ratings require evidence of effective protection. Technology presence, high scores and absence of findings do not establish safety, and missing evidence does not establish low change relevance.

- **REQ-05 — Fast and bounded.** Repository scans use a default budget of about 60 seconds with bounded processing. Retain available evidence when processing is incomplete and state what was not covered.

- **REQ-06 — Analyzer only on request.** AppSec Analyzer is used only when selected
  explicitly. The internal engine stays the default, even when Analyzer is installed.

- **REQ-07 — Explainable calculation.** Publish understandable, manually reproducible criteria and calculations, centrally editable scoring values, and comparison examples. Count each underlying weakness once, and prevent unrelated strengths from offsetting serious weaknesses. Detailed output explains the subscores, decisive evidence and gaps.

- **REQ-08 — Console and structured output.** `--score` shows five subscores and an overall verdict; `--details` explains results, while JSON/YAML preserve the structured evidence. Legacy direct calls retain one-line output and numeric `--quiet`; all modes preserve actual completion status, keep progress on stderr, and prevent terminal-control injection. Detailed output includes elapsed time as observational metadata only.

- **REQ-09 — End-to-end check before release.** Changes to URL scanning or console
  output need a live run of the installed CLI against
  `https://github.com/juice-shop/juice-shop` before release. Once enabled, this test
  fails on missing evidence, crashes, or a missed deadline instead of skipping.

- **REQ-10 — Architecture and service profiles.** Report recognized architecture traits, authentication services and concrete SSO endpoints, and configured or lockfile-observed artifact repositories with their evidence. Preserve useful endpoint paths without credentials or query tokens, and distinguish declarations from runtime use. Technology and endpoint inventories give no score credit; evidenced security-design weaknesses can affect the architecture subscore.

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

- **REQ-23 — Network usage in details.** Internal scans with `--details` report
  HTTP request attempts and response body bytes read, in total and per host,
  including metadata and overview requests and discarded reads. State the
  measurement boundaries, expose no credentials or request paths, and add no
  requests or changes to scoring, exit status, plain output or quiet output;
  JSON/YAML with details includes the counters as `network`.

- **REQ-24 — Automatic host-bound credentials.** An explicit `--token-env`
  selection takes precedence. Otherwise, remote reads start anonymously and may
  retry once with a token environment variable configured by the user for that
  exact HTTPS origin when authentication is needed, falling back to `GIT_TOKEN`
  if no mapping matches and that variable is set. Bind either automatic selection
  to the selected repository's HTTPS API origin; never use credential mappings
  from the scanned repository or send a token to another origin.

- **REQ-25 — Proxy support.** Honor user-configured HTTP proxies and host
  exclusions for HTTPS repository scans. Preserve destination validation and
  verified TLS for repository credentials, and report proxy failures instead of
  falling back to a direct connection.
