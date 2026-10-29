# Requirements for Security Score

Core requirements for Security Score. Usage and output are described in the
[README](README.md), the calculation in the [scoring reference](references/scoring.md).
Tests pin the exact behavior.

- **REQ-01 — Standalone and deterministic.** The default engine uses only the
  bundled rules, without AppSec Analyzer or model calls. The same sources, rules,
  and settings give the same result, and each result names its rule and scoring
  versions.

- **REQ-02 — Repositories and changes.** Scan local checkouts and GitHub.com or
  GitLab.com repository URLs, including the repository-host security settings for
  URLs. Analyze changes (staged, unstaged, commits, revision ranges, patches) and
  state the compared versions. Checks cover data access, frontend output and CSP,
  hardening, and the dependency and build supply chain.

- **REQ-03 — Score, grade, and change relevance.** A repository scan gives a score
  from 0 to 100, where 100 means no deductions, and a grade: A ≥ 90, B ≥ 80, C ≥ 70,
  D ≥ 60, E ≥ 50, F < 50. Passed checks cannot offset a serious finding. A change
  gets a security relevance of high, medium, low, or unclear instead of a score. It
  depends on the security behavior the change touches, not only on detected
  weaknesses; introduced, worsened, resolved, and pre-existing findings are
  reported separately.

- **REQ-04 — Honest limits.** Keep findings, positive evidence, unknowns, and
  exclusions apart. A detected technology is no proof of protection. Without
  enough coverage, or when required checks fail, withhold score and grade but keep
  the findings. No findings in a change does not mean low relevance, and a high
  score does not mean the code is safe.

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
  characters.

- **REQ-09 — End-to-end check before release.** Changes to URL scanning or console
  output need a live run of the installed CLI against
  `https://github.com/juice-shop/juice-shop` before release. Once enabled, this test
  fails on missing evidence, crashes, or a missed deadline instead of skipping.
