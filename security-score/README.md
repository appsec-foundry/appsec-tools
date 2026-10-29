# Security Score

Assess a repository with a score from 0 to 100 (A–F), or classify the security relevance of changes. See [Security Score explained](<security score.md>) for how to read the results and how the score is calculated.

Repository scans use a **60-second budget** by default. URL scans reserve time to
analyze downloaded sources. When the whole repository cannot be processed, the
tool still prints an observed index such as `59/100 (partial)` if it recognized
source evidence. This is a quick indication; coverage and selection limits show
how much of the repository contributed. No recognized evidence means no
numeric indication.

## Interpreting the scale

**Higher is better.** The number describes the static patterns recognized by this scanner. Each assessed area starts at 100; findings deduct points, severity can cap the result, and the lowest area result determines the overall index.

The interpretation below applies to the default internal engine. The optional Analyzer engine has its own [scoring policy](references/compatibility.md).

| Index | Grade, when fully scored | Meaning in plain language |
| --- | --- | --- |
| 0–9 | F | Extremely low index. Deductions in at least one area have nearly or completely exhausted its 100-point budget. |
| 10–19 | F | Very low index. The weakest assessed area retains only 10–19 points after deductions and caps. |
| 20–29 | F | Low index. The weakest assessed area retains only 20–29 points. |
| 30–39 | F | Low index. A critical candidate alone caps its area at 39; accumulated lower-severity candidates can also produce this range. |
| 40–49 | F | Below half the scale. Accumulated deductions leave the weakest assessed area below 50 points. |
| 50–59 | E | Substantial deductions or a high-severity cap. For example, one high candidate yields 59. |
| 60–69 | D | Noticeable deductions. For example, four medium candidates in the same area yield 60. |
| 70–79 | C | Moderate deductions or a medium-severity cap. One medium candidate yields 79. |
| 80–89 | B | Smaller deductions or a low-severity cap. One low candidate yields 89. |
| 90–100 | A | Highest band. With the bundled default weights and caps, a scored result in this band is 100: no recognized findings deducted points. |

The ten-point ranges are reading aids; the grading policy makes **no separate risk classification within 0–49**, which is all F. Repeated candidates count, so four high candidates in one area already yield 0. Additional candidates cannot lower that area below 0. Tests, examples, assets, and other selected sources remain in the assessment; `--details` separates their path-hint groups.

**0 does not establish that every part of an application is insecure, and 100 does not establish that it is safe.** The index is neither a security percentage nor an attack probability. Review candidate validity and coverage with `--details`. A value marked `(partial)`, or printed by `--quiet` with exit status 1 or 2, describes recognized evidence only and receives no repository grade. See [the worked examples](<security score.md>) for the exact deductions and limits.

## Quick start

### Installation

Requires Python 3.10+, `pipx`, and Git. The installation below uses SSH access to GitHub:

```sh
pipx install "git+ssh://git@github.com/appsec-foundry/appsec-analyzer-tools.git#subdirectory=security-score"
```

From an existing clone, run `pipx install ./security-score` at the repository root instead. The default engine needs no additional Python packages or AppSec Analyzer installation.

Check the installed release and source revision with:

```sh
security-score --version
```

Installed wheels embed the Git commit at build time, so this does not need a local checkout or network access. Source checkouts also identify tracked modifications. Builds from sources without Git or embedded metadata report `commit unknown`.

Release verification is covered by `python3 -B -m unittest test_packaging -v` from this directory, using the declared build tools (`setuptools>=61` and `wheel`). It builds a source archive and wheel, installs into an isolated environment without downloading dependencies, and checks the installed version with Git absent from `PATH`.

For routine updates, run `pipx upgrade appsec-security-score`, then check `security-score --version`. This uses the installation source recorded by pipx. There is no need for `--force` on a routine upgrade.

Use forced installation when explicitly replacing an existing installation or repairing a stale one. Older pipx versions may leave the same package version installed with `install --force` alone: that flag permits replacing the pipx environment/apps, while the pip arguments below explicitly upgrade and reinstall the package without reusing the pip cache. To replace it from GitHub:

```sh
pipx install --force --pip-args="--upgrade --force-reinstall --no-cache-dir" "git+ssh://git@github.com/appsec-foundry/appsec-analyzer-tools.git#subdirectory=security-score"
security-score --version
```

Or install the current local checkout (including an unchanged version number):

```sh
pipx install --force --pip-args="--upgrade --force-reinstall --no-cache-dir" ./security-score
security-score --version
```

### Local repository

```sh
security-score /path/to/repository
security-score /path/to/repository --details
security-score /path/to/repository --quiet
```

Without a path, `security-score` scans the current directory. Normal text mode
prints exactly one score line, for example `59/100 (E)` or `59/100 (partial)`,
without progress, calculations or diagnostics when a result is available.
`--detail` (alias `--details`) shows category subscores, their deductions and
severity caps, and the actual scanner findings grouped under each category with
rules, severity, file/line locations and review suggestions. Unassessed categories
remain explicit; observed subscores are marked `(partial)` when a repository grade
is withheld. Detailed mode also shows origin groups and coverage explanations.
Only detailed text mode emits work steps on stderr, with a spinner on interactive
terminals and plain lines when redirected.

For a number alone, use `--quiet` (also accepted as `--quite`). Output is, for example, `59` followed by a newline, without progress, calculation, grade, diagnostics, or other text. Quiet mode overrides `--details` and cannot be combined with JSON/YAML, change relevance, or rule-list/example commands. With partial or incomplete evidence, the number is the observed pattern index; the exit status remains 2 or 1 respectively. With no numeric result, stdout and stderr are empty and the exit status indicates failure or undetermined coverage. Do not treat a number alone as successful complete assessment: always check the exit status. Explicit `--help` and `--version` still perform their requested display action.

With uncertain coverage, the tool reports `partial` and an observed pattern index without a repository score or grade. `--details` groups static candidates by path hints (`source`, `tests`, `examples`, `assets`, `build`, and `repository-host`) and summarizes repeated locations and parser issues. These hints do not prove production use or third-party ownership and do not remove candidates from the assessment. JSON/YAML retain every candidate and location.

Detailed text includes the number of files checked, selection limits, coverage explanations and source locations. JSON/YAML retain structured diagnostics and the actual verdict without progress messages. A `(partial)` index never substitutes for the withheld repository score or grade. Exit status remains 1 for incomplete processing and 2 for partial/undetermined assessments, including quiet mode. With no numeric result, normal text prints the verdict; failures without a result report an error on stderr, while quiet mode stays silent.

### Repository URL

```sh
security-score https://github.com/example/project
security-score https://gitlab.com/example/group/project --details
```

Supported URLs are HTTPS repository URLs on GitHub.com and GitLab.com, including nested GitLab groups and an optional `.git` suffix. For SSH URLs or self-hosted services, use a local checkout. URLs must not contain credentials, query strings, or fragments.

Public repositories need no token. For private repositories, provide a read-only API token through an environment variable and select its name:

```sh
security-score https://github.com/example/private-project --token-env GITHUB_READ_TOKEN
```

Set `GITHUB_READ_TOKEN` in your environment before running this command.

Remote scans first read the file listing at an identified commit, then download only supported files outside the excluded paths. They do not clone the repository or download a repository archive. Up to eight source requests run in parallel and reuse HTTPS connections. Declarations such as package manifests, lockfiles and Dockerfiles come first, followed by application sources and build configuration, then tests, examples and assets. This ordering only affects sampling when limits are reached; all supported sources remain eligible. Private GitHub sources use the authenticated API; public GitHub sources use the public raw-content host without forwarding API credentials.

Missing or inaccessible repositories, authentication failures, API rate limits during repository discovery, and invalid file listings produce distinct errors and no score. A host may return the same 404 for a missing repository and an inaccessible private repository, so those cases cannot always be distinguished. URL scans use 70% of the remaining budget after host discovery for source selection and downloads, reserving the rest for analysis and reporting. Time, entry-count and source-byte limits, truncated listings, or individual source download failures retain the available sources and produce an incomplete indication when evidence exists. Per-file size mismatches still fail without a result. Incomplete scans do not receive a grade. Use `--details` to inspect excluded files and limits, or `--timeout 120` for a larger sample. Active network requests may need a few seconds to settle; the budget is checked between bounded operations rather than enforced by a hard process kill.

HTTP header/body reads have a five-second request deadline as well as socket
timeouts, so a connection that trickles bytes cannot occupy the rest of the scan.
If one resolved public address is unreachable, the client tries the remaining
checked addresses within the budget. Truncated responses are rejected. Optional
host-setting requests have a smaller budget and remain unknown on failure.
`--details` and JSON/YAML include the HTTP status for individual download failures.
Source parser limitations are recorded with the affected file, preserving findings
from other sources and withholding a repository grade. Host settings alone never
produce a numeric application indication.

### Changes in a local Git repository

```sh
security-score /path/to/repository --staged
security-score /path/to/repository --base main --head HEAD
security-score /path/to/repository --patch changes.diff
```

Change analysis returns `high`, `medium`, `low`, or `unclear` security relevance instead of a score.

## Parameters

| Parameter | Meaning |
| --- | --- |
| `repository` | Local directory or supported HTTPS repository URL; defaults to the current directory. |
| `--repo DIRECTORY` | Alternative to the positional argument for a local directory. |
| `--detail`, `--details` | Show category subscores with deductions and located findings, coverage, architecture observations, and progress. |
| `--quiet`, `--quite` | Repository scans: output only the numeric index; no progress or diagnostics. Preserve exit status; no output if no index exists. |
| `--json`, `--yaml` | Output JSON or YAML instead of text; choose one. |
| `--staged` | Compare HEAD with staged changes. |
| `--unstaged` | Compare the index with unstaged working files. |
| `--worktree` | Compare HEAD with working files, including untracked files. |
| `--base REVISION` | Compare local Git revisions, starting at this revision. |
| `--head REVISION` | End revision for `--base`; defaults to HEAD. |
| `--commit REVISION` | Compare a local commit with its first parent. |
| `--patch FILE`, `--diff FILE` | Read a UTF-8 unified patch for change analysis; these are aliases. |
| `--pr URL`, `--mr URL` | Attach a GitHub PR or GitLab MR URL to an explicitly supplied patch or local Git comparison. The URL does not fetch changes; choose one. |
| `--token-env NAME` | Name of the environment variable holding the API token for a repository URL. |
| `--engine internal\|analyzer` | Select the engine; defaults to `internal`. `analyzer` requires a separately installed compatible AppSec Analyzer and supports repository scores only. See [compatibility](references/compatibility.md). |
| `--analyzer PATH` | Trusted absolute Analyzer executable path; requires `--engine analyzer`. Otherwise the executable is selected from `PATH`. |
| `--list-rules` | Display the bundled rule catalog without scanning. |
| `--verify-rules` | Run bundled rule examples without scanning. |
| `--timeout SECONDS` | Total execution budget: 0.1–120 seconds; default 60. URL scans reserve time for analysis and retain available evidence when source selection reaches a limit. |
| `-h`, `--help` | Show CLI help. |
| `--version` | Show package version and embedded source commit, then exit without scanning. |

Choose one change selector: `--staged`, `--unstaged`, `--worktree`, `--base`, `--commit`, or `--patch`/`--diff`. These operate on local sources; repository URLs select a repository scan.
