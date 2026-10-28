# Security Score

Assesses a repository with a deterministic score from 0 to 100 (A to F), or classifies the security relevance of changes. Requires Python 3.10+ and, for local Git comparisons, Git. The internal scoring engine needs no additional Python packages.

## Installation

With `pipx`, Git, and SSH access to the GitHub repository:

```sh
pipx install "git+ssh://git@github.com/appsec-foundry/appsec-analyzer-tools.git#subdirectory=security-score"
```

No local clone is needed. From an existing clone, you can instead run
`pipx install ./security-score` at the repository root.

The command is then available as `security-score`. The internal engine is the default. A separately installed AppSec Analyzer is needed only when you select `--engine analyzer`.

## Understand your score

The default engine reports results such as `59/100 (E)`. Higher is better:
A = 90–100, B = 80–89, C = 70–79, D = 60–69, E = 50–59, F = 0–49.
This is a rule-based indication, not a percentage of security requirements met
or a measure of attack probability.

The calculation has three steps:

1. Each assessed area (for example, execution or transport) starts at 100.
   Every detected finding subtracts points from its area, including repeated
   findings across files.
2. The most severe finding also limits that area's highest possible score.
   Use the lower of the remaining points and this limit, with a minimum of 0.
3. The **lowest assessed area score** becomes the repository score. Good results
   elsewhere do not compensate for a weak area; deductions in different areas
   are not added together.

| Finding severity | Points deducted per finding | Highest area score |
| --- | ---: | ---: |
| Critical | 50 | 39 |
| High | 25 | 59 |
| Medium | 10 | 79 |
| Low | 3 | 89 |

For example, one high finding leaves 75 points, but its limit reduces the area
score to **59 (E)**. Two high findings in that same area leave **50 (E)**.
One high finding in each of two different areas gives **59 (E)** overall.
Additional findings may leave the headline unchanged when an area's limit or
a lower-scoring area already determines the result. Fixes may likewise leave
it unchanged until the limiting findings are addressed.

**100 (A) means no deductions from recognized checks, not that the application
is secure.** Even one recognized check can produce a score. Unknown checks do
not deduct points and areas with only unknown checks do not enter the minimum.
Inspect coverage as well as findings, especially when comparing repositories
of different sizes or results from different versions or scan scopes.

Use `security-score /path/to/repository --details` to see findings with file
locations, next actions, check outcomes, and the calculation for each area.
If there is no recognized source or dependency evidence, the result is
`undetermined`. If required processing fails or reaches a limit, it is
`incomplete`. Both withhold the score and grade; available findings remain in
detailed output. Host settings alone cannot establish a score.

Change analysis reports `high`, `medium`, `low`, or `unclear` relevance instead
of points. A security fix can have high relevance: the level describes what the
change touches, not whether it introduces a weakness. The optional Analyzer
engine uses a separate scoring policy.

See [the scoring guide](references/scoring.md) for the formula, check coverage,
limits, and editable scoring values.

## Run on a local repository

Pass a local directory to score its current files. With no directory argument, the current directory is used.

```sh
security-score /path/to/repository
security-score /path/to/repository --details
```

For a local Git repository, select changes to classify their security relevance:

```sh
security-score /path/to/repository --staged
security-score /path/to/repository --unstaged
security-score /path/to/repository --base main --head HEAD
```

Change analysis produces a relevance class rather than a repository score. `--worktree` compares HEAD with working files, including untracked files. `--commit REVISION` compares a commit with its first parent. `--patch FILE` reads a UTF-8 unified patch.

## Run on a supported Git repository URL

Pass a canonical HTTPS repository URL on GitHub.com or GitLab.com to score its selected repository contents and check available host settings:

```sh
security-score https://github.com/example/project
security-score https://gitlab.com/example/project
security-score https://gitlab.com/example/group/project --details
```

A GitLab URL may include nested groups. A trailing `.git` is accepted. SSH URLs, self-hosted Git services, URL credentials, query strings, and fragments are not supported. Public repositories need no token. For a private repository, set an operator-selected read-only GitHub or GitLab API token in an environment variable and pass its name with `--token-env NAME`; the tool does not automatically read arbitrary credential variables.

PR and MR URLs are identifiers for change analysis, not implicit fetch requests. Retrieve the change through an authorized host tool first, then provide a local `--patch FILE` or `--base REVISION` comparison together with `--pr URL` or `--mr URL`.

## Options

| Option | Purpose |
| --- | --- |
| `--details` | Show findings, coverage, architecture observations, and the score or relevance calculation. |
| `--json`, `--yaml` | Produce structured output; choose one. |
| `--repo DIRECTORY` | Select a local directory instead of passing it as a positional argument. |
| `--staged` | Compare HEAD with staged changes. |
| `--unstaged` | Compare the index with unstaged working files. |
| `--worktree` | Compare HEAD with working files, including untracked files. |
| `--base REVISION` with optional `--head REVISION` | Compare two local Git revisions; `--head` defaults to HEAD. |
| `--commit REVISION` | Compare a local commit with its first parent. |
| `--patch FILE` or `--diff FILE` | Assess a supplied UTF-8 unified patch. |
| `--pr URL`, `--mr URL` | Attach a canonical GitHub PR or GitLab MR identity to an explicitly supplied patch or local comparison. |
| `--token-env NAME` | Read a selected API token for a GitHub/GitLab repository URL. |
| `--engine analyzer` | Use a separately installed compatible AppSec Analyzer for repository scores only. |
| `--analyzer PATH` | Select its trusted absolute executable path; requires `--engine analyzer`. |
| `--list-rules` | Display the bundled rule catalog without scanning. |
| `--verify-rules` | Run bundled rule examples without scanning. |
| `--timeout SECONDS` | Set the total execution budget (0.1–120 seconds; default 15). |
| `--help` | List all CLI options. |

The rule catalog and calculation are documented in [scoring.md](references/scoring.md). The Analyzer variant's prerequisites are in [compatibility.md](references/compatibility.md).

Run tests from this directory with `python3 -B -m unittest test_security_score -v`.
