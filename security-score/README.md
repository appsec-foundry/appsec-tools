# Security Score

Assesses a repository with a deterministic score from 0 to 100 (A to F), or classifies the security relevance of changes. Requires Python 3.10+ and, for local Git comparisons, Git. The internal scoring engine needs no additional Python packages.

## Installation

With `pipx` installed, run from the repository root:

```sh
pipx install ./security-score
```

The command is then available as `security-score`. The internal engine is the default. A separately installed AppSec Analyzer is needed only when you select `--engine analyzer`.

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
