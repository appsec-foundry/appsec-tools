# Security Score

Assess a repository with a score from 0 to 100 (A–F), or classify the security relevance of changes. See [Security Score explained](<security score.md>) for how to read the results and how the score is calculated.

## Quick start

### Installation

Requires Python 3.10+, `pipx`, and Git. The installation below uses SSH access to GitHub:

```sh
pipx install "git+ssh://git@github.com/appsec-foundry/appsec-analyzer-tools.git#subdirectory=security-score"
```

From an existing clone, run `pipx install ./security-score` at the repository root instead. The default engine needs no additional Python packages or AppSec Analyzer installation.

### Local repository

```sh
security-score /path/to/repository
security-score /path/to/repository --details
```

Without a path, `security-score` scans the current directory. The default output shows the score and grade; `--details` adds findings, file locations, and explanations.

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
| `--details` | Show findings, locations, coverage, architecture observations, and the calculation. |
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
| `--timeout SECONDS` | Total execution budget: 0.1–120 seconds; default 15. |
| `-h`, `--help` | Show CLI help. |

Choose one change selector: `--staged`, `--unstaged`, `--worktree`, `--base`, `--commit`, or `--patch`/`--diff`. These operate on local sources; repository URLs select a repository scan.
