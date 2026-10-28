# Security Score

Assess a repository with a score from 0 to 100 (A–F), or classify the security relevance of changes. See [Security Score explained](<security score.md>) for how to read the results and how the score is calculated.

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
```

Without a path, `security-score` scans the current directory. The default output shows the score and grade; `--details` adds findings, file locations, and explanations.

With uncertain coverage, the tool reports `partial` and an observed pattern index without a repository score or grade. `--details` groups static candidates by path hints (`source`, `tests`, `examples`, `assets`, `build`, and `repository-host`) and summarizes repeated locations and parser issues. These hints do not prove production use or third-party ownership and do not remove candidates from the assessment. JSON/YAML retain every candidate and location.

An `incomplete` result also shows its observed pattern index in compact output when recognized evidence is available, alongside the processing limit or failure. With no recognized evidence it explicitly reports that no index is available. An observed index never substitutes for the withheld repository score or grade.

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

Remote scans first read the file listing at an identified commit, then download only supported files outside the excluded paths. They do not clone the repository or download a repository archive. Up to eight source requests run in parallel and reuse HTTPS connections. Private GitHub sources use the authenticated API; public GitHub sources use the public raw-content host without forwarding API credentials.

Missing or inaccessible repositories, authentication failures, API rate limits, and invalid file listings produce distinct errors and no score. A host may return the same 404 for a missing repository and an inaccessible private repository, so those cases cannot always be distinguished. Large repositories can still exceed the time, file-count, or selected-source limits; an incomplete scan does not produce a grade. Use `--details` to inspect excluded files and limits, or `--timeout 60` when more execution time is needed.

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
| `--version` | Show package version and embedded source commit, then exit without scanning. |

Choose one change selector: `--staged`, `--unstaged`, `--worktree`, `--base`, `--commit`, or `--patch`/`--diff`. These operate on local sources; repository URLs select a repository scan.
