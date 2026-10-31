# Security Score

Gives a repository a quick security score from 0 to 100 with a grade from A to
F, based on static checks of source code, dependencies, CI, container and
Terraform files, and repository settings. For a change, such as a commit or staged files, it
rates the security relevance instead: `high`, `medium`, `low`, or `unclear`.

The checks are bundled, deterministic rules. No LLM and no AppSec Analyzer are
needed. The score is a quick indication: 100 means the checks found nothing,
not that the code is secure.

## Quick start

Requires Python 3.10+, `pipx`, and Git with SSH access to GitHub.

```sh
pipx install "git+ssh://git@github.com/appsec-foundry/appsec-analyzer-tools.git#subdirectory=security-score"

security-score /path/to/repository             # score
security-score /path/to/repository --details   # subscores and findings per topic
security-score https://github.com/juice-shop/juice-shop
security-score /path/to/repository --staged    # relevance of staged changes
```

Without a path, the current directory is scanned. From a clone of this
repository, `pipx install ./security-score` works as well.

## Examples

Score of a local repository:

```console
$ security-score /path/to/repository
59/100 (E)
```

`59/100 (partial)` instead of a grade means that some checks were inconclusive
or a limit was reached. The number then covers only the recognized evidence.

With `--details` (excerpt from a Juice Shop scan):

```text
Security score · 0/100 (partial)
Scope: https://github.com/juice-shop/juice-shop @ 717f5efa886b
Findings are static pattern matches; exploitability unverified.
Partial result: subscores describe recognized evidence only; no repository grade is available.

Repository               79/100  ████████░░  2 findings
  Score: 100 - 20 = 80, capped at 79 by a medium finding
  MEDIUM    Default branch protection reported disabled (-10)
            HOST-DEFAULT-BRANCH-PROTECTION · host API
  MEDIUM    Required reviews reported disabled (-10)
            HOST-REQUIRED-REVIEWS · host API
  OK        Security policy present
            REPO-SECURITY-POLICY · SECURITY.md:1

Authentication          not assessed
  No recognized control evidence from the available checks.

Architecture              0/100  ░░░░░░░░░░  19 findings
  Score: execution 100 - 100 = 0; injection 100 - 75 = 25. The lowest area counts.
  HIGH      Constructed SQL passed to a query call (-75)
            JS-SQL · routes/login.ts:34 (+12 more)
  HIGH      JavaScript code evaluation (-75)
            JS-EVAL · lib/xml.ts:12 (+4 more)
  HIGH      JavaScript command execution through exec (-25)
            JS-SHELL · scripts/package.mjs:20
  OK        Data-only parsing with JSON.parse
            JS-EVAL · frontend/src/app/Services/basket.service.ts:98 (+44 more)
  OK        Literal SQL text passed to a query call
            JS-SQL · data/static/codefixes/loginAdminChallenge_3.ts:15 (+4 more)
  Profile (context only, adds no score credit):
    Login           SSO and passwords
    Password hash   none recognized
    Authentication  local passwords (password from request), SSO (OIDC/OAuth) (Google sign-in), JWT
                    (express-jwt, jsonwebtoken)
    Frontend        single-page app (@angular/core), server-side templates (hbs, pug)
    Persistence     SQL (sequelize, sqlite3)
    SQL queries     concatenated or interpolated in 13 of 33 query calls, 14 unresolved
                    (routes/login.ts:34)
    Deployment      AWS, Docker Compose, Terraform
    Cloud login     none recognized
...
Dependencies & CI         0/100  ░░░░░░░░░░  31 findings
  Score: 100 - 117, floored at 0
  HIGH      CI step pipes a download to an interpreter (-25)
            CI-REMOTE-SCRIPT · .github/workflows/ci.yml:374
...
  Profile (context only, adds no score credit):
    Lockfile        none recognized
    Exact versions  npm 6 of 176 direct dependencies
    Updates         none recognized

Secrets                   5/100  ░░░░░░░░░░  5 findings
  Score: 100 - 95 = 5
  HIGH      Credential in a recognized format (-75)
            SECRET-TOKEN · lib/insecurity.ts:21 (+2 more)
  MEDIUM    Credential or key file in the repository (-20)
            SECRET-FILE · ctf.key:1 (+1 more)

Cryptography             59/100  ██████░░░░  1 finding
  Score: 100 - 25 = 75, capped at 59 by a high finding
  HIGH      Predictable random value for a named secret (-25)
            JS-RANDOM · lib/insecurity.ts:53

Deployment & transport  not assessed
  OK        Non-root container user declared
            IAC-USER · Dockerfile:39 (+1 more)

Coverage
  965 files checked · 89 findings · scan incomplete
```

Every area starts at 100. A rule deducts points per occurrence, up to three
occurrences, and the worst severity also limits the score, as in the `Score:`
lines above. The number in brackets is what a finding costs. A closing note in
the output repeats the current values.

This scan hit a limit, so its exit status is `1` and there is no grade.

Only the number, for scripts and CI. Always check the exit status as well;
here, `2` marks a partial result:

```console
$ security-score /path/to/repository --quiet; echo "exit $?"
59
exit 2
```

Security relevance of the last commit:

```console
$ security-score /path/to/repository --commit HEAD
Security relevance: high · 0 introduced, 0 worsened findings
```

With `--details`, the output lists the signals behind the rating by rule, with
file and line.

## Reading the score

Each area, such as execution or transport, starts at 100 points. A finding
deducts points and caps the area score by its severity; only the first three
findings of a rule deduct points. The lowest area score is the repository score,
so a strong area cannot offset a weak one.

| Severity | Deduction per finding | Area score at most |
| --- | ---: | ---: |
| Critical | 50 | 39 |
| High | 25 | 59 |
| Medium | 10 | 79 |
| Low | 3 | 89 |

One high finding gives 59 (E); two high findings in the same area give 50 (E);
three or more findings of one high rule give 25 (F).

| Score | 90–100 | 80–89 | 70–79 | 60–69 | 50–59 | 0–49 |
| --- | --- | --- | --- | --- | --- | --- |
| Grade | A | B | C | D | E | F |

[Security Score explained](<security score.md>) has worked examples and explains
`partial`, `undetermined`, and `incomplete`. The optional Analyzer engine has its
own [scoring policy](references/compatibility.md).

### Topics in `--details`

| Topic | Checks |
| --- | --- |
| Repository | Host settings such as branch protection, rulesets, and required reviews (URL scans only); security policy file |
| Authentication | JWT verification options, password hashing, cookie flags, credentialed CORS, Django and Flask session and host settings; no rules for login flows or access control |
| Architecture | Code execution, SQL injection, and unsafe deserialization patterns |
| Frontend | HTML output sinks, framework bypasses, Content Security Policy, and other security headers (positive evidence only) |
| Dependencies & CI | Package sources and indexes, missing lockfiles, exactly pinned Python requirements, lockfile sources and integrity, Maven, Gradle, Cargo and `pyproject.toml` sources, install scripts, committed binaries, Action, image, GitLab include and Terraform module pinning, CI permissions, script injection, privileged pull request checkouts, downloads in CI and container builds |
| Secrets | Credential and key files by name, Terraform state, and credentials in formats with a fixed prefix |
| Cryptography | Weak hashes and predictable random values |
| Deployment & transport | Debug mode, container host privileges, TLS verification, and Terraform: open administrative ports, public storage and databases, wildcard IAM |

Each topic shows the lowest area score within it, how that score came about, and
up to three findings with file, line and points deducted. Below them, `OK` lines
show up to two kinds of positive evidence,
such as literal SQL text or pinned Actions, with a location and how often it
occurs. Positive evidence adds no points and does not offset findings. Some rules
can only report positive evidence, such as security headers, SBOM or provenance
steps, or a non-root container user. Their absence is no finding, and they cannot
make a topic or repository assessable.
Architecture also shows a profile: SSO, passwords or both, the hash a password
reaches, authentication mechanisms, single-page app or server-side templates,
persistence, whether SQL queries are built by concatenation, deployment targets,
and whether CI logs in to a cloud through OIDC or a stored key. SSO counts when a
package, a setting or a provider's sign-in URL in the code shows it; whether it is
switched on stays open. Dependencies & CI shows a similar profile: lockfiles, how
many direct dependencies name an exact version, and Renovate or Dependabot. Both
profiles are context and add no points.
`--json` and `--yaml` contain every finding and the full calculation.

### Exit status

| Status | Meaning |
| --- | --- |
| 0 | Complete result: a score with grade, or a finished change analysis (also `unclear`) |
| 1 | Incomplete result or error: a limit such as the time budget was reached, the repository was not accessible, or processing failed |
| 2 | Partial or undetermined result, or invalid arguments |
| 130 | Cancelled |

## Usage

### Repository URLs

HTTPS URLs on GitHub.com and GitLab.com are supported, including nested GitLab
groups. For SSH URLs and self-hosted servers, scan a local checkout. URLs must
not contain credentials, query strings, or fragments.

The tool does not clone the repository. It lists the files at one commit and
downloads only files it can check. If a large repository does not fit into the
60-second budget, the result is partial; `--timeout 120` allows a larger sample.

Private repositories need a read-only API token. Put it in an environment
variable and pass the variable name:

```sh
security-score https://github.com/example/private-project --token-env GITHUB_READ_TOKEN
```

A missing repository and a private one without access can both return HTTP 404,
so the error message cannot always tell them apart.

Without a token, GitHub allows 60 API requests per hour per IP address, shared
with everything else on that address. A scan uses three or four of them, because
files come from `raw.githubusercontent.com`, which does not count. A token raises
the limit to 5,000 per hour. For a public repository it goes only to the API; file
downloads stay on the raw host without the token. A private repository uses one
API request per file. When a limit is reached, the error says how long to wait.
The tool never picks up a token on its own: `GITHUB_TOKEN` and `gh` logins are used
only if you name the variable with `--token-env`.

### Changes

Choose one comparison per call:

```sh
security-score /path/to/repository --staged              # staged changes vs. HEAD
security-score /path/to/repository --unstaged            # working files vs. index
security-score /path/to/repository --worktree            # working files incl. untracked vs. HEAD
security-score /path/to/repository --commit abc1234      # commit vs. its parent
security-score /path/to/repository --base main --head HEAD
security-score /path/to/repository --patch changes.diff  # unified diff, also --diff
```

`--pr URL` or `--mr URL` attaches a GitHub PR or GitLab MR link to a local
comparison or patch; it does not download anything. The relevance levels are
explained in the [technical reference](references/scoring.md#change-relevance).

### Options

| Option | Meaning |
| --- | --- |
| `repository` | Local directory or supported HTTPS URL; defaults to the current directory. `--repo DIRECTORY` is an alternative for local directories. |
| `--details`, `--detail` | Subscores and findings per topic; for changes, the signals grouped by rule. |
| `--quiet`, `--quite` | Print only the number, or nothing if there is none. Cannot be combined with `--json`, `--yaml`, change analysis, `--list-rules`, or `--verify-rules`. |
| `--json`, `--yaml` | Structured output with all findings and the calculation. |
| `--token-env NAME` | Environment variable that holds the API token for a repository URL. |
| `--timeout SECONDS` | Time budget from 0.1 to 120 seconds; default 60. |
| `--engine analyzer` | Use a separately installed AppSec Analyzer instead of the bundled rules; repository scans only. `--analyzer PATH` sets the absolute path of a trusted executable; otherwise it is taken from `PATH`. See [compatibility](references/compatibility.md). |
| `--list-rules` | Show the bundled rules. |
| `--verify-rules` | Run the bundled rule examples. |
| `--version` | Show the version and the Git commit it was built from. |
| `--update` | Update the pipx installation; see below. |

Text output is colored only on an interactive terminal. Set `NO_COLOR` to turn
color off.

## Update and reinstall

```sh
security-score --update
security-score --version
```

`--update` runs `pipx upgrade --pip-args="--upgrade --force-reinstall --no-cache-dir" appsec-security-score`.
It reinstalls from the source pipx recorded at installation: the default branch
of this repository or your local clone, not a signed release. Review changes
you do not trust before updating.

To repair a stale or broken installation:

```sh
pipx install --force --pip-args="--upgrade --force-reinstall --no-cache-dir" \
  "git+ssh://git@github.com/appsec-foundry/appsec-analyzer-tools.git#subdirectory=security-score"
```

From a clone, use `./security-score` instead of the URL.

## Limits

- The rules recognize static patterns. Findings are pattern matches, not confirmed
  vulnerabilities.
- Not checked: login flows, access control, business logic, and known
  vulnerabilities in dependencies.
- Secrets count only with a fixed prefix or a recognized file name; a generic
  key or password in source code is not found. Credential values never appear in
  the output, and sensitive files are not read.
- A password hash is followed only within one file.
- Application code is read for Python and JavaScript/TypeScript only. A repository
  in another language gets configuration checks at most.
- Code, tests, and builds of the scanned project are never run.
- Time and size limits are listed in the
  [technical reference](references/scoring.md#limits).

## Development

Run from `security-score/`:

```sh
python3 -B -m unittest test_security_score -v   # offline tests
python3 -B -m unittest test_packaging -v        # build and install a wheel
python3 scripts/score.py --verify-rules         # rule examples
```

The packaging test needs `setuptools>=61`, `wheel`, and a pip with `--python`
support; it downloads no packages.

Before releasing changes to URL scanning or console output, run the live test
against Juice Shop. It takes about three minutes:

```sh
SECURITY_SCORE_LIVE_E2E=1 python3 -B -m unittest test_e2e_juice_shop -v
```

It builds and installs a wheel from the current checkout, scans
`https://github.com/juice-shop/juice-shop` in the default, `--details`, and
`--quiet` modes, and stores outputs, exit statuses, and hashes in
`out/juice-shop-e2e/`. Juice Shop code is not run. To test an existing
installation instead, also set `SECURITY_SCORE_E2E_EXECUTABLE` to the absolute
path of its `security-score`.

How to change rules and weights is described in the
[technical reference](references/scoring.md#maintaining-the-rules).
