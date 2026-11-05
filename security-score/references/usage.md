# Usage reference

Details for the [README](../README.md). The calculation is described in
[Security Score explained](<../security score.md>), rule coverage and limits in the
[technical reference](scoring.md).

## Reading `--score --details`

Five area assessments show points, ratings, coverage, deductions and open questions,
followed by the overall qualitative verdict. The repository overview and service,
cloud/IaC and supply-chain profiles provide located context. See the
[five-subscore reference](subscores.md) for criteria, arithmetic and profile limits.

## Reading legacy `--details` (without `--score`)

The report starts with an overview of the repository, then lists the score and
findings per topic.

- `0/100 (partial)` is the overall result. Partial means that some topics could
  not be assessed, so there is no grade.
- *Overview* describes the repository. It is context only and adds no points.
- Each topic has its own score. `Score: 100 - 85 = 15` shows how it came about.
  Each finding shows its rule ID, file, line and the points it deducted. `OK`
  lines are positive evidence and add no points.

The report ends with a coverage line. Under Authentication it also lists the
identity servers and grants it recognized. Endpoint URLs preserve useful paths
while omitting credentials and query tokens; structured `server` values remain
origins for compatibility. A closing line shows the scan time, for example
`Duration: 8.42 s`; JSON/YAML with `--details` includes `duration_seconds` instead.

## Topics

| Topic | Checks |
| --- | --- |
| Repository | Host settings such as branch protection, rulesets, and required reviews (URL scans only); security policy file |
| Authentication | JWT verification, password hashing and direct password comparisons, OAuth implicit/password grants and PKCE method, explicit SAML audience/time-check bypasses, cookie flags, credentialed CORS, Django/Flask settings; SSO usage and identity-server/grant profile |
| Architecture | Code execution, SQL injection, and unsafe deserialization patterns |
| Frontend | HTML output sinks, framework bypasses, Content Security Policy, and other security headers (positive evidence only) |
| Dependencies & CI | Package sources and indexes, missing lockfiles, exactly pinned Python requirements, lockfile sources and integrity, Maven, Gradle, Cargo and `pyproject.toml` sources, install scripts, committed binaries, Action, image, GitLab include and Terraform module pinning, CI permissions, script injection, privileged pull request checkouts, downloads in CI and container builds |
| Secrets | Credential and key files by name, Terraform state, and credentials in formats with a fixed prefix |
| Cryptography | Weak hashes and predictable random values |
| Deployment & transport | Debug mode, container host privileges, TLS verification including Python client contexts, TLS/certificate configuration evidence, and Terraform: open administrative ports, public storage and databases, wildcard IAM |

Each topic shows the lowest area score within it, how that score came about, and
up to three findings with file, line and points deducted. Below them, `OK` lines
show up to two kinds of positive evidence, such as literal SQL text or pinned
Actions, with a location and how often it occurs. `--json` and `--yaml` contain
every finding and the full calculation.

Positive evidence adds no points and does not offset findings. Some rules can only
report positive evidence, such as security headers, SBOM or provenance steps, or a
non-root container user. Their absence is no finding, and they cannot make a topic
or repository assessable. SSO, TLS and certificate usage are also configuration
evidence only. A package name alone is not a successful check, and certificate
validity or a live TLS handshake is not tested. Header evidence includes CSP, HSTS,
framing, content-type, referrer and cross-origin opener/resource policies.

Architecture also shows a profile: SSO, passwords or both, the hash a password
reaches, authentication mechanisms, single-page app or server-side templates,
persistence, whether SQL queries are built by concatenation, deployment targets,
and whether CI logs in to a cloud through OIDC or a stored key. SSO counts when a
package, a setting or a provider's sign-in URL in the code shows it; whether it is
switched on stays open. Dependencies & CI shows a similar profile: lockfiles, how
many direct dependencies name an exact version, and Renovate or Dependabot. Both
profiles are context and add no points.

## Overview

Only `--details` collects the overview: a plain, `--json`, `--yaml` or `--quiet`
scan does not load this code, reads no Git history and sends no extra API request.

| Block | Content |
| --- | --- |
| Technology | Languages, files by kind, frameworks, test tools, declared runtimes, package tools |
| Technology risks | Entries of a bundled list: dependencies that are insecure in every version or end of life, such as `node-serialize` or Log4j 1; runtimes and base images past end of life; DES, RC4, ECB mode and TLS below 1.2; Flash and Silverlight content |
| Development | Branches, up to the last 100 commits with pull or merge request markers, merges, authors and latest date; CODEOWNERS and other process files; CI system, whether it runs on pull or merge requests and runs tests; quality and security tools |

The overview is context. It never changes the score, grade, findings or exit
status. That includes technology risks: they run only with `--details`, and a score
must not depend on the output mode. An empty row says nothing was recognized, not
that the technology is absent. Risk entries cover manifests, source and build files
outside `tests` and `examples`, and Go and Ruby manifests are not read.

Commits follow the first-parent line. A commit without a marker may still have been
reviewed, because a rebase or an unmarked squash merge leaves no trace in the
subject. Author addresses are counted, never shown. URL scans take one page of
commits from the host API, which also lists side branches, so often fewer than 100
remain. A directory without `.git` or a rate limit shows as `unavailable`.

## Repository URLs

HTTPS URLs on GitHub.com, GitLab.com and self-managed GitLab instances are
supported, including nested GitLab groups. Other HTTPS hosts are treated as
GitLab. The host and optional port come directly from the repository URL;
there is no separate host option. URLs must not contain credentials, query
strings, or fragments.

An optional `.git` suffix and a trailing slash are normalized before the API
lookup. For example, `/team/project`, `/team/project.git` and
`/team/project.git/` select the same project. A 404 therefore needs an access,
namespace or connectivity check rather than a second request with `.git` added.

```sh
security-score https://gitlab.company.example:8443/team/project --token-env GITLAB_READ_TOKEN --details
```

For a private GitLab project, provide a token with `read_api` and project access
through the named environment variable. It is sent only to the selected
HTTPS origin. RFC 1918 private IPv4, [RFC 6598 shared address space](https://www.rfc-editor.org/rfc/rfc6598)
(`100.64.0.0/10`) and IPv6 unique-local addresses are supported for self-managed
GitLab. Loopback, link-local and metadata destinations remain
blocked. TLS verification stays enabled. Trust an internal CA through the system
trust store or `SSL_CERT_FILE`. The optional Analyzer engine supports GitHub.com
and GitLab.com URLs only.

The tool does not clone the repository. It lists the files at one commit and
downloads only files it can check. If a large repository does not fit into the
60-second budget, the result is partial; `--timeout 120` allows a larger sample.

A missing repository and a private one without access can both return HTTP 404,
so the error message cannot always tell them apart.

### Tokens and rate limits

Without a token, GitHub allows 60 API requests per hour per IP address, shared
with everything else on that address. A scan uses three or four of them, because
files come from `raw.githubusercontent.com`, which does not count; `--details` adds
two for commits and branches. A token raises the limit to 5,000 per hour. For a
public repository it goes only to the API; file downloads stay on the raw host
without the token. A private repository uses one API request per file. When a
limit is reached, the error says how long to wait.

`--token-env NAME` selects a token explicitly and uses it from the first request,
overriding any automatic configuration. The variable name is arbitrary, such as
`GIT_TOKEN`, `GITLAB_TOKEN` or `GITHUB_READ_TOKEN`.

Without `--token-env`, the tool starts anonymously. On HTTP 401, 403 or 404 it
retries once with the token mapped to the selected HTTPS API origin, or with
`GIT_TOKEN` if no mapping matches and that environment variable is set. An
exported `GIT_TOKEN` therefore needs no configuration file:

```sh
security-score https://gitlab.company.example/team/project --details
```

To assign different tokens to specific hosts, create the user file
`~/.config/security-score/token-hosts.json`. An absolute `XDG_CONFIG_HOME`
changes that location to `$XDG_CONFIG_HOME/security-score/token-hosts.json`.
Project files are not searched for credentials.

```json
{
  "https://gitlab.company.example": "GIT_TOKEN",
  "https://gitlab.company.example:8443": "OTHER_GIT_TOKEN",
  "https://api.github.com": "GITHUB_TOKEN"
}
```

Keys are exact HTTPS API origins and values are environment variable names,
never token values. For GitHub.com repositories, use the API origin
`https://api.github.com`. Other hosts and ports receive no credential from that
mapping. The default HTTPS port 443 and an omitted port identify the same origin.

HTTP 401, 403 or 404 triggers at most one retry with the mapped or fallback token.
Subsequent requests in the same scan reuse it only at that API origin, including
overview requests with `--details`. Public GitHub source downloads remain
anonymous. Redirects, TLS failures and other network failures do not trigger
token selection. A missing or invalid explicitly selected variable fails
immediately; a mapped variable fails only when authentication is needed. Neither
failure falls back to `GIT_TOKEN`. An invalid `GIT_TOKEN` fallback also fails only
when authentication is needed. Malformed or ambiguous configuration is rejected;
an explicit `--token-env` bypasses that configuration.

`GIT_TOKEN` is the only environment-name fallback; `gh` and `glab` logins are
not used. Local scans do not read the host mapping. The optional Analyzer
continues to manage its own repository-source authentication; the mapping covers
this tool's API requests.

### HTTP proxies

The internal engine supports HTTP CONNECT proxies for HTTPS repository reads.
It selects `HTTPS_PROXY`, then `ALL_PROXY`, then `HTTP_PROXY`. Lowercase forms
override uppercase forms. `NO_PROXY` accepts comma-separated host names, domain
suffixes, optional ports, or `*` for direct access to all hosts. CIDR exclusions
are not supported.

```sh
export HTTP_PROXY=http://proxy.company.example:3128
export NO_PROXY=localhost,.direct.company.example
security-score https://gitlab.company.example/team/project --token-env GIT_TOKEN --details
```

Use an `http://` proxy URL without user information. HTTPS or SOCKS proxy URLs
and embedded proxy credentials are rejected with a diagnostic. An existing
`HTTPS_PROXY` takes precedence over the `HTTP_PROXY` in this example.

The client resolves and checks the repository destination before requesting a
tunnel to that IP. The proxy must permit CONNECT to IP addresses, and the client
must be able to resolve the repository host. Repository TLS still verifies the
original hostname, and repository tokens are sent only inside that TLS session.
CONNECT contains no repository token. Locally configured loopback proxies are
supported; a proxy does not relax validation of repository destinations.

A failed proxy connection or CONNECT response stops that request with a proxy
diagnostic, including the HTTP status when available. It never falls back to a
direct connection or treats a proxy 404 as a missing repository. The optional
Analyzer manages its own transport settings.

### Network usage

With `--details`, a closing `Network:` block reports HTTP request attempts and
download volume, in total and per host. This includes host settings, file
listings, selected files and the overview's commits and branches; failed HTTP
attempts count too. Proxy CONNECT attempts are counted under the proxy's host
and port with zero response body bytes; their headers are excluded. Local scans
report zero HTTP requests. Measuring adds no
requests. JSON/YAML with details includes the same counters under `network`,
with exact byte counts in `response_body_bytes`.

The byte count measures response body bytes actually read, including partial or
oversized reads discarded by the scan. It excludes unread bodies (including
rejected HTTP error responses), HTTP headers, uploads, DNS and TLS/TCP overhead;
it is not total traffic on the network interface. A connection that fails before
an HTTP request can be attempted does not count as a request. These counters
cover the internal engine; the optional Analyzer engine is not instrumented.

## Changes

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
comparison or patch; it does not download anything. With `--details`, the output
lists the signals behind the rating by rule, with file and line. The relevance
levels are explained in the [technical reference](scoring.md#change-relevance).

## Selecting checks

Choose checks without editing the bundled rules:

```sh
security-score --list-checks
security-score /path/to/repository --checks authentication,tls,headers --details
security-score /path/to/repository --skip-checks dependencies --details
security-score /path/to/repository --checks JS-JWT,PY-JWT --json
```

The default is `all`. Available groups are `authentication`, `tls`, `headers`,
`architecture`, `frontend`, `dependencies`, `secrets`, `cryptography`, `deployment`
and `repository`; individual rule IDs from `--list-rules` also work. Groups can
overlap. `--skip-checks` removes checks from the selection. Selection applies to
internal repository scans, and an empty or unknown selection is an argument error.
A subset reports its recognized index as partial and withholds the overall
repository grade; `--checks all` preserves the default behavior.

## Options

| Option | Meaning |
| --- | --- |
| `repository` | Local directory or supported HTTPS URL; defaults to the current directory. `--repo DIRECTORY` is an alternative for local directories. |
| `--details`, `--detail` | Repository overview, subscores and findings per topic; for changes, the signals grouped by rule. |
| `--quiet`, `--quite` | Print only the number, or nothing if there is none. Cannot be combined with `--json`, `--yaml`, change analysis, `--list-rules`, or `--verify-rules`. |
| `--json`, `--yaml` | Structured output with all findings and the calculation. With `--details` it also contains the `overview`. |
| `--token-env NAME` | Explicit API token environment variable for a repository URL; overrides host mappings and the `GIT_TOKEN` fallback. |
| `--timeout SECONDS` | Time budget from 0.1 to 120 seconds; default 60. |
| `--engine analyzer` | Use a separately installed AppSec Analyzer instead of the bundled rules; repository scans only. `--analyzer PATH` sets the absolute path of a trusted executable; otherwise it is taken from `PATH`. See [compatibility](compatibility.md). |
| `--list-rules` | Show the bundled rules. |
| `--list-checks` | List selectable groups and their check counts without scanning. |
| `--checks GROUPS_OR_IDS` | Run comma-separated groups or rule IDs; default `all`. |
| `--skip-checks GROUPS_OR_IDS` | Omit groups or rule IDs from the selected checks. |
| `--verify-rules` | Run the bundled rule examples. |
| `--version` | Show the version and the Git commit it was built from. |
| `--update` | Update the pipx installation; see below. |

`--details` logs preparation, selected-check count, file progress, path checks,
profile collection and scoring steps to stderr. JSON/YAML and both spellings
`--quiet`/`--quite` suppress progress. Quiet mode prints only the numeric index;
the exit status still indicates partial coverage.

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

From a clone of this repository, `pipx install ./security-score` installs the tool,
and the repair command in the README takes `./security-score` instead of the URL.

## Development

The packaging test needs `setuptools>=61`, `wheel`, and a pip with `--python`
support; it downloads no packages.

To exercise the installed CLI through a real loopback HTTP proxy, including
`HTTP_PROXY` fallback for HTTPS repository scans:

```sh
SECURITY_SCORE_LIVE_E2E=1 SECURITY_SCORE_E2E_HTTP_PROXY=1 python3 -B -m unittest test_e2e_juice_shop -v
```

The fixture relays only public IP addresses on port 443, uses no repository
credentials and writes CONNECT counts to `out/juice-shop-e2e/proxy.json`.

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
[technical reference](scoring.md#maintaining-the-rules).

## Five security subscores

Use `--score` for five evidence-qualified area assessments and an overall verdict without a numeric average. Combine it with `--details`, `--json` or `--yaml`. See [criteria, endpoint profiles and compatibility](subscores.md).
