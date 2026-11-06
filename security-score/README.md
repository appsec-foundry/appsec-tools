# Security Score

Reports a repository security score and plain-language rating in one line, such
as `59/100 (Bad)`. `--details` shows a colored overview with bars, grouped findings,
evidence coverage and the tool version. Its areas are Architecture & isolation,
Identity & access, Data & processing, Dependencies & supply chain, Deployment
& operations, and AI & agents. Insufficient evidence leaves an area or the overall
result Not assessed; AI & agents is Not applicable when no AI use is recognized.

It reads selected source and configuration with fixed rules, without model calls
or executing the target. The [scoring reference](references/subscores.md) explains
the criteria, worked calculations and architecture limits. `--score` remains a
compatibility alias; `--legacy-score` selects the previous 0–100/A–F output.
Changes retain security relevance.

## Quick start

Requires Python 3.10+, `pipx`, and Git. Installation uses HTTPS; public
repositories need no GitHub account or SSH key.

```sh
pipx install "git+https://github.com/appsec-foundry/appsec-tools.git#subdirectory=security-score"
```

```console
$ security-score /path/to/repository
59/100 (Bad)

$ security-score /path/to/repository --commit HEAD
Security relevance: high · 0 introduced, 0 worsened findings
```

The repository example contains one explicitly disabled certificate check.
Unavailable evidence remains separate from that established weakness.

The default output contains only the score and rating; `--score` is an alias.
The overall number takes the lowest assessed subscore, subject to the overall
evidence gate. Partial positive evidence alone does not establish a favorable
overall result. Incomplete processing retains a nonzero exit status; details and
structured output explain coverage. `security-score --version` explicitly shows the version and source commit.
JSON/YAML contain no text banner; `--quiet` remains numeric. Use `--legacy-score`
to retain the previous single-score JSON/YAML schema.

`--details` adds the tool version, repository overview, colored bars and up to
three grouped finding types per area, with point deductions, readable dependency
check outcomes and one coverage summary.
The overview separates route counts, HTTP methods and recognized API types,
without listing paths:

```text
Routes          12 recognized
HTTP methods    ALL 1, GET 7, POST 3
API types       GraphQL 1, HTTP (unclassified) 2, REST (inferred) 8, WebSocket 1
```

GraphQL needs a supported server-handler registration. REST is inferred from API
namespaces such as `/api/` or `/rest/`, versioned API paths, or inline JSON response
handlers; this does not verify REST architectural constraints. Counts refer to
declarations, not verified live endpoints.
Route collection runs only with `--details` and adds no score credit; supported
patterns and counting limits are described in the [usage reference](references/usage.md#overview).
JSON/YAML retain every occurrence, deduction and gap. The screenshot below shows
the earlier legacy layout; the default details use the six areas with the same styling.

<a href="docs/details-juice-shop.png">
  <img src="docs/details-juice-shop-crop.png" alt="Excerpt of security-score --details on Juice Shop: repository overview, then the score and findings for the Repository and Authentication topics">
</a>

## Subscore assessment

```sh
security-score /path/to/repository
security-score /path/to/repository --details
security-score /path/to/repository --json
```

For a fixture with one explicitly disabled certificate check, Deployment is
`59/100 · Bad · limited evidence`; other areas without evidence stay Not assessed.
The compact output is `59/100 (Bad)`; details name certificate validation as the reason.

`--details` shows grouped deductions and concrete control evidence, and shows
recognized SSO server URLs (including realm paths) and artifact repositories such
as Nexus or Artifactory. Endpoint profiles distinguish configuration from lockfile
observations and omit credentials and query tokens. These names earn no points.

Cloud/IaC details identify declared Terraform providers, regions, resource roles,
selected security properties and state backends. Python/Node profiles distinguish
version/lock consistency, artifact hashes and applicable locked-install declarations.
Unsupported lock formats and unresolved build workflows remain gaps; see the
[profile coverage](references/subscores.md#cloud-and-supply-chain-profiles).
Compose details also show each service’s declared ports and bind addresses, network
settings, privileges, mounts, image references, healthcheck and operating limits,
with source locations. Profiles report files independently; interpolation and
override order remain unresolved. Missing settings give no finding or score credit.
This profile requires version 0.3.1 or later. Since 0.3.2, text details omit empty
profile rows and services without recognized settings or unresolved evidence;
JSON/YAML retain all captured declarations.

Architecture is assessed automatically from supported request-to-database boundaries
and declared isolation or privilege controls. Direct request interpolation into SQL
yields a located architecture finding; explicit parameter binding is positive
evidence. Independent declared container-isolation and privilege controls can
establish a positive static Architecture score. Wider manual architecture review
is a separate limitation and no longer blocks these supported criteria. Identity
still requires wider resource-authorization evidence for a favorable rating. See [criteria and examples](references/subscores.md).

AI & agents follows model output in Python and JavaScript/TypeScript files that
import an AI SDK into code, shell, SQL and HTML sinks, checks whether parsed
structured output is schema-validated, and flags request data passed as the
model conversation, which lets a client forge system or assistant turns. It also reads committed MCP and agent
configuration (`.mcp.json`, `mcp.json`, `.claude/settings*.json`,
`.gemini/settings.json`) for literal credentials, unpinned or unencrypted MCP
servers, bypassed confirmations, broad permission rules and missing sandboxes:

```console
$ security-score /path/to/ai-app --details
...
AI & agents                    0/100  ░░░░░░░░░░  Very bad
  HIGH      Committed permission rule pre-approves shell or unrestricted writes (-41.0 points)
            AI-AGENT-PERMISSIONS · .claude/settings.json:1
  HIGH      Remote MCP server uses an unencrypted connection (-41.0 points)
            AI-MCP-TRANSPORT · .mcp.json:4
  HIGH      Model output reaches code, shell or SQL execution (-41.0 points)
            AI-OUTPUT-EXEC, JS-EVAL · src/chat.js:8
  +4 more finding types (-77.0 points).
  AI profile:
    Model           not resolved
    API             OpenAI-compatible
    Agent config    .claude/settings.json, .mcp.json
```

The AI profile keeps the essentials: declared models, API/endpoint classes,
explicit token and step limits, tools and tool policies. Identical values appear
once. Model declarations can come from code or explicit LLM sections in JSON/YAML
files under `config/` or `configs/`:

```text
  AI profile:
    Model (config)  gemma-example:4b
    API             OpenAI-compatible; loopback HTTP
    Limits          steps 10
    Tools           searchProducts, getProductReviews, getOrderById, generateCoupon
```

JSON/YAML retain every source location, SDK import, model call and captured option,
including sampling, retries and unresolved values. Text omits these technical
details and shows `Model: not resolved` only when no literal model is recognized.
Configuration files are not merged and the active model is not verified;
OpenAI-compatible does not identify the model vendor. Profiles earn no points,
and omitted limits do not establish a weakness. Model profiles require version
0.3.3 or later.
Model-chosen tool arguments, URLs and file paths are not yet followed; see the
[AI & agents criteria](references/subscores.md#ai--agents).

## Usage

```sh
security-score                                           # current directory
security-score /path/to/repository --details             # overview and findings per topic
security-score /path/to/repository --json                # all findings, also --yaml
security-score /path/to/repository --quiet               # only the number
security-score /path/to/repository --checks tls,headers  # selected checks
security-score /path/to/repository --staged              # relevance of staged changes
security-score /path/to/repository --base main --head HEAD
security-score https://github.com/example/private-project --token-env GITHUB_READ_TOKEN
```

URLs work for GitHub.com, GitLab.com and self-managed GitLab instances. Other
HTTPS hosts are treated as GitLab; the host and optional port come from the
repository URL. Public repositories need no token. To select a token explicitly,
put it in an environment variable and pass its name:

```sh
security-score https://gitlab.company.example/team/project --token-env GITLAB_READ_TOKEN --details
```

Repository URLs work with or without a trailing `.git`; both select the same
project through the host API.

If `GIT_TOKEN` is already exported, you can omit `--token-env` and the
configuration file. The tool starts anonymously and retries once with
`GIT_TOKEN` on HTTP 401, 403 or 404, only at the selected HTTPS API origin:

```sh
security-score https://gitlab.company.example/team/project --details
```

To assign different tokens to specific hosts, create
`~/.config/security-score/token-hosts.json`
(or `$XDG_CONFIG_HOME/security-score/token-hosts.json`):

```json
{
  "https://gitlab.company.example": "GIT_TOKEN",
  "https://api.github.com": "GITHUB_TOKEN"
}
```

This file contains environment variable names, not token values. Set the named
variables before running the tool. You can then omit `--token-env`:

```sh
security-score https://gitlab.company.example/team/project --details
```

Automatic reads start anonymously. On HTTP 401, 403 or 404, the tool retries the
request once with the token assigned to that exact HTTPS origin, or `GIT_TOKEN`
when no mapping matches. An origin includes its port; configure
`https://gitlab.company.example:8443` separately when needed. `--token-env NAME`
overrides both and uses that token from the first request. A missing or invalid
explicitly selected or mapped variable is an error; it does not fall back to
`GIT_TOKEN`. Without a matching mapping or `GIT_TOKEN`, access stays anonymous.

The GitLab token needs `read_api` and access to the project. The tool reads files
and host settings through the API without cloning. Internal GitLab addresses,
including shared address space `100.64.0.0/10`, and custom HTTPS ports are
supported; loopback, link-local and cloud metadata addresses remain
blocked. For an internal certificate authority, use your system trust store or
set `SSL_CERT_FILE` to its CA bundle. SSH URLs and other Git providers need a
local checkout. Self-managed GitLab URLs use the internal engine.

HTTP proxies are supported for HTTPS repository scans:

```sh
export HTTP_PROXY=http://proxy.company.example:3128
security-score https://gitlab.company.example/team/project --token-env GIT_TOKEN --details
```

The tool checks `HTTPS_PROXY`, then `ALL_PROXY`, then `HTTP_PROXY`; lowercase
forms take precedence over their uppercase equivalents. `NO_PROXY` supports
hosts, domain suffixes, optional ports and `*`. Proxy URLs must use `http://`
without embedded credentials. Repository requests and tokens remain inside the
verified HTTPS tunnel. Proxy failures are reported separately from a repository
404 and never cause an automatic direct connection.

## Reading the legacy result

Use `--legacy-score` for the previous one-line score and A–F grade.

Each area, such as execution or transport, starts at 100 and loses points per
finding. The lowest area score is the repository score, so a strong area cannot
offset a weak one.

| Score | 90–100 | 80–89 | 70–79 | 60–69 | 50–59 | 0–49 |
| --- | --- | --- | --- | --- | --- | --- |
| Grade | A | B | C | D | E | F |

In scripts and CI, check the exit status as well. `--quiet` also prints a number
for a partial result.

| Status | Meaning |
| --- | --- |
| 0 | Complete result, including a change rated `unclear` |
| 1 | Incomplete result or error, such as a reached limit or an inaccessible repository |
| 2 | Partial or undetermined result, or invalid arguments |
| 130 | Cancelled |

## Limits

- Findings are pattern matches, not confirmed vulnerabilities.
- Not checked: login flows, access control, business logic, and known
  vulnerabilities in dependencies.
- Application code is read for Python and JavaScript/TypeScript only. Other
  languages get configuration checks at most.
- Secrets are found by fixed prefix or file name. A generic key or password in
  source code is not found.

## Update

Automatic architecture assessment requires tool version 0.3.0 or later. Installing or
pushing the separate `appsec-skills` repository does not update this Python tool. When publishing a
local tool change, commit and push it from the `appsec-tools` checkout first.

```sh
security-score --update
```

This reinstalls from the original installation source, not from a signed
release. Local directory installations use their recorded absolute source path,
so updates work from any directory. They install the current local files without
pulling Git changes. To switch an existing SSH installation to HTTPS or repair a
broken installation:

```sh
pipx install --force --pip-args="--upgrade --force-reinstall --no-cache-dir" \
  "git+https://github.com/appsec-foundry/appsec-tools.git#subdirectory=security-score"
```

For a local installation, run this once from the `appsec-tools` repository root
to repair an older updater that fails with `Directory '.' is not installable`:

```sh
pipx install --force --pip-args="--upgrade --force-reinstall --no-cache-dir" \
  "$PWD/security-score"
```

## Development

Run from `security-score/`:

```sh
python3 -B -m unittest test_security_score test_security_controls test_gitlab_remote test_auto_token test_http_proxy -v  # offline tests
python3 -B -m unittest test_packaging -v                              # build and install a wheel
python3 scripts/score.py --verify-rules                               # rule examples
```

## Further reading

- [Security Score explained](<security score.md>): how the score is calculated,
  with examples
- [Usage reference](references/usage.md): `--details` output, URL scans and tokens,
  change comparisons, all options, live test
- [Technical reference](references/scoring.md): what each check recognizes, limits,
  maintaining the rules
- [Engines and compatibility](references/compatibility.md): the optional
  `--engine analyzer` with a separately installed AppSec Analyzer
