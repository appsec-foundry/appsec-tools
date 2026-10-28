# Reference

Details on configuration, extraction, authentication, and output. For an
introduction, see the [quick start](../README.md). Run all commands from the tool
directory.

## Create a configuration

The complete [JSON schema](../harvester/schemas/config.schema.json) is the
authoritative configuration interface. Another example is [table.yaml](../examples/table.yaml).

```bash
.venv/bin/python -m harvester schema > /tmp/harvester-config.schema.json
```

A configuration contains `config-version: 1`, `output`, optional `defaults`, and
`sources`. Unknown fields, duplicate YAML keys, YAML aliases, and executable
tags are rejected. Paths are resolved relative to the configuration file.

For each source, specify:

- `id`, `title`, and one or more `start-urls`;
- `crawl.allowed-origins`, such as `https://wiki.example.org` without a trailing slash;
- optionally `allowed-path-prefixes`, `exclude-path-prefixes`, and `allowed-query-keys`;
- `auth`, optional `ca-bundle`, and `extraction`.

The `/` path scope allows the entire host; `/policies/` allows that path and its
descendants but not `/policies-old/`. Subdomains are separate origins. Start
pages must be within scope. Query parameters are followed only when their keys
are explicitly allowed. Credential parameters are excluded. Diagnostics contain
no query values.

`crawl.max-depth: 0` reads only start pages; `1` also reads their direct links,
and so on. `null` removes the depth limit, while other resource limits still
apply. `crawl.mode: explicit-pages` limits a run to start pages. Multiple start
pages are processed together in breadth-first order; the shortest distance
applies when there are multiple link paths. Unlinked pages are not discovered.

Important defaults: 200 pages, link depth 3, 400 requests per source, 5 MiB per
response before and after decompression, a 1-second interval between requests,
a 5-second connection timeout, and a 30-second read timeout. The entire run is
limited to 900 seconds. `defaults` changes these values; `crawl` can override
source-specific values. See the schema for further limits. Exceeding a budget
marks the run incomplete; reaching the configured scope or link depth normally
is not an error.

Configure internal networks explicitly for each source:

```yaml
crawl:
  allowed-origins: [https://wiki.internal.example]
  allowed-path-prefixes: [/requirements/]
  allowed-private-networks: [10.20.30.0/24]
ca-bundle: ./company-ca.pem
```

Only RFC1918 networks and IPv6 unique local addresses can additionally be
allowed. Loopback, link-local, metadata destinations, and IPv6 transition
addresses remain blocked. Destination addresses are resolved and checked
immediately before connection, then connected to numerically; TLS still
verifies the original hostname. Redirects are checked again. HTTP proxy
environment variables are not used; the runner needs direct access to sources.

## Extraction rules

`content-selector` must select exactly one main content region. An optional
`context-selector` takes shared context from that region; `exclude-selectors`
removes navigation or known side notes, for example.

Each rule has a unique `id`, an `item-selector`, `fields`, and a strategy:

| Strategy | Meaning |
| --- | --- |
| `blocks` | One requirement per selected content block, such as a list item. |
| `table-rows` | One requirement per `tr`; when the entire row is used, table headers are retained as field labels. |
| `sections` | A heading and following sibling elements up to the next heading of equal or higher level. |

`page-selector` activates a rule only on matching pages. An active rule must
find matches unless `required: false` is set. By default, a page without
requirements fails; set `extraction.allow-empty-pages: true` for known index-only
pages. Main content and rules are still checked. A completely empty source
remains an error.

Fields: `original-id`, `title`, `statement`, `obligation`, `context`,
`applicability`, `exceptions`, `category`, `revision`, `guidance`, `example`.
Only `statement` is required; it must be nonempty after extraction.

```yaml
fields:
  original-id: {attribute: id}
  title: {selector: h2}
  statement: {selector: .requirement-text}
  applicability:
    scope: page
    selector: .applicability
    many: true
```

A field selector is relative to the item, or to the entire page with
`scope: page`. Without a selector, the entire item is used. `attribute` reads
an attribute allowed by the schema; `many: true` joins multiple matches.
Otherwise, multiple matches are an error. Alternatively, `value` sets an
explicit constant. Missing optional fields remain empty. The tool does not
infer obligation from keywords or add MUST or SHOULD.

Paragraphs, nested lists, tables, and code are retained as Markdown. Conditions
and exceptions belong in the statement or corresponding context fields. Rules
cannot prove their own semantic completeness: check trial runs against
representative pages and expected results.

Identity uses the original ID within the source, otherwise the page URL plus
an anchor directly on the item, otherwise the page URL plus content. IDs are
based on SHA-256 and separated by source. Without an original ID or stable
anchor, changing content produces a new ID. Inserting other items does not
shift existing IDs. Conflicting statements with the same source identity
abort the run.

## Authentication

Credentials are loaded only through external references. Do not put real
credentials in configurations, process arguments, or Git. Authenticated sources
have exactly one origin; credentials are not forwarded to other origins.

API token:

```yaml
auth:
  mode: token
  token-env: HARVEST_TOKEN
  header: Authorization
  prefix: Bearer
```

For `X-Api-Key`, for example, `prefix: ""` is possible.

Username and password via HTTP Basic over verified HTTPS:

```yaml
auth:
  mode: basic
  username-env: HARVEST_USERNAME
  password-env: HARVEST_PASSWORD
```

Form logins are not a generic HTTP Basic method and require an adapter for the
specific target application if needed.

Entra ID for unattended runs:

```yaml
auth:
  mode: entra
  flow: client-credentials
  tenant-id: 00000000-0000-4000-8000-000000000001
  client-id: 00000000-0000-4000-8000-000000000002
  client-secret-env: ENTRA_CLIENT_SECRET
  scopes: [api://YOUR-RESOURCE/.default]
```

Replace the tenant, client, and scope with real, administratively configured
values. The target application must accept this token for its content and
grant the application appropriate read permissions.

For interactive sign-in with Microsoft Entra ID:

```yaml
auth:
  mode: entra
  flow: interactive
  tenant-id: 00000000-0000-4000-8000-000000000001
  client-id: 00000000-0000-4000-8000-000000000002
  scopes: [api://YOUR-RESOURCE/Requirements.Read]
  token-file: ../.sessions/company.json
```

```bash
.venv/bin/python -m harvester login --config company.yaml --source company
.venv/bin/python -m harvester run --config company.yaml
```

Interactive sign-in uses MSAL's authorization-code flow with PKCE and a local
callback. The app registration needs the corresponding desktop/public-client
access path with `http://localhost` as redirect URI. See
[Microsoft's MSAL documentation](https://learn.microsoft.com/en-us/entra/msal/python/getting-started/acquiring-tokens).

Only the access token is stored, with its expiry and binding to source, tenant,
client, origin, and scopes, in a file with mode 0600; no refresh token is stored.
After expiry, sign in again. `run` never opens a browser and never waits for
input, even without `--non-interactive`.

Entra support here means bearer-token access to the target application. A
website that accepts only its own browser session cookies is not automatically
supported. Its specific access method must first be established. A real company
tenant was unavailable for local implementation tests; SDK integration, error
cases, and storage were tested with synthetic responses.

## Output and OSCAL

The default uses `output.catalog`, `title`, `version`, and `report`. For multiple
files:

```yaml
output:
  report: ../out/report.json
  catalogs:
    - id: all
      path: ../out/all.oscal.yaml
      title: All Requirements
      version: "1.0.0"
      source-ids: [engineering, operations]
    - id: operations
      path: ../out/operations.oscal.yaml
      title: Operations
      version: "1.0.0"
      source-ids: [operations]
```

A source is crawled only once, even if assigned to multiple outputs. Every
source must belong to at least one output. The example needs matching source
IDs in `sources`.

Each source becomes an OSCAL group; each requirement becomes a control with a
`statement`. Original IDs, provenance, and optional metadata are stored as
properties in the project namespace. Multiline context, applicability, and
exceptions are separate parts; `guidance` and `example` use OSCAL part names.
Source URLs and references are retained as links. Linked resources are fetched
only under normal crawl rules, not for export validation.

The [official NIST schema](../harvester/schemas/README.md) is bundled locally.
Each new export gets a new document UUID and modification time; control IDs and
semantic content remain stable for identical inputs. Therefore, comparing the
entire file including runtime metadata does not yield byte-identical results.

| Exit code | Meaning |
| --- | --- |
| 0 | Success; a dry run validates but writes no catalog. |
| 2 | Invalid configuration or invocation. |
| 3 | Authentication failed, missing, or expired. |
| 4 | Fetch, scope, budget, or extraction failed. |
| 5 | Export validation, publication, or CI artifact preparation failed. |
| 130 | Cancelled by the user. |

## CI and development

Templates for [GitLab CI/CD](../ci/gitlab-ci.yml) and [GitHub Actions](../ci/github-actions.yml),
with setup guidance, are in [ci/README.md](../ci/README.md). They are not
enabled automatically. The tool has no write access to repositories.

```bash
.venv/bin/python -m pip install --require-hashes -r requirements-dev.lock
.venv/bin/python -m pytest
python3 scripts/check_dependencies.py
```

Tests use synthetic sources, controlled transport interfaces, and network
failures. The dependency check queries published PyPI advisories; network
errors make it fail. Package versions and origins checked during development
are recorded in `dependency-provenance.json`.

HTML is read statically. JavaScript rendering, attachments, PDFs, arbitrary
login forms, and automatic rule changes are not implemented. The
[requirements document](../requirements.md) records requirements, decisions,
and implementation status.
