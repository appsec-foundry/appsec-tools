# Requirements for Requirement Harvester

Target behavior and agreed decisions. Usage is described in the
[README](README.md) and the [reference](docs/reference.md); the
[configuration schema](harvester/schemas/config.schema.json) is the
authoritative interface.

## Purpose

The tool reads requirements of any kind from HTTPS websites and wikis and
writes them to an OSCAL catalog in YAML. Its main use is to turn internal
company policies into input for automated checks, such as code reviews against
security policies. Obligation, applicability, conditions, exceptions, and
source must be preserved. The tool does not assess compliance and does not
change source pages.

## Decisions

- A Python CLI started with a YAML configuration file. It is developed
  independently of the harvester in appsec-analyzer; no code, extraction
  rules, or tests are reused.
- Scans are deterministic and need no LLM, model service, or API key.
  Configurations are written by hand or with an external assistant; the tool
  itself has no LLM integration.
- The configuration is declarative: CSS selectors and fixed extraction
  strategies, no expressions, shell commands, or import paths. Another layout
  needs another rule; a different fetch method may need an adapter.
- OSCAL 1.2.3 YAML is the only output format. Export in the appsec-analyzer
  catalog format is out of scope.
- Every run regenerates the catalogs completely from the sources. Old content
  and manual additions are not kept.
- Access methods per source: public, API token, username/password, and company
  SSO. Microsoft Entra ID is the first SSO provider.
- Unattended runs in GitLab CI/CD and GitHub Actions, GitLab first.
- Expected scale is a few dozen pages per run; distributed crawling is not
  planned.
- Not supported: JavaScript rendering, PDF/Office/archive files, and generic
  form logins, which need an adapter for the target application.

## Functional requirements

| ID | Requirement |
| --- | --- |
| RH-F01 | Support multiple named sources per configuration; each source has a stable, unique ID and one or more start URLs. |
| RH-F02 | Process requirements of any subject matter, including mixed sources. Keep optional categories from the source or configuration traceable; do not require a fixed taxonomy. |
| RH-F03 | Follow links recursively from multiple start pages. Start pages are depth 0; each followed link adds 1. A page reachable through multiple paths gets the shortest distance from a start page of the same source. |
| RH-F04 | Define hosts, ports, path scopes, inclusions/exclusions, depth, and fetch budgets per source. Exclusions take precedence; links outside scope are not fetched; start pages outside scope make the configuration invalid. |
| RH-F05 | Support different content structures through named extraction rules, such as table rows, headings with following paragraphs, lists, and marked content blocks. |
| RH-F06 | Separate main content from navigation, footer, and other page chrome. Report mismatched or ambiguous rules instead of treating arbitrary page text as requirements. Layout changes produce diagnostics, never automatic rule changes. |
| RH-F07 | Capture at least a stable identifier, statement, and source evidence for each entry. Include title, original ID, obligation, applicability, conditions, exceptions, context, category, and source version where available. |
| RH-F08 | Preserve full content in the source language. Normalization must not lose normative terms, negations, conditions, exceptions, table relationships, or relevant code examples. |
| RH-F09 | Do not treat every web page or paragraph as a requirement. Definitions, recommendations, examples, and explanatory context must remain distinguishable. |
| RH-F10 | Treat missing obligation as unknown. Do not add MUST, SHOULD, or MAY without source evidence or an explicitly configured source convention. |
| RH-F11 | Make the source, actual fetched page URL, section or anchor, and fetch time traceable for each entry. Include page revision and original ID when available. |
| RH-F12 | Deduplicate repeated fetches of the same page and identical entries within one source. Treat matching IDs with differing content as conflicts; do not silently merge different sources. |
| RH-F13 | Keep entry IDs stable across runs when source identity is unchanged. Preserve original IDs and use source namespaces to avoid collisions. Without an original ID or stable anchor, identity is the page URL plus statement; changing content then creates a new ID. |
| RH-F14 | Preserve existing relationships and references between requirements. Do not fetch referenced content outside crawl scope; report unresolved relationships. |
| RH-F15 | Generate a valid OSCAL catalog as UTF-8 YAML; do not publish semantically incomplete, conflicting, or schema-invalid results as successful. |
| RH-F16 | Write a machine-readable run report listing fetched, excluded, and failed pages, entry counts, conflicts, and extraction gaps. Reports do not contain complete source pages. |
| RH-F17 | Offer configuration validation without network access and a dry run with fetching and extraction that does not replace the target catalog. |
| RH-F18 | By default, end with an error and leave the last valid catalog unchanged on fetch errors, exhausted resource budgets with pending pages within scope and depth, extraction conflicts, or unexpectedly empty output. Reaching the intended scope or depth is not an error. Report pages without relevant content separately from extraction errors. |
| RH-F19 | Run a full scan including OSCAL export without an LLM, model access, or API key. Identical input and tool version give the same entries, IDs, ordering, and statements. |
| RH-F20 | Provide a versioned, documented configuration schema with examples. Validate every configuration, whether written by hand or by an assistant, before the first fetch: reject unknown fields, duplicate keys, invalid selectors, conflicting scopes, and unresolved rule references, with errors naming the field path. |
| RH-F21 | By default, produce one OSCAL catalog from all sources. Optionally support multiple named catalogs with target paths and source assignments; each output is independently valid and retains provenance. Publication is atomic per file; a failure during publication fails the run, and the report lists which files were replaced. |
| RH-F22 | Besides public sources, support API tokens, username/password, and company SSO, configured per source with credential references. |
| RH-F23 | Regenerate catalogs completely on every run and replace previous output files only after successful fetch, extraction, and validation. Do not copy manual additions or requirements no longer present in the sources. Stable IDs remain as specified in RH-F13. |
| RH-F24 | Provide noninteractive runs and documented CI templates for GitLab CI/CD and GitHub Actions, using the same CLI and configuration as local runs. Noninteractive runs never wait for input; missing or expired access ends with an error. Success, invalid configuration, access problems, and incomplete results have distinct exit codes. A failed CI run publishes no catalog. |

## Security requirements

Assets are source credentials, internal content, the local catalogs, and source
availability. Trust boundaries lie between operator configuration, remote pages
and links, the parser, and local files.

| ID | Requirement |
| --- | --- |
| RH-S01 | Use HTTPS with certificate and hostname verification; allow a configured internal CA. Provide no option to disable TLS verification. |
| RH-S02 | Check configured origins, ports, path scopes, and allowed destination networks at the actual connection, including IPv6 and DNS changes. Block loopback, link-local, and metadata destinations; allow internal networks only through explicit, narrow configuration. |
| RH-S03 | Recheck scope and addresses on every redirect and limit the hop count. Never forward authentication data or cookies to other origins. Login endpoints are configured separately from crawl scope and are not reachable through page links. URL normalization and path limits must resist traversal and alternative address spellings. |
| RH-S04 | Obtain read-only credentials for protected sources from external configuration or secret management; configurations contain references, not secret values. Missing credentials and 401/403 responses produce clear errors; login pages do not count as content pages. Stored sessions are kept outside the configuration with restrictive file permissions. |
| RH-S05 | Reject URLs with embedded credentials. Do not put tokens in URLs, process arguments, catalogs, or reports; remove sensitive query values from logs and structurally encode untrusted log fields. |
| RH-S06 | Limit page count, link queue, requests, redirects, retries, decompressed bytes, parser work, and runtime. Respect rate limits and Retry-After; prevent endless loops through links or URL variants. Source-specific settings cannot bypass global safety limits or destination checks. |
| RH-S07 | Treat web pages and configuration only as data. Do not execute scripts, embedded instructions, or parser loading functions, and do not fetch unplanned subresources. |
| RH-S08 | Parse only needed content types, considering Content-Type and actual content. |
| RH-S09 | Derive local target files from operator configuration, never from page titles or remote filenames. Serialize YAML safely, validate output before replacement, and write catalogs with restrictive file permissions. |
| RH-S10 | Do not store complete authenticated pages by default. Send neither content nor credentials to model services. |
| RH-S11 | Give CI jobs minimal, read-only permissions. Do not run code or configuration from untrusted merge/pull requests with source credentials. Install dependencies from lockfiles with verified hashes; pin external Actions and containers to immutable references; check dependencies regularly for vulnerabilities; run containers without root. Restrict access to artifacts and do not write results back to a repository. |

## OSCAL mapping

The output uses the OSCAL [Catalog Model](https://pages.nist.gov/OSCAL/learn/concepts/layer/control/catalog/).
Mapping a requirement to a control does not make it a security requirement.

| Requirement data | OSCAL |
| --- | --- |
| Collection and version | `catalog.metadata` with title, version, OSCAL version, and modification time |
| Source or category | `groups` with stable IDs and titles |
| Requirement | `controls` with `id`, `title`, and a `statement` part |
| Explanations and examples | Parts named `guidance` and `example` |
| Original ID, provenance, optional categories | Properties in the `https://github.com/appsec-foundry/appsec-analyzer-tools/ns/requirement-harvester` namespace |
| Source reference | `links` with `rel: reference`, with a section anchor where available |
| Context, applicability, exceptions | Parts named `context`, `applicability`, and `exceptions` in the same namespace |

Control IDs are stable; the document UUID and `metadata.last-modified` change
with every export, as NIST requires for changed documents.

## Verification

Tests use synthetic HTML fixtures and controlled HTTP/DNS test doubles.
Connection protection (RH-S01 to RH-S03) is tested at the transport boundary;
a mock above the destination check is not sufficient evidence. Live tests with
real credentials are not part of the regular test suite.

## Integration with appsec-analyzer

At appsec-analyzer commit `486d201252409859ddcf6aac69e5d8ea299c953e`, the
requirements catalog contract (`schemas/requirements-catalog.schema.yaml`) is
its own YAML format (`categories[].requirements[]` with `id`, `text`,
`priority`, `url`), not OSCAL. Direct OSCAL import has not been established;
a valid OSCAL file is therefore not proof of compatibility. Adding OSCAL
support is a separate task in the main repository and not a prerequisite for
this tool.

## Open questions

| ID | Question | Status |
| --- | --- | --- |
| O01 | Which other company pages should be captured? | TSS-WEB is configured as an example. Other layouts need their own configuration and a review of their dry runs. |
| O02 | Which access method does each protected target application support? | Header tokens, HTTP Basic, and Entra bearer tokens are implemented. Tenant, app registration, read permissions, and token acceptance need on-site verification; cookie or form logins need an adapter. |
| O10 | Which private CI projects, runners, and artifact recipients will be used? | The templates document prerequisites and were tested locally; hosted pipeline runs happen during setup. |
