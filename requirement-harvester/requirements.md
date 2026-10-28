# Requirement Harvester — requirements and implementation plan

As of 2026-10-28. Status: version 0.1.0 implemented; operational integration
with protected company sources and hosted CI instances still needs on-site verification.

## Implementation status

- The Python CLI supports a configuration schema, offline validation, dry runs,
  and complete regeneration of one or more OSCAL 1.2.3 catalogs.
- Crawl scope and depth, multiple start pages, resource budgets, three declarative
  extraction strategies, provenance, and controlled error handling are implemented.
- The bundled TSS-WEB configuration was tested live on 21 pages and produced
  121 schema-valid requirements. It includes rules for the observed list, section,
  and table layouts; this does not replace a complete semantic review of all
  source text.
- Authentication is implemented with header tokens, HTTP Basic, and Entra bearer
  tokens. Entra uses MSAL for interactive sign-in or client credentials.
  Application-specific form logins and websites that accept only their own
  browser session cookies require a separate adapter.
- GitLab and GitHub templates and their shared noninteractive entry point are
  available. Hosted pipeline runs and a real Entra tenant were unavailable;
  the relevant interfaces and error paths were tested locally with synthetic
  sources or responses.
- Installation, concrete configuration fields, and operational prerequisites
  are in the [README](README.md). The [configuration schema](harvester/schemas/config.schema.json)
  is the authoritative interface.

## Goal and confirmed scope

The tool collects requirements of any kind from HTTPS websites and wiki pages
and stores them as OSCAL YAML. Content can have different descriptions and
structures in each source. A configuration file controls sources, crawl
behavior, and content recognition.

Its main purpose is to prepare internal company policies as input for automated
processes, such as code reviews against the company's security policies.
Obligation, applicability, conditions, exceptions, and provenance must be
preserved. The first public source is a starting point; intended use includes
internal websites. Security policies are one use case, not a subject-matter
restriction. Functional, organizational, technical, and other requirements can
also be processed. The tool assumes no fixed subject taxonomy.

Confirmed decisions:

- Implement a Python command-line tool started with a configuration file.
- Develop it independently in this repository; do not reuse code, extraction
  rules, or tests from the existing harvester in appsec-analyzer.
- Support unattended execution in GitLab CI/CD and GitHub Actions, implementing
  GitLab first.
- First source: `https://tss-web.secodis.com`, publicly accessible according to
  the user. A verified example configuration for `/Controls/` is available.
- Include protected internal pages in the initial feature set. Plan API tokens,
  username/password, and company SSO as access methods configurable per source.
- Support Microsoft Entra ID as the first company SSO solution.
- Support multiple start pages, recursive link following, configurable host or
  path scope, and a maximum crawl depth.
- Expected scale: a few dozen pages per run. Crawl limits remain configurable;
  distributed crawl infrastructure is not planned for this scale.
- By default, put all requirements into one OSCAL file. Allow optional
  configuration of multiple output files and their source assignments.
- OSCAL YAML is the only semantic output format. An additional export in the
  existing appsec-analyzer catalog format is outside scope.
- Regenerate the intended catalogs completely from current sources and the
  configuration on every run. Do not merge or retain existing catalog content
  or manual additions.
- Run the scan deterministically from a saved configuration, without an LLM,
  API key, or running model service.
- Create and revise configurations manually or with an external assistant.
  The first version has no built-in LLM integration. The schema, examples,
  configuration validation, and dry runs support both workflows.

The tool belongs in this repository as an independently usable supplementary
tool. It prepares catalogs for appsec-analyzer and other automation. It neither
assesses application compliance nor changes source pages.

The following mandatory requirements record the agreed target behavior.
Concrete limitations and outstanding operational checks are stated in the
implementation status and README.

## Domain model

A requirement is a statement taken from a source, with its original meaning,
obligation, and scope. The label used on the website does not determine whether
it is captured. Optional categories and groupings come from the source or an
explicit configuration mapping; they are not prerequisites for extraction.
The tool preserves existing semantics without needing to assign requirements
to predefined subject classes.

## Workflow

### Optional configuration preparation

1. The operator selects representative example pages and the permitted source scope.
2. An external assistant may suggest declarative extraction rules from these
   examples. The harvester itself does not call a model.
3. Suggestions undergo the same schema and value validation as manual
   configurations. Before accepting one, the operator checks in particular that
   proposed start pages and scope match the intended boundaries.
4. A deterministic dry run shows detected entries with source locations and
   exposes missing or conflicting mappings.
5. Save and version the reviewed configuration. Expected results for
   representative pages serve as regression tests for later rule changes.

The LLM generates configuration data, not executable program code. Page content
and model responses are untrusted data; instructions within them cannot affect
the harvester's permissions or fetch targets. Choosing an assistant approved
for internal content and approving example data take place outside the tool.
The harvester configuration contains no model-provider settings or LLM credentials.

### Regular scan

1. Load and fully validate the configuration.
2. Fetch permitted start pages and discover further pages within crawl scope.
3. Read main content and relevant structures using each source's rules.
4. Map content into a shared internal model with source evidence.
5. Check identities, duplicates, conflicts, and ambiguous mappings.
6. Generate the OSCAL document and validate it against the selected version.
7. Only after all intended catalogs pass validation, atomically publish each
   target file and write a run report.

With identical page content, configuration, and tool version, entries, IDs,
ordering, and semantic statements must be reproducible. Runtime metadata and
OSCAL document versioning are handled separately. Layout changes produce
diagnostics; there is no automatic LLM fallback or automatic change to stored
rules during a scan.

The chosen design is a local Python CLI with separate components for
configuration, HTTP fetching, link discovery, extraction, the internal model,
and OSCAL export. A web UI or running server is not planned for the first version.

## Functional requirements

| ID | Requirement |
| --- | --- |
| RH-F01 | Support multiple named sources per configuration; each source has a stable, unique ID and one or more start URLs. |
| RH-F02 | Process requirements of any subject matter, including mixed sources. Preserve optional categories from the source or configuration with traceability; do not require a fixed taxonomy. |
| RH-F03 | Follow links recursively from multiple start pages. Start pages are depth 0; each followed page link increases depth by 1. For a page reachable through multiple paths, use the shortest distance from a start page of the same source. |
| RH-F04 | Define hosts, ports, path scopes, inclusions/exclusions, depth, and fetch budgets per source. Exclusions take precedence; links outside scope are not fetched. |
| RH-F05 | Support different content structures through named extraction rules, such as table rows, headings with following paragraphs, lists, and marked content blocks. |
| RH-F06 | Separate main content from navigation, footer, and other page chrome. Report mismatched or ambiguous rules instead of treating arbitrary page text as requirements. |
| RH-F07 | Capture at least a stable identifier, statement, and source evidence for each entry. Include title, original ID, obligation, applicability, conditions, exceptions, context, category, and source version where available. |
| RH-F08 | Preserve full content in the source language. Normalization must not lose normative terms, negations, conditions, exceptions, table relationships, or relevant code examples. |
| RH-F09 | Do not automatically treat every web page or paragraph as a requirement. Definitions, recommendations, examples, and explanatory context must remain distinguishable. |
| RH-F10 | Treat missing obligation as unknown. Do not add MUST, SHOULD, or MAY without source evidence or an explicitly configured source convention. |
| RH-F11 | Make the source, actual fetched page URL, section or anchor, and fetch time traceable for each entry. Include page revision and original ID when available. |
| RH-F12 | Deduplicate repeated fetches of the same page and identical entries within one source. Treat matching IDs with differing content as conflicts; do not silently merge different sources. |
| RH-F13 | Keep entry IDs stable across repeated runs when source identity is unchanged. Preserve original IDs and use source namespaces to avoid collisions. Without an original ID or stable anchor, identity is the page URL plus statement; changing content then creates a new ID. |
| RH-F14 | Preserve existing relationships and references between requirements. Do not automatically fetch referenced content outside crawl scope; report unresolved relationships. |
| RH-F15 | Generate a valid OSCAL catalog as UTF-8 YAML; do not publish semantically incomplete, conflicting, or schema-invalid results as successful. |
| RH-F16 | Write a machine-readable run report listing fetched, excluded, and failed pages, entry counts, conflicts, and extraction gaps. Reports do not contain complete source pages. |
| RH-F17 | Offer configuration validation without network access and a dry run with fetching and extraction that does not replace the target catalog. |
| RH-F18 | By default, end with an error and leave the last valid catalog unchanged on fetch errors, exhausted resource budgets with pending pages within the chosen scope and depth, extraction conflicts, or unexpectedly empty output. Intended scope and depth limits are not errors. Report pages without relevant content separately from extraction errors. |
| RH-F19 | Support a full scan including OSCAL export without an LLM dependency, model access, or API key. Produce semantically reproducible results for identical input and tool version. |
| RH-F20 | Provide a documented configuration schema and examples for manual creation or creation with an external assistant. Validate imported configurations regardless of origin and make them testable with dry runs. The first version has no model calls or LLM-provider integration. |
| RH-F21 | By default, produce one OSCAL catalog from all sources. Optionally support multiple named catalogs with configured target paths and source assignments. Each output must be independently valid and retain entry provenance. |
| RH-F22 | In addition to public sources, support access with API tokens, username/password, and company SSO. Configure methods and credential references per source; authentication and session management remain independent of an LLM. |
| RH-F23 | Regenerate catalogs completely from currently captured sources and the configuration on every run. Replace previous output files after successful fetch, extraction, and validation. Do not copy manual additions or requirements no longer present in sources from old outputs. Stable requirement identities remain as specified in RH-F13. |
| RH-F24 | Provide noninteractive runs and documented CI templates for GitLab CI/CD and GitHub Actions, with GitLab first. Both use the same CLI and configuration as local runs. Success, invalid configuration, access problems, and incomplete results must be distinguishable through documented exit codes and the run report. |

## Configuration as the central interface

Use a versioned YAML file with a strict schema and understandable errors that
include the field path. Reject unknown fields, duplicate keys, invalid selectors,
conflicting scopes, unresolved rule references, and missing required values
before the first fetch. Load YAML only as data, without executable tags.

The configuration describes:

- global limits and explicit per-source overrides;
- source identity, start pages, and permitted crawl scope;
- authentication references and, if needed, an internal CA;
- source type or adapter and rules for different page layouts;
- field mapping including original ID, title, statement, context, and obligation;
- optional categories and groupings matching the source;
- one shared output target or multiple catalogs with source assignments,
  catalog metadata, and a fixed OSCAL version.

The configuration must not execute Python expressions, shell commands, or
arbitrary import paths. Initially, use declarative CSS selectors and fixed
extraction strategies. Another layout gets another rule; a fundamentally
different fetch method may require an adapter. Unknown layouts produce a
diagnostic report rather than a silent fallback rule.

### Start pages, scope, and depth

- `start-urls` contains one or more start pages per source. Each start page
  must be in the configured scope, or the configuration is invalid.
- `allowed-origins` fixes the HTTPS host and port exactly. Subdomains are not
  included automatically. The `/` path scope allows the entire host.
- `allowed-path-prefixes` limits scope to one or more path regions. `/policies/`
  includes that path and descendants, but not `/policies-old/`, for example.
- Host, path, and exclusions are checked together. A link cannot leave scope
  even when it appears on an allowed page.
- `max-depth: 0` reads only start pages, `1` also their direct links, and so on.
  A finite value is a nonnegative integer; `null` follows all reachable links
  in scope without a depth limit. Page, request, and runtime budgets still apply.
- Depth counts links, not URL path segments. Redirects do not increase link
  depth, but are subject to scope checks and a separate redirect limit.
- Overlapping start pages and link loops must not cause repeated fetches of
  the same normalized page URL within a source.
- Scope permits fetching reachable pages; it does not guarantee discovery of
  unlinked pages. These need additional start URLs or a later, explicitly
  configured discovery method.

### Authentication per source

Three access methods are confirmed in addition to `auth.mode: none`:

- **API token:** Send an externally supplied token using the header method
  defined for the source. Do not put tokens in URLs or process arguments.
- **Username/password:** Use externally supplied credentials through a method
  supported by the source. HTTP Basic over HTTPS is implemented. Form login
  requires an adapter for the target application if needed.
- **Company SSO:** Plan a separate interactive sign-in step through the normal
  company login. MFA and other login requirements remain in effect. The crawl
  uses the valid access context obtained through that path. Microsoft Entra ID
  is the first chosen provider. Determine the actual integration path from the
  protected target application; choosing a provider alone does not establish
  the application's login interface.

When storage is needed, session data is kept separately from the versioned
configuration with restrictive access permissions. Credentials and sessions
are bound to the respective source or identity. Expired or rejected access
causes an authentication error; the run does not silently continue with
restricted anonymous content. Unattended runs need a suitable access method;
SSO requiring user interaction is not claimed to work unattended. Login
destinations are configured separately from crawl scope and are used only by
the intended login method, not by ordinary page links.

### Unattended execution and CI

- Provide a GitLab CI/CD template first, followed by a corresponding GitHub
  Actions workflow. Both support manually triggered and scheduled jobs;
  scheduling is handled by the respective CI platform.
- In noninteractive mode, the CLI never waits for password input, browser login,
  or MFA. Missing or expired access produces an error status.
- Protected sources require an approved machine access method supported by the
  target application. Entra ID integration must account for that specific path;
  interactive SSO alone is insufficient.
- Supply credentials through the CI platform's secret management. Exclude
  secrets from versioned configurations, logs, caches, and artifacts.
- Successfully generated OSCAL files and the run report are job artifacts.
  After a failed run, do not upload an old or incomplete catalog as a new
  successful result. Keep diagnostics accessible.
- Restrict access to artifacts containing internal requirements and document
  their retention period. Do not publish them publicly or write them back to
  a repository automatically.
- Runners must be able to reach configured internal sources. Document required
  network access and internal CAs as operational prerequisites.

### Example source with tabular requirements

This synthetic example uses the implemented configuration format. Adjust the
domain and selectors for your source. The runnable public example configuration
is [examples/tss-web.yaml](examples/tss-web.yaml).

```yaml
config-version: 1
output:
  catalog: ./out/catalog.oscal.yaml
  report: ./out/harvest-report.json
  title: Organization Policies
  version: "1.0.0"
  oscal-version: "1.2.3"
defaults:
  max-pages: 200
  max-depth: 3
  max-response-bytes: 5242880
  connect-timeout-seconds: 5
  read-timeout-seconds: 30
  max-run-seconds: 900
  max-requests: 400
  request-interval-seconds: 1
sources:
  - id: engineering-requirements
    title: Engineering Requirements
    adapter: html
    start-urls:
      - https://wiki.example.org/security/index
      - https://wiki.example.org/security/services
    crawl:
      mode: linked-pages
      max-depth: 2
      allowed-origins:
        - https://wiki.example.org
      allowed-path-prefixes:
        - /security/
      exclude-path-prefixes:
        - /security/history/
    auth:
      mode: none
    extraction:
      content-selector: main
      rules:
        - id: requirement-table
          strategy: table-rows
          item-selector: table.requirements tbody tr
          fields:
            original-id: {selector: "td:nth-child(1)"}
            title: {selector: "td:nth-child(2)"}
            statement: {selector: "td:nth-child(3)"}
            obligation: {selector: "td:nth-child(4)"}
```

The limits are proposed initial values with room for the expected few dozen
pages per run. Request and runtime budgets also cover retries and redirects;
the size limit applies to decompressed content. A different rule for another
source cannot bypass global safety limits or destination checks.

### One or more output files

`output.catalog` in the example above is the default: all configured sources
are combined in one catalog. Alternatively, `output.catalogs` defines multiple
catalogs. The two forms are mutually exclusive.

The implemented mapping lists the source IDs to include in each output. A
source may be assigned to multiple outputs and is crawled only once. Every
configured source must be assigned to at least one output. Unknown source IDs,
duplicate catalog IDs, and colliding target paths are rejected before fetching.
Further criteria for splitting a source are not yet defined.

This alternative configuration fragment assumes sources with IDs `engineering`
and `operations`:

```yaml
output:
  report: ./out/harvest-report.json
  catalogs:
    - id: engineering-catalog
      path: ./out/engineering.oscal.yaml
      title: Engineering Requirements
      version: "1.0.0"
      source-ids: [engineering]
    - id: operations-catalog
      path: ./out/operations.oscal.yaml
      title: Operations Requirements
      version: "1.0.0"
      source-ids: [operations]
```

Assignment does not change requirement identities. Each file has its own
catalog metadata and document UUID. All catalogs are validated before
publication. Atomic replacement applies per file; multiple files do not form
a filesystem transaction. A failure during publication produces an error
status and a report identifying files already replaced and not replaced,
never an overall success.

## OSCAL mapping

The initial target is the **Catalog Model**. It describes collections of
controls, including statements, groups, and references, and supports YAML.
See [NIST: Control Layer](https://pages.nist.gov/OSCAL/learn/concepts/layer/control/)
and [Catalog Model](https://pages.nist.gov/OSCAL/learn/concepts/layer/control/catalog/).

| Internal feature | OSCAL mapping |
| --- | --- |
| Collection and version | `catalog.metadata` with title, version, OSCAL version, and modification time |
| Category or source structure | `groups` with stable IDs and titles |
| Standalone requirement or recommendation | `controls` with `id`, `title`, and a statement in `parts` with `name: statement` |
| Explanations and examples | Separate parts, such as `guidance` and `example` |
| Original ID | Property on the control; preserve the original value |
| Source reference | `links` with `rel: reference`, preferably including a section anchor |
| Additional provenance and optional categories | Properties in the `https://github.com/appsec-foundry/appsec-analyzer-tools/ns/requirement-harvester` namespace |
| Multiline context, applicability, and exceptions | Parts named `context`, `applicability`, and `exceptions` in the same namespace |

OSCAL is the intended interchange format. Mapping a requirement to a control
does not automatically make it a security requirement. The suitability of the
field mapping is also assessed against other kinds of requirements.

OSCAL 1.2.3 is implemented. The official schema is versioned locally without
changes; validation also supports its Unicode character patterns. Source
content does not trigger schema downloads. Stable control IDs are distinct
from the document UUID: NIST requires a new document UUID and
`metadata.last-modified` when document content changes. Identical semantic
content must remain comparable independently of runtime metadata.

## Integration with appsec-analyzer

During planning, these files were read from local checkout
`/home/mrohr/appsec-analyzer`, HEAD `486d201252409859ddcf6aac69e5d8ea299c953e`:

- `scripts/requirements/harvest_requirements.py`: an existing configurable HTML
  harvester for requirements and blueprints with its own YAML catalog format.
- `schemas/requirements-catalog.schema.yaml`: documented catalog contract with
  `categories[].requirements[]` and fields such as `id`, `text`, `priority`, and `url`.

That contract does not match the OSCAL catalog structure. Direct OSCAL support
by the consumer was not established. Only OSCAL YAML was chosen as the semantic
export. Any necessary consumer extension in the main project is a separate
integration task and is not a prerequisite for completing the harvester.
OSCAL schema validity alone does not prove compatibility with the existing
Analyzer import.

The new tool is developed independently from the requirements here. Code,
extraction rules, and tests from the previous harvester are not reused. The
files above document only the integration state observed during planning.
Changing or replacing the previous harvester in the main project is outside
this plan.

## Security and operational requirements

Affected assets are wiki credentials, internal content, the local catalog, and
source availability. Trust boundaries lie between operator configuration,
remote pages and links, the parser, and local files.

| ID | Requirement |
| --- | --- |
| RH-S01 | Use HTTPS with certificate and hostname verification; allow a configured internal CA. Provide no option to disable TLS verification. |
| RH-S02 | Check configured origins, ports, path scopes, and allowed destination networks at the actual connection, including IPv6 and DNS changes. Block loopback, link-local, and metadata destinations; allow internal wiki networks only through explicit, narrow configuration. |
| RH-S03 | Recheck the destination scope and addresses on every redirect and limit the hop count. Never forward authentication data or cookies to other origins. URL normalization and path limits must resist traversal and alternative address spellings. |
| RH-S04 | For protected sources, obtain read-only credentials from external configuration or secret management. Configurations contain references, not secret values. Missing required credentials and 401/403 responses produce clear errors; login pages do not count as successful content pages. |
| RH-S05 | Reject URLs with embedded credentials. Do not put tokens in URLs, process arguments, catalogs, or reports; remove sensitive query values from logs and structurally encode untrusted log fields. |
| RH-S06 | Limit page count, link queue, requests, redirects, retries, decompressed bytes, parser work, and runtime. Respect rate limits and Retry-After; prevent endless loops through links or URL variants. |
| RH-S07 | Treat web pages and configuration only as data. Do not execute scripts, embedded instructions, or parser loading functions, and do not fetch unplanned subresources. |
| RH-S08 | Parse only needed content types, considering Content-Type and actual content. Initially exclude PDF, Office, archive, and attachment processing. |
| RH-S09 | Derive local target files from operator configuration, never page titles or remote filenames. Serialize YAML safely, validate output before replacement, and write confidential catalogs with restrictive file permissions. |
| RH-S10 | Do not store complete authenticated pages by default. The tool sends neither content nor credentials to model services. Validate externally created configurations against the same strict schema and allowed values as manual ones; reject unknown fields and executable content. |
| RH-S11 | Give CI jobs minimal, read-only-by-default permissions. Do not run code and configuration from untrusted merge/pull requests with source credentials. Install dependencies using lockfiles and verified integrity values; pin external Actions and containers to immutable references and check dependencies regularly for vulnerabilities. Run containers without root. |

## Acceptance criteria and tests

| ID | Evidence |
| --- | --- |
| RH-A01 | One synthetic source each for table, list, and section structures produces expected entries, including context and source anchors. Examples cover different kinds of requirements and requirements without a category. |
| RH-A02 | Negations, MUST NOT, conditions, examples, non-ASCII characters, multiline statements, and code preserve their meaning; unknown obligation is not guessed. |
| RH-A03 | Unchanged source identities yield stable IDs; link loops and duplicate pages do not create duplicate entries. Conflicting original IDs cause a conflict. |
| RH-A04 | Inclusions/exclusions, path boundaries, depth, and budgets are respected; missing start pages and reached limits do not produce misleading success. |
| RH-A05 | Unknown fields, duplicate YAML keys, executable YAML tags, wrong types, and invalid rules are rejected before network access. |
| RH-A06 | Invalid certificates, out-of-scope redirects, unapproved private or metadata destinations, IPv6 variants, and DNS changes are rejected at the connection boundary. Allowed internal wikis work within their explicit network allowance. |
| RH-A07 | Missing secrets, 401/403 responses, and login pages are detected. Tests with synthetic tokens show that they are absent from logs and outputs and from redirects to other origins. |
| RH-A08 | Oversized and highly compressed responses, large link sets, endless redirects, 429 responses, and timeouts end within configured limits. |
| RH-A09 | YAML export validates against the chosen OSCAL schema and additional semantic rules for IDs, statements, types, and provenance. An intentionally invalid export is rejected. |
| RH-A10 | On fetch, extraction, generation, or validation failure before publication, existing target files remain unchanged; dry runs do not replace catalogs. Publication failures are handled as specified in RH-A16. |
| RH-A12 | A complete scan with saved page fixtures works without model access or an API key. Repeated runs with identical configuration and tool version produce identical semantic results, including IDs and ordering. |
| RH-A13 | Malformed externally created configurations, unknown fields, and executable content are rejected. Links and instructions in pages cannot extend the source scope defined by the validated configuration. Manual and externally generated configurations undergo the same checks. |
| RH-A14 | A layout change produces diagnostics without a model call or automatic configuration change. Rule tests check both expected content and page elements deliberately excluded. |
| RH-A15 | Multiple overlapping start pages, shorter alternative link paths, and link loops yield the expected page set without duplicate fetches. Depths 0, 1, and 2, host scope, path scope, and excluded neighboring paths are tested. Intended depth limits yield a complete run within configured scope; an early resource-budget exhaustion reports incompleteness. |
| RH-A16 | Without splitting, one shared catalog is produced. With multiple configured outputs, each file contains exactly the requirements from its sources and passes OSCAL validation. Unknown or unassigned sources and colliding targets are rejected. A source assigned to multiple outputs is not crawled multiple times. Publication failures are reported as errors with the actual state of each file. |
| RH-A17 | Test the three implemented authentication methods with valid, missing, and rejected credentials. SSO cancellation and session expiry are detected as errors. Sessions and credentials reach neither other sources nor configurations, catalogs, or logs; saved sessions have restrictive access permissions. |
| RH-A18 | A successful subsequent run includes changed and new source requirements, removes requirements no longer present, and does not retain manual additions from old output. Unchanged source identities keep their requirement IDs. A failed fetch must not publish deletion of requirements. |
| RH-A19 | Both CI templates run the noninteractive path with synthetic sources and produce expected exit codes, reports, and valid artifacts. Missing or expired credentials cause no input prompt. Failed runs publish no successful catalog. Job permissions, secret separation from untrusted changes, and artifact access are checked for both platforms. |

Tests use synthetic HTML fixtures and controlled HTTP/DNS test doubles.
Connection protection is tested at the transport boundary; a mock above
destination checking is insufficient evidence. Live tests with real wiki
credentials do not belong in the regular test suite.

## Completed work packages

1. **Clarify sources and export contract:** Select representative pages with
   different structures, access methods, recognition needs, and the exact
   OSCAL version.
2. **Configuration and internal model:** Define the schema, errors, field
   mapping, identities, and synthetic example data.
3. **Fetch and crawl:** Implement HTTPS, access, destination limits, link
   discovery, budgets, and error handling; verify positive and negative cases.
4. **Extraction:** Support the layouts actually needed first; preserve context
   and provenance, and handle duplicates and conflicts.
5. **OSCAL export:** Implement a versioned schema, semantic rules, atomic
   output, and a run report.
6. **CLI and documentation:** Document configuration validation, dry runs,
   status codes, installation, and reproducible invocation examples.
7. **External configuration creation:** Document the schema, representative
   examples, and a workflow for creating, checking, and versioning a
   configuration. The same workflow works manually or with an external assistant.
8. **CI integration:** Add GitLab CI/CD first and GitHub Actions second, with
   noninteractive invocation, secrets, artifacts, and positive and negative tests.

## Outstanding source-specific and operational decisions

| ID | Question | Proposal / impact |
| --- | --- | --- |
| O01 | Which other company pages should be captured? | TSS-WEB is implemented as an example. Other layouts need suitable configurations and semantic review of their dry runs. |
| O02 | Which access method does the particular protected target application support? | Header tokens, HTTP Basic, and Entra bearer tokens are implemented. Tenant, app registration, read permissions, and token acceptance at the source endpoint need on-site verification. Cookie/form adapters are additionally required if that is the access method. |
| O10 | Which private CI projects, runners, and authorized artifact recipients will be used? | The templates document prerequisites and provide locally tested entry points. Hosted pipeline checks occur during setup. |
