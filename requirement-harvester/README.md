# Requirement Harvester

Reads requirements from websites and wikis and writes them to an
[OSCAL](https://pages.nist.gov/OSCAL/) 1.2.3 catalog in YAML. A configuration
file sets which pages are read and how requirements are recognized on them.
Runs are deterministic and need no LLM.

Requires Python 3.12+ on Linux or macOS, `pipx`, and Git. Installation uses
HTTPS; public repositories need no GitHub account or SSH key.

## Quick start

Install from a clone, which also contains the example configurations:

```sh
git clone https://github.com/appsec-foundry/appsec-tools.git
cd appsec-tools/requirement-harvester
pipx install .
```

Read the public TSS-WEB example. `validate` checks the configuration without
network access, `run --dry-run` fetches and extracts but writes only the run
report, and `run` also writes the catalog:

```console
$ requirement-harvester validate --config examples/tss-web.yaml
Configuration valid; no network access made.
$ requirement-harvester run --config examples/tss-web.yaml --dry-run
{"status": "complete", "requirements": 116, "catalogs": 1, "dry-run": true}
$ requirement-harvester run --config examples/tss-web.yaml
{"status": "complete", "requirements": 116, "catalogs": 1, "dry-run": false}
```

The catalog is written to `out/tss-web.oscal.yaml`, the run report to
`out/tss-web-report.json`. Output paths are set in the configuration and are
relative to the configuration file. A successful run replaces the previous
catalog. A failed run prints the error and exit code, leaves the catalog
unchanged, and records the error in the report.

To install without a clone:

```sh
pipx install "git+https://github.com/appsec-foundry/appsec-tools.git#subdirectory=requirement-harvester"
```

## Configure your own source

1. Copy the example closest to your pages:
   - [lists.yaml](examples/lists.yaml): one requirement per list item
   - [sections.yaml](examples/sections.yaml): a heading with its following text
   - [table.yaml](examples/table.yaml): one requirement per table row
   - [token.yaml](examples/token.yaml): protected source with an API token
   - [entra-ci.yaml](examples/entra-ci.yaml): Microsoft Entra ID in CI
   - [multiple-outputs.yaml](examples/multiple-outputs.yaml): several catalogs
   - [owasp-cheatsheets.yaml](examples/owasp-cheatsheets.yaml): OWASP Cheat
     Sheet Series, one entry per section; see the notes in the file
2. Set the start pages, the allowed scope, and the CSS selectors.
3. Run `validate`, then `run --dry-run`, and check the found entries and the
   page list in the report against your pages.
4. Run `run` and keep the reviewed configuration under version control.

A minimal configuration for requirements in list items:

```yaml
config-version: 1
output:
  catalog: out/requirements.oscal.yaml
  report: out/report.json
  title: Company Requirements
  version: 1.0.0
sources:
- id: company
  title: Company Requirements
  start-urls:
  - https://wiki.example.org/requirements/engineering
  crawl:
    allowed-origins: [https://wiki.example.org]
    allowed-path-prefixes: [/requirements/]
    max-depth: 2
  auth:
    mode: none
  extraction:
    content-selector: main
    rules:
    - id: list-items
      strategy: blocks
      item-selector: ul.requirements > li
      fields:
        original-id: {attribute: id}
        statement: {}
```

If an assistant writes the configuration for you, check the start pages and
the allowed scope before the first run.

## Output

Each source becomes an OSCAL group and each requirement a control with its
statement, source URL, and original ID. The catalog is checked against the
official NIST schema before it is written. Shortened example:

```yaml
catalog:
  metadata:
    title: Company Requirements
    version: 1.0.0
    oscal-version: 1.2.3
  groups:
  - id: company
    title: Company Requirements
    controls:
    - id: company-3f9a2c41d07e8b56a1c4e2d9
      title: Encryption at rest
      links:
      - href: https://wiki.example.org/requirements/engineering#encryption-at-rest
        rel: reference
      parts:
      - name: statement
        prose: Confidential data MUST be encrypted before it is stored.
```

OSCAL YAML is the only output format. appsec-analyzer reads its own
requirements catalog format, not OSCAL, so it cannot import this catalog
directly yet ([details](requirements.md#integration-with-appsec-analyzer)).

## Limits

- Reads static HTML over HTTPS. JavaScript rendering, PDFs, and attachments are
  not supported.
- HTTP proxies are not used; the machine needs direct HTTPS access to the
  sources.
- Access: public, API token, HTTP Basic, and Microsoft Entra ID bearer tokens.
  Form logins need an adapter for the target application.
- Obligation comes only from a configured field. The tool does not derive MUST,
  SHOULD, or MAY from the text.

## Further documentation

- [Reference](docs/reference.md): configuration, extraction rules,
  authentication, output, and exit codes
- [CI templates](ci/README.md) for GitLab CI/CD and GitHub Actions
- [Configuration schema](harvester/schemas/config.schema.json)
- [Requirements and decisions](requirements.md)
