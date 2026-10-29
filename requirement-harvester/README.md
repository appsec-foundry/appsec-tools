# Requirement Harvester

Reads requirements from configured websites and wikis and writes an OSCAL YAML
catalog. Requires Python 3.10+ on Linux or macOS.

## Installation

With `pipx`, Git, and SSH access to the GitHub repository:

```sh
pipx install "git+ssh://git@github.com/appsec-foundry/appsec-analyzer-tools.git#subdirectory=requirement-harvester"
```

No local clone is needed. From an existing clone, you can instead run
`pipx install ./requirement-harvester` at the repository root.

## Run

Save an [example configuration](examples/lists.yaml) as `my-config.yaml` and
adjust its URLs and selectors. For public sources, see the examples for
[TSS-WEB](examples/tss-web.yaml) and the
[OWASP Cheat Sheet Series](examples/owasp-cheatsheets.yaml). `pipx` does not
install the example files; copy them from the repository.

```sh
requirement-harvester validate --config my-config.yaml
requirement-harvester run --config my-config.yaml
```

`validate` checks the configuration without fetching pages. To preview a run,
add `--dry-run`; this writes a preview report but no catalog. Output paths are
set in the configuration and resolved relative to that file. A successful run
replaces the output files.

### OWASP Cheat Sheet Series

`examples/owasp-cheatsheets.yaml` reads all cheat sheets from
`cheatsheetseries.owasp.org` and creates one entry per section. Cheat sheets
are recommendations, so the entries have no obligation level. The content is
licensed under CC BY-SA; keep the source URLs when you pass the catalog on.
A full crawl has not been tested yet.

## Input and output

Input is static HTML pages (HTTPS only). The output is an
[OSCAL](https://pages.nist.gov/OSCAL/) 1.2.3 catalog in YAML, checked against
the official NIST schema before it is written. Each source becomes a group and
each requirement a control with its statement, source URL, and original ID.
Details are in [docs/reference.md](docs/reference.md#output-and-oscal).

Other output formats are not supported, including the appsec-analyzer catalog
format.

## CI and reference

The [GitLab and GitHub templates](ci/README.md) use a local virtual
environment and locked dependencies. Put credentials in protected CI
variables.

- [Configuration, authentication, and exit codes](docs/reference.md)
- [Configuration schema](harvester/schemas/config.schema.json)
- [Requirements](requirements.md)

Supports static HTML, API tokens, HTTP Basic, and Entra bearer tokens.
JavaScript rendering, PDFs, and form logins are not supported.
