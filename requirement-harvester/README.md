# Requirement Harvester

Reads requirements from configured websites and wikis and writes an OSCAL YAML catalog. Requires Python 3.10+ on Linux or macOS.

## Quick start

With `pipx` installed, run from the repository root:

```sh
pipx install ./requirement-harvester
requirement-harvester validate --config requirement-harvester/examples/tss-web.yaml
requirement-harvester run --config requirement-harvester/examples/tss-web.yaml
```

This run reads public TSS-WEB pages. The catalog and report are written to `requirement-harvester/out/`; the number of requirements depends on the current page content.

## Your own source

Copy an [example configuration](examples/lists.yaml) and adjust its URLs and selectors. Paths in the configuration are relative to the configuration file.

```sh
requirement-harvester validate --config my-config.yaml
requirement-harvester run --config my-config.yaml --dry-run
requirement-harvester run --config my-config.yaml
```

`validate` does not fetch pages. `--dry-run` writes a preview report but no catalog. A successful run replaces the output files.

## CI and reference

The [GitLab and GitHub templates](ci/README.md) use a local virtual environment and locked dependencies. Put credentials in protected CI variables.

- [Configuration, authentication, and exit codes](docs/reference.md)
- [Configuration schema](harvester/schemas/config.schema.json)
- [Requirements](requirements.md)

Supports static HTML, API tokens, HTTP Basic, and Entra bearer tokens. JavaScript rendering, PDFs, and form logins are not supported.
