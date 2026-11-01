# appsec-analyzer-tools

Small command-line tools that go with
[appsec-analyzer](https://github.com/appsec-foundry/appsec-analyzer). Each tool
lives in its own directory and is installed and used on its own. The core
application is developed in the appsec-analyzer repository.

All tools need Python 3.10 or newer, `pipx`, and Git with SSH access to GitHub.

## Security Score

Scans a repository and gives it a security score from 0 to 100 and a grade from
A to F. It also rates how security-relevant a single change is. The checks are
fixed rules; no LLM is involved. The scanned code is never run.

```console
$ security-score /path/to/repository
59/100 (E)
```

Works on a local directory or a GitHub/GitLab URL. `--details` shows what was
found, per topic and with file and line.

[Read more](security-score/README.md)

## Requirement Harvester

Reads security requirements from websites and wikis and writes them to an
[OSCAL](https://pages.nist.gov/OSCAL/) catalog in YAML. A configuration file
says which pages to read and how requirements are recognized on them. No LLM is
involved.

```console
$ requirement-harvester run --config examples/tss-web.yaml
{"status": "complete", "requirements": 116, "catalogs": 1, "dry-run": false}
```

appsec-analyzer cannot import the OSCAL catalog directly yet.

[Read more](requirement-harvester/README.md)
