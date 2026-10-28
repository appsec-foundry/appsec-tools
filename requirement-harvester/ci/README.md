# CI setup

Both templates run the same CLI as local runs. GitLab was the first integration;
GitHub Actions is provided as an equivalent template. The templates were tested
locally for structure and with the real CI entry point against synthetic sources;
hosted pipeline runs were not started.

## GitLab CI/CD

1. Adopt `ci/gitlab-ci.yml` as the project pipeline or include it with `include:local`.
2. Provide a dedicated shell runner tagged `python-nonroot` with Python >=3.10,
   `venv`, write access to the job directory, and execution without root. Production
   crawl jobs need a protected runner; untrusted projects must not share it.
3. Keep the project private and the default branch protected. Configure a schedule
   or manually triggered web pipeline on that branch.
4. Store credentials as masked and protected CI variables with environment scope
   `requirement-harvest`. This keeps source credentials out of verification jobs
   and unrelated merge-request pipelines. Keep job-token permissions read-only.
5. Replace `examples/tss-web.yaml` in the harvest job with the approved company
   configuration. Public test sources need no credentials.

Catalogs and reports remain available for 7 days, with access limited to
maintainers. The template uses `artifacts:access`; the deployed GitLab version
must support `maintainer`. See [GitLab artifact access](https://docs.gitlab.com/ci/jobs/job_artifacts/#control-who-can-download-artifacts).

## GitHub Actions

1. Copy `ci/github-actions.yml` to `.github/workflows/requirement-harvester.yml`.
2. Use a private repository and the `requirement-harvest` environment. Restrict
   the environment to the protected default branch.
3. Set the required environment secrets: `HARVEST_TOKEN`, `HARVEST_USERNAME`,
   `HARVEST_PASSWORD`, or `ENTRA_CLIENT_SECRET`. Only the selected authentication
   method needs its values. Do not provide secrets to the verification job.
4. Adjust the configuration in the harvest step. Run the workflow manually or
   on the included weekly schedule; cron times are UTC.
5. Use an appropriate private runner for company pages that are not publicly
   reachable. It must support current Actions runner versions and the runtime
   required by the selected Actions.

The template uses `contents: read`, no PR trigger for crawling,
`persist-credentials: false`, and 7-day artifact retention. Artifacts are
available to people with read access to the private repository. Those recipients
must be authorized for the contained requirements. See
[GitHub: Secure use](https://docs.github.com/en/actions/reference/security/secure-use).

The two Actions are pinned to signed release commits verified through the
official GitHub API (as of 2026-10-28):

| Action | Version | Commit |
| --- | --- | --- |
| `actions/checkout` | v7.0.1 | `3d3c42e5aac5ba805825da76410c181273ba90b1` |
| `actions/upload-artifact` | v7.0.2 | `cf430e030ddbb5b0abf93d22962f4752f3646cd9` |

## Artifacts and errors

`scripts/ci_run.py` creates a fresh `ci-artifacts` directory. If it already
exists, the job fails. Successful catalogs are copied into the artifact directory
together only after the entire CLI run succeeds. On failure, only an error report
is provided; detailed controlled diagnostics are also available in the job log.
Old catalogs from `out/` are not copied.

Use a fresh working directory when rerunning this helper locally. Credentials,
session files, and complete HTML pages are not job artifacts. The templates do
not share caches for run data.

## Entra ID and network access

CI cannot complete an interactive browser login or MFA dialog. For Entra ID, the
target application needs approved client-credentials access with appropriate
application read permissions. A personal browser session is not durable pipeline
access. Without a supported machine-to-machine access path, the job ends with an
authentication error.

Runners need direct HTTPS access to source hosts and, for Entra, to
`login.microsoftonline.com`. Installation and the dependency check need PyPI;
the scan itself downloads neither packages nor OSCAL schemas. Internal networks
and CA certificates are allowed in the source configuration. TLS verification
remains enabled.
