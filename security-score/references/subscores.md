# Five security subscores

Use `--score` for five area assessments and an overall qualitative verdict.
This is a separate, versioned scoring policy from the legacy A–F index returned
by direct calls without `--score`. It makes no model calls and runs no target code.

## Criteria and evidence

| Area | Assessed criteria | Important limits |
| --- | --- | --- |
| Architecture & isolation | Declared container/host isolation and wildcard infrastructure privileges; native Kubernetes JSON also resolves container volume mounts to host resources. | Complete trust boundaries and sensitive data flows need a wider design review. |
| Identity & access | Recognized token validation, password hashing, session settings, OAuth choices and SAML validation. | Resource authorization and tenant isolation are not established by these checks. |
| Data & processing | Recognized input-to-execution observations, query construction, deserialization, output binding, cryptography and credential formats. | Unresolved data flows remain review hints. |
| Dependencies & supply chain | Package declarations, integrity and source checks, build/CI permissions and repository controls. | No vulnerability-feed query or runtime integrity verification. |
| Deployment & operations | Recognized transport verification, debug, session-host configuration and infrastructure exposure. | Declarations do not prove deployment or enforcement. |

The `subscore_policy` object in `rules.json` assigns each rule to one criterion
and area, including explicit ownership for overlapping password-hash evidence.
Technology inventories, SSO server names, artifact repository URLs and
positive-only observations do not establish a score.

Each subscore reports its supported criteria and evidence gaps. A positive rating
requires at least two independent recognized control criteria, no unresolved
checks in the area, a complete source selection and the full check catalog.
Repeated evidence for the same criterion cannot satisfy that minimum twice.
This qualifies the **assessed static criteria**, not all application behavior.

The scanner currently cannot complete the trust-boundary/data-flow review or
resource-authorization review. Architecture and Identity therefore remain
unassessed for favorable ratings; a concrete serious weakness in either can
still yield a negative score. An overall favorable verdict is likewise withheld
while these areas are unresolved. This is an explicit capability limit, not a
point deduction or a guess about their security.

An established serious weakness is sufficient for a negative assessment despite
wider evidence gaps. For example, one explicitly disabled certificate-validation
check gives Deployment **59/100 · Bad · limited evidence**, while other areas
can remain **Not assessed**. Incomplete processing is identified separately and
keeps exit status 1. Known findings are never converted into a successful scan.

## Context-sensitive observations

- Python `eval('1 + 1')` establishes no external input and adds no deduction.
  `eval(input())` establishes an interactive-input-to-execution flow and deducts
  as high severity. `eval(payload)` remains a review hint until input trust is known.
- Other unresolved execution, SQL, deserialization and output candidates retain
  their locations as review hints. The static catalog is not a taint analyzer.
- A fixed `theme` cookie with a literal `dark`/`light` value does not establish a
  session-cookie weakness. Other recognized cookie findings remain visible.
- Wildcard credentialed CORS is distinguished from reflected-origin credential
  access: browsers block the wildcard case. It remains a configuration review hint.
- Secret-looking filenames, binary filenames, public-resource declarations and
  absent vendor-specific scanning/update settings alone remain contextual hints.

Raw scanner findings stay in structured output, including the original rule
severity; `review_hints` explains which candidates did not enter the new arithmetic.
These decisions do not change the legacy catalog's detection results.

## Calculation

Each area starts at 100 once sufficient evidence exists. The editable deductions
are low **3**, medium **12**, high **41**, and critical **61**. High severity caps
an area at **59**; critical caps it at **39**. Low and medium have no extra cap.

Detections of the same criterion at the same file and location share one
deduction, even across domains; the most specific owner retains all detector IDs.
For native container design checks, the component JSON pointer is the location,
so multiple ways the same container crosses the host boundary count once.
Locations cannot establish whether two distant observations share a deeper root
cause; such relationships are not silently guessed.

Within one criterion, sort independent locations by severity, then location.
The first deducts its full weight, the second half its weight, the third a third,
and so on. Different criteria add their deductions. Subtract from 100, apply the
strictest severity cap and a floor of zero, then round once to the nearest whole
point, with halves rounded up. Exact rational arithmetic avoids cumulative
rounding differences. `--details` and JSON/YAML show the numerator and divisor
for every contribution.

| Comparison case | Calculated index | Expected relationship |
| --- | ---: | --- |
| One low weakness, with sufficient control evidence | 97 | Small weaknesses do not force an eleven-point drop. |
| One medium weakness, with sufficient control evidence | 88 | No unexplained cap at 79. |
| Two independent medium weaknesses in one criterion | 82 | Fixing either visibly improves the result. |
| One high weakness | 59 | Unrelated strengths cannot yield a favorable verdict. |
| Two independent high weaknesses in one criterion | 39 | Broader repetition worsens the assessment. |
| Three / four independent high weaknesses in one criterion | 25 / 15 | Contributions continue beyond three occurrences. |
| PY-TLS and PY-TLS-CONTEXT on one assignment | 59 | Overlapping detections count once. |
| One high weakness in each of two areas | Both 59 | Both affected areas remain visible, without a numeric average. |

These are documented, example-calibrated policy values, not measured attack
probabilities or an empirically validated risk scale. A numeric index is withheld
when its evidence gate is unmet; the available deductions and findings remain
in details. Fixes cannot increase deductions, and additional satisfied checks
cannot cancel them.

| Points | Rating |
| --- | --- |
| 90–100 | Very good |
| 80–89 | Good |
| 70–79 | OK |
| 60–69 | Needs improvement |
| 50–59 | Bad |
| 0–49 | Very bad |

The overall verdict takes the worst supported negative rating, with its main
reason. A favorable overall verdict requires sufficient evidence in all five
areas. There is no sixth numeric score. Coverage never changes point weights.

## Architecture inspection

Beyond existing explicit privilege findings, the design check reads native JSON
Pod, Deployment, StatefulSet, DaemonSet and Job specifications. It follows each
container's volumeMount references to declared hostPath volumes. Privileged
containers, shared host process/IPC namespaces, or a mounted host root or runtime
control socket establish an isolation weakness. An unused hostPath volume does not.
Explicit non-root identity, disabled escalation, non-privileged execution and
dropped capabilities establish bounded positive isolation evidence, not a complete
architecture grade. Malformed values, duplicate JSON keys and unresolved references
never establish positive evidence. Other formats retain their narrower existing
pattern observations.

Check selection is honored: custom `--checks`/`--skip-checks` scans do not add the
supplemental design inspection, cannot establish favorable subscores, and identify
their reduced scope. `coverage.design_checks` identifies supplemental inspections.

## SSO and artifact endpoints

Detailed output and structured results preserve SSO issuer, authorization, token
and JWKS paths, including Keycloak realms. Supported configuration includes the
existing JS/Python integrations and metadata, Keycloak adapter JSON, Spring OAuth2
client and resource-server YAML/properties, and Quarkus OIDC properties.
Unresolved environment expressions remain unresolved; the scanner does not read
process credentials, contact discovery endpoints or infer active deployment.

Artifact observations cover Maven repository/plugin/mirror URLs with one literal
same-file property substitution, Gradle Maven/Ivy repository blocks, selected
Python index/source declarations, and npm lockfile resolutions. Paths such as
`/repository/releases/` and `/artifactory/libs/` are preserved. Product labels are
explicitly “compatible” indications, not verified server identities. Lockfile
URLs identify the repository endpoint, not every package archive. Ambiguous
duplicate URL declarations are not treated as resolved configuration.

URLs omit userinfo, query strings and fragments. Credential-bearing or ambiguous
URLs retain only the origin; useful literal paths remain for ordinary endpoints.
Sensitive files such as `.npmrc` are not read; their presence is reported as an
endpoint-profile gap. These observations never change scores merely because a
particular service or product is present.

## Cloud and supply-chain profiles

Terraform HCL and `.tf.json` profiles identify AWS, Azure, GCP, Kubernetes and Helm
providers, literal regions/locations, resource roles and selected direct security
attributes. These include public access, encryption, HTTPS-only settings, deletion
protection and public-access blocking. State backends report their type and explicit
encryption/locking declarations. Network and IAM wildcard observations require
effective-policy context. Comments, tags and quoted examples do not establish these
properties; duplicate or dynamic values remain unresolved. No state, credentials,
Terraform evaluation or cloud API is accessed. HCL property windows are limited
to 200 lines/40,000 characters. Both formats use the source-size limit and a
1,000-block limit per selected file.

Dependency profiles distinguish these controls:

| Ecosystem | Recognized evidence | Limits |
| --- | --- | --- |
| Node.js | npm manifest/workspace declarations versus lock entries; resolved stable exact/caret/tilde versions; well-formed registry SHA integrity; matching `npm ci`; declared lifecycle scripts. | Other version expressions and Yarn/pnpm lock contents remain unresolved. Hash declarations are not downloaded-artifact verification. |
| Python | Exact requirements pins, SHA-256/SHA-512 hash declarations, and hash-enforced pip installation referencing the assessed requirements. | Includes/dynamic inputs and uv/Poetry/Pipenv lock contents remain unresolved. `uv sync --locked`/`--frozen` is recognized as a declaration when its lockfile exists, without asserting lock integrity. |

Positive supply-chain evidence requires both recognized artifact integrity and an
applicable locked-install declaration. Inconsistent npm manifests/resolved versions
produce a medium finding; merely missing evidence does not. Profile observations
replace the corresponding legacy pattern-based positive criteria in `--score`.
Existing catalog checks still cover source choices, CI permissions, update settings
and other recognized build controls. This is not a dependency vulnerability scan,
provenance verification or a review of dependency lifecycle-script behavior.

Install recognition is deliberately bounded to direct commands in selected CI or
container-build sources. Printed commands, help/dry-run options, disabled enforcement
and mismatching project/requirements paths do not establish it. Conditional jobs,
alternate working directories, compound-command setup and wrapper executables remain
unresolved. The profile cannot prove that a pipeline ran or that all production
builds use it. Sensitive package configuration remains unread as described above.

## CLI and compatibility

```sh
security-score /selected/repository --score
security-score /selected/repository --score --details
security-score /selected/repository --score --json
security-score /selected/repository --score --yaml
```

`--score` supports internal repository scans only. It cannot be combined with
change selection, Analyzer, `--quiet`, or rule-listing operations. Existing direct
calls without `--score`, including legacy JSON/quiet output and change relevance,
retain their interface. The new structured result uses `analysis:
security-assessment`, `scoring_policy: five-subscores`, `subscores` and `overall`;
legacy top-level score, grade, observed index and area indices are absent.

Exit 0 means sufficient evidence for all five areas, 2 means limited assessment
or invalid arguments, 1 means incomplete processing or operational failure, and
130 means cancellation. A negative verdict can coexist with exit 2; these are
completion statuses, not CI pass/fail gates.
