# Security subscores

Repository scans show one overall score and plain-language rating by default.
`--details` shows the tool version and six area assessments with colored bars.
This is a separate, versioned scoring policy from the legacy A–F index returned
with `--legacy-score`. It makes no model calls and runs no target code.

## Criteria and evidence

| Area | Assessed criteria | Important limits |
| --- | --- | --- |
| Architecture & isolation | Supported request-to-database boundaries and declared container/host isolation or infrastructure privileges; native Kubernetes JSON resolves host mounts. | Only supported static criteria are scored; wider data flows, tenancy and deployed enforcement remain unverified. |
| Identity & access | Recognized token validation, password hashing, session settings, OAuth choices and SAML validation. | Resource authorization and tenant isolation are not established by these checks. |
| Data & processing | Recognized input-to-execution observations, query construction, deserialization, output binding, cryptography and credential formats. | Unresolved data flows remain review hints. |
| Dependencies & supply chain | Package declarations, integrity and source checks, build/CI permissions and repository controls. | No vulnerability-feed query or runtime integrity verification. |
| Deployment & operations | Recognized transport verification, debug, session-host configuration and infrastructure exposure. | Declarations do not prove deployment or enforcement. |
| AI & agents | Model output reaching code, shell, SQL or HTML sinks, schema validation of structured output, and committed MCP and agent configuration. | Flows stay within one file and scope; tool arguments, prompt injection and retrieval trust need design review. |

The `subscore_policy` object in `rules.json` assigns each rule to one criterion
and area, including explicit ownership for overlapping password-hash evidence
and `location_owners` for specific findings that own generic ones at the same
location.
Technology inventories, SSO server names, artifact repository URLs and
positive-only observations do not establish a score.

Each subscore reports its supported criteria and evidence gaps. A positive rating
requires at least two independent recognized control criteria, no unresolved
checks in the area, a complete source selection and the full check catalog.
Repeated evidence for the same criterion cannot satisfy that minimum twice.
This qualifies the **assessed static criteria**, not all application behavior.

Since subscore policy version 2, Architecture is scored automatically for supported
static criteria. The absence of a complete manual architecture review is recorded
under `limitations`, not added as a permanently failing evidence gate. Explicit
container isolation and privilege restrictions are independent control criteria.
Positive scores still require sufficient evidence, complete processing and no
unresolved applicable checks. A concrete serious architecture weakness can
establish a negative score despite wider gaps. Identity still requires wider
resource-authorization evidence for a favorable rating; overall coverage remains
separate from the numeric assessment.

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
  their locations as review hints. The supported boundary patterns below are
  deliberately narrower than general whole-program taint analysis.
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
rounding differences. `--details` summarizes grouped point deductions. JSON/YAML retain the numerator
and divisor for every contribution.

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
reason. A favorable overall verdict requires sufficient evidence in all applicable
areas. Compact text shows the lowest assessed subscore as the overall number
only when the overall evidence gate is met, for example `59/100 (Bad)`. This is
a minimum, not an average or another independently calculated score. Coverage
never changes point weights.

## AI & agents

The area applies when an AI SDK import or declaration, a model call, a supported
LLM configuration declaration or parseable committed agent or MCP configuration
is recognized. Otherwise it shows **Not
applicable**, carries `applicable: false` in JSON/YAML and does not affect the
overall verdict. Incomplete processing, a check subset or unresolved source
coverage never establish absence; the area is then Not assessed.

| Rule | Severity | Violated by | Satisfied by |
| --- | --- | --- | --- |
| `AI-OUTPUT-EXEC` | high | Model output in `eval`, `exec`, `new Function`, shell commands or SQL text | Model output only as a bound SQL parameter |
| `AI-OUTPUT-HTML` | high | Model output in `innerHTML`, `document.write`, `dangerouslySetInnerHTML`, `Markup`, `mark_safe` and similar sinks | Sanitizer around every model value, text sinks, escaping |
| `AI-OUTPUT-PARSE` | medium | JSON parsed from model output without a schema validator in the same scope | Pydantic, zod, ajv or jsonschema validation; SDK calls with a schema |
| `AI-CLIENT-MESSAGES` | medium | Request data passed as `messages`, `contents` or `history` to a model call, so the client can add system, assistant or tool turns | Request data only as `content` with roles set by the server |
| `AI-MCP-CREDENTIAL` | high | Literal credential in MCP `env`, `headers` or arguments | Environment reference such as `${TOKEN}` |
| `AI-MCP-SOURCE` | medium | `npx`, `uvx`, `pipx`, `pnpm dlx` and similar without an exact version | Exact version or Git commit |
| `AI-MCP-TRANSPORT` | high | Remote `http`/`ws` server URL | `https`/`wss` |
| `AI-AGENT-BYPASS` | high | Claude Code `bypassPermissions`, Gemini CLI `autoAccept`, MCP `trust: true` | `disableBypassPermissionsMode: "disable"` |
| `AI-AGENT-AUTO-APPROVE` | medium | `enableAllProjectMcpServers: true`, `autoApprove`/`alwaysAllow` lists | — |
| `AI-AGENT-PERMISSIONS` | high | Allow rules for unrestricted `Bash`, wildcard high-risk commands, or `Write`/`Edit` on any or credential paths | — |
| `AI-AGENT-SANDBOX` | medium | Pre-approved tools beyond read access without a sandbox | Enabled sandbox |

`AI-INTEGRATION` is a positive-only inventory rule: it makes the area applicable
and never earns credit. Its locations name SDK imports, provider API families,
model calls, declared models, selected call options and model-callable tools
(AI SDK `tool()`, MCP `server.tool()`, Python `@tool` decorators and function-tool
definitions). `--details` shows a compact AI profile: distinct model declarations,
API/endpoint classes, explicit token/step limits, tools and tool policies.
Locations, SDK imports, model calls, sampling, retries and unresolved options stay
in JSON/YAML. If no literal model is recognized, text shows `Model: not resolved`;
a recognized configuration declaration does not resolve dynamic model selection.
Provider families come
from imports and do not identify the service behind a configurable endpoint.
Literal model options and supported provider factories/constructors are recognized;
variable aliases, imported settings and dynamic expressions stay unresolved.
Direct environment/config references name the reference without reading its value.
Call options cover temperature/top-p, output token limits, tool choice, parallel
tool calls, streaming, retries and step limits, including `stepCountIs(n)`.
Missing settings produce neither findings nor control evidence.

JSON/YAML files under `config/` or `configs/` also contribute selected declarations
directly inside `llm`, `chatBot`, `openai`, `anthropic` and `ollama` mappings.
Model identifiers and endpoint classes (loopback/non-loopback, HTTP/HTTPS) are
shown; endpoint URLs, credentials, query strings and prompts are omitted.
YAML evidence uses field lines; JSON evidence locates the document at line 1.
Unsupported YAML, duplicate values and interpolation remain unresolved or
unrecognized; tags and aliases are never executed. Configuration files are not
merged, and neither the active model nor runtime locality is verified.
Configuration-only model evidence makes the area applicable but earns no credit.

Request data means `req.body`, `req.query`, `request.json()` and similar
request objects, plus parameters of Python route functions except injected
dependencies. Model output is followed only in Python and
JavaScript/TypeScript files that import an AI SDK, from the assignment of a
recognized model call through further assignments and loops within the same
function or block. A value passed to another function or file is not followed.
Configuration files with duplicate keys or comments are unresolved.

When model output reaches `eval()`, the specific `AI-OUTPUT-EXEC` finding owns
the generic `JS-EVAL` or `PY-EXEC` candidate at the same location and deducts
once; `AI-MCP-CREDENTIAL` likewise owns `SECRET-TOKEN` in MCP configuration.
`location_owners` in `rules.json` lists these pairs. A positive AI rating needs
two independent satisfied criteria, for example an enabled agent sandbox and
model output written to a text sink.

Not yet assessed: tool arguments chosen by the model, model-selected URLs and
file paths, prompt construction, retrieval and memory, MCP server code, TOML and
YAML agent settings, VS Code `settings.json`, and Markdown instruction files.

## Architecture inspection

Beyond existing explicit privilege findings, the design check reads native JSON
Pod, Deployment, StatefulSet, DaemonSet and Job specifications. It follows each
container's volumeMount references to declared hostPath volumes. Privileged
containers, shared host process/IPC/network namespaces, or a mounted host root or runtime
control socket establish an isolation weakness. An unused hostPath volume does not.
Explicit non-root identity, disabled escalation, non-privileged execution and
dropped capabilities establish independent declared isolation and privilege
criteria. Other host-path mounts retain a review gap rather than establishing
positive isolation. A positive score qualifies these supported static criteria,
not a complete architecture review. Malformed values, duplicate JSON keys and unresolved references
never establish positive evidence. Other formats retain their narrower existing
pattern observations.

Check selection is honored: custom `--checks`/`--skip-checks` scans do not add the
supplemental design inspection, cannot establish favorable subscores, and identify
their reduced scope. `coverage.design_checks` identifies supplemental inspections.

## Automatic data-access boundaries

Results from subscore policies 1 and 2 are not directly comparable: version 2
adds supported automatic architecture controls and request-to-database findings.
Policy version 2 adds `DESIGN-DATA-BOUNDARY` evidence for complete TypeScript
sources with Express `Request` parameters and recognized named Sequelize/pg query
receivers. The inspector follows one selected relative database export, including
a simple constructor factory and typed setter, and one unchanged local value
alias. Source code is never imported or executed, and unselected modules are not
read. Comments, strings, unrelated query methods, shadowed bindings, patch
fragments and malformed lexical/bracket context cannot establish protection.

Direct request-field interpolation or concatenation into SQL is a high-severity
architecture finding. Literal SQL with explicit parameter binding is positive
query-boundary evidence. Unknown transformations and preceding local guards stay
reviewable; control-flow feasibility, external middleware and arbitrary helper
sanitizers are outside this bounded analysis. A finding describes the observed
unsafe construction, not verified exploitability. A constant query without a
request data flow earns no boundary credit.

Generic JS-SQL evidence and the resolved boundary at the same file/line share one
owner and one deduction. `boundary_evidence` retains source, query and database
locations without source snippets or request values. Incomplete source coverage
still blocks favorable ratings, while recognized serious weaknesses remain rated.
Custom check subsets do not run supplemental boundary or container inspection.
The implementation reuses the scanner's source/budget limits and 4 KiB expression
windows; arbitrary call chains and nested callback flows remain outside scope.

| Example | Architecture result | Meaning |
| --- | ---: | --- |
| One direct HTTP input embedded in SQL | 59 (Bad) | A concrete data-access boundary weakness is sufficient for a negative assessment. |
| Two independent unsafe request-to-query locations | 39 (Very bad) | Both locations contribute; generic SQL detections are not counted again. |
| One parameter-bound HTTP query | Not assessed alone | One supported criterion cannot establish a complete positive basis. |
| Explicit independent container isolation and privilege restrictions | 100 for supported static criteria | Wider architecture limitations remain separate and visible in structured output. |
| Framework/database inventory alone | Not assessed | Presence is not control evidence. |

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

Compose profiles appear under **Deployment & operations**, independently of its
score, and in JSON/YAML at `architecture.compose`. Each service reports declared
image references and SHA-256 digest pinning; short/long port and mount syntax;
network names and host namespaces; user, privileged mode, capability additions and
drops, selected security options and Docker socket mounts; read-only filesystems;
CPU, memory and PID limits; healthcheck presence/disablement and restart settings.
Supported `deploy.resources.limits` and restart conditions are declarations only.
Each property includes its source line. Values, commands and contents from environment,
secrets, labels, build arguments and healthcheck commands are omitted.

The dependency-free reader supports block YAML maps and sequences, simple scalar
flow lists and JSON flow values. Other flow YAML, YAML tags, aliases, anchors,
merges, interpolation, includes and `extends` remain unresolved; block scalar
contents are skipped. Files are never merged or evaluated. Duplicate keys do not
establish a value. Missing means not declared in that file, including for overrides;
it is neither a finding nor proof of a default or deployed control. Unavailable or
partial files and reader limits appear as profile gaps. Existing container findings
remain separate; profile presence alone never changes a score or completion status.
The reader uses the existing selected source and scan budgets, with at most 20,000
lines, 32 indentation levels, 100 services per file and 100 entries per selected
list. Details show at most three services with recognized settings or unresolved
evidence. Since 0.3.2, absent fields and services without such evidence are omitted
from text; parser gaps and unresolved declared values remain visible. JSON/YAML
keep all captured services.
Profiles require tool version 0.3.1 or later.

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
security-score /selected/repository
security-score /selected/repository --details
security-score /selected/repository --json
security-score /selected/repository --yaml
```

The default assessment supports internal repository scans. Compact text contains
only `score/100 (plain-language rating)`, or `Not assessed` when the overall
evidence gate is unmet. `--details` adds the tool version and colored bars,
with up to three grouped finding types per area, readable architecture and
dependency-check outcomes and one coverage summary;
Internal criterion IDs, unresolved-check lists and formula traces remain in
JSON/YAML, which retain every occurrence, deduction and gap. `--score` remains a
compatible alias; it cannot be combined with change selection, Analyzer,
`--quiet`, or rule-listing operations. Use `--legacy-score` for the previous text
or structured single-score result. Numeric `--quiet`, change relevance and
explicit Analyzer requests retain their interfaces. The structured result uses `analysis:
security-assessment`, `scoring_policy: area-subscores` (named `five-subscores`
before subscore policy version 3), `subscores` and `overall`;
legacy top-level score, grade, observed index and area indices are absent.

Exit 0 means sufficient evidence for all applicable areas, 2 means limited assessment
or invalid arguments, 1 means incomplete processing or operational failure, and
130 means cancellation. A negative verdict can coexist with exit 2; these are
completion statuses, not CI pass/fail gates.
