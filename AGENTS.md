# Working rules for coding agents

## Repository purpose

This repository is the central collection of supplementary tools for
[appsec-analyzer](https://github.com/appsec-foundry/appsec-analyzer).
Develop utilities and integrations here; changes to the core application
belong in the main repository.

## Current state

The repository contains two standalone Python tools (Python >=3.10). Run
tests in the tool directory:

- `requirement-harvester/`: local lockfiles and pytest;
  `.venv/bin/python -m pytest`.
- `security-score/`: no runtime dependencies, unittest;
  `python3 -B -m unittest test_security_score -v`.

Each tool's README describes installation, the CLI, and further checks.
Do not infer features or interfaces of the main project from the repository
name; verify them before implementing anything that depends on them.

## Structure and implementation

- Put each new tool in its own directory at the repository root.
- Keep tools independently usable and their dependencies local to each tool.
- Choose a language and runtime appropriate to the task and existing patterns.
- Introduce shared libraries or frameworks only when there is a concrete need.
- Limit changes to the requested task.

## Documentation

- Maintain repository documentation in English unless requested otherwise.
- Give each tool its own `README.md` covering purpose, prerequisites,
  installation, configuration, a usage example, and inputs/outputs.
- State relevant compatibility requirements for appsec-analyzer explicitly.
- Add a linked entry to the central README when a tool exists.
- Mark planned features as planned; do not document unverified commands or
  interfaces as working.
- Start each README with what the tool does and a quick start with real
  commands and output. Write plainly and briefly; put details in reference
  docs instead of repeating caveats.

## Requirements

Each tool has a `requirements.md` with its purpose, scope, agreed decisions,
and the functional and security requirements that later work must respect.

- Add or change a requirement only for significant changes: a new capability,
  a changed scope or interface contract (CLI, configuration, output format,
  exit codes), a security boundary, or a decision later work must follow.
- Bug fixes, output layout, wording, refactoring, and new tests need no
  requirement. Document user-visible behavior in the README or reference
  docs; tests pin the details.
- Write one to three sentences per requirement: what must hold and, if not
  obvious, why. Leave out implementation details, implementation status, test
  results, and change history.
- Keep requirement IDs stable. Do not renumber or reuse them; code and tests
  may reference them.

## Verification and handoff

- Add suitable tests for functional changes and use the affected tool's existing
  verification tools.
- Use synthetic or sanitized data for examples and tests; do not put
  credentials or confidential analysis results in the repository.
- Review the diff before handing off and keep documentation consistent with
  the actual implementation.
- At handoff, state the changes, checks performed, and remaining limitations.
  Do not claim a check succeeded if it was not run.
