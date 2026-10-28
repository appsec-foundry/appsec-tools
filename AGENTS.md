# Working rules for coding agents

## Repository purpose

This repository is the central collection of supplementary tools for
[appsec-analyzer](https://github.com/appsec-foundry/appsec-analyzer).
Develop utilities and integrations here; changes to the core application
belong in the main repository.

## Current state

The first tool is the standalone Python Requirement Harvester in
`requirement-harvester/`. It uses Python >=3.10, local lockfiles, and
pytest. Run tests in the tool directory with `.venv/bin/python -m pytest`.
The README describes installation, the CLI, and CI templates.
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

## Verification and handoff

- Add suitable tests for functional changes and use the affected tool's existing
  verification tools.
- Use synthetic or sanitized data for examples and tests; do not put
  credentials or confidential analysis results in the repository.
- Review the diff before handing off and keep documentation consistent with
  the actual implementation.
- At handoff, state the changes, checks performed, and remaining limitations.
  Do not claim a check succeeded if it was not run.
