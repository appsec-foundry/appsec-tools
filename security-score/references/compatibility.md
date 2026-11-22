# Engines and compatibility

Security Score has two engines. The internal engine runs by default. The Analyzer engine is optional and runs only when you pass `--engine analyzer`.

| Engine | What it returns | What it needs |
| --- | --- | --- |
| Internal | Repository score, or security relevance for changes | Python 3.12+; Git for local comparisons; no extra Python packages |
| Analyzer | Repository score only | A separately installed, compatible AppSec Analyzer |

The engines use different scoring policies. Do not compare their numbers as if they measured the same thing. Internal scoring version 2 counts each finding at its full weight; version 1 used a logarithmic formula for repeated findings. Compare internal scores only when their scoring versions and coverage match.

## Using the Analyzer engine

Select an installed executable on your `PATH`, or specify its absolute path:

```sh
security-score /path/to/repository --engine analyzer
security-score /path/to/repository --engine analyzer --analyzer /absolute/path/to/appsec-analyzer
```

The executable cannot come from the repository being assessed. Security Score checks its `version` and `capabilities` commands before scoring. The required public interface is version 1, with `score.available: true`, `score.model_calls: false`, and `score.scoring_version: 2` as recorded in [dependencies.json](../dependencies.json). If the executable is missing or incompatible, the command fails. It does not install Analyzer or switch to the internal engine.

The Analyzer engine accepts a local repository or a supported HTTPS repository URL. It does not accept change selectors such as `--staged`, `--base`, or `--patch`. Analyzer manages any source credentials through its own trusted installation. For a repository URL, `--token-env NAME` selects a token only for the separate GitHub/GitLab host-setting API checks; those checks do not alter Analyzer's score.

Structured output keeps Analyzer's original result in `analyzer_result`, including its warnings, scanner statuses, and unscored findings. The wrapper checks the result status, score range, exit status, and scoring identity, then adds the A–F grade. `--details` shows the underlying result; compact text shows the score and grade.

## Comparing results

Compare repository scores only for the same engine, compatible scoring and rule versions, comparable sources, and similar coverage. A high grade reflects the checks that ran; it is not a verified security assessment. Change analysis is a separate result with `analysis: change-relevance`, `relevance`, `relevance_version`, `signals`, and `finding_changes`. It has no score or grade. An `unclear` relevance result does not approve a change.

The internal engine reads local files without following symlinks on Linux and macOS. Windows filesystem behavior has not been qualified. Direct URLs are limited to canonical HTTPS repositories on GitHub.com and GitLab.com; SSH and self-hosted URLs need a local checkout. Remote transport and API tests are offline, so live GitHub/GitLab behavior still needs verification in the deployment environment.
