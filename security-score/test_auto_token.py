"""REQ-24: user-configured credentials stay lazy, bounded and origin-specific."""

import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent / "scripts"))
import score as cli
import score_remote as remote
import score_sources as sources


class AutomaticTokenTests(unittest.TestCase):
    HOST = "gitlab.internal:8443"
    ORIGIN = "https://" + HOST
    TOKEN = "isolated-auto-token"

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="score-auto-token-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.configuration = self.root / "user-config"
        self.path = self.configuration / "security-score" / "token-hosts.json"
        patcher = mock.patch.dict(
            os.environ,
            {"XDG_CONFIG_HOME": str(self.configuration), "GIT_TOKEN": self.TOKEN},
            clear=True,
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def configure(self, data=None):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(data or {self.ORIGIN: "GIT_TOKEN"}))

    def test_missing_mapping_keeps_public_requests_anonymous(self):
        for configured in (False, True):
            if configured:
                self.configure({"https://other.internal:8443": "OTHER_TOKEN"})
            with self.subTest(configured=configured), mock.patch.object(remote, "read_token") as load:
                token = remote.select_token(self.HOST)
                self.assertIsInstance(token, remote.AutomaticToken)
                self.assertEqual(token.name, "GIT_TOKEN")
                with mock.patch.object(remote, "get", return_value=(b"{}", 200)) as get:
                    remote.credential_get(
                        self.ORIGIN + "/api/v4/projects/group%2Fproject",
                        sources.Budget(), token=token, token_host=self.HOST,
                    )
                load.assert_not_called()
                self.assertIsNone(get.call_args.kwargs["token"])

    def test_missing_fallback_keeps_authentication_failures_anonymous(self):
        os.environ.pop("GIT_TOKEN")
        self.assertIsNone(remote.select_token(self.HOST))
        for status in (401, 403, 404):
            with self.subTest(status=status), mock.patch.object(remote, "get", return_value=(None, status)) as get:
                self.assertEqual(
                    remote.credential_get(
                        self.ORIGIN + "/api/v4/projects/group%2Fproject",
                        sources.Budget(), token=remote.select_token(self.HOST), token_host=self.HOST,
                    ),
                    (None, status),
                )
                get.assert_called_once()
                self.assertIsNone(get.call_args.kwargs["token"])

    def test_host_mapping_takes_precedence_over_git_token(self):
        self.configure({self.ORIGIN: "CUSTOM_TOKEN"})
        os.environ["CUSTOM_TOKEN"] = "isolated-mapped-token"
        token = remote.select_token(self.HOST)
        with mock.patch.object(remote, "get", side_effect=[(None, 404), (b"{}", 200)]) as get:
            remote.credential_get(
                self.ORIGIN + "/api/v4/projects/group%2Fproject",
                sources.Budget(), token=token, token_host=self.HOST,
            )
        self.assertEqual(get.call_args.kwargs["token"], "isolated-mapped-token")

    def test_mapping_contains_a_name_and_does_not_load_token_before_a_challenge(self):
        self.configure()
        with mock.patch.object(remote, "read_token") as load:
            token = remote.select_token(self.HOST)
            self.assertIsInstance(token, remote.AutomaticToken)
            with mock.patch.object(remote, "get", return_value=(b"{}", 200)) as get:
                self.assertEqual(
                    remote.credential_get(
                        self.ORIGIN + "/api/v4/projects/group%2Fproject",
                        sources.Budget(), token=token, token_host=self.HOST,
                    ),
                    (b"{}", 200),
                )
            load.assert_not_called()
            self.assertIsNone(get.call_args.kwargs["token"])

    def test_explicit_selection_ignores_automatic_mapping_and_invalid_config(self):
        self.configure()
        self.path.write_text("not JSON")
        with mock.patch.dict(os.environ, {"CUSTOM_TOKEN": "isolated-explicit-token"}):
            self.assertEqual(
                remote.select_token(self.HOST, "CUSTOM_TOKEN"),
                "isolated-explicit-token",
            )
            with self.assertRaises(sources.SourceError):
                remote.select_token(self.HOST, "MISSING_EXPLICIT_TOKEN")

    def test_authentication_failure_retries_once_then_reuses_the_selected_token(self):
        for configured in (False, True):
            if configured:
                self.configure()
            for status in (401, 403, 404):
                with self.subTest(configured=configured, status=status):
                    token = remote.select_token(self.HOST)
                    with mock.patch.object(
                        remote, "get", side_effect=[(None, status), (b"{}", 200), (b"[]", 200)]
                    ) as get:
                        for _ in range(2):
                            remote.credential_get(
                                self.ORIGIN + "/api/v4/projects/group%2Fproject",
                                sources.Budget(), token=token, token_host=self.HOST,
                            )
                    self.assertEqual(get.call_count, 3)
                    self.assertIsNone(get.call_args_list[0].kwargs["token"])
                    self.assertEqual(get.call_args_list[1].kwargs["token"], self.TOKEN)
                    self.assertEqual(get.call_args_list[2].kwargs["token"], self.TOKEN)

    def test_bad_token_never_causes_a_retry_loop(self):
        self.configure()
        token = remote.select_token(self.HOST)
        with mock.patch.object(remote, "get", return_value=(None, 401)) as get:
            self.assertEqual(
                remote.credential_get(
                    self.ORIGIN + "/api/v4/projects/group%2Fproject",
                    sources.Budget(), token=token, token_host=self.HOST,
                ),
                (None, 401),
            )
        self.assertEqual(get.call_count, 2)

    def test_unrelated_hosts_and_ports_cannot_trigger_token_loading(self):
        self.configure()
        self.check_unrelated_hosts_and_ports()

    def test_fallback_cannot_load_or_send_credentials_at_another_origin(self):
        self.check_unrelated_hosts_and_ports()

    def check_unrelated_hosts_and_ports(self):
        token = remote.select_token(self.HOST)
        for active in (False, True):
            if active:
                token.activate(self.HOST)
            with self.subTest(active=active), mock.patch.object(remote, "read_token") as load:
                for authority in ("other.internal:8443", "gitlab.internal:9443", "gitlab.internal.evil:8443"):
                    with mock.patch.object(remote, "get", return_value=(None, 401)) as get:
                        remote.credential_get(
                            f"https://{authority}/api/v4/projects/group%2Fproject",
                            sources.Budget(), token=token, token_host=authority,
                        )
                        self.assertEqual(get.call_count, 1)
                        self.assertIsNone(get.call_args.kwargs["token"])
                load.assert_not_called()

    def test_github_mapping_authorizes_only_the_api_and_never_the_raw_host(self):
        self.configure({"https://api.github.com": "GIT_TOKEN"})
        self.check_github_api_credentials()

    def test_github_fallback_authorizes_only_the_api_and_never_the_raw_host(self):
        self.check_github_api_credentials()

    def check_github_api_credentials(self):
        token = remote.select_token("github.com")
        with mock.patch.object(remote, "get", side_effect=[(None, 404), (b"{}", 200), (None, 404)]) as get:
            remote.credential_get(
                "https://api.github.com/repos/group/project", sources.Budget(),
                token=token, token_host="api.github.com",
            )
            remote.credential_get(
                "https://raw.githubusercontent.com/group/project/main/app.py", sources.Budget(),
                token=token, token_host="api.github.com",
            )
        self.assertEqual(get.call_count, 3)
        self.assertEqual(get.call_args_list[1].kwargs["token"], self.TOKEN)
        self.assertIsNone(get.call_args_list[2].kwargs["token"])

    def test_mapping_a_web_origin_does_not_authorize_a_different_api_origin(self):
        os.environ.pop("GIT_TOKEN")
        self.configure({"https://github.com": "GIT_TOKEN"})
        self.assertIsNone(remote.select_token("github.com"))

    def test_protected_host_metadata_can_activate_token_after_public_source_metadata(self):
        self.configure()
        token = remote.select_token(self.HOST)
        urls = []

        def get(url, budget, **kwargs):
            urls.append((url, kwargs["token"]))
            if "/approval_rules?" in url:
                if kwargs["token"] is None:
                    return None, 401
                data = [{"approvals_required": 1, "applies_to_all_protected_branches": True}]
            elif "/repository/branches/" in url:
                data = {"protected": True, "commit": {"id": "a" * 40}}
            else:
                data = {"default_branch": "main"}
            return json.dumps(data).encode(), 200

        with mock.patch.object(remote, "get", side_effect=get):
            settings, _, _ = remote.host_settings(
                self.HOST, "group/project", sources.Budget(), token, require_source=True
            )
        self.assertTrue(all(value is None for _, value in urls[:3]))
        self.assertEqual(urls[3][1], self.TOKEN)
        self.assertEqual(
            next(row["status"] for row in settings if row["setting"] == "required_reviews"),
            "set",
        )

    def test_tls_redirect_server_and_rate_limit_failures_do_not_select_a_token(self):
        self.configure()
        self.check_non_authentication_failures()

    def test_non_authentication_failures_do_not_select_the_fallback(self):
        self.check_non_authentication_failures()

    def check_non_authentication_failures(self):
        for failure in ((None, 0), (None, 500), (None, 429), sources.SourceError("redirect rejected")):
            token = remote.select_token(self.HOST)
            with mock.patch.object(remote, "read_token") as load:
                kwargs = {"side_effect": failure} if isinstance(failure, Exception) else {"return_value": failure}
                with mock.patch.object(remote, "get", **kwargs) as get:
                    if isinstance(failure, Exception):
                        with self.assertRaises(sources.SourceError):
                            remote.credential_get(self.ORIGIN + "/api/v4/projects/x", sources.Budget(), token=token, token_host=self.HOST)
                    else:
                        remote.credential_get(self.ORIGIN + "/api/v4/projects/x", sources.Budget(), token=token, token_host=self.HOST)
                self.assertEqual(get.call_count, 1)
                load.assert_not_called()

    def test_anonymous_rate_limit_403_can_retry_once_with_configured_credentials(self):
        self.configure()
        token = remote.select_token(self.HOST)
        with mock.patch.object(remote, "get", side_effect=[remote.RateLimited("rate limit", 403), (b"{}", 200)]) as get:
            self.assertEqual(
                remote.credential_get(self.ORIGIN + "/api/v4/projects/x", sources.Budget(), token=token, token_host=self.HOST),
                (b"{}", 200),
            )
        self.assertEqual(get.call_count, 2)
        self.assertEqual(get.call_args.kwargs["token"], self.TOKEN)

    def test_missing_mapped_token_fails_only_when_authentication_is_needed(self):
        self.configure({self.ORIGIN: "ISOLATED_MISSING_TOKEN"})
        with mock.patch.dict(os.environ, {}, clear=True):
            os.environ["XDG_CONFIG_HOME"] = str(self.configuration)
            os.environ["GIT_TOKEN"] = self.TOKEN
            token = remote.select_token(self.HOST)
            with mock.patch.object(remote, "get", return_value=(b"{}", 200)):
                remote.credential_get(self.ORIGIN + "/api/v4/projects/x", sources.Budget(), token=token, token_host=self.HOST)
            with mock.patch.object(remote, "get", return_value=(None, 401)) as get:
                with self.assertRaisesRegex(sources.SourceError, "missing or invalid"):
                    remote.credential_get(self.ORIGIN + "/api/v4/projects/x", sources.Budget(), token=token, token_host=self.HOST)
                self.assertEqual(get.call_count, 1)

    def test_config_rejects_ambiguous_origins_values_and_oversized_or_invalid_json(self):
        self.configure()
        for raw in (
            "not JSON", "[]", "null",
            '{"https://gitlab.internal:8443":"GIT_TOKEN","https://gitlab.internal:8443":"OTHER"}',
            '{"https://gitlab.internal":"GIT_TOKEN","https://gitlab.internal:443/":"OTHER"}',
            json.dumps({self.ORIGIN: self.TOKEN}),
            json.dumps({self.ORIGIN: {"token": self.TOKEN}}),
            json.dumps({"https://user:secret@gitlab.internal": "GIT_TOKEN"}),
            json.dumps({"https://gitlab.internal/team/project": "GIT_TOKEN"}),
            json.dumps({"http://gitlab.internal": "GIT_TOKEN"}),
            " " * (remote.MAX_TOKEN_CONFIG + 1),
        ):
            with self.subTest(raw=raw[:50]):
                self.path.write_text(raw)
                with self.assertRaises(sources.SourceError) as error:
                    remote.select_token(self.HOST)
                self.assertNotIn(self.TOKEN, str(error.exception))
                self.assertNotIn("secret", str(error.exception))

    def test_project_config_is_ignored_and_relative_xdg_paths_use_the_home_directory(self):
        project = self.root / "project"
        (project / "security-score").mkdir(parents=True)
        (project / "security-score/token-hosts.json").write_text(json.dumps({self.ORIGIN: "PROJECT_TOKEN"}))
        previous = Path.cwd()
        try:
            os.chdir(project)
            with mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": "."}), mock.patch.object(remote.Path, "home", return_value=self.root / "isolated-home"):
                self.assertEqual(remote.select_token(self.HOST).name, "GIT_TOKEN")
        finally:
            os.chdir(previous)

    def test_local_scans_never_read_the_token_host_configuration(self):
        project = self.root / "local-project"
        project.mkdir()
        (project / "app.py").write_text("requests.get(url, verify=True)\n")
        with mock.patch.object(remote, "token_hosts", side_effect=AssertionError("read config")):
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(cli.main(["--legacy-score", str(project), "--json"]), 0)

    def test_remote_cli_authenticates_only_after_a_challenge_and_keeps_details_on_same_session(self):
        self.configure()
        self.check_remote_cli_authentication(challenge=401)

    def test_remote_cli_uses_git_token_after_404_without_host_configuration(self):
        self.check_remote_cli_authentication()

    def check_remote_cli_authentication(self, challenge=404):
        calls = []
        source = b"requests.get(url, verify=True)\n"

        def get(url, budget, **kwargs):
            calls.append((url, kwargs.get("token")))
            if kwargs.get("token") is None:
                return None, challenge
            path = urlsplit(url).path
            if path.endswith("/repository/branches/main"):
                data = {"protected": True, "commit": {"id": "a" * 40}}
            elif path.endswith("/approval_rules"):
                data = [{"approvals_required": 1, "applies_to_all_protected_branches": True}]
            elif path.endswith("/repository/tree"):
                data = [{"path": "app.py", "type": "blob", "mode": "100644", "id": "b" * 40}]
            elif "/repository/blobs/" in path:
                return source, 200
            elif path.endswith("/repository/commits") or path.endswith("/repository/branches"):
                data = []
            else:
                data = {"default_branch": "main", "only_allow_merge_if_pipeline_succeeds": True}
            return json.dumps(data).encode(), 200

        output, errors = io.StringIO(), io.StringIO()
        with mock.patch.object(remote, "get", side_effect=get):
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                status = cli.main(["--legacy-score", self.ORIGIN + "/group/project", "--details", "--json"])
        self.assertEqual(status, 0, errors.getvalue())
        result = json.loads(output.getvalue())
        self.assertEqual(result["scope"]["revision"], "a" * 40)
        self.assertIn("overview", result)
        self.assertIsNone(calls[0][1])
        self.assertTrue(all(token == self.TOKEN for _, token in calls[1:]))
        self.assertNotIn(self.TOKEN, output.getvalue() + errors.getvalue())

    def test_rejected_fallback_stops_after_one_retry_without_exposing_the_token(self):
        output, errors = io.StringIO(), io.StringIO()
        with mock.patch.object(remote, "get", return_value=(None, 404)) as get:
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                status = cli.main(["--legacy-score", self.ORIGIN + "/group/project", "--json"])
        self.assertEqual(status, 1)
        self.assertEqual(get.call_count, 2)
        self.assertIsNone(get.call_args_list[0].kwargs["token"])
        self.assertEqual(get.call_args_list[1].kwargs["token"], self.TOKEN)
        self.assertEqual(output.getvalue(), "")
        self.assertIn("HTTP 404", errors.getvalue())
        self.assertNotIn(self.TOKEN, errors.getvalue())

    def test_invalid_fallback_is_checked_only_on_authentication_failure(self):
        for invalid in ("", "invalid\r\nheader"):
            os.environ["GIT_TOKEN"] = invalid
            token = remote.select_token(self.HOST)
            with self.subTest(invalid=repr(invalid)):
                with mock.patch.object(remote, "get", return_value=(b"{}", 200)):
                    remote.credential_get(
                        self.ORIGIN + "/api/v4/projects/group%2Fproject",
                        sources.Budget(), token=token, token_host=self.HOST,
                    )
                with mock.patch.object(remote, "get", return_value=(None, 404)) as get:
                    with self.assertRaisesRegex(sources.SourceError, "missing or invalid"):
                        remote.credential_get(
                            self.ORIGIN + "/api/v4/projects/group%2Fproject",
                            sources.Budget(), token=token, token_host=self.HOST,
                        )
                    get.assert_called_once()


if __name__ == "__main__":
    unittest.main()
