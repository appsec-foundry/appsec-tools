"""REQ-02: self-managed GitLab sources, authentication and destination boundaries."""

import contextlib
import io
import json
import os
from pathlib import Path
import socket
import ssl
import sys
import unittest
from unittest import mock
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent / "scripts"))
import score as cli
import score_remote as remote
import score_sources as sources


class GitLabRemoteTests(unittest.TestCase):
    HOST = "gitlab.internal:8443"
    REPO = f"https://{HOST}/group/team/project"
    TOKEN = "isolated-test-token"

    def setUp(self):
        proxy = mock.patch.object(remote, "proxy_for", return_value=None)
        proxy.start()
        self.addCleanup(proxy.stop)

    def test_host_and_port_come_from_the_repository_url(self):
        for host in ("gitlab.internal", self.HOST, "10.23.4.5:8443", "[fd12::8]:8443"):
            with self.subTest(host=host):
                self.assertEqual(
                    remote.repository_url(f"https://{host}/group/team/project.git"),
                    (host, "group/team/project"),
                )

    def test_git_suffix_and_bare_repository_url_select_identical_api_resources(self):
        selected = []
        for suffix in ("", ".git", ".git/"):
            output = io.StringIO()
            with (
                mock.patch.object(remote, "host_settings", return_value=([], "a" * 40, False)) as settings,
                mock.patch.object(remote, "get", return_value=(b"[]", 200)) as get,
                contextlib.redirect_stdout(output),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                cli.main(["--legacy-score", self.REPO + suffix, "--json"])
            selected.append((settings.call_args.args[:2], get.call_args.args[0]))
        self.assertEqual(selected[0], selected[1])
        self.assertEqual(selected[0], selected[2])

    def test_malformed_and_credential_bearing_urls_fail_before_network_access(self):
        for url in (
            "http://gitlab.internal/group/project",
            "https://user:secret@gitlab.internal/group/project",
            "https://gitlab.internal/group/../project",
            "https://gitlab.internal/group/%2e%2e/project",
            "https://gitlab.internal/group/project?token=secret",
            "https://gitlab.internal/group/project#secret",
            "https://gitlab.internal:0/group/project",
            "https://gitlab.internal:65536/group/project",
            "https://gitlab.internal:abc/group/project",
            "https://gitlab.internal:/group/project",
            "https://gitlab.internal\\other/group/project",
            "https://[fd12::8/group/project",
            "https://[fd12::8%25eth0]/group/project",
            "https://gitlab.internal\n/group/project",
        ):
            with self.subTest(url=url), mock.patch.object(remote, "get") as get:
                output, errors = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                    self.assertEqual(cli.main(["--legacy-score", url, "--json"]), 1)
                get.assert_not_called()
                self.assertEqual(output.getvalue(), "")
                self.assertNotIn("secret", errors.getvalue())

    def test_private_addresses_are_limited_to_the_selected_gitlab_instance(self):
        for address in (
            "10.23.4.5", "172.20.1.2", "192.168.2.3", "fd12::8",
            "100.64.1.31", "100.64.0.1", "100.127.255.254",
            "::ffff:100.64.1.31",
        ):
            rows = [(socket.AF_INET, 1, 6, "", (address, 8443))]
            with self.subTest(address=address), mock.patch.object(
                remote.socket, "getaddrinfo", return_value=rows
            ) as lookup:
                self.assertEqual(
                    remote.public_addresses("gitlab.internal", sources.Budget(), port=8443, allow_private=True),
                    rows,
                )
                lookup.assert_called_once_with("gitlab.internal", 8443, type=socket.SOCK_STREAM)
                with self.assertRaises(sources.SourceError):
                    remote.public_addresses("gitlab.com", sources.Budget())

    def test_metadata_loopback_multicast_and_mixed_dns_answers_remain_blocked(self):
        for address in (
            "127.0.0.1", "169.254.169.254", "100.100.100.200", "0.0.0.0",
            "224.0.0.1", "::1", "::", "fe80::1", "ff02::1", "::ffff:127.0.0.1",
            "::ffff:100.100.100.200",
        ):
            rows = [(socket.AF_INET, 1, 6, "", ("10.23.4.5", 8443)),
                    (socket.AF_INET, 1, 6, "", (address, 8443))]
            with self.subTest(address=address), mock.patch.object(
                remote.socket, "getaddrinfo", return_value=rows
            ):
                with self.assertRaises(sources.SourceError):
                    remote.public_addresses("gitlab.internal", sources.Budget(), port=8443, allow_private=True)

    def request(self, url=None, *, status=200, token_host=None, body=b"{}", tls_error=False, address="10.23.4.5"):
        response = mock.Mock(status=status)
        response.getheader.return_value = None
        response.read.side_effect = [body, b""]
        connection = mock.Mock()
        connection.getresponse.return_value = response
        raw_socket = mock.Mock()
        if tls_error:
            connection._context.wrap_socket.side_effect = ssl.SSLCertVerificationError("isolated TLS failure")
        rows = [(socket.AF_INET, 1, 6, "", (address, 8443))]
        with (
            mock.patch.object(remote.socket, "getaddrinfo", return_value=rows),
            mock.patch.object(remote.socket, "socket", return_value=raw_socket),
            mock.patch.object(remote.http.client, "HTTPSConnection", return_value=connection) as factory,
        ):
            result = remote.get(
                url or f"https://{self.HOST}/api/v4/projects/group%2Fproject",
                sources.Budget(), token=self.TOKEN,
                token_host=token_host or self.HOST, gitlab_host=self.HOST,
            )
        return result, connection, raw_socket, factory

    def test_private_connection_pins_the_checked_ip_and_keeps_tls_hostname_and_port(self):
        result, connection, raw, factory = self.request()
        self.assertEqual(result, (b"{}", 200))
        raw.connect.assert_called_once_with(("10.23.4.5", 8443))
        connection._context.wrap_socket.assert_called_once_with(raw, server_hostname="gitlab.internal")
        self.assertEqual(factory.call_args.args, ("gitlab.internal",))
        self.assertEqual(factory.call_args.kwargs["port"], 8443)
        context = factory.call_args.kwargs["context"]
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        headers = connection.request.call_args.kwargs["headers"]
        self.assertEqual(headers["PRIVATE-TOKEN"], self.TOKEN)
        self.assertNotIn("Authorization", headers)

    def test_token_binding_includes_the_port(self):
        _, connection, _, _ = self.request(token_host="gitlab.internal:9443")
        headers = connection.request.call_args.kwargs["headers"]
        self.assertNotIn("PRIVATE-TOKEN", headers)
        self.assertNotIn("Authorization", headers)

    def test_shared_address_space_connects_to_selected_gitlab_with_tls_and_token(self):
        result, connection, raw, factory = self.request(address="100.64.1.31")
        self.assertEqual(result, (b"{}", 200))
        raw.connect.assert_called_once_with(("100.64.1.31", 8443))
        connection._context.wrap_socket.assert_called_once_with(
            raw, server_hostname="gitlab.internal"
        )
        self.assertTrue(factory.call_args.kwargs["context"].check_hostname)
        self.assertEqual(
            connection.request.call_args.kwargs["headers"]["PRIVATE-TOKEN"],
            self.TOKEN,
        )

    def test_request_cannot_escape_the_selected_origin_or_api(self):
        for url in (
            "https://other.internal/api/v4/projects/group%2Fproject",
            "https://gitlab.internal:9443/api/v4/projects/group%2Fproject",
            "https://gitlab.internal.evil:8443/api/v4/projects/group%2Fproject",
            "https://api.github.com/repos/example/project",
            f"https://{self.HOST}/login",
        ):
            with self.subTest(url=url), mock.patch.object(remote.socket, "socket") as connect:
                with self.assertRaises(sources.SourceError):
                    remote.get(url, sources.Budget(), token=self.TOKEN, token_host=self.HOST, gitlab_host=self.HOST)
                connect.assert_not_called()
        with self.assertRaises(sources.SourceError):
            remote.get(f"https://{self.HOST}/api/v4/projects/group%2Fproject", sources.Budget())

    def test_redirects_are_not_followed_and_tls_failures_do_not_fall_back(self):
        with self.assertRaisesRegex(sources.SourceError, "redirects are not followed"):
            self.request(status=302)
        result, connection, _, _ = self.request(tls_error=True)
        self.assertEqual(result, (None, 0))
        connection.request.assert_not_called()

    def test_dns_changes_are_checked_again_before_a_new_connection(self):
        connection = mock.Mock()
        response = mock.Mock(status=200)
        response.getheader.return_value = None
        response.read.side_effect = [b"{}", b""]
        connection.getresponse.return_value = response
        raw = mock.Mock()
        answers = [
            [(socket.AF_INET, 1, 6, "", ("10.23.4.5", 8443))],
            [(socket.AF_INET, 1, 6, "", ("169.254.169.254", 8443))],
        ]
        with (
            mock.patch.object(remote.socket, "getaddrinfo", side_effect=answers),
            mock.patch.object(remote.socket, "socket", return_value=raw),
            mock.patch.object(
                remote.http.client, "HTTPSConnection", return_value=connection
            ),
        ):
            url = f"https://{self.HOST}/api/v4/projects/group%2Fproject"
            self.assertEqual(
                remote.get(url, sources.Budget(), gitlab_host=self.HOST),
                (b"{}", 200),
            )
            with self.assertRaises(sources.SourceError):
                remote.get(url, sources.Budget(), gitlab_host=self.HOST)
        raw.connect.assert_called_once_with(("10.23.4.5", 8443))

    def scan(self, *, details=False, failure=None):
        source = b"requests.get(url, verify=True)\n"
        requests = []

        def fetch(url, budget, **kwargs):
            requests.append((url, kwargs))
            if failure:
                return None, failure
            path = urlsplit(url).path
            if path.endswith("/repository/branches/main"):
                data = {"protected": True, "commit": {"id": "a" * 40}}
            elif path.endswith("/approval_rules"):
                data = [{"approvals_required": 1, "applies_to_all_protected_branches": True}]
            elif path.endswith("/repository/tree"):
                data = [{"path": "app.py", "type": "blob", "mode": "100644", "id": "b" * 40}]
            elif path.endswith("/repository/blobs/" + "b" * 40 + "/raw"):
                return source, 200
            elif path.endswith("/repository/commits"):
                data = [{"id": "a" * 40, "parent_ids": [], "title": "Initial", "author_email": "private@example.invalid", "committed_date": "2026-11-03T10:00:00Z"}]
            elif path.endswith("/repository/branches"):
                data = [{"name": "main"}]
            elif path.endswith("/projects/group%2Fteam%2Fproject"):
                data = {"default_branch": "main", "only_allow_merge_if_pipeline_succeeds": True}
            else:
                raise AssertionError(f"Unexpected API request: {url}")
            return json.dumps(data).encode(), 200

        output, errors = io.StringIO(), io.StringIO()
        args = [self.REPO, "--token-env", "ISOLATED_GITLAB_READ_TOKEN", "--json"]
        if details:
            args.append("--details")
        with (
            mock.patch.dict(os.environ, {"ISOLATED_GITLAB_READ_TOKEN": self.TOKEN}),
            mock.patch.object(remote, "get", side_effect=fetch),
            mock.patch.object(sources, "command", side_effect=AssertionError("Git must not run")),
            contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors),
        ):
            status = cli.main(["--legacy-score", *args])
        return status, output.getvalue(), errors.getvalue(), requests

    def test_remote_cli_reads_pinned_files_and_host_settings_without_a_clone(self):
        status, output, errors, requests = self.scan()
        result = json.loads(output)
        self.assertEqual(status, 0, errors)
        self.assertEqual(result["scope"]["repository"], self.REPO)
        self.assertEqual(result["scope"]["revision"], "a" * 40)
        self.assertEqual(result["coverage"]["files_downloaded"], 1)
        settings = {row["setting"]: row["status"] for row in result["host_settings"]}
        self.assertEqual(settings["default_branch_protection"], "set")
        self.assertEqual(settings["required_reviews"], "set")
        self.assertEqual(settings["successful_pipeline_before_merge"], "set")
        self.assertTrue(any("ref=" + "a" * 40 in url for url, _ in requests))
        self.assertTrue(any("/blobs/" + "b" * 40 + "/raw" in url for url, _ in requests))
        for url, arguments in requests:
            self.assertEqual(urlsplit(url).netloc, self.HOST)
            self.assertEqual(arguments["token_host"], self.HOST)
            self.assertEqual(arguments["gitlab_host"], self.HOST)
        self.assertNotIn(self.TOKEN, output + errors)

    def test_details_history_uses_the_same_gitlab_origin_and_token(self):
        status, output, errors, requests = self.scan(details=True)
        result = json.loads(output)
        self.assertEqual(status, 0, errors)
        self.assertIn("overview", result)
        for suffix in ("/repository/commits", "/repository/branches"):
            selected = [(url, args) for url, args in requests if urlsplit(url).path.endswith(suffix)]
            self.assertEqual(len(selected), 1)
            self.assertEqual(selected[0][1]["gitlab_host"], self.HOST)
            self.assertEqual(selected[0][1]["token_host"], self.HOST)
        self.assertNotIn("private@example.invalid", output)

    def test_missing_or_invalid_token_fails_before_a_request(self):
        for token in (None, "", "isolated\r\ninjection"):
            environment = {} if token is None else {"ISOLATED_GITLAB_READ_TOKEN": token}
            with mock.patch.dict(os.environ, environment, clear=True), mock.patch.object(remote, "get") as get:
                output, errors = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                    status = cli.main(["--legacy-score", self.REPO, "--token-env", "ISOLATED_GITLAB_READ_TOKEN", "--json"])
                self.assertEqual(status, 1)
                self.assertEqual(output.getvalue(), "")
                get.assert_not_called()
                self.assertNotIn("injection", errors.getvalue())

    def test_unauthorized_or_missing_project_does_not_produce_a_score_or_leak_token(self):
        for failure in (401, 403, 404):
            with self.subTest(status=failure):
                status, output, errors, _ = self.scan(failure=failure)
                self.assertEqual(status, 1)
                self.assertEqual(output, "")
                self.assertIn("No score", errors)
                self.assertNotIn(self.TOKEN, errors)

    def test_analyzer_is_not_invoked_for_a_self_managed_url(self):
        with mock.patch.object(cli, "command") as command:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(cli.main(["--legacy-score", self.REPO, "--engine", "analyzer"]), 1)
            command.assert_not_called()


if __name__ == "__main__":
    unittest.main()
