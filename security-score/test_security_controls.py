"""Targeted positive, negative and abuse examples for authentication and transport."""

import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent / "scripts"))
import score as cli  # noqa: E402
import score_controls as controls  # noqa: E402
import score_core as core  # noqa: E402
import score_sources as sources  # noqa: E402


class SecurityControlTests(unittest.TestCase):
    def run_cli(self, directory, *flags):
        output, errors = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            status = cli.main(["--legacy-score", str(directory), *flags])
        return status, output.getvalue(), errors.getvalue()

    def test_check_groups_cover_the_catalog_and_default_selection_is_all(self):
        expected = {rule["id"] for rule in core.RULES}
        groups = core.check_groups()
        self.assertEqual(set(groups["all"]), expected)
        self.assertEqual(
            set().union(*(set(ids) for group, ids in groups.items() if group != "all")),
            expected,
        )
        self.assertEqual(core.selected_rules(), core.RULES)
        self.assertEqual(
            {rule["id"] for rule in core.selected_rules("tls,headers", "TLS-USAGE")},
            (set(groups["tls"]) | set(groups["headers"])) - {"TLS-USAGE"},
        )
        for include, exclude in (
            ("unknown", None),
            ("", None),
            ("all", "all"),
            ("tls", "missing"),
        ):
            with (
                self.subTest(include=include, exclude=exclude),
                self.assertRaises(ValueError),
            ):
                core.selected_rules(include, exclude)

    def test_cli_selection_filters_findings_and_default_does_not_change(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "app.ts").write_text(
                "eval(payload);\ncrypto.createHash('md5').update(password);\n"
            )
            _, raw, _ = self.run_cli(root, "--json")
            baseline = json.loads(raw)
            _, raw, _ = self.run_cli(root, "--json", "--checks", "all")
            self.assertEqual(json.loads(raw), baseline)
            status, raw, errors = self.run_cli(
                root, "--json", "--checks", "authentication"
            )
            selected = json.loads(raw)
            self.assertEqual(status, 2)
            self.assertEqual(errors, "")
            self.assertEqual(
                {row["rule"] for row in selected["findings"]}, {"PASSWORD-HASH"}
            )
            self.assertIsNone(selected["grade"])
            self.assertEqual(
                set(selected["coverage"]["selected_checks"]),
                set(core.check_groups()["authentication"]),
            )
            self.assertNotIn("JS-EVAL", {row["rule"] for row in selected["checks"]})
            _, raw, _ = self.run_cli(root, "--json", "--skip-checks", "authentication")
            self.assertNotIn(
                "PASSWORD-HASH", {row["rule"] for row in json.loads(raw)["findings"]}
            )
            _, raw, _ = self.run_cli(root, "--json")
            self.assertEqual(
                json.loads(raw), baseline
            )  # Selection never mutates the catalog.

    def test_selected_header_checks_do_not_execute_unselected_source_detectors(self):
        with (
            mock.patch.object(
                core,
                "python_observations",
                side_effect=AssertionError("Unselected Python control executed"),
            ),
            mock.patch.object(
                core,
                "other_observations",
                side_effect=AssertionError("Unselected JS control executed"),
            ),
        ):
            findings, checks = core.scan(
                {
                    "headers.py": {
                        "text": "response.headers['X-Frame-Options'] = 'DENY'\neval(payload)\n"
                    }
                },
                sources.Budget(),
                rules=core.selected_rules("headers"),
            )
        self.assertFalse(findings)
        self.assertEqual({row["rule"] for row in checks}, {"WEB-CSP", "WEB-HEADERS"})

    def test_invalid_check_selection_fails_before_scanning_and_quite_stays_silent(self):
        for flags in (
            ("--checks", "missing"),
            ("--skip-checks", "all"),
            ("--checks", "tls", "--worktree"),
            ("--checks", "tls", "--engine", "analyzer"),
        ):
            with (
                self.subTest(flags=flags),
                mock.patch.object(
                    cli,
                    "run",
                    side_effect=AssertionError("Invalid request reached scanning"),
                ),
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit) as error,
            ):
                cli.main(list(flags))
            self.assertEqual(error.exception.code, 2)
        with (
            contextlib.redirect_stderr(io.StringIO()) as errors,
            self.assertRaises(SystemExit),
        ):
            cli.main(["--legacy-score", "--quite", "--checks", "missing"])
        self.assertEqual(errors.getvalue(), "")

    def test_details_shows_scan_steps_while_quite_and_json_hide_progress(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "app.py").write_text("requests.get(url, verify=False)\n")
            status, output, errors = self.run_cli(root, "--details", "--checks", "tls")
            self.assertEqual(status, 2)
            self.assertIn("Preparing scan: 5 selected checks", errors)
            self.assertIn("Checking sources: 1/1 files", errors)
            self.assertIn(
                "Building architecture and identity-provider profiles", errors
            )
            self.assertIn("Checks: tls", output)
            self.assertRegex(output, r"Duration: \d+\.\d{2} s\n$")
            quiet_status, output, errors = self.run_cli(
                root, "--quite", "--details", "--checks", "tls"
            )
            self.assertEqual(quiet_status, status)
            self.assertEqual((output, errors), ("59\n", ""))
            _, output, errors = self.run_cli(
                root, "--json", "--details", "--checks", "tls"
            )
            self.assertEqual(errors, "")
            self.assertIn("duration_seconds", json.loads(output))

    def test_list_checks_works_without_reading_a_repository(self):
        with mock.patch.object(
            cli, "select", side_effect=AssertionError("Listing read a repository")
        ):
            status, output, errors = self.run_cli(
                "/nonexistent", "--list-checks", "--json"
            )
        self.assertEqual((status, errors), (0, ""))
        self.assertEqual(json.loads(output)["default"], "all")
        self.assertIn("tls", json.loads(output)["check_groups"])

    def inspect(self, text, path="login.ts"):
        code = (
            core.javascript_code(text)
            if Path(path).suffix in core.JS_EXTENSIONS
            else text
        )
        return controls.inspect_controls(path, text, code)

    def test_juice_shop_style_implicit_flow_and_sso_are_detected_at_the_redirect(self):
        source = (
            "const provider = 'https://accounts.google.com/o/oauth2/v2/auth';\n"
            "this.windowRefService.nativeWindow.location.replace(`${provider}?client_id=${this.clientId}&response_type=token&scope=email&redirect_uri=${this.redirectUri}`);\n"
        )
        rows = self.inspect(source)
        self.assertEqual(rows["AUTH-OAUTH-IMPLICIT"], [(2, "violated")])
        self.assertEqual(
            rows["AUTH-SSO"], [(2, "satisfied", "OAuth/OIDC authorization request")]
        )
        self.assertNotIn("AUTH-OAUTH-PKCE", rows)  # No claim from absence alone.

    def test_authorization_urls_distinguish_flow_and_pkce_choices(self):
        for query, implicit, pkce in (
            ("response_type=code&code_challenge_method=S256", "satisfied", "satisfied"),
            ("response_type=token&code_challenge_method=plain", "violated", "violated"),
            ("response_type=code%20token", "violated", None),
            ("response_type=id_token", "unclear", None),
            ("response_type=${flow}", "unclear", None),
            ("response_type=code&response_type=token", "unclear", None),
        ):
            with self.subTest(query=query):
                rows = self.inspect(
                    f"res.redirect(`https://idp.example/authorize?client_id=example&{query}`);"
                )
                self.assertEqual(rows["AUTH-OAUTH-IMPLICIT"], [(1, implicit)])
                self.assertEqual(
                    rows.get("AUTH-OAUTH-PKCE"), [(1, pkce)] if pkce else None
                )

    def test_unrelated_strings_comments_and_dynamic_endpoints_prove_nothing(self):
        for source in (
            "// window.location.assign('https://idp.example/authorize?client_id=c&response_type=token');",
            "/* window.location.assign('https://idp.example/authorize?client_id=c&response_type=token'); */",
            "const note = \"window.location.assign('https://idp.example/authorize?client_id=c&response_type=token')\";",
            "const data = {response_type: 'token'};",
            "window.location.assign('https://example.test/?response_type=token');",
            "window.location.assign(`${unknown}?client_id=c&response_type=token`);",
            "const provider = 'https://idp.example/authorize'; provider = dynamic(); window.location.assign(`${provider}?client_id=c&response_type=token`);",
        ):
            with self.subTest(source=source):
                self.assertEqual(self.inspect(source), {})

    def test_oauth_parameters_on_actual_builders(self):
        for values, rule, status in (
            ("grant_type: 'password'", "AUTH-OAUTH-PASSWORD", "violated"),
            ("grant_type: 'client_credentials'", "AUTH-OAUTH-PASSWORD", "satisfied"),
            ("grant_type: mode", "AUTH-OAUTH-PASSWORD", "unclear"),
            ("code_challenge_method: 'plain'", "AUTH-OAUTH-PKCE", "violated"),
            ("code_challenge_method: 'S256'", "AUTH-OAUTH-PKCE", "satisfied"),
            ("'response_type': 'token'", "AUTH-OAUTH-IMPLICIT", "violated"),
        ):
            with self.subTest(values=values):
                self.assertEqual(
                    self.inspect(f"new URLSearchParams({{{values}}});")[rule],
                    [(1, status)],
                )
        for source in (
            "new URLSearchParams({...options, grant_type: 'password'});",
            "new URLSearchParams({grant_type: 'password', grant_type: 'client_credentials'});",
        ):
            self.assertEqual(self.inspect(source), {})

    def test_python_token_requests_resolve_import_aliases_and_dynamic_values(self):
        for source, status in (
            (
                "import requests as r\nr.post(endpoint, data={'grant_type': 'password'})",
                "violated",
            ),
            (
                "from httpx import post as send\nsend(endpoint, json={'grant_type': 'authorization_code'})",
                "satisfied",
            ),
            (
                "import requests\nrequests.post(endpoint, data={'grant_type': mode})",
                "unclear",
            ),
        ):
            with self.subTest(source=source):
                self.assertEqual(
                    self.inspect(source, "oauth.py")["AUTH-OAUTH-PASSWORD"],
                    [(2, status)],
                )
        self.assertEqual(
            self.inspect("data = {'grant_type': 'password'}", "data.py"), {}
        )

    def test_sso_requires_usage_not_just_packages_or_imports(self):
        for source in (
            "import {Strategy} from 'passport-oauth2';",
            "const Strategy = factory(); new Strategy({state: false});",
            "// import {Strategy} from 'passport-oauth2';\nnew Strategy(options);",
        ):
            self.assertNotIn("AUTH-SSO", self.inspect(source))
        for source, path in (
            (
                "import {auth as login} from 'express-openid-connect'; login(options);",
                "auth.ts",
            ),
            (
                "const oidc = require('openid-client'); oidc.discovery(issuer, client);",
                "auth.js",
            ),
            (
                "from requests_oauthlib import OAuth2Session as Login\nclient = Login(client_id)",
                "auth.py",
            ),
        ):
            self.assertTrue(self.inspect(source, path)["AUTH-SSO"])

    def test_saml_disabled_controls_are_call_scoped_and_signature_alternatives_are_kept(
        self,
    ):
        prefix = "import {SAML as Client} from '@node-saml/node-saml';\n"
        for options, status in (
            ("{audience: false}", "violated"),
            ("{acceptedClockSkewMs: -1}", "violated"),
            ("{audience: 'https://sp.example'}", "satisfied"),
            ("{acceptedClockSkewMs: 5000}", "satisfied"),
            ("options", "unclear"),
            ("{audience: expectedAudience}", "unclear"),
            ("{...options, audience: false}", "unclear"),
            ("{audience: false, audience: 'sp'}", "unclear"),
        ):
            with self.subTest(options=options):
                self.assertEqual(
                    self.inspect(prefix + f"new Client({options});")[
                        "AUTH-SAML-VALIDATION"
                    ],
                    [(2, status)],
                )
        rows = self.inspect(
            prefix
            + "new Client({wantAssertionsSigned: false, wantAuthnResponseSigned: true});"
        )
        self.assertNotIn("AUTH-SAML-VALIDATION", rows)
        self.assertTrue(rows["AUTH-SSO"])
        self.assertEqual(
            self.inspect("const options = {audience: false, acceptedClockSkewMs: -1};"),
            {},
        )

    def test_direct_password_comparisons_and_kdf_verification_are_distinguished(self):
        for source, path in (
            ("if (req.body.password === user.password) login();", "auth.ts"),
            ("if (account.password !== request.body.password) deny();", "auth.ts"),
            ("if request.form['password'] == user.password:\n    login()", "auth.py"),
        ):
            self.assertTrue(self.inspect(source, path)["AUTH-PASSWORD-COMPARE"])
        for source in (
            "if (await bcrypt.compare(req.body.password, user.password)) login();",
            "if (req.body.password === req.body.confirmPassword) accept();",
            "// if (req.body.password === user.password) login();",
            "const note = 'req.body.password === user.password';",
        ):
            self.assertNotIn("AUTH-PASSWORD-COMPARE", self.inspect(source))

    def test_tls_and_certificate_options_are_usage_not_assurance(self):
        for source in (
            "import https from 'node:https'; https.createServer({cert: chain, key: privateKey}, app);",
            "const tls = require('node:tls'); tls.connect({ca: caBundle, rejectUnauthorized: false});",
            "import {createSecureServer as serve} from 'node:http2'; serve({pfx: keystore});",
        ):
            with self.subTest(source=source):
                rows = self.inspect(source)
                self.assertTrue(rows["TLS-USAGE"])
                self.assertTrue(rows["TLS-CERTIFICATE"])
        for source in (
            "const cert = 'server.pem';",
            "const options = {cert: chain};",
            "// https.createServer({cert: chain});",
            "other.createServer({cert: chain});",
        ):
            self.assertEqual(self.inspect(source), {})
        self.assertNotIn(
            "TLS-CERTIFICATE",
            self.inspect(
                "import https from 'https'; https.createServer({cert: null}, app);"
            ),
        )

    def test_python_tls_verification_is_scoped_to_client_contexts(self):
        for factory, assignment, status in (
            ("s.create_default_context()", "ctx.check_hostname = False", "violated"),
            (
                "s.SSLContext(s.PROTOCOL_TLS_CLIENT)",
                "ctx.verify_mode = s.CERT_NONE",
                "violated",
            ),
            ("s.create_default_context()", "ctx.check_hostname = True", "satisfied"),
            (
                "s.create_default_context()",
                "ctx.verify_mode = s.CERT_REQUIRED",
                "satisfied",
            ),
            ("s.create_default_context()", "ctx.check_hostname = setting", "unclear"),
        ):
            with self.subTest(factory=factory, assignment=assignment):
                rows = self.inspect(
                    f"import ssl as s\nctx = {factory}\n{assignment}\n", "client.py"
                )
                self.assertEqual(rows["PY-TLS-CONTEXT"], [(3, status)])
        for body in (
            "ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)\nctx.check_hostname = False",
            "ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)\nctx.check_hostname = False",
            "ctx = ssl.create_default_context()\nctx = unrelated()\nctx.check_hostname = False",
            "ctx = unrelated()\nctx.verify_mode = ssl.CERT_NONE",
        ):
            self.assertNotIn(
                "PY-TLS-CONTEXT", self.inspect("import ssl\n" + body, "server.py")
            )
        rows = self.inspect(
            "import ssl\nctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)\nctx.load_cert_chain('cert.pem', 'key.pem')",
            "server.py",
        )
        self.assertTrue(rows["TLS-CERTIFICATE"])

    def test_nginx_tls_and_certificate_directives_exclude_comments(self):
        rows = self.inspect(
            "# listen 443 ssl;\nlisten 443 ssl;\nssl_certificate /run/tls/cert.pem;\n# ssl_certificate /fake.pem;\n",
            "nginx.conf",
        )
        self.assertEqual(rows["TLS-USAGE"], [(2, "satisfied", "nginx TLS listener")])
        self.assertEqual(
            rows["TLS-CERTIFICATE"], [(3, "satisfied", "nginx certificate configured")]
        )

    def test_usage_evidence_never_creates_a_security_score(self):
        findings, checks = core.scan(
            {
                "app.ts": {
                    "text": "import {auth} from 'express-openid-connect'; auth(options);"
                },
                "nginx.conf": {
                    "text": "listen 443 ssl;\nssl_certificate /run/tls/cert.pem;"
                },
            },
            sources.Budget(),
        )
        result = core.calculate(findings, checks)
        self.assertIsNone(result["score"])
        self.assertIsNone(result["observed_score"])
        self.assertFalse(findings)
        self.assertEqual(
            {row["rule"] for row in checks if row["status"] == "satisfied"},
            {"AUTH-SSO", "TLS-USAGE", "TLS-CERTIFICATE"},
        )

    def test_sensitive_literal_values_never_enter_findings_or_labels(self):
        marker = "SYNTHETIC_PRIVATE_VALUE_DO_NOT_PRINT"
        files = {
            "auth.ts": {
                "text": f"window.location.assign('https://idp.example/authorize?client_id={marker}&response_type=token');"
            },
            "server.ts": {
                "text": f"import https from 'https'; https.createServer({{cert: '{marker}', key: '{marker}'}}, app);"
            },
        }
        findings, checks = core.scan(files, sources.Budget())
        self.assertNotIn(marker, json.dumps({"findings": findings, "checks": checks}))
        self.assertTrue(any(row["rule"] == "AUTH-OAUTH-IMPLICIT" for row in findings))

    def test_new_rules_are_shipped_and_verifiable(self):
        with contextlib.redirect_stdout(io.StringIO()):
            result = cli.verify_rules()
        self.assertEqual(result["rules_verified"], len(core.RULES))

    def profile(self, text, path="auth.ts"):
        metadata = {}
        code = (
            core.javascript_code(text)
            if Path(path).suffix in core.JS_EXTENSIONS
            else text
        )
        controls.inspect_controls(path, text, code, metadata)
        return metadata

    def test_identity_profile_reports_actual_google_authorization_request_and_grant(
        self,
    ):
        metadata = self.profile(
            "const provider = 'https://accounts.google.com/o/oauth2/v2/auth';\nwindow.location.assign(`${provider}?client_id=${client}&response_type=token`);"
        )
        provider = metadata["identity_providers"][0]
        self.assertEqual(
            (
                provider["technology"],
                provider["server"],
                provider["endpoint"],
                provider["line"],
            ),
            ("Google", "https://accounts.google.com", "authorization", 2),
        )
        grant = metadata["oauth_grants"][0]
        self.assertEqual(
            (
                grant["grant_type"],
                grant["response_type"],
                grant["server"],
                grant["evidence"],
            ),
            ("implicit", "token", provider["server"], "requested"),
        )

    def test_discovery_and_configuration_do_not_infer_runtime_grants(self):
        for declaration, call in (
            ("import * as oidc from 'openid-client';", "oidc.discovery"),
            ("import {discovery as discover} from 'openid-client';", "discover"),
        ):
            metadata = self.profile(
                declaration
                + f"\n{call}(new URL('https://login.example/realms/corp/'), clientId);"
            )
            self.assertEqual(
                metadata["identity_providers"][0]["server"], "https://login.example"
            )
            self.assertEqual(metadata["identity_providers"][0]["protocol"], "OIDC")
            self.assertEqual(metadata["oauth_grants"], [])
        metadata = self.profile(
            "import {auth} from 'express-openid-connect'; auth({issuerBaseURL: process.env.ISSUER});"
        )
        self.assertIsNone(metadata["identity_providers"][0]["server"])
        self.assertEqual(metadata["oauth_grants"], [])

    def test_supported_metadata_grants_are_separate_from_requested_grants(self):
        source = json.dumps(
            {
                "issuer": "https://idp.example/tenant",
                "authorization_endpoint": "https://auth.example/authorize",
                "token_endpoint": "https://token.example/token",
                "grant_types_supported": [
                    "authorization_code",
                    "client_credentials",
                    "password",
                ],
            }
        )
        profile = self.profile(source, "oidc.json")
        self.assertEqual(
            {row["server"] for row in profile["identity_providers"]},
            {"https://idp.example", "https://auth.example", "https://token.example"},
        )
        self.assertEqual(
            {(row["grant_type"], row["evidence"]) for row in profile["oauth_grants"]},
            {
                ("authorization_code", "supported"),
                ("client_credentials", "supported"),
                ("password", "supported"),
            },
        )
        findings, _ = core.scan({"oidc.json": {"text": source}}, sources.Budget())
        self.assertFalse(findings)

    def test_spring_registration_explicit_provider_mapping_links_configured_grant(self):
        source = """spring:
  security:
    oauth2:
      client:
        provider:
          company:
            issuer-uri: https://login.example/realms/corp/
          other:
            issuer-uri: https://other.example
        registration:
          backend:
            provider: company
            authorization-grant-type: client_credentials
          unresolved:
            authorization-grant-type: authorization_code
"""
        profile = self.profile(source, "application.yml")
        grants = profile["oauth_grants"]
        self.assertEqual(
            (grants[0]["grant_type"], grants[0]["server"], grants[0]["evidence"]),
            ("client_credentials", "https://login.example", "configured"),
        )
        self.assertIsNone(grants[1]["server"])
        self.assertEqual(
            self.profile("issuer-uri: https://random.example", "arbitrary.yml")[
                "identity_providers"
            ],
            [],
        )

    def test_identity_profile_strips_credentials_path_query_and_fragments(self):
        marker = "SYNTHETIC_PRIVATE_VALUE_DO_NOT_PRINT"
        source = f"import {{auth}} from 'express-openid-connect'; auth({{issuerBaseURL: 'https://user:{marker}@login.example/{marker}?token={marker}#{marker}'}});"
        profile = self.profile(source)
        self.assertEqual(
            profile["identity_providers"][0]["server"], "https://login.example"
        )
        self.assertNotIn(marker, json.dumps(profile))
        self.assertEqual(
            controls.server_identity(
                "https://accounts.google.com.attacker.test/authorize"
            )[1],
            "Custom / unrecognized provider",
        )

    def test_python_header_dict_and_cross_origin_headers_are_positive_only(self):
        source = "headers = {'X-Content-Type-Options': 'nosniff', 'Cross-Origin-Opener-Policy': 'same-origin', 'Cross-Origin-Resource-Policy': 'same-site'}\n"
        findings, checks = core.scan({"server.py": {"text": source}}, sources.Budget())
        self.assertEqual(
            {
                item["detail"]
                for row in checks
                if row["rule"] == "WEB-HEADERS"
                for item in row["locations"]
            },
            {
                "X-Content-Type-Options",
                "Cross-Origin-Opener-Policy",
                "Cross-Origin-Resource-Policy",
            },
        )
        self.assertFalse(findings)
        self.assertIsNone(core.calculate(findings, checks)["score"])

    def test_large_and_malformed_protocol_inputs_are_bounded(self):
        for text in (
            "\n" * 100000,
            "new URLSearchParams(" * 10000 + ")" * 10000,
            "window.location.assign('https://idp.example/?client_id=c&response_type=token&"
            + "x=y&" * 10000
            + "');",
            "const value = 'unterminated",
        ):
            with self.subTest(prefix=text[:35]):
                started = time.monotonic()
                try:
                    self.inspect(text)
                except SyntaxError:
                    pass  # The caller records lexical failure instead of evaluating it.
                self.assertLess(time.monotonic() - started, 3)


if __name__ == "__main__":
    unittest.main()
