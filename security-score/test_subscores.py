"""REQ-03/04/07: observable ranking, evidence boundaries and CLI compatibility."""

import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent / "scripts"))
import score
import score_assessment as assessment
import score_design
import score_profiles
from score_sources import Budget


class Invocation:
    def invoke(self, files, *flags):
        with tempfile.TemporaryDirectory(prefix="subscore-test-") as directory:
            for path, source in files.items():
                target = Path(directory, path)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(source)
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                status = score.main([directory, "--score", "--json", *flags])
            return status, json.loads(out.getvalue())

    def area(self, result, name):
        return next(row for row in result["subscores"] if row["id"] == name)


class SubscoreTests(Invocation, unittest.TestCase):
    def test_one_safe_pattern_does_not_award_a_subscore(self):
        status, result = self.invoke({"app.py": "import ast\nast.literal_eval(value)\n"})
        self.assertEqual(status, 2)
        self.assertEqual(len(result["subscores"]), 5)
        self.assertTrue(all(row["score"] is None for row in result["subscores"]))
        self.assertEqual(result["overall"]["rating"], "Not assessed")
        self.assertFalse({"score", "observed_score", "grade", "areas", "origin_groups"} & result.keys())

    def test_confirmed_disable_retains_bad_rating_despite_missing_context(self):
        status, result = self.invoke({"app.py": "import requests\nrequests.get(url, verify=False)\n"})
        area = self.area(result, "deployment")
        self.assertEqual((area["score"], area["rating"]), (59, "Bad"))
        self.assertEqual(result["overall"]["rating"], "Bad")
        self.assertEqual(status, 2)
        self.assertEqual(area["coverage"], "limited")

    def test_overlapping_tls_rules_deduct_once(self):
        _, result = self.invoke({"app.py": "import ssl\nctx = ssl.create_default_context()\nctx.check_hostname = False\n"})
        area = self.area(result, "deployment")
        self.assertEqual(area["score"], 59)
        self.assertEqual(area["independent_weaknesses"], 1)
        self.assertEqual(set(area["breakdown"][0]["rules"]), {"PY-TLS", "PY-TLS-CONTEXT"})

    def test_password_hash_overlap_has_one_owner_across_domains(self):
        _, result = self.invoke({"app.py": "import hashlib\nast.literal_eval(value)\ncursor.execute('SELECT 1')\nhashed = hashlib.md5(password.encode()).hexdigest()\n"})
        self.assertEqual(self.area(result, "identity")["score"], 59)
        self.assertEqual(self.area(result, "data")["score"], 100)
        self.assertEqual(sum(len(row["breakdown"]) for row in result["subscores"]), 1)
        self.assertEqual(set(self.area(result, "identity")["breakdown"][0]["rules"]), {"PASSWORD-HASH", "PY-HASH"})

    def test_selected_checks_do_not_expand_into_design_inspection(self):
        pod = {"apiVersion": "v1", "kind": "Pod", "spec": {"containers": [{"securityContext": {"privileged": True}}]}}
        _, result = self.invoke({"pod.json": json.dumps(pod)}, "--checks", "PY-EXEC")
        self.assertIsNone(self.area(result, "architecture")["score"])
        self.assertEqual(result["coverage"]["design_checks"], [])

    def test_repeated_independent_weaknesses_continue_to_matter(self):
        values = []
        for count in (1, 2, 3, 4):
            _, result = self.invoke({"app.py": "requests.get(url, verify=False)\n" * count})
            values.append(self.area(result, "deployment")["score"])
        self.assertEqual(values, [59, 39, 25, 15])

    def test_unrelated_passes_do_not_offset_a_serious_weakness(self):
        base = {"app.py": "requests.get(url, verify=False)\n"}
        _, first = self.invoke(base)
        _, second = self.invoke({**base, "other.py": "ast.literal_eval(value)\n" * 100})
        self.assertEqual(self.area(first, "deployment")["score"], self.area(second, "deployment")["score"])

    def test_constant_dynamic_and_external_execution_have_distinct_evidence(self):
        for text, expected, disposition in (
            ("eval('1 + 1')", None, "neutral"),
            ("eval(payload)", None, "review"),
            ("eval(input())", 59, None),
        ):
            with self.subTest(text=text):
                _, result = self.invoke({"app.py": text + "\n"})
                self.assertEqual(self.area(result, "data")["score"], expected)
                if disposition:
                    self.assertEqual(result["review_hints"][0]["disposition"], disposition)

    def test_positive_score_requires_independent_controls_and_no_known_gap(self):
        files = {"app.py": "ast.literal_eval(value)\ncursor.execute('SELECT 1')\n"}
        _, result = self.invoke(files)
        self.assertEqual(self.area(result, "data")["score"], 100)
        _, result = self.invoke({**files, "other.py": "eval(payload)\n"})
        self.assertIsNone(self.area(result, "data")["score"])
        _, result = self.invoke(files, "--checks", "PY-EXEC,PY-SQL")
        self.assertIsNone(self.area(result, "data")["score"])

    def test_new_ranges_make_small_deductions_and_fixes_visible(self):
        def row(severity, index):
            return {"criterion": "sample", "severity": severity, "file": "example", "line": index}
        self.assertEqual(assessment.deductions([row("low", 1)])[0], 97)
        self.assertEqual(assessment.deductions([row("medium", 1)])[0], 88)
        self.assertEqual(assessment.deductions([row("medium", 1), row("medium", 2)])[0], 82)

    def test_design_defect_limits_overall_despite_safe_implementation(self):
        pod = {"apiVersion": "v1", "kind": "Pod", "spec": {
            "volumes": [{"name": "engine", "hostPath": {"path": "/var/run/docker.sock"}}],
            "containers": [{"name": "worker", "volumeMounts": [{"name": "engine", "mountPath": "/engine"}]}],
        }}
        _, result = self.invoke({"pod.json": json.dumps(pod), "app.py": "ast.literal_eval(value)\ncursor.execute('SELECT 1')\n"})
        self.assertEqual(self.area(result, "data")["rating"], "Very good")
        self.assertEqual(self.area(result, "architecture")["rating"], "Bad")
        self.assertEqual(result["overall"]["rating"], "Bad")
        self.assertIn("Architecture", result["overall"]["reason"])
        pod["spec"]["containers"][0]["volumeMounts"] = []
        _, result = self.invoke({"pod.json": json.dumps(pod)})
        self.assertIsNone(self.area(result, "architecture")["score"])

    def test_declared_isolation_does_not_certify_trust_boundaries(self):
        pod = {"apiVersion": "v1", "kind": "Pod", "spec": {"containers": [{"securityContext": {
            "privileged": False, "allowPrivilegeEscalation": False,
            "runAsNonRoot": True, "capabilities": {"drop": ["ALL"]},
        }}]}}
        _, result = self.invoke({"pod.json": json.dumps(pod)})
        area = self.area(result, "architecture")
        self.assertIsNone(area["score"])
        self.assertIn("isolation", area["controls"])
        self.assertTrue(any("trust-boundaries" in gap for gap in area["gaps"]))

    def test_malformed_design_values_never_create_positive_evidence(self):
        for value in ({"apiVersion": []}, {"apiVersion": "v1", "kind": {}},
                      {"apiVersion": "v1", "kind": "Pod", "spec": {"containers": "not a list"}}):
            result = score_design.inspect({"pod.json": {"text": json.dumps(value)}}, Budget())
            self.assertFalse(any(r["status"] == "satisfied" for r in result))

    def test_invalid_combinations_rejected_before_scan(self):
        for flag in ("--staged", "--quiet", "--list-rules"):
            with self.subTest(flag=flag), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as caught:
                    score.main(["--score", flag, "/nonexistent"])
                self.assertEqual(caught.exception.code, 2)

    def test_text_output_keeps_exactly_five_scores_and_no_legacy_partial(self):
        _, result = self.invoke({"app.py": "requests.get(url, verify=False)\n"})
        text = score.render(result)
        self.assertNotIn("partial", text)
        self.assertNotIn("(E)", text)
        self.assertEqual(sum(title in text for title in ("Architecture & isolation", "Identity & access", "Data & processing", "Dependencies & supply chain", "Deployment & operations")), 5)

    def test_terminal_control_sequences_are_encoded_in_new_output(self):
        _, result = self.invoke({"app.py": "requests.get(url, verify=False)\n"})
        self.area(result, "deployment")["breakdown"][0]["file"] = "unsafe\x1b[2J.py"
        self.assertNotIn("\x1b", score.render(result, details=True))

    def test_failure_keeps_findings_but_never_claims_completion(self):
        status, result = self.invoke({"app.py": "requests.get(url, verify=False)\n", "bad.py": "def broken(\n"})
        self.assertEqual(status, 1)
        self.assertEqual(result["verdict"], "incomplete")
        self.assertEqual(self.area(result, "deployment")["score"], 59)
        self.assertIn("Processing incomplete", score.render(result))


class EndpointTests(Invocation, unittest.TestCase):
    def test_spring_properties_and_resource_server_retain_realm_urls(self):
        _, result = self.invoke({"application.properties": "spring.security.oauth2.resourceserver.jwt.issuer-uri=https://login.example/realms/team\n"}, "--details")
        providers = result["architecture"]["identity_providers"]
        self.assertEqual(providers[0]["url"], "https://login.example/realms/team")
        self.assertEqual(providers[0]["technology"], "Keycloak-compatible endpoint")
        self.assertIn(providers[0]["url"], score.render(result, details=True))

    def test_keycloak_adapter_resolves_its_realm_without_discovery(self):
        _, result = self.invoke({"keycloak.json": json.dumps({"auth-server-url": "https://sso.example/auth", "realm": "staff"})})
        self.assertEqual(result["architecture"]["identity_providers"][0]["url"], "https://sso.example/auth/realms/staff")

    def test_maven_literal_property_and_gradle_artifact_repositories(self):
        _, result = self.invoke({
            "pom.xml": '<project><properties><repo.base>https://packages.example</repo.base></properties><repositories><repository><url>${repo.base}/repository/releases/</url></repository></repositories></project>',
            "settings.gradle.kts": 'repositories { maven { url = uri("https://packages.example/artifactory/libs") } }\n',
        })
        repos = result["architecture"]["artifact_repositories"]
        self.assertEqual({r["url"] for r in repos}, {"https://packages.example/repository/releases/", "https://packages.example/artifactory/libs"})
        self.assertEqual({r["evidence"] for r in repos}, {"configured"})

    def test_lockfiles_name_repository_endpoints_not_package_paths(self):
        _, result = self.invoke({"package-lock.json": json.dumps({"packages": {
            "node_modules/demo": {"resolved": "https://packages.example/repository/npm-group/demo/-/demo-1.tgz"}
        }})})
        repos = result["architecture"]["artifact_repositories"]
        self.assertEqual(repos[0]["url"], "https://packages.example/repository/npm-group/")
        self.assertEqual(repos[0]["evidence"], "lockfile")

    def test_endpoints_never_disclose_userinfo_query_or_credential_bearing_paths(self):
        marker = "SYNTHETIC_PRIVATE_VALUE"
        value = f"https://user:{marker}@packages.example/{marker}?token={marker}#{marker}"
        _, result = self.invoke({"requirements.txt": f"--index-url {value}\n", "application.properties": f"quarkus.oidc.auth-server-url={value}\n"})
        self.assertNotIn(marker, json.dumps(result))
        self.assertEqual(score_profiles.endpoint_url("https://sso.example/realms/office"), "https://sso.example/realms/office")

    def test_unresolved_and_duplicate_settings_are_not_guessed(self):
        _, result = self.invoke({"application.properties": "quarkus.oidc.auth-server-url=https://one.example\nquarkus.oidc.auth-server-url=https://two.example\n"})
        self.assertIsNone(result["architecture"]["identity_providers"][0]["url"])

    def test_xml_entities_are_not_loaded(self):
        source = '<!DOCTYPE project [<!ENTITY x SYSTEM "file:///etc/passwd">]><project><repositories><repository><url>&x;</url></repository></repositories></project>'
        self.assertEqual(score_profiles.artifact_repositories({"pom.xml": {"text": source}}, Budget()), [])

    def test_maven_mirror_urls_are_recognized_without_server_credentials(self):
        _, result = self.invoke({"settings.xml": '<settings><servers><server><password>SYNTHETIC_PRIVATE_VALUE</password></server></servers><mirrors><mirror><url>https://packages.example/repository/public/</url></mirror></mirrors></settings>'})
        self.assertEqual(result["architecture"]["artifact_repositories"][0]["url"], "https://packages.example/repository/public/")
        self.assertNotIn("SYNTHETIC_PRIVATE_VALUE", json.dumps(result))

    def test_sensitive_repository_config_remains_unread_and_visible_as_gap(self):
        _, result = self.invoke({".npmrc": "registry=https://packages.example/\n_authToken=SYNTHETIC_PRIVATE_VALUE\n"})
        self.assertFalse(result["architecture"]["artifact_repositories"])
        self.assertEqual(result["architecture"]["artifact_repository_gaps"][0]["file"], ".npmrc")
        self.assertNotIn("SYNTHETIC_PRIVATE_VALUE", json.dumps(result))

    def test_unrelated_or_ambiguous_repository_urls_are_not_claimed(self):
        for path, text in (
            ("build.gradle", 'task docs { def url = "https://docs.example/artifactory/usage/" }'),
            ("pyproject.toml", '[[tool.poetry.source]]\nurl="https://one.example"\nurl="https://two.example"\n'),
            ("pom.xml", '<project><repositories><repository><url>https://one.example</url><url>https://two.example</url></repository></repositories></project>'),
        ):
            with self.subTest(path=path):
                self.assertEqual(score_profiles.artifact_repositories({path: {"text": text}}, Budget()), [])


class ArchitectureAndSupplyChainTests(Invocation, unittest.TestCase):
    def test_terraform_declared_cloud_resources_region_backend_and_controls(self):
        source = '''provider "aws" {
  region = "eu-central-1"
}
terraform {
  backend "s3" {
    bucket = "SYNTHETIC_PRIVATE_VALUE"
    encrypt = true
    use_lockfile = true
  }
}
resource "aws_ecs_service" "app" {}
resource "aws_db_instance" "db" {
  publicly_accessible = false
  storage_encrypted = true
}
resource "aws_security_group" "entry" {
  ingress {
    cidr_blocks = ["0.0.0.0/0"]
    from_port = 443
    to_port = 443
  }
}
'''
        _, result = self.invoke({"main.tf": source})
        profile = result["architecture"]["iac"]
        self.assertEqual(profile["providers"][0]["region"], "eu-central-1")
        self.assertEqual({r["category"] for r in profile["resources"]}, {"container workload", "database", "network / ingress"})
        self.assertEqual(profile["state_backends"][0]["type"], "s3")
        self.assertEqual(profile["state_backends"][0]["locking"], "declared")
        db = next(row for row in profile["resources"] if row["category"] == "database")
        self.assertEqual(db["properties"]["storage-encryption"], "enabled")
        self.assertNotIn("SYNTHETIC_PRIVATE_VALUE", json.dumps(profile))
        rendered = score.render(result, details=True)
        self.assertIn("Declared deployment targets: AWS, Terraform", rendered)
        self.assertIn("AWS region: eu-central-1", rendered)
        self.assertIn("Terraform state backend: s3", rendered)

    def test_iac_comments_heredocs_and_dynamic_values_do_not_establish_facts(self):
        source = '''/* provider "aws" {} */
locals {
  example = <<EOT
provider "azurerm" {}
resource "aws_db_instance" "fake" {}
EOT
}
provider "google" { region = var.region }
resource "google_sql_database_instance" "db" {
  publicly_accessible = var.public
}
'''
        _, result = self.invoke({"main.tf": source})
        profile = result["architecture"]["iac"]
        self.assertEqual([row["technology"] for row in profile["providers"]], ["GCP"])
        self.assertIsNone(profile["providers"][0]["region"])
        self.assertEqual(len(profile["resources"]), 1)
        self.assertEqual(profile["resources"][0]["properties"]["public-access"], "unresolved")
        self.assertNotIn("AWS", {r["technology"] for r in result["architecture"]["deployment"]})

    def node_files(self):
        import base64

        return {
            "package.json": json.dumps({"dependencies": {"example": "1.0.0"}}),
            "package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {
                "": {"dependencies": {"example": "1.0.0"}},
                "node_modules/example": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/example/-/example-1.0.0.tgz", "integrity": "sha512-" + base64.b64encode(b"\x00" * 64).decode()},
            }}),
            ".github/workflows/build.yml": "jobs:\n  build:\n    steps:\n      - run: npm ci\n",
        }

    def test_node_quality_combines_lock_consistency_integrity_and_ci(self):
        _, result = self.invoke(self.node_files())
        profile = result["architecture"]["supply_chain"][0]
        statuses = {r["criterion"]: r["status"] for r in profile["controls"]}
        self.assertEqual(statuses["node-lock-consistency"], "supported")
        self.assertEqual(statuses["node-artifact-integrity"], "supported")
        self.assertEqual(statuses["node-locked-install"], "supported")
        self.assertEqual(self.area(result, "dependencies")["score"], 100)

    def test_node_manifest_drift_withholds_positive_dependency_score(self):
        files = self.node_files()
        files["package.json"] = json.dumps({"dependencies": {"example": "2.0.0"}})
        _, result = self.invoke(files)
        self.assertIsNone(self.area(result, "dependencies")["score"])
        self.assertTrue(any(row["rule"] == "SC-NODE-LOCK-CONSISTENCY" for row in self.area(result, "dependencies")["breakdown"]))

    def test_printed_install_command_is_not_enforcement(self):
        files = self.node_files()
        files[".github/workflows/build.yml"] = "jobs:\n  build:\n    steps:\n      - run: echo 'npm ci'\n"
        _, result = self.invoke(files)
        profile = result["architecture"]["supply_chain"][0]
        status = next(row["status"] for row in profile["controls"] if row["criterion"] == "node-locked-install")
        self.assertEqual(status, "not_assessed")
        self.assertIsNone(self.area(result, "dependencies")["score"])

    def test_python_hash_declarations_need_enforced_installation(self):
        files = {"requirements.txt": "example==1.0.0 --hash=sha256:" + "a" * 64 + "\n"}
        _, first = self.invoke(files)
        self.assertIsNone(self.area(first, "dependencies")["score"])
        files["Dockerfile"] = "FROM example@sha256:" + "a" * 64 + "\nRUN python -m pip install --require-hashes -r requirements.txt\n"
        _, result = self.invoke(files)
        profile = result["architecture"]["supply_chain"][0]
        statuses = {r["criterion"]: r["status"] for r in profile["controls"]}
        self.assertEqual(statuses["python-version-pins"], "supported")
        self.assertEqual(statuses["python-artifact-hashes"], "supported")
        self.assertEqual(statuses["python-locked-install"], "supported")
        self.assertEqual(self.area(result, "dependencies")["score"], 100)

    def test_install_examples_dry_runs_and_disabled_flags_are_not_enforcement(self):
        for command in ("npm exec -- echo 'npm ci'", "npm ci --dry-run", "npm ci --help",
                        "pnpm exec echo 'pnpm install --frozen-lockfile'",
                        "pnpm install --frozen-lockfile --frozen-lockfile=false"):
            with self.subTest(command=command):
                files = self.node_files()
                files[".github/workflows/build.yml"] = "jobs:\n  build:\n    steps:\n      - run: " + command + "\n"
                _, result = self.invoke(files)
                controls = result["architecture"]["supply_chain"][0]["controls"]
                self.assertEqual(next(c["status"] for c in controls if c["criterion"] == "node-locked-install"), "not_assessed")
                self.assertIsNone(self.area(result, "dependencies")["score"])

    def test_resolved_node_version_must_satisfy_manifest_constraint(self):
        for constraint, version in (("1.0.0", "9.0.0"), ("^1.0.0", "2.0.0"), ("~1.1.0", "1.2.0"), ("^0.1.0", "0.2.0")):
            with self.subTest(constraint=constraint):
                files = self.node_files()
                files["package.json"] = json.dumps({"dependencies": {"example": constraint}})
                lock = json.loads(files["package-lock.json"])
                lock["packages"][""]["dependencies"]["example"] = constraint
                lock["packages"]["node_modules/example"]["version"] = version
                files["package-lock.json"] = json.dumps(lock)
                _, result = self.invoke(files)
                self.assertIsNone(self.area(result, "dependencies")["score"])
                self.assertTrue(any(r["rule"] == "SC-NODE-LOCK-CONSISTENCY" for r in self.area(result, "dependencies")["breakdown"]))

    def test_duplicate_lock_keys_cannot_establish_supply_chain_controls(self):
        files = self.node_files()
        files["package-lock.json"] = files["package-lock.json"].replace('"version": "1.0.0"', '"version": "9.0.0", "version": "1.0.0"')
        _, result = self.invoke(files)
        self.assertIsNone(self.area(result, "dependencies")["score"])
        controls = result["architecture"]["supply_chain"][0]["controls"]
        self.assertNotEqual(next(c["status"] for c in controls if c["criterion"] == "node-artifact-integrity"), "supported")

    def test_install_evidence_must_apply_to_assessed_dependencies(self):
        for command in ("npm ci --prefix tooling", "npm ci --cwd tooling"):
            files = self.node_files()
            files[".github/workflows/build.yml"] = "jobs:\n  build:\n    steps:\n      - run: " + command + "\n"
            _, result = self.invoke(files)
            self.assertIsNone(self.area(result, "dependencies")["score"])
        files = self.node_files()
        files[".github/workflows/build.yml"] = "jobs:\n  build:\n    steps:\n      - if: false\n        run: npm ci\n"
        _, result = self.invoke(files)
        self.assertIsNone(self.area(result, "dependencies")["score"])
        files = {"requirements.txt": "example==1.0.0 --hash=sha256:" + "a" * 64 + "\n",
                 "Dockerfile": "FROM scratch\nRUN pip install --require-hashes -r docs/requirements.txt\n"}
        _, result = self.invoke(files)
        self.assertIsNone(self.area(result, "dependencies")["score"])

    def test_missing_or_short_python_hashes_do_not_receive_positive_score(self):
        for suffix in ("", " --hash=sha256:abc"):
            files = {"requirements.txt": "example==1.0.0" + suffix + "\n",
                     "Dockerfile": "FROM scratch\nRUN pip install --require-hashes -r requirements.txt\n"}
            _, result = self.invoke(files)
            self.assertIsNone(self.area(result, "dependencies")["score"])
            self.assertTrue(any("artifact integrity" in gap for gap in self.area(result, "dependencies")["gaps"]))

    def test_terraform_tags_examples_and_duplicate_flags_do_not_establish_controls(self):
        source = '''resource "aws_db_instance" "db" {
  tags = {
    encrypted = true
    publicly_accessible = false
    deletion_protection = true
  }
  description = "encrypted = true"
  storage_encrypted = true
  storage_encrypted = false
}
terraform {
  backend "s3" {
    key = "use_lockfile = true"
    use_lockfile = true
    use_lockfile = false
  }
}
'''
        _, result = self.invoke({"main.tf": source})
        profile = result["architecture"]["iac"]
        self.assertEqual(profile["resources"][0]["properties"], {"storage-encryption": "unresolved"})
        self.assertEqual(profile["state_backends"][0]["locking"], "not established")

    def test_terraform_json_extracts_only_direct_declared_properties(self):
        source = {"provider": {"aws": {"region": "eu-west-1"}},
                  "terraform": {"backend": {"s3": {"encrypt": True, "use_lockfile": True}}},
                  "resource": {"aws_db_instance": {"db": {"storage_encrypted": True, "tags": {"publicly_accessible": False}}}}}
        _, result = self.invoke({"main.tf.json": json.dumps(source)})
        profile = result["architecture"]["iac"]
        self.assertEqual(profile["providers"][0]["region"], "eu-west-1")
        self.assertEqual(profile["resources"][0]["properties"], {"storage-encryption": "enabled"})
        self.assertEqual(profile["state_backends"][0]["locking"], "declared")

    def test_terraform_trailing_list_comma_and_azure_location(self):
        _, result = self.invoke({"main.tf": '''resource "google_compute_firewall" "entry" {
  source_ranges = ["0.0.0.0/0",]
}
resource "azurerm_linux_web_app" "app" {
  location = "West Europe"
}
'''})
        rows = result["architecture"]["iac"]["resources"]
        self.assertIn("network-source", rows[0]["properties"])
        self.assertEqual(rows[1]["category"], "managed web application")
        self.assertEqual(rows[1]["properties"]["deployment-location"], "West Europe")


if __name__ == "__main__":
    unittest.main()
