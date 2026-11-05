"""REQ-26: supported architecture flows, controls, evidence and scope limits."""

import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent / "scripts"))
from score_boundaries import inspect
from score_sources import Budget
from test_subscores import Invocation
import score


PRELUDE = """import { type Request } from 'express'
import { Sequelize } from 'sequelize'
const db = new Sequelize('sqlite::memory:')
"""


class ArchitectureBoundaryTests(Invocation, unittest.TestCase):
    def evidence(self, body, *, prelude=PRELUDE):
        text = prelude + "export function handler(req: Request) {\n" + body + "\n}\n"
        return inspect({"app.ts": {"text": text}}, Budget())

    def test_direct_request_interpolation_and_concatenation_establish_a_boundary_weakness(self):
        for query in ("`SELECT * FROM users WHERE id = '${req.params.id}'`", "'SELECT * FROM users WHERE id = ' + req.params.id"):
            with self.subTest(query=query):
                rows = self.evidence(f"db.query({query})")
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]["status"], "violated")
                self.assertEqual(rows[0]["source"]["file"], "app.ts")
                self.assertEqual(rows[0]["database_declaration"]["file"], "app.ts")

    def test_one_unchanged_local_alias_is_followed(self):
        rows = self.evidence("const value = req.params.id\ndb.query(`SELECT * FROM users WHERE id = '${value}'`)")
        self.assertEqual(rows[0]["status"], "violated")

    def test_a_reassigned_alias_or_nested_shadow_never_establishes_a_flow(self):
        for body in (
            "let value = req.params.id\nvalue = 'fixed'\ndb.query(`SELECT ${value}`)",
            "items.map((req) => { db.query(`SELECT ${req.body.id}`) })",
            "items.map((req) => db.query(`SELECT ${req.body.id}`))",
            "items.map(req => db.query(`SELECT ${req.body.id}`))",
            "const db = unrelated\ndb.query(`SELECT ${req.body.id}`)",
        ):
            with self.subTest(body=body):
                self.assertFalse(self.evidence(body))

    def test_parameter_binding_establishes_one_control_without_manufacturing_a_complete_score(self):
        body = "db.query('SELECT * FROM users WHERE id = :id', { replacements: { id: req.params.id } })"
        self.assertEqual(self.evidence(body)[0]["status"], "satisfied")
        _, result = self.invoke({"app.ts": PRELUDE + "function handler(req: Request) { " + body + " }"})
        architecture = self.area(result, "architecture")
        self.assertIn("query-binding", architecture["controls"])
        self.assertIsNone(architecture["score"])

    def test_pg_binding_with_import_and_request_aliases(self):
        source = "import { type Request as Incoming } from 'express'\nimport { Pool as Database } from 'pg'\nconst conn = new Database()\nfunction handler(input: Incoming) { conn.query('SELECT * FROM users WHERE id = $1', [input.params.id]) }"
        rows = inspect({"app.ts": {"text": source}}, Budget())
        self.assertEqual(rows[0]["status"], "satisfied")

    def test_unknown_protection_remains_reviewable_instead_of_becoming_a_weakness(self):
        for query in (
            "`SELECT * FROM users WHERE id = '${escapeSql(req.params.id)}'`",
            "sql`SELECT * FROM users WHERE id = ${req.params.id}`",
            "prepare(`SELECT ${req.params.id}`)",
            "buildQuery(req.params.id)",
        ):
            with self.subTest(query=query):
                rows = self.evidence(f"db.query({query})")
                self.assertEqual(rows[0]["status"], "unclear")

    def test_preceding_validation_and_rewritten_request_values_are_not_reported_as_confirmed_weaknesses(self):
        for prefix in (
            "if (!/^\\d+$/.test(req.params.id)) { throw new Error('invalid') }\n",
            "req.params.id = validate(req.params.id)\n",
        ):
            with self.subTest(prefix=prefix):
                rows = self.evidence(prefix + "db.query(`SELECT ${req.params.id}`)")
                self.assertEqual(rows[0]["status"], "unclear")

    def test_a_shadowed_driver_constructor_never_establishes_a_database(self):
        text = PRELUDE + "function handler(req: Request, Sequelize: unknown) { const other = new Sequelize(); other.query(`SELECT ${req.body.id}`) }"
        self.assertFalse(inspect({"app.ts": {"text": text}}, Budget()))

    def test_validation_of_a_local_request_alias_stays_reviewable(self):
        rows = self.evidence("const value = req.params.id\nif (!/^\\d+$/.test(value)) { throw new Error('invalid') }\ndb.query(`SELECT ${value}`)")
        self.assertEqual(rows[0]["status"], "unclear")

    def test_constants_comments_strings_and_unrelated_methods_add_no_architecture_credit(self):
        for body in (
            "db.query('SELECT 1')",
            "// db.query(`SELECT ${req.body.id}`)\ndb.query('SELECT 1')",
            "const example = 'db.query(`SELECT ${req.body.id}`)'",
            "other.query(`SELECT ${req.body.id}`)",
        ):
            with self.subTest(body=body):
                self.assertFalse(self.evidence(body))
        self.assertFalse(self.evidence("db.query(`SELECT ${req.body.id}`)", prelude="const db = unrelated\n"))

    def test_relative_database_export_is_resolved_from_selected_sources_only(self):
        files = {
            "routes/app.ts": {"text": "import { type Request } from 'express'\nimport * as models from '../models'\nfunction handler(req: Request) { models.db.query(`SELECT ${req.body.id}`) }"},
            "models/index.ts": {"text": "import { Sequelize } from 'sequelize'\nexport const db = new Sequelize('sqlite::memory:')"},
        }
        self.assertEqual(inspect(files, Budget())[0]["status"], "violated")
        self.assertFalse(inspect({"routes/app.ts": files["routes/app.ts"]}, Budget()))
        files["models/index.ts"]["fragment"] = True
        self.assertFalse(inspect(files, Budget()))

    def test_exported_factory_and_typed_setter_preserve_a_recognized_database(self):
        files = {
            "app.ts": {"text": "import { type Request } from 'express'\nimport { db } from './database'\nfunction handler(req: Request) { db.query(`SELECT ${req.body.id}`) }"},
            "database.ts": {"text": "import { Sequelize } from 'sequelize'\nlet db = create()\nfunction create() { return new Sequelize('sqlite::memory:') }\nfunction set(value: Sequelize) { db = value }\nexport { db, set }"},
        }
        self.assertEqual(inspect(files, Budget())[0]["status"], "violated")
        files["database.ts"]["text"] = files["database.ts"]["text"].replace("value: Sequelize", "value: unknown")
        self.assertFalse(inspect(files, Budget()))

    def test_architecture_score_is_negative_and_the_underlying_query_is_counted_once(self):
        source = PRELUDE + "function handler(req: Request) { db.query(`SELECT ${req.body.id}`) }"
        status, result = self.invoke({"app.ts": source})
        self.assertEqual(status, 2)
        architecture = self.area(result, "architecture")
        self.assertEqual(architecture["score"], 59)
        self.assertEqual(architecture["independent_weaknesses"], 1)
        self.assertEqual(set(architecture["breakdown"][0]["rules"]), {"JS-SQL", "DESIGN-DATA-BOUNDARY"})
        self.assertEqual(sum(len(row["breakdown"]) for row in result["subscores"]), 1)
        self.assertTrue(architecture["limitations"])
        self.assertIn("HTTP request data", score.render(result, details=True))

    def test_custom_check_selection_does_not_run_supplemental_boundary_checks(self):
        _, result = self.invoke({"app.ts": PRELUDE + "function handler(req: Request) { db.query(`SELECT ${req.body.id}`) }"}, "--checks", "JS-SQL")
        self.assertEqual(result["boundary_evidence"], [])
        self.assertIsNone(self.area(result, "architecture")["score"])

    def test_repeated_independent_flows_and_complete_positive_controls(self):
        source = PRELUDE + "function handler(req: Request) {\n" + "db.query(`SELECT ${req.body.id}`)\n" * 2 + "}"
        _, result = self.invoke({"app.ts": source})
        self.assertEqual(self.area(result, "architecture")["score"], 39)
        pod = {"apiVersion": "v1", "kind": "Pod", "spec": {"containers": [{"securityContext": {
            "privileged": False, "allowPrivilegeEscalation": False, "runAsNonRoot": True,
            "capabilities": {"drop": ["ALL"]},
        }}]}}
        _, result = self.invoke({"pod.json": json.dumps(pod)})
        self.assertEqual(self.area(result, "architecture")["score"], 100)
        self.assertEqual(result["overall"]["rating"], "Not assessed")
        guarded_source = PRELUDE + "function handler(req: Request) { db.query(buildQuery(req.body.id)) }"
        _, result = self.invoke({"pod.json": json.dumps(pod), "app.ts": guarded_source})
        self.assertIsNone(self.area(result, "architecture")["score"])

    def test_unbalanced_input_and_patch_fragments_do_not_establish_protection(self):
        text = PRELUDE + "function handler(req: Request) { db.query('SELECT 1', [req.body.id]) }"
        for source in ({"text": text[:-1]}, {"text": text, "fragment": True}):
            self.assertFalse(inspect({"app.ts": source}, Budget()))

    def test_source_literals_and_request_values_do_not_reach_boundary_evidence(self):
        marker = "SYNTHETIC_PRIVATE_VALUE"
        prelude = PRELUDE.replace("sqlite::memory:", marker)
        rows = self.evidence(f"db.query(`SELECT '{marker}' WHERE id = '${{req.params.id}}'`)", prelude=prelude)
        self.assertTrue(rows)
        self.assertNotIn(marker, json.dumps(rows))

    def test_host_network_and_unreviewed_host_mounts_cannot_receive_positive_isolation_scores(self):
        context = {"privileged": False, "allowPrivilegeEscalation": False, "runAsNonRoot": True,
                   "capabilities": {"drop": ["ALL"]}}
        for spec, expected in (
            ({"hostNetwork": True, "containers": [{"securityContext": context}]}, 59),
            ({"volumes": [{"name": "host", "hostPath": {"path": "/etc"}}],
              "containers": [{"securityContext": context, "volumeMounts": [{"name": "host", "mountPath": "/config"}]}]}, None),
        ):
            with self.subTest(spec=spec):
                pod = {"apiVersion": "v1", "kind": "Pod", "spec": spec}
                _, result = self.invoke({"pod.json": json.dumps(pod)})
                self.assertEqual(self.area(result, "architecture")["score"], expected)


if __name__ == "__main__":
    unittest.main()
