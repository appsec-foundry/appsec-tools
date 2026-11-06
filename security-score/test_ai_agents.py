"""AI & agents area: model-output flows, agent configuration and applicability."""

import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest

sys.path.insert(0, str(Path(__file__).parent / "scripts"))
import score
from score_core import scan
from score_sources import Budget


OPENAI_JS = "import OpenAI from 'openai';\nconst client = new OpenAI();\n"
OPENAI_PY = "from openai import OpenAI\nclient = OpenAI()\n"


def observed(files, rule):
    _, checks = scan({path: {"text": text} for path, text in files.items()}, Budget())
    return sorted(
        (row["file"], location["line"], location["status"])
        for row in checks
        if row["rule"] == rule
        for location in row["locations"]
    )


def invoke(files, *flags):
    with tempfile.TemporaryDirectory(prefix="ai-test-") as directory:
        for path, text in files.items():
            target = Path(directory, path)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            status = score.main([directory, *flags])
        return status, out.getvalue()


def area(result, name):
    return next(row for row in result["subscores"] if row["id"] == name)


def inventory(files):
    _, checks = scan({path: {"text": text} for path, text in files.items()}, Budget())
    return [(check["file"], row["line"], row.get("detail", ""))
            for check in checks if check["rule"] == "AI-INTEGRATION"
            for row in check["locations"]]


class ModelProfileTests(unittest.TestCase):
    def test_vercel_model_factory_options_and_provider_api(self):
        source = (
            "import { streamText, stepCountIs } from 'ai';\n"
            "import { openai } from '@ai-sdk/openai';\n"
            "const reply = streamText({model: openai('gpt-example'), messages,\n"
            "  temperature: 0.2, maxOutputTokens: 512, toolChoice: 'required',\n"
            "  stopWhen: stepCountIs(10), maxRetries: retryCount});\n"
        )
        rows = inventory({"chat.ts": source})
        self.assertIn(("chat.ts", 2, "provider API: OpenAI-compatible"), rows)
        self.assertIn(("chat.ts", 3, "model: gpt-example"), rows)
        self.assertIn(("chat.ts", 3, "call options: temperature=0.2, maxOutputTokens=512, toolChoice=required, stopWhen=stepCountIs(10), maxRetries=unresolved"), rows)

    def test_python_direct_models_environment_and_constructor(self):
        source = (
            "from openai import OpenAI\nimport os\n"
            "from langchain_anthropic import ChatAnthropic\n"
            "a = OpenAI().responses.create(model='gpt-example', max_output_tokens=500, stream=True)\n"
            "b = OpenAI().responses.create(model=os.getenv('LLM_MODEL'), input=prompt)\n"
            "c = ChatAnthropic(model_name='claude-example', temperature=0)\n"
        )
        rows = inventory({"chat.py": source})
        for row in (
            ("chat.py", 1, "provider API: OpenAI-compatible"),
            ("chat.py", 3, "provider API: Anthropic"),
            ("chat.py", 4, "model: gpt-example"),
            ("chat.py", 4, "call options: max_output_tokens=500, stream=true"),
            ("chat.py", 5, "model: environment LLM_MODEL (unresolved)"),
            ("chat.py", 6, "model: claude-example"),
        ):
            self.assertIn(row, rows)

    def test_js_constructor_and_dynamic_models_do_not_invent_a_model(self):
        source = (
            "import { ChatOllama } from '@langchain/ollama';\n"
            "const llm = new ChatOllama({model: 'llama-example:8b'});\n"
            "llm.invoke(prompt);\n"
            "llm.invoke({model: process.env.LLM_MODEL});\n"
            "llm.invoke({model: config.get<string>('ai.model')});\n"
        )
        rows = inventory({"chat.ts": source})
        self.assertIn(("chat.ts", 1, "provider API: Ollama"), rows)
        self.assertIn(("chat.ts", 2, "model: llama-example:8b"), rows)
        self.assertIn(("chat.ts", 3, "model: unresolved (options or model not literal)"), rows)
        self.assertIn(("chat.ts", 4, "model: environment LLM_MODEL (unresolved)"), rows)
        self.assertIn(("chat.ts", 5, "model: config ai.model (unresolved)"), rows)

    def test_spreads_duplicates_computed_fields_and_large_objects_stay_unresolved(self):
        for fields in (
            "model: 'visible', ...options", "...options, model: 'visible'",
            "model: 'visible', model: other", "['model']: 'visible'",
            "model: 'visible', prompt: '" + "x" * 9000 + "'",
        ):
            with self.subTest(fields=fields[:80]):
                rows = inventory({"chat.js": OPENAI_JS + f"client.responses.create({{{fields}}});\n"})
                self.assertTrue(any("model: unresolved" in row[2] for row in rows))
                self.assertFalse(any("model: visible" == row[2] for row in rows))
        rows = inventory({"chat.py": OPENAI_PY + "client.responses.create(model='visible', **options)\n"})
        self.assertIn(("chat.py", 3, "model: unresolved (options or model not literal)"), rows)

    def test_comments_strings_and_non_ai_files_are_not_model_evidence(self):
        source = (OPENAI_JS + "// client.responses.create({model: 'fake-one'});\n"
                  "const text = `client.responses.create({model: 'fake-two'})`;\n"
                  "// import ollama from 'ollama';\n")
        rows = inventory({"chat.js": source, "unrelated.js": "client.responses.create({model: 'fake-three'});"})
        self.assertFalse(any("fake-" in row[2] or "Ollama" in row[2] for row in rows))

    def test_yaml_configuration_models_and_endpoint_class_have_locations(self):
        files = {"config/default.yml": "application:\n  chatBot:\n    model: 'gemma-example:4b'\n    llmApiUrl: 'http://localhost:11434/v1?key=private-query'\n    llmMaxRetries: 2\n"}
        rows = inventory(files)
        self.assertIn(("config/default.yml", 3, "configured model: gemma-example:4b (declared)"), rows)
        self.assertIn(("config/default.yml", 4, "model endpoint: loopback HTTP (declared)"), rows)
        self.assertNotIn("private-query", str(rows))
        _, output = invoke(files, "--json")
        ai = area(json.loads(output), "ai")
        self.assertTrue(ai["applicable"])
        self.assertIsNone(ai["score"])
        self.assertEqual(ai["controls"], [])

    def test_json_configuration_is_document_evidence_and_not_merged(self):
        files = {
            "config/a.json": '{"llm":{"model":"first-model","base_url":"https://llm.example/v1"}}',
            "config/b.json": '{"llm":{"model":"second-model"}}',
        }
        rows = inventory(files)
        self.assertIn(("config/a.json", 1, "configured model: first-model (declared)"), rows)
        self.assertIn(("config/b.json", 1, "configured model: second-model (declared)"), rows)
        self.assertIn(("config/a.json", 1, "model endpoint: non-loopback HTTPS (declared)"), rows)

    def test_endpoint_classes_require_literal_valid_http_destinations(self):
        for endpoint, label in (
            ("http://[::1]:11434/v1", "loopback HTTP (declared)"),
            ("https://llm.example:8443/v1", "non-loopback HTTPS (declared)"),
            ("http://${LLM_HOST}/v1", "unresolved"),
            ("http://localhost:99999/v1", "unresolved"),
            ("http://localhost:0/v1", "unresolved"),
            ("file:///private/path", "unresolved"),
            ("http://user:pass@localhost/v1", "unresolved"),
            ("http://localhost\n.example/v1", "unresolved"),
        ):
            with self.subTest(endpoint=endpoint):
                rows = inventory({"config/llm.json": json.dumps({"llm": {"endpoint": endpoint}})})
                self.assertIn(("config/llm.json", 1, "model endpoint: " + label), rows)

    def test_configuration_does_not_read_unrelated_models_or_unsafe_yaml(self):
        for text in (
            "database:\n  model: private-value\n",
            "llm:\n  prompt: |\n    model: private-value\n",
            "llm:\n  tools:\n    model: private-value\n",
            "llm: !custom\n  model: private-value\n",
            "llm:\n  model: !python/object:private-value\n",
            "llm:\n  model: first\n  model: private-value\n",
            "llm:\n  model: &alias private-value\n",
        ):
            with self.subTest(text=text):
                self.assertNotIn("private-value", str(inventory({"config/default.yml": text})))
        self.assertEqual(inventory({"data/models.yml": "llm:\n  model: unselected\n"}), [])
        self.assertEqual(inventory({"config/default.json": '{"llm":{"model":"first","model":"private-value"}}'}), [])

    def test_inventory_omits_prompts_credentials_urls_and_terminal_controls(self):
        sensitive = ["sk-" + "XyZ123" * 8, "person@example.test", "https://private.example/model", "name\x1b[2J"]
        for value in sensitive:
            files = {
                "chat.js": OPENAI_JS + "client.responses.create({model: " + json.dumps(value) + ", input: 'private-prompt', apiKey: 'private-key'});\n",
                "chat.py": OPENAI_PY + "client.responses.create(model=" + repr(value) + ", input='private-prompt')\n",
                "config/default.json": json.dumps({"llm": {"model": value, "apiKey": "private-key", "endpoint": "https://user:private-password@private.example/?key=private-query"}}),
            }
            for flags in (("--json",), ("--details",), ("--yaml",)):
                with self.subTest(value=value, flags=flags):
                    _, output = invoke(files, *flags)
                    for hidden in (value, "private-prompt", "private-key", "private-password", "private-query"):
                        self.assertNotIn(hidden, output)

    def test_profile_details_and_structured_modes_keep_same_security_result(self):
        files = {"chat.js": OPENAI_JS + "client.responses.create({model: 'example-model', max_output_tokens: 512});\n"}
        status, output = invoke(files, "--details")
        self.assertRegex(output, r"(?m)^ +API +OpenAI-compatible$")
        self.assertRegex(output, r"(?m)^ +Model \(code\) +example-model$")
        self.assertRegex(output, r"(?m)^ +Limits +output tokens 512$")
        plain_status, plain = invoke(files, "--json")
        detail_status, detailed = invoke(files, "--json", "--details")
        self.assertEqual((status, plain_status, detail_status), (2, 2, 2))
        plain, detailed = json.loads(plain), json.loads(detailed)
        for key in ("subscores", "overall", "checks", "findings"):
            self.assertEqual(plain[key], detailed[key])

    def test_compact_profile_keeps_essential_declarations_and_full_structured_evidence(self):
        files = {
            "chat.ts": "import { streamText, tool, stepCountIs } from 'ai';\n"
                       "import { createOpenAICompatible } from '@ai-sdk/openai-compatible';\n"
                       "const tools = { searchProducts: tool({execute: search}) };\n"
                       "streamText({model: provider(model), tools, maxRetries: retries,\n"
                       "  temperature: 0.2, stopWhen: stepCountIs(10)});\n",
            "config/default.yml": "chatBot:\n  model: 'gemma-example:4b'\n  llmApiUrl: http://localhost:11434/v1\n",
            "config/test.yml": "chatBot:\n  llmApiUrl: http://localhost:11434/v1\n",
        }
        _, output = invoke(files, "--details")
        profile = output.split("AI profile:", 1)[1].split("\nCoverage", 1)[0]
        self.assertEqual([line.strip() for line in profile.splitlines() if line.strip()], [
            "Model (config)  gemma-example:4b",
            "API             OpenAI-compatible; loopback HTTP",
            "Limits          steps 10",
            "Tools           searchProducts",
        ])
        for omitted in ("unresolved", "SDK imports", "Model calls", "maxRetries", "temperature", "chat.ts:", "config/test.yml"):
            self.assertNotIn(omitted, profile)
        _, output = invoke(files, "--json")
        checks = [check for check in json.loads(output)["checks"] if check["rule"] == "AI-INTEGRATION"]
        details = [row.get("detail", "") for check in checks for row in check["locations"]]
        self.assertIn("model: unresolved (dynamic expression)", details)
        self.assertIn("call options: maxRetries=unresolved, temperature=0.2, stopWhen=stepCountIs(10)", details)
        self.assertEqual(sum("model endpoint: loopback HTTP (declared)" == detail for detail in details), 2)


class ModelOutputFlowTests(unittest.TestCase):
    def test_model_output_is_followed_within_its_scope_only(self):
        source = OPENAI_JS + (
            "async function answer(question, el) {\n"
            "  const reply = await client.chat.completions.create({ model, messages: [question] });\n"
            "  const text = reply.choices[0].message.content;\n"
            "  el.innerHTML = text;\n"
            "}\n"
            "async function page(el) {\n"
            "  const text = await fetch('/page').then(r => r.text());\n"
            "  el.innerHTML = text;\n"
            "}\n"
        )
        self.assertEqual(observed({"chat.js": source}, "AI-OUTPUT-HTML"), [("chat.js", 6, "violated")])

    def test_html_sink_needs_every_model_value_sanitized(self):
        base = OPENAI_JS + "const reply = await client.responses.create({ model, input });\nconst text = reply.output_text;\n"
        cases = (
            ("el.innerHTML = DOMPurify.sanitize(text);\n", [5], "satisfied"),
            ("el.innerHTML = DOMPurify.sanitize(intro) + text;\n", [5], "violated"),
            ("const safe = DOMPurify.sanitize(text);\nel.innerHTML = safe;\n", [6], "satisfied"),
            ("el.textContent = text;\n", [5], "satisfied"),
        )
        for tail, lines, status in cases:
            with self.subTest(tail=tail):
                rows = observed({"a.js": base + tail}, "AI-OUTPUT-HTML")
                self.assertEqual(rows, [("a.js", line, status) for line in lines])

    def test_model_text_in_query_text_violates_and_bound_parameter_satisfies(self):
        base = OPENAI_JS + "const { text } = await generateText({ model, prompt });\n"
        built = base + "await db.query(`SELECT * FROM tags WHERE name = '${text}'`);\n"
        bound = base + "await db.query('SELECT * FROM tags WHERE name = $1', [text]);\n"
        self.assertEqual(observed({"q.js": built}, "AI-OUTPUT-EXEC"), [("q.js", 4, "violated")])
        self.assertEqual(observed({"q.js": bound}, "AI-OUTPUT-EXEC"), [("q.js", 4, "satisfied")])
        argv = base + "spawn('git', ['log', text]);\nspawn(text, { shell: true });\n"
        self.assertEqual(observed({"q.js": argv}, "AI-OUTPUT-EXEC"), [("q.js", 5, "violated")])

    def test_python_flows_reach_shell_and_sql_but_not_other_scopes(self):
        source = "import subprocess\n" + OPENAI_PY + (
            "def run(cursor, messages):\n"
            "    reply = client.chat.completions.create(model=MODEL, messages=messages)\n"
            "    command = reply.choices[0].message.content\n"
            "    subprocess.run(command, shell=True)\n"
            "    cursor.execute(f\"SELECT * FROM notes WHERE title = '{command}'\")\n"
            "    cursor.execute('SELECT * FROM notes WHERE title = %s', (command,))\n"
            "    subprocess.run(['git', 'log', command])\n"
            "def other(cursor, command):\n"
            "    cursor.execute(command)\n"
        )
        self.assertEqual(
            observed({"agent.py": source}, "AI-OUTPUT-EXEC"),
            [("agent.py", 7, "violated"), ("agent.py", 8, "violated"), ("agent.py", 9, "satisfied")],
        )

    def test_streamed_model_output_is_followed_through_loops(self):
        source = OPENAI_PY + (
            "with client.messages.stream(model=MODEL, messages=messages, max_tokens=99) as stream:\n"
            "    for chunk in stream.text_stream:\n"
            "        exec(chunk)\n"
        )
        self.assertEqual(observed({"stream.py": source}, "AI-OUTPUT-EXEC"), [("stream.py", 5, "violated")])

    def test_structured_output_needs_schema_validation(self):
        head = "import json\n" + OPENAI_PY + "reply = client.responses.create(model=MODEL, input=prompt)\n"
        cases = (
            ("plan = json.loads(reply.output_text)\nrun(plan)\n", "violated"),
            ("plan = json.loads(reply.output_text)\nPlan.model_validate(plan)\n", "satisfied"),
            ("plan = Plan.model_validate(json.loads(reply.output_text))\n", "satisfied"),
            ("print(json.loads(reply.output_text))\n", "unclear"),
        )
        for tail, status in cases:
            with self.subTest(tail=tail):
                self.assertEqual(observed({"p.py": head + tail}, "AI-OUTPUT-PARSE"), [("p.py", 5, status)])
        js = OPENAI_JS + (
            "const reply = await client.chat.completions.create({ model, messages });\n"
            "const data = JSON.parse(reply.choices[0].message.content);\n"
        )
        self.assertEqual(observed({"p.js": js}, "AI-OUTPUT-PARSE"), [("p.js", 4, "violated")])
        validated = js + "const plan = PlanSchema.parse(data);\n"
        self.assertEqual(observed({"p.js": validated}, "AI-OUTPUT-PARSE"), [("p.js", 4, "satisfied")])

    def test_long_untrusted_lines_and_specs_stay_bounded(self):
        blank = "x".join(["'" + " " * 50000 + "'"] * 4)
        source = OPENAI_JS + "const reply = await client.responses.create({});\n" + (
            "a: " + blank + "\n" + ("el.innerHTML = reply + " * 2000) + "1;\n"
        )
        spec = "mcp-server==1.0" + "a" * 60 + "!"
        config = json.dumps({"mcpServers": {"s": {"command": "uvx", "args": [spec]}}})
        started = time.monotonic()
        self.assertEqual(observed({"big.js": source}, "AI-OUTPUT-HTML"), [("big.js", 5, "violated")])
        self.assertEqual([row[2] for row in observed({".mcp.json": config}, "AI-MCP-SOURCE")], ["violated"])
        self.assertLess(time.monotonic() - started, 5)

    def test_files_without_an_ai_import_are_not_followed(self):
        source = "const reply = await client.chat.completions.create({});\nel.innerHTML = reply;\n"
        self.assertEqual(observed({"chat.js": source}, "AI-OUTPUT-HTML"), [])
        self.assertEqual(observed({"chat.js": source}, "AI-INTEGRATION"), [])


class ClientConversationTests(unittest.TestCase):
    def test_request_history_in_a_multiline_model_call_violates(self):
        source = "import { streamText } from 'ai';\n" + (
            "export function chat () {\n"
            "  return async (req, res) => {\n"
            "    const history = req.body?.messages ?? []\n"
            "    try {\n"
            "      const result = streamText({\n"
            "        model: provider(name),\n"
            "        system: prompt,\n"
            "        messages: history,\n"
            "      })\n"
            "    } catch (error) {}\n"
            "  }\n"
            "}\n"
        )
        self.assertEqual(observed({"chat.ts": source}, "AI-CLIENT-MESSAGES"), [("chat.ts", 9, "violated")])

    def test_roles_set_by_the_server_satisfy(self):
        head = "import OpenAI from 'openai';\nconst { question, turns } = req.body;\n"
        cases = (
            ("await client.chat.completions.create({ model, messages: [{ role: 'user', content: question }] });\n", "satisfied"),
            ("await client.chat.completions.create({ model, messages: turns.map(t => ({ role: 'user', content: t.text })) });\n", "satisfied"),
            ("await client.chat.completions.create({ model, messages: turns.map(t => ({ role: t.role, content: t.text })) });\n", "violated"),
            ("await client.chat.completions.create({ model, messages: [system, ...turns] });\n", "violated"),
            ("await client.chat.completions.create({ model, messages: convert(turns) });\n", "violated"),
            ("await client.chat.completions.create({ model, messages: stored });\n", None),
        )
        for tail, status in cases:
            with self.subTest(tail=tail):
                rows = observed({"chat.js": head + tail}, "AI-CLIENT-MESSAGES")
                self.assertEqual(rows, [("chat.js", 3, status)] if status else [])

    def test_python_route_parameters_and_request_data_are_client_supplied(self):
        source = OPENAI_PY + (
            "@router.post('/chat')\n"
            "async def chat(body: ChatRequest, user=Depends(current_user)):\n"
            "    client.chat.completions.create(model=MODEL, messages=body.messages)\n"
            "    client.chat.completions.create(model=MODEL, messages=[{'role': 'user', 'content': body.question}])\n"
            "    client.chat.completions.create(model=MODEL, messages=[{'role': 'user', 'content': m.text} for m in body.turns])\n"
            "    client.chat.completions.create(model=MODEL, messages=user.history)\n"
            "def flask_chat():\n"
            "    turns = request.get_json()['messages']\n"
            "    client.chat.completions.create(model=MODEL, messages=turns)\n"
        )
        self.assertEqual(
            observed({"api.py": source}, "AI-CLIENT-MESSAGES"),
            [("api.py", 5, "violated"), ("api.py", 6, "satisfied"), ("api.py", 7, "satisfied"), ("api.py", 11, "violated")],
        )


class AgentConfigurationTests(unittest.TestCase):
    def test_mcp_credentials_are_located_but_never_reported(self):
        secret = "trk_" + "93hf72kd02ld83jfq"
        config = json.dumps({"mcpServers": {"tracker": {
            "command": "node",
            "args": ["server.js", "--api-key", "abcd1234" + "efgh5678"],
            "env": {"TRACKER_TOKEN": secret, "TRACKER_TOKEN_URL": "https://tracker.test/token", "API_KEY": "your-api-key"},
            "headers": {"Authorization": "Bearer ${TRACKER_TOKEN}"},
        }}}, indent=2)
        self.assertEqual(
            [status for _, _, status in observed({".mcp.json": config}, "AI-MCP-CREDENTIAL")],
            ["violated", "violated", "satisfied"],
        )
        for flags in (("--json",), ("--details",)):
            _, output = invoke({".mcp.json": config}, *flags)
            self.assertNotIn(secret, output)
            self.assertNotIn("efgh5678", output)

    def test_mcp_server_packages_need_an_exact_version(self):
        cases = (
            ("uvx", ["mcp-server-fetch"], "violated"),
            ("uvx", ["mcp-server-fetch==2025.4.7"], "satisfied"),
            ("pnpm", ["dlx", "@acme/mcp@1.2.3"], "satisfied"),
            ("npx", ["-y", "@acme/mcp@latest"], "violated"),
            ("npx", ["github:acme/mcp#" + "a" * 40], "satisfied"),
            ("npx", ["${MCP_PACKAGE}"], "unclear"),
            ("node", ["server.js"], None),
        )
        for command, args, status in cases:
            with self.subTest(command=command, args=args):
                config = json.dumps({"mcpServers": {"s": {"command": command, "args": args}}})
                rows = observed({".mcp.json": config}, "AI-MCP-SOURCE")
                self.assertEqual([row[2] for row in rows], [status] if status else [])

    def test_remote_transport_excludes_loopback_and_leaves_variables_unresolved(self):
        for url, status in (("http://localhost:8080/mcp", None), ("${MCP_URL}", "unclear"), ("wss://mcp.test/ws", "satisfied")):
            with self.subTest(url=url):
                config = json.dumps({"servers": {"s": {"type": "http", "url": url}}})
                rows = observed({".vscode/mcp.json": config}, "AI-MCP-TRANSPORT")
                self.assertEqual([row[2] for row in rows], [status] if status else [])

    def test_duplicate_or_invalid_settings_never_establish_controls(self):
        duplicate = '{"sandbox": {"enabled": true}, "sandbox": {"enabled": false}, "permissions": {"allow": ["Bash(make:*)"]}}'
        self.assertEqual(observed({".claude/settings.json": duplicate}, "AI-AGENT-SANDBOX"), [(".claude/settings.json", 1, "unclear")])
        self.assertEqual(observed({".mcp.json": "{ // comment\n}"}, "AI-MCP-SOURCE"), [(".mcp.json", 1, "unclear")])

    def test_permission_rules_flag_shell_and_unrestricted_writes_only(self):
        settings = json.dumps({"permissions": {"allow": ["Bash(npm test:*)", "Edit(src/**)", "Write(~/.ssh/**)", "Bash"]}}, indent=2)
        rows = observed({".claude/settings.json": settings}, "AI-AGENT-PERMISSIONS")
        self.assertEqual(rows, [(".claude/settings.json", 6, "violated"), (".claude/settings.json", 7, "violated")])

    def test_gemini_trusted_servers_need_a_sandbox(self):
        trusted = {"mcpServers": {"x": {"command": "node", "args": ["s.js"], "trust": True}}}
        path = ".gemini/settings.json"
        self.assertEqual([r[2] for r in observed({path: json.dumps(trusted)}, "AI-AGENT-BYPASS")], ["violated"])
        self.assertEqual([r[2] for r in observed({path: json.dumps(trusted)}, "AI-AGENT-SANDBOX")], ["violated"])
        isolated = {**trusted, "tools": {"sandbox": "docker"}}
        self.assertEqual([r[2] for r in observed({path: json.dumps(isolated)}, "AI-AGENT-SANDBOX")], ["satisfied"])

    def test_llm_provider_tokens_are_recognized(self):
        tokens = ("sk-proj-" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0", "hf_" + "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789")
        source = "A = '%s'\nB = '%s'\n" % tokens
        self.assertEqual(observed({"cfg.py": source}, "SECRET-TOKEN"), [("cfg.py", 1, "violated"), ("cfg.py", 2, "violated")])


class AreaAssessmentTests(unittest.TestCase):
    def test_repository_without_ai_marks_the_area_not_applicable(self):
        status, output = invoke({"app.py": "import requests\nrequests.get(url, verify=False)\n"}, "--json")
        result = json.loads(output)
        ai = area(result, "ai")
        self.assertEqual((ai["applicable"], ai["score"], ai["rating"], ai["gaps"]), (False, None, "Not applicable", []))
        self.assertEqual(result["overall"]["rating"], "Bad")
        self.assertEqual(result["scoring_policy"], "area-subscores")
        self.assertEqual(status, 2)

    def test_incomplete_processing_cannot_establish_absence(self):
        status, output = invoke({"legacy.py": "print 'python 2'\n", "app.py": "print(1)\n"}, "--json")
        result = json.loads(output)
        ai = area(result, "ai")
        self.assertEqual((status, ai["applicable"], ai["rating"]), (1, True, "Not assessed"))
        self.assertIn("Required source processing did not complete", ai["gaps"])

    def test_selected_checks_cannot_establish_absence(self):
        _, output = invoke({"app.py": "eval(input())\n"}, "--json", "--checks", "PY-EXEC")
        ai = area(json.loads(output), "ai")
        self.assertTrue(ai["applicable"])
        self.assertEqual(ai["rating"], "Not assessed")

    def test_model_output_execution_deducts_once_and_owns_the_generic_candidate(self):
        source = OPENAI_JS + (
            "const reply = await client.chat.completions.create({ model, messages });\n"
            "const code = reply.choices[0].message.content;\n"
            "eval(code);\n"
        )
        _, output = invoke({"agent.js": source}, "--json")
        result = json.loads(output)
        ai = area(result, "ai")
        self.assertEqual([(row["rules"], row["line"]) for row in ai["breakdown"]], [(["AI-OUTPUT-EXEC", "JS-EVAL"], 5)])
        self.assertEqual((ai["score"], ai["rating"]), (59, "Bad"))
        self.assertFalse([hint for hint in result["review_hints"] if hint["line"] == 5])
        self.assertEqual(result["overall"]["rating"], "Bad")

    def test_recognized_token_in_mcp_config_deducts_once(self):
        token = "ghp_" + "0123456789abcdefghijABCDEFGHIJ012345"
        config = '{"mcpServers": {"gh": {"command": "node", "env": {"GITHUB_TOKEN": "%s"}}}}\n' % token
        _, output = invoke({".mcp.json": config}, "--json")
        result = json.loads(output)
        self.assertEqual([(row["rules"], row["line"]) for row in area(result, "ai")["breakdown"]],
                         [(["AI-MCP-CREDENTIAL", "SECRET-TOKEN"], 1)])
        self.assertEqual(area(result, "data")["breakdown"], [])
        self.assertNotIn(token, output)

    def test_two_independent_ai_controls_allow_a_positive_rating(self):
        chat = OPENAI_JS + (
            "const reply = await client.chat.completions.create({ model, messages });\n"
            "el.textContent = reply.choices[0].message.content;\n"
        )
        settings = '{"sandbox": {"enabled": true}, "permissions": {"allow": ["Bash(npm test:*)"]}}\n'
        _, output = invoke({"chat.js": chat, ".claude/settings.json": settings}, "--json")
        ai = area(json.loads(output), "ai")
        self.assertEqual((ai["score"], ai["rating"]), (100, "Very good"))
        self.assertEqual(ai["controls"], ["agent-sandbox", "model-output-encoding"])
        _, output = invoke({"chat.js": chat}, "--json")
        ai = area(json.loads(output), "ai")
        self.assertEqual((ai["applicable"], ai["score"], ai["rating"]), (True, None, "Not assessed"))

    def test_details_show_the_ai_area_and_sdk_inventory(self):
        files = {
            "package.json": '{"dependencies": {"openai": "^4.0.0"}}\n',
            "agent.js": OPENAI_JS + "const r = await client.chat.completions.create({});\neval(r.output);\n",
        }
        _, output = invoke(files, "--details")
        self.assertRegex(output, r"(?m)^AI & agents +59/100 ")
        self.assertRegex(output, r"(?m)^ +AI SDKs +OpenAI SDK$")
        self.assertIn("AI-OUTPUT-EXEC, JS-EVAL", output)
        _, output = invoke({"app.py": "print(1)\n"}, "--details")
        self.assertRegex(output, r"(?m)^AI & agents +— +Not applicable$")
        self.assertIn("No AI integration or agent configuration was recognized.", output)
        self.assertNotIn("AI profile:", output)

    def test_ai_profile_lists_tools_and_agent_configuration_with_unknown_model(self):
        files = {
            "chat.ts": "import { generateText, tool } from 'ai';\n"
                       "const tools = { lookupOrder: tool({ execute: async ({ id }) => find(id) }) };\n"
                       "const result = await generateText({ model, tools, prompt: 'Hi' });\n",
            "agent.py": "from langchain_core.tools import tool\nfrom openai import OpenAI\n"
                        "@tool\ndef refund(order_id: str) -> str:\n    return issue(order_id)\n"
                        "TOOLS = [{'type': 'function', 'function': {'name': 'get_weather'}}]\n"
                        "reply = OpenAI().chat.completions.create(model=MODEL, messages=m, tools=TOOLS)\n",
            ".mcp.json": '{"mcpServers": {"docs": {"command": "node", "args": ["server.js"]}}}\n',
        }
        _, output = invoke(files, "--details")
        profile = output.split("AI profile:", 1)[1].split("\nCoverage", 1)[0]
        self.assertRegex(profile, r"Model +not resolved")
        self.assertNotIn("Model calls", profile)
        for tool in ("lookupOrder", "refund", "get_weather"):
            self.assertIn(tool, profile)
        self.assertRegex(profile, r"Agent config +\.mcp\.json")
        rows = inventory(files)
        self.assertIn(("agent.py", 7, "model call: chat.completions.create"), rows)
        self.assertIn(("chat.ts", 3, "model call: generateText"), rows)
        _, output = invoke(files, "--json")
        self.assertTrue(area(json.loads(output), "ai")["applicable"])


if __name__ == "__main__":
    unittest.main()
