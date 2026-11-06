"""AI and agent checks: model-output flows and committed agent configuration.

Reads only already-selected sources; nothing from the target is imported or
executed. Model-output flows are followed within one file and one function or
block scope, never across files. Prompts and credentials never leave this
module; inventory values are limited to model identifiers and selected options.
"""

from __future__ import annotations

import ast
from collections import defaultdict
import ipaddress
import json
from pathlib import PurePosixPath
import re
from urllib.parse import urlsplit

from score_core import GRADLE_BUILD_FILES, JS_EXTENSIONS
from score_infrastructure import document, logical_lines


INTEGRATION = "AI-INTEGRATION"
CLIENT = "AI-CLIENT-MESSAGES"
EXEC = "AI-OUTPUT-EXEC"
HTML = "AI-OUTPUT-HTML"
PARSE = "AI-OUTPUT-PARSE"
MCP_CREDENTIAL = "AI-MCP-CREDENTIAL"
MCP_SOURCE = "AI-MCP-SOURCE"
MCP_TRANSPORT = "AI-MCP-TRANSPORT"
BYPASS = "AI-AGENT-BYPASS"
AUTO_APPROVE = "AI-AGENT-AUTO-APPROVE"
PERMISSIONS = "AI-AGENT-PERMISSIONS"
SANDBOX = "AI-AGENT-SANDBOX"
MCP_RULES = (MCP_CREDENTIAL, MCP_SOURCE, MCP_TRANSPORT, AUTO_APPROVE, BYPASS)
SETTINGS_RULES = (BYPASS, AUTO_APPROVE, PERMISSIONS, SANDBOX)

# (ecosystem, package or Maven group): display name. Inventory only; no score credit.
AI_PACKAGES = {
    ("npm", "openai"): "OpenAI SDK",
    ("npm", "@anthropic-ai/sdk"): "Anthropic SDK",
    ("npm", "@google/genai"): "Google Gen AI SDK",
    ("npm", "@google/generative-ai"): "Google Gen AI SDK",
    ("npm", "@mistralai/mistralai"): "Mistral SDK",
    ("npm", "cohere-ai"): "Cohere SDK",
    ("npm", "ollama"): "Ollama",
    ("npm", "@aws-sdk/client-bedrock-runtime"): "Amazon Bedrock",
    ("npm", "ai"): "Vercel AI SDK",
    ("npm", "langchain"): "LangChain",
    ("npm", "llamaindex"): "LlamaIndex",
    ("npm", "@modelcontextprotocol/sdk"): "MCP SDK",
    ("python", "openai"): "OpenAI SDK",
    ("python", "anthropic"): "Anthropic SDK",
    ("python", "google-genai"): "Google Gen AI SDK",
    ("python", "google-generativeai"): "Google Gen AI SDK",
    ("python", "mistralai"): "Mistral SDK",
    ("python", "cohere"): "Cohere SDK",
    ("python", "ollama"): "Ollama",
    ("python", "litellm"): "LiteLLM",
    ("python", "langchain"): "LangChain",
    ("python", "langchain-core"): "LangChain",
    ("python", "langchain-openai"): "LangChain",
    ("python", "langchain-anthropic"): "LangChain",
    ("python", "langgraph"): "LangGraph",
    ("python", "llama-index"): "LlamaIndex",
    ("python", "llama-index-core"): "LlamaIndex",
    ("python", "pydantic-ai"): "Pydantic AI",
    ("python", "crewai"): "CrewAI",
    ("python", "autogen-agentchat"): "AutoGen",
    ("python", "mcp"): "MCP SDK",
    ("maven", "dev.langchain4j"): "LangChain4j",
    ("maven", "org.springframework.ai"): "Spring AI",
    ("maven", "com.openai"): "OpenAI SDK",
    ("maven", "com.anthropic"): "Anthropic SDK",
}
NPM_PREFIXES = {"@langchain/": "LangChain", "@ai-sdk/": "Vercel AI SDK"}
PYTHON_MODULES = {
    "openai", "anthropic", "google.genai", "google.generativeai", "mistralai",
    "cohere", "ollama", "litellm", "langchain", "langchain_core", "langchain_openai",
    "langchain_anthropic", "langchain_community", "langgraph", "llama_index",
    "pydantic_ai", "crewai", "autogen", "autogen_agentchat", "mcp",
}


def package_name(ecosystem, package):
    """Display name of a recognized AI package, else None."""
    name = AI_PACKAGES.get((ecosystem, package)) or AI_PACKAGES.get((ecosystem, package.split(":")[0]))
    if name is None and ecosystem == "npm":
        name = next((value for prefix, value in NPM_PREFIXES.items() if package.startswith(prefix)), None)
    return name


def python_package(value):
    return re.sub(r"[-_.]+", "-", value).lower()


def line_at(text, position):
    return text.count("\n", 0, position) + 1


# --- Inventory: SDK imports and declared packages --------------------------

JS_IMPORT = re.compile(
    r"""(?:\bfrom\s*|\brequire\s*\(\s*|\bimport\s*\(\s*|^[ \t]*import\s+)(['"])([^'"\n]{1,200})\1""",
    re.M,
)


def js_module(specifier):
    parts = specifier.split("/")
    root = "/".join(parts[:2]) if specifier.startswith("@") else parts[0]
    return package_name("npm", specifier) is not None or package_name("npm", root) is not None


def in_code(text, code, position):
    """Whether raw text at `position` is code; comments and strings are blank in `code`."""
    return len(code) != len(text) or code[position] == text[position]


def js_imports(text, code):
    """Lines importing an AI SDK outside comments."""
    lines = set()
    for match in JS_IMPORT.finditer(text):
        start = match.start() + len(match[0]) - len(match[0].lstrip())
        if js_module(match[2]) and in_code(text, code, start):
            lines.add(line_at(text, match.start()))
    return sorted(lines)


def call_label(value):
    label = re.sub(r"\s+", "", value).strip(".(")
    return re.sub(r"^new(?=[A-Z])", "", label)


# API families, not claims about the service behind a configurable endpoint.
PROVIDER_MODULES = {
    "openai": "OpenAI-compatible", "@ai-sdk/openai": "OpenAI-compatible",
    "@ai-sdk/openai-compatible": "OpenAI-compatible", "langchain_openai": "OpenAI-compatible",
    "@langchain/openai": "OpenAI-compatible",
    "anthropic": "Anthropic", "@anthropic-ai/sdk": "Anthropic", "@ai-sdk/anthropic": "Anthropic",
    "langchain_anthropic": "Anthropic", "@langchain/anthropic": "Anthropic",
    "google.genai": "Google Gemini", "google.generativeai": "Google Gemini",
    "@google/genai": "Google Gemini", "@google/generative-ai": "Google Gemini",
    "@ai-sdk/google": "Google Gemini", "@ai-sdk/azure": "Azure OpenAI",
    "ollama": "Ollama", "@langchain/ollama": "Ollama",
    "mistralai": "Mistral", "@mistralai/mistralai": "Mistral", "@ai-sdk/mistral": "Mistral",
    "cohere": "Cohere", "cohere-ai": "Cohere", "@ai-sdk/cohere": "Cohere",
    "@aws-sdk/client-bedrock-runtime": "Amazon Bedrock", "@ai-sdk/amazon-bedrock": "Amazon Bedrock",
}
MODEL_KEYS = {"model", "modelName", "model_name", "modelId", "model_id"}
CALL_OPTIONS = {
    "temperature", "top_p", "topP", "max_tokens", "max_completion_tokens", "max_output_tokens",
    "maxTokens", "maxOutputTokens", "maxSteps", "maxRetries", "tool_choice", "toolChoice",
    "parallel_tool_calls", "stream", "stopWhen",
}
LLM_SECTIONS = {"llm", "chatbot", "openai", "anthropic", "ollama"}
MODEL_CONSTRUCTOR = re.compile(
    r"\bnew\s+(?:ChatOpenAI|AzureChatOpenAI|ChatAnthropic|ChatGoogleGenerativeAI|ChatOllama|Ollama|GoogleGenerativeAI)\s*\("
    r"|\.getGenerativeModel\s*\("
)
PROFILE_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,127}", re.ASCII)


def profile_identifier(value):
    """Only short identifiers; never output credential-shaped or arbitrary strings."""
    if not isinstance(value, str) or not PROFILE_IDENTIFIER.fullmatch(value):
        return None
    if re.search(r"(?i)(?:sk-|hf_|gh[pousr]_|github_pat_|AIza|AKIA|bearer|password|secret|token)", value):
        return None
    if "://" in value or re.search(r"@[^/]+\.[A-Za-z]{2,}$", value):
        return None
    return value


def provider_name(module):
    return next((label for name, label in PROVIDER_MODULES.items()
                 if module == name or module.startswith(name + ("/" if module.startswith("@") else "."))), None)


def js_fields(text, code, start):
    """Top-level fields of a bounded, literal first-argument object; retain offsets.

    Comments and strings are already masked in code. Spreads, duplicate fields,
    computed keys and incomplete objects leave the options unresolved.
    """
    end = min(len(code), start + MAX_CALL_CHARS)
    match = re.match(r"\s*\{", code[start:end])
    if not match:
        return {}
    field_start = start + match.end()
    stack, spans = ["}"], []
    for pos in range(field_start, end):
        char = code[pos]
        if char in "({[":
            stack.append({"(": ")", "{": "}", "[": "]"}[char])
        elif char in ")}]":
            if not stack or stack.pop() != char:
                return {}
            if not stack:
                spans.append((field_start, pos))
                break
        elif char == "," and len(stack) == 1:
            spans.append((field_start, pos))
            field_start = pos + 1
    else:
        return {}
    fields = {}
    for left, right in spans:
        if not code[left:right].strip() and not text[left:right].strip():
            continue
        field = re.match(r"\s*([A-Za-z_$][\w$]*)\s*:", code[left:right])
        shorthand = re.fullmatch(r"\s*([A-Za-z_$][\w$]*)\s*", code[left:right])
        if shorthand:
            if shorthand[1] in fields:
                return {}
            fields[shorthand[1]] = shorthand[1]
            continue
        if not field or field[1] in fields:
            return {}
        value_start = left + field.end()
        fields[field[1]] = text[value_start:right].strip()
    return fields


def js_model_value(value):
    """A literal identifier or a configuration reference, without evaluating code."""
    literal = re.fullmatch(r"(['\"`])([A-Za-z0-9_.:/@+-]{1,128})\1", value)
    if literal:
        return profile_identifier(literal[2]) or "unresolved"
    env = re.fullmatch(r"process\.env\.([A-Za-z_][A-Za-z0-9_]{0,79})", value)
    config = re.fullmatch(r"config\.get(?:<\w+>)?\(\s*(['\"])([\w.\-]{1,100})\1\s*\)", value)
    if env:
        return f"environment {env[1]} (unresolved)"
    if config:
        return f"config {config[2]} (unresolved)"
    # Vercel provider factories: openai('model'), provider.chat('model'), etc.
    factory = re.fullmatch(r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)?\(\s*(.{1,300}?)\s*\)", value, re.S)
    if factory:
        inner = factory[1]
        if re.fullmatch(r"(['\"`])[A-Za-z0-9_.:/@+-]{1,128}\1", inner) or inner.startswith("process.env."):
            return js_model_value(inner)
    return "unresolved (dynamic expression)"


def option_value(key, value):
    """Only fixed scalar options; prompts, schemas, URLs and expressions stay private."""
    if re.fullmatch(r"(?:0|[1-9][0-9]{0,7})(?:\.[0-9]{1,8})?|true|false", value):
        return value
    choice = re.fullmatch(r"(['\"])(auto|none|required|any)\1", value)
    if key in {"tool_choice", "toolChoice"} and choice:
        return choice[2]
    steps = re.fullmatch(r"stepCountIs\(\s*([1-9][0-9]{0,5})\s*\)", value)
    if key == "stopWhen" and steps:
        return f"stepCountIs({steps[1]})"
    return "unresolved"


def python_model_value(node):
    if isinstance(node, ast.Constant):
        return profile_identifier(node.value) or "unresolved"
    if isinstance(node, ast.Subscript) and dotted(node.value) == "os.environ":
        key = node.slice
    elif isinstance(node, ast.Call) and dotted(node.func) in {"os.getenv", "os.environ.get"} and node.args:
        key = node.args[0]
        if len(node.args) != 1 or node.keywords:
            return "unresolved (dynamic expression)"
    else:
        return "unresolved (dynamic expression)"
    if isinstance(key, ast.Constant) and isinstance(key.value, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,79}", key.value):
        return f"environment {key.value} (unresolved)"
    return "unresolved"


def python_call_inventory(node):
    # **options and repeated fields could override the visible values.
    fields = {item.arg: item.value for item in node.keywords}
    if None in fields or len(fields) != len(node.keywords):
        fields = {}
    rows = [(node.lineno, "satisfied", f"model: {python_model_value(value)}")
            for key, value in fields.items() if key in MODEL_KEYS]
    if not rows:
        rows.append((node.lineno, "satisfied", "model: unresolved (options or model not literal)"))
    options = []
    for key, value in fields.items():
        if key not in CALL_OPTIONS:
            continue
        if isinstance(value, ast.Constant) and isinstance(value.value, (str, int, float, bool)):
            raw = json.dumps(value.value)
        else:
            raw = ""
        options.append(f"{key}={option_value(key, raw)}")
    if options:
        rows.append((node.lineno, "satisfied", "call options: " + ", ".join(options)))
    return rows


def js_call_inventory(text, code, match):
    line = line_at(code, match.start())
    fields = js_fields(text, code, match.end())
    models = [(line, "satisfied", f"model: {js_model_value(value)}")
              for key, value in fields.items() if key in MODEL_KEYS]
    if not models:
        models = [(line, "satisfied", "model: unresolved (options or model not literal)")]
    options = [f"{key}={option_value(key, value)}" for key, value in fields.items() if key in CALL_OPTIONS]
    if options:
        models.append((line, "satisfied", "call options: " + ", ".join(options)))
    return models


def js_inventory(text, code):
    """Imports, model calls and model-callable tools of a file that imports an AI SDK."""
    imports = js_imports(text, code)
    if not imports:
        return []
    rows = [(line, "satisfied", "import") for line in imports]
    for match in JS_IMPORT.finditer(text):
        provider = provider_name(match[2])
        start = match.start() + len(match[0]) - len(match[0].lstrip())
        if provider and in_code(text, code, start):
            rows.append((line_at(text, match.start()), "satisfied", f"provider API: {provider}"))
    rows += [(line_at(code, m.start()), "satisfied", f"model call: {call_label(m[0])}") for m in JS_MODEL_CALL.finditer(code)]
    for match in list(JS_MODEL_CALL.finditer(code)) + list(MODEL_CONSTRUCTOR.finditer(code)):
        rows += js_call_inventory(text, code, match)
    rows += [(line_at(code, m.start()), "satisfied", f"tool: {m[1]}") for m in JS_TOOL.finditer(code)]
    for match in JS_REGISTERED_TOOL.finditer(text):
        if in_code(text, code, match.start()):
            rows.append((line_at(text, match.start()), "satisfied", f"tool: {match[2]}"))
    for match in JS_FUNCTION_TOOL.finditer(text):
        name = JS_TOOL_NAME.search(text, match.end(), match.end() + 400)
        if name and in_code(text, code, match.start()):
            rows.append((line_at(text, match.start()), "satisfied", f"tool: {name[2]}"))
    return rows


def python_inventory(tree):
    """Imports, model calls and model-callable tools of a module that imports an AI SDK."""
    imports = python_imports(tree)
    if not imports:
        return []
    rows = [(line, "satisfied", "import") for line in imports]
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            modules = [a.name for a in node.names] if isinstance(node, ast.Import) else [node.module or ""]
            for module in modules:
                provider = provider_name(module)
                if provider and not getattr(node, "level", 0):
                    rows.append((node.lineno, "satisfied", f"provider API: {provider}"))
        if isinstance(node, ast.Call) and PY_MODEL_CALL.search(dotted(node.func)):
            label = ".".join(part for part in dotted(node.func).split(".") if part != "()")
            rows.append((node.lineno, "satisfied", f"model call: {'.'.join(label.split('.')[-3:])}"))
            rows += python_call_inventory(node)
        elif isinstance(node, ast.Call) and dotted(node.func).split(".")[-1] in {
            "ChatOpenAI", "AzureChatOpenAI", "ChatAnthropic", "ChatGoogleGenerativeAI", "ChatOllama", "Ollama",
        }:
            rows += python_call_inventory(node)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for decorator in node.decorator_list:
                target = decorator.func if isinstance(decorator, ast.Call) else decorator
                if re.search(r"(?:^|\.)tool(?:_plain)?$", dotted(target)):
                    first = decorator.args[0] if isinstance(decorator, ast.Call) and decorator.args else None
                    name = first.value if isinstance(first, ast.Constant) and isinstance(first.value, str) else node.name
                    rows.append((node.lineno, "satisfied", f"tool: {name[:64]}"))
        elif isinstance(node, ast.Dict):
            fields = {key.value: value for key, value in zip(node.keys, node.values) if isinstance(key, ast.Constant)}
            kind, inner = fields.get("type"), fields.get("function")
            if isinstance(inner, ast.Dict):
                fields.update({k.value: v for k, v in zip(inner.keys, inner.values) if isinstance(k, ast.Constant)})
            name = fields.get("name")
            if isinstance(kind, ast.Constant) and kind.value == "function" and isinstance(name, ast.Constant) and isinstance(name.value, str):
                rows.append((node.lineno, "satisfied", f"tool: {name.value[:64]}"))
    return rows


def python_imports(tree):
    lines = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            names = [node.module]
        else:
            continue
        if any(name == module or name.startswith(module + ".") for name in names for module in PYTHON_MODULES):
            lines.add(node.lineno)
    return sorted(lines)


def manifest_lines(path, text):
    """Lines of AI packages declared in a supported manifest."""
    name = PurePosixPath(path).name
    lines = set()
    if name == "package.json":
        manifest = document(text) or {}
        for field in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            values = manifest.get(field)
            for package in values if isinstance(values, dict) else ():
                if package_name("npm", package):
                    position = text.find(json.dumps(package))
                    lines.add(line_at(text, max(position, 0)))
    elif name.startswith("requirements") and name.endswith(".txt"):
        for number, value in logical_lines(text):
            match = re.match(r"[A-Za-z0-9][\w.-]{0,200}", value.strip())
            if match and package_name("python", python_package(match[0])):
                lines.add(number)
    elif name == "pyproject.toml":
        for number, line in enumerate(text.splitlines(), 1):
            for match in re.finditer(r"""(?:^\s*|["'])([A-Za-z0-9][\w.-]{0,200})""", line):
                if package_name("python", python_package(match[1])):
                    lines.add(number)
    elif name == "pom.xml" or name in GRADLE_BUILD_FILES:
        groups = "|".join(re.escape(group) for ecosystem, group in AI_PACKAGES if ecosystem == "maven")
        for match in re.finditer(rf"(?<![\w.])(?:{groups})(?!\w)", text):
            lines.add(line_at(text, match.start()))
    return sorted(lines)


def model_config_path(path):
    parts = PurePosixPath(path).parts
    return bool(set(parts[:-1]) & {"config", "configs"}) and PurePosixPath(path).suffix.lower() in {".json", ".yaml", ".yml"}


def endpoint_class(value):
    """Describe a declared endpoint without copying hosts, credentials or URL tokens."""
    if not isinstance(value, str) or re.search(r"[\x00-\x20\x7f${}<>\\]", value):
        return "unresolved"
    try:
        parts = urlsplit(value)
        if parts.scheme not in {"http", "https"} or not parts.hostname or parts.username or parts.password:
            return "unresolved"
        if parts.port is not None and parts.port == 0:
            return "unresolved"
        host = parts.hostname.lower()
        try:
            local = ipaddress.ip_address(host).is_loopback
        except ValueError:
            local = host == "localhost"
        return f"{'loopback' if local else 'non-loopback'} {parts.scheme.upper()} (declared)"
    except ValueError:
        return "unresolved"


def config_inventory(path, text):
    """Selected declarations under explicit LLM sections; no configuration merging."""
    if not model_config_path(path):
        return []
    # Reuse the existing bounded data-only YAML reader, including duplicate-key
    # handling, nesting limits and rejection of tags/aliases for selected scalars.
    from score_compose import Unsupported, decode, mapping as yaml_mapping, parse
    from score_sources import Budget

    if PurePosixPath(path).suffix.lower() == ".json":
        data = strict_json(text)
        if data is None:
            return []
        pending = [(data, False, 0)]
        rows = []
        while pending:
            fields, active, depth = pending.pop()
            if depth > 32:
                continue
            for key, value in fields.items():
                if isinstance(value, dict):
                    pending.append((value, key.lower() in LLM_SECTIONS, depth + 1))
                elif active:
                    # JSON evidence locates the document; repeated key names in
                    # different sections cannot safely be located with find().
                    rows += config_field(key, value, 1)
        return rows
    try:
        root = parse(text, Budget())
    except Unsupported:
        return []
    pending, rows = [(root, False)], []
    while pending:
        node, active = pending.pop()
        for key, value in (yaml_mapping(node) or {}).items():
            if value.children:
                pending.append((value, key.lower() in LLM_SECTIONS))
            elif active:
                rows += config_field(key, decode(value), value.line)
    return rows


def config_field(key, value, line):
    if key in MODEL_KEYS:
        return [(line, "satisfied", f"configured model: {profile_identifier(value) or 'unresolved'} (declared)")]
    if key in {"llmApiUrl", "baseURL", "base_url", "api_base", "endpoint"}:
        return [(line, "satisfied", f"model endpoint: {endpoint_class(value)}")]
    return []


# --- Model-output flows: JavaScript and TypeScript --------------------------

JS_MODEL_CALL = re.compile(
    r"\.(?:chat\.)?completions\.(?:create|parse|stream)\s*\("
    r"|\.responses\.(?:create|parse|stream)\s*\("
    r"|\.messages\.(?:create|stream)\s*\("
    r"|\.generateContent(?:Stream)?\s*\("
    r"|(?<![\w$.])(?:generateText|streamText|generateObject|streamObject)\s*\("
    r"|\bnew\s+(?:InvokeModel|InvokeModelWithResponseStream|Converse|ConverseStream)Command\s*\("
    r"|\bollama\s*\.\s*(?:chat|generate)\s*\("
    r"|\b(?:llm|model|chatModel|chain|agent|agentExecutor|executor|queryEngine|chatEngine)"
    r"\s*\.\s*(?:invoke|call|predict|generate|stream|run|query|chat)\s*\("
)
JS_TOOL = re.compile(r"(?<![\w$.])([A-Za-z_$][\w$]*)\s*:\s*tool\s*\(")
JS_REGISTERED_TOOL = re.compile(r"""\.(?:tool|registerTool)\s*\(\s*(['"])([\w.-]{1,64})\1""")
JS_FUNCTION_TOOL = re.compile(r"""\btype\s*:\s*(['"])function\1""")
JS_TOOL_NAME = re.compile(r"""\bname\s*:\s*(['"])([\w.-]{1,64})\1""")
# Request data that a client controls; the conversation keys carry roles.
JS_CLIENT_SOURCE = re.compile(
    r"\b(?:req|request|ctx\s*\.\s*request)\s*(?:\?\.|\.)\s*(?:body|query)\b|\b(?:req|request)\s*\.\s*json\s*\("
)
JS_CONVERSATION = re.compile(r"(?<![\w$.'\"])(messages|contents|history)\b\s*(:)?")
USER_ROLE = re.compile(r"""\brole\s*:\s*(['"`])user\1""")
DATA_ROLE = re.compile(r"""\brole\s*:(?!\s*['"`])|(?<![\w$.'"`])role\s*[,}]""")
JS_CONTENT_ONLY = re.compile(r"\bcontent\s*:\s*[\w$.?\[\]\s]{0,200}$")
JS_MAPPED = re.compile(r"(?:\s*(?:\?\.|\.)\s*[A-Za-z_$][\w$]*){0,10}\s*(?:\?\.|\.)\s*map\s*\(")
MAX_CALL_LINES, MAX_CALL_CHARS = 80, 8000
# The SDK validates these results against the schema it is given.
JS_SCHEMA_CALL = re.compile(r"(?<![\w$.])(?:generateObject|streamObject)\s*\(")
JS_FORMAT_HELPER = re.compile(r"\bzod(?:ResponseFormat|TextFormat)\s*\(")
JS_SDK_PARSE = re.compile(r"\.(?:chat\.)?completions\.parse\s*\(|\.responses\.parse\s*\(")
# Blanked strings become long runs of spaces, so every quantifier next to
# whitespace is bounded to keep matching linear on untrusted source lines.
JS_ASSIGN = re.compile(
    r"\s*(?:export\s+)?(?:(const|let|var)\s+)?(\{[^{}]*\}|\[[^\[\]]*\]|[A-Za-z_$][\w$]*)"
    r"[ \t]{0,20}(?::[ \t]{0,20}[\w$<>\[\]., |]{1,120}?)?[ \t]{0,20}(?:\+|\?\?|\|\|)?=(?![=>])\s*(.*)"
)
JS_FOR_OF = re.compile(r"\bfor\s*(?:await\s*)?\(\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s+of\s+(.{1,500}?)\)")
SINK_WINDOW = 2000
JS_EXEC = re.compile(
    r"(?<![\w$.])(?:eval|exec|execSync)\s*\(|\bnew\s+Function\s*\("
    r"|\bvm\s*\.\s*runIn(?:New|This)?Context\s*\(|\bchild_process\s*\.\s*(?:exec|execSync)\s*\("
)
JS_SPAWN = re.compile(r"(?<![\w$])(?:spawn|spawnSync|execFile|execFileSync)\s*\(")
JS_SQL = re.compile(
    r"(?i)\b(?:db|database|sql|cursor|sequelize|connection|conn|pool|client|knex|prisma|queryRunner|manager)"
    r"\w*\s*\.\s*(?:query|execute|raw|\$queryRawUnsafe|\$executeRawUnsafe)\s*\("
)
JS_HTML = re.compile(
    r"\.(?:inner|outer)HTML\s*\+?=(?!=)|\.insertAdjacentHTML\s*\(|\bdocument\s*\.\s*write(?:ln)?\s*\("
    r"|\bdangerouslySetInnerHTML\b|\bbypassSecurityTrustHtml\s*\("
)
JS_TEXT = re.compile(r"\.(?:textContent|innerText)\s*=(?!=)")
JS_SANITIZER = re.compile(
    r"\b(?:DOMPurify\s*\.\s*sanitize|purify\s*\.\s*sanitize|sanitizeHtml|sanitize|escapeHtml|filterXSS)\s*\("
)
JS_JSON_PARSE = re.compile(r"\bJSON\s*\.\s*parse\s*\(")
JS_VALIDATOR = (
    r"(?<!JSON\.)\b(?:validate\w*|assert\w*|parse|parseAsync|safeParse|safeParseAsync|cast|check)"
    r"\s*(?:<[^<>()]*>)?\s*\(\s*(?:[\w$.]+\s*,\s*)?"
)
JS_WRAPPED = re.compile(JS_VALIDATOR + r"$")


def reference(name):
    """A variable use, including a spread such as ...name, but not a property such as obj.name."""
    return re.compile(rf"(?:(?<=\.\.\.)|(?<![\w$.])){re.escape(name)}(?![\w$])")


def arguments(line, start):
    """(first argument, remaining arguments) of the call whose parenthesis ends before `start`."""
    depth, comma, index = 0, None, start
    while index < len(line):
        char = line[index]
        if char in "([{":
            depth += 1
        elif char in ")]}":
            if depth == 0:
                break
            depth -= 1
        elif char == "," and depth == 0 and comma is None:
            comma = index
        index += 1
    if comma is None:
        return line[start:index], ""
    return line[start:comma], line[comma + 1:index]


def js_targets(target):
    if target[0] not in "{[":
        return [target]
    names = []
    for part in target[1:-1].split(","):
        part = part.split("=")[0].strip().lstrip(".").split(":")[-1].strip()
        if re.fullmatch(r"[A-Za-z_$][\w$]*", part):
            names.append(part)
    return names


def call_region(lines, index, start):
    """Text of the call opened at lines[index][start:], bounded in lines and characters."""
    parts, depth, total = [], 0, 0
    for offset, line in enumerate(lines[index:index + MAX_CALL_LINES]):
        segment = line[start:] if offset == 0 else line
        for position, char in enumerate(segment):
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    return "\n".join(parts + [segment[:position]])
        parts.append(segment)
        total += len(segment)
        if total > MAX_CALL_CHARS:
            break
    return "\n".join(parts)


def js_conversation(value, raw, client):
    """'violated' when client data supplies whole messages, 'satisfied' when only their content."""
    refs = [m for name in client for m in reference(name).finditer(value)] + list(JS_CLIENT_SOURCE.finditer(value))
    if not refs:
        return None
    fixed_role = USER_ROLE.search(raw) and not DATA_ROLE.search(raw)
    for ref in refs:
        if JS_CONTENT_ONLY.search(value[max(ref.start() - 200, 0):ref.start()]):
            continue
        if fixed_role and JS_MAPPED.match(value, ref.end()):
            continue
        return "violated"
    return "satisfied"


def js_flows(text, code):
    rows = defaultdict(list)
    schema_helper = JS_FORMAT_HELPER.search(code) is not None
    lines = code.splitlines()
    raw_lines = text.splitlines() if len(text) == len(code) else lines
    tainted, sanitized, pending, client = {}, {}, {}, {}
    depth = 0

    def flowing(segment):
        return JS_MODEL_CALL.search(segment) is not None or any(reference(n).search(segment) for n in tainted)

    def close(level):
        for state in (tainted, sanitized, client):
            for name in [n for n, d in state.items() if d > level]:
                del state[name]
        for name in [n for n, (_, d) in pending.items() if d > level]:
            rows[PARSE].append((pending.pop(name)[0], "violated"))

    for index, line in enumerate(lines):
        number = index + 1
        stripped = line.lstrip()
        start_depth = max(depth - (len(stripped) - len(stripped.lstrip("}"))), 0)
        model = JS_MODEL_CALL.search(line)
        if model:
            region = call_region(lines, index, model.start())
            raw = call_region(raw_lines, index, model.start())
            for match in JS_CONVERSATION.finditer(region):
                if region[:match.start()].rstrip()[-1:] not in {"{", ","}:
                    continue
                value = arguments(region, match.end())[0] if match[2] else match[1]
                start = match.end() if match[2] else match.start()
                status = js_conversation(value, raw[start:start + len(value)], client)
                if status:
                    rows[CLIENT].append((number + region.count("\n", 0, match.start()), status))
        if model and (JS_SCHEMA_CALL.search(line) or (schema_helper and JS_SDK_PARSE.search(line))):
            rows[PARSE].append((number, "satisfied"))
        for match in JS_EXEC.finditer(line):
            if flowing("".join(arguments(line, match.end()))):
                rows[EXEC].append((number, "violated"))
        if re.search(r"\bshell\s*:\s*true\b", line):
            for match in JS_SPAWN.finditer(line):
                if flowing("".join(arguments(line, match.end()))):
                    rows[EXEC].append((number, "violated"))
        for match in JS_SQL.finditer(line):
            first, rest = arguments(line, match.end())
            if flowing(first):
                rows[EXEC].append((number, "violated"))
            elif flowing(rest):
                rows[EXEC].append((number, "satisfied"))
        for match in JS_HTML.finditer(line):
            segment = line[match.end():match.end() + SINK_WINDOW]
            guarded = [
                (m.end(), m.end() + len(",".join(arguments(segment, m.end()))) + 1)
                for m in JS_SANITIZER.finditer(segment)
            ]
            hits = [m.start() for name in tainted for m in reference(name).finditer(segment)]
            hits += [m.start() for m in JS_MODEL_CALL.finditer(segment)]
            if any(not any(a <= hit < b for a, b in guarded) for hit in hits):
                rows[HTML].append((number, "violated"))
            elif hits or any(reference(name).search(segment) for name in sanitized):
                rows[HTML].append((number, "satisfied"))
        text_sink = JS_TEXT.search(line)
        if text_sink and flowing(line[text_sink.end():text_sink.end() + SINK_WINDOW]):
            rows[HTML].append((number, "satisfied"))
        for name in list(pending):
            if re.search(JS_VALIDATOR + re.escape(name) + r"(?![\w$])", line):
                rows[PARSE].append((pending.pop(name)[0], "satisfied"))
        assignment = JS_ASSIGN.match(line)
        parse = JS_JSON_PARSE.search(line)
        parsed = None
        if parse and flowing(arguments(line, parse.end())[0]):
            if JS_WRAPPED.search(line[:parse.start()]):
                rows[PARSE].append((number, "satisfied"))
            elif assignment and assignment.start(3) <= parse.start():
                parsed = number
            else:
                rows[PARSE].append((number, "unclear"))
        if assignment:
            declared, target, value = assignment.groups()
            carries = flowing(value)
            supplied = JS_CLIENT_SOURCE.search(value) is not None or any(reference(n).search(value) for n in client)
            for name in js_targets(target):
                level = start_depth if declared else tainted.get(name, sanitized.get(name, client.get(name, start_depth)))
                tainted.pop(name, None)
                sanitized.pop(name, None)
                client.pop(name, None)
                if supplied:
                    client[name] = level
                if carries and JS_SANITIZER.search(value):
                    sanitized[name] = level
                elif carries:
                    tainted[name] = level
                    if parsed:
                        pending[name] = (parsed, level)
        loop = JS_FOR_OF.search(line)
        if loop and flowing(loop[2]):
            tainted[loop[1]] = start_depth + 1
        if loop and (JS_CLIENT_SOURCE.search(loop[2]) or any(reference(n).search(loop[2]) for n in client)):
            client[loop[1]] = start_depth + 1
        depth = max(depth + line.count("{") - line.count("}"), 0)
        close(depth)
    for number, _ in pending.values():
        rows[PARSE].append((number, "violated"))
    return rows


# --- Model-output flows: Python ---------------------------------------------

PY_MODEL_CALL = re.compile(
    r"(?:^|\.)(?:chat\.)?completions\.(?:create|parse|stream)$"
    r"|(?:^|\.)responses\.(?:create|parse|stream)$"
    r"|(?:^|\.)messages\.(?:create|stream)$"
    r"|(?:^|\.)generate_content(?:_async)?$"
    r"|(?:^|\.)(?:invoke_model|invoke_model_with_response_stream|converse|converse_stream)$"
    r"|^(?:litellm\.)?a?completion$"
    r"|^ollama\.(?:chat|generate)$"
    r"|(?:^|\.)(?:llm|model|chat_model|chain|agent|agent_executor|executor|query_engine|chat_engine|graph)"
    r"\.(?:a?invoke|a?predict|a?run|a?generate|a?chat|a?complete|a?query|a?stream)$"
)
PY_SDK_PARSE = re.compile(r"(?:^|\.)(?:completions|responses)\.parse$")
PY_EXEC = {
    "eval", "exec", "compile", "os.system", "os.popen", "render_template_string",
    "flask.render_template_string", "subprocess.getoutput", "subprocess.getstatusoutput",
}
PY_SUBPROCESS = {"subprocess.run", "subprocess.call", "subprocess.Popen", "subprocess.check_output", "subprocess.check_call"}
PY_SQL_RECEIVER = re.compile(r"(?i)(?:^|\.)(?:cursor|cur|conn|connection|db|database|session|engine|sql)\w*$")
PY_HTML = {"Markup", "markupsafe.Markup", "mark_safe", "django.utils.safestring.mark_safe"}
PY_SANITIZER = {"escape", "html.escape", "markupsafe.escape", "bleach.clean", "nh3.clean"}
PY_JSON = {"json.loads", "loads", "orjson.loads", "ujson.loads"}
PY_VALIDATOR = {"model_validate", "model_validate_json", "parse_obj", "parse_raw", "validate_python", "validate_json", "validate"}
PY_REQUEST = {
    f"request.{name}"
    for name in ("json", "get_json", "form", "args", "values", "data", "POST", "GET", "body", "query_params", "stream")
}
PY_ROUTE = re.compile(r"\.(?:get|post|put|patch|delete|route|api_route|websocket)$")
CONVERSATION_KEYS = {"messages", "contents", "history"}


def route_parameters(function):
    """Parameters a web framework fills from the request; injected dependencies excluded."""
    if not any(PY_ROUTE.search(dotted(d.func if isinstance(d, ast.Call) else d)) for d in function.decorator_list):
        return set()
    arguments_ = function.args
    positional = arguments_.posonlyargs + arguments_.args
    defaults = [None] * (len(positional) - len(arguments_.defaults)) + list(arguments_.defaults)
    pairs = list(zip(positional, defaults)) + list(zip(arguments_.kwonlyargs, arguments_.kw_defaults))
    return {
        argument.arg for argument, default in pairs
        if argument.arg not in {"self", "cls", "request"}
        and not (isinstance(default, ast.Call) and dotted(default.func).rsplit(".", 1)[-1] in {"Depends", "Security"})
    }


def dotted(node):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    elif isinstance(node, ast.Call):
        parts.append("()")
    else:
        return ""
    return ".".join(reversed(parts))


def nodes(node):
    """Nodes of one scope; nested functions, lambdas and classes are separate scopes."""
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(
            child for child in ast.iter_child_nodes(current)
            if not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda))
        )


def unwrap(node):
    return node.value if isinstance(node, ast.Await) else node


class PythonFlow:
    """Statement-ordered flow from model calls to sinks within one scope."""

    def __init__(self, rows, client=()):
        self.rows, self.tainted, self.sanitized, self.pending, self.assigned = rows, set(), set(), {}, set()
        self.client = set(client)

    def supplied(self, node):
        return node is not None and any(
            (isinstance(item, ast.Name) and item.id in self.client)
            or (isinstance(item, ast.Attribute) and dotted(item) in PY_REQUEST)
            for item in nodes(node)
        )

    def conversation(self, value):
        """'violated' when client data supplies whole messages, 'satisfied' when only their content."""
        parents = {child: parent for parent in ast.walk(value) for child in ast.iter_child_nodes(parent)}
        refs = [
            item for item in ast.walk(value)
            if (isinstance(item, ast.Name) and item.id in self.client)
            or (isinstance(item, ast.Attribute) and dotted(item) in PY_REQUEST)
        ]
        if not refs:
            return None
        for ref in refs:
            node, guarded = ref, False
            while node is not value and node in parents and not guarded:
                parent = parents[node]
                if isinstance(parent, ast.Dict) and node in parent.values:
                    key = parent.keys[parent.values.index(node)]
                    guarded = isinstance(key, ast.Constant) and key.value == "content"
                elif isinstance(parent, ast.comprehension) and node is parent.iter:
                    element = getattr(parents.get(parent), "elt", None)
                    roles = {
                        k.value: v for k, v in zip(getattr(element, "keys", []), getattr(element, "values", []))
                        if isinstance(k, ast.Constant)
                    }
                    guarded = isinstance(roles.get("role"), ast.Constant) and roles["role"].value == "user"
                node = parent
            if not guarded:
                return "violated"
        return "satisfied"

    def flows(self, node):
        return node is not None and any(
            (isinstance(item, ast.Name) and item.id in self.tainted)
            or (isinstance(item, ast.Call) and PY_MODEL_CALL.search(dotted(item.func)))
            for item in nodes(node)
        )

    def json_call(self, node):
        return isinstance(node, ast.Call) and dotted(node.func) in PY_JSON and any(self.flows(arg) for arg in node.args)

    def block(self, body):
        for statement in body:
            self.statement(statement)

    def statement(self, node):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return
        if isinstance(node, (ast.If, ast.While)):
            self.expression(node.test)
            self.block(node.body)
            self.block(node.orelse)
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            self.expression(node.iter)
            self.bind(node.target, node.iter, loop=True)
            self.block(node.body)
            self.block(node.orelse)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                self.expression(item.context_expr)
                if item.optional_vars is not None:
                    self.bind(item.optional_vars, item.context_expr)
            self.block(node.body)
        elif isinstance(node, ast.Try) or type(node).__name__ == "TryStar":
            self.block(node.body)
            for handler in node.handlers:
                self.block(handler.body)
            self.block(node.orelse)
            self.block(node.finalbody)
        elif type(node).__name__ == "Match":
            self.expression(node.subject)
            for case in node.cases:
                self.block(case.body)
        else:
            value = getattr(node, "value", None)
            if isinstance(node, (ast.Assign, ast.AnnAssign)) and self.json_call(unwrap(value)):
                self.assigned.add(id(unwrap(value)))
            self.expression(node)
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    self.bind(target, value)
            elif isinstance(node, ast.AnnAssign) and value is not None:
                self.bind(node.target, value)
            elif isinstance(node, ast.AugAssign) and self.flows(value):
                self.bind(node.target, value, loop=True)

    def bind(self, target, value, loop=False):
        if not isinstance(target, (ast.Name, ast.Tuple, ast.List, ast.Starred)):
            return
        carries, supplied = self.flows(value), self.supplied(value)
        names = [n.id for n in nodes(target) if isinstance(n, ast.Name)]
        if supplied or not loop:
            for name in names:
                (self.client.add if supplied else self.client.discard)(name)
        if loop and not carries:
            return
        inner = unwrap(value)
        clean = isinstance(inner, ast.Call) and dotted(inner.func) in PY_SANITIZER
        for name in names:
            self.tainted.discard(name)
            self.sanitized.discard(name)
            if carries and clean:
                self.sanitized.add(name)
            elif carries:
                self.tainted.add(name)
                if id(inner) in self.assigned:
                    self.pending[name] = inner.lineno

    def expression(self, node):
        calls = sorted(
            (item for item in nodes(node) if isinstance(item, ast.Call)),
            key=lambda item: (item.lineno, item.col_offset),
        )
        handled = set()
        for call in calls:
            self.sink(call, handled)

    def sink(self, call, handled):
        name = dotted(call.func)
        last = name.rsplit(".", 1)[-1]
        args = [self.flows(arg) for arg in call.args]
        hot = any(args) or any(self.flows(keyword.value) for keyword in call.keywords)
        line = call.lineno
        if PY_MODEL_CALL.search(name):
            for keyword in call.keywords:
                status = self.conversation(keyword.value) if keyword.arg in CONVERSATION_KEYS else None
                if status:
                    self.rows[CLIENT].append((keyword.value.lineno, status))
        if PY_SDK_PARSE.search(name) and {"response_format", "text_format"} & {k.arg for k in call.keywords}:
            self.rows[PARSE].append((line, "satisfied"))
        if last in PY_VALIDATOR and name not in PY_JSON:
            for value in [*call.args, *(keyword.value for keyword in call.keywords)]:
                for item in nodes(value):
                    if isinstance(item, ast.Name) and item.id in self.pending:
                        self.rows[PARSE].append((self.pending.pop(item.id), "satisfied"))
                    elif self.json_call(item):
                        handled.add(id(item))
                        self.rows[PARSE].append((line, "satisfied"))
            if last in {"model_validate_json", "parse_raw", "validate_json"} and hot:
                self.rows[PARSE].append((line, "satisfied"))
            return
        if name in PY_JSON and hot and id(call) not in handled and id(call) not in self.assigned:
            self.rows[PARSE].append((line, "unclear"))
        if not hot:
            return
        shell = any(
            keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True
            for keyword in call.keywords
        )
        receiver = dotted(call.func.value) if isinstance(call.func, ast.Attribute) else ""
        if name in PY_EXEC or (name in PY_SUBPROCESS and shell):
            self.rows[EXEC].append((line, "violated"))
        elif (last in {"execute", "executemany", "executescript"} and PY_SQL_RECEIVER.search(receiver)) or (
            last == "raw" and receiver.endswith("objects")
        ):
            self.rows[EXEC].append((line, "violated" if args and args[0] else "satisfied"))
        elif name in PY_HTML or last in {"Markup", "mark_safe"}:
            first = unwrap(call.args[0]) if call.args else None
            guarded = isinstance(first, ast.Call) and dotted(first.func) in PY_SANITIZER
            self.rows[HTML].append((line, "satisfied" if guarded else "violated"))
        elif name in PY_SANITIZER:
            self.rows[HTML].append((line, "satisfied"))

    def finish(self):
        for line in self.pending.values():
            self.rows[PARSE].append((line, "violated"))


def python_flows(tree):
    rows = defaultdict(list)
    scopes = [tree] + [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    for scope in scopes:
        flow = PythonFlow(rows, route_parameters(scope) if scope is not tree else ())
        flow.block(scope.body)
        flow.finish()
    return rows


# --- Committed agent and MCP configuration ----------------------------------

AGENT_CONFIG = re.compile(
    r"(?i)(?:^|/)(?:\.?mcp\.json|mcp_config\.json|mcp_settings\.json|cline_mcp_settings\.json|claude_desktop_config\.json)$"
    r"|(?:^|/)\.claude/settings(?:\.local)?\.json$|(?:^|/)\.gemini/settings\.json$"
)
CLAUDE_SETTINGS = re.compile(r"(?i)(?:^|/)\.claude/settings(?:\.local)?\.json$")
GEMINI_SETTINGS = re.compile(r"(?i)(?:^|/)\.gemini/settings\.json$")
SECRET_KEY = re.compile(r"(?i)api[_-]?key|token|secret|passw(?:or)?d|authorization|bearer|credential|private[_-]?key")
REFERENCE = re.compile(r"\$\{[^}]+\}|\$[A-Za-z_][A-Za-z0-9_]*|\{\{[^}]+\}\}|%[A-Za-z_][A-Za-z0-9_]*%")
PLACEHOLDER = re.compile(r"(?i)your|example|placeholder|changeme|replace|<[^>]*>|\.\.\.|\*\*\*|^x+$")
NPM_RUNNERS = {"npx", "bunx", "pnpx"}
DLX_RUNNERS = {"pnpm", "yarn", "bun"}
PYTHON_RUNNERS = {"uvx", "pipx"}
NPM_PINNED = re.compile(r"(?:@[\w.-]+/)?[\w.-]+@v?\d+\.\d+\.\d+(?:[-+][\w.-]+)?")
PYTHON_PINNED = re.compile(r"[A-Za-z0-9][\w.-]*(?:\[[\w,.-]+\])?(?:==|@)v?\d+(?:\.\d+)+(?:(?:a|b|rc|\.post|\.dev)\d+)*")
MAX_SPEC = 300
READ_ONLY_TOOLS = {"Glob", "Grep", "LS", "NotebookRead", "Read"}
WILDCARDS = {"", "*", "*:*", ":*", "**", "**/*"}
HIGH_RISK_COMMANDS = {
    "sudo", "su", "rm", "chmod", "chown", "ssh", "scp", "nc", "ncat", "eval", "exec", "dd", "mkfs", "curl", "wget",
}
SENSITIVE_PATH = re.compile(r"(?i)\.ssh|\.aws|\.gnupg|\.kube|\.netrc|\.npmrc|\.env\b|id_rsa|id_ed25519|credential|\.git/config")
LOOPBACK = {"localhost", "127.0.0.1", "::1"}


def agent_config(path):
    return AGENT_CONFIG.search(path) is not None


def strict_json(text):
    """A JSON object, or None; duplicate keys could hide the effective value."""
    def pairs(items):
        keys = [key for key, _ in items]
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate key")
        return dict(items)

    try:
        data = json.loads(text, object_pairs_hook=pairs)
    except (ValueError, RecursionError):
        return None
    return data if isinstance(data, dict) else None


def mapping(value):
    return value if isinstance(value, dict) else {}


class Locator:
    def __init__(self, text):
        self.text = text

    def find(self, *needles, start=0):
        """Line and offset of the first needle found at or after `start`, else of `start`."""
        for needle in needles:
            position = self.text.find(needle, start)
            if position >= 0:
                return line_at(self.text, position), position
        return line_at(self.text, start), start

    def key(self, *names, start=0):
        return self.find(*(json.dumps(name) for name in names), start=start)[0]


def servers(data):
    for value in (data.get("mcpServers"), data.get("servers"), mapping(data.get("mcp")).get("servers")):
        for name, server in mapping(value).items():
            if isinstance(server, dict):
                yield name, server


def credential(value):
    """'satisfied' for a reference, 'violated' for a literal, None for placeholders and non-secrets."""
    if not isinstance(value, str):
        return None
    stripped = re.sub(r"(?i)^(?:bearer|basic|token)\s+", "", value.strip())
    if REFERENCE.search(stripped):
        return "satisfied"
    if (
        len(stripped) < 8 or stripped.isdigit() or len(set(stripped)) < 4 or PLACEHOLDER.search(stripped)
        or stripped.startswith(("/", "~", "./", "http://", "https://"))
        or stripped.lower() in {"true", "false", "none", "null"}
    ):
        return None
    return "violated"


def transport(url):
    if REFERENCE.search(url):
        return "unclear"
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
    except ValueError:
        return "unclear"
    if parts.scheme in {"https", "wss"}:
        return "satisfied"
    if parts.scheme in {"http", "ws"}:
        return None if host in LOOPBACK or host.endswith(".localhost") else "violated"
    return None


def launch(server):
    """Pinning status of a package that a registry runner fetches at start, else None."""
    command, args = server.get("command"), server.get("args", [])
    if not isinstance(command, str) or not isinstance(args, list):
        return None
    tokens = command.split() + [str(arg) for arg in args]
    if not tokens:
        return None
    runner = re.sub(r"(?i)\.(?:cmd|exe)$", "", PurePosixPath(tokens[0].replace("\\", "/")).name).lower()
    rest = tokens[1:]
    if runner in DLX_RUNNERS and rest[:1] in (["dlx"], ["x"]):
        runner, rest = "npx", rest[1:]
    elif runner == "pipx" and rest[:1] == ["run"]:
        rest = rest[1:]
    elif runner == "uv" and rest[:2] == ["tool", "run"]:
        runner, rest = "uvx", rest[2:]
    if runner not in NPM_RUNNERS | PYTHON_RUNNERS:
        return None
    spec = None
    for index, token in enumerate(rest):
        if token in {"-p", "--package", "--from", "--spec"}:
            spec = rest[index + 1] if index + 1 < len(rest) else None
            break
        if token.startswith(("--package=", "--from=", "--spec=")):
            spec = token.split("=", 1)[1]
            break
        if not token.startswith("-"):
            spec = token
            break
    if spec is None or len(spec) > MAX_SPEC or REFERENCE.search(spec):
        return "unclear"
    if spec.startswith((".", "/", "~")) or re.match(r"[A-Za-z]:[\\/]", spec):
        return None
    if re.match(r"(?i)(?:git\+|github:|gitlab:|https?:)", spec):
        return "satisfied" if re.search(r"[#@][0-9a-fA-F]{40}$", spec) else "violated"
    pattern = PYTHON_PINNED if runner in PYTHON_RUNNERS else NPM_PINNED
    return "satisfied" if pattern.fullmatch(spec) else "violated"


def permission_grant(rule):
    """Whether a committed allow rule pre-approves shell or unrestricted writes."""
    if not isinstance(rule, str):
        return False
    match = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:\((.*)\))?", rule.strip(), re.S)
    if not match:
        return False
    tool, argument = match[1], (match[2] or "").strip()
    if tool == "Bash":
        if argument in WILDCARDS:
            return True
        command = re.split(r"[\s:]", argument, maxsplit=1)[0]
        return command in HIGH_RISK_COMMANDS and argument.endswith("*")
    if tool in {"Write", "Edit", "MultiEdit", "NotebookEdit"}:
        return argument in WILDCARDS or SENSITIVE_PATH.search(argument) is not None
    return False


def server_observations(rows, find, data):
    for name, server in servers(data):
        if server.get("disabled") is True:
            continue
        start = find.find(json.dumps(name))[1]
        for container in ("env", "headers"):
            for key, value in mapping(server.get(container)).items():
                status = credential(value) if SECRET_KEY.search(str(key)) else None
                if status:
                    rows[MCP_CREDENTIAL].append((find.key(key, start=start), status))
        argv = server.get("args") if isinstance(server.get("args"), list) else []
        for index, argument in enumerate(argv):
            flag = re.fullmatch(r"--?([\w-]+)(?:=(.*))?", str(argument), re.S)
            if flag and SECRET_KEY.search(flag[1]):
                value = flag[2] if flag[2] is not None else (argv[index + 1] if index + 1 < len(argv) else None)
                status = credential(value)
                if status:
                    rows[MCP_CREDENTIAL].append((find.key(str(argument), start=start), status))
        key = next((key for key in ("url", "serverUrl", "httpUrl", "uri") if isinstance(server.get(key), str)), None)
        status = transport(server[key]) if key else None
        if status:
            rows[MCP_TRANSPORT].append((find.key(key, start=start), status))
        status = launch(server)
        if status:
            rows[MCP_SOURCE].append((find.key("command", start=start), status))
        if server.get("trust") is True:
            rows[BYPASS].append((find.key("trust", start=start), "violated"))
        for key in ("autoApprove", "alwaysAllow"):
            approved = server.get(key)
            if isinstance(approved, list) and any(isinstance(tool, str) and tool.strip() for tool in approved):
                rows[AUTO_APPROVE].append((find.key(key, start=start), "violated"))


def claude_observations(rows, find, data):
    permissions = mapping(data.get("permissions"))
    mode = permissions.get("defaultMode", data.get("defaultMode"))
    if mode == "bypassPermissions":
        rows[BYPASS].append((find.key("defaultMode"), "violated"))
    if permissions.get("disableBypassPermissionsMode") == "disable":
        rows[BYPASS].append((find.key("disableBypassPermissionsMode"), "satisfied"))
    if data.get("enableAllProjectMcpServers") is True:
        rows[AUTO_APPROVE].append((find.key("enableAllProjectMcpServers"), "violated"))
    allow = permissions.get("allow") if isinstance(permissions.get("allow"), list) else []
    for rule in allow:
        if permission_grant(rule):
            rows[PERMISSIONS].append((find.key(rule), "violated"))
    sandbox = data.get("sandbox")
    autonomy = (
        any(isinstance(rule, str) and rule.strip() and rule.split("(", 1)[0].strip() not in READ_ONLY_TOOLS for rule in allow)
        or mode in {"acceptEdits", "bypassPermissions"}
        or data.get("enableAllProjectMcpServers") is True
    )
    if sandbox is True or mapping(sandbox).get("enabled") is True:
        rows[SANDBOX].append((find.key("sandbox"), "satisfied"))
    elif autonomy:
        rows[SANDBOX].append((find.key("sandbox", "permissions", "defaultMode", "enableAllProjectMcpServers"), "violated"))


def gemini_observations(rows, find, data):
    tools = mapping(data.get("tools"))
    accepts = tools.get("autoAccept", data.get("autoAccept")) is True
    if accepts:
        rows[BYPASS].append((find.key("autoAccept"), "violated"))
    sandbox = tools.get("sandbox", data.get("sandbox"))
    if sandbox is True or (isinstance(sandbox, str) and sandbox.strip().lower() in {"docker", "podman"}):
        rows[SANDBOX].append((find.key("sandbox"), "satisfied"))
    elif accepts or any(server.get("trust") is True for _, server in servers(data)):
        rows[SANDBOX].append((find.key("sandbox", "autoAccept", "trust"), "violated"))


def config_observations(path, text):
    rows = defaultdict(list)
    claude, gemini = CLAUDE_SETTINGS.search(path), GEMINI_SETTINGS.search(path)
    data = strict_json(text)
    if data is None:
        rules = SETTINGS_RULES if claude else SETTINGS_RULES + MCP_RULES if gemini else MCP_RULES
        for rule in dict.fromkeys(rules):
            rows[rule].append((1, "unclear"))
        return rows
    rows[INTEGRATION].append((1, "satisfied", "agent configuration"))
    find = Locator(text)
    server_observations(rows, find, data)
    if claude:
        claude_observations(rows, find, data)
    if gemini:
        gemini_observations(rows, find, data)
    return rows


def inspect(path, text, code=None, tree=None):
    """Observations by AI rule ID for one file: one (line, status) row per location."""
    rows = observations(path, text, code, tree)
    return {rule: sorted(set(values)) for rule, values in rows.items()}


def observations(path, text, code, tree):
    if agent_config(path):
        return config_observations(path, text)
    suffix = PurePosixPath(path).suffix.lower()
    rows = defaultdict(list)
    if suffix == ".py":
        inventory = python_inventory(tree) if tree is not None else []
        if inventory:
            rows.update(python_flows(tree))
    elif suffix in JS_EXTENSIONS:
        code = text if code is None else code
        inventory = js_inventory(text, code)
        if inventory:
            rows.update(js_flows(text, code))
    else:
        inventory = [(line, "satisfied", "declared package") for line in manifest_lines(path, text)]
        inventory += config_inventory(path, text)
    rows[INTEGRATION] = inventory
    return rows
