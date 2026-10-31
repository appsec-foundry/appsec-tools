"""Deterministic, source-only checks. No imports or execution from the target."""

from __future__ import annotations

import ast
from bisect import bisect_right
from collections import Counter, defaultdict
import hashlib
from pathlib import Path
import re
import textwrap
from score_infrastructure import ci_file, manifests_without_lock
from score_reporting import container_build_file, source_priority

from score_calculation import (
    CATALOG_BYTES,
    POLICY,
    VERSION,
    WEIGHTS,
    calculate as calculate,
    grade as grade,
    validate_scoring,
)


MODULES = Path(__file__).resolve().parent
RULE_VERSION = POLICY["rule_version"]
RULES = POLICY["rules"]


def validate_policy():
    kinds = {
        "py-exec",
        "py-shell",
        "py-sql",
        "py-tls",
        "py-yaml",
        "py-pickle",
        "py-hash",
        "py-debug",
        "py-random",
        "py-jwt",
        "js-eval",
        "js-shell",
        "js-random",
        "js-hash",
        "js-html",
        "js-tls",
        "js-jwt",
        "actions",
        "image",
        "image-script",
        "image-add",
        "user",
        "js-sql",
        "frontend",
        "csp",
        "headers",
        "npm-sources",
        "npm-lock",
        "npm-install",
        "requirements",
        "workflow-permissions",
        "workflow-injection",
        "workflow-checkout",
        "container-privileges",
        "container-hardening",
        "host",
        "path",
        "dependency-lock",
        "secret-token",
        "ci-script",
        "install-command",
        "gitlab-image",
        "gitlab-include",
        "gitlab-injection",
        "lockfile",
        "manifest-sources",
        "release-integrity",
        "cloud-oidc",
        "password-hash",
        "js-cookie",
        "js-cors",
        "web-settings",
        "tf-ingress",
        "tf-public",
        "tf-iam",
        "tf-module",
    }
    catalog = POLICY["rules"]  # Disabled rules still reserve their IDs.
    if (
        type(VERSION) is not int
        or VERSION < 1
        or not isinstance(catalog, list)
        or not catalog
    ):
        raise ValueError("Invalid rule catalog version or rule list.")
    validate_scoring()
    identifiers = set()
    for rule in catalog:
        if (
            not isinstance(rule, dict)
            or not re.fullmatch(r"[A-Z][A-Z0-9-]{0,79}", rule.get("id", ""))
            or rule["id"] in identifiers
        ):
            raise ValueError("Rule IDs must be unique and stable.")
        identifiers.add(rule["id"])
        if rule.get("kind") not in kinds or rule.get("severity") not in WEIGHTS:
            raise ValueError("Unknown detector or severity in rule catalog.")
        if type(rule.get("enabled", True)) is not bool:
            raise ValueError("A rule's enabled flag must be true or false.")
        for field in ("area", "title", "criteria", "next_action"):
            if not isinstance(rule.get(field), str) or not rule[field].strip():
                raise ValueError(
                    "Each rule needs area, title, criteria and next action."
                )
        if not isinstance(rule.get("examples"), list) or not rule["examples"]:
            raise ValueError("Every rule needs verifiable examples.")
        if type(rule.get("positive_only", False)) is not bool:
            raise ValueError("A rule's positive_only flag must be true or false.")
        if rule["kind"] == "path":
            if not isinstance(rule.get("pattern"), str):
                raise ValueError("A path rule needs a pattern.")
            re.compile(rule["pattern"])
            re.compile(rule.get("exclude", "(?!)"))
    relevance = POLICY["change_relevance"]
    if (
        type(RULE_VERSION) is not int
        or RULE_VERSION < 1
        or type(relevance["version"]) is not int
        or relevance["version"] < 1
    ):
        raise ValueError("Rule and relevance versions must be positive integers.")
    relevance_rules = [
        *relevance["path_rules"],
        *relevance["code_rules"],
        *relevance["area_rules"].values(),
        relevance["documentation_rule"],
        relevance["executable_rule"],
    ]
    for rule in relevance_rules:
        if rule["id"] in identifiers or not re.fullmatch(
            r"[A-Z][A-Z0-9-]{0,79}", rule["id"]
        ):
            raise ValueError("Relevance rule IDs must be unique and stable.")
        identifiers.add(rule["id"])
        if (
            rule["level"] not in {"high", "medium"}
            or not rule["reason"]
            or not rule["aspect"]
        ):
            raise ValueError(
                "Positive relevance signals need a level, aspect and reason."
            )
        if "pattern" in rule:
            re.compile(rule["pattern"])
    if not relevance["examples"] or not all(
        example["expected_relevance"] in {"high", "medium", "low", "unclear"}
        for example in relevance["examples"]
    ):
        raise ValueError("Relevance examples need expected outcomes.")
    if not any(rule.get("enabled", True) for rule in catalog):
        raise ValueError("Invalid rule catalog version or rule list.")


validate_policy()
# Disabled rules keep their ID reserved and their examples, but never run.
RULES = [rule for rule in RULES if rule.get("enabled", True)]
CATALOG_HASH = hashlib.sha256(CATALOG_BYTES).hexdigest()
IMPLEMENTATION_HASH = hashlib.sha256(
    b"".join(
        (MODULES / name).read_bytes()
        for name in (
            "score_core.py",
            "score_calculation.py",
            "score_reporting.py",
            "score_sources.py",
            "score_remote.py",
            "score_remote_sources.py",
            "score_architecture.py",
            "score_infrastructure.py",
            "score_relevance.py",
            "score.py",
        )
    )
).hexdigest()
JS_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
SOURCE_EXTENSIONS = JS_EXTENSIONS | {
    ".py",
    ".yaml",
    ".yml",
    ".json",
    ".html",
    ".conf",
    ".config",
    ".tf",
}
GRADLE_BUILD_FILES = {
    "build.gradle",
    "build.gradle.kts",
    "settings.gradle",
    "settings.gradle.kts",
}
DEPENDENCY_FILES = {"pyproject.toml", "pom.xml", "Cargo.toml"} | GRADLE_BUILD_FILES
LOCKFILES = {"package-lock.json", "npm-shrinkwrap.json"}


class ScanLimit(ValueError):
    pass


def supported(path):
    return (
        Path(path).suffix.lower() in SOURCE_EXTENSIONS
        or Path(path).name in DEPENDENCY_FILES
        or container_build_file(Path(path).name)
        or (Path(path).name.startswith("requirements") and Path(path).suffix == ".txt")
    )


def change_supported(path):
    """Read selected context for relevance without expanding repository scoring."""
    return (
        supported(path)
        or Path(path).suffix.lower()
        in {
            ".md",
            ".rst",
            ".adoc",
            ".txt",
            ".java",
            ".kt",
            ".scala",
            ".go",
            ".rs",
            ".cs",
            ".php",
            ".rb",
            ".sql",
            ".vue",
            ".svelte",
            ".xml",
            ".toml",
            ".ini",
            ".properties",
            ".sh",
            ".bash",
            ".ps1",
            ".tf",
            ".lock",
            ".gradle",
            ".kts",
            ".svg",
        }
        or Path(path).name in {"Gemfile", "Jenkinsfile", "CODEOWNERS"}
    )


def qualified(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return qualified(node.value) + "." + node.attr
    return ""


def literal(node, value):
    return (
        isinstance(node, ast.Constant)
        and type(node.value) is type(value)
        and node.value == value
    )


SECRET_WORDS = {"token", "secret", "otp", "nonce", "salt", "csrf", "xsrf", "password"}
SECRET_PAIRS = {("session", "id"), ("api", "key"), ("private", "key")}
DIGEST_WORDS = {"signature", "token", "password", "credential", "secret", "hmac"}


def identifier_named(line, words, pairs=()):
    """Match camelCase and snake_case identifier segments, not substrings."""
    for identifier in re.findall(r"[A-Za-z_$][\w$]*", line):
        parts = [
            part.lower()
            for part in re.findall(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+", identifier)
        ]
        if words.intersection(parts) or any(
            pair in pairs for pair in zip(parts, parts[1:])
        ):
            return True
    return False


def module_strings(tree):
    """Module-level names bound exactly once to a string literal."""
    values, counts = {}, Counter()
    for node in tree.body:
        targets = (
            node.targets
            if isinstance(node, ast.Assign)
            else [node.target]
            if isinstance(node, (ast.AnnAssign, ast.AugAssign))
            else []
        )
        for target in targets:
            for name in ast.walk(target):
                if isinstance(name, ast.Name):
                    counts[name.id] += 1
            if isinstance(target, ast.Name) and (
                isinstance(getattr(node, "value", None), ast.Constant)
                and isinstance(node.value.value, str)
            ):
                values[target.id] = node.value.value
    return {name: value for name, value in values.items() if counts[name] == 1}


def jwt_status(call, strings):
    """Disabled verification violates; only a literal allow-list without none satisfies."""
    options = {kw.arg: kw.value for kw in call.keywords}
    if literal(options.get("verify"), False):
        return "violated"
    settings = options.get("options")
    unclear = settings is not None and not isinstance(settings, ast.Dict)
    if isinstance(settings, ast.Dict):
        for key, value in zip(settings.keys, settings.values):
            if key is None:
                unclear = True
            elif isinstance(key, ast.Constant) and key.value in {
                "verify_signature",
                "verify_exp",
            }:
                if literal(value, False):
                    return "violated"
                unclear = unclear or not literal(value, True)
    algorithms = options.get("algorithms")
    names = (
        [
            element.value
            if isinstance(element, ast.Constant) and isinstance(element.value, str)
            else strings.get(element.id)
            if isinstance(element, ast.Name)
            else None
            for element in algorithms.elts
        ]
        if isinstance(algorithms, (ast.List, ast.Tuple, ast.Set))
        else []
    )
    if any(isinstance(name, str) and name.lower() == "none" for name in names):
        return "violated"
    if names and all(isinstance(name, str) for name in names) and not unclear:
        return "satisfied"
    return "unclear"


def python_observations(rule, text, tree=None):
    """Return (line, status) for recognized calls; unrecognized aliases stay uncovered."""
    try:
        tree = tree if tree is not None else ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return [], True
    observations = []
    kind = rule["kind"]
    lines = text.splitlines()
    strings = module_strings(tree) if kind == "py-jwt" else {}
    for call in ast.walk(tree):
        if (
            kind == "py-tls"
            and isinstance(call, ast.Assign)
            and any(
                isinstance(target, ast.Attribute)
                and target.attr in {"check_hostname", "verify_mode"}
                for target in call.targets
            )
        ):
            value = qualified(call.value)
            observations.append(
                (
                    call.lineno,
                    "violated"
                    if literal(call.value, False) or value == "ssl.CERT_NONE"
                    else "satisfied"
                    if literal(call.value, True) or value == "ssl.CERT_REQUIRED"
                    else "unclear",
                )
            )
            continue
        if not isinstance(call, ast.Call):
            continue
        name = qualified(call.func)
        args = call.args
        options = {kw.arg: kw.value for kw in call.keywords}
        status = None
        if kind == "py-exec" and name in {"eval", "exec", "ast.literal_eval"}:
            status = "satisfied" if name == "ast.literal_eval" else "violated"
        elif kind == "py-shell" and name in {
            "subprocess.run",
            "subprocess.call",
            "subprocess.check_call",
            "subprocess.check_output",
            "subprocess.Popen",
        }:
            shell = options.get("shell", ast.Constant(False))
            if literal(shell, True):
                status = "violated"
            elif (
                literal(shell, False)
                and args
                and isinstance(args[0], (ast.List, ast.Tuple))
            ):
                status = "satisfied"
            else:
                status = "unclear"
        elif kind == "py-shell" and name in {
            "os.system",
            "os.popen",
            "subprocess.getoutput",
            "subprocess.getstatusoutput",
            "asyncio.create_subprocess_shell",
        }:
            status = "violated"  # These interfaces always invoke a shell.
        elif (
            kind == "py-sql"
            and name.rsplit(".", 1)[-1] in {"execute", "executemany"}
            and args
        ):
            query = args[0]
            if isinstance(query, (ast.JoinedStr, ast.BinOp)) or (
                isinstance(query, ast.Call)
                and isinstance(query.func, ast.Attribute)
                and query.func.attr == "format"
            ):
                status = "violated"
            elif isinstance(query, ast.Constant) and isinstance(query.value, str):
                status = "satisfied"
            else:
                status = "unclear"
        elif kind == "py-tls" and name in {
            module + "." + verb
            for module, verbs in (
                ("requests", ()),
                ("httpx", ("options", "stream", "Client", "AsyncClient")),
            )
            for verb in (
                "get",
                "post",
                "put",
                "patch",
                "delete",
                "head",
                "request",
                *verbs,
            )
        }:
            verify = options.get("verify", ast.Constant(True))
            status = (
                "violated"
                if literal(verify, False)
                else "satisfied"
                if literal(verify, True)
                else "unclear"
            )
        elif kind == "py-tls" and name == "ssl._create_unverified_context":
            status = "violated"
        elif kind == "py-yaml" and name in {
            "yaml.load",
            "yaml.load_all",
            "yaml.safe_load",
            "yaml.safe_load_all",
            "yaml.unsafe_load",
            "yaml.unsafe_load_all",
        }:
            loader = qualified(options.get("Loader"))
            status = (
                "satisfied"
                if name.startswith("yaml.safe_")
                or loader in {"yaml.SafeLoader", "yaml.CSafeLoader"}
                else "violated"
                if name.startswith("yaml.unsafe_")
                or loader
                in {
                    "yaml.Loader",
                    "yaml.UnsafeLoader",
                    "yaml.CLoader",
                    "yaml.CUnsafeLoader",
                }
                else "unclear"
            )
        elif kind == "py-pickle" and name in {"pickle.load", "pickle.loads"}:
            status = "violated"
        elif kind == "py-hash" and name.startswith("hashlib."):
            # A broken primitive is relevant here only with a named security purpose.
            line = lines[call.lineno - 1]
            if re.search(
                r"\b(?:signature|token|password|credential|secret|hmac)\w*\b",
                line,
                re.I,
            ):
                status = (
                    "violated" if name in {"hashlib.md5", "hashlib.sha1"} else "unclear"
                )
        elif kind == "py-debug" and name == "app.run" and "debug" in options:
            status = (
                "violated"
                if literal(options["debug"], True)
                else "satisfied"
                if literal(options["debug"], False)
                else "unclear"
            )
        elif (
            kind == "py-random"
            and (
                name.startswith(("random.", "secrets."))
                or name in {"os.urandom", "random.SystemRandom"}
            )
            and identifier_named(lines[call.lineno - 1], SECRET_WORDS, SECRET_PAIRS)
        ):
            status = (
                "violated"
                if name.startswith("random.") and name != "random.SystemRandom"
                else "satisfied"
            )
        elif kind == "py-jwt" and (
            name == "jwt.decode" or name.endswith(".jwt.decode")
        ):
            status = jwt_status(call, strings)
        if status:
            observations.append((call.lineno, status))
    return observations, False


REGEX_KEYWORDS = {
    "return",
    "typeof",
    "instanceof",
    "in",
    "new",
    "delete",
    "void",
    "throw",
    "case",
    "do",
    "else",
    "yield",
    "await",
}


def regex_start(text, previous, position, word_start):
    """A slash after an operator, an opening bracket or a keyword starts a regex.

    After a value, `)`, `]` or `}` it is division. `<` and `>` count as values so
    JSX closing tags are never masked; `=>` starts an expression.
    """
    if not previous:
        return True
    before = text[position - 1] if position else ""
    if previous.isalnum() or previous in "_$":
        # Keywords are short; slicing only those keeps long identifiers cheap.
        return (
            0 <= position - word_start < 10
            and text[word_start : position + 1] in REGEX_KEYWORDS
        )
    if previous in "+-" and before == previous:
        return False
    if previous == ">":
        return before == "="
    return previous in "(,=:[!&|?{};~+-*%^"


def regex_end(text, start):
    """Return (end, reached) of a literal closed on the same line; end is None if open."""
    in_class = False
    index = start + 1
    while index < len(text):
        char = text[index]
        if char in "\n\r":
            return None, index
        if char == "\\":
            if text[index + 1 : index + 2] in {"\n", "\r", ""}:
                return None, index + 1
            index += 2
            continue
        if in_class:
            in_class = char != "]"
        elif char == "[":
            in_class = True
        elif char == "/":
            index += 1
            while index < len(text) and (text[index].isalnum() or text[index] in "_$"):
                index += 1
            return index, index
        index += 1
    return None, index


def javascript_code(text):
    """Mask comments and literal contents, preserving offsets and line numbers.

    This is a lexer for narrow patterns, not a JavaScript parser. Template
    interpolation is retained as code. Regular-expression literals are recognized
    from the preceding token; an unclosed candidate is read as division, except in
    template interpolation, where it fails closed. After one unclosed candidate the
    rest of its line is read as division, which keeps the lexer linear.
    """
    out = list(text)
    state = None
    quote = None
    escaped = False
    interpolations = []
    previous, position, word_start = "", 0, -1
    no_regex_until = -1
    index = 0
    while index < len(text):
        char = text[index]
        pair = text[index : index + 2]
        if state == "line":
            if char == "\n":
                state = None
            else:
                out[index] = " "
        elif state == "block":
            if pair == "*/":
                out[index : index + 2] = "  "
                index += 1
                state = None
            elif char != "\n":
                out[index] = " "
        elif state == "string":
            if quote == "`" and not escaped and pair == "${":
                out[index : index + 2] = "  "
                interpolations.append(0)
                state = None
                previous, position, word_start = "{", index + 1, -1
                index += 2
                continue
            if char != "\n":
                out[index] = " "
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                state = None
                previous, position, word_start = ")", index, -1  # A literal is a value.
        elif interpolations and char == "}":
            if interpolations[-1] == 0:
                interpolations.pop()
                state, quote = "string", "`"
                out[index] = " "
            else:
                interpolations[-1] -= 1
                previous, position, word_start = char, index, -1
        elif interpolations and char == "{":
            interpolations[-1] += 1
            previous, position, word_start = char, index, -1
        elif pair in {"//", "/*"}:
            state = "line" if pair == "//" else "block"
            out[index : index + 2] = "  "
            index += 1
        elif char == "/":
            if regex_start(text, previous, position, word_start):
                end, reached = (
                    regex_end(text, index) if index > no_regex_until else (None, index)
                )
                if end is not None:
                    out[index:end] = " " * (end - index)
                    previous, position, word_start = ")", end - 1, -1
                    index = end
                    continue
                if interpolations:
                    raise SyntaxError("Ambiguous slash in template interpolation")
                no_regex_until = max(no_regex_until, reached)
            previous, position, word_start = char, index, -1
        elif char in {"'", '"', "`"}:
            state, quote = "string", char
            out[index] = " "
        elif char.isalnum() or char in "_$":
            if position != index - 1 or word_start < 0:
                word_start = index
            previous, position = char, index
        elif not char.isspace():
            previous, position, word_start = char, index, -1
        index += 1
    if state in {"string", "block"} or interpolations:
        raise SyntaxError("Incomplete JavaScript lexical context")
    return "".join(out)


def shell_observations(text, code):
    """Resolve narrow child_process imports; a method called exec is insufficient."""
    bindings = {}
    methods = {"exec", "execSync", "execFile", "execFileSync"}
    declarations = [
        (
            r"\bimport\s+(\*\s+as\s+\w+|\w+|\{[^{}\n]*\})\s+from\s+['\"](?:node:)?child_process['\"]",
            "as",
        ),
        (
            r"\b(?:const|let|var)\s+(\w+|\{[^{}\n]*\})\s*=\s*require\s*\(\s*['\"](?:node:)?child_process['\"]\s*\)",
            ":",
        ),
    ]
    for pattern, separator in declarations:
        for match in re.finditer(pattern, text):
            if code[match.start()].isspace():
                continue
            binding = match[1].strip()
            if binding.startswith("{"):
                for item in binding[1:-1].split(","):
                    names = re.split(
                        r"\s+as\s+" if separator == "as" else r"\s*:\s*", item.strip()
                    )
                    if names[0] in methods and re.fullmatch(
                        r"[A-Za-z_$][\w$]*", names[-1]
                    ):
                        bindings[names[-1]] = names[0]
            else:
                namespace = binding.split()[-1]
                bindings.update(
                    {namespace + "." + method: method for method in methods}
                )
    breaks = [match.start() for match in re.finditer("\n", code)]
    rows = []
    handled = set()
    for match in re.finditer(
        r"(?<![\w$.])([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)?)\s*\(", code
    ):
        name = re.sub(r"\s", "", match[1])
        method = bindings.get(name)
        if method:
            status = "violated" if method in {"exec", "execSync"} else "unclear"
        elif name.split(".")[-1] in methods:
            status = "unclear"
        else:
            continue
        handled.add(match.end())
        rows.append((bisect_right(breaks, match.start()) + 1, status))
    for match in re.finditer(
        r"\.\s*(?:exec|execSync|execFile|execFileSync)\s*\(", code
    ):
        if match.end() not in handled:
            rows.append((bisect_right(breaks, match.start()) + 1, "unclear"))
    return rows


def other_observations(rule, text, code=None):
    kind = rule["kind"]
    code = (
        code
        if code is not None
        else javascript_code(text)
        if kind.startswith("js-")
        else text
    )
    observations = []
    if kind == "js-shell":
        return shell_observations(text, code), False
    if kind == "js-eval":
        line_breaks = [match.start() for match in re.finditer("\n", code)]
        return [
            (
                bisect_right(line_breaks, match.start()) + 1,
                "satisfied" if match.group().startswith("JSON") else "violated",
            )
            # `$eval` (Puppeteer, Playwright) is a selector helper, not evaluation.
            for match in re.finditer(
                r"(?<![\w$])(?:eval|Function|JSON\.parse)\s*\(", code
            )
        ], False
    original_lines = text.splitlines() if kind in {"js-hash", "js-tls"} else []
    stages = set()
    for number, line in enumerate(code.splitlines(), 1):
        status = None
        if kind == "js-random":
            if re.search(r"\bMath\.random\s*\(", line):
                status = "violated"
            elif re.search(
                r"\bcrypto\.(?:randomBytes|randomUUID|getRandomValues|randomInt)\s*\(",
                line,
            ):
                status = "satisfied"
            if status and not identifier_named(line, SECRET_WORDS, SECRET_PAIRS):
                status = None
        elif kind == "js-hash":
            match = re.search(r"\bcreateHash\s*\(", line)
            if match and identifier_named(line, DIGEST_WORDS):
                algorithm = re.match(
                    r"\s*(['\"`])([\w-]+)\1", original_lines[number - 1][match.end() :]
                )
                status = (
                    "violated"
                    if algorithm and algorithm[2].lower() in {"md5", "sha1"}
                    else "unclear"
                )
        elif kind == "js-html":
            if re.search(
                r"\.(?:inner|outer)HTML\s*\+?=(?!=)|\.insertAdjacentHTML\s*\(|\bdocument\s*\.\s*write(?:ln)?\s*\(",
                line,
            ):
                status = "violated"
            elif re.search(r"\.textContent\s*=(?!=)", line):
                status = "satisfied"
        elif kind == "js-tls":
            match = re.search(r"\brejectUnauthorized\s*:\s*(\w+)", line)
            setting = re.search(r"\bNODE_TLS_REJECT_UNAUTHORIZED\s*=(?!=)", line)
            if match:
                status = {"false": "violated", "true": "satisfied"}.get(
                    match[1], "unclear"
                )
            elif setting:
                value = re.match(
                    r"\s*(['\"`]?)(\w*)\1\s*(?:[;,)]|$)",
                    original_lines[number - 1][setting.end() :],
                )
                status = (
                    {"0": "violated", "1": "satisfied"}.get(value[2], "unclear")
                    if value
                    else "unclear"
                )
        elif kind == "actions":
            match = re.match(r"\s*(?:-\s*)?uses:\s*['\"]?([^\s'\"#]+)", line)
            if match and not match[1].startswith("./"):
                value = match[1]
                if value.startswith("docker://"):
                    status = (
                        "satisfied"
                        if re.search(r"@sha256:[0-9a-fA-F]{64}$", value)
                        else "violated"
                    )
                elif re.fullmatch(r"[\w.-]+/[\w./-]+@[\w.-]+", value):
                    status = (
                        "satisfied"
                        if re.search(r"@[0-9a-fA-F]{40}$", value)
                        else "violated"
                    )
                else:
                    status = "unclear"
        elif kind == "image":
            match = re.match(
                r"(?i)\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?", line
            )
            # A reference to an earlier build stage pulls no image.
            if match and match[1].lower() not in stages | {"scratch"}:
                value = match[1]
                status = (
                    "satisfied"
                    if re.search(r"@sha256:[0-9a-fA-F]{64}$", value)
                    else "unclear"
                    if "$" in value
                    else "violated"
                )
            if match and match[2]:
                stages.add(match[2].lower())
        if status:
            observations.append((number, status))
    return observations, False


def applies(rule, path):
    kind = rule["kind"]
    suffix = Path(path).suffix.lower()
    if kind.startswith("py-"):
        return suffix == ".py"
    if kind.startswith("js-"):
        return suffix in JS_EXTENSIONS
    if kind == "actions":
        return path.startswith(".github/workflows/") and suffix in {".yml", ".yaml"}
    if kind in {"workflow-permissions", "workflow-injection", "workflow-checkout"}:
        return path.startswith(".github/workflows/") and suffix in {".yml", ".yaml"}
    if kind == "container-privileges":
        return suffix in {".yml", ".yaml"}
    if kind.startswith("npm-"):
        return Path(path).name == "package.json"
    if kind == "requirements":
        return Path(path).name.startswith("requirements") and suffix == ".txt"
    if kind == "js-sql":
        return suffix in JS_EXTENSIONS
    if kind == "frontend":
        return suffix in JS_EXTENSIONS or path.endswith(".component.html")
    if kind in {"csp", "headers"}:
        return suffix in JS_EXTENSIONS | {".py", ".json", ".conf", ".config"}
    if kind in {"host", "path", "dependency-lock"}:
        return False
    if kind == "secret-token":
        return True
    if kind in {
        "ci-script",
        "gitlab-image",
        "gitlab-include",
        "gitlab-injection",
        "release-integrity",
        "cloud-oidc",
    }:
        return ci_file(path) and (
            not kind.startswith("gitlab-") or not path.startswith(".github/")
        )
    if kind == "install-command":
        return ci_file(path) or container_build_file(Path(path).name)
    if kind == "container-hardening":
        return suffix in {".yml", ".yaml"}
    if kind == "lockfile":
        return Path(path).name in LOCKFILES
    if kind == "manifest-sources":
        return Path(path).name in DEPENDENCY_FILES
    if kind == "password-hash":
        return suffix in JS_EXTENSIONS | {".py"}
    if kind == "web-settings":
        return suffix == ".py"
    if kind.startswith("tf-"):
        return suffix == ".tf"
    return container_build_file(Path(path).name)


def scan_paths(paths, findings, checks, files=None):
    """Rules decided by the file list: a path alone, or a lockfile beside a manifest.

    Without files the lockfile rule stays silent, as for an incomplete listing.
    """
    for rule in RULES:
        status = "satisfied" if rule.get("positive_only") else "violated"
        if rule["kind"] == "path":
            pattern = re.compile(rule["pattern"])
            ignored = re.compile(rule.get("exclude", "(?!)"))
            matches = [
                path
                for path in paths
                if pattern.search(path) and not ignored.search(path)
            ]
            evidence = "Recognized by its path; the file's content was not read."
        elif rule["kind"] == "dependency-lock":
            matches = [] if files is None else manifests_without_lock(paths, files)
            evidence = "No lockfile beside this manifest or in a directory above it."
        else:
            continue
        for path in matches:
            checks.append(
                {
                    "rule": rule["id"],
                    "area": rule["area"],
                    "file": path,
                    "status": status,
                    "locations": [{"line": 1, "status": status}],
                }
            )
            if status == "violated":
                findings.append(
                    {
                        "rule": rule["id"],
                        "area": rule["area"],
                        "severity": rule["severity"],
                        "title": rule["title"],
                        "file": path,
                        "line": 1,
                        "evidence": evidence,
                        "next_action": rule["next_action"],
                    }
                )
    return findings, checks


def scan(files, budget, findings=None, checks=None):
    findings = [] if findings is None else findings
    checks = [] if checks is None else checks
    for path in sorted(files, key=source_priority):
        original = files[path]
        for source in original.get("fragments", [original]):
            try:
                scan_source(path, source, budget, findings, checks, files)
            except (RecursionError, TypeError, IndexError, OverflowError):
                checks.append(
                    {
                        "rule": "SOURCE-PROCESSING",
                        "area": "coverage",
                        "file": path,
                        "status": "unclear",
                        "error": "Source structure exceeds this scanner's parser capabilities.",
                    }
                )
    return findings, checks


def scan_source(path, source, budget, findings, checks, files):
    from score_architecture import observations

    budget.check()
    text = textwrap.dedent(source["text"]) if source.get("fragment") else source["text"]
    tree, parse_error = None, False
    parse_reason = "Source syntax or lexical context could not be read reliably."
    if Path(path).suffix.lower() == ".py":
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError, RecursionError):
            parse_error = True
            parse_reason = "Python syntax is unsupported or invalid for this scanner."
    try:
        code = (
            javascript_code(text)
            if Path(path).suffix.lower() in JS_EXTENSIONS
            else text
        )
    except SyntaxError as error:
        code, parse_error = "", True
        parse_reason = f"JavaScript lexer limitation: {error.msg}"
    code_lines = code.splitlines()
    signatures = {}
    signatures_ready = False
    if tree is not None:

        class Signatures(ast.NodeVisitor):
            def __init__(self):
                self.context = []

            def visit_FunctionDef(self, node):
                self.context.append(node.name)
                self.generic_visit(node)
                self.context.pop()

            visit_AsyncFunctionDef = visit_FunctionDef
            visit_ClassDef = visit_FunctionDef

            def visit_Call(self, node):
                signatures.setdefault(node.lineno, []).append(
                    (tuple(self.context), ast.dump(node, include_attributes=False))
                )
                self.generic_visit(node)

    for rule in RULES:
        if not applies(rule, path):
            continue
        budget.check()
        # Secret formats are read from raw text and need no parsed source.
        unreadable = parse_error and rule["kind"] != "secret-token"
        if unreadable:
            observed = []
        elif rule["kind"].startswith("py-"):
            observed = python_observations(rule, text, tree)[0]
        elif rule["kind"] in {
            "js-sql",
            "frontend",
            "csp",
            "headers",
            "npm-sources",
            "npm-lock",
            "npm-install",
            "requirements",
            "workflow-permissions",
            "workflow-injection",
            "workflow-checkout",
            "container-privileges",
            "container-hardening",
            "image-script",
            "image-add",
            "js-jwt",
            "user",
            "secret-token",
            "ci-script",
            "install-command",
            "gitlab-image",
            "gitlab-include",
            "gitlab-injection",
            "lockfile",
            "manifest-sources",
            "release-integrity",
            "cloud-oidc",
            "password-hash",
            "js-cookie",
            "js-cors",
            "web-settings",
            "tf-ingress",
            "tf-public",
            "tf-iam",
            "tf-module",
        }:
            observed = observations(rule, path, text, code, files)
        else:
            observed = other_observations(rule, text, code)[0]
        states = Counter(row[1] for row in observed)
        status = (
            "violated"
            if states["violated"]
            else "unclear"
            if states["unclear"] or unreadable
            else "satisfied"
            if states["satisfied"]
            else "not_applicable"
        )
        checks.append(
            {
                "rule": rule["id"],
                "area": rule["area"],
                "file": path,
                "status": status,
                "locations": [
                    {
                        "line": source.get("lines", {}).get(row[0], row[0]),
                        "status": row[1],
                        # Some observations name what they recognized, such as a header.
                        **({"detail": row[2]} if len(row) > 2 else {}),
                    }
                    for row in observed
                ],
            }
        )
        if unreadable:
            checks[-1]["error"] = parse_reason
        for line, outcome, *_ in observed:
            if outcome != "violated":
                continue
            if len(findings) >= 5000:
                raise ScanLimit("Finding limit reached; the result is incomplete.")
            actual_line = source.get("lines", {}).get(line, line)
            if tree is not None and not signatures_ready:
                Signatures().visit(tree)
                signatures_ready = True
            observation = signatures.get(line) or re.sub(
                r"\s+", "", code_lines[line - 1]
            )
            identity = hashlib.sha256(repr(observation).encode()).hexdigest()
            # Raw source and literal values never enter the result.
            findings.append(
                {
                    "rule": rule["id"],
                    "area": rule["area"],
                    "severity": rule["severity"],
                    "title": rule["title"],
                    "file": path,
                    "line": actual_line,
                    "evidence": "Static pattern at the referenced location; exploitability unverified.",
                    "next_action": rule["next_action"],
                    "_identity": identity,
                }
            )


def compare(before, after):
    """Compare instances by rule and file, not unstable source line numbers.

    More occurrences of an existing check are 'worsened'; fewer are 'resolved'.
    Equal counts cannot establish that an individual flow stayed unchanged.
    """
    groups = defaultdict(lambda: [[], []])
    for side, findings in enumerate((before, after)):
        for finding in findings:
            groups[(finding["file"], finding["rule"])][side].append(finding)
    output = []
    for key in sorted(groups):
        old, new = groups[key]
        remaining = Counter(finding.get("_identity") for finding in old)
        for finding in new:
            identity = finding.get("_identity")
            if remaining[identity]:
                remaining[identity] -= 1
                status = "pre_existing"
            else:
                status = "worsened" if old and len(new) > len(old) else "introduced"
            output.append({**finding, "change": status, "side": "proposed"})
        for finding in old:
            identity = finding.get("_identity")
            if remaining[identity]:
                remaining[identity] -= 1
                output.append({**finding, "change": "resolved", "side": "baseline"})
    return output
