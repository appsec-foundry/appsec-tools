"""Readable detectors for architecture and dependency declarations.

Each detector kind is linked from rules.json and returns located observations.
Presence of a framework, ORM, or lockfile never establishes application safety.
"""

from __future__ import annotations

import ast
from bisect import bisect_right
from collections import Counter
from pathlib import Path, PurePosixPath
import re

from score_core import JS_EXTENSIONS, javascript_code, qualified
from score_infrastructure import (
    PIPE_TO_SHELL,
    ci_file,
    ci_script_observations,
    cloud_login_rows,
    cloud_oidc_observations,
    container_hardening_observations,
    container_user_observations,
    deployment_rows,
    document,
    gitlab_image_observations,
    gitlab_include_observations,
    gitlab_injection_observations,
    install_observations,
    line_of,
    lockfile_observations,
    lockfiles,
    logical_lines,
    manifest_source_observations,
    OWN_CODE,
    release_observations,
    script_lines,
    terraform_iam_observations,
    terraform_ingress_observations,
    terraform_module_observations,
    terraform_public_observations,
)
from score_reporting import origin, source_priority


UNTRUSTED_CONTEXT = re.compile(
    r"\bgithub\s*\.\s*(?:head_ref\b|event\s*\.\s*(?:"
    r"(?:issue|pull_request|discussion)\s*\.\s*(?:title|body)\b"
    r"|pull_request\s*\.\s*head\s*\.\s*(?:ref|label)\b"
    r"|(?:comment|review|review_comment|discussion_comment)\s*\.\s*body\b"
    r"|(?:workflow_run\s*\.\s*)?head_commit\s*\.\s*(?:message|author\s*\.\s*(?:name|email))\b"
    r"|workflow_run\s*\.\s*head_branch\b"
    r"|commits\s*(?:\[[^\]]{0,20}\]|\.\s*\*)\s*\.\s*(?:message|author\s*\.\s*(?:name|email))\b"
    r"|pages\s*(?:\[[^\]]{0,20}\]|\.\s*\*)\s*\.\s*page_name\b"
    r"))",
    re.I,
)
PROPOSED_REVISION = re.compile(
    r"\bgithub\s*\.\s*(?:head_ref\b|event\s*\.\s*(?:pull_request\s*\.\s*head\s*\.\s*(?:sha|ref)"
    r"|workflow_run\s*\.\s*head_(?:sha|branch)|(?:number|pull_request\s*\.\s*number)\b))",
    re.I,
)


def csp_status(policy):
    directives = {}
    for part in policy.split(";"):
        tokens = part.lower().split()
        if tokens:
            directives.setdefault(tokens[0], tokens[1:])
    scripts = directives.get("script-src", directives.get("default-src"))
    if scripts is None:
        return "unclear"
    # CSP Level 2 ignores 'unsafe-inline' next to a nonce or hash; with
    # 'strict-dynamic', Level 3 also ignores it and 'self', host and scheme sources.
    nonce = any(
        token.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-"))
        for token in scripts
    )
    dynamic = "'strict-dynamic'" in scripts
    effective = [
        token
        for token in scripts
        if not ((nonce or dynamic) and token == "'unsafe-inline'")
        and not (dynamic and (not token.startswith("'") or token == "'self'"))
    ]
    if any(
        token in {"*", "'unsafe-inline'", "'unsafe-eval'", "http:", "https:", "data:"}
        for token in effective
    ):
        return "violated"
    if (
        not scripts
        or directives.get("object-src") != ["'none'"]
        or directives.get("base-uri") != ["'none'"]
        or not directives.get("frame-ancestors")
    ):
        return "unclear"
    return "satisfied"


def literal_declarations(names, text, code, flags=0):
    """(line, name, value) for literal header declarations outside Python.

    Object literals, subscript assignments, setter calls and [name, value] pairs
    count; reading a header, as in a test assertion, does not. The separator must
    be outside a JS string/comment, so quoted documentation is no declaration.
    """
    value = r"""\s*(?P<quote>["'])(?P<value>[^\n]*?)(?P=quote)"""
    rows = []
    for pattern in (
        rf"""["'](?P<name>{names})["']\s*(?P<separator>:|\]\s*=(?!=))""",
        rf"""\b(?:set|setHeader|header|append)\s*\(\s*["'](?P<name>{names})["']\s*(?P<separator>,)""",
        rf"""\[\s*["'](?P<name>{names})["']\s*(?P<separator>,)""",
    ):
        for match in re.finditer(pattern + value, text, flags):
            if not code[match.start("separator")].isspace():
                line = text.count("\n", 0, match.start()) + 1
                rows.append((line, match["name"], match["value"]))
    return sorted(rows)


def csp_observations(path, text, code):
    observations = []
    if Path(path).suffix == ".py":
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError, RecursionError):
            return []
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Assign)
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)
            ):
                for target in node.targets:
                    if (
                        isinstance(target, ast.Subscript)
                        and isinstance(target.slice, ast.Constant)
                        and target.slice.value == "Content-Security-Policy"
                    ):
                        observations.append((node.lineno, csp_status(node.value.value)))
            elif (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr
                in {"set_header", "setHeader", "header", "setdefault"}
                and len(node.args) >= 2
                and isinstance(node.args[0], ast.Constant)
                and node.args[0].value == "Content-Security-Policy"
            ):
                policy = node.args[1]
                observations.append(
                    (
                        node.lineno,
                        csp_status(policy.value)
                        if isinstance(policy, ast.Constant)
                        and isinstance(policy.value, str)
                        else "unclear",
                    )
                )
        return observations
    for line, _, policy in literal_declarations("Content-Security-Policy", text, code):
        observations.append((line, csp_status(policy)))
    for match in re.finditer(
        r"""(?im)^\s*add_header\s+Content-Security-Policy\s+(["'])(.*?)\1""", text
    ):
        observations.append(
            (text.count("\n", 0, match.start()) + 1, csp_status(match[2]))
        )
    # A report-only policy is deliberately not recognized as enforcement.
    return observations


# Browser security headers other than CSP. They are positive evidence only: a
# proxy or platform outside the repository may set them, so a missing, weak or
# dynamic value is neither a finding nor an unclear check.
SECURITY_HEADERS = {
    name.lower(): name
    for name in (
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Strict-Transport-Security",
        "Referrer-Policy",
    )
}
# helmet() sends all four by default. An option naming a header is not evaluated.
HELMET_OPTIONS = {
    "noSniff": "X-Content-Type-Options",
    "xContentTypeOptions": "X-Content-Type-Options",
    "frameguard": "X-Frame-Options",
    "xFrameOptions": "X-Frame-Options",
    "hsts": "Strict-Transport-Security",
    "strictTransportSecurity": "Strict-Transport-Security",
    "referrerPolicy": "Referrer-Policy",
}


def header_accepted(name, value):
    value = value.strip().lower()
    if name == "X-Content-Type-Options":
        return value == "nosniff"
    if name == "X-Frame-Options":
        return value in {"deny", "sameorigin"}
    if name == "Strict-Transport-Security":
        match = re.search(r"(?:^|;)\s*max-age\s*=\s*\"?(\d+)", value)
        return bool(match) and int(match[1]) > 0
    # Browsers apply the last listed value they support; only the last is read.
    return value.split(",")[-1].strip() in {
        "no-referrer",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
    }


HELMET_OPTION = re.compile(r"(?<![\w$])(?:" + "|".join(HELMET_OPTIONS) + r")(?![\w$])")


def bracket_pairs(code):
    """Opening bracket offset -> closing offset, in one linear pass."""
    pairs, stack = {}, []
    for index, char in enumerate(code):
        if char in "([{":
            stack.append(index)
        elif char in ")]}" and stack:
            pairs[stack.pop()] = index
    return pairs


def helmet_headers(text, code):
    """Headers from helmet() and its middlewares, for a recognized helmet import."""
    names = set()
    for match in re.finditer(
        r"\bimport\s+(?:\*\s+as\s+)?([A-Za-z_$][\w$]*)\s*(?:,\s*\{[^{}\n]*\}\s*)?from\s+['\"]helmet['\"]"
        r"|\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*['\"]helmet['\"]\s*\)",
        text,
    ):
        if not code[match.start()].isspace():
            names.add(match[1] or match[2])
    if not names:
        return []
    breaks = [match.start() for match in re.finditer("\n", code)]
    pairs = bracket_pairs(code)
    rows = []
    for name in sorted(names):
        for match in re.finditer(
            rf"(?<![\w$.]){re.escape(name)}\s*(?:\.\s*([A-Za-z_$][\w$]*)\s*)?\(", code
        ):
            end = pairs.get(match.end() - 1)
            # Unclosed or long argument lists are not evaluated, which bounds the work.
            if end is None or code[end] != ")" or end - match.end() > 4000:
                continue
            arguments = code[match.end() : end].strip()
            if match[1]:
                headers = (
                    [HELMET_OPTIONS[match[1]]] if match[1] in HELMET_OPTIONS else []
                )
                if arguments:
                    continue  # Middleware options are not evaluated.
            elif not arguments:
                headers = SECURITY_HEADERS.values()
            elif (
                arguments.startswith("{")
                and arguments.endswith("}")
                and "..." not in arguments
            ):
                named = {
                    HELMET_OPTIONS[option]
                    for option in HELMET_OPTION.findall(text, match.end(), end)
                }
                headers = [h for h in SECURITY_HEADERS.values() if h not in named]
            else:
                continue
            line = bisect_right(breaks, match.start()) + 1
            rows += [(line, "satisfied", header) for header in headers]
    return rows


def header_observations(path, text, code):
    """(line, 'satisfied', header) for literal declarations with an accepted value."""
    rows = []
    if Path(path).suffix == ".py":
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError, RecursionError):
            return []
        for node in ast.walk(tree):
            pairs = []
            if isinstance(node, ast.Assign):
                pairs = [
                    (target.slice, node.value)
                    for target in node.targets
                    if isinstance(target, ast.Subscript)
                ]
            elif (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr
                in {"set_header", "setHeader", "header", "setdefault"}
                and len(node.args) >= 2
            ):
                pairs = [(node.args[0], node.args[1])]
            for key, value in pairs:
                if (
                    isinstance(key, ast.Constant)
                    and isinstance(key.value, str)
                    and key.value.lower() in SECURITY_HEADERS
                    and isinstance(value, ast.Constant)
                    and isinstance(value.value, str)
                ):
                    name = SECURITY_HEADERS[key.value.lower()]
                    if header_accepted(name, value.value):
                        rows.append((node.lineno, "satisfied", name))
        return sorted(rows)
    names = "|".join(re.escape(name) for name in SECURITY_HEADERS.values())
    for line, name, value in literal_declarations(names, text, code, re.I):
        name = SECURITY_HEADERS[name.lower()]
        if header_accepted(name, value):
            rows.append((line, "satisfied", name))
    for match in re.finditer(
        rf"""(?im)^\s*add_header\s+({names})\s+(?:(["'])(.*?)\2|([^\s;"']+))""", text
    ):
        name = SECURITY_HEADERS[match[1].lower()]
        if header_accepted(name, match[3] if match[2] else match[4]):
            rows.append((text.count("\n", 0, match.start()) + 1, "satisfied", name))
    if Path(path).suffix.lower() in JS_EXTENSIONS:
        rows += helmet_headers(text, code)
    return sorted(rows)


def npm_observations(kind, path, text, files):
    manifest = document(text)
    if manifest is None:
        return [(1, "unclear")]
    dependencies = {}
    for field in ("dependencies", "devDependencies", "optionalDependencies"):
        values = manifest.get(field, {})
        if not isinstance(values, dict):
            return [(1, "unclear")]
        dependencies.update(values)
    if kind == "npm-sources":
        rows = []
        for name, value in sorted(dependencies.items()):
            if not isinstance(value, str):
                status = "unclear"
            elif value.startswith(("http://", "git+http://")):
                status = "violated"
            elif value.startswith(("git+", "github:", "gitlab:")):
                status = (
                    "satisfied"
                    if re.search(r"#[0-9a-fA-F]{40}$", value)
                    else "violated"
                )
            elif value.startswith(("file:", "link:", "workspace:")):
                status = "unclear"
            else:
                status = "unclear"  # Registry ranges need resolution/lock evidence.
            rows.append((line_of(text, '"' + name + '"'), status))
        return rows
    if kind == "npm-lock":
        if not dependencies:
            return []
        parent = str(Path(path).parent)
        prefix = "" if parent == "." else parent + "/"
        for name in ("npm-shrinkwrap.json", "package-lock.json"):
            source = files.get(prefix + name)
            if not source:
                continue
            lock = document(source["text"])
            if (
                lock
                and type(lock.get("lockfileVersion")) is int
                and lock["lockfileVersion"] in {2, 3}
                and isinstance(lock.get("packages"), dict)
            ):
                root = lock["packages"].get("")
                if isinstance(root, dict) and all(
                    manifest.get(field, {}) == root.get(field, {})
                    for field in (
                        "dependencies",
                        "devDependencies",
                        "optionalDependencies",
                    )
                ):
                    return [(1, "satisfied")]
            return [(1, "unclear")]
        # External or other-manager locks may exist outside this selected scope.
        return [(1, "unclear")]
    scripts = manifest.get("scripts", {})
    if not isinstance(scripts, dict):
        return [(1, "unclear")]
    rows = []
    for name in ("preinstall", "install", "postinstall", "prepare"):
        value = scripts.get(name)
        if isinstance(value, str):
            unsafe = PIPE_TO_SHELL.search(value)
            rows.append(
                (line_of(text, '"' + name + '"'), "violated" if unsafe else "unclear")
            )
    return rows


EXACT_REQUIREMENT = re.compile(r"[\w.-]+(?:\[[\w,.-]+\])?==[^\s*]+")
EXACT_NPM_VERSION = re.compile(r"=?v?\d+\.\d+\.\d+(?:[-+][\w.+-]+)?")


def requirement_observations(text):
    """Options are unclear unless they add a plaintext, untrusted or mutable source."""
    rows = []
    for number, value in logical_lines(text):
        value = re.sub(r"(?:^|\s)#.*", "", value).strip()
        if not value:
            continue
        if "http://" in value or re.match(
            r"--(?:extra-index-url|trusted-host)\b", value
        ):
            status = "violated"
        elif value.startswith("-"):
            vcs = re.match(r"(?:-e|--editable)[\s=]+(?:git|hg|svn|bzr)\+", value)
            status = (
                "violated"
                if vcs and not re.search(r"@[0-9a-fA-F]{40}(?:[#&\s]|$)", value)
                else "unclear"
            )
        elif not EXACT_REQUIREMENT.match(value):
            status = "violated"
        else:
            hashed = re.search(r"--hash=sha256:[0-9a-fA-F]{64}", value)
            rows.append(
                (number, "satisfied", "sha256 hash" if hashed else "exact version")
            )
            continue
        rows.append((number, status))
    return rows


def expression_matches(segment, pattern):
    """Search only inside `${{ ... }}`; plain script text is not expanded."""
    start = segment.find("${{")
    while start >= 0:
        end = segment.find("}}", start + 3)
        if end < 0:
            return False
        if pattern.search(segment, start + 3, end):
            return True
        start = segment.find("${{", end + 2)
    return False


def workflow_injection_observations(text):
    """Untrusted event text expanded into run scripts or github-script code."""
    return [
        (number, "violated")
        for number, segment in script_lines(text, "run|script")
        if expression_matches(segment, UNTRUSTED_CONTEXT)
    ]


def workflow_checkout_observations(text):
    """A privileged pull request trigger combined with a checkout of proposed code."""
    lines = text.splitlines()
    trigger = re.compile(
        r"\s*(?:[\"']?on[\"']?\s*:[^#\n]*\b(?:pull_request_target|workflow_run)\b"
        r"|(?:-\s*)?(?:pull_request_target|workflow_run)\s*(?::|$))"
    )
    if not any(trigger.match(line) for line in lines):
        return []
    rows = []
    for number, line in enumerate(lines, 1):
        stripped = line.strip()
        if re.match(r"(?:-\s+)?ref\s*:", stripped) and expression_matches(
            stripped, PROPOSED_REVISION
        ):
            rows.append((number, "violated"))
        elif not stripped.startswith("#") and re.search(
            r"\bgh\s+pr\s+checkout\b", stripped
        ):
            rows.append((number, "violated"))
    return rows


def container_privilege_observations(text):
    """Explicit privileged, host-namespace and Docker socket settings in YAML."""
    rows = []
    for number, line in enumerate(text.splitlines(), 1):
        status = None
        flag = re.match(
            r"\s*(?:-\s+)?[\"']?(privileged|allowPrivilegeEscalation|hostNetwork|hostPID|hostIPC)[\"']?\s*:(.*)",
            line,
        )
        if flag:
            value = re.split(r"\s#", flag[2], maxsplit=1)[0].strip().strip("\"'")
            if value.lower() in {"true", "yes", "on"}:
                status = "violated"
            elif value.lower() in {"false", "no", "off"}:
                status = "satisfied"
            elif value:
                status = "unclear"  # Templated or substituted values are unresolved.
        elif re.match(
            r"\s*(?:-\s+)?(?:network_mode|pid|ipc)\s*:\s*[\"']?host[\"']?\s*(?:#|$)",
            line,
        ) or re.match(
            r"\s*(?:-\s+)?(?:(?:source|path)\s*:\s*)?[\"']?(?:/var)?/run/docker\.sock(?:[\"':\s]|$)",
            line,
        ):
            status = "violated"
        if status:
            rows.append((number, status))
    return rows


def dockerfile_observations(kind, text):
    """RUN downloads piped to a shell; remote ADD sources without a pin."""
    rows = []
    for number, instruction in logical_lines(text, comment=r"\s*#"):
        if kind == "image-script":
            if re.match(r"(?i)\s*RUN\b", instruction) and PIPE_TO_SHELL.search(
                instruction
            ):
                rows.append((number, "violated"))
            continue
        match = re.match(r"(?i)\s*ADD\s+((?:--\S+\s+)*)(\S+)", instruction)
        if match and re.match(r"(?i)https?://", match[2]):
            pinned = re.search(
                r"--checksum=sha256:[0-9a-fA-F]{64}(?:\s|$)", match[1]
            ) or re.search(r"\.git#[0-9a-fA-F]{40}(?::|$)", match[2])
            rows.append((number, "satisfied" if pinned else "violated"))
    return rows


JS_NAME = r"[A-Za-z_$][\w$]*"
JS_CALL = re.compile(rf"(?<![\w$.])({JS_NAME}(?:\s*\.\s*{JS_NAME})?)\s*\(")


def js_imports(text, code):
    """Active ESM and require bindings, without importing the target project."""
    patterns = (
        (
            rf"\bimport\s+(\*\s+as\s+{JS_NAME}|{JS_NAME}|\{{[^{{}}]{{1,1000}}\}})\s+from\s+['\"]([^'\"\n]+)['\"]",
            "as",
        ),
        (
            rf"\b(?:const|let|var)\s+({JS_NAME}|\{{[^{{}}]{{1,1000}}\}})\s*=\s*require\s*\(\s*['\"]([^'\"\n]+)['\"]\s*\)",
            ":",
        ),
    )
    for pattern, separator in patterns:
        for match in re.finditer(pattern, text):
            if code[match.start()].isspace():
                continue
            binding, module = match[1].strip(), match[2]
            if binding.startswith("{"):
                for item in binding[1:-1].split(","):
                    names = re.split(
                        r"\s+as\s+" if separator == "as" else r"\s*:\s*", item.strip()
                    )
                    if all(re.fullmatch(JS_NAME, name) for name in names):
                        yield names[-1], module, names[0]
            else:
                member = (
                    "*"
                    if binding.startswith("*")
                    else "="
                    if separator == ":"
                    else None
                )
                yield binding.split()[-1], module, member


def js_arguments(code, opening, pairs):
    """Top-level argument spans; cap each inspected expression at 4 KiB."""
    end = pairs.get(opening)
    if (
        end is None
        or code[end] != {"(": ")", "{": "}", "[": "]"}.get(code[opening])
        or end - opening > 4000
    ):
        return None
    spans, start, index = [], opening + 1, opening + 1
    while index < end:
        if code[index] in "([{":
            closing = pairs.get(index)
            if closing is None or closing >= end:
                return None
            index = closing
        elif code[index] == ",":
            spans.append((start, index))
            start = index + 1
        index += 1
    if start < end or start != opening + 1:
        spans.append((start, end))
    return spans


def js_jwt_observations(text, code):
    """Assess options on verification calls, never unrelated algorithms fields."""
    names = {
        "jwt.verify": 2,
        "jsonwebtoken.verify": 2,
        "expressJwt": 0,
        "expressjwt": 0,
    }
    for local, module, member in js_imports(text, code):
        if module == "jsonwebtoken" and member in {None, "*", "=", "verify"}:
            names[local + ".verify" if member in {None, "*", "="} else local] = 2
        elif module == "express-jwt" and member in {None, "expressjwt"}:
            names[local] = 0
        elif module == "express-jwt" and member in {"*", "="}:
            names[local + ".expressjwt"] = 0
            if member == "=":
                names[local] = 0
    rows = []
    breaks = [match.start() for match in re.finditer("\n", code)]
    pairs = bracket_pairs(code)
    for call in JS_CALL.finditer(code):
        name = re.sub(r"\s", "", call[1])
        if name not in names:
            continue
        number = bisect_right(breaks, call.start()) + 1
        arguments = js_arguments(code, call.end() - 1, pairs)
        option_index = names[name]
        if arguments is None or len(arguments) <= option_index:
            rows.append((number, "unclear"))
            continue
        start, stop = arguments[option_index]
        option_code = code[start:stop]
        opening = start + len(option_code) - len(option_code.lstrip())
        if (
            not option_code.strip().startswith("{")
            or pairs.get(opening) != start + len(option_code.rstrip()) - 1
        ):
            rows.append((number, "unclear"))
            continue
        properties = js_arguments(code, opening, pairs)
        if properties is None or any("..." in code[a:b] for a, b in properties):
            rows.append((number, "unclear"))
            continue
        algorithms, expiries = [], []
        for a, b in properties:
            if re.match(r"\s*algorithms\s*:", code[a:b]):
                algorithms.append((a, b))
            if re.match(r"\s*ignoreExpiration\s*:", code[a:b]):
                expiries.append((a, b))
        expiry = (
            re.fullmatch(
                r"\s*ignoreExpiration\s*:\s*(true|false)\s*", code[slice(*expiries[0])]
            )
            if len(expiries) == 1
            else None
        )
        if expiry and expiry[1] == "true":
            rows.append((number, "violated"))
            continue
        if len(algorithms) != 1:
            rows.append((number, "unclear"))
            continue
        a, b = algorithms[0]
        match = re.match(r"\s*algorithms\s*:\s*\[", code[a:b])
        if not match:
            rows.append((number, "unclear"))
            continue
        offset = a + match.end()
        end = pairs.get(offset - 1, -1)
        items = (
            [item.strip() for item in text[offset:end].split(",")] if end >= 0 else []
        )
        values = [re.fullmatch(r"(['\"`])([\w.-]+)\1", item) for item in items if item]
        status = (
            "unclear"
            if end < 0
            else "violated"
            if any(value and value[2].lower() == "none" for value in values)
            else "unclear"
            if expiries and expiry is None or code[end + 1 : b].strip()
            else "satisfied"
            if values and all(values)
            else "unclear"
        )
        rows.append((number, status))
    return rows


def js_cookie_observations(code):
    """Literal httpOnly and secure flags in recognized cookie options."""
    rows = []
    breaks = [match.start() for match in re.finditer("\n", code)]
    for match in re.finditer(
        r"\bcookie\s*:\s*\{|\.cookie\s*\(|\bcookies\s*\.\s*set\s*\(", code
    ):
        closing = "}" if match[0].endswith("{") else ")"
        end = code.find(closing, match.end(), match.end() + 400)
        window = code[match.end() : end if end >= 0 else match.end() + 400]
        for flag in re.finditer(r"\b(?:httpOnly|secure)\s*:\s*(true|false)\b", window):
            rows.append(
                (
                    bisect_right(breaks, match.end() + flag.start()) + 1,
                    "violated" if flag[1] == "false" else "satisfied",
                )
            )
    return rows


def js_cors_observations(text, code):
    """Credentialed CORS: a wildcard or reflected origin versus literal HTTPS origins."""
    rows = []
    breaks = [match.start() for match in re.finditer("\n", code)]
    for match in re.finditer(r"\bcors\s*\(\s*\{", code):
        end = code.find("}", match.end(), match.end() + 400)
        if end < 0 or not re.search(
            r"\bcredentials\s*:\s*true\b", code[match.end() : end]
        ):
            continue
        origin = re.search(r"\borigin\s*:", code[match.end() : end])
        if not origin:
            continue
        value = text[match.end() + origin.end() : end].lstrip()
        status = (
            "violated"
            if re.match(r"true\b|['\"`]\*['\"`]", value)
            else "satisfied"
            if re.match(r"\[?\s*['\"`]https://", value)
            else None
        )
        if status:
            rows.append((bisect_right(breaks, match.start()) + 1, status))
    return rows


WEB_SETTINGS = re.compile(
    r"\s*(?:\w+\.config\[['\"])?"
    r"(?:SESSION_COOKIE_SECURE|SESSION_COOKIE_HTTPONLY|CSRF_COOKIE_SECURE|REMEMBER_COOKIE_SECURE)"
    r"(?:['\"]\])?\s*=\s*(True|False)\b"
)


def web_settings_observations(text):
    """Django and Flask session settings; computed values stay unassessed."""
    rows = []
    credentials = re.search(r"(?m)^CORS_ALLOW_CREDENTIALS\s*=\s*True\b", text)
    for number, line in enumerate(text.splitlines(), 1):
        flag = WEB_SETTINGS.match(line)
        hosts = re.match(r"\s*ALLOWED_HOSTS\s*=\s*\[([^\]]+)\]", line)
        if flag:
            rows.append((number, "satisfied" if flag[1] == "True" else "violated"))
        elif hosts:
            literal = re.fullmatch(
                r"\s*(['\"])[^'\"]+\1\s*(?:,\s*(['\"])[^'\"]+\2\s*)*,?\s*", hosts[1]
            )
            if re.search(r"['\"]\*['\"]", hosts[1]):
                rows.append((number, "violated"))
            elif literal:
                rows.append((number, "satisfied"))
        elif credentials and re.match(
            r"\s*(?:CORS_ALLOW_ALL_ORIGINS|CORS_ORIGIN_ALLOW_ALL)\s*=\s*True\b", line
        ):
            rows.append((number, "violated"))
    return rows


# Formats with a fixed prefix; generic high-entropy strings are not assessed.
SECRET_FORMATS = re.compile(
    r"\bAKIA[0-9A-Z]{16}\b"
    r"|\bgh[pousr]_[A-Za-z0-9]{36,}\b"
    r"|\bgithub_pat_[A-Za-z0-9_]{22,}\b"
    r"|\bglpat-[A-Za-z0-9_-]{20,}"
    r"|\bxox[abprs]-[A-Za-z0-9-]{10,}"
    r"|\bnpm_[A-Za-z0-9]{36}\b"
    r"|\bsk_live_[0-9a-zA-Z]{24,}\b"
    r"|\bsk-ant-[A-Za-z0-9_-]{32,}"
)
PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----(?:\\r|\\n|\s)+[A-Za-z0-9+/]{40,}"
)


def secret_token_observations(text):
    """Lines only: a matched value never leaves this function."""
    breaks = [match.start() for match in re.finditer("\n", text)]
    rows = {
        bisect_right(breaks, match.start()) + 1
        for match in SECRET_FORMATS.finditer(text)
        # Documentation samples and repeated placeholder characters.
        if "EXAMPLE" not in match[0].upper() and len(set(match[0])) >= 12
    } | {
        bisect_right(breaks, match.start()) + 1 for match in PRIVATE_KEY.finditer(text)
    }
    return [(number, "violated") for number in sorted(rows)]


PASSWORD_NAME = re.compile(r"(?i)pass(?:word|wd)")
LOCAL_FUNCTION = re.compile(
    r"\s*(?:export\s+)?(?:async\s+)?(?:def\s+(\w+)\s*\(|function\s+(\w+)\s*\("
    r"|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:function\b|\([^()\n]*\)\s*=>|\w+\s*=>))"
)
WEAK_HASH = re.compile(
    r"\bcreateHash\s*\(\s*['\"`](md5|sha1|sha224|sha256|sha384|sha512|sha3-\d+)['\"`]"
    r"|\bhashlib\s*\.\s*(md5|sha1|sha224|sha256|sha384|sha512|sha3_\d+)\s*\(",
    re.I,
)
PASSWORD_HASHES = (
    (
        "bcrypt",
        re.compile(
            r"\bbcrypt(?:js)?\s*\.\s*(?:hash|hashSync|hashpw|compare|compareSync|checkpw)\s*\("
        ),
    ),
    ("Argon2", re.compile(r"\bargon2\s*\.\s*(?:hash|verify)\s*\(")),
    (
        "scrypt",
        re.compile(r"\b(?:crypto\s*\.\s*scrypt(?:Sync)?|hashlib\s*\.\s*scrypt)\s*\("),
    ),
    (
        "PBKDF2",
        re.compile(
            r"\b(?:crypto\s*\.\s*pbkdf2(?:Sync)?|hashlib\s*\.\s*pbkdf2_hmac)\s*\("
        ),
    ),
    (
        "framework hasher",
        re.compile(
            r"\b(?:generate_password_hash|check_password_hash|make_password|check_password)\s*\("
        ),
    ),
)


def hash_call(text):
    """(status, label) of the first recognized password or weak hash call."""
    weak = WEAK_HASH.search(text)
    if weak:
        algorithm = (weak[1] or weak[2]).lower().replace("_", "-")
        label = (
            "MD5"
            if algorithm == "md5"
            else "SHA-" + algorithm[3:]
            if not algorithm.startswith("sha3")
            else algorithm.upper()
        )
        return "violated", label
    for label, pattern in PASSWORD_HASHES:
        if pattern.search(text):
            return "satisfied", label
    return None


def hash_helpers(lines):
    """Functions of this file by name, with the hash call in their body."""
    helpers = {}
    for index, line in enumerate(lines):
        match = LOCAL_FUNCTION.match(line)
        if not match:
            continue
        indent = len(line) - len(line.lstrip())
        end = index + 1
        while (
            end < len(lines)
            and end - index <= 40
            and (
                not lines[end].strip()
                or len(lines[end]) - len(lines[end].lstrip()) > indent
            )
        ):
            end += 1
        found = hash_call("\n".join(lines[index:end]))
        if found:
            helpers[match[1] or match[2] or match[3]] = found
    return helpers


def js_hash_uses(text, code):
    """Located hash operations and the value actually passed as password input."""
    pairs = bracket_pairs(code)
    for call in JS_CALL.finditer(code):
        args = js_arguments(code, call.end() - 1, pairs)
        if not args:
            continue
        end = pairs[call.end() - 1] + 1
        expression = text[call.start() : end]
        weak = WEAK_HASH.search(expression)
        found = (
            hash_call(expression)
            if weak and weak.start() < call.end() - call.start()
            else next(
                (
                    ("satisfied", label)
                    for label, pattern in PASSWORD_HASHES
                    if pattern.match(expression)
                ),
                None,
            )
        )
        if not found:
            continue
        name = re.sub(r"\s", "", call[1])
        if name.endswith("createHash"):
            update = re.match(r"\s*\.\s*update\s*\(", code[end : end + 100])
            if not update:
                continue
            args = js_arguments(code, end + update.end() - 1, pairs)
            if not args:
                continue
        input_index = 1 if name in {"argon2.verify", "check_password_hash"} else 0
        if len(args) > input_index:
            start, stop = args[input_index]
            yield call.start(), code[start:stop], found


JS_HASH_HELPER = re.compile(
    rf"(?m)^[ \t]*(?P<export>export\s+)?(?:async\s+)?(?:"
    rf"function\s+(?P<function>{JS_NAME})\s*\(\s*(?P<param>{JS_NAME})(?:\s*:\s*\w+)?\s*\)\s*\{{\s*return\s+"
    rf"|(?:const|let|var)\s+(?P<arrow>{JS_NAME})\s*=\s*(?:async\s+)?\(\s*(?P<arg>{JS_NAME})(?:\s*:\s*\w+)?\s*\)\s*=>\s*(?:\{{\s*return\s+)?)"
)


def js_hash_helpers(text, code, exported=False):
    """Single-expression helpers whose parameter reaches a recognized hash."""
    helpers = {}
    for match in JS_HASH_HELPER.finditer(code):
        if exported and not match["export"]:
            continue
        # Only a simple return expression on one line is summarized.
        end = code.find("\n", match.end())
        end = min(len(code) if end < 0 else end, match.end() + 4000)
        body = code[match.end() : end]
        raw = text[match.end() : end]
        parameter = match["param"] or match["arg"]
        for position, argument, found in js_hash_uses(raw, body):
            # The expression must start with the hashing operation, not a separate call.
            if (
                body[:position].strip() in {"", "await"}
                and argument.strip() == parameter
            ):
                helpers[match["function"] or match["arrow"]] = found
    return helpers


class PasswordHashResolver:
    """One import hop over already-selected sources; no filesystem or module execution."""

    def __init__(self, files, budget):
        self.files, self.budget, self.cache = files, budget, {}

    def exports(self, path, module):
        if (
            not (module.startswith(("./", "../")) or module in {".", ".."})
            or "\\" in module
        ):
            return {}
        parts = list(PurePosixPath(path).parent.parts)
        for part in module.split("/"):
            if part == "..":
                if not parts:
                    return {}
                parts.pop()
            elif part not in {"", "."}:
                parts.append(part)
        base = "/".join(parts)
        candidates = (
            [base]
            if Path(base).suffix in JS_EXTENSIONS
            else [base + ext for ext in sorted(JS_EXTENSIONS)]
            + [base + "/index" + ext for ext in sorted(JS_EXTENSIONS)]
        )
        selected = [candidate for candidate in candidates if candidate in self.files]
        if len(selected) != 1:
            return {}  # Ambiguous language/runtime resolution stays unassessed.
        target = selected[0]
        if target not in self.cache:
            self.budget.check()
            source = self.files[target]
            result = {}
            if not source.get("fragment") and not source.get("fragments"):
                try:
                    code = javascript_code(source["text"])
                    result = js_hash_helpers(source["text"], code, exported=True)
                except SyntaxError:
                    pass
            self.cache[target] = result
        return self.cache[target]

    def bindings(self, path, text, code):
        helpers = js_hash_helpers(text, code)
        for local, module, member in js_imports(text, code):
            exported = self.exports(path, module)
            if member in exported:
                helpers[local] = exported[member]
            elif member in {"*", "="}:
                helpers.update(
                    {local + "." + name: found for name, found in exported.items()}
                )
        return helpers


def password_hash_observations(text, code, path="", resolver=None):
    """Hash calls that receive a password, directly or through a helper in this file."""
    if Path(path).suffix.lower() in JS_EXTENSIONS:
        breaks = [match.start() for match in re.finditer("\n", code)]
        rows = [
            (bisect_right(breaks, position) + 1, *found)
            for position, argument, found in js_hash_uses(text, code)
            if PASSWORD_NAME.search(argument)
        ]
        helpers = (
            resolver.bindings(path, text, code)
            if resolver
            else js_hash_helpers(text, code)
        )
        pairs = bracket_pairs(code)
        for call in JS_CALL.finditer(code):
            name = re.sub(r"\s", "", call[1])
            if name not in helpers:
                continue
            args = js_arguments(code, call.end() - 1, pairs)
            if args and PASSWORD_NAME.search(code[args[0][0] : args[0][1]]):
                rows.append((bisect_right(breaks, call.start()) + 1, *helpers[name]))
        return sorted(set(rows))
    lines = [
        "" if not active.strip() or active.lstrip().startswith("#") else line
        for line, active in zip(text.splitlines(), code.splitlines())
    ]
    helpers = hash_helpers(lines)
    rows = []
    for number, line in enumerate(lines, 1):
        if not PASSWORD_NAME.search(line):
            continue
        found = hash_call(line)
        if not found and not LOCAL_FUNCTION.match(line):
            called = re.findall(r"(?<![\w.$])(\w+)\s*\(", line)
            found = next((helpers[name] for name in called if name in helpers), None)
        if found:
            rows.append((number, *found))
    return rows


TEXT_DETECTORS = {
    "container-hardening": container_hardening_observations,
    "gitlab-image": gitlab_image_observations,
    "gitlab-include": gitlab_include_observations,
    "lockfile": lockfile_observations,
    "release-integrity": release_observations,
    "secret-token": secret_token_observations,
    "tf-iam": terraform_iam_observations,
    "tf-ingress": terraform_ingress_observations,
    "tf-module": terraform_module_observations,
    "tf-public": terraform_public_observations,
    "user": container_user_observations,
    "web-settings": web_settings_observations,
}
PATH_DETECTORS = {
    "ci-script": ci_script_observations,
    "cloud-oidc": cloud_oidc_observations,
    "gitlab-injection": gitlab_injection_observations,
    "install-command": install_observations,
    "manifest-sources": manifest_source_observations,
}


def observations(rule, path, text, code, files, password_resolver=None):
    kind = rule["kind"]
    if kind in TEXT_DETECTORS:
        return TEXT_DETECTORS[kind](text)
    if kind in PATH_DETECTORS:
        return PATH_DETECTORS[kind](path, text)
    if kind == "password-hash":
        return password_hash_observations(text, code, path, password_resolver)
    if kind == "js-cookie":
        return js_cookie_observations(code)
    if kind == "js-cors":
        return js_cors_observations(text, code)
    if kind.startswith("npm-"):
        return npm_observations(kind, path, text, files)
    if kind == "csp":
        return csp_observations(path, text, code)
    if kind == "headers":
        return header_observations(path, text, code)
    if kind == "requirements":
        return requirement_observations(text)
    if kind == "workflow-injection":
        return workflow_injection_observations(text)
    if kind == "workflow-checkout":
        return workflow_checkout_observations(text)
    if kind == "container-privileges":
        return container_privilege_observations(text)
    if kind in {"image-script", "image-add"}:
        return dockerfile_observations(kind, text)
    if kind == "js-jwt":
        return js_jwt_observations(text, code)
    rows = []
    original_lines = text.splitlines()
    for number, line in enumerate(code.splitlines(), 1):
        status = None
        if kind == "js-sql":
            match = re.search(
                r"\.(?:query|execute|\$queryRawUnsafe|\$executeRawUnsafe)\s*\(", line
            )
            if match:
                original = original_lines[number - 1][match.end() :].strip()
                if re.match(
                    r"[`'\"]\s*(?:SELECT|INSERT|UPDATE|DELETE|WITH|CREATE)\b",
                    original,
                    re.I,
                ):
                    status = (
                        "violated"
                        if re.search(r"\$\{|['\"]\s*\+|\+\s*['\"]", original)
                        else "satisfied"
                    )
                else:
                    status = "unclear"
        elif kind == "frontend":
            if re.search(
                r"\bdangerouslySetInnerHTML\s*=|\bbypassSecurityTrust(?:Html|Script|Url|ResourceUrl)\s*\(",
                line,
            ):
                status = "violated"
            elif re.search(
                r"<(?:div|span|p|li|label|button)\b[^>]{0,200}>\s*\{[^{}]{1,200}\}\s*</",
                line,
            ):
                status = "satisfied"
            elif path.endswith(".component.html") and re.search(
                r"\{\{[^{}]{1,200}\}\}", line
            ):
                status = "satisfied"
        elif kind == "workflow-permissions":
            if re.match(r"\s*permissions:\s*write-all\s*(?:#.*)?$", line):
                status = "violated"
            elif re.match(r"\s*permissions:\s*read-all\s*(?:#.*)?$", line):
                status = "satisfied"
        if status:
            rows.append((number, status))
    return rows


# (trait, kind, names): declared npm packages that indicate an architecture trait.
NPM_TRAITS = (
    (
        "frontend",
        None,
        ("react", "@angular/core", "vue", "preact", "svelte", "solid-js"),
    ),
    (
        "templates",
        None,
        ("ejs", "pug", "hbs", "handlebars", "express-handlebars", "nunjucks"),
    ),
    (
        "persistence",
        "sql",
        (
            "pg",
            "mysql",
            "mysql2",
            "sqlite3",
            "better-sqlite3",
            "mssql",
            "oracledb",
            "sequelize",
            "knex",
            "@prisma/client",
            "typeorm",
            "drizzle-orm",
        ),
    ),
    ("persistence", "document", ("mongodb", "mongoose")),
    (
        "authentication",
        "local-password",
        (
            "bcrypt",
            "bcryptjs",
            "argon2",
            "@node-rs/argon2",
            "@node-rs/bcrypt",
            "passport-local",
        ),
    ),
    (
        "authentication",
        "federated",
        (
            "openid-client",
            "express-openid-connect",
            "passport-openidconnect",
            "passport-oauth2",
            "next-auth",
            "@auth/core",
            "@azure/msal-node",
            "@azure/msal-browser",
            "angular-oauth2-oidc",
            "oidc-client-ts",
            "keycloak-js",
            "keycloak-connect",
            "@auth0/auth0-react",
            "@auth0/auth0-spa-js",
            "passport-google-oauth20",
            "@react-oauth/google",
        ),
    ),
    ("authentication", "saml", ("passport-saml", "@node-saml/passport-saml")),
    (
        "authentication",
        "jwt",
        ("jsonwebtoken", "jose", "express-jwt", "passport-jwt", "@nestjs/jwt"),
    ),
    (
        "authentication",
        "session",
        (
            "express-session",
            "cookie-session",
            "koa-session",
            "@fastify/session",
            "iron-session",
        ),
    ),
)
# The same for Python imports; a name also matches its submodules and members.
PYTHON_TRAITS = (
    (
        "templates",
        None,
        (
            "jinja2",
            "mako",
            "django.template",
            "django.shortcuts.render",
            "flask.render_template",
            "fastapi.templating",
            "starlette.templating",
        ),
    ),
    (
        "persistence",
        "sql",
        (
            "sqlalchemy",
            "django.db",
            "sqlite3",
            "psycopg",
            "psycopg2",
            "pymysql",
            "MySQLdb",
            "asyncpg",
            "peewee",
        ),
    ),
    ("persistence", "document", ("pymongo", "motor", "mongoengine")),
    (
        "authentication",
        "local-password",
        (
            "bcrypt",
            "argon2",
            "passlib",
            "flask_bcrypt",
            "werkzeug.security",
            "django.contrib.auth.authenticate",
            "django.contrib.auth.hashers",
            "fastapi.security.OAuth2PasswordRequestForm",
        ),
    ),
    (
        "authentication",
        "federated",
        (
            "authlib",
            "social_core",
            "social_django",
            "allauth",
            "msal",
            "requests_oauthlib",
            "mozilla_django_oidc",
            "flask_dance",
        ),
    ),
    ("authentication", "saml", ("onelogin.saml2", "saml2")),
    (
        "authentication",
        "jwt",
        ("jwt", "jose", "flask_jwt_extended", "rest_framework_simplejwt"),
    ),
    (
        "authentication",
        "session",
        ("flask_login", "flask_session", "django.contrib.sessions"),
    ),
)
# Login configured in settings rather than declared as a package or import.
LOGIN_CONFIGURATION = (
    ("federated", "Spring OAuth2 client", (".yml", ".yaml"), r"(?m)^\s*issuer-uri\s*:"),
    ("saml", "Spring SAML", (".yml", ".yaml"), r"(?m)^\s*saml2\s*:\s*$"),
    (
        "federated",
        "Keycloak",
        (".yml", ".yaml", ".json"),
        r"[\"']?auth-server-url[\"']?\s*:",
    ),
    ("federated", "django-allauth", (".py",), r"(?m)^SOCIALACCOUNT_PROVIDERS\s*="),
    (
        "federated",
        "mozilla-django-oidc",
        (".py",),
        r"(?m)^OIDC_OP_AUTHORIZATION_ENDPOINT\s*=",
    ),
    ("saml", "SAML settings", (".py",), r"(?m)^(?:SAML_CONFIG|SAML2_AUTH)\s*="),
    (
        "local-password",
        "next-auth credentials",
        tuple(JS_EXTENSIONS),
        r"\bCredentialsProvider\s*\(",
    ),
)
# Sign-in endpoints of identity providers; code that names one starts a federated login.
SSO_ENDPOINTS = tuple(
    (name, re.compile(pattern))
    for name, pattern in (
        ("Google sign-in", r"accounts\.google\.com/o/oauth2"),
        ("Microsoft sign-in", r"login\.microsoftonline\.com/[\w.-]{1,100}/oauth2"),
        ("GitHub sign-in", r"github\.com/login/oauth/authorize"),
        ("GitLab sign-in", r"gitlab\.com/oauth/authorize"),
        ("Apple sign-in", r"appleid\.apple\.com/auth/authorize"),
        ("Okta", r"\.okta\.com/oauth2/"),
        ("Auth0", r"\.auth0\.com/authorize"),
        ("Keycloak", r"/protocol/openid-connect/auth\b"),
        ("Amazon Cognito", r"\.amazoncognito\.com/oauth2/authorize"),
    )
)
COMMENT_LINE = re.compile(r"[ \t]*(?://|#|/?\*)")
# A password read from a request body indicates a local password login.
JS_PASSWORD_INPUT = re.compile(
    r"\b(?:req|request|ctx\.request)\.body\s*(?:\??\.\s*|\[\s*['\"])(?:password|passwd)\b"
    r"|\{[^{}\n]{0,200}\bpassword\b[^{}\n]{0,200}\}\s*=\s*(?:req|request|ctx\.request)\.body\b"
)
PYTHON_REQUEST_FIELDS = {
    "request.form",
    "request.json",
    "request.POST",
    "request.data",
    "request.values",
    "request.get_json()",
    "form.cleaned_data",
    "self.cleaned_data",
}
PASSWORD_KEYS = {"password", "passwd"}


def python_imports(tree):
    """Absolute dotted import names, including `from` members; relative ones are local."""
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            names.add(node.module)
            names.update(node.module + "." + alias.name for alias in node.names)
    return names


def python_password_input(tree):
    """First line reading a password key from a recognized request field."""

    def field(node):
        if isinstance(node, ast.Call) and not node.args:
            return qualified(node.func) + "()"
        return qualified(node)

    lines = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Subscript):
            base, key = node.value, node.slice
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and node.args
        ):
            base, key = node.func.value, node.args[0]
        else:
            continue
        if (
            isinstance(key, ast.Constant)
            and key.value in PASSWORD_KEYS
            and field(base) in PYTHON_REQUEST_FIELDS
        ):
            lines.append(node.lineno)
    return min(lines, default=None)


def sql_queries(checks):
    """How recognized SQL query calls build their text, from the PY-SQL/JS-SQL checks."""
    counts, first = Counter(), None
    for row in checks:
        if row["rule"] not in {"PY-SQL", "JS-SQL"}:
            continue
        for item in row.get("locations", []):
            counts[item["status"]] += 1
            key = (source_priority(row["file"]), row["file"], item["line"])
            if item["status"] == "violated" and (first is None or key < first):
                first = key
    calls = sum(counts.values())
    return {
        "status": "constructed"
        if counts["violated"]
        else "unresolved"
        if counts["unclear"]
        else "literal"
        if calls
        else "none",
        "calls": calls,
        "constructed": counts["violated"],
        "literal": counts["satisfied"],
        "unresolved": counts["unclear"],
        **({"example": {"file": first[1], "line": first[2]}} if first else {}),
    }


def sso_endpoints(text):
    """Provider sign-in endpoints named outside comment lines, with their first line."""
    found = []
    for name, pattern in SSO_ENDPOINTS:
        for match in pattern.finditer(text):
            start = text.rfind("\n", 0, match.start()) + 1
            if not COMMENT_LINE.match(text, start):
                found.append((name, text.count("\n", 0, start) + 1))
                break
    return found


def exact_versions(files, budget):
    """How many direct dependencies name one version; context, not a control."""
    counts = {"npm": Counter(), "Python": Counter()}

    def count(ecosystem, exact):
        counts[ecosystem]["direct"] += 1
        counts[ecosystem]["exact"] += bool(exact)

    for path, source in sorted(files.items()):
        budget.check()
        name = Path(path).name
        if origin(path) not in OWN_CODE:
            continue
        if name == "package.json":
            manifest = document(source["text"]) or {}
            for field in ("dependencies", "devDependencies", "optionalDependencies"):
                values = manifest.get(field)
                for value in values.values() if isinstance(values, dict) else ():
                    if isinstance(value, str) and not value.startswith(
                        ("file:", "link:", "workspace:")
                    ):
                        count("npm", EXACT_NPM_VERSION.fullmatch(value))
        elif name.startswith("requirements") and Path(path).suffix == ".txt":
            for _, value in logical_lines(source["text"]):
                value = re.sub(r"(?:^|\s)#.*", "", value).strip()
                if value and not value.startswith("-"):
                    count("Python", EXACT_REQUIREMENT.match(value))
    return [
        {"ecosystem": ecosystem, "exact": row["exact"], "direct": row["direct"]}
        for ecosystem, row in counts.items()
        if row["direct"]
    ]


def dependency_updates(checks):
    """Which tool a recognized update configuration belongs to."""
    return sorted(
        (
            {
                "technology": "Renovate" if "renovate" in row["file"] else "Dependabot",
                "file": row["file"],
            }
            for row in checks
            if row["rule"] == "DEP-UPDATE-CONFIG"
        ),
        key=lambda row: row["file"],
    )


def password_hashing(checks):
    """Which recognized hash a password reaches, from the PASSWORD-HASH check."""
    rows = [
        {
            "technology": item["detail"],
            "status": item["status"],
            "file": row["file"],
            "line": item["line"],
        }
        for row in checks
        if row["rule"] == "PASSWORD-HASH"
        for item in row.get("locations", [])
    ]
    return sorted(rows, key=lambda row: (source_priority(row["file"]), row["line"]))


def login_summary(authentication):
    mechanisms = {row["mechanism"] for row in authentication}
    sso = bool(mechanisms & {"federated", "saml"})
    password = "local-password" in mechanisms
    return (
        "both"
        if sso and password
        else "sso"
        if sso
        else "password"
        if password
        else "none"
    )


def describe(files, budget, checks=(), paths=()):
    """Technology observations are context, not scored control evidence."""
    traits = {"frontend": [], "templates": [], "persistence": [], "authentication": []}
    keys = {"persistence": "kind", "authentication": "mechanism"}
    cloud_login = []

    def add(trait, kind, name, path, line=None):
        row = {"technology": name, "file": path}
        if trait in keys:
            row[keys[trait]] = kind
        if line is not None:
            row["line"] = line
        traits[trait].append(row)

    for path, source in sorted(files.items()):
        budget.check()
        suffix = Path(path).suffix.lower()
        for mechanism, name, suffixes, pattern in LOGIN_CONFIGURATION:
            if suffix in suffixes and re.search(pattern, source["text"]):
                add("authentication", mechanism, name, path)
        if origin(path) == "source":
            for name, line in sso_endpoints(source["text"]):
                add("authentication", "federated", name, path, line)
        if ci_file(path):
            cloud_login.extend(cloud_login_rows(path, source["text"]))
        if Path(path).name == "package.json":
            manifest = document(source["text"]) or {}
            dependencies = {}
            for key in ("dependencies", "devDependencies"):
                if isinstance(manifest.get(key), dict):
                    dependencies.update(manifest[key])
            for trait, kind, names in NPM_TRAITS:
                for name in names:
                    if name in dependencies:
                        add(trait, kind, name, path)
        elif suffix in JS_EXTENSIONS:
            for number, line in enumerate(source["text"].splitlines(), 1):
                if not re.match(r"\s*(?://|/?\*)", line) and JS_PASSWORD_INPUT.search(
                    line
                ):
                    add(
                        "authentication",
                        "local-password",
                        "password from request",
                        path,
                        number,
                    )
                    break
        elif suffix == ".py":
            try:
                tree = ast.parse(source["text"])
            except (SyntaxError, ValueError, RecursionError):
                continue
            imports = python_imports(tree)
            for trait, kind, names in PYTHON_TRAITS:
                for name in names:
                    if any(
                        imported == name or imported.startswith(name + ".")
                        for imported in imports
                    ):
                        add(trait, kind, name, path)
            line = python_password_input(tree)
            if line is not None:
                add(
                    "authentication",
                    "local-password",
                    "password from request",
                    path,
                    line,
                )
    return {
        **traits,
        "login": login_summary(traits["authentication"]),
        "password_hashing": password_hashing(checks),
        "sql_queries": sql_queries(checks),
        "deployment": deployment_rows(files, paths),
        "cloud_login": cloud_login,
        "lockfiles": lockfiles(paths),
        "exact_versions": exact_versions(files, budget),
        "dependency_updates": dependency_updates(checks),
        "interpretation": "Declared packages, imports and selected code patterns only; their presence gives no score credit, and an unrecognized trait may still exist. CSP delivery, authorization, DB privileges and deployment controls require wider evidence.",
    }
