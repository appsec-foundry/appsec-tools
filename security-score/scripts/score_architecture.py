"""Readable detectors for architecture and dependency declarations.

Each detector kind is linked from rules.json and returns located observations.
Presence of a framework, ORM, or lockfile never establishes application safety.
"""

from __future__ import annotations

import ast
from bisect import bisect_right
from collections import Counter
import json
from pathlib import Path
import re

from score_core import JS_EXTENSIONS, qualified
from score_reporting import source_priority


# A download piped to an interpreter, also through sudo or `sh -c "$(curl ...)"`.
PIPE_TO_SHELL = re.compile(
    r"\b(?:curl|wget)\b[^\n]{0,1000}\|\s*(?:sudo\s+(?:-\S+\s+){0,3})?(?:ba|z|k|da)?sh\b"
    r"|\b(?:ba|z|k|da)?sh\s+-c\s+[\"']?\$\(\s*(?:curl|wget)\b"
    r"|\b(?:Invoke-WebRequest|iwr)\b[^\n]{0,1000}\|\s*(?:iex|Invoke-Expression)\b",
    re.I,
)
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


def document(text):
    try:
        result = json.loads(text)
        return result if isinstance(result, dict) else None
    except (ValueError, RecursionError):
        return None


def line_of(text, name):
    index = text.find(name)
    return text.count("\n", 0, index) + 1 if index >= 0 else 1


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


def logical_lines(text, comment=None):
    """Join backslash continuations; yield (first line, instruction)."""
    parts, start = [], 1
    for number, line in enumerate(text.splitlines(), 1):
        if comment and parts and re.match(comment, line):
            continue  # Comment lines inside a continuation are removed.
        parts.append(line.rstrip())
        if parts[-1].endswith("\\"):
            parts[-1] = parts[-1][:-1]
            continue
        yield start, " ".join(parts)
        parts, start = [], number + 1
    if parts:
        yield start, " ".join(parts)


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
        elif not re.match(r"[\w.-]+(?:\[[\w,.-]+\])?==[^\s*]+", value):
            status = "violated"
        else:
            status = (
                "satisfied"
                if re.search(r"--hash=sha256:[0-9a-fA-F]{64}", value)
                else "unclear"
            )
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
    rows = []
    owner = None  # column of the run/script key whose value continues
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.lstrip(" ")
        indent = len(line) - len(stripped)
        if owner is not None and stripped and indent <= owner:
            owner = None
        if owner is None:
            match = re.match(r"(?:-\s+)*(run|script)\s*:(?=\s|$)", stripped)
            if not match:
                continue
            owner = indent + match.start(1)
            segment = stripped[match.end() :]
        else:
            segment = line
        if expression_matches(segment, UNTRUSTED_CONTEXT):
            rows.append((number, "violated"))
    return rows


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


def js_jwt_observations(text, code):
    """Literal algorithm allow-lists and expiry handling in token verification options."""
    rows = []
    breaks = [match.start() for match in re.finditer("\n", code)]
    for match in re.finditer(r"\balgorithms\s*:\s*\[", code):
        number = bisect_right(breaks, match.start()) + 1
        end = code.find("]", match.end(), match.end() + 400)
        items = (
            [item.strip() for item in text[match.end() : end].split(",")]
            if end >= 0
            else []
        )
        values = [re.fullmatch(r"(['\"`])([\w.-]+)\1", item) for item in items if item]
        status = (
            "unclear"
            if end < 0
            else "violated"
            if any(value and value[2].lower() == "none" for value in values)
            else "satisfied"
            if values and all(values)
            else "unclear"
        )
        rows.append((number, status))
    for match in re.finditer(r"\bignoreExpiration\s*:\s*(\w+)", code):
        rows.append(
            (
                bisect_right(breaks, match.start()) + 1,
                {"true": "violated", "false": "satisfied"}.get(match[1], "unclear"),
            )
        )
    return rows


def observations(rule, path, text, code, files):
    kind = rule["kind"]
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
            "passport-saml",
            "@node-saml/passport-saml",
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
        ),
    ),
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
            "onelogin.saml2",
            "saml2",
            "msal",
            "requests_oauthlib",
            "mozilla_django_oidc",
            "flask_dance",
        ),
    ),
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


def describe(files, budget, checks=()):
    """Technology observations are context, not scored control evidence."""
    traits = {"frontend": [], "templates": [], "persistence": [], "authentication": []}
    keys = {"persistence": "kind", "authentication": "mechanism"}

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
        "sql_queries": sql_queries(checks),
        "interpretation": "Declared packages, imports and selected code patterns only; their presence gives no score credit, and an unrecognized trait may still exist. CSP delivery, authorization, DB privileges and deployment controls require wider evidence.",
    }
