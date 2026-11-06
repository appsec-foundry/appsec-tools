"""Repository context for --details: technologies, files, development practice.

score.py imports this module only for a --details run, so a plain scan does not
even load it; keep it out of every other module's imports.
Nothing here becomes a finding, a check or an input to the score: a score must
not depend on how its result is displayed. Repository text is only compared with
the fixed tables below. Apart from paths and version specifications of a
restricted shape, everything in the output comes from these tables.
"""

import ast
from collections import Counter
from pathlib import Path
import re
from urllib.parse import quote

from score_ai import package_name as ai_package
from score_architecture import COMMENT_LINE, JS_NAME, bracket_pairs, js_arguments, js_imports
from score_core import GRADLE_BUILD_FILES, JS_EXTENSIONS, javascript_code
from score_infrastructure import OWN_CODE, ci_file, document, line_of, logical_lines
from score_remote import json_get, repository_url, select_token
from score_reporting import container_build_file, origin, source_priority
from score_sources import SourceError, git

COMMIT_SAMPLE = 100
BRANCH_PAGE = 100
HISTORY_OUTPUT = 1024 * 1024

HTTP_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT")
ROUTE_METHODS = {method.lower(): method for method in HTTP_METHODS}
ROUTE_METHODS.update(all="ALL", websocket="WebSocket")
# Narrow declaration shapes, rather than every .get() call (HTTP clients, maps).
JS_ROUTE = re.compile(
    r"(?<![\w$.])(?:app|router|server)\s*\.\s*("
    + "|".join((*ROUTE_METHODS, "use"))
    + r")\s*\("
)
JS_ROUTE_PATH = re.compile(r"\s*(['\"`])(/[^'\"`\n]{0,2048})\1\s*,")
REST_PATH = re.compile(r"^/(?:api|rest)(?:/|$)|^/(?:[a-z][\w-]*/)?v[0-9]+/")
OTHER_API_PATH = re.compile(
    r"(?:^|/)(?:graphql|graphiql|gql|rpc|trpc|jsonrpc|xmlrpc|soap|ws|websocket|socket\.io)(?:/|$)",
    re.IGNORECASE,
)
PAGE_OR_FILE_PATH = re.compile(
    r"\.(?:html?|css|[cm]?js|png|jpe?g|gif|svg|ico|txt|xml|pdf|mp4|zip)$", re.IGNORECASE
)
JS_RESPONSE = r"\b(?:res|response)\s*(?:\.\s*status\s*\([^()]{1,200}\)\s*)?\.\s*"
JS_JSON_RESPONSE = re.compile(JS_RESPONSE + r"json\s*\(")
JS_PAGE_RESPONSE = re.compile(JS_RESPONSE + r"(?:render|sendFile|download|redirect)\s*\(")
GRAPHQL_FACTORIES = {
    "graphql-http/lib/use/express": "createHandler",
    "express-graphql": "graphqlHTTP",
    "@apollo/server/express4": "expressMiddleware",
    "@as-integrations/express4": "expressMiddleware",
    "@as-integrations/express5": "expressMiddleware",
    "graphql-yoga": "createYoga",
}
JS_CONST_HANDLER = re.compile(
    rf"\bconst\s+({JS_NAME})\s*=\s*({JS_NAME}(?:\s*\.\s*{JS_NAME})?)\s*\("
)
JS_HANDLER_END = re.compile(r"[ \t]*(?:;|\n|$)")


def graphql_bindings(text, code, pairs, budget):
    """Recognize imported factories and simple local const handlers, never run them."""
    factories, handlers = set(), {}
    for local, module, member in js_imports(text, code):
        budget.check()
        expected = GRAPHQL_FACTORIES.get(module)
        if expected and member == expected:
            factories.add(local)
        elif expected and member in {"*", "="}:
            factories.add(f"{local}.{expected}")
    for match in JS_CONST_HANDLER.finditer(code):
        budget.check()
        if re.sub(r"\s", "", match[2]) not in factories:
            continue
        opening = match.end() - 1
        if js_arguments(code, opening, pairs) is not None:
            end = pairs[opening] + 1
            if JS_HANDLER_END.match(code, end):
                handlers[match[1]] = end
    return factories, handlers


def graphql_argument(code, span, pairs, factories, handlers, registration):
    start, end = span
    value = code[start:end].strip()
    if value in handlers and handlers[value] < registration:
        return True
    call = re.match(rf"\s*({JS_NAME}(?:\s*\.\s*{JS_NAME})?)\s*\(", code[start:end])
    if not call or re.sub(r"\s", "", call[1]) not in factories:
        return False
    opening = start + call.end() - 1
    closing = pairs.get(opening)
    return (js_arguments(code, opening, pairs) is not None
            and closing is not None and not code[closing + 1:end].strip())


def rest_route(path, handler_code=""):
    """Infer an HTTP API style from namespaces or an inline JSON handler.

    This is overview evidence, not verification of REST architectural constraints.
    Other known protocol paths and page/file responses take precedence.
    """
    if ("\\" in path or OTHER_API_PATH.search(path) or PAGE_OR_FILE_PATH.search(path)
            or JS_PAGE_RESPONSE.search(handler_code)):
        return False
    return bool(REST_PATH.match(path) or (
        ("=>" in handler_code or re.match(r"\s*(?:async\s+)?function\b", handler_code))
        and JS_JSON_RESPONSE.search(handler_code)
    ))


def route_counts(path, text, budget):
    """Count recognized declarations, never retain paths or execute source.

    Method counts can overlap: one Python decorator can declare GET and POST.
    Framework-generated HEAD/OPTIONS routes and dynamic registrations stay out.
    """
    counts, kinds, total = Counter(), Counter(), 0
    suffix = Path(path).suffix.lower()
    if suffix in JS_EXTENSIONS:
        try:
            code = javascript_code(text)
        except SyntaxError:
            return 0, counts, kinds
        pairs = bracket_pairs(code)
        factories, handlers = graphql_bindings(text, code, pairs, budget)
        for match in JS_ROUTE.finditer(code):
            budget.check()
            path_match = JS_ROUTE_PATH.match(text, match.end())
            if path_match and not (path_match[1] == "`" and "${" in path_match[0]):
                arguments = js_arguments(code, match.end() - 1, pairs)
                graphql = arguments is not None and any(
                    graphql_argument(code, span, pairs, factories, handlers, match.start())
                    for span in arguments[1:]
                )
                if match[1] == "use" and not graphql:
                    continue
                method = ROUTE_METHODS.get(match[1], "ALL")
                handler = code[slice(*arguments[-1])] if arguments else ""
                if method == "WebSocket":
                    kind = "WebSocket"
                elif graphql:
                    kind = "GraphQL"
                elif rest_route(path_match[2], handler):
                    kind = "REST"
                else:
                    kind = "HTTP"
                counts[method] += 1
                kinds[kind] += 1
                total += 1
    elif suffix == ".py":
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError, RecursionError):
            return 0, counts, kinds
        for node in ast.walk(tree):
            budget.check()
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for decorator in node.decorator_list:
                if not (
                    isinstance(decorator, ast.Call)
                    and isinstance(decorator.func, ast.Attribute)
                    and decorator.func.attr in {*ROUTE_METHODS, "route", "api_route"}
                ):
                    continue
                path_node = decorator.args[0] if decorator.args else next(
                    (kw.value for kw in decorator.keywords if kw.arg in {"path", "rule"}), None
                )
                if not (isinstance(path_node, ast.Constant)
                        and isinstance(path_node.value, str)
                        and path_node.value.startswith("/")):
                    continue
                method = decorator.func.attr
                if method in {"route", "api_route"}:
                    methods = next(
                        (kw.value for kw in decorator.keywords if kw.arg == "methods"), None
                    )
                    if methods is None:
                        recognized = {"GET"}
                    elif isinstance(methods, (ast.List, ast.Tuple, ast.Set)) and methods.elts and all(
                        isinstance(item, ast.Constant) and isinstance(item.value, str)
                        and item.value.upper() in HTTP_METHODS for item in methods.elts
                    ):
                        recognized = {item.value.upper() for item in methods.elts}
                    else:
                        recognized = {"unspecified"}
                else:
                    recognized = {ROUTE_METHODS[method]}
                counts.update(recognized)
                if "WebSocket" in recognized:
                    kind = "WebSocket"
                else:
                    kind = "REST" if rest_route(path_node.value) else "HTTP"
                kinds[kind] += 1
                total += 1
    return total, counts, kinds


LANGUAGES = {
    ".py": "Python",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".java": "Java",
    ".kt": "Kotlin",
    ".scala": "Scala",
    ".go": "Go",
    ".rs": "Rust",
    ".cs": "C#",
    ".php": "PHP",
    ".rb": "Ruby",
    ".c": "C",
    ".h": "C",
    ".cpp": "C++",
    ".cc": "C++",
    ".hpp": "C++",
    ".swift": "Swift",
    ".dart": "Dart",
    ".lua": "Lua",
    ".vue": "Vue",
    ".svelte": "Svelte",
    ".html": "HTML",
    ".css": "CSS",
    ".scss": "CSS",
    ".sh": "Shell",
    ".bash": "Shell",
    ".ps1": "PowerShell",
    ".sql": "SQL",
    ".tf": "Terraform",
}

# Maven coordinates also match by group, so every starter of a framework counts.
FRAMEWORKS = {
    ("npm", "express"): "Express",
    ("npm", "fastify"): "Fastify",
    ("npm", "koa"): "Koa",
    ("npm", "@hapi/hapi"): "hapi",
    ("npm", "@nestjs/core"): "NestJS",
    ("npm", "next"): "Next.js",
    ("npm", "nuxt"): "Nuxt",
    ("npm", "@angular/core"): "Angular",
    ("npm", "react"): "React",
    ("npm", "vue"): "Vue",
    ("npm", "svelte"): "Svelte",
    ("npm", "socket.io"): "Socket.IO",
    ("npm", "graphql"): "GraphQL",
    ("npm", "electron"): "Electron",
    ("python", "django"): "Django",
    ("python", "flask"): "Flask",
    ("python", "fastapi"): "FastAPI",
    ("python", "starlette"): "Starlette",
    ("python", "tornado"): "Tornado",
    ("python", "aiohttp"): "aiohttp",
    ("python", "pyramid"): "Pyramid",
    ("python", "celery"): "Celery",
    ("maven", "org.springframework.boot"): "Spring Boot",
    ("maven", "io.quarkus"): "Quarkus",
    ("maven", "io.micronaut"): "Micronaut",
    ("php", "laravel/framework"): "Laravel",
    ("php", "symfony/framework-bundle"): "Symfony",
}
TEST_TOOLS = {
    ("npm", "jest"): "Jest",
    ("npm", "mocha"): "Mocha",
    ("npm", "vitest"): "Vitest",
    ("npm", "cypress"): "Cypress",
    ("npm", "@playwright/test"): "Playwright",
    ("npm", "karma"): "Karma",
    ("npm", "jasmine-core"): "Jasmine",
    ("python", "pytest"): "pytest",
    ("python", "tox"): "tox",
    ("python", "nox"): "nox",
    ("python", "hypothesis"): "Hypothesis",
    ("maven", "junit"): "JUnit",
    ("maven", "org.junit.jupiter"): "JUnit",
    ("maven", "org.testng"): "TestNG",
    ("php", "phpunit/phpunit"): "PHPUnit",
}
# The package itself is the problem, in every version, so this list needs no
# version feed. Known vulnerabilities of maintained packages stay out (REQ-13).
INSECURE_PACKAGES = {
    ("npm", "node-serialize"): "runs code embedded in serialized data",
    ("npm", "vm2"): "sandbox with repeated escapes",
    ("npm", "angular"): "AngularJS, support ended 2021",
    ("npm", "request"): "deprecated, SSRF bypass without a fixed release",
    ("python", "pycrypto"): "unmaintained, use pycryptodome",
    ("maven", "log4j:log4j"): "Log4j 1, end of life 2015",
    ("maven", "struts:struts"): "Struts 1, end of life 2013",
    ("maven", "org.apache.struts:struts-core"): "Struts 1, end of life 2013",
    ("maven", "commons-httpclient:commons-httpclient"): "end of life",
}

RUNTIME_NAMES = {
    "node": "Node.js",
    "python": "Python",
    "php": "PHP",
    "ruby": "Ruby",
    "centos": "CentOS",
    "debian": "Debian",
    "ubuntu": "Ubuntu",
}
# First version with upstream support, fixed per release of this table. Comparing
# with today's date would make the same sources give a different result (REQ-01).
EOL_BELOW = {
    "node": (22,),
    "python": (3, 10),
    "php": (8, 2),
    "ruby": (3, 2),
    "centos": (9999,),  # Every CentOS Linux release ended.
    "debian": (11,),
    "ubuntu": (20, 4),
}
DEBIAN_CODENAMES = {"jessie": "8", "stretch": "9", "buster": "10"}
# Official images only: the tag of another publisher's image says nothing here.
IMAGE = re.compile(
    r"(?:docker\.io/)?(?:library/)?(" + "|".join(RUNTIME_NAMES) + r")"
    r":(\d{1,4}(?:\.\d{1,4}){0,3}|" + "|".join(DEBIAN_CODENAMES) + r")"
    r"(?:-\S*)?(?:@\S+)?"
)
DOCKER_FROM = re.compile(r"(?i)[ \t]*FROM[ \t]+(?:--platform=\S+[ \t]+)?(\S+)")
YAML_IMAGE = re.compile(r"[ \t]*(?:-[ \t]+)?image[ \t]*:[ \t]*[\"']?([^\s\"'#]+)")
VERSION_SPEC = re.compile(r"[\w.,<>=~^*| -]{1,40}")
NODE_LINE = re.compile(r"[\^~=v]{0,2}(\d{1,4}(?:\.\d{1,4}){0,2})(?:\.[x*])?")
PYTHON_LINE = re.compile(r"==[ ]?(\d{1,4}\.\d{1,4})(?:\.(?:\d{1,4}|\*))?")

LEGACY_TLS = ("TLS below 1.2", "deprecated by RFC 8996")
CIPHER_CALL = r"""(?i)\bcreate(?:de)?cipher(?:iv)?\s*\(\s*['"`]"""
DES = ("DES or 3DES", "retired block ciphers")
RC4 = ("RC4", "broken stream cipher")
ECB = ("ECB mode", "repeated plaintext blocks stay visible")
# Bounded repeats and [ \t] keep these linear on hostile input.
SOURCE_RISKS = tuple(
    (suffixes, *risk, re.compile(pattern, flags))
    for suffixes, risk, pattern, flags in (
        (
            {".py"},
            LEGACY_TLS,
            r"\bssl\.(?:PROTOCOL_(?:SSLv[23]|TLSv1(?:_1)?)"
            r"|TLSVersion\.(?:SSLv3|TLSv1(?:_1)?))\b",
            0,
        ),
        (
            JS_EXTENSIONS,
            LEGACY_TLS,
            r"""\bsecureProtocol\s*:\s*['"](?:SSLv[23]|TLSv1(?:_1)?)_"""
            r"""|\bminVersion\s*:\s*['"]TLSv1(?:\.1)?['"]""",
            0,
        ),
        (
            {".conf"},
            LEGACY_TLS,
            r"^[ \t]*ssl_protocols\b[^;#]{0,200}\b(?:SSLv[23]|TLSv1(?:\.1)?)(?![.\d])",
            re.M,
        ),
        (
            {".conf"},
            LEGACY_TLS,
            r"^[ \t]*SSLProtocol\b[^#\n]{0,200}(?<![-\w])\+?"
            r"(?:SSLv3|TLSv1(?:\.1)?)(?![.\d])",
            re.M,
        ),
        (
            {".tf"},
            LEGACY_TLS,
            r'\bmin(?:imum)?_tls_version\s*=\s*"(?:TLS_?1[_.][01]|1\.[01])"'
            r'|\bminimum_protocol_version\s*=\s*"(?:SSLv3|TLSv1(?:_2016|\.1_2016)?)"'
            r"|ELBSecurityPolicy-TLS-1-[01]-",
            0,
        ),
        ({".py"}, DES, r"\b(?:DES3?\.new\s*\(|algorithms\.TripleDES\b)", 0),
        ({".py"}, RC4, r"\b(?:ARC4\.new\s*\(|algorithms\.ARC4\b)", 0),
        ({".py"}, ECB, r"\b(?:AES\.MODE_ECB|modes\.ECB)\b", 0),
        (JS_EXTENSIONS, DES, CIPHER_CALL + r"(?:des|3des)", 0),
        (JS_EXTENSIONS, RC4, CIPHER_CALL + r"rc4", 0),
        (JS_EXTENSIONS, ECB, CIPHER_CALL + r"aes-\d{3}-ecb", 0),
        (
            JS_EXTENSIONS,
            ("crypto.createCipher", "unsalted key, removed from Node.js 22"),
            r"\bcreate(?:De)?[cC]ipher\s*\(",
            0,
        ),
    )
)
LEGACY_CONTENT = (
    ("Adobe Flash", "support ended 2020", re.compile(r"(?i)\.swf$")),
    ("Microsoft Silverlight", "support ended 2021", re.compile(r"(?i)\.xap$")),
)

PACKAGE_TOOLS = (
    ("npm", r"(?:^|/)(?:package\.json|package-lock\.json|npm-shrinkwrap\.json)$"),
    ("Yarn", r"(?:^|/)yarn\.lock$"),
    ("pnpm", r"(?:^|/)pnpm-lock\.yaml$"),
    ("Bun", r"(?:^|/)bun\.lockb?$"),
    ("pip", r"(?:^|/)requirements[^/]*\.txt$"),
    ("Poetry", r"(?:^|/)poetry\.lock$"),
    ("uv", r"(?:^|/)uv\.lock$"),
    ("Pipenv", r"(?:^|/)Pipfile$"),
    ("Maven", r"(?:^|/)pom\.xml$"),
    ("Gradle", r"(?:^|/)build\.gradle(?:\.kts)?$"),
    ("Go modules", r"(?:^|/)go\.mod$"),
    ("Cargo", r"(?:^|/)Cargo\.toml$"),
    ("Bundler", r"(?:^|/)Gemfile$"),
    ("Composer", r"(?:^|/)composer\.json$"),
)
PROCESS_FILES = (
    ("CODEOWNERS", r"^(?:\.github/|\.gitlab/|docs/)?CODEOWNERS$"),
    ("contributing guide", r"^(?:\.github/|docs/)?CONTRIBUTING(?:\.\w+)?$"),
    (
        "pull request template",
        r"(?i)^(?:\.github/|docs/)?pull_request_template(?:\.\w+)?$"
        r"|^\.github/pull_request_template/",
    ),
    ("merge request template", r"^\.gitlab/merge_request_templates/"),
    ("changelog", r"(?i)^(?:docs/)?change(?:log|s)(?:\.\w+)?$"),
)
QUALITY_TOOLS = (
    ("pre-commit", r"(?:^|/)\.pre-commit-config\.ya?ml$"),
    ("Husky", r"^\.husky/"),
    ("ESLint", r"(?:^|/)(?:\.eslintrc(?:\.\w+)?|eslint\.config\.\w+)$"),
    ("Prettier", r"(?:^|/)\.prettierrc(?:\.\w+)?$"),
    ("Ruff", r"(?:^|/)\.?ruff\.toml$"),
    ("Flake8", r"(?:^|/)\.flake8$"),
    ("golangci-lint", r"(?:^|/)\.golangci\.ya?ml$"),
    ("RuboCop", r"(?:^|/)\.rubocop\.yml$"),
)
CI_SYSTEMS = (
    ("GitHub Actions", r"^\.github/workflows/[^/]+\.ya?ml$"),
    ("GitLab CI", r"^\.gitlab-ci\.ya?ml$"),
    ("Jenkins", r"(?:^|/)Jenkinsfile$"),
    ("CircleCI", r"^\.circleci/config\.ya?ml$"),
    ("Azure Pipelines", r"^azure-pipelines\.ya?ml$"),
    ("Travis CI", r"^\.travis\.yml$"),
    ("Bitbucket Pipelines", r"^bitbucket-pipelines\.yml$"),
)
CI_STEPS = tuple(
    (name, re.compile(pattern))
    for name, pattern in (
        (
            "on pull or merge requests",
            r"(?m)^on:[^\n]{0,200}\bpull_request\b"
            r"|^[ \t]+(?:-[ \t]+)?pull_request(?:_target)?[ \t]*:?[ \t]*$"
            r"|\bmerge_request_event\b|^[ \t]+-[ \t]+merge_requests[ \t]*$",
        ),
        (
            "tests",
            r"\b(?:(?:npm|yarn|pnpm)(?: run)? test|pytest|tox|nox"
            r"|mvn(?: -\S+){0,5} (?:test|verify)|gradlew?(?: -\S+){0,5} (?:test|check)"
            r"|go test|cargo test|rspec|phpunit)\b",
        ),
    )
)
# A step or a command, because workflows also mention tools in lists and messages.
SECURITY_TOOLS = tuple(
    (name, re.compile(pattern, re.I))
    for name, pattern in (
        ("CodeQL", r"uses:\s*github/codeql-action/"),
        ("Semgrep", r"uses:\s*(?:semgrep|returntocorp)/|\bsemgrep (?:scan|ci)\b"),
        (
            "Trivy",
            r"uses:\s*aquasecurity/trivy-action|\btrivy (?:image|fs|repo|config)\b",
        ),
        ("Grype", r"uses:\s*anchore/scan-action|\bgrype (?:dir:|sbom:|\S+:\S)"),
        ("Gitleaks", r"uses:\s*gitleaks/|\bgitleaks (?:detect|protect|git|dir)\b"),
        (
            "TruffleHog",
            r"uses:\s*trufflesecurity/|\btrufflehog (?:git|github|filesystem)\b",
        ),
        ("Snyk", r"uses:\s*snyk/|\bsnyk (?:test|monitor|code|container|iac)\b"),
        ("Bandit", r"uses:\s*PyCQA/bandit|\bbandit (?:-r|--recursive)\b"),
        ("OWASP ZAP", r"uses:\s*zaproxy/"),
        ("OSV-Scanner", r"uses:\s*google/osv-scanner|\bosv-scanner (?:scan|--)"),
        ("Dependency Review", r"uses:\s*actions/dependency-review-action"),
        ("OpenSSF Scorecard", r"uses:\s*ossf/scorecard-action"),
        ("GitLab SAST", r"Security/SAST\.gitlab-ci\.yml"),
    )
)

# A rebase or an unmarked squash leaves none of these on a reviewed change.
REQUEST_MARKER = re.compile(
    r"^Merge pull request #\d+|^Merged PR \d+|\(pull request #\d+\)"
    r"|^Merge branch '[^']+' into '[^']+'|\(#\d+\)\s*$"
)
DATE = re.compile(r"\d{4}-\d{2}-\d{2}")


def declared_packages(path, text):
    """(ecosystem, package, line or None) from a manifest; other shapes yield nothing.

    Package names are only compared with the tables, so most never need a line.
    """
    name = Path(path).name
    if name in {"package.json", "composer.json"}:
        ecosystem, fields = (
            ("npm", ("dependencies", "devDependencies", "optionalDependencies"))
            if name == "package.json"
            else ("php", ("require", "require-dev"))
        )
        manifest = document(text) or {}
        for field in fields:
            values = manifest.get(field)
            for package in values if isinstance(values, dict) else ():
                yield ecosystem, package, None
    elif name.startswith("requirements") and Path(path).suffix == ".txt":
        for number, value in logical_lines(text):
            match = re.match(r"[A-Za-z0-9][\w.-]{0,200}", value.strip())
            if match:
                yield "python", python_name(match[0]), number
    elif name == "pyproject.toml":
        yield from pyproject_packages(text)
    elif name == "pom.xml":
        for match in re.finditer(
            r"<groupId>\s*([\w.-]{1,200})\s*</groupId>"
            r"\s*<artifactId>\s*([\w.-]{1,200})\s*</artifactId>",
            text,
        ):
            line = text.count("\n", 0, match.start()) + 1
            yield "maven", f"{match[1]}:{match[2]}", line
    elif name in GRADLE_BUILD_FILES:
        for number, line in enumerate(text.splitlines(), 1):
            if not COMMENT_LINE.match(line):
                for match in re.finditer(
                    r"""['"]([\w.-]{1,200}):([\w.-]{1,200})(?::[^'"\n]{0,100})?['"]""",
                    line,
                ):
                    yield "maven", f"{match[1]}:{match[2]}", number


def python_name(value):
    return re.sub(r"[-_.]+", "-", value).lower()


def pyproject_packages(text):
    """PEP 621 dependency lists and Poetry tables, read line by line."""
    section, inside = "", False
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if not inside and stripped.startswith("["):
            section = stripped
        if re.match(r"dependencies\s*=\s*\[", stripped):
            inside = True
        if inside:
            for name in re.findall(r"[\"']([A-Za-z0-9][\w.-]{0,200})", line):
                yield "python", python_name(name), number
            inside = not re.search(r"\]\s*(?:#.*)?$", stripped)
        elif section == "[tool.poetry.dependencies]":
            match = re.match(r"([A-Za-z0-9][\w.-]{0,200})\s*=", stripped)
            if match:
                yield "python", python_name(match[1]), number


def runtime_rows(path, text):
    """(runtime, shown version, single release line or None, line number)."""
    name = Path(path).name
    if name == "package.json":
        engines = (document(text) or {}).get("engines")
        spec = engines.get("node") if isinstance(engines, dict) else None
        if isinstance(spec, str) and VERSION_SPEC.fullmatch(spec):
            release = NODE_LINE.fullmatch(spec)
            yield "node", spec, release and release[1], line_of(text, '"engines"')
    elif name == "pyproject.toml":
        match = re.search(
            r"(?m)^[ \t]*requires-python[ \t]*=[ \t]*[\"']([^\"'\n]+)", text
        )
        if match and VERSION_SPEC.fullmatch(match[1]):
            release = PYTHON_LINE.fullmatch(match[1])
            line = text.count("\n", 0, match.start()) + 1
            yield "python", match[1], release and release[1], line
    elif Path(path).suffix.lower() in {".yml", ".yaml"} or container_build_file(name):
        pattern = DOCKER_FROM if container_build_file(name) else YAML_IMAGE
        for number, line in enumerate(text.splitlines(), 1):
            match = pattern.match(line)
            image = match and IMAGE.fullmatch(match[1])
            if image:
                version = DEBIAN_CODENAMES.get(image[2], image[2])
                yield image[1], version, version, number


def past_end_of_life(runtime, version):
    """A tag that stops above the limit's precision, such as python:3, stays open."""
    numbers = tuple(int(part) for part in version.split("."))
    limit = EOL_BELOW[runtime]
    return numbers[: len(limit)] < limit[: len(numbers)]


def path_names(table, paths):
    return sorted(
        {name for name, pattern in table if any(re.search(pattern, p) for p in paths)}
    )


def repository_overview(files, paths, listed, budget):
    """Technologies, files and development signals from sources already read."""
    own_paths = [path for path in paths if origin(path) in OWN_CODE]
    frameworks, test_tools, runtimes, risks = set(), set(), {}, {}
    ai_sdks = set()
    ci_steps, security_tools = set(), set()
    routes, route_types, route_kinds = 0, Counter(), Counter()

    def risk(category, technology, reason, path, line=None):
        row = risks.setdefault(
            (category, technology),
            {
                "category": category,
                "technology": technology,
                "reason": reason,
                "file": path,
                "occurrences": 0,
                **({} if line is None else {"line": line}),
            },
        )
        row["occurrences"] += 1

    for path in sorted(files, key=source_priority):
        budget.check()
        if origin(path) not in OWN_CODE:
            continue
        text = files[path]["text"]
        if not files[path].get("fragment") and not files[path].get("fragments"):
            count, types, kinds = route_counts(path, text, budget)
            routes += count
            route_types.update(types)
            route_kinds.update(kinds)
        for ecosystem, package, line in declared_packages(path, text):
            key = (ecosystem, package)
            group = (ecosystem, package.split(":")[0])
            if key in FRAMEWORKS or group in FRAMEWORKS:
                frameworks.add(FRAMEWORKS.get(key) or FRAMEWORKS[group])
            if key in TEST_TOOLS or group in TEST_TOOLS:
                test_tools.add(TEST_TOOLS.get(key) or TEST_TOOLS[group])
            if ai_package(ecosystem, package):
                ai_sdks.add(ai_package(ecosystem, package))
            if key in INSECURE_PACKAGES:
                number = line or line_of(text, f'"{package}"')
                risk("dependency", package, INSECURE_PACKAGES[key], path, number)
        for runtime, version, release, line in runtime_rows(path, text):
            row = {
                "runtime": RUNTIME_NAMES[runtime],
                "version": version,
                "file": path,
                "line": line,
            }
            runtimes.setdefault((row["runtime"], version), row)
            if release and past_end_of_life(runtime, release):
                name = f"{RUNTIME_NAMES[runtime]} {version}"
                risk("runtime", name, "end of life", path, line)
        suffix = Path(path).suffix.lower()
        for suffixes, name, reason, pattern in SOURCE_RISKS:
            if suffix in suffixes:
                for match in pattern.finditer(text):
                    start = text.rfind("\n", 0, match.start()) + 1
                    if not COMMENT_LINE.match(text, start):
                        line = text.count("\n", 0, start) + 1
                        risk("crypto", name, reason, path, line)
        if ci_file(path):
            ci_steps.update(n for n, p in CI_STEPS if p.search(text))
            security_tools.update(n for n, p in SECURITY_TOOLS if p.search(text))
    for path in paths:
        for name, reason, pattern in LEGACY_CONTENT:
            if pattern.search(path) and origin(path) not in {"tests", "examples"}:
                risk("content", name, reason, path)
    languages = Counter(
        LANGUAGES[Path(path).suffix.lower()]
        for path in paths
        if Path(path).suffix.lower() in LANGUAGES and origin(path) != "assets"
    )
    ci_systems = Counter(
        name
        for path in own_paths
        for name, pattern in CI_SYSTEMS
        if re.search(pattern, path)
    )
    return {
        "interpretation": "Context from the file list, manifests and CI files of a --details run. It adds no score credit, and what is missing here may still exist.",
        "languages": [
            {"language": name, "files": count}
            for name, count in sorted(languages.items(), key=lambda p: (-p[1], p[0]))
        ],
        "files": {
            "listed": len(paths),
            "listing_complete": listed,
            "read": len(files),
            "lines": sum(source["text"].count("\n") + 1 for source in files.values()),
            "by_origin": dict(sorted(Counter(map(origin, paths)).items())),
        },
        "frameworks": sorted(frameworks),
        "routes": {
            "total": routes,
            "by_type": dict(sorted(route_types.items())),
            "by_kind": dict(sorted(route_kinds.items())),
        },
        "ai_sdks": sorted(ai_sdks),
        "test_tools": sorted(test_tools),
        "runtimes": sorted(
            runtimes.values(), key=lambda row: (row["runtime"], row["version"])
        ),
        "package_tools": path_names(PACKAGE_TOOLS, own_paths),
        "technology_risks": sorted(
            risks.values(), key=lambda row: (row["category"], row["technology"])
        ),
        "development": {
            "process_files": path_names(PROCESS_FILES, own_paths),
            "ci": [
                {"system": name, "files": count}
                for name, count in sorted(ci_systems.items())
            ],
            "ci_steps": sorted(ci_steps),
            "quality_tools": path_names(QUALITY_TOOLS, own_paths),
            "security_tools": sorted(security_tools),
        },
    }


def commit_row(identifier, parents, author, date, subject):
    """One commit in a uniform shape; host fields of a wrong type become empty."""
    return {
        "id": identifier if isinstance(identifier, str) else "",
        "parents": (
            [parent for parent in parents if isinstance(parent, str)]
            if isinstance(parents, list)
            else []
        ),
        "author": author if isinstance(author, str) else "",
        "date": date[:10] if isinstance(date, str) and DATE.match(date) else "",
        "subject": subject[:300] if isinstance(subject, str) else "",
    }


def local_history(root, budget):
    """Recent commits and the branch count of a checkout.

    Repository configuration must not start a program: showing signatures would
    run gpg.program, and a promisor remote would fetch missing commits.
    """
    if not (root / ".git").exists():
        raise SourceError("no Git history in the selected directory")
    guarded = ("-c", "log.showSignature=false", "-c", "protocol.allow=never")
    try:
        log = git(
            root,
            budget,
            *guarded,
            "log",
            "--first-parent",
            "--no-use-mailmap",
            "--encoding=UTF-8",
            f"--max-count={COMMIT_SAMPLE}",
            "--format=%H%x1f%P%x1f%ae%x1f%cs%x1f%s",
            limit=HISTORY_OUTPUT,
        )
        refs = git(
            root,
            budget,
            "for-each-ref",
            "--format=%(refname)",
            "refs/heads",
            "refs/remotes",
            limit=HISTORY_OUTPUT,
        )
    except SourceError:
        raise SourceError("Git history not readable") from None
    rows = []
    for line in log.decode("utf-8", "replace").split("\n"):
        fields = line.split("\x1f", 4)
        if len(fields) == 5:
            rows.append(
                commit_row(
                    fields[0], fields[1].split(), fields[2], fields[3], fields[4]
                )
            )
    # A local branch and its remote-tracking copy are one branch.
    names = set()
    for ref in refs.decode("utf-8", "replace").split():
        parts = ref.split("/")
        names.add("/".join(parts[2 if parts[1] == "heads" else 3 :]))
    names.discard("HEAD")
    return rows, rows[0]["id"] if rows else None, len(names)


def github_commit(row):
    commit = row.get("commit") if isinstance(row.get("commit"), dict) else {}
    author = commit.get("author") if isinstance(commit.get("author"), dict) else {}
    parents = row.get("parents") if isinstance(row.get("parents"), list) else []
    message = commit.get("message")
    return commit_row(
        row.get("sha"),
        [parent.get("sha") for parent in parents if isinstance(parent, dict)],
        author.get("email"),
        author.get("date"),
        message.split("\n", 1)[0] if isinstance(message, str) else None,
    )


def gitlab_commit(row):
    return commit_row(
        row.get("id"),
        row.get("parent_ids"),
        row.get("author_email"),
        row.get("committed_date"),
        row.get("title"),
    )


def remote_history(options, revision, budget):
    """One page of commits and one of branches: two API requests per --details run."""
    host, project = repository_url(options.repo)
    token = (
        options._remote_token
        if hasattr(options, "_remote_token")
        else select_token(host, options.token_env)
    )
    if host == "github.com":
        api, token_host, parse = (
            "https://api.github.com/repos/" + project,
            "api.github.com",
            github_commit,
        )
        commits_url = f"{api}/commits?sha={revision}&per_page={COMMIT_SAMPLE}"
        branches_url = f"{api}/branches?per_page={BRANCH_PAGE}"
    else:
        api, token_host, parse = (
            f"https://{host}/api/v4/projects/" + quote(project, safe=""),
            host,
            gitlab_commit,
        )
        commits_url = (
            f"{api}/repository/commits?ref_name={revision}&per_page={COMMIT_SAMPLE}"
        )
        branches_url = f"{api}/repository/branches?per_page={BRANCH_PAGE}"
    destination = (
        {"gitlab_host": host} if host not in {"github.com", "gitlab.com"} else {}
    )
    commits, reason = json_get(
        commits_url, budget, token, token_host, list, **destination
    )
    if reason:
        raise SourceError(reason)
    branches, reason = json_get(
        branches_url, budget, token, token_host, list, **destination
    )
    rows = [parse(row) for row in commits if isinstance(row, dict)]
    count = None if reason else len(branches)
    return rows, revision, f"{count}+" if count == BRANCH_PAGE else count


def history_summary(rows, head, branches, ref):
    """Counts along the first-parent line; author addresses never leave this function.

    Host responses list side branches too and could describe a loop, which removing
    each visited commit ends.
    """
    by_id = {row["id"]: row for row in rows}
    line, current = [], head
    while current in by_id:
        row = by_id.pop(current)
        line.append(row)
        current = row["parents"][0] if row["parents"] else None
    marked = [row for row in line if REQUEST_MARKER.search(row["subject"])]
    merges = sum(len(row["parents"]) > 1 for row in line)
    other_merges = merges - sum(len(row["parents"]) > 1 for row in marked)
    return {
        "ref": ref,
        "branches": branches,
        "commits": len(line),
        "with_request_marker": len(marked),
        "other_merges": other_merges,
        "without_marker": len(line) - len(marked) - other_merges,
        "authors": len({row["author"] for row in line if row["author"]}),
        "latest_commit": max((row["date"] for row in line), default=""),
        "basis": "Commit subjects only; a rebased or unmarked squash merge shows no marker, so a commit without one may still have been reviewed.",
    }
