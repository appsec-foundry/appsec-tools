"""Readable detectors for CI scripts, dependency sources and infrastructure files.

YAML, TOML, XML and HCL are read line by line without a parser dependency, so
shapes other than the documented ones stay unrecognized. A declaration does not
establish that a pipeline ran or that a resource was deployed.
"""

from __future__ import annotations

from bisect import bisect_right
from collections import Counter
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

from score_reporting import container_build_file, origin

# A download piped to an interpreter, also through sudo or `sh -c "$(curl ...)"`.
PIPE_TO_SHELL = re.compile(
    r"\b(?:curl|wget)\b[^\n]{0,1000}\|\s*(?:sudo\s+(?:-\S+\s+){0,3})?(?:ba|z|k|da)?sh\b"
    r"|\b(?:ba|z|k|da)?sh\s+-c\s+[\"']?\$\(\s*(?:curl|wget)\b"
    r"|\b(?:Invoke-WebRequest|iwr)\b[^\n]{0,1000}\|\s*(?:iex|Invoke-Expression)\b",
    re.I,
)
INSECURE_URL = re.compile(r"\bhttp://(?!localhost\b|127\.0\.0\.1\b|\[::1\])", re.I)
FULL_COMMIT = re.compile(r"[0-9a-fA-F]{40}")


def document(text):
    try:
        result = json.loads(text)
        return result if isinstance(result, dict) else None
    except (ValueError, RecursionError):
        return None


NPM_LOCK = re.compile(
    r"package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?"
)
PYTHON_LOCK = re.compile(r"uv\.lock|poetry\.lock|pdm\.lock|pylock(?:\.[\w.-]+)?\.toml")
PYPROJECT_DEPENDENCIES = re.compile(
    r"(?m)^[ \t]*dependencies[ \t]*=[ \t]*\[\s*[\"']|^\[tool\.poetry\.dependencies\]"
)
# Where a project keeps its own manifests; fixtures and vendored copies do not count.
OWN_CODE = {"source", "build"}


def lockfiles(paths):
    return [
        {"technology": Path(path).name, "file": path}
        for path in paths
        if origin(path) in OWN_CODE
        and (
            NPM_LOCK.fullmatch(Path(path).name)
            or PYTHON_LOCK.fullmatch(Path(path).name)
            or Path(path).name == "Pipfile.lock"
        )
    ]


def manifests_without_lock(paths, files):
    """Manifests with dependencies and no lockfile beside them or at a root above.

    A pyproject.toml with a build backend may be a library, which leaves its
    versions to the consuming project, so it needs no lockfile here.
    """

    def directories(pattern):
        return {
            str(Path(path).parent)
            for path in paths
            if pattern.fullmatch(Path(path).name)
        }

    def locked(path, found):
        return any(str(parent) in found for parent in Path(path).parents)

    npm, python = directories(NPM_LOCK), directories(PYTHON_LOCK)
    requirements = directories(re.compile(r"requirements[^/]*\.txt"))
    present = set(paths)
    missing = []
    for path in paths:
        name = Path(path).name
        if origin(path) not in OWN_CODE:
            continue
        text = files.get(path, {}).get("text", "")
        if name == "package.json":
            manifest = document(text) or {}
            if not locked(path, npm) and any(
                isinstance(manifest.get(field), dict) and manifest[field]
                for field in ("dependencies", "devDependencies", "optionalDependencies")
            ):
                missing.append(path)
        elif name == "Pipfile":
            if path + ".lock" not in present:
                missing.append(path)
        elif name == "pyproject.toml":
            if (
                PYPROJECT_DEPENDENCIES.search(text)
                and "[build-system]" not in text
                and not locked(path, python)
                and str(Path(path).parent) not in requirements
            ):
                missing.append(path)
    return missing


def line_of(text, name):
    index = text.find(name)
    return text.count("\n", 0, index) + 1 if index >= 0 else 1


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


def gitlab_ci(path):
    return Path(path).name in {".gitlab-ci.yml", ".gitlab-ci.yaml"} or (
        path.startswith(".gitlab/ci/")
        and Path(path).suffix.lower() in {".yml", ".yaml"}
    )


def ci_file(path):
    return gitlab_ci(path) or (
        path.startswith(".github/workflows/")
        and Path(path).suffix.lower() in {".yml", ".yaml"}
    )


def script_lines(text, keys):
    """(line, text) of the values of script keys, including block scalars and lists."""
    pattern = re.compile(r"(?:-\s+)*(" + keys + r")\s*:(?=\s|$)")
    owner = None  # column of the key whose value continues
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.lstrip(" ")
        indent = len(line) - len(stripped)
        if (
            owner is not None
            and stripped
            and (indent < owner or (indent == owner and not stripped.startswith("- ")))
        ):
            owner = None
        if owner is not None:
            yield number, line
            continue
        match = pattern.match(stripped)
        if match:
            owner = indent + match.start(1)
            yield number, stripped[match.end() :]


def ci_commands(path, text):
    keys = "script|before_script|after_script" if gitlab_ci(path) else "run"
    for number, value in script_lines(text, keys):
        if not re.match(r"\s*(?:-\s+)?#", value):
            yield number, value


def ci_script_observations(path, text):
    return [
        (number, "violated")
        for number, command in ci_commands(path, text)
        if PIPE_TO_SHELL.search(command)
    ]


FROZEN_INSTALL = re.compile(
    r"\bnpm\s+ci\b"
    r"|\b(?:yarn|pnpm)\s+install\b[^\n&;|]{0,200}--(?:frozen-lockfile|immutable)\b"
)
NPM_INSTALL = re.compile(r"\bnpm\s+(?:install|i)\b(?P<arguments>[^\n&;|]*)")


def install_observations(path, text):
    """Project installs only: named packages and global tools are other operations."""
    commands = (
        [
            row
            for row in logical_lines(text, comment=r"\s*#")
            if re.match(r"(?i)\s*RUN\b", row[1])
        ]
        if container_build_file(Path(path).name)
        else ci_commands(path, text)
    )
    rows = []
    for number, command in commands:
        if FROZEN_INSTALL.search(command):
            rows.append((number, "satisfied"))
        for match in NPM_INSTALL.finditer(command):
            words = match["arguments"].split()
            if all(
                word.startswith("-") and word not in {"-g", "--global"}
                for word in words
            ):
                rows.append((number, "violated"))
    return rows


def gitlab_image_observations(text):
    """Variables usually name a project's own registry and stay unassessed."""
    rows, lines = [], text.splitlines()
    for index, line in enumerate(lines):
        match = re.match(r"\s*image\s*:\s*[\"']?([^\s\"'#]*)", line)
        if not match:
            continue
        value = match[1]
        if not value and index + 1 < len(lines):
            nested = re.match(r"\s+name\s*:\s*[\"']?([^\s\"'#]+)", lines[index + 1])
            value = nested[1] if nested else ""
        if value and "$" not in value:
            pinned = re.search(r"@sha256:[0-9a-fA-F]{64}$", value)
            rows.append((index + 1, "satisfied" if pinned else "violated"))
    return rows


def gitlab_include_observations(text):
    """Remote, project and component includes run outside this repository's review."""
    rows, inside, project = [], False, None

    def close_project():
        nonlocal project
        if project:
            rows.append((project, "violated"))
        project = None

    for number, line in enumerate(text.splitlines(), 1):
        if re.match(r"[^\s#]", line):
            close_project()
            inside = bool(re.match(r"include\s*:", line))
        if not inside:
            continue
        if re.match(r"\s*-\s", line):
            close_project()
        remote = re.search(
            r"(?:\bremote\s*:|^include\s*:|^\s*-)\s*[\"']?(https?://[^\s\"']+)", line
        )
        component = re.search(r"\bcomponent\s*:\s*[\"']?([^\s\"']+)", line)
        reference = re.search(r"\bref\s*:\s*[\"']?([^\s\"'#]+)", line)
        if remote:
            pinned = re.search(r"/[0-9a-fA-F]{40}/", remote[1])
            rows.append((number, "satisfied" if pinned else "violated"))
        elif component:
            pinned = re.search(r"@[0-9a-fA-F]{40}$", component[1])
            rows.append((number, "satisfied" if pinned else "violated"))
        elif re.search(r"\bproject\s*:", line):
            close_project()
            project = number
        elif reference and project:
            if "$" not in reference[1]:
                pinned = FULL_COMMIT.fullmatch(reference[1])
                rows.append((project, "satisfied" if pinned else "violated"))
            project = None
    close_project()
    return sorted(rows)


# The shell only expands these values; they become code when evaluated again.
GITLAB_UNTRUSTED = re.compile(
    r"\$\{?CI_(?:COMMIT_(?:MESSAGE|TITLE|DESCRIPTION|BRANCH|REF_NAME|AUTHOR)"
    r"|MERGE_REQUEST_(?:TITLE|DESCRIPTION|SOURCE_BRANCH_NAME))\b"
)
EVALUATED = re.compile(r"\beval\b|\b(?:ba|z|k|da)?sh\s+-c\b")


def gitlab_injection_observations(path, text):
    return [
        (number, "violated")
        for number, command in ci_commands(path, text)
        if EVALUATED.search(command) and GITLAB_UNTRUSTED.search(command)
    ]


REGISTRIES = {"registry.npmjs.org", "registry.yarnpkg.com"}


def lock_entries(text):
    """(resolved URL, whether integrity is present) of npm lock entries."""
    tree = document(text) or {}
    packages = tree.get("packages")
    if not isinstance(packages, dict):
        packages = tree.get("dependencies")
    return [
        (entry["resolved"], bool(entry.get("integrity")))
        for entry in (packages if isinstance(packages, dict) else {}).values()
        if isinstance(entry, dict) and isinstance(entry.get("resolved"), str)
    ]


def url_host(url):
    try:
        return urlsplit(url).hostname
    except ValueError:
        return None


def lockfile_observations(text):
    """A host beside the lock's usual registry is the shape of a lockfile injection."""
    entries = [
        (url, integrity)
        for url, integrity in lock_entries(text)
        if url.startswith(("http://", "https://"))
    ]
    hosts = Counter(host for host in map(url_host, [url for url, _ in entries]) if host)
    usual = REGISTRIES | {hosts.most_common(1)[0][0]} if hosts else REGISTRIES
    breaks = [match.start() for match in re.finditer("\n", text)]
    lines = {}  # One pass: a line lookup per entry would be quadratic in the file size.
    for match in re.finditer(r"\"resolved\"\s*:\s*\"([^\"]+)\"", text):
        lines.setdefault(match[1], bisect_right(breaks, match.start()) + 1)
    violations = {
        lines.get(url, 1)
        for url, integrity in entries
        if url.startswith("http://") or url_host(url) not in usual or not integrity
    }
    if violations:
        return [(number, "violated") for number in sorted(violations)]
    return [(1, "satisfied")] if entries else []


def toml_git_rows(lines):
    rows = []
    for index, line in enumerate(lines):
        if line.lstrip().startswith("#"):
            continue
        git = re.search(r"\bgit\s*=\s*[\"']([^\"']+)", line)
        if git:
            scope = [line]
            if re.match(r"\s*git\s*=", line):  # A table form continues on later lines.
                for following in lines[index + 1 : index + 21]:
                    if following.lstrip().startswith("["):
                        break
                    scope.append(following)
            revision = re.search(
                r"\brev\s*=\s*[\"'][0-9a-fA-F]{40}[\"']", "\n".join(scope)
            )
            safe = revision and not INSECURE_URL.search(git[1])
            rows.append((index + 1, "satisfied" if safe else "violated"))
    return rows


def pyproject_observations(lines):
    rows, section = toml_git_rows(lines), ""
    for number, line in enumerate(lines, 1):
        if line.lstrip().startswith("#"):
            continue
        if line.lstrip().startswith("["):
            section = line.strip()
        direct = re.search(r"@\s*git\+[^\"'\s,]+", line)
        if direct:
            pinned = re.search(r"@[0-9a-fA-F]{40}$", direct[0])
            rows.append((number, "satisfied" if pinned else "violated"))
        if re.match(r"\s*extra[-_]index[-_]url\s*=", line):
            rows.append((number, "violated"))
        elif section.startswith(
            ("[[tool.poetry.source", "[[tool.uv.index", "[tool.uv")
        ):
            source = re.match(r"\s*(?:url|index-url)\s*=\s*[\"']([^\"']+)", line)
            if source:
                rows.append(
                    (
                        number,
                        "violated" if INSECURE_URL.search(source[1]) else "satisfied",
                    )
                )
    return sorted(rows)


def maven_observations(lines):
    rows, inside = [], False
    for number, line in enumerate(lines, 1):
        if re.search(r"<(?:repository|pluginRepository|snapshotRepository)>", line):
            inside = True
        source = re.search(r"<url>\s*(\S+?)\s*</url>", line)
        if inside and source:
            rows.append(
                (number, "violated" if INSECURE_URL.search(source[1]) else "satisfied")
            )
        if re.search(r"</(?:repository|pluginRepository|snapshotRepository)>", line):
            inside = False
    return rows


def gradle_observations(lines):
    rows = []
    for number, line in enumerate(lines, 1):
        if re.match(r"\s*(?://|/?\*)", line):
            continue
        source = re.search(
            r"\b(?:url|uri|maven)\b[^\n]{0,200}?[\"'](https?://[^\"']+)", line
        )
        if re.search(r"\ballowInsecureProtocol\s*(?:=\s*)?true\b", line):
            rows.append((number, "violated"))
        elif source:
            rows.append(
                (number, "violated" if INSECURE_URL.search(source[1]) else "satisfied")
            )
    return rows


def manifest_source_observations(path, text):
    name, lines = Path(path).name, text.splitlines()
    if name == "pom.xml":
        return maven_observations(lines)
    if name == "pyproject.toml":
        return pyproject_observations(lines)
    if name == "Cargo.toml":
        return toml_git_rows(lines)
    return gradle_observations(lines)


def hcl_lines(text):
    """Source lines with whole-line comments blanked; line numbers stay stable."""
    return [
        "" if re.match(r"\s*(?:#|//)", line) else line for line in text.splitlines()
    ]


def hcl_blocks(lines):
    """(first index, last index) of every brace-delimited block."""
    stack, blocks = [], []
    for index, line in enumerate(lines):
        for character in re.sub(r'"(?:[^"\\]|\\.)*"', '""', line):
            if character == "{":
                stack.append(index)
            elif character == "}" and stack:
                blocks.append((stack.pop(), index))
    return blocks


def block_owners(lines):
    """The innermost block of each line, in linear time for hostile nesting."""
    owners = [None] * len(lines)
    following = list(range(len(lines) + 1))  # The next line without an owner.

    def unassigned(index):
        while following[index] != index:
            following[index] = following[following[index]]
            index = following[index]
        return index

    for block in hcl_blocks(lines):  # Inner blocks close first.
        index = unassigned(block[0])
        while index <= block[1]:
            owners[index] = block
            following[index] = index + 1
            index = unassigned(index + 1)
    return owners


def block_text(lines, block):
    return "\n".join(lines[block[0] : min(block[1] + 1, block[0] + BLOCK_LINES)])


BLOCK_LINES = 200  # A longer block is read only up to this line.
BLOCK_CHECKS = 1000  # Further blocks of one kind in a file are not assessed.
OPEN_NETWORK = re.compile(
    r"\b(?:cidr_blocks|ipv6_cidr_blocks|cidr_ipv4|cidr_ipv6|source_ranges"
    r"|source_address_prefix)\b[^\n]{0,200}\"(?:0\.0\.0\.0/0|::/0|\*|Internet)\""
)
OUTBOUND = re.compile(
    r'\btype\s*=\s*"egress"|\bdirection\s*=\s*"(?:Outbound|EGRESS)"|\baccess\s*=\s*"Deny"'
)
ADMIN_PORTS = (22, 3389)


def admin_port_exposed(body):
    if re.search(r'\b(?:ip_)?protocol\s*=\s*"(?:-1|all)"', body):
        return True
    first = re.search(r"\bfrom_port\s*=\s*(\d+)", body)
    last = re.search(r"\bto_port\s*=\s*(\d+)", body)
    ranges = [(int(first[1]), int(last[1]))] if first and last else []
    declared = re.findall(
        r'\b(?:destination_port_ranges?|ports)\s*=\s*(\[[^\]]*\]|"[^"]*")', body
    )
    for token in re.findall(r'"([^"]*)"', " ".join(declared)):
        span = re.fullmatch(r"(\d+)(?:-(\d+))?", token)
        if token == "*":
            return True
        if span:
            ranges.append((int(span[1]), int(span[2] or span[1])))
    return any(low <= port <= high for low, high in ranges for port in ADMIN_PORTS)


def terraform_ingress_observations(text):
    lines, rows = hcl_lines(text), []
    owners = block_owners(lines)
    matches = [index for index, line in enumerate(lines) if OPEN_NETWORK.search(line)]
    for index in matches[:BLOCK_CHECKS]:
        block = owners[index]
        if block is None:
            continue
        body = block_text(lines, block)
        header = lines[block[0]]
        if (
            not re.match(r"\s*egress\b", header)
            and "_egress_rule" not in header
            and not OUTBOUND.search(body)
            and admin_port_exposed(body)
        ):
            rows.append((index + 1, "violated"))
    return rows


def terraform_public_observations(text):
    rows = []
    for number, line in enumerate(hcl_lines(text), 1):
        if re.match(
            r'\s*(?:acl\s*=\s*"public-read(?:-write)?"'
            r"|(?:publicly_accessible|public_network_access_enabled)\s*=\s*true\b)",
            line,
        ):
            rows.append((number, "violated"))
        elif re.match(
            r"\s*(?:(?:publicly_accessible|public_network_access_enabled)\s*=\s*false\b"
            r"|block_public_(?:acls|policy)\s*=\s*true\b)",
            line,
        ):
            rows.append((number, "satisfied"))
    return rows


IAM_ACTION = re.compile(r'"?\bactions?"?\s*[=:]\s*\[?\s*"\*"', re.I)
IAM_RESOURCE = re.compile(r'"?\bresources?"?\s*[=:]\s*\[?\s*"\*"', re.I)
IAM_DENY = re.compile(r'"?\beffect"?\s*[=:]\s*"deny"', re.I)


def terraform_iam_observations(text):
    lines, rows = hcl_lines(text), []
    owners = block_owners(lines)
    matches = [index for index, line in enumerate(lines) if IAM_ACTION.search(line)]
    for index in matches[:BLOCK_CHECKS]:
        block = owners[index]
        if block is None:
            continue
        body = block_text(lines, block)
        if IAM_RESOURCE.search(body) and not IAM_DENY.search(body):
            rows.append((index + 1, "violated"))
    return rows


def terraform_module_observations(text):
    """Commits and exact versions are pinned; a tag or version range stays unassessed."""
    lines, rows = hcl_lines(text), []
    modules = [
        block
        for block in hcl_blocks(lines)
        if re.match(r'\s*module\s+"', lines[block[0]])
    ]
    for block in modules[:BLOCK_CHECKS]:
        body = block_text(lines, block)
        source = re.search(r'(?m)^\s*source\s*=\s*"([^"]+)"', body)
        if source is None or source[1].startswith(("./", "../")):
            continue
        number, value = block[0] + 1 + body.count("\n", 0, source.start(1)), source[1]
        if re.match(
            r"(?:git::|hg::|s3::|gcs::|https?://|git@|github\.com/|bitbucket\.org/)",
            value,
        ):
            reference = re.search(r"[?&]ref=([^&]+)", value)
            if reference and FULL_COMMIT.fullmatch(reference[1]):
                rows.append((number, "satisfied"))
            elif not reference or reference[1] in {"main", "master", "develop", "HEAD"}:
                rows.append((number, "violated"))
            continue
        version = re.search(r'(?m)^\s*version\s*=\s*"([^"]+)"', body)
        if not version:
            rows.append((number, "violated"))
        elif re.fullmatch(r"=?\s*v?\d+\.\d+\.\d+\S*", version[1]):
            rows.append((number, "satisfied"))
    return sorted(rows)


def container_user_observations(text):
    """The last USER of the final stage; earlier stages do not set the runtime user."""
    user = None
    for number, instruction in logical_lines(text, comment=r"\s*#"):
        if re.match(r"(?i)\s*FROM\b", instruction):
            user = None
        match = re.match(r"(?i)\s*USER\s+(\S+)", instruction)
        if match:
            user = (number, match[1].split(":", 1)[0])
    if user and user[1] not in {"root", "0"} and "$" not in user[1]:
        return [(user[0], "satisfied")]
    return []


def container_hardening_observations(text):
    return [
        (number, "satisfied", match[1])
        for number, line in enumerate(text.splitlines(), 1)
        for match in [
            re.match(
                r"\s*(?:-\s+)?[\"']?(runAsNonRoot|readOnlyRootFilesystem)[\"']?\s*:"
                r"\s*[\"']?true[\"']?\s*(?:#|$)",
                line,
            )
        ]
        if match
    ]


TRUSTED_PUBLISHING = "trusted publishing"
RELEASE_EVIDENCE = (
    ("SBOM", re.compile(r"\banchore/sbom-action\b|\bcyclonedx\b|\bsyft\s", re.I)),
    ("signature", re.compile(r"\bcosign\s+sign\b|\bsigstore/cosign-installer\b")),
    (
        "provenance",
        re.compile(
            r"\bactions/attest-build-provenance\b|\bslsa-framework/slsa-github-generator\b"
            r"|\bnpm\s+publish\b[^\n]{0,200}--provenance\b"
        ),
    ),
    (TRUSTED_PUBLISHING, re.compile(r"\bpypa/gh-action-pypi-publish\b")),
)


def release_observations(text):
    """Declared release steps; a declaration does not show that a release used them."""
    tokenless = re.search(r"\bid-token\s*:\s*write\b", text) and not re.search(
        r"(?m)^\s*password\s*:", text
    )
    rows = []
    for number, line in enumerate(text.splitlines(), 1):
        if re.match(r"\s*#", line):
            continue
        for label, pattern in RELEASE_EVIDENCE:
            if pattern.search(line) and (label != TRUSTED_PUBLISHING or tokenless):
                rows.append((number, "satisfied", label))
    return rows


# (provider, method, pattern, marker the file must contain for an ambiguous key)
CLOUD_LOGIN = (
    ("AWS", "oidc", r"^\s*(?:-\s+)?role-to-assume\s*:", None),
    (
        "AWS",
        "stored-key",
        r"^\s*(?:-\s+)?aws-access-key-id\s*:|\bAWS_ACCESS_KEY_ID\s*:\s*\$\{\{\s*secrets\.",
        None,
    ),
    ("Azure", "oidc", r"^\s*(?:-\s+)?tenant-id\s*:", "azure/login"),
    ("Azure", "stored-key", r"^\s*(?:-\s+)?creds\s*:", "azure/login"),
    ("GCP", "oidc", r"^\s*(?:-\s+)?workload_identity_provider\s*:", None),
    ("GCP", "stored-key", r"^\s*(?:-\s+)?credentials_json\s*:", None),
    ("GitLab CI", "oidc", r"^\s*id_tokens\s*:", None),
)


def cloud_login_rows(path, text):
    rows = []
    for provider, method, pattern, marker in CLOUD_LOGIN:
        if marker and marker not in text:
            continue
        for number, line in enumerate(text.splitlines(), 1):
            if re.search(pattern, line) and not re.match(r"\s*#", line):
                rows.append(
                    {
                        "technology": provider,
                        "method": method,
                        "file": path,
                        "line": number,
                    }
                )
    return rows


def cloud_oidc_observations(path, text):
    return [
        (row["line"], "satisfied", row["technology"])
        for row in cloud_login_rows(path, text)
        if row["method"] == "oidc"
    ]


DEPLOYMENT_PATHS = (
    ("Terraform", re.compile(r"\.tf$")),
    ("Docker Compose", re.compile(r"(?:^|/)(?:docker-)?compose[^/]*\.ya?ml$")),
    ("Helm", re.compile(r"(?:^|/)Chart\.ya?ml$")),
    ("Serverless Framework", re.compile(r"(?:^|/)serverless\.ya?ml$")),
    ("AWS CDK", re.compile(r"(?:^|/)cdk\.json$")),
    ("Pulumi", re.compile(r"(?:^|/)Pulumi\.ya?ml$")),
    ("Vercel", re.compile(r"(?:^|/)vercel\.json$")),
    ("Netlify", re.compile(r"(?:^|/)netlify\.toml$")),
    ("Fly.io", re.compile(r"(?:^|/)fly\.toml$")),
    ("Heroku", re.compile(r"(?:^|/)Procfile$")),
)
DEPLOYMENT_TEXT = (
    ("AWS", ".tf", r'\bprovider\s+"aws"|\bhashicorp/aws\b'),
    ("Azure", ".tf", r'\bprovider\s+"azurerm"|\bhashicorp/azurerm\b'),
    ("GCP", ".tf", r'\bprovider\s+"google"|\bhashicorp/google\b'),
    ("AWS", "ci", r"\baws-actions/"),
    ("Azure", "ci", r"\bazure/(?:login|webapps-deploy|k8s-deploy)\b"),
    ("GCP", "ci", r"\bgoogle-github-actions/"),
    ("Kubernetes", "ci", r"\bkubectl\s+apply\b|\bhelm\s+(?:upgrade|install)\b"),
    ("AWS", ".yaml", r"(?m)^AWSTemplateFormatVersion\s*:|^Transform\s*:\s*\S*AWS::"),
    (
        "Kubernetes",
        ".yaml",
        r"(?m)^kind\s*:\s*(?:Deployment|StatefulSet|DaemonSet)\s*$",
    ),
)


def deployment_rows(files, paths):
    """Declared targets as context; whether anything is deployed there stays open."""
    found = {}
    for path in sorted({*paths, *files}):
        for technology, pattern in DEPLOYMENT_PATHS:
            if pattern.search(path):
                found.setdefault(technology, path)
    for path, source in sorted(files.items()):
        suffix = Path(path).suffix.lower().replace(".yml", ".yaml")
        for technology, scope, pattern in DEPLOYMENT_TEXT:
            if (scope == "ci" and ci_file(path)) or (
                scope == suffix and not ci_file(path)
            ):
                if re.search(pattern, source["text"]):
                    found.setdefault(technology, path)
    return [
        {"technology": technology, "file": path}
        for technology, path in sorted(found.items())
    ]
