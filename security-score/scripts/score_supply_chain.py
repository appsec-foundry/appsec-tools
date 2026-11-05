"""Evidence about Python/Node dependency workflows, never package execution."""

import json
import base64
import binascii
from pathlib import PurePosixPath
import re
import shlex

from score_design import pairs
from score_infrastructure import ci_file, ci_commands, logical_lines, NPM_LOCK, PYTHON_LOCK
from score_reporting import container_build_file, origin


def inspect(files, paths, budget):
    profiles = []
    commands = []
    for path, source in sorted(files.items()):
        budget.check()
        if ci_file(path):
            selected = ci_commands(path, source["text"])
        elif container_build_file(PurePosixPath(path).name):
            selected = ((n, re.sub(r"(?i)^\s*RUN\s+", "", line)) for n, line in logical_lines(source["text"], comment=r"\s*#") if re.match(r"(?i)^\s*RUN\s+", line))
        else:
            continue
        # This bounded reader cannot resolve conditional jobs or alternate working
        # directories. Keep the command out of positive evidence in those cases.
        context = source["text"]
        if re.search(r"(?m)^\s*(?:-\s*)?(?:if|rules|only|except|working-directory)\s*:|\bcd\s+|(?im:^\s*WORKDIR\s+)", context):
            continue
        for number, line in selected:
            line = line.strip()
            if line.startswith("- "):
                line = line[2:].strip()
            if len(line) >= 2 and line[0] in {"'", '"'} and line[-1] == line[0]:
                line = line[1:-1]
            if re.match(r"(?:npm|pnpm|yarn|pip|pip3|uv|python(?:3)?\s+-m\s+pip)\s", line):
                commands.append((path, number, line))
    manifests = []
    for path, source in sorted(files.items()):
        if PurePosixPath(path).name != "package.json" or origin(path) not in {"source", "build"}:
            continue
        try:
            document = json.loads(source["text"], object_pairs_hook=pairs)
        except (ValueError, RecursionError):
            continue
        if isinstance(document, dict) and any(document.get(k) for k in ("dependencies", "devDependencies", "optionalDependencies")):
            manifests.append((path, document))
    if manifests:
        locks = [path for path in paths if NPM_LOCK.fullmatch(PurePosixPath(path).name)]
        consistency, locations, integrity, resolved_manifests, lock_roots = [], [], [], [], set()
        for path, manifest in manifests:
            budget.check()
            parent = PurePosixPath(path).parent
            selected = None
            for directory in (parent, *parent.parents):
                matches = [str(directory / name) for name in ("package-lock.json", "npm-shrinkwrap.json") if str(directory / name) in files]
                if matches:
                    selected = matches[0] if len(matches) == 1 else None
                    break
            if selected is None:
                consistency.append(None)
                continue
            lock_roots.add(str(PurePosixPath(selected).parent))
            try:
                lock = json.loads(files[selected]["text"], object_pairs_hook=pairs)
            except (ValueError, RecursionError):
                consistency.append(None)
                continue
            relative = str(parent.relative_to(PurePosixPath(selected).parent))
            relative = "" if relative == "." else relative
            packages = lock.get("packages") if isinstance(lock, dict) else None
            root = packages.get(relative) if isinstance(packages, dict) else None
            if not isinstance(root, dict):
                consistency.append(None)
                continue
            fields = ("dependencies", "devDependencies", "optionalDependencies")
            valid = all(isinstance(owner.get(key, {}), dict) and all(isinstance(v, str) for v in owner.get(key, {}).values()) for owner in (manifest, root) for key in fields)
            matches = all(manifest.get(k, {}) == root.get(k, {}) for k in fields) if valid else None
            consistency.append(matches)
            locations.append({"file": path, "line": 1, "related_file": selected, "matches": matches})
            direct = {key: value for field in fields for key, value in manifest.get(field, {}).items()} if valid else {}
            resolved = bool(matches and direct)
            for dependency, constraint in direct.items():
                entry = packages.get((relative + "/" if relative else "") + "node_modules/" + dependency) or packages.get("node_modules/" + dependency)
                compatible = version_matches(constraint, entry.get("version")) if isinstance(entry, dict) else None
                if compatible is False:
                    consistency[-1] = False
                    locations[-1]["matches"] = False
                resolved = resolved and bool(
                    compatible is True
                    and isinstance(entry, dict) and isinstance(entry.get("resolved"), str)
                    and entry["resolved"].startswith(("http://", "https://"))
                    and valid_integrity(entry.get("integrity"))
                )
            if resolved:
                resolved_manifests.append(path)
            for entry in packages.values():
                if isinstance(entry, dict) and isinstance(entry.get("resolved"), str) and entry["resolved"].startswith(("http://", "https://")):
                    integrity.append(valid_integrity(entry.get("integrity")))
        frozen = [(p, n) for p, n, line in commands if install_kind(line) == "node"
                  and direct_command(line)[:2] == ["npm", "ci"] and install_directory(line) in lock_roots]
        installed_roots = {install_directory(line) for _, _, line in commands if install_kind(line) == "node" and direct_command(line)[:2] == ["npm", "ci"]}
        if not lock_roots or not lock_roots <= installed_roots:
            frozen = []
        controls = [
            control("node-lockfiles", "observed" if locks else "not_assessed", "Lockfile presence; contents and build enforcement are separate checks.", [{"file": p, "line": 1} for p in locks]),
            control("node-lock-consistency", state(consistency), "Manifest constraints match the npm lockfile workspace entry; supported version ranges also agree with resolved versions." if state(consistency) == "supported" else "Manifest/lock consistency differs or cannot be established for every selected manifest.", locations),
            control("node-locked-install", "supported" if frozen else "not_assessed", "A locked Node install command is declared in CI or a container build.", [{"file": p, "line": n} for p, n in frozen]),
            control("node-artifact-integrity", "supported" if integrity and all(integrity) else "not_assessed", "Registry entries in the inspected npm lockfiles carry well-formed SHA integrity digests.", locations if integrity and all(integrity) else []),
            control("node-lifecycle-scripts", "observed" if any(isinstance(m.get("scripts"), dict) and any(k in m["scripts"] for k in ("preinstall", "install", "postinstall", "prepare")) for _, m in manifests) else "not_assessed", "Install lifecycle scripts are declared; their behavior and installer permissions need separate assessment.", [{"file": p, "line": 1} for p, m in manifests if isinstance(m.get("scripts"), dict) and any(k in m["scripts"] for k in ("preinstall", "install", "postinstall", "prepare"))]),
        ]
        profiles.append({"ecosystem": "Node.js", "controls": controls, "resolved_registry_manifests": resolved_manifests})
    requirements = []
    for path, source in sorted(files.items()):
        name = PurePosixPath(path).name
        if name.startswith("requirements") and name.endswith(".txt") and origin(path) in {"source", "build"}:
            for number, line in logical_lines(source["text"]):
                budget.check()
                value = re.split(r"\s+#", line, maxsplit=1)[0].strip()
                if not value or value.startswith("#"):
                    continue
                if value.startswith(("--index-url", "--extra-index-url", "--trusted-host")):
                    continue
                pinned = bool(re.match(r"[A-Za-z0-9_.-]+(?:\[[\w,.-]+\])?\s*==\s*[A-Za-z0-9][A-Za-z0-9.+!-]*(?:\s|;|$)", value))
                digest = bool(re.search(r"--hash(?:=|\s+)sha256:[0-9a-fA-F]{64}(?:\s|$)|--hash(?:=|\s+)sha512:[0-9a-fA-F]{128}(?:\s|$)", value))
                requirements.append((path, number, None if value.startswith("-") else pinned, digest))
    python_locks = [path for path in paths if PYTHON_LOCK.fullmatch(PurePosixPath(path).name) or PurePosixPath(path).name == "Pipfile.lock"]
    python_present = requirements or python_locks or any(PurePosixPath(path).name in {"pyproject.toml", "Pipfile"} for path in paths)
    if python_present:
        selected_requirements = {p for p, _, _, _ in requirements}
        installed_requirements = set()
        enforced = []
        for p, n, line in commands:
            if install_kind(line) != "python":
                continue
            targets = requirement_targets(line)
            if targets and targets <= selected_requirements:
                enforced.append((p, n))
                installed_requirements.update(targets)
            elif not selected_requirements and direct_command(line)[:2] == ["uv", "sync"] and "uv.lock" in python_locks:
                enforced.append((p, n))
        if selected_requirements and not selected_requirements <= installed_requirements:
            enforced = []
        locations = [{"file": p, "line": n} for p, n, _, _ in requirements]
        pins = state([pinned for _, _, pinned, _ in requirements])
        # Missing hashes are an evidence gap, not proof that external integrity controls are absent.
        hashes = "supported" if requirements and all(pinned is True and digest for _, _, pinned, digest in requirements) else "not_assessed"
        profiles.append({"ecosystem": "Python", "controls": [
            control("python-lockfiles", "observed" if python_locks else "not_assessed", "Lockfile presence; locked resolution is not inferred from the filename.", [{"file": p, "line": 1} for p in python_locks]),
            control("python-version-pins", pins, "Exact versions in the selected requirements; includes and dynamic inputs remain unresolved.", locations),
            control("python-artifact-hashes", hashes, "Each assessed pinned requirement carries a SHA-256 or SHA-512 artifact hash.", locations if hashes == "supported" else []),
            control("python-locked-install", "supported" if enforced else "not_assessed", "CI or container builds declare hash-enforced pip installation or a locked uv operation.", [{"file": p, "line": n} for p, n in enforced]),
        ]})
    return profiles


def state(values):
    return "weakness" if any(value is False for value in values) else "supported" if values and all(value is True for value in values) else "not_assessed"


def control(identity, status, reason, locations):
    return {"criterion": identity, "status": status, "reason": reason, "locations": locations}


def valid_integrity(value):
    if not isinstance(value, str):
        return False
    for digest in value.split():
        algorithm, separator, encoded = digest.partition("-")
        if not separator or algorithm not in {"sha256", "sha384", "sha512"}:
            continue
        try:
            decoded = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error):
            continue
        if len(decoded) == {"sha256": 32, "sha384": 48, "sha512": 64}[algorithm]:
            return True
    return False


def version_matches(constraint, version):
    """Only stable exact/caret/tilde ranges; other npm expressions stay unresolved."""
    if not isinstance(constraint, str) or not isinstance(version, str):
        return None
    wanted = re.fullmatch(r"([~^]?)(\d+)\.(\d+)\.(\d+)", constraint)
    actual = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", version)
    if not wanted or not actual:
        return None
    lower = tuple(int(v) for v in wanted.groups()[1:])
    value = tuple(int(v) for v in actual.groups())
    if wanted[1] == "":
        return value == lower
    major, minor, patch = lower
    upper = (major, minor + 1, 0) if wanted[1] == "~" else (
        (major + 1, 0, 0) if major else (0, minor + 1, 0) if minor else (0, 0, patch + 1)
    )
    return lower <= value < upper


def install_kind(line):
    """Recognize the first direct command, never text inside echo/help arguments."""
    command = direct_command(line)
    if not command:
        return None
    if any(word.split("=", 1)[0] in {"--help", "--version", "--dry-run", "-h"} for word in command):
        return None
    if any(word in {"--no-frozen-lockfile", "--no-immutable", "--frozen-lockfile=false", "--immutable=false", "--require-hashes=false"} for word in command):
        return None
    if command[:2] == ["npm", "ci"]:
        return "node"
    if command[:2] in (["pnpm", "install"], ["yarn", "install"]) and any(word in {"--frozen-lockfile", "--immutable"} for word in command[2:]):
        return "node"
    if command[:3] in (["python", "-m", "pip"], ["python3", "-m", "pip"]):
        command = command[2:]
    if command[:2] in (["pip", "install"], ["pip3", "install"]) and "--require-hashes" in command[2:]:
        return "python"
    if command[:3] == ["uv", "pip", "sync"] and "--require-hashes" in command[3:]:
        return "python"
    if command[:2] == ["uv", "sync"] and any(word in {"--locked", "--frozen"} for word in command[2:]):
        return "python"
    return None


def direct_command(line):
    try:
        lexer = shlex.shlex(line, posix=True, punctuation_chars=";&|<>()")
        lexer.whitespace_split = True
        words = list(lexer)
    except ValueError:
        return []
    command = []
    for word in words:
        if word and all(char in ";&|<>()" for char in word):
            break
        command.append(word)
    return command


def relative_path(value):
    if not isinstance(value, str) or re.search(r"[^A-Za-z0-9_./-]", value):
        return None
    path = PurePosixPath(value)
    return str(path) if not path.is_absolute() and ".." not in path.parts else None


def install_directory(line):
    command = direct_command(line)
    directories = []
    for index, value in enumerate(command):
        if value in {"--prefix", "--cwd", "--directory", "-C"}:
            directories.append(relative_path(command[index + 1]) if index + 1 < len(command) else None)
        elif value.startswith(("--prefix=", "--cwd=", "--directory=")):
            directories.append(relative_path(value.split("=", 1)[1]))
    return "." if not directories else directories[0] if len(directories) == 1 else None


def requirement_targets(line):
    command = direct_command(line)
    targets = set()
    for index, value in enumerate(command):
        target = None
        if value in {"-r", "--requirement"}:
            target = command[index + 1] if index + 1 < len(command) else None
        elif value.startswith("--requirement="):
            target = value.split("=", 1)[1]
        elif value.startswith("-r"):
            target = value[2:]
        if target is not None:
            target = relative_path(target)
            if target is None:
                return set()
            targets.add(target)
    return targets
