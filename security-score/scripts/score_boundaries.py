"""Bounded Express-to-database flows from already selected source files.

Recognize typed Express request parameters, SQL
interpolation/concatenation, and explicit Sequelize/pg parameter binding. Follow
one relative database export and one unchanged local request-value alias. No
project imports, calls, extra file reads, or claims about whole-program flows.
"""

from pathlib import PurePosixPath
import re


NAME = r"[A-Za-z_$][\w$]{0,127}"
SQL_MODULES = {"sequelize": {"Sequelize"}, "pg": {"Pool", "Client"}}
RULE = "DESIGN-DATA-BOUNDARY"


def pairs(code):
    result, stack = {}, []
    for index, char in enumerate(code):
        if char in "([{":
            stack.append((char, index))
        elif char in ")]}":
            if not stack or stack[-1][0] != {")": "(", "]": "[", "}": "{"}[char]:
                return None
            _, opening = stack.pop()
            result[opening] = index
    return None if stack else result


def unchanged(name, code):
    """Reject rebinding, shadow declarations and mutation of recognized bindings."""
    escaped = re.escape(name)
    return not re.search(
        rf"\b(?:let|var|function|class)\s+{escaped}\b|\b{escaped}\s*(?:=(?!=)|\+=|\+\+|--)",
        code,
    )


class Sources:
    def __init__(self, files, budget):
        self.files, self.budget, self.cache = files, budget, {}
        self.database_cache = {}

    def read(self, path):
        if path not in self.cache:
            self.budget.check()
            source = self.files.get(path, {})
            text = source.get("text", "")
            if source.get("fragment") or source.get("fragments"):
                self.cache[path] = None
            else:
                from score_core import javascript_code

                try:
                    code = javascript_code(text)
                    brackets = pairs(code)
                    self.cache[path] = (text, code, brackets) if brackets is not None else None
                except SyntaxError:
                    self.cache[path] = None
        return self.cache[path]

    def relative(self, path, module):
        if not module.startswith(".") or "\\" in module:
            return None
        parts = list(PurePosixPath(path).parent.parts)
        for part in module.split("/"):
            if part == "..":
                if not parts:
                    return None
                parts.pop()
            elif part not in {"", "."}:
                parts.append(part)
        root = "/".join(parts)
        candidates = [root] if PurePosixPath(root).suffix else [
            root + suffix for suffix in (".ts", ".js", ".mjs", ".cjs", "/index.ts", "/index.js")
        ]
        available = [candidate for candidate in candidates if candidate in self.files]
        return available[0] if len(available) == 1 else None

    def databases(self, path, *, exports=False):
        from score_architecture import js_imports

        if exports and path in self.database_cache:
            return self.database_cache[path]
        source = self.read(path)
        if source is None:
            return {}
        text, code, brackets = source
        constructors, result = set(), {}
        imports = list(js_imports(text, code))
        for binding, module, member in imports:
            if len(binding) <= 128 and module in SQL_MODULES and member in SQL_MODULES[module]:
                constructors.add(binding)
        factories, typed = set(), []
        scopes = functions(code, brackets)
        constructors = {
            name for name in constructors if unchanged(name, code)
            and not any(re.search(rf"(?:^|,)\s*{re.escape(name)}\s*(?:[:,)]|$)", code[a + 1:b]) for a, b, _, _ in scopes)
            and not re.search(rf"\bconst\s+{re.escape(name)}\b", code)
        }
        constructor_pattern = "|".join(re.escape(name) for name in sorted(constructors))
        for opening, closing, body, end in scopes:
            for parameter in code[opening + 1:closing].split(","):
                matched = re.fullmatch(rf"\s*({NAME})\s*:\s*({NAME})\s*", parameter)
                if matched and matched[2] in constructors and unchanged(matched[1], code[body + 1:end]):
                    typed.append((matched[1], body, end))
            declaration = re.search(rf"\bfunction\s+({NAME})\s*$", code[max(0, opening - 150):opening])
            if declaration and constructor_pattern:
                section = code[body + 1:end]
                if len(re.findall(r"\breturn\b", section)) == 1 and re.search(rf"\breturn\s+new\s+(?:{constructor_pattern})\s*\(", section):
                    factories.add(declaration[1])
        if constructor_pattern:
            initializer = rf"(?:new\s+(?:{constructor_pattern})|{'|'.join(re.escape(name) for name in sorted(factories)) or '(?!)'})\s*\("
            for match in re.finditer(rf"\b(export\s+)?(?:const|let)\s+({NAME})\s*=\s*({initializer})", code):
                self.budget.check()
                name = match[2]
                exported = bool(match[1]) or any(
                    re.search(rf"(?:^|,)\s*{re.escape(name)}\s*(?:,|$)", found[1])
                    for found in re.finditer(r"\bexport\s*\{([^{}]{1,1000})\}", code)
                )
                if exports and not exported:
                    continue
                assignments = list(re.finditer(rf"\b{re.escape(name)}\s*=(?!=)\s*", code))
                valid = True
                for assignment in assignments:
                    self.budget.check()
                    rhs = code[assignment.end():assignment.end() + 200]
                    supported = bool(re.match(initializer, rhs)) or any(
                        start < assignment.start() < end and re.match(rf"{re.escape(parameter)}\s*(?:[;}}]|\n|$)", rhs)
                        for parameter, start, end in typed
                    )
                    valid &= supported
                if valid and len(re.findall(rf"\b(?:const|let|var)\s+{re.escape(name)}\b", code)) == 1:
                    result[name] = {"file": path, "line": text.count("\n", 0, match.start()) + 1}
        if exports:
            self.database_cache[path] = result
            return result
        for binding, module, member in imports:
            self.budget.check()
            if len(binding) > 128:
                continue
            target = self.relative(path, module)
            if target is None or not unchanged(binding, code):
                continue
            if re.search(rf"\bconst\s+{re.escape(binding)}\b", code):
                continue
            for name, evidence in self.databases(target, exports=True).items():
                if member == "*":
                    result[binding + "." + name] = evidence
                elif member == name:
                    result[binding] = evidence
        return result


def request_types(text, code):
    names = set()
    for match in re.finditer(r"\bimport\s+(?:type\s+)?\{([^{}]{1,1000})\}\s+from\s*['\"]express['\"]", text):
        if code[match.start()].isspace():
            continue
        for member in match[1].split(","):
            parsed = re.fullmatch(rf"\s*(?:type\s+)?Request(?:\s+as\s+({NAME}))?\s*", member)
            if parsed:
                names.add(parsed[1] or "Request")
    return names


def functions(code, brackets):
    """Block-bodied functions only; nested scopes are kept separate."""
    result = []
    for opening, closing in brackets.items():
        if code[opening] != "(":
            continue
        after = re.match(r"\s*(=>)?\s*\{", code[closing + 1:closing + 100])
        if after is None:
            continue
        before = re.search(rf"({NAME})\s*$", code[max(0, opening - 100):opening])
        if not after[1] and before and before[1] in {"if", "while", "for", "switch", "catch", "with"}:
            continue
        body = closing + 1 + after.end() - 1
        end = brackets.get(body)
        if end is not None:
            result.append((opening, closing, body, end))
    return result


def direct_value(expression, request, aliases):
    value = rf"{re.escape(request)}\s*\.\s*(?:body|query|params)\s*(?:\.\s*{NAME}|\[\s*\])"
    # Literal defaults have been masked. Function calls and transformations are
    # intentionally excluded: they may implement an effective protection.
    if re.fullmatch(rf"\s*\(*\s*{value}\s*\)*\s*(?:(?:\|\||\?\?)\s*)?", expression):
        return True
    alias = re.fullmatch(rf"\s*\(*\s*({NAME})\s*\)*\s*", expression)
    return bool(alias and alias[1] in aliases)


def expression_functions(code, brackets):
    """Ranges of expression arrows and single-parameter callbacks, not sources."""
    ranges = []
    single = list(re.finditer(rf"\b{NAME}\s*=>\s*", code))
    enclosing, stack = {}, []
    for position in sorted(set(brackets) | {match.start() for match in single}):
        while stack and stack[-1] <= position:
            stack.pop()
        enclosing[position] = stack[-1] if stack else len(code)
        if position in brackets:
            stack.append(brackets[position])
    for opening, closing in brackets.items():
        if code[opening] != "(":
            continue
        arrow = re.match(r"\s*=>\s*", code[closing + 1:closing + 100])
        if arrow:
            start = closing + 1 + arrow.end()
            if start < len(code) and code[start] != "{":
                end = enclosing[opening]
                ranges.append((start, end))
    for match in single:
        start = match.end()
        end = brackets.get(start) if start < len(code) and code[start] == "{" else None
        if end is None:
            end = enclosing[match.start()]
        ranges.append((start, end))
    return ranges


def inspect(files, budget):
    from score_architecture import js_arguments
    from score_core import JS_EXTENSIONS

    sources, observations = Sources(files, budget), []
    for path in sorted(files):
        if PurePosixPath(path).suffix not in JS_EXTENSIONS:
            continue
        budget.check()
        source = sources.read(path)
        if source is None:
            continue
        text, code, brackets = source
        types = request_types(text, code)
        databases = sources.databases(path) if types else {}
        if not databases:
            continue
        scopes = functions(code, brackets)
        expressions = expression_functions(code, brackets)
        for opening, closing, body, end in scopes:
            budget.check()
            parameter = re.match(rf"\s*({NAME})\s*:\s*({NAME})\b", code[opening + 1:closing])
            if parameter is None or parameter[2] not in types:
                continue
            request = parameter[1]
            section = code[body + 1:end]
            if not unchanged(request, section) or re.search(rf"\bconst\s+{re.escape(request)}\b", section):
                continue
            aliases = set()
            for match in re.finditer(rf"\bconst\s+({NAME})(?:\s*:\s*{NAME})?\s*=([^;\n]{{1,1000}})", section):
                budget.check()
                if direct_value(match[2], request, ()) and unchanged(match[1], section[match.end():]):
                    aliases.add(match[1])
            for database, declaration in databases.items():
                # Do not infer a sink if an inner scope shadows its receiver.
                root = database.split(".")[0]
                if re.search(rf"(?:^|,)\s*{re.escape(root)}\b", code[opening + 1:closing]):
                    continue
                for call in re.finditer(rf"(?<![\w$.]){re.escape(database)}\s*\.\s*query\s*\(", section):
                    budget.check()
                    position = body + 1 + call.start()
                    if any(nbody > body and nbody < position < nend for _, _, nbody, nend in scopes):
                        continue
                    if any(body < start <= position < end for start, end in expressions):
                        continue
                    args = js_arguments(code, body + 1 + call.end() - 1, brackets)
                    if not args:
                        continue
                    start, stop = args[0]
                    active, raw = code[start:stop], text[start:stop]
                    local_aliases = {name for name in aliases if re.search(rf"\bconst\s+{re.escape(name)}\b", code[body + 1:start])}
                    request_pattern = rf"\b{re.escape(request)}\s*\.\s*(?:body|query|params)\b"
                    uses_request = bool(re.search(request_pattern, active)) or any(
                        re.search(rf"\b{re.escape(alias)}\b", active) for alias in local_aliases
                    )
                    if not re.search(r"\b(?:SELECT|INSERT|UPDATE|DELETE|WITH)\b", raw, re.I) and not uses_request:
                        continue
                    direct = False
                    if raw.strip().startswith("`") and raw.strip().endswith("`"):
                        for interpolation in re.finditer(r"\$\{([^{}]{1,1000})\}", raw):
                            a, b = interpolation.span(1)
                            direct |= direct_value(active[a:b], request, local_aliases)
                    if "+" in active:
                        terms = active.split("+")
                        direct |= all(not term.strip() or direct_value(term, request, local_aliases) for term in terms) and any(direct_value(term, request, local_aliases) for term in terms)
                    status, reason = None, None
                    if direct:
                        status, reason = "violated", "HTTP request data is embedded in SQL text across the data-access boundary."
                        before = code[body + 1:position]
                        guards = [match for match in re.finditer(r"\bif\s*\(", before)]
                        guarded = any(
                            (finish := brackets.get(body + 1 + guard.end() - 1)) is not None
                            and (
                                re.search(request_pattern, code[body + 1 + guard.end():finish])
                                or any(re.search(rf"\b{re.escape(alias)}\b", code[body + 1 + guard.end():finish]) for alias in local_aliases)
                            )
                            for guard in guards
                        )
                        rewritten = re.search(request_pattern + rf"\s*\.\s*{NAME}\s*=(?!=)", before)
                        if guarded or rewritten:
                            status, reason = "unclear", "A preceding request validation or transformation needs review."
                    elif uses_request:
                        status, reason = "unclear", "A request-to-database transformation needs review."
                    elif not active.strip() and len(args) >= 2:
                        a, b = args[1]
                        binding = code[a:b].strip()
                        if (binding.startswith("[") or re.match(r"\{\s*(?:bind|replacements)\s*:", binding)) and re.search(request_pattern, binding):
                            status, reason = "satisfied", "HTTP request values are passed separately from literal SQL text."
                    if status:
                        observations.append({
                            "rule": RULE, "criterion": "query-binding", "status": status,
                            "file": path, "line": text.count("\n", 0, position) + 1,
                            "severity": "high", "area": "architecture", "certainty": "source-flow",
                            "reason": reason, "source": {"file": path, "line": text.count("\n", 0, opening) + 1},
                            "database_declaration": declaration,
                        })
    return observations
