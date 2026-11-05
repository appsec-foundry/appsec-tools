"""Bounded, data-only Compose declaration profiles; no merge or execution.

Supports block mappings/sequences, scalar flow lists and JSON flow values.
Other YAML constructs remain unresolved. Only selected fields leave this module;
commands, environment, labels, build arguments and secret values are never copied.
"""

from dataclasses import dataclass, field
import ipaddress
import json
import re

from score_design import pairs as unique_pairs


COMPOSE_PATH = re.compile(r"(?:^|/)(?:docker-)?compose[^/]*\.ya?ml$")
MAX_LINES = 20000
MAX_SERVICES = 100
MAX_ITEMS = 100
UNKNOWN = "unresolved"


@dataclass
class Node:
    value: object = None
    line: int = 1
    children: list = field(default_factory=list)
    indent: int = -1


class Unsupported(ValueError):
    pass


def uncomment(line):
    quote, escaped = None, False
    for index, char in enumerate(line):
        if escaped:
            escaped = False
        elif char == "\\" and quote == '"':
            escaped = True
        elif quote:
            if char == quote:
                quote = None
        elif char in "\"'":
            quote = char
        elif char == "#" and (index == 0 or line[index - 1].isspace()):
            return line[:index].rstrip()
    return line.rstrip()


def scalar(raw):
    if not raw:
        return None
    if raw.startswith(('!', '&', '*', '|', '>')) or '$' in raw:
        return UNKNOWN
    if raw[0] == '"':
        try:
            return json.loads(raw, object_pairs_hook=unique_pairs)
        except (ValueError, RecursionError):
            return UNKNOWN
    if raw[0] == "'":
        return raw[1:-1].replace("''", "'") if raw.endswith("'") else UNKNOWN
    if raw in {"true", "false"}:
        return raw == "true"
    if raw in {"null", "~"}:
        return None
    if raw[0] in "[{":
        try:
            return json.loads(raw, object_pairs_hook=unique_pairs)
        except (ValueError, RecursionError):
            if raw.startswith('[') and raw.endswith(']'):
                items = raw[1:-1].split(',') if raw[1:-1].strip() else []
                if all(re.fullmatch(r"\s*[A-Za-z0-9_.:/-]+\s*", item) for item in items):
                    return [item.strip() for item in items]
            return UNKNOWN
    return raw


def parse(text, budget):
    """Retain a bounded indentation tree without constructing YAML objects."""
    if text.count('\n') >= MAX_LINES:
        raise Unsupported("file exceeds Compose profile line limit")
    root, stack, block = Node(), [(-1, Node())], None
    stack[0] = (-1, root)
    for number, raw in enumerate(text.splitlines(), 1):
        budget.check()
        indent = len(raw) - len(raw.lstrip(' '))
        if block is not None and (not raw.strip() or indent > block):
            continue
        block = None
        if '\t' in raw[:len(raw) - len(raw.lstrip())]:
            raise Unsupported("tab indentation is unsupported")
        value = uncomment(raw).strip()
        if not value:
            continue
        if value in {'---', '...'}:
            raise Unsupported("YAML document markers are unsupported")
        while stack[-1][0] >= indent:
            stack.pop()
        if len(stack) > 32:
            raise Unsupported("Compose profile nesting limit exceeded")
        siblings = stack[-1][1].children
        if siblings and siblings[0].indent != indent:
            raise Unsupported("inconsistent YAML indentation")
        node = Node(value, number, indent=indent)
        stack[-1][1].children.append(node)
        stack.append((indent, node))
        if re.search(r":\s*[|>][+-]?\d?\s*$", value) or re.match(r"-\s*[|>]", value):
            block = indent
    return root


def pair(raw):
    match = re.match(r"(?:([A-Za-z0-9_.-]+)|\"([^\"]+)\"|'([^']+)'|(<<)):(?:\s+|$)(.*)$", raw)
    if match:
        return next(value for value in match.groups()[:4] if value is not None), match[5]
    return None


def mapping(node):
    if node.value not in {None, ''}:
        return None
    result = {}
    for child in node.children:
        parts = pair(child.value)
        if parts is None:
            return None
        key, raw = parts
        if key in result:
            result[key] = Node(UNKNOWN, child.line)
        else:
            result[key] = Node(raw, child.line, child.children)
    return result


def decode(node):
    """Decode only the selected field subtree; never evaluate references or tags."""
    if node is None:
        return None
    if node.children:
        if node.value:
            return UNKNOWN
        if all(child.value.startswith('- ') or child.value == '-' for child in node.children):
            items = []
            if len(node.children) > MAX_ITEMS:
                return UNKNOWN
            for child in node.children:
                raw = child.value[1:].strip()
                parts = pair(raw)
                if parts:
                    first = Node(raw, child.line)
                    entry = Node(children=[first, *child.children])
                    value = decode(entry)
                else:
                    value = decode(Node(raw, child.line, child.children))
                items.append(value)
            return items
        fields = mapping(node)
        return {key: decode(value) for key, value in fields.items()} if fields is not None else UNKNOWN
    return scalar(node.value or '')


def text_value(value, pattern):
    return value if isinstance(value, str) and value != UNKNOWN and re.fullmatch(pattern, value) else UNKNOWN


def boolean(value):
    return value if type(value) is bool else UNKNOWN


def port(value):
    if type(value) is int:
        value = str(value)
    if isinstance(value, str):
        match = re.fullmatch(r"(?:(\[[0-9a-fA-F:]+\]|[0-9]+\.[0-9.]+):)?(?:(\d+(?:-\d+)?):)?(\d+(?:-\d+)?)(?:/(tcp|udp))?", value)
        if not match:
            return UNKNOWN
        host, published, target, protocol = match.groups()
        value = {"host_ip": host.strip('[]') if host else None, "published": published, "target": target, "protocol": protocol or 'tcp'}
    if not isinstance(value, dict) or not value.get('target'):
        return UNKNOWN
    result = {}
    for key in ('target', 'published'):
        item = value.get(key)
        if item is not None:
            if type(item) not in (str, int) or not re.fullmatch(r"\d+(?:-\d+)?", str(item)):
                return UNKNOWN
            if any(not 1 <= int(part) <= 65535 for part in str(item).split('-')):
                return UNKNOWN
            result[key] = str(item)
    host = value.get('host_ip')
    if host is not None:
        try:
            result['host_ip'] = str(ipaddress.ip_address(host))
        except (ValueError, TypeError):
            return UNKNOWN
    result['binding'] = 'dynamic host port; bind address not declared' if 'published' not in result else 'bind address not declared'
    if host:
        result['binding'] = 'loopback' if ipaddress.ip_address(host).is_loopback else 'all interfaces' if ipaddress.ip_address(host).is_unspecified else 'specific address'
    result['protocol'] = value.get('protocol', 'tcp') if value.get('protocol', 'tcp') in ('tcp', 'udp') else UNKNOWN
    return result


def mount(value):
    if isinstance(value, str):
        match = re.fullmatch(r"(?:(.+):)?(/[^:]*?)(?::(ro|rw|[a-z,]+))?", value)
        if not match:
            return UNKNOWN
        source, target, mode = match.groups()
        value = {'source': source, 'target': target, 'read_only': 'ro' in (mode or '').split(','),
                 'type': 'volume' if not source or re.fullmatch(r'[\w.-]+', source) else 'bind'}
    if not isinstance(value, dict):
        return UNKNOWN
    result = {'type': value.get('type') if value.get('type') in ('bind', 'volume', 'tmpfs', 'npipe', 'image') else UNKNOWN}
    for key in ('source', 'target'):
        if value.get(key) is not None:
            result[key] = text_value(value[key], r"[A-Za-z0-9_./~ -]+")
    result['read_only'] = boolean(value['read_only']) if 'read_only' in value else 'not declared'
    result['docker_socket'] = any(value.get(key) in ('/var/run/docker.sock', '/run/docker.sock') for key in ('source', 'target'))
    if not result['docker_socket'] and (UNKNOWN in (result.get('source'), result.get('target')) or 'target' not in result or result['type'] == 'bind' and 'source' not in result):
        result['docker_socket'] = UNKNOWN
    return result


def selected(key, value):
    if key in {'privileged', 'read_only', 'init', 'use_api_socket'}:
        return boolean(value)
    if key in {'ports', 'volumes'}:
        return [(port if key == 'ports' else mount)(item) for item in value[:MAX_ITEMS]] if isinstance(value, list) and len(value) <= MAX_ITEMS else UNKNOWN
    if key in {'cap_add', 'cap_drop'}:
        return [text_value(item, r'(?:CAP_)?[A-Z][A-Z0-9_]*') for item in value] if isinstance(value, list) and len(value) <= MAX_ITEMS else UNKNOWN
    if key == 'security_opt':
        if not isinstance(value, list) or len(value) > MAX_ITEMS:
            return UNKNOWN
        return [item if isinstance(item, str) and re.fullmatch(r'no-new-privileges(?::true|=true)?|(?:seccomp|apparmor)[:=]unconfined', item) else UNKNOWN for item in value]
    if key == 'image':
        ref = text_value(value, r'[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]+)?(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?(?:@sha256:[a-fA-F0-9]{64})?')
        return {'reference': ref, 'immutable_digest': '@sha256:' in ref} if ref != UNKNOWN else UNKNOWN
    if key == 'user':
        return text_value(value, r'[a-zA-Z0-9_.-]+(?::[a-zA-Z0-9_.-]+)?')
    if key in {'network_mode', 'pid', 'ipc'}:
        return text_value(value, r'[a-zA-Z0-9_.:-]+')
    if key == 'restart':
        return value if isinstance(value, str) and re.fullmatch(r'no|always|unless-stopped|on-failure(?::\d+)?', value) else UNKNOWN
    if key in {'cpus', 'mem_limit', 'pids_limit'}:
        return str(value) if type(value) in (str, int, float) and re.fullmatch(r'-?\d+(?:\.\d+)?(?:[bkmgBKMG](?:[bB])?)?', str(value)) else UNKNOWN
    if key == 'healthcheck':
        if not isinstance(value, dict):
            return UNKNOWN
        if value.get('disable') is True or value.get('test') == ['NONE']:
            return 'disabled'
        if 'disable' in value and type(value['disable']) is not bool:
            return UNKNOWN
        test = value.get('test')
        return 'declared; command omitted' if isinstance(test, (str, list)) and test and test != UNKNOWN else UNKNOWN
    if key == 'deploy':
        if not isinstance(value, dict):
            return UNKNOWN
        resources = value.get('resources', {})
        limits = resources.get('limits', {}) if isinstance(resources, dict) else UNKNOWN
        result = {}
        if isinstance(limits, dict):
            for name, mapped in (('cpus', 'cpus'), ('memory', 'mem_limit'), ('pids', 'pids_limit')):
                if name in limits:
                    result[name] = selected(mapped, limits[name])
        else:
            result['limits'] = UNKNOWN
        if 'restart_policy' in value:
            policy = value['restart_policy']
            condition = policy.get('condition') if isinstance(policy, dict) else None
            result['restart_condition'] = condition if condition in ('none', 'on-failure', 'any') else UNKNOWN
        return result or 'no supported limits or restart condition declared'
    if key == 'networks':
        names = list(value) if isinstance(value, (list, dict)) else None
        return [text_value(name, r'[\w.-]+') for name in names] if names is not None and len(names) <= MAX_ITEMS else UNKNOWN
    return UNKNOWN


FIELDS = ('image', 'ports', 'networks', 'network_mode', 'pid', 'ipc', 'user', 'privileged',
          'cap_add', 'cap_drop', 'security_opt', 'read_only', 'volumes', 'use_api_socket',
          'cpus', 'mem_limit', 'pids_limit', 'healthcheck', 'restart', 'init', 'deploy')


def inspect(files, budget, paths=()):
    result = {'services': [], 'gaps': [], 'files': []}
    selected_paths = sorted(path for path in set(files) | set(paths) if COMPOSE_PATH.search(path))
    for path in selected_paths:
        budget.check()
        result['files'].append(path)
        def gap(reason, line=1):
            result['gaps'].append({'file': path, 'line': line, 'reason': reason})
        if path not in files or files[path].get('fragment') or not files[path].get('complete', True):
            gap('Compose source unavailable or incomplete')
            continue
        try:
            root = mapping(parse(files[path]['text'], budget))
        except Unsupported as error:
            gap(str(error))
            continue
        if root is None:
            gap('unsupported or ambiguous top-level YAML mapping')
            continue
        if 'include' in root:
            gap('Compose includes are not resolved', root['include'].line)
        services = mapping(root['services']) if 'services' in root else None
        if services is None:
            gap('services mapping is missing, duplicated or unsupported')
            continue
        for index, (name, node) in enumerate(services.items()):
            budget.check()
            if index >= MAX_SERVICES:
                gap('Compose service limit exceeded; further services omitted')
                break
            if not re.fullmatch(r'[a-zA-Z0-9_.-]+', name):
                gap('unsupported service name', node.line)
                continue
            fields = mapping(node)
            row = {'file': path, 'line': node.line, 'service': name, 'evidence': 'declared', 'properties': {}, 'unresolved': []}
            if fields is None:
                row['unresolved'].append('service mapping, alias or anchor is unsupported')
            else:
                for key in FIELDS:
                    if key in fields:
                        row['properties'][key] = {'line': fields[key].line, 'value': selected(key, decode(fields[key]))}
                if '<<' in fields or 'extends' in fields:
                    row['unresolved'].append('YAML merge or service inheritance is not resolved')
                if any(value.value and str(value.value).startswith('&') for value in fields.values()):
                    row['unresolved'].append('YAML anchors are not resolved')
            result['services'].append(row)
    if selected_paths:
        result['interpretation'] = 'Each file is reported independently; interpolation, includes, inheritance and override order are not evaluated. Missing means not declared in this file; declarations give no score credit.'
    return result
