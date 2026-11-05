"""Bounded IaC profile: declared targets and selected security properties.

No Terraform evaluation, state access, cloud API calls, or credential values.
Dynamic expressions remain unresolved. A declaration does not prove deployment.
"""

from pathlib import PurePosixPath
import re
import json

from score_design import pairs as unique_pairs


PROVIDERS = {"aws": "AWS", "azurerm": "Azure", "google": "GCP", "kubernetes": "Kubernetes", "helm": "Helm"}
KINDS = (
    ("managed web application", r"azurerm_(?:linux_web_app|windows_web_app|app_service)$"),
    ("container workload", r"(?:aws_(?:ecs_|eks_)|azurerm_(?:kubernetes_cluster|container_)|google_container_|kubernetes_(?:deployment|pod|stateful_set))"),
    ("serverless workload", r"(?:aws_lambda_|azurerm_(?:linux_|windows_)?function_app|google_cloudfunctions_|google_cloud_run_)"),
    ("virtual machine", r"(?:aws_instance$|azurerm_.*virtual_machine|google_compute_instance$)"),
    ("database", r"(?:aws_(?:db_|rds_|dynamodb_)|azurerm_(?:postgresql_|mysql_|mssql_|cosmosdb_)|google_sql_)"),
    ("storage", r"(?:aws_s3_|azurerm_storage_|google_storage_)"),
    ("identity / permissions", r"(?:aws_iam_|azurerm_(?:role_|user_assigned_identity)|google_.*iam_|kubernetes_(?:role|cluster_role|service_account))"),
    ("network / ingress", r"(?:aws_(?:vpc|subnet|security_group|vpc_security_group|lb|alb|route|internet_gateway)|azurerm_(?:network_|virtual_network|subnet|application_gateway|lb)|google_compute_(?:network|subnetwork|firewall|forwarding_rule)|kubernetes_(?:network_policy|ingress|service))"),
    ("key / secret management", r"(?:aws_(?:kms_|secretsmanager_)|azurerm_key_vault|google_(?:kms_|secret_manager_))"),
    ("audit / monitoring", r"(?:aws_(?:cloudtrail|cloudwatch_)|azurerm_monitor_|google_logging_)"),
)
FLAGS = {
    "publicly_accessible": "public-access",
    "public_network_access_enabled": "public-access",
    "map_public_ip_on_launch": "public-address-assignment",
    "associate_public_ip_address": "public-address-assignment",
    "storage_encrypted": "storage-encryption",
    "encrypted": "encryption",
    "enable_https_traffic_only": "https-only",
    "https_only": "https-only",
    "deletion_protection": "deletion-protection",
    "block_public_acls": "block-public-acls",
    "block_public_policy": "block-public-policy",
}


def clean_hcl(text):
    """Blank comments/heredocs, retaining newlines and ordinary quoted literals."""
    out = list(text)
    index = 0
    while index < len(text):
        if text[index] == '"':
            index += 1
            while index < len(text):
                if text[index] == "\\":
                    index += 2
                elif text[index] == '"':
                    index += 1
                    break
                else:
                    index += 1
            continue
        end = None
        if text.startswith("/*", index):
            close = text.find("*/", index + 2)
            end = len(text) if close < 0 else close + 2
        elif text.startswith("//", index) or text[index] == "#":
            close = text.find("\n", index)
            end = len(text) if close < 0 else close
        elif text.startswith("<<", index):
            marker = re.match(r"<<-?([A-Za-z_]\w*)[^\n]*\n", text[index:])
            if marker:
                start = index + marker.end()
                close = re.search(r"(?m)^\s*" + re.escape(marker[1]) + r"\s*$", text[start:])
                end = len(text) if close is None else start + close.end()
        if end is not None:
            for position in range(index, end):
                if out[position] != "\n":
                    out[position] = " "
            index = end
        else:
            index += 1
    return "".join(out)


def inspect(files, budget):
    result = {"providers": [], "resources": [], "state_backends": []}
    for path, source in sorted(files.items()):
        if path.endswith(".tf.json"):
            budget.check()
            for kind, name, attrs, scopes in json_blocks(source["text"]):
                budget.check()
                record(result, kind, name, attrs, scopes, {"file": path, "line": 1, "evidence": "declared"})
            continue
        if PurePosixPath(path).suffix != ".tf":
            continue
        budget.check()
        text = clean_hcl(source["text"])
        masked = re.sub(r'"(?:[^"\\]|\\.)*"', lambda m: " " * len(m[0]), text)
        stack, pairs = [], {}
        for token in re.finditer(r"[{}]", masked):
            if token[0] == "{":
                stack.append(token.start())
            elif stack:
                pairs[stack.pop()] = token.start()
        blocks = re.finditer(r'\b(resource|data|provider|backend)\s+"([\w.-]+)"(?:\s+"([\w.-]+)")?\s*\{', text)
        for index, match in enumerate(blocks):
            budget.check()
            if index >= 1000:
                break
            # A declaration-looking string has no active keyword in the masked text.
            if masked[match.start():match.start() + len(match[1])] != match[1]:
                continue
            end = pairs.get(match.end() - 1)
            if end is None:
                continue
            body = text[match.end():end]
            bounded = len(body.splitlines()) <= 200 and len(body) <= 40000
            body = "\n".join(body.splitlines()[:200])[:40000]
            where = {"file": path, "line": text.count("\n", 0, match.start()) + 1, "evidence": "declared"}
            kind, name = match[1], match[2]
            attrs = attributes(body) if bounded else {}
            scopes = [attrs]
            if bounded:
                body_masked, depths = structure(body)
                for child in re.finditer(r"(?m)^\s*(?:ingress|egress|statement)\s*\{", body):
                    keyword = child.start() + len(child[0]) - len(child[0].lstrip())
                    if depths[keyword] != 0 or body_masked[keyword] != body[keyword]:
                        continue
                    start = match.end() + child.end()
                    close = pairs.get(start - 1)
                    if close is not None:
                        scopes.append(attributes(text[start:close]))
            record(result, kind, name, attrs, scopes, where, bounded)
    return result


def structure(body):
    masked = re.sub(r'"(?:[^"\\]|\\.)*"', lambda m: " " * len(m[0]), body)
    depths, depth = [], 0
    for char in masked:
        depths.append(depth)
        if char in "{[(":
            depth += 1
        elif char in "}])":
            depth -= 1
    return masked, depths


def attributes(body):
    """Select direct attributes; nested tags and quoted examples are never controls."""
    masked, depths = structure(body)
    values = {}
    for match in re.finditer(r"(?m)^[ \t]*([\w-]+)[ \t]*=", masked):
        if depths[match.start(1)] != 0:
            continue
        end = match.end()
        while end < len(body) and not (body[end] == "\n" and depths[end] == 0):
            end += 1
        raw = body[match.end():end].strip()
        # HCL permits trailing commas in literal lists. Do not alter strings.
        raw_mask = re.sub(r'"(?:[^"\\]|\\.)*"', lambda m: " " * len(m[0]), raw)
        trailing = {m.start() for m in re.finditer(r",(?=\s*\])", raw_mask)}
        raw = "".join(char for index, char in enumerate(raw) if index not in trailing)
        try:
            value = json.loads(raw, object_pairs_hook=unique_pairs)
        except (ValueError, RecursionError):
            value = None
        key = match[1]
        values[key] = value if key not in values else None
    return values


def flag(attrs, field):
    if type(attrs.get(field)) is bool:
        return "enabled" if attrs[field] else "disabled"
    return "unresolved"


def record(result, kind, name, attrs, scopes, where, bounded=True):
    if kind == "provider":
        if name in PROVIDERS:
            region = attrs.get("region")
            region = region if isinstance(region, str) and re.fullmatch(r"[A-Za-z0-9-]{2,40}", region) else None
            result["providers"].append({**where, "technology": PROVIDERS[name], "region": region})
    elif kind == "backend":
        table = attrs.get("dynamodb_table")
        locking = attrs.get("use_lockfile") is True or (isinstance(table, str) and re.fullmatch(r"[A-Za-z0-9_.-]{3,255}", table))
        result["state_backends"].append({**where, "type": name, "encryption": flag(attrs, "encrypt"),
                                       "locking": "declared" if locking else "not established"})
    else:
        provider = PROVIDERS.get(name.split("_", 1)[0])
        if provider is None:
            return
        category = next((label for label, pattern in KINDS if re.match(pattern, name)), "other resource")
        properties = {label: flag(attrs, field) for field, label in FLAGS.items() if field in attrs}
        for field in ("location", "region", "zone"):
            value = attrs.get(field)
            if isinstance(value, str) and re.fullmatch(r"[A-Za-z][A-Za-z0-9 -]{1,39}", value):
                properties["deployment-" + field] = value
        for scope in scopes:
            for field in ("cidr_blocks", "ipv6_cidr_blocks", "cidr_ipv4", "cidr_ipv6", "source_ranges", "source_address_prefix"):
                value = scope.get(field)
                values = value if isinstance(value, list) else [value]
                if any(isinstance(v, str) and v in {"0.0.0.0/0", "::/0", "*", "Internet"} for v in values):
                    properties["network-source"] = "unrestricted range declared; direction and effective reachability need context"
            for field in ("action", "actions", "resource", "resources"):
                value = scope.get(field)
                if value == "*" or isinstance(value, list) and "*" in value:
                    properties["permissions"] = "wildcard declared; effective scope needs policy context"
        if not bounded:
            properties["coverage"] = "resource exceeds the 200-line or 40000-character observation window"
        result["resources"].append({**where, "technology": provider, "type": name, "category": category,
                                    "mode": kind, "properties": properties})


def json_blocks(text):
    try:
        document = json.loads(text, object_pairs_hook=unique_pairs)
    except (ValueError, RecursionError):
        return
    if not isinstance(document, dict):
        return
    count = 0
    for kind in ("provider", "resource", "data", "backend"):
        root = document.get("terraform", {}) if kind == "backend" else document
        groups = root.get(kind, {}) if isinstance(root, dict) else {}
        if not isinstance(groups, dict):
            continue
        for name, contents in groups.items():
            blocks = contents.values() if kind in {"resource", "data"} and isinstance(contents, dict) else [contents]
            for block in blocks:
                for attrs in block if isinstance(block, list) else [block]:
                    count += 1
                    if count > 1000:
                        return
                    if not isinstance(attrs, dict):
                        continue
                    scopes = [attrs]
                    for child in ("ingress", "egress", "statement"):
                        value = attrs.get(child, [])
                        scopes.extend(v for v in (value if isinstance(value, list) else [value]) if isinstance(v, dict))
                    yield kind, name, attrs, scopes
