"""Bounded design evidence from native Kubernetes JSON manifests.

Inspect container/host boundaries and resolve volumeMounts to hostPath volumes.
Never execute manifests or infer runtime deployment, authentication or tenancy.
Other configuration shapes remain with the existing pattern checks.
"""

import json
from pathlib import PurePosixPath


def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("Ambiguous JSON object")
        result[key] = value
    return result


def inspect(files, budget):
    observations = []
    for path, source in sorted(files.items()):
        if PurePosixPath(path).suffix != ".json":
            continue
        budget.check()
        if source.get("fragment") or source.get("fragments"):
            continue
        try:
            doc = json.loads(source["text"], object_pairs_hook=pairs)
        except (ValueError, RecursionError):
            continue
        if not isinstance(doc, dict) or not isinstance(doc.get("apiVersion"), str) or doc["apiVersion"] not in {"v1", "apps/v1", "batch/v1"}:
            continue
        kind = doc.get("kind")
        if not isinstance(kind, str) or kind not in {"Pod", "Deployment", "StatefulSet", "DaemonSet", "Job"}:
            continue
        root = "/spec" if kind == "Pod" else "/spec/template/spec"
        pod = doc
        for key in root.strip("/").split("/"):
            pod = pod.get(key) if isinstance(pod, dict) else None
        if not isinstance(pod, dict):
            observations.append(evidence(path, root, "unclear", "Pod specification is not a literal object."))
            continue
        volumes = pod.get("volumes", [])
        containers = [*pod.get("containers", [])] if isinstance(pod.get("containers"), list) else []
        init = pod.get("initContainers", [])
        if not containers or not isinstance(init, list) or not isinstance(volumes, list):
            observations.append(evidence(path, root, "unclear", "Container or volume declarations are unresolved."))
            continue
        volume_names = [v.get("name") for v in volumes if isinstance(v, dict)]
        if any(not isinstance(name, str) for name in volume_names) or len(set(volume_names)) != len(volumes):
            observations.append(evidence(path, root, "unclear", "Volume identities are ambiguous."))
            continue
        volume_map = {v["name"]: v for v in volumes}
        for group, entries in (("containers", containers), ("initContainers", init)):
            for index, container in enumerate(entries):
                budget.check()
                pointer = f"{root}/{group}/{index}"
                if not isinstance(container, dict):
                    observations.append(evidence(path, pointer, "unclear", "Container configuration is unresolved."))
                    continue
                sc = container.get("securityContext", {})
                if not isinstance(sc, dict):
                    observations.append(evidence(path, pointer, "unclear", "Container security context is unresolved."))
                    continue
                reasons = []
                if sc.get("privileged") is True:
                    reasons.append("Container is explicitly privileged across the host isolation boundary.")
                if any(pod.get(key) is True for key in ("hostPID", "hostIPC")):
                    reasons.append("Container shares host process or IPC namespaces.")
                if pod.get("hostNetwork") is True:
                    reasons.append("Container shares the host network namespace.")
                mounts = container.get("volumeMounts", [])
                unresolved = not isinstance(mounts, list)
                for mount in mounts if isinstance(mounts, list) else []:
                    name = mount.get("name") if isinstance(mount, dict) else None
                    if not isinstance(name, str) or name not in volume_map:
                        unresolved = True
                        continue
                    host = volume_map[name].get("hostPath")
                    if host is None:
                        continue
                    value = host.get("path") if isinstance(host, dict) else None
                    if isinstance(value, str) and value in {"/", "/var/run/docker.sock", "/run/docker.sock", "/run/containerd/containerd.sock"}:
                        reasons.append("Container mounts the host root or a container-runtime control socket.")
                    else:
                        unresolved = True
                if reasons:
                    observations.append(evidence(path, pointer, "violated", " ".join(reasons)))
                    continue
                booleans = [(pod, "hostPID"), (pod, "hostIPC"), (pod, "hostNetwork"), (sc, "privileged"), (sc, "allowPrivilegeEscalation")]
                unresolved |= any(key in owner and type(owner[key]) is not bool for owner, key in booleans)
                caps = sc.get("capabilities", {})
                positive = (
                    not unresolved
                    and sc.get("privileged") is False
                    and sc.get("allowPrivilegeEscalation") is False
                    and sc.get("runAsNonRoot") is True
                    and isinstance(caps, dict)
                    and caps.get("drop") == ["ALL"]
                    and not caps.get("add")
                )
                row = evidence(
                    path, pointer, "satisfied" if positive else "unclear",
                    "Container explicitly restricts privilege escalation, root identity and capabilities."
                    if positive else "Container isolation controls are not sufficiently established.",
                )
                if positive:
                    row["supported_criteria"] = ["isolation", "privileges"]
                observations.append(row)
    return observations


def evidence(path, pointer, status, reason):
    return {"rule": "DESIGN-CONTAINER-ISOLATION", "file": path, "pointer": pointer,
            "status": status, "reason": reason, "criterion": "isolation",
            "severity": "high", "area": "architecture", "certainty": "declared-design"}
