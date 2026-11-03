"""Select remote sources from a pinned Git tree, without downloading an archive."""

from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
import json
import re
from urllib.parse import quote

from score_core import supported
from score_reporting import source_priority
from score_sources import (
    MAX_BYTES,
    MAX_FILE,
    MAX_FILES,
    BudgetExceeded,
    RemoteError,
    SourceError,
    decode,
    excluded,
    relative,
)


MAX_INDEX = 8 * 1024 * 1024
MAX_PARALLEL = 8


def read_json(read, url, budget, expected=dict, *, limit=MAX_INDEX):
    budget.check()
    if limit <= 0:
        raise SourceError("Repository file listing exceeds the 8 MiB metadata limit.")
    raw = read(url, limit=limit)
    if len(raw) > limit:
        raise SourceError("Repository file listing exceeds the 8 MiB metadata limit.")
    try:
        value = json.loads(raw)
    except (ValueError, RecursionError):
        raise SourceError(
            "Repository file listing is invalid; no score is available."
        ) from None
    if not isinstance(value, expected):
        raise SourceError(
            "Repository file listing has an unexpected format; no score is available."
        )
    return value, len(raw)


def tree_entries(host, project, revision, budget, read, *, exclusions=None):
    exclusions = [] if exclusions is None else exclusions
    if host == "github.com":
        tree, _ = read_json(
            read,
            f"https://api.github.com/repos/{project}/git/trees/{revision}?recursive=1",
            budget,
        )
        if type(tree.get("truncated")) is not bool or not isinstance(
            tree.get("tree"), list
        ):
            raise SourceError(
                "Repository file listing is incomplete or truncated; no score is available."
            )
        entries = tree["tree"]
        if len(entries) > MAX_FILES:
            exclusions.append(
                {"file": "repository-tree", "reason": "repository entry limit"}
            )
        if tree["truncated"]:
            exclusions.append(
                {"file": "repository-tree", "reason": "truncated repository listing"}
            )
        return entries[:MAX_FILES]
    base = (
        f"https://{host}/api/v4/projects/{quote(project, safe='')}/repository/tree"
    )
    entries, metadata_bytes = [], 0
    for page in range(1, MAX_FILES // 100 + 2):
        try:
            rows, size = read_json(
                read,
                f"{base}?ref={revision}&recursive=true&per_page=100&page={page}",
                budget,
                list,
                limit=MAX_INDEX - metadata_bytes,
            )
        except BudgetExceeded:
            if not entries:
                raise
            exclusions.append(
                {"file": "repository-tree", "reason": "source time budget"}
            )
            return entries
        metadata_bytes += size
        if len(rows) > 100:
            raise SourceError("Repository file listing has an invalid page size.")
        entries.extend(rows)
        if len(entries) > MAX_FILES:
            exclusions.append(
                {"file": "repository-tree", "reason": "repository entry limit"}
            )
            return entries[:MAX_FILES]
        if len(rows) < 100:
            return entries[:MAX_FILES]
        if len(entries) >= MAX_FILES:
            exclusions.append(
                {"file": "repository-tree", "reason": "repository entry limit"}
            )
            return entries[:MAX_FILES]
    raise SourceError("Repository file listing did not finish within the entry limit.")


def select_files(host, project, revision, budget, read, *, authenticated=False):
    selected, exclusions, paths = [], [], set()
    # Pagination must leave time to download sources from the retained pages.
    entries = tree_entries(
        host, project, revision, budget.portion(0.25), read, exclusions=exclusions
    )
    for entry in entries:
        if not isinstance(entry, dict):
            raise SourceError("Repository file listing contains an invalid entry.")
        path = relative(entry.get("path"))
        if path != entry["path"]:
            raise SourceError("Repository file listing contains a noncanonical path.")
        if path in paths:
            raise SourceError(
                "Repository file listing contains duplicate source paths."
            )
        paths.add(path)
        kind, mode = entry.get("type"), entry.get("mode")
        if not isinstance(kind, str) or not isinstance(mode, str):
            raise SourceError("Repository file listing contains an invalid entry type.")
        if kind == "tree" and mode == "040000":
            continue
        if (kind, mode) not in {
            ("blob", "100644"),
            ("blob", "100755"),
            ("blob", "120000"),
            ("commit", "160000"),
        }:
            raise SourceError("Repository file listing contains an invalid entry type.")
        if mode in {"120000", "160000"}:
            exclusions.append({"file": path, "reason": "link or submodule"})
            continue
        if excluded(path) or not supported(path):
            exclusions.append({"file": path, "reason": "excluded or unsupported"})
            continue
        oid = entry.get("sha") if host == "github.com" else entry.get("id")
        if not isinstance(oid, str) or not re.fullmatch(
            r"[0-9a-f]{40}(?:[0-9a-f]{24})?", oid
        ):
            raise SourceError("Repository file listing contains an invalid object ID.")
        size = entry.get("size")
        if (host == "github.com" or size is not None) and (
            type(size) is not int or size < 0
        ):
            raise SourceError("Repository file listing contains an invalid file size.")
        if size is not None:
            if size > MAX_FILE:
                exclusions.append({"file": path, "reason": "oversized"})
                continue
        selected.append((path, oid, mode, size))

    # Apply the aggregate bound to a deterministic sample rather than throwing
    # away every source when a large repository cannot fit within it.
    kept, declared_bytes = [], 0
    for entry in sorted(selected, key=lambda row: source_priority(row[0])):
        path, _, _, size = entry
        if size is not None and declared_bytes + size > MAX_BYTES:
            exclusions.append({"file": path, "reason": "source byte limit"})
            continue
        declared_bytes += size or 0
        kept.append(entry)
    selected = kept

    def download(entry):
        path, oid, mode, size = entry
        budget.check()
        if host == "github.com" and not authenticated:
            url = f"https://raw.githubusercontent.com/{project}/{revision}/{quote(path, safe='/')}"
        elif host == "github.com":
            url = f"https://api.github.com/repos/{project}/git/blobs/{oid}"
        else:
            url = f"https://{host}/api/v4/projects/{quote(project, safe='')}/repository/blobs/{oid}/raw"
        try:
            data = read(url, limit=MAX_FILE, accept="application/vnd.github.raw+json")
        except BudgetExceeded:
            raise
        except SourceError as error:
            # A failed individual request does not invalidate other pinned
            # sources. Do not expose raw network diagnostics in the result.
            detail = (
                f"HTTP {error.status}"
                if isinstance(error, RemoteError) and error.status
                else "connection failed"
                if isinstance(error, RemoteError)
                else "request failed or response rejected"
            )
            return (
                path,
                None,
                mode,
                0,
                {"reason": "source download failed", "detail": detail},
            )
        if len(data) > MAX_FILE:
            raise SourceError(
                f"Selected source {path} exceeds the 512 KiB file limit; no score is available."
            )
        if size is not None and len(data) != size:
            raise SourceError(
                "A remote source does not match its listed size; no score is available."
            )
        text = decode(data)
        return path, text, mode, len(data), None

    files, total = {}, 0

    def retain(future):
        nonlocal total
        if future.cancelled():
            return
        try:
            path, text, mode, size, error = future.result()
        except BudgetExceeded:
            return
        if total + size > MAX_BYTES:
            exclusions.append({"file": path, "reason": "source byte limit"})
        elif error:
            exclusions.append({"file": path, **error})
        elif text is None:
            exclusions.append({"file": path, "reason": "binary or non-UTF-8"})
        else:
            files[path] = {"text": text, "executable": mode == "100755"}
        total += size

    # Keep only a bounded number of active and queued requests.
    with ThreadPoolExecutor(max_workers=MAX_PARALLEL) as pool:
        pending, remaining = {}, iter(selected)
        try:
            while True:
                budget.check()
                if total >= MAX_BYTES:
                    break
                while len(pending) < MAX_PARALLEL:
                    entry = next(remaining, None)
                    if entry is None:
                        break
                    pending[pool.submit(download, entry)] = entry
                if not pending:
                    break
                done, _ = wait(
                    pending, timeout=budget.remaining(), return_when=FIRST_COMPLETED
                )
                for future in sorted(done, key=lambda item: pending[item][0]):
                    pending.pop(future)
                    retain(future)
                if not done:
                    budget.check()
        except BudgetExceeded:
            pass
        finally:
            for future in pending:
                future.cancel()
    # The executor waits for active bounded requests to settle. Retain any
    # successful completions from that interval as well, even at the deadline.
    for future in sorted(pending, key=lambda item: pending[item][0]):
        retain(future)
    recorded = set(files) | {row["file"] for row in exclusions}
    for path, _, _, _ in selected:
        if path not in recorded:
            exclusions.append(
                {
                    "file": path,
                    "reason": "source byte limit"
                    if total >= MAX_BYTES
                    else "source time budget",
                }
            )
    return dict(sorted(files.items())), sorted(exclusions, key=lambda row: row["file"])
