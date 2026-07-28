from __future__ import annotations

"""Bounded local evidence collectors for the manual Web GPT bridge.

This module deliberately has no subprocess or app-server dependency.  Callers map a
web-supplied description to one exact project-relative path before any source is read.
"""

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Mapping

from .policy import PolicyError, bridge_packet_safety_reason, canonical_json, resolve_safe_evidence_mapping, sha256_json


COLLECTOR_VERSION = "1"
SUPPORTED_TYPES = frozenset({"file_metadata", "fast_fingerprint", "text_range", "log_excerpt", "json_structure"})
MAX_REQUESTS = 20
MAX_RESULT_BYTES = 32 * 1024
MAX_TOTAL_BYTES = 50 * 1024
MAX_TEXT_LINES = 250
MAX_FILE_TEXT_LINES = 1000
MAX_LOG_LINES = 200
MAX_JSON_BYTES = 1024 * 1024
EDGE_BYTES = 1024 * 1024
_DB_URL = re.compile(r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://")


def normalize_requested_evidence(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > MAX_REQUESTS:
        raise PolicyError("requested_evidence must contain at most 20 structured entries")
    normalized: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict) or set(item) != {"type", "label", "reason", "required", "target_hint"}:
            raise PolicyError("requested_evidence entries must contain only type, label, reason, required, target_hint")
        kind, label, reason, required, hint = (item.get(key) for key in ("type", "label", "reason", "required", "target_hint"))
        if kind not in SUPPORTED_TYPES or not all(isinstance(text, str) and text.strip() for text in (label, reason, hint)) or not isinstance(required, bool):
            raise PolicyError("requested_evidence entry is invalid")
        entry = {"type": kind, "label": label.strip()[:240], "reason": reason.strip()[:1024], "required": required, "target_hint": hint.strip()[:1024]}
        if reason := bridge_packet_safety_reason(entry):
            raise PolicyError(reason)
        normalized.append(entry)
    return normalized


def sensitive_file_reason(relative: str) -> str | None:
    # The policy layer performs this check before opening user-mapped sources.
    return None


def _safe_text(data: bytes) -> str:
    if b"\x00" in data:
        raise PolicyError("Binary source cannot be collected as text")
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise PolicyError("Unsupported source encoding") from exc


def _bounded_text_lines(path: Path, start: int, end: int, limit: int) -> list[str]:
    selected: list[str] = []
    with path.open("rb") as source:
        for number, raw in enumerate(source, 1):
            if len(raw) > 64 * 1024:
                raise PolicyError("Source has an excessively long line")
            if start <= number <= end:
                selected.append(_safe_text(raw).rstrip("\r\n"))
                if len(selected) > limit:
                    raise PolicyError("Requested line range exceeds collector limit")
    return selected


def _json_shape(value: Any, depth: int = 0) -> Any:
    if depth >= 5:
        return {"type": type(value).__name__}
    if isinstance(value, dict):
        return {"type": "object", "keys": {str(key): _json_shape(item, depth + 1) for key, item in sorted(value.items())}}
    if isinstance(value, list):
        return {"type": "array", "length": len(value), "item_types": sorted({type(item).__name__ for item in value})}
    return {"type": type(value).__name__}


def collect(request: Mapping[str, Any], root: str | Path) -> dict[str, Any]:
    """Read one mapped source under strict type-specific bounds and return redacted data."""
    mapped = request.get("mapped_path")
    if not isinstance(mapped, str) or not mapped.strip():
        raise PolicyError("Evidence request must be mapped to a project-relative file")
    path, relative = resolve_safe_evidence_mapping(root, mapped)
    kind = request.get("type")
    if kind not in SUPPORTED_TYPES:
        raise PolicyError("Evidence type is not supported")
    stat_before = path.stat()
    base: dict[str, Any] = {"request_id": request["request_id"], "type": kind, "label": request["label"], "path": f"PROJECT_ROOT/{relative}", "collector_version": COLLECTOR_VERSION}
    if kind == "file_metadata":
        result = {**base, "size": stat_before.st_size, "mtime_ns": stat_before.st_mtime_ns, "suffix": path.suffix.casefold()}
    elif kind == "fast_fingerprint":
        digest = hashlib.sha256()
        with path.open("rb") as source:
            first = source.read(EDGE_BYTES)
            digest.update(first)
            if stat_before.st_size > EDGE_BYTES:
                source.seek(max(0, stat_before.st_size - EDGE_BYTES))
                digest.update(source.read(EDGE_BYTES))
        result = {**base, "size": stat_before.st_size, "mtime_ns": stat_before.st_mtime_ns, "edge_sha256": digest.hexdigest()}
    elif kind == "text_range":
        start, end = int(request.get("start_line", 1)), int(request.get("end_line", MAX_TEXT_LINES))
        if start < 1 or end < start or end - start + 1 > MAX_TEXT_LINES:
            raise PolicyError("text_range must be at most 250 lines")
        lines = _bounded_text_lines(path, start, end, MAX_TEXT_LINES)
        result = {**base, "start_line": start, "end_line": end, "lines": [{"line": start + index, "text": text} for index, text in enumerate(lines)]}
    elif kind == "log_excerpt":
        center, before, after = int(request.get("line", 1)), int(request.get("context_before", 0)), int(request.get("context_after", MAX_LOG_LINES - 1))
        if center < 1 or before < 0 or after < 0 or before + after + 1 > MAX_LOG_LINES:
            raise PolicyError("log_excerpt must be at most 200 lines including context")
        start, end = max(1, center - before), center + after
        lines = _bounded_text_lines(path, start, end, MAX_LOG_LINES)
        result = {**base, "start_line": start, "end_line": end, "lines": [{"line": start + index, "text": text} for index, text in enumerate(lines)]}
    else:
        if stat_before.st_size > MAX_JSON_BYTES:
            raise PolicyError("json_structure source exceeds 1MB")
        with path.open("rb") as source:
            raw = source.read(MAX_JSON_BYTES + 1)
        if len(raw) > MAX_JSON_BYTES:
            raise PolicyError("json_structure source exceeds 1MB")
        try:
            parsed = json.loads(_safe_text(raw))
        except json.JSONDecodeError as exc:
            raise PolicyError("json_structure source is invalid JSON") from exc
        result = {**base, "shape": _json_shape(parsed)}
    stat_after = path.stat()
    if (stat_before.st_size, stat_before.st_mtime_ns) != (stat_after.st_size, stat_after.st_mtime_ns):
        raise PolicyError("Evidence source changed while being collected")
    encoded = canonical_json(result).encode("utf-8")
    if len(encoded) > MAX_RESULT_BYTES:
        raise PolicyError("Evidence result exceeds 32KB")
    if bridge_packet_safety_reason(result) or _DB_URL.search(canonical_json(result)):
        raise PolicyError("Evidence result contains sensitive content")
    return {**result, "result_hash": sha256_json(result), "size_bytes": len(encoded)}
