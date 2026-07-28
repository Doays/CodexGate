from __future__ import annotations

import os
import re
import hashlib
import json
import shlex
import stat
import subprocess
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path, PureWindowsPath
from typing import Any, Sequence


BUDGETS = {
    "tiny": {"tokens": 250_000, "tools": 15, "changed_files": 2},
    "standard": {"tokens": 750_000, "tools": 30, "changed_files": 5},
    "complex": {"tokens": 2_000_000, "tools": 50, "changed_files": 10},
    "critical": {"tokens": 4_000_000, "tools": 60, "changed_files": 10},
}
ROUTE_PLAN_BUDGET_LEVELS = {
    "T0": "tiny",
    "T1": "tiny",
    "T2": "standard",
    "T3": "standard",
    "T4": "complex",
    "T5": "critical",
}

HIGH_RISK_TERMS = (
    "paper_trader.py",
    "postgres",
    "database migration",
    "nginx",
    "crontab",
    "vps",
    "mount",
    "secret",
    "assetbundle",
    "game install",
    "production",
)

DEFAULT_FORBIDDEN_ROOTS = (Path(r"E:\.codex"),)
ALLOWED_ARTIFACT_NAMES = frozenset({"request.md", "decision.json", "result.json", "diff.patch"})
_PROJECT_ID_SLUG = re.compile(r"^[a-z0-9](?:[a-z0-9_-]{0,78}[a-z0-9])?$")
_UUID_TEXT = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
BRIDGE_MAX_PACKET_BYTES = 60 * 1024
BRIDGE_SCHEMA_VERSION = "2.0"
_BRIDGE_SECRET_PATTERNS = (
    re.compile(r"\b(?:sk|rk|pk)_[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----"),
    re.compile(r"(?i)\b(?:password|passwd|secret|api[_-]?key|token)\s*[:=]\s*\S+"),
)
_ABSOLUTE_USER_PATH = re.compile(r"(?i)(?:\b[a-z]:[\\/]|(?:^|\s)/(?:users|home)/)")
_SENSITIVE_EVIDENCE_NAME = re.compile(r"(?i)(?:^|[\\/])(?:\.env|[^\\/]*\.(?:pem|key|pfx)|credentials(?:\.[^\\/]*)?|service-account[^\\/]*)$")


class PolicyError(ValueError):
    pass


@dataclass(frozen=True)
class Decision:
    decision: str
    task_class: str
    recommended_model: str
    recommended_effort: str
    allowed_files: list[str]
    forbidden_files: list[str]
    validation_commands: list[str]
    stop_conditions: list[str]
    evidence_files: list[str] = field(default_factory=list)
    evidence_ranges: list[dict[str, int | str]] = field(default_factory=list)
    risk: str = "medium"
    parallel_audit: bool = False
    independent_axes: int = 0

    @classmethod
    def from_json(cls, payload: dict[str, Any]) -> "Decision":
        if not isinstance(payload, dict):
            raise PolicyError("decision JSON must be an object")
        known = {
            "decision", "task_class", "recommended_model", "recommended_effort",
            "allowed_files", "forbidden_files", "validation_commands", "stop_conditions",
            "evidence_files", "evidence_ranges", "risk", "parallel_audit", "independent_axes",
        }
        unexpected = sorted(set(payload) - known)
        if unexpected:
            raise PolicyError(f"decision JSON has unknown fields: {', '.join(unexpected)}")
        required = ("decision", "task_class", "recommended_model", "recommended_effort")
        missing = [field for field in required if not isinstance(payload.get(field), str) or not payload[field].strip()]
        if missing:
            raise PolicyError(f"decision JSON is missing required fields: {', '.join(missing)}")
        lists = {}
        for field in ("allowed_files", "forbidden_files", "validation_commands", "stop_conditions", "evidence_files"):
            value = payload.get(field, [])
            if not isinstance(value, list) or not all(isinstance(item, str) and item.strip() for item in value):
                raise PolicyError(f"{field} must be a non-empty string list")
            lists[field] = [item.strip() for item in value]
        evidence_ranges = payload.get("evidence_ranges", [])
        if not isinstance(evidence_ranges, list):
            raise PolicyError("evidence_ranges must be a list")
        normalized_ranges: list[dict[str, int | str]] = []
        for item in evidence_ranges:
            if not isinstance(item, dict) or set(item) != {"path", "start_line", "end_line"}:
                raise PolicyError("evidence_ranges entries must contain path, start_line, and end_line")
            path = item.get("path")
            start_line = item.get("start_line")
            end_line = item.get("end_line")
            if not isinstance(path, str) or not path.strip():
                raise PolicyError("evidence_ranges path must be a non-empty string")
            if (
                isinstance(start_line, bool)
                or isinstance(end_line, bool)
                or not isinstance(start_line, int)
                or not isinstance(end_line, int)
                or start_line < 1
                or end_line < start_line
            ):
                raise PolicyError("evidence_ranges line bounds must be positive integers with start_line <= end_line")
            normalized_ranges.append({
                "path": path.strip(),
                "start_line": start_line,
                "end_line": end_line,
            })
        if payload["decision"] not in {"execute", "hold", "evidence_only"}:
            raise PolicyError("decision must be execute, hold, or evidence_only")
        risk = payload.get("risk", "medium")
        if not isinstance(risk, str) or risk.strip().casefold() not in {"low", "medium", "high"}:
            raise PolicyError("risk must be low, medium, or high")
        parallel_audit = payload.get("parallel_audit", False)
        if not isinstance(parallel_audit, bool):
            raise PolicyError("parallel_audit must be a boolean")
        independent_axes = payload.get("independent_axes", 0)
        if isinstance(independent_axes, bool) or not isinstance(independent_axes, int) or not 0 <= independent_axes <= 20:
            raise PolicyError("independent_axes must be an integer from 0 through 20")
        return cls(
            decision=payload["decision"].strip(),
            task_class=payload["task_class"].strip(),
            recommended_model=payload["recommended_model"].strip(),
            recommended_effort=payload["recommended_effort"].strip(),
            **lists,
            evidence_ranges=normalized_ranges,
            risk=risk.strip().casefold(),
            parallel_audit=parallel_audit,
            independent_axes=independent_axes,
        )

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)

    def canonical_json(self) -> str:
        return canonical_json(self.as_dict())

    def sha256(self) -> str:
        return sha256_text(self.canonical_json())


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_json(value: Any) -> str:
    return sha256_text(canonical_json(value))


def bridge_packet_safety_reason(value: Any) -> str | None:
    """Reject data that must never cross the manual Web GPT bridge."""
    text = canonical_json(value) if not isinstance(value, str) else value
    if _ABSOLUTE_USER_PATH.search(text):
        return "Bridge packets cannot contain absolute user paths."
    if any(pattern.search(text) for pattern in _BRIDGE_SECRET_PATTERNS):
        return "Bridge packet may contain a secret."
    return None


def canonical_path_text(value: str | Path) -> str:
    return Path(value).as_posix().casefold()


def _normalize_text(value: str | Path) -> str:
    return str(value).strip()


def _windows_absolute_path(value: str | Path) -> PureWindowsPath | None:
    candidate = PureWindowsPath(_normalize_text(value))
    if candidate.is_absolute() and candidate.drive:
        return candidate
    return None


def _windows_parts(value: PureWindowsPath) -> tuple[str, tuple[str, ...]]:
    return value.drive.casefold(), tuple(part.casefold() for part in value.parts[1:])


def _windows_is_relative_to(parent: PureWindowsPath, child: PureWindowsPath) -> bool:
    parent_drive, parent_parts = _windows_parts(parent)
    child_drive, child_parts = _windows_parts(child)
    return parent_drive == child_drive and child_parts[:len(parent_parts)] == parent_parts


def _path_key(value: str | Path) -> str:
    windows_path = _windows_absolute_path(value)
    if windows_path is not None:
        return str(windows_path).replace("/", "\\").casefold().rstrip("\\")
    return Path(value).expanduser().resolve(strict=False).as_posix().casefold().rstrip("/")


def _is_within_root(root: str | Path, candidate: str | Path) -> bool:
    windows_root = _windows_absolute_path(root)
    windows_candidate = _windows_absolute_path(candidate)
    if windows_root is not None or windows_candidate is not None:
        return windows_root is not None and windows_candidate is not None and _windows_is_relative_to(windows_root, windows_candidate)
    root_key = _path_key(root)
    candidate_key = _path_key(candidate)
    return candidate_key == root_key or candidate_key.startswith(f"{root_key}/")


def configured_forbidden_roots(extra: Sequence[str | Path] | None = None) -> tuple[Path, ...]:
    roots: list[Path] = [Path(item).expanduser() for item in DEFAULT_FORBIDDEN_ROOTS]
    env_value = os.environ.get("CODEX_GATE_FORBIDDEN_ROOTS", "")
    if env_value:
        for raw in re.split(r"[;\n]", env_value):
            raw = raw.strip()
            if raw:
                roots.append(Path(raw).expanduser())
    if extra:
        roots.extend(Path(item).expanduser() for item in extra if str(item).strip())
    deduped: list[Path] = []
    seen: set[str] = set()
    for root in roots:
        key = _path_key(root)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(root)
    return tuple(deduped)


def forbidden_workspace_reason(root: str | Path, forbidden_roots: Sequence[str | Path] | None = None) -> str | None:
    windows_root = _windows_absolute_path(root)
    if windows_root is not None:
        for forbidden in configured_forbidden_roots(forbidden_roots):
            windows_forbidden = _windows_absolute_path(forbidden)
            if windows_forbidden is None:
                continue
            if _windows_is_relative_to(windows_forbidden, windows_root) or _windows_is_relative_to(windows_root, windows_forbidden):
                return f"workspace root is blocked by forbidden root: {forbidden}"
        return None

    root_path = Path(root).expanduser().resolve(strict=False)
    for forbidden in configured_forbidden_roots(forbidden_roots):
        if _is_within_root(forbidden, root_path) or _is_within_root(root_path, forbidden):
            return f"workspace root is blocked by forbidden root: {forbidden}"
    return None


def validate_workspace_root(root: str | Path, forbidden_roots: Sequence[str | Path] | None = None) -> Path:
    windows_root = _windows_absolute_path(root)
    if windows_root is not None and os.name != "nt":
        raise PolicyError("Windows absolute workspace paths are not allowed on this platform")
    root_path = Path(root).expanduser().resolve(strict=False)
    reason = forbidden_workspace_reason(root_path if windows_root is None else str(windows_root), forbidden_roots=forbidden_roots)
    if reason:
        raise PolicyError(reason)
    if not root_path.is_dir():
        raise PolicyError("project root directory does not exist")
    return root_path


def validate_catalog_source_root(root: str | Path, forbidden_roots: Sequence[str | Path] | None = None) -> Path:
    """Validate an explicitly selected catalog root without dereferencing links."""
    raw = _normalize_text(root)
    windows_root = _windows_absolute_path(raw)
    if windows_root is not None and os.name != "nt":
        raise PolicyError("Windows absolute source roots are not allowed on this platform")
    path = Path(raw).expanduser()
    if windows_root is None and not path.is_absolute():
        raise PolicyError("catalog source root must be an absolute path")
    if is_link_or_junction(path):
        raise PolicyError("catalog source root cannot be a symlink or junction")
    resolved = validate_workspace_root(raw, forbidden_roots=forbidden_roots)
    if is_link_or_junction(resolved):
        raise PolicyError("catalog source root cannot be a symlink or junction")
    return resolved


def validate_source_alias(value: str) -> str:
    alias = value.strip()
    if not alias or len(alias) > 120:
        raise PolicyError("catalog source alias must be 1 to 120 characters")
    if "\x00" in alias or _windows_absolute_path(alias) is not None or Path(alias).is_absolute():
        raise PolicyError("catalog source alias is invalid")
    return alias


def resolve_project_path(root: str | Path, value: str) -> tuple[Path, str]:
    """Resolve a candidate path and reject traversal, symlink, junction, and volume escapes."""
    root_path = Path(root).expanduser().resolve(strict=False)
    raw = Path(value).expanduser()
    if _windows_absolute_path(value) is not None and os.name != "nt":
        raise PolicyError("project path escapes the configured root")
    if raw.drive and not raw.is_absolute():
        raise PolicyError("project path escapes the configured root")
    candidate = raw if raw.is_absolute() else root_path / raw
    resolved = candidate.resolve(strict=False)
    if not _is_within_root(root_path, resolved):
        raise PolicyError("project path escapes the configured root")
    try:
        relative = resolved.relative_to(root_path).as_posix()
    except ValueError:
        relative = resolved.as_posix()
    return resolved, relative.casefold()


def validate_allowed_file_scope(root: str | Path, allowed_files: list[str]) -> tuple[list[str], list[str]]:
    """Return unique exact project-relative files and unresolved-scope reasons."""
    root_path = Path(root).expanduser().resolve(strict=False)
    normalized: list[str] = []
    seen: set[str] = set()
    reasons: list[str] = []
    glob_characters = frozenset("*?[]{}")
    for raw in allowed_files:
        value = raw.strip()
        if any(character in value for character in glob_characters):
            reasons.append(f"allowed_files entry is a glob, not an exact file: {value}")
            continue
        if value.endswith(("/", "\\")):
            reasons.append(f"allowed_files entry is a directory, not an exact file: {value}")
            continue
        candidate = Path(value)
        if candidate.is_absolute() or _windows_absolute_path(value) is not None or candidate.drive:
            reasons.append(f"allowed_files entry must be project-relative: {value}")
            continue
        try:
            resolved, relative_key = resolve_project_path(root_path, value)
        except PolicyError:
            reasons.append(f"allowed_files entry escapes the project root: {value}")
            continue
        if resolved == root_path or resolved.is_dir():
            reasons.append(f"allowed_files entry is a directory, not an exact file: {value}")
            continue
        relative = resolved.relative_to(root_path).as_posix()
        if relative_key in seen:
            continue
        seen.add(relative_key)
        normalized.append(relative)
    return normalized, reasons


def is_link_or_junction(path: Path) -> bool:
    if path.is_symlink():
        return True
    is_junction = getattr(path, "is_junction", None)
    if is_junction and is_junction():
        return True
    try:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except OSError:
        return False
    reparse_point = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x0400)
    return bool(attributes & reparse_point)


def resolve_evidence_file(root: str | Path, value: str) -> tuple[Path, str]:
    """Resolve one exact evidence file without traversing a link or junction."""
    root_path = Path(root).expanduser().resolve(strict=False)
    raw_value = value.strip()
    if any(character in raw_value for character in "*?[]{}"):
        raise PolicyError("evidence entry is a glob, not an exact file")
    if raw_value.endswith(("/", "\\")):
        raise PolicyError("evidence entry is a directory, not an exact file")
    raw = Path(raw_value)
    if raw.is_absolute() or _windows_absolute_path(raw_value) is not None or raw.drive:
        raise PolicyError("evidence entry must be project-relative")
    if any(part == ".." for part in raw.parts):
        raise PolicyError("evidence entry escapes the project root")

    candidate = root_path
    for part in raw.parts:
        if part in {"", "."}:
            continue
        candidate /= part
        if is_link_or_junction(candidate):
            raise PolicyError("evidence entry traverses a symlink or junction")
    resolved, _ = resolve_project_path(root_path, raw_value)
    if resolved == root_path or not candidate.exists() or not candidate.is_file():
        raise PolicyError("evidence entry must name an existing regular file")
    if is_link_or_junction(candidate):
        raise PolicyError("evidence entry traverses a symlink or junction")
    return resolved, resolved.relative_to(root_path).as_posix()


def resolve_safe_evidence_mapping(root: str | Path, value: str) -> tuple[Path, str]:
    """Resolve an explicitly user-mapped evidence path and reject sensitive names."""
    path, relative = resolve_evidence_file(root, value)
    if _SENSITIVE_EVIDENCE_NAME.search(relative.replace("/", "\\")):
        raise PolicyError("Sensitive file names cannot be collected.")
    return path, relative


def merge_evidence_ranges(ranges: Sequence[dict[str, int | str]]) -> list[dict[str, int | str]]:
    """Sort and merge overlapping ranges without changing the source-file selection."""
    grouped: dict[str, list[dict[str, int | str]]] = {}
    display_paths: dict[str, str] = {}
    for entry in ranges:
        path = str(entry["path"])
        key = canonical_path_text(path)
        display_paths.setdefault(key, path)
        grouped.setdefault(key, []).append({
            "path": path,
            "start_line": int(entry["start_line"]),
            "end_line": int(entry["end_line"]),
        })

    merged: list[dict[str, int | str]] = []
    for key in sorted(grouped):
        current: dict[str, int | str] | None = None
        for entry in sorted(grouped[key], key=lambda item: (int(item["start_line"]), int(item["end_line"]))):
            normalized = {**entry, "path": display_paths[key]}
            if current is not None and int(normalized["start_line"]) <= int(current["end_line"]):
                current["end_line"] = max(int(current["end_line"]), int(normalized["end_line"]))
            else:
                if current is not None:
                    merged.append(current)
                current = normalized
        if current is not None:
            merged.append(current)
    return merged


def evidence_fingerprint(
    task_hash: str,
    decision_hash: str,
    evidence_files: Sequence[str],
    evidence_ranges: Sequence[dict[str, int | str]],
    evidence_sources: Sequence[dict[str, int | str]],
) -> str:
    """Hash sealed evidence without binding it to a Route Plan instance ID."""
    normalized_files = sorted({canonical_path_text(path) for path in evidence_files})
    normalized_ranges = sorted(
        (
            {
                "path": canonical_path_text(str(entry["path"])),
                "start_line": int(entry["start_line"]),
                "end_line": int(entry["end_line"]),
            }
            for entry in evidence_ranges
        ),
        key=lambda item: (item["path"], item["start_line"], item["end_line"]),
    )
    normalized_sources = sorted(
        (
            {
                "path": canonical_path_text(str(entry["path"])),
                "sha256": str(entry["sha256"]),
            }
            for entry in evidence_sources
        ),
        key=lambda item: item["path"],
    )
    return sha256_json({
        "task_hash": task_hash,
        "decision_hash": decision_hash,
        "scope": {
            "evidence_files": normalized_files,
            "evidence_ranges": normalized_ranges,
        },
        "source_sha256": normalized_sources,
    })


def validate_evidence_scope(
    root: str | Path,
    evidence_files: Sequence[str],
    evidence_ranges: Sequence[dict[str, int | str]],
) -> tuple[list[str], list[dict[str, int | str]], list[str]]:
    """Validate the bounded read scope separately from the write-oriented allowed_files."""
    normalized_files: list[str] = []
    normalized_ranges: list[dict[str, int | str]] = []
    reasons: list[str] = []
    seen_files: set[str] = set()
    for value in evidence_files:
        try:
            _, relative = resolve_evidence_file(root, value)
        except PolicyError as exc:
            reasons.append(f"evidence_files entry is unresolved: {value} ({exc})")
            continue
        key = canonical_path_text(relative)
        if key not in seen_files:
            seen_files.add(key)
            normalized_files.append(relative)

    for entry in evidence_ranges:
        path = str(entry["path"])
        try:
            _, relative = resolve_evidence_file(root, path)
        except PolicyError as exc:
            reasons.append(f"evidence_ranges entry is unresolved: {path} ({exc})")
            continue
        normalized_ranges.append({
            "path": relative,
            "start_line": int(entry["start_line"]),
            "end_line": int(entry["end_line"]),
        })
    return normalized_files, merge_evidence_ranges(normalized_ranges), reasons


def evidence_source_metadata(
    root: str | Path,
    evidence_files: Sequence[str],
    evidence_ranges: Sequence[dict[str, int | str]],
) -> tuple[list[dict[str, int | str]], list[str]]:
    """Hash only the explicitly selected source files; never enumerate the project tree."""
    source_paths = [*evidence_files, *(str(entry["path"]) for entry in evidence_ranges)]
    entries: list[dict[str, int | str]] = []
    reasons: list[str] = []
    seen: set[str] = set()
    for value in source_paths:
        try:
            path, relative = resolve_evidence_file(root, value)
            key = canonical_path_text(relative)
            if key in seen:
                continue
            seen.add(key)
            digest = hashlib.sha256()
            size = 0
            with path.open("rb") as source:
                while chunk := source.read(64 * 1024):
                    digest.update(chunk)
                    size += len(chunk)
            entries.append({"path": relative, "sha256": digest.hexdigest(), "size": size})
        except (OSError, PolicyError) as exc:
            reasons.append(f"evidence source is unavailable: {value} ({exc})")
    return sorted(entries, key=lambda item: canonical_path_text(str(item["path"]))), reasons


def validation_evidence(root: str | Path, validation_commands: list[str]) -> dict[str, Any]:
    """Derive test evidence only from validation commands and local target metadata."""
    root_path = Path(root).expanduser().resolve(strict=False)
    commands_present = bool(validation_commands)
    checked_targets: list[str] = []
    local_test_target_exists = False
    for command in validation_commands:
        try:
            tokens = shlex.split(command, posix=os.name != "nt")
        except ValueError:
            tokens = command.split()
        lowered = [token.strip("\"'").casefold() for token in tokens]
        invokes_test_runner = any(
            token in {"pytest", "unittest", "test"} or token.endswith(("pytest.exe", "pytest", "jest", "vitest"))
            for token in lowered
        ) or ("python" in lowered and "-m" in lowered and any(token in {"pytest", "unittest"} for token in lowered))
        candidates: list[str] = []
        for token in tokens[1:]:
            value = token.strip("\"'")
            if not value or value.startswith("-") or "=" in value or _windows_absolute_path(value) is not None:
                continue
            if "/" in value or "\\" in value or Path(value).suffix:
                candidates.append(value.split("::", 1)[0])
        if invokes_test_runner and not candidates:
            candidates.extend(("tests", "test"))
        for candidate in candidates:
            try:
                resolved, relative_key = resolve_project_path(root_path, candidate)
            except PolicyError:
                continue
            checked_targets.append(relative_key)
            if resolved.exists():
                local_test_target_exists = True
    return {
        "validation_commands_present": commands_present,
        "local_test_target_exists": local_test_target_exists,
        "has_tests": commands_present and local_test_target_exists,
        "checked_targets": list(dict.fromkeys(checked_targets)),
    }


def validate_project_file(root: str | Path, value: str, allowed_files: list[str], forbidden_files: list[str]) -> str:
    _, relative = resolve_project_path(root, value)
    forbidden = {canonical_path_text(path) for path in forbidden_files}
    allowed = {canonical_path_text(path) for path in allowed_files}
    if relative in forbidden:
        raise PolicyError("forbidden file path")
    if relative not in allowed:
        raise PolicyError("file path is not on the allowed list")
    return relative


def validate_project_id(value: str) -> str:
    candidate = value.strip().casefold()
    if _PROJECT_ID_SLUG.fullmatch(candidate):
        return candidate
    if _UUID_TEXT.fullmatch(candidate):
        return str(uuid.UUID(candidate))
    raise PolicyError("project_id must be a safe slug or UUID")


def validate_task_id(value: str) -> str:
    candidate = value.strip().casefold()
    if _PROJECT_ID_SLUG.fullmatch(candidate):
        return candidate
    if not _UUID_TEXT.fullmatch(candidate):
        raise PolicyError("task_id must be a UUID")
    return str(uuid.UUID(candidate))


def validate_artifact_name(value: str) -> str:
    candidate = Path(value).as_posix().casefold()
    if candidate not in ALLOWED_ARTIFACT_NAMES:
        raise PolicyError("artifact name is not allowed")
    return candidate


def find_forbidden_root_reference(payload: Any, forbidden_roots: Sequence[str | Path] | None = None) -> str | None:
    needles = tuple(
        (_normalize_text(root), _normalize_text(root).casefold().replace("/", "\\").rstrip("\\"))
        for root in configured_forbidden_roots(forbidden_roots)
    )
    return _find_forbidden_root_reference(payload, needles)


def _find_forbidden_root_reference(payload: Any, needles: tuple[tuple[str, str], ...]) -> str | None:
    if isinstance(payload, str):
        normalized = payload.casefold().replace("/", "\\")
        for display, needle in needles:
            if not needle:
                continue
            start = normalized.find(needle)
            while start != -1:
                end = start + len(needle)
                before_ok = start == 0 or normalized[start - 1] in "\\/ \t\r\n'\";:,([{"
                after_ok = end == len(normalized) or normalized[end] in "\\/ \t\r\n'\";:,)]}"
                if before_ok and after_ok:
                    return display
                start = normalized.find(needle, start + 1)
        return None
    if isinstance(payload, dict):
        for value in payload.values():
            match = _find_forbidden_root_reference(value, needles)
            if match:
                return match
        return None
    if isinstance(payload, (list, tuple, set)):
        for value in payload:
            match = _find_forbidden_root_reference(value, needles)
            if match:
                return match
        return None
    return None


def model_choices(models: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Keep the server catalogue order and only expose server advertised efforts."""
    result = []
    for item in models:
        if item.get("hidden"):
            continue
        result.append({
            "id": item["id"],
            "model": item.get("model", item["id"]),
            "display_name": item.get("displayName", item["id"]),
            "default_effort": item.get("defaultReasoningEffort"),
            "efforts": [entry["reasoningEffort"] for entry in item.get("supportedReasoningEfforts", [])],
        })
    return result


def validate_selection(models: list[dict[str, Any]], model: str, effort: str) -> None:
    available = {entry["id"]: entry for entry in model_choices(models)}
    candidate = available.get(model)
    if not candidate:
        raise PolicyError("selected model is not available in the current app-server")
    if effort == "ultra":
        raise PolicyError("Ultra is locked in this release")
    if effort not in candidate["efforts"]:
        raise PolicyError("selected effort is not supported by the chosen model")


def validate_workspace(
    root: str,
    permission: str,
    task_text: str,
    forbidden_roots: Sequence[str | Path] | None = None,
) -> Path:
    path = validate_workspace_root(root, forbidden_roots=forbidden_roots)
    if permission not in {"read-only", "workspace-write"}:
        raise PolicyError("permission must be read-only or workspace-write")
    lowered = task_text.lower()
    if permission == "workspace-write" and any(term in lowered for term in HIGH_RISK_TERMS):
        raise PolicyError("high-risk workspace-write tasks are blocked in the first release")
    return path


def validate_decision_for_run(decision: Decision, permission: str) -> None:
    if decision.decision == "hold":
        raise PolicyError("decision hold is not executable")
    if decision.decision == "evidence_only" and permission != "read-only":
        raise PolicyError("evidence_only is only allowed for read-only runs")
    if permission == "workspace-write" and not decision.allowed_files:
        raise PolicyError("workspace-write runs need an allowed file list")


def budget_for(level: str) -> dict[str, int]:
    try:
        return BUDGETS[level]
    except KeyError as exc:
        raise PolicyError("unknown budget level") from exc


def budget_for_task_class(task_class: str) -> tuple[str, dict[str, int]]:
    try:
        level = ROUTE_PLAN_BUDGET_LEVELS[task_class.strip().upper()]
    except (AttributeError, KeyError) as exc:
        raise PolicyError("unknown task class for Route Plan budget") from exc
    return level, dict(budget_for(level))


def parse_git_porcelain_v2_z(payload: bytes | str) -> list[str]:
    data = payload.encode("utf-8") if isinstance(payload, str) else payload
    records = data.split(b"\0")
    paths: list[str] = []
    index = 0
    while index < len(records):
        record = records[index]
        index += 1
        if not record:
            continue
        kind = record[:1]
        if kind in {b"1", b"u"}:
            parts = record.split(b" ", 8)
            if len(parts) >= 9:
                paths.append(canonical_path_text(parts[8].decode("utf-8", errors="replace")))
        elif kind == b"2":
            parts = record.split(b" ", 9)
            if len(parts) >= 10:
                paths.append(canonical_path_text(parts[9].decode("utf-8", errors="replace")))
            if index < len(records) and records[index]:
                paths.append(canonical_path_text(records[index].decode("utf-8", errors="replace")))
                index += 1
        elif kind in {b"?", b"!"}:
            parts = record.split(b" ", 1)
            if len(parts) == 2:
                paths.append(canonical_path_text(parts[1].decode("utf-8", errors="replace")))
    return paths


def collect_git_paths(root: str | Path) -> set[str]:
    try:
        completed = subprocess.run(
            ["git", "status", "--porcelain=v2", "-z", "--untracked-files=all"],
            cwd=root,
            capture_output=True,
            text=False,
            timeout=8,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return set()
    if completed.returncode:
        return set()
    return set(parse_git_porcelain_v2_z(completed.stdout))
