from __future__ import annotations

import os
import re
import hashlib
import json
import shlex
import subprocess
import uuid
from dataclasses import asdict, dataclass
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
            "risk", "parallel_audit", "independent_axes",
        }
        unexpected = sorted(set(payload) - known)
        if unexpected:
            raise PolicyError(f"decision JSON has unknown fields: {', '.join(unexpected)}")
        required = ("decision", "task_class", "recommended_model", "recommended_effort")
        missing = [field for field in required if not isinstance(payload.get(field), str) or not payload[field].strip()]
        if missing:
            raise PolicyError(f"decision JSON is missing required fields: {', '.join(missing)}")
        lists = {}
        for field in ("allowed_files", "forbidden_files", "validation_commands", "stop_conditions"):
            value = payload.get(field, [])
            if not isinstance(value, list) or not all(isinstance(item, str) and item.strip() for item in value):
                raise PolicyError(f"{field} must be a non-empty string list")
            lists[field] = [item.strip() for item in value]
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
