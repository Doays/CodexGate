from __future__ import annotations

import os
import re
import subprocess
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Sequence


BUDGETS = {
    "tiny": {"tokens": 250_000, "tools": 15, "changed_files": 2},
    "standard": {"tokens": 750_000, "tools": 30, "changed_files": 5},
    "complex": {"tokens": 2_000_000, "tools": 50, "changed_files": 10},
    "critical": {"tokens": 4_000_000, "tools": 60, "changed_files": 10},
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

    @classmethod
    def from_json(cls, payload: dict[str, Any]) -> "Decision":
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
        return cls(
            decision=payload["decision"].strip(),
            task_class=payload["task_class"].strip(),
            recommended_model=payload["recommended_model"].strip(),
            recommended_effort=payload["recommended_effort"].strip(),
            **lists,
        )

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def canonical_path_text(value: str | Path) -> str:
    return Path(value).as_posix().casefold()


def _path_key(value: str | Path) -> str:
    return Path(value).expanduser().resolve(strict=False).as_posix().casefold().rstrip("/")


def _is_within_root(root: str | Path, candidate: str | Path) -> bool:
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


def validate_workspace_root(root: str | Path, forbidden_roots: Sequence[str | Path] | None = None) -> Path:
    root_path = Path(root).expanduser().resolve(strict=False)
    for forbidden in configured_forbidden_roots(forbidden_roots):
        if _is_within_root(forbidden, root_path):
            raise PolicyError(f"workspace root is blocked: {root_path}")
    if not root_path.is_dir():
        raise PolicyError("project root directory does not exist")
    return root_path


def resolve_project_path(root: str | Path, value: str) -> tuple[Path, str]:
    """Resolve a candidate path and reject traversal, symlink, junction, and volume escapes."""
    root_path = Path(root).expanduser().resolve(strict=False)
    raw = Path(value).expanduser()
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
