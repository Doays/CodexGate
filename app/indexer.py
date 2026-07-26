from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path
from typing import Any

from .policy import validate_workspace_root


EXCLUDED_DIRS = {".git", ".codex", "node_modules", "dist", "build", "cache", "backup", "obsolete", ".venv", "__pycache__"}
MAX_FILES = 4000
MAX_FILE_BYTES = 128 * 1024


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(64 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git_summary(root: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "status", "--short"], cwd=root, text=True, capture_output=True, timeout=8, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return "Git 상태를 확인할 수 없습니다."
    if result.returncode:
        return "Git 저장소가 아니거나 Git 상태를 읽을 수 없습니다."
    return result.stdout.strip() or "변경 사항 없음"


def collect_metadata(root: Path, limit: int = 120) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for directory, dirs, files in os.walk(root):
        dirs[:] = [name for name in dirs if name.lower() not in EXCLUDED_DIRS]
        for filename in files:
            if len(records) >= MAX_FILES:
                return records
            path = Path(directory) / filename
            try:
                stat = path.stat()
            except OSError:
                continue
            if stat.st_size > MAX_FILE_BYTES:
                continue
            try:
                relative = path.relative_to(root).as_posix()
                checksum = _sha256(path)
            except (OSError, ValueError):
                continue
            records.append({
                "path": relative,
                "extension": path.suffix.lower() or "(none)",
                "bytes": stat.st_size,
                "mtime": int(stat.st_mtime),
                "sha256": checksum,
            })
    records.sort(key=lambda item: item["path"])
    return records[:limit]


def build_web_packet(project_name: str, root: Path, task: str, files: list[dict[str, Any]], models: list[dict[str, Any]]) -> str:
    available_models = [
        f"- {entry.get('displayName', entry.get('id'))} ({entry.get('id')}): "
        + ", ".join(option.get("reasoningEffort", "") for option in entry.get("supportedReasoningEfforts", []))
        for entry in models if not entry.get("hidden")
    ]
    file_lines = [f"- {entry['path']} | {entry['bytes']} bytes | sha256:{entry['sha256'][:16]}…" for entry in files]
    return "\n".join([
        "# Codex Gate 상담 패킷",
        f"프로젝트: {project_name}",
        f"정본 경로: {root}",
        "", "## 작업 목표", task.strip(),
        "", "## 로컬 증거", f"Git 상태: {git_summary(root)}", "파일 메타데이터:", *file_lines,
        "", "## 사용 가능한 Codex 모델", *available_models,
        "", "## 판단 요청",
        "아래 JSON 형식으로만 답하세요. 허용 파일은 정본 경로 기준 상대 경로로 명시하고, "
        "DB migration·운영 변경·허용 파일 외 수정이 필요하면 decision을 hold로 설정하세요.",
        '{"decision":"execute|hold|evidence_only","task_class":"...","recommended_model":"...",'
        '"recommended_effort":"...","allowed_files":[],"forbidden_files":[],"validation_commands":[],"stop_conditions":[]}',
    ])


def preflight(project_name: str, root: Path, task: str, models: list[dict[str, Any]]) -> dict[str, Any]:
    root = validate_workspace_root(root)
    files = collect_metadata(root)
    risk = "R3" if any(token in task.lower() for token in ("production", "vps", "database", "주문", "인증")) else "R2"
    return {
        "risk": risk,
        "candidate_files": len(files),
        "estimated_context": min(20_000, 400 + len(files) * 130),
        "files": files,
        "web_packet": build_web_packet(project_name, root, task, files, models),
        "git_status": git_summary(root),
    }
