from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .policy import PolicyError, resolve_project_path, validate_artifact_name, validate_project_id, validate_task_id


class Store:
    def __init__(self, root: Path):
        self.root = Path(root).expanduser().resolve(strict=False)
        self.root.mkdir(parents=True, exist_ok=True)
        self.db_path = self.root / "app.db"
        with self._connection() as conn:
            conn.execute(
                """CREATE TABLE IF NOT EXISTS tasks (
                    id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    thread_id TEXT,
                    turn_id TEXT,
                    payload TEXT NOT NULL
                )"""
            )

    def _connection(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    def _validate_ids(self, task_id: str, project_id: str) -> tuple[str, str]:
        return validate_task_id(task_id), validate_project_id(project_id)

    def save_task(
        self,
        task_id: str,
        project_id: str,
        status: str,
        payload: dict[str, Any],
        thread_id: str | None = None,
        turn_id: str | None = None,
    ) -> None:
        task_id, project_id = self._validate_ids(task_id, project_id)
        now = datetime.now(timezone.utc).isoformat()
        with self._connection() as conn:
            conn.execute(
                """INSERT INTO tasks (id, project_id, created_at, status, thread_id, turn_id, payload)
                   VALUES (?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(id) DO UPDATE SET status=excluded.status, thread_id=excluded.thread_id,
                   turn_id=excluded.turn_id, payload=excluded.payload""",
                (task_id, project_id, now, status, thread_id, turn_id, json.dumps(payload, ensure_ascii=False)),
            )

    def write_artifact(self, project_id: str, task_id: str, name: str, content: str | dict[str, Any]) -> Path:
        task_id, project_id = self._validate_ids(task_id, project_id)
        artifact = validate_artifact_name(name)
        relative = Path("projects") / project_id / "tasks" / task_id / artifact
        _, relative_key = resolve_project_path(self.root, relative.as_posix())
        path = self.root / Path(relative_key)
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, dict):
            path.write_text(json.dumps(content, ensure_ascii=False, indent=2), encoding="utf-8")
        else:
            path.write_text(content, encoding="utf-8")
        return path
