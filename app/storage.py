from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

from .policy import (
    PolicyError,
    canonical_json,
    resolve_project_path,
    sha256_json,
    validate_artifact_name,
    validate_project_id,
    validate_task_id,
)


DEFAULT_USAGE_THRESHOLDS = {"conserve": 70, "critical": 90, "blocked": 100}
MODEL_STATUSES = frozenset({"AVAILABLE", "LIMITED", "DEPLETED", "UNKNOWN", "DISABLED"})


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sparse_merge(existing: Any, update: Any) -> Any:
    """Merge a rolling server update without treating null as a reset."""
    if isinstance(existing, Mapping) and isinstance(update, Mapping):
        merged = dict(existing)
        for key, value in update.items():
            if value is None:
                continue
            merged[key] = _sparse_merge(merged.get(key), value)
        return merged
    return update


def _mask_email(value: Any) -> str | None:
    if not isinstance(value, str) or "@" not in value:
        return None
    local, domain = value.split("@", 1)
    if not local:
        return f"***@{domain}"
    return f"{local[0]}***@{domain}"


def _rate_window(value: Any) -> dict[str, int | None] | None:
    if not isinstance(value, Mapping):
        return None
    used = value.get("usedPercent")
    if not isinstance(used, int):
        return None
    return {
        "usedPercent": used,
        "resetsAt": value.get("resetsAt") if isinstance(value.get("resetsAt"), int) else None,
        "windowDurationMins": value.get("windowDurationMins") if isinstance(value.get("windowDurationMins"), int) else None,
    }


def _rate_snapshot(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    result: dict[str, Any] = {}
    for field in ("limitId", "limitName", "planType", "rateLimitReachedType", "spendControlReached"):
        item = value.get(field)
        if isinstance(item, (str, bool)) or item is None:
            result[field] = item
    for field in ("primary", "secondary"):
        window = _rate_window(value.get(field))
        if window is not None:
            result[field] = window
    return result


def account_state_details_from_snapshot(snapshot: Mapping[str, Any] | None, thresholds: Mapping[str, int]) -> dict[str, Any]:
    """Classify all account-wide windows without inferring any per-model balance."""
    if not isinstance(snapshot, Mapping):
        return {
            "status": "UNKNOWN", "maximum_used_percent": None, "maximum_window": None,
            "windows": [], "blocking_reason": None,
        }

    snapshots: list[tuple[str, Mapping[str, Any]]] = []
    if isinstance(snapshot.get("rateLimits"), Mapping):
        snapshots.append(("rateLimits", snapshot["rateLimits"]))
    elif any(key in snapshot for key in ("primary", "secondary", "spendControlReached", "rateLimitReachedType")):
        snapshots.append(("rateLimits", snapshot))
    by_limit_id = snapshot.get("rateLimitsByLimitId")
    if isinstance(by_limit_id, Mapping):
        for limit_id, value in by_limit_id.items():
            if isinstance(value, Mapping):
                snapshots.append((f"rateLimitsByLimitId.{limit_id}", value))

    windows: list[dict[str, Any]] = []
    blocking_reason: str | None = None
    for source, rate_limit in snapshots:
        if rate_limit.get("spendControlReached") is True:
            blocking_reason = f"{source}.spendControlReached"
        reached_type = rate_limit.get("rateLimitReachedType")
        if isinstance(reached_type, str) and reached_type:
            blocking_reason = f"{source}.rateLimitReachedType={reached_type}"
        for name in ("primary", "secondary"):
            window = rate_limit.get(name)
            used_percent = window.get("usedPercent") if isinstance(window, Mapping) else None
            if isinstance(used_percent, int):
                windows.append({"source": source, "window": name, "used_percent": used_percent})

    maximum_window = max(windows, key=lambda item: item["used_percent"], default=None)
    maximum_used_percent = maximum_window["used_percent"] if maximum_window else None
    if blocking_reason:
        status = "BLOCKED"
    elif maximum_used_percent is None:
        status = "UNKNOWN"
    elif maximum_used_percent >= thresholds["blocked"]:
        status = "BLOCKED"
    elif maximum_used_percent >= thresholds["critical"]:
        status = "CRITICAL"
    elif maximum_used_percent >= thresholds["conserve"]:
        status = "CONSERVE"
    else:
        status = "NORMAL"
    return {
        "status": status,
        "maximum_used_percent": maximum_used_percent,
        "maximum_window": maximum_window,
        "windows": windows,
        "blocking_reason": blocking_reason,
    }


def account_state_from_snapshot(snapshot: Mapping[str, Any] | None, thresholds: Mapping[str, int]) -> str:
    return account_state_details_from_snapshot(snapshot, thresholds)["status"]


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
            conn.execute(
                """CREATE TABLE IF NOT EXISTS account_snapshots (
                    kind TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    captured_at TEXT NOT NULL,
                    payload TEXT NOT NULL
                )"""
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS account_settings (
                    name TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )"""
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS model_catalog (
                    model_id TEXT PRIMARY KEY,
                    position INTEGER NOT NULL,
                    payload TEXT NOT NULL,
                    captured_at TEXT NOT NULL
                )"""
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS model_manual_status (
                    model_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )"""
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS route_plans (
                    plan_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    decision_hash TEXT NOT NULL,
                    task_hash TEXT NOT NULL,
                    root TEXT NOT NULL,
                    project_id TEXT NOT NULL,
                    account_snapshot_at TEXT,
                    model_catalog_hash TEXT NOT NULL,
                    status TEXT NOT NULL,
                    final_model TEXT,
                    final_effort TEXT,
                    bridge_idempotency_key TEXT,
                    payload TEXT NOT NULL,
                    integrity_hash TEXT NOT NULL
                )"""
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS route_plan_uses (
                    plan_id TEXT PRIMARY KEY REFERENCES route_plans(plan_id),
                    used_at TEXT NOT NULL,
                    run_id TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'claimed',
                    claimed_at TEXT,
                    started_at TEXT,
                    failed_at TEXT,
                    completed_at TEXT,
                    error TEXT
                )"""
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS evidence_capsules (
                    plan_id TEXT PRIMARY KEY REFERENCES route_plans(plan_id),
                    capsule_id TEXT,
                    status TEXT NOT NULL,
                    capsule_hash TEXT,
                    payload TEXT NOT NULL,
                    integrity_hash TEXT NOT NULL
                )"""
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS isolation_probe_results (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    status TEXT NOT NULL,
                    checked_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    codex_version TEXT,
                    schema_sha256 TEXT,
                    payload TEXT NOT NULL,
                    integrity_hash TEXT NOT NULL
                )"""
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS bridge_tasks (
                    task_id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    active_action TEXT NOT NULL,
                    pending_nonce TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    copied_at TEXT,
                    received_at TEXT,
                    response_hash TEXT,
                    payload TEXT NOT NULL,
                    integrity_hash TEXT NOT NULL
                )"""
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS bridge_nonces (
                    nonce TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL REFERENCES bridge_tasks(task_id),
                    phase TEXT NOT NULL,
                    packet_type TEXT NOT NULL,
                    issued_at TEXT NOT NULL,
                    consumed_at TEXT,
                    response_hash TEXT,
                    claimed_at TEXT,
                    completed_at TEXT,
                    failed_at TEXT,
                    error_code TEXT
                )"""
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS bridge_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_id TEXT NOT NULL REFERENCES bridge_tasks(task_id),
                    event_type TEXT NOT NULL,
                    occurred_at TEXT NOT NULL,
                    response_hash TEXT
                )"""
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS evidence_requests (
                    request_id TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL REFERENCES bridge_tasks(task_id),
                    state TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    integrity_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )"""
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS evidence_results (
                    request_id TEXT PRIMARY KEY REFERENCES evidence_requests(request_id),
                    task_id TEXT NOT NULL REFERENCES bridge_tasks(task_id),
                    state TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    result_hash TEXT,
                    integrity_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )"""
            )
            self._migrate_route_plan_uses(conn)
            self._migrate_route_plans(conn)
            self._migrate_bridge_nonces(conn)

    def _connection(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    @staticmethod
    def _migrate_route_plan_uses(conn: sqlite3.Connection) -> None:
        """Add lifecycle columns without reopening a previously created local database."""
        existing = {row[1] for row in conn.execute("PRAGMA table_info(route_plan_uses)")}
        additions = {
            "status": "TEXT NOT NULL DEFAULT 'completed'",
            "claimed_at": "TEXT",
            "started_at": "TEXT",
            "failed_at": "TEXT",
            "completed_at": "TEXT",
            "error": "TEXT",
        }
        for name, declaration in additions.items():
            if name not in existing:
                conn.execute(f"ALTER TABLE route_plan_uses ADD COLUMN {name} {declaration}")
        conn.execute(
            """UPDATE route_plan_uses
               SET claimed_at = COALESCE(claimed_at, used_at),
                   status = COALESCE(status, 'completed')
               WHERE claimed_at IS NULL OR status IS NULL"""
        )

    @staticmethod
    def _migrate_route_plans(conn: sqlite3.Connection) -> None:
        existing = {row[1] for row in conn.execute("PRAGMA table_info(route_plans)")}
        if "bridge_idempotency_key" not in existing:
            conn.execute("ALTER TABLE route_plans ADD COLUMN bridge_idempotency_key TEXT")
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS route_plans_bridge_key ON route_plans(bridge_idempotency_key) WHERE bridge_idempotency_key IS NOT NULL")

    @staticmethod
    def _migrate_bridge_nonces(conn: sqlite3.Connection) -> None:
        existing = {row[1] for row in conn.execute("PRAGMA table_info(bridge_nonces)")}
        for name, declaration in {
            "response_hash": "TEXT", "claimed_at": "TEXT", "completed_at": "TEXT",
            "failed_at": "TEXT", "error_code": "TEXT",
        }.items():
            if name not in existing:
                conn.execute(f"ALTER TABLE bridge_nonces ADD COLUMN {name} {declaration}")

    def _validate_ids(self, task_id: str, project_id: str) -> tuple[str, str]:
        return validate_task_id(task_id), validate_project_id(project_id)

    def create_bridge_task(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        record = dict(payload)
        required = {"task_id", "project_id", "status", "active_action", "phase", "packet_type", "pending_nonce", "created_at", "updated_at"}
        missing = sorted(required - record.keys())
        if missing:
            raise PolicyError(f"Bridge task is missing fields: {', '.join(missing)}")
        task_id, project_id = self._validate_ids(str(record["task_id"]), str(record["project_id"]))
        record["task_id"] = task_id
        record["project_id"] = project_id
        integrity_hash = sha256_json(record)
        with self._connection() as conn:
            conn.execute(
                """INSERT INTO bridge_tasks
                   (task_id, project_id, status, active_action, pending_nonce, created_at, updated_at,
                    copied_at, received_at, response_hash, payload, integrity_hash)
                   VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, ?, ?)""",
                (task_id, project_id, record["status"], record["active_action"], record["pending_nonce"],
                 record["created_at"], record["updated_at"],
                 json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")), integrity_hash),
            )
            self._issue_bridge_nonce(conn, task_id, str(record["pending_nonce"]), str(record["phase"]), str(record["packet_type"]))
        return {**record, "integrity_hash": integrity_hash}

    @staticmethod
    def _issue_bridge_nonce(conn: sqlite3.Connection, task_id: str, nonce: str, phase: str, packet_type: str) -> None:
        conn.execute(
            """INSERT INTO bridge_nonces (nonce, task_id, phase, packet_type, issued_at, consumed_at, response_hash, claimed_at, completed_at)
               VALUES (?, ?, ?, ?, ?, NULL, NULL, NULL, NULL)""",
            (nonce, task_id, phase, packet_type, _now()),
        )

    def _persist_bridge_task(
        self,
        conn: sqlite3.Connection,
        normalized_task_id: str,
        record: Mapping[str, Any],
        *,
        copied: bool = False,
        received_hash: str | None = None,
    ) -> None:
        integrity_hash = sha256_json(record)
        if record.get("pending_nonce"):
            existing = conn.execute("SELECT 1 FROM bridge_nonces WHERE nonce = ?", (record["pending_nonce"],)).fetchone()
            if not existing:
                self._issue_bridge_nonce(conn, normalized_task_id, str(record["pending_nonce"]), str(record["phase"]), str(record["packet_type"]))
        copied_at = _now() if copied else None
        received_at = _now() if received_hash is not None else None
        conn.execute(
            """UPDATE bridge_tasks SET status=?, active_action=?, pending_nonce=?, updated_at=?,
               copied_at=COALESCE(?, copied_at), received_at=COALESCE(?, received_at),
               response_hash=COALESCE(?, response_hash), payload=?, integrity_hash=? WHERE task_id=?""",
            (record["status"], record["active_action"], record["pending_nonce"], record["updated_at"],
             copied_at, received_at, received_hash,
             json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")), integrity_hash, normalized_task_id),
        )
        if copied:
            conn.execute("INSERT INTO bridge_history (task_id, event_type, occurred_at, response_hash) VALUES (?, 'copied', ?, NULL)", (normalized_task_id, copied_at))
        if received_hash is not None:
            conn.execute("INSERT INTO bridge_history (task_id, event_type, occurred_at, response_hash) VALUES (?, 'received', ?, ?)", (normalized_task_id, received_at, received_hash))

    def bridge_response_duplicate(self, task_id: str, nonce: str, response_hash: str) -> bool:
        normalized_task_id = validate_task_id(task_id)
        with self._connection() as conn:
            row = conn.execute(
                "SELECT consumed_at, response_hash FROM bridge_nonces WHERE task_id = ? AND nonce = ?",
                (normalized_task_id, nonce),
            ).fetchone()
        return bool(row and row[0] and row[1] == response_hash)

    def claim_bridge_response(self, task_id: str, nonce: str, response_hash: str, *, task_payload: Mapping[str, Any] | None = None, received_hash: str | None = None) -> str:
        """Atomically consume a response nonce before a Bridge side effect begins."""
        normalized_task_id = validate_task_id(task_id)
        with self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT consumed_at, response_hash FROM bridge_nonces WHERE task_id = ? AND nonce = ?",
                (normalized_task_id, nonce),
            ).fetchone()
            if not row:
                raise PolicyError("Bridge nonce is invalid")
            if row[0]:
                if row[1] == response_hash:
                    return "duplicate"
                raise PolicyError("Bridge nonce was already used")
            now = _now()
            cursor = conn.execute(
                """UPDATE bridge_nonces SET consumed_at = ?, claimed_at = ?, response_hash = ?
                   WHERE task_id = ? AND nonce = ? AND consumed_at IS NULL""",
                (now, now, response_hash, normalized_task_id, nonce),
            )
            if cursor.rowcount != 1:
                raise PolicyError("Bridge nonce claim was rejected")
            if task_payload is not None:
                record = dict(task_payload)
                if record.get("task_id") != normalized_task_id:
                    raise PolicyError("Bridge task id does not match")
                self._persist_bridge_task(conn, normalized_task_id, record, received_hash=received_hash)
        return "claimed"

    def fail_bridge_response(
        self,
        task_id: str,
        nonce: str,
        response_hash: str,
        *,
        task_payload: Mapping[str, Any],
        received_hash: str | None,
        error_code: str,
    ) -> str:
        """Atomically consume and fail a response nonce when the pasted response is no longer usable."""
        normalized_task_id = validate_task_id(task_id)
        with self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT consumed_at, response_hash, completed_at, failed_at FROM bridge_nonces WHERE task_id = ? AND nonce = ?",
                (normalized_task_id, nonce),
            ).fetchone()
            if not row:
                raise PolicyError("Bridge nonce is invalid")
            if row[0]:
                if row[1] == response_hash:
                    return "duplicate"
                raise PolicyError("Bridge nonce was already used")
            now = _now()
            cursor = conn.execute(
                """UPDATE bridge_nonces
                   SET consumed_at = ?, claimed_at = ?, response_hash = ?, failed_at = ?, error_code = ?
                   WHERE task_id = ? AND nonce = ? AND consumed_at IS NULL AND completed_at IS NULL AND failed_at IS NULL""",
                (now, now, response_hash, now, error_code, normalized_task_id, nonce),
            )
            if cursor.rowcount != 1:
                raise PolicyError("Bridge nonce failure was rejected")
            record = dict(task_payload)
            if record.get("task_id") != normalized_task_id:
                raise PolicyError("Bridge task id does not match")
            self._persist_bridge_task(conn, normalized_task_id, record, received_hash=received_hash)
        return "failed"

    def recover_bridge_processing_tasks(self, *, hold_reason: str, error_code: str) -> list[str]:
        recovered: list[str] = []
        with self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            rows = conn.execute(
                """SELECT task_id, payload, integrity_hash
                   FROM bridge_tasks
                   WHERE status = 'PROCESSING_RESPONSE'
                   ORDER BY updated_at DESC"""
            ).fetchall()
            for task_id, payload_text, integrity_hash in rows:
                try:
                    record = json.loads(payload_text)
                except json.JSONDecodeError as exc:
                    raise PolicyError("Bridge task payload was modified") from exc
                if not isinstance(record, dict) or sha256_json(record) != integrity_hash:
                    raise PolicyError("Bridge task integrity check failed")
                if record.get("task_id") != task_id or record.get("status") != "PROCESSING_RESPONSE":
                    raise PolicyError("Bridge task metadata was modified")
                pending_nonce = record.get("pending_nonce")
                if not isinstance(pending_nonce, str) or not pending_nonce:
                    continue
                nonce_row = conn.execute(
                    """SELECT consumed_at, completed_at, failed_at
                       FROM bridge_nonces WHERE task_id = ? AND nonce = ?""",
                    (task_id, pending_nonce),
                ).fetchone()
                if not nonce_row:
                    continue
                consumed_at, completed_at, failed_at = nonce_row
                if completed_at or failed_at or not consumed_at:
                    continue
                now = _now()
                cursor = conn.execute(
                    """UPDATE bridge_nonces SET failed_at = ?, error_code = ?
                       WHERE task_id = ? AND nonce = ? AND consumed_at IS NOT NULL AND completed_at IS NULL AND failed_at IS NULL""",
                    (now, error_code, task_id, pending_nonce),
                )
                if cursor.rowcount != 1:
                    continue
                updated = {
                    **record,
                    "status": "HOLD",
                    "active_action": "restart",
                    "pending_nonce": None,
                    "hold_reason": hold_reason,
                    "error_code": error_code,
                    "updated_at": now,
                }
                self._persist_bridge_task(conn, task_id, updated)
                recovered.append(task_id)
        return recovered

    def recent_bridge_tasks(self, limit: int = 12) -> list[dict[str, Any]]:
        if limit < 1 or limit > 100:
            raise PolicyError("Bridge task list limit is invalid")
        # HOLD, REDESIGN, and ROLLBACK still need an explicit user restart, so they are recoverable work.
        terminal = ("SUCCESS",)
        placeholders = ", ".join("?" for _ in terminal)
        with self._connection() as conn:
            rows = conn.execute(
                f"SELECT task_id FROM bridge_tasks WHERE status NOT IN ({placeholders}) ORDER BY updated_at DESC LIMIT ?",
                (*terminal, limit),
            ).fetchall()
        return [self.load_bridge_task(row[0]) for row in rows]

    def load_bridge_task(self, task_id: str) -> dict[str, Any]:
        normalized_task_id = validate_task_id(task_id)
        with self._connection() as conn:
            row = conn.execute(
                """SELECT project_id, status, active_action, pending_nonce, created_at, updated_at,
                          copied_at, received_at, response_hash, payload, integrity_hash
                   FROM bridge_tasks WHERE task_id = ?""", (normalized_task_id,),
            ).fetchone()
        if not row:
            raise PolicyError("Bridge task was not found")
        try:
            record = json.loads(row[9])
        except json.JSONDecodeError as exc:
            raise PolicyError("Bridge task payload was modified") from exc
        fixed = {
            "task_id": normalized_task_id, "project_id": row[0], "status": row[1], "active_action": row[2],
            "pending_nonce": row[3], "created_at": row[4], "updated_at": row[5],
        }
        if not isinstance(record, dict) or any(record.get(key) != value for key, value in fixed.items()):
            raise PolicyError("Bridge task metadata was modified")
        if sha256_json(record) != row[10]:
            raise PolicyError("Bridge task integrity check failed")
        return {**record, "copied_at": row[6], "received_at": row[7], "response_hash": row[8], "integrity_hash": row[10]}

    def update_bridge_task(
        self,
        task_id: str,
        payload: Mapping[str, Any],
        *,
        copied: bool = False,
        received_hash: str | None = None,
        consume_nonce: str | None = None,
        complete_nonce: str | None = None,
        complete_nonce_response_hash: str | None = None,
        fail_nonce: str | None = None,
        fail_nonce_response_hash: str | None = None,
        fail_nonce_error_code: str | None = None,
    ) -> dict[str, Any]:
        record = dict(payload)
        normalized_task_id = validate_task_id(task_id)
        if record.get("task_id") != normalized_task_id:
            raise PolicyError("Bridge task id does not match")
        with self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            if consume_nonce is not None:
                cursor = conn.execute(
                    "UPDATE bridge_nonces SET consumed_at = ? WHERE nonce = ? AND task_id = ? AND consumed_at IS NULL",
                    (_now(), consume_nonce, normalized_task_id),
                )
                if cursor.rowcount != 1:
                    raise PolicyError("Bridge nonce was already used or is invalid")
            if record.get("pending_nonce"):
                existing = conn.execute("SELECT 1 FROM bridge_nonces WHERE nonce = ?", (record["pending_nonce"],)).fetchone()
                if not existing:
                    self._issue_bridge_nonce(conn, normalized_task_id, str(record["pending_nonce"]), str(record["phase"]), str(record["packet_type"]))
            if complete_nonce is not None:
                row = conn.execute(
                    "SELECT consumed_at, response_hash, completed_at, failed_at FROM bridge_nonces WHERE task_id = ? AND nonce = ?",
                    (normalized_task_id, complete_nonce),
                ).fetchone()
                if not row or not row[0]:
                    raise PolicyError("Bridge nonce was already used or is invalid")
                if complete_nonce_response_hash is not None and row[1] != complete_nonce_response_hash:
                    raise PolicyError("Bridge nonce was already used or is invalid")
                cursor = conn.execute(
                    """UPDATE bridge_nonces SET completed_at = ?
                       WHERE task_id = ? AND nonce = ? AND consumed_at IS NOT NULL AND completed_at IS NULL AND failed_at IS NULL""",
                    (_now(), normalized_task_id, complete_nonce),
                )
                if cursor.rowcount != 1:
                    raise PolicyError("Bridge nonce completion was rejected")
            if fail_nonce is not None:
                row = conn.execute(
                    "SELECT consumed_at, response_hash, completed_at, failed_at FROM bridge_nonces WHERE task_id = ? AND nonce = ?",
                    (normalized_task_id, fail_nonce),
                ).fetchone()
                if not row or not row[0]:
                    raise PolicyError("Bridge nonce was already used or is invalid")
                if fail_nonce_response_hash is not None and row[1] != fail_nonce_response_hash:
                    raise PolicyError("Bridge nonce was already used or is invalid")
                cursor = conn.execute(
                    """UPDATE bridge_nonces SET failed_at = ?, error_code = ?
                       WHERE task_id = ? AND nonce = ? AND consumed_at IS NOT NULL AND completed_at IS NULL AND failed_at IS NULL""",
                    (_now(), fail_nonce_error_code, normalized_task_id, fail_nonce),
                )
                if cursor.rowcount != 1:
                    raise PolicyError("Bridge nonce failure was rejected")
            self._persist_bridge_task(conn, normalized_task_id, record, copied=copied, received_hash=received_hash)
        return self.load_bridge_task(normalized_task_id)

    def bridge_history(self, task_id: str) -> list[dict[str, Any]]:
        normalized_task_id = validate_task_id(task_id)
        with self._connection() as conn:
            rows = conn.execute(
                "SELECT event_type, occurred_at, response_hash FROM bridge_history WHERE task_id = ? ORDER BY id", (normalized_task_id,)
            ).fetchall()
        return [{"event_type": row[0], "occurred_at": row[1], "response_hash": row[2]} for row in rows]

    def create_evidence_requests(self, task_id: str, requests: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
        """Persist structured web requests. Replays are content-idempotent."""
        normalized_task_id = validate_task_id(task_id)
        now = _now()
        records: list[dict[str, Any]] = []
        with self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            for request in requests:
                record = dict(request)
                request_id = str(record.get("request_id", ""))
                if not request_id:
                    raise PolicyError("Evidence request id is invalid")
                record.update({"request_id": request_id, "task_id": normalized_task_id, "state": record.get("state", "REQUESTED"), "updated_at": now})
                record.setdefault("created_at", now)
                digest = sha256_json(record)
                existing = conn.execute("SELECT payload, integrity_hash FROM evidence_requests WHERE request_id = ?", (request_id,)).fetchone()
                if existing:
                    if existing[1] != sha256_json(json.loads(existing[0])):
                        raise PolicyError("Evidence request integrity check failed")
                    if json.loads(existing[0]).get("task_id") != normalized_task_id:
                        raise PolicyError("Evidence request belongs to another task")
                    records.append(json.loads(existing[0]))
                    continue
                conn.execute("INSERT INTO evidence_requests (request_id, task_id, state, payload, integrity_hash, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)", (request_id, normalized_task_id, record["state"], json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")), digest, record["created_at"], now))
                records.append(record)
        return records

    def evidence_requests(self, task_id: str) -> list[dict[str, Any]]:
        normalized_task_id = validate_task_id(task_id)
        with self._connection() as conn:
            rows = conn.execute("SELECT payload, integrity_hash FROM evidence_requests WHERE task_id = ? ORDER BY created_at, request_id", (normalized_task_id,)).fetchall()
        result = []
        for payload, digest in rows:
            record = json.loads(payload)
            if sha256_json(record) != digest:
                raise PolicyError("Evidence request integrity check failed")
            result.append(record)
        return result

    def update_evidence_request(self, task_id: str, request_id: str, changes: Mapping[str, Any]) -> dict[str, Any]:
        normalized_task_id = validate_task_id(task_id)
        with self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT payload, integrity_hash FROM evidence_requests WHERE task_id = ? AND request_id = ?", (normalized_task_id, request_id)).fetchone()
            if not row:
                raise PolicyError("Evidence request was not found")
            record = json.loads(row[0])
            if sha256_json(record) != row[1]:
                raise PolicyError("Evidence request integrity check failed")
            updated = {**record, **dict(changes), "task_id": normalized_task_id, "request_id": request_id, "updated_at": _now()}
            digest = sha256_json(updated)
            conn.execute("UPDATE evidence_requests SET state=?, payload=?, integrity_hash=?, updated_at=? WHERE request_id=?", (updated["state"], json.dumps(updated, ensure_ascii=False, sort_keys=True, separators=(",", ":")), digest, updated["updated_at"], request_id))
        return updated

    def save_evidence_result(self, task_id: str, request_id: str, result: Mapping[str, Any], state: str) -> dict[str, Any]:
        normalized_task_id = validate_task_id(task_id)
        record = dict(result)
        record.update({"request_id": request_id, "task_id": normalized_task_id, "state": state, "updated_at": _now()})
        record.setdefault("created_at", record["updated_at"])
        digest = sha256_json(record)
        with self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute("SELECT payload, integrity_hash FROM evidence_results WHERE request_id=?", (request_id,)).fetchone()
            if existing:
                old = json.loads(existing[0])
                if sha256_json(old) != existing[1]:
                    raise PolicyError("Evidence result integrity check failed")
                if old.get("result_hash") == record.get("result_hash") and old.get("state") == state:
                    return old
            conn.execute("INSERT INTO evidence_results (request_id, task_id, state, payload, result_hash, integrity_hash, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(request_id) DO UPDATE SET state=excluded.state, payload=excluded.payload, result_hash=excluded.result_hash, integrity_hash=excluded.integrity_hash, updated_at=excluded.updated_at", (request_id, normalized_task_id, state, json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")), record.get("result_hash"), digest, record["created_at"], record["updated_at"]))
        return record

    def finalize_evidence_collection(self, task_id: str, request_id: str, result: Mapping[str, Any], state: str, *, error_code: str | None = None, error_reason: str | None = None) -> dict[str, Any]:
        """Atomically persist one result and its request terminal state."""
        normalized_task_id = validate_task_id(task_id)
        result_record = dict(result)
        now = _now()
        result_record.update({"request_id": request_id, "task_id": normalized_task_id, "state": state, "updated_at": now})
        result_record.setdefault("created_at", now)
        result_digest = sha256_json(result_record)
        with self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT payload, integrity_hash FROM evidence_requests WHERE task_id=? AND request_id=?", (normalized_task_id, request_id)).fetchone()
            if not row:
                raise PolicyError("Evidence request was not found")
            request_record = json.loads(row[0])
            if sha256_json(request_record) != row[1]:
                raise PolicyError("Evidence request integrity check failed")
            request_record.update({"state": state, "error_code": error_code, "error_reason": error_reason, "updated_at": now})
            request_digest = sha256_json(request_record)
            conn.execute("INSERT INTO evidence_results (request_id, task_id, state, payload, result_hash, integrity_hash, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(request_id) DO UPDATE SET state=excluded.state, payload=excluded.payload, result_hash=excluded.result_hash, integrity_hash=excluded.integrity_hash, updated_at=excluded.updated_at", (request_id, normalized_task_id, state, json.dumps(result_record, ensure_ascii=False, sort_keys=True, separators=(",", ":")), result_record.get("result_hash"), result_digest, result_record["created_at"], now))
            conn.execute("UPDATE evidence_requests SET state=?, payload=?, integrity_hash=?, updated_at=? WHERE request_id=?", (state, json.dumps(request_record, ensure_ascii=False, sort_keys=True, separators=(",", ":")), request_digest, now, request_id))
        return result_record

    def evidence_results(self, task_id: str) -> list[dict[str, Any]]:
        normalized_task_id = validate_task_id(task_id)
        with self._connection() as conn:
            rows = conn.execute("SELECT payload, integrity_hash FROM evidence_results WHERE task_id=? ORDER BY request_id", (normalized_task_id,)).fetchall()
        output = []
        for payload, digest in rows:
            value = json.loads(payload)
            if sha256_json(value) != digest:
                raise PolicyError("Evidence result integrity check failed")
            output.append(value)
        return output

    def save_isolation_result(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        """Store a redacted isolation result; canary paths and bytes are never accepted."""
        record = dict(payload)
        required = {"status", "checked_at", "expires_at", "codex_version", "schema_sha256", "outside_denied_explicitly"}
        missing = required - record.keys()
        if missing:
            raise PolicyError(f"isolation result is missing fields: {', '.join(sorted(missing))}")
        if record["status"] not in {"SAFE_CAPSULE_ONLY", "SAFE_CANDIDATE", "UNSAFE_FULL_DISK_READ", "ERROR", "UNKNOWN"}:
            raise PolicyError("isolation result status is not supported")
        if not isinstance(record["outside_denied_explicitly"], bool):
            raise PolicyError("outside_denied_explicitly must be a boolean")
        for forbidden in (
            "inside_path", "outside_path", "probe_root", "capsule_root", "outside_root",
            "command", "stdout", "stderr", "inside_stdout", "outside_stdout",
            "inside_stderr", "outside_stderr", "raw_stdout", "raw_stderr",
            "canary", "canary_bytes",
        ):
            if forbidden in record:
                raise PolicyError("isolation result includes sensitive probe data")
        integrity_hash = sha256_json(record)
        with self._connection() as conn:
            conn.execute(
                """INSERT INTO isolation_probe_results
                   (singleton, status, checked_at, expires_at, codex_version, schema_sha256, payload, integrity_hash)
                   VALUES (1, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(singleton) DO UPDATE SET
                     status=excluded.status, checked_at=excluded.checked_at, expires_at=excluded.expires_at,
                     codex_version=excluded.codex_version, schema_sha256=excluded.schema_sha256,
                     payload=excluded.payload, integrity_hash=excluded.integrity_hash""",
                (
                    record["status"], record["checked_at"], record["expires_at"], record["codex_version"],
                    record["schema_sha256"], json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
                    integrity_hash,
                ),
            )
        return {**record, "integrity_hash": integrity_hash}

    def isolation_result(self, codex_version: str | None = None, schema_sha256: str | None = None) -> dict[str, Any]:
        with self._connection() as conn:
            row = conn.execute(
                """SELECT status, checked_at, expires_at, codex_version, schema_sha256, payload, integrity_hash
                   FROM isolation_probe_results WHERE singleton = 1"""
            ).fetchone()
        if not row:
            return {"status": "UNKNOWN", "reason": "no isolation probe result"}
        try:
            record = json.loads(row[5])
        except json.JSONDecodeError as exc:
            raise PolicyError("isolation result payload was modified") from exc
        if not isinstance(record, dict) or sha256_json(record) != row[6]:
            raise PolicyError("isolation result integrity check failed")
        if any(record.get(key) != value for key, value in {
            "status": row[0], "checked_at": row[1], "expires_at": row[2],
            "codex_version": row[3], "schema_sha256": row[4],
        }.items()):
            raise PolicyError("isolation result metadata was modified")
        if record.get("status") not in {"SAFE_CANDIDATE", "SAFE_CAPSULE_ONLY"}:
            return {**record, "integrity_hash": row[6]}
        try:
            expired = datetime.fromisoformat(record["expires_at"]) <= datetime.now(timezone.utc)
        except (KeyError, TypeError, ValueError):
            expired = True
        changed = (
            (codex_version is not None and record.get("codex_version") != codex_version)
            or (schema_sha256 is not None and record.get("schema_sha256") != schema_sha256)
        )
        if expired or changed:
            reason = "isolation probe expired" if expired else "Codex version or schema changed"
            now = _now()
            return self.save_isolation_result({
                "status": "UNKNOWN",
                "checked_at": now,
                "expires_at": now,
                "codex_version": codex_version if codex_version is not None else record.get("codex_version"),
                "schema_sha256": schema_sha256 if schema_sha256 is not None else record.get("schema_sha256"),
                "inside_read_succeeded": False,
                "outside_read_succeeded": False,
                "outside_denied_explicitly": False,
                "reason": reason,
            })
        return {**record, "integrity_hash": row[6]}

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
        now = _now()
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

    def _save_snapshot(self, kind: str, status: str, payload: dict[str, Any]) -> None:
        with self._connection() as conn:
            conn.execute(
                """INSERT INTO account_snapshots (kind, status, captured_at, payload)
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT(kind) DO UPDATE SET status=excluded.status, captured_at=excluded.captured_at,
                   payload=excluded.payload""",
                (kind, status, _now(), json.dumps(payload, ensure_ascii=False)),
            )

    def mark_account_unknown(self, kind: str) -> None:
        if kind not in {"account", "rate_limits", "usage"}:
            raise PolicyError("unknown account snapshot kind")
        self._save_snapshot(kind, "UNKNOWN", {})

    def save_account(self, response: Mapping[str, Any]) -> None:
        account = response.get("account")
        if not isinstance(account, Mapping):
            self.mark_account_unknown("account")
            return
        auth_mode = account.get("type")
        plan_type = account.get("planType")
        payload = {
            "auth_mode": auth_mode if isinstance(auth_mode, str) else "UNKNOWN",
            "plan_type": plan_type if isinstance(plan_type, str) else "UNKNOWN",
            "email_masked": _mask_email(account.get("email")),
            "requires_openai_auth": response.get("requiresOpenaiAuth") if isinstance(response.get("requiresOpenaiAuth"), bool) else None,
        }
        self._save_snapshot("account", "AVAILABLE", payload)

    def save_rate_limits(self, response: Mapping[str, Any]) -> None:
        primary = _rate_snapshot(response.get("rateLimits"))
        if primary is None:
            self.mark_account_unknown("rate_limits")
            return
        payload: dict[str, Any] = {"rateLimits": primary}
        by_limit_id = response.get("rateLimitsByLimitId")
        if isinstance(by_limit_id, Mapping):
            payload["rateLimitsByLimitId"] = {
                str(key): snapshot
                for key, value in by_limit_id.items()
                if (snapshot := _rate_snapshot(value)) is not None
            }
        self._save_snapshot("rate_limits", "AVAILABLE", payload)

    def merge_rate_limits(self, update: Mapping[str, Any]) -> None:
        incoming = _rate_snapshot(update.get("rateLimits"))
        if incoming is None:
            self.mark_account_unknown("rate_limits")
            return
        current = self._load_snapshot("rate_limits")
        previous_payload = current["payload"] if current and current["status"] == "AVAILABLE" else {}
        payload: dict[str, Any] = {
            "rateLimits": _sparse_merge(previous_payload.get("rateLimits", {}), incoming)
        }
        if isinstance(previous_payload.get("rateLimitsByLimitId"), Mapping):
            payload["rateLimitsByLimitId"] = previous_payload["rateLimitsByLimitId"]
        self._save_snapshot("rate_limits", "AVAILABLE", payload)

    def save_usage(self, response: Mapping[str, Any]) -> None:
        buckets = response.get("dailyUsageBuckets")
        if not isinstance(buckets, list):
            self.mark_account_unknown("usage")
            return
        daily: list[dict[str, Any]] = []
        for bucket in buckets:
            if not isinstance(bucket, Mapping):
                self.mark_account_unknown("usage")
                return
            start_date, tokens = bucket.get("startDate"), bucket.get("tokens")
            if not isinstance(start_date, str) or not isinstance(tokens, int):
                self.mark_account_unknown("usage")
                return
            daily.append({"startDate": start_date, "tokens": tokens})
        self._save_snapshot("usage", "AVAILABLE", {"daily": daily})

    def _load_snapshot(self, kind: str) -> dict[str, Any] | None:
        with self._connection() as conn:
            row = conn.execute(
                "SELECT status, captured_at, payload FROM account_snapshots WHERE kind = ?", (kind,)
            ).fetchone()
        if not row:
            return None
        return {"status": row[0], "captured_at": row[1], "payload": json.loads(row[2])}

    def usage_thresholds(self) -> dict[str, int]:
        with self._connection() as conn:
            row = conn.execute("SELECT value FROM account_settings WHERE name = 'usage_thresholds'").fetchone()
        if not row:
            return dict(DEFAULT_USAGE_THRESHOLDS)
        try:
            value = json.loads(row[0])
        except json.JSONDecodeError:
            return dict(DEFAULT_USAGE_THRESHOLDS)
        if not isinstance(value, Mapping):
            return dict(DEFAULT_USAGE_THRESHOLDS)
        try:
            thresholds = {key: int(value[key]) for key in DEFAULT_USAGE_THRESHOLDS}
        except (KeyError, TypeError, ValueError):
            return dict(DEFAULT_USAGE_THRESHOLDS)
        if not (0 <= thresholds["conserve"] < thresholds["critical"] < thresholds["blocked"] <= 100):
            return dict(DEFAULT_USAGE_THRESHOLDS)
        return thresholds

    def set_usage_thresholds(self, thresholds: Mapping[str, int]) -> dict[str, int]:
        try:
            normalized = {key: int(thresholds[key]) for key in DEFAULT_USAGE_THRESHOLDS}
        except (KeyError, TypeError, ValueError) as exc:
            raise PolicyError("usage thresholds must include conserve, critical, and blocked") from exc
        if not (0 <= normalized["conserve"] < normalized["critical"] < normalized["blocked"] <= 100):
            raise PolicyError("usage thresholds must be ascending percentages through 100")
        with self._connection() as conn:
            conn.execute(
                """INSERT INTO account_settings (name, value) VALUES ('usage_thresholds', ?)
                   ON CONFLICT(name) DO UPDATE SET value=excluded.value""",
                (json.dumps(normalized),),
            )
        return normalized

    def account_overview(self) -> dict[str, Any]:
        account = self._load_snapshot("account") or {"status": "UNKNOWN", "captured_at": None, "payload": {}}
        rate_limits = self._load_snapshot("rate_limits") or {"status": "UNKNOWN", "captured_at": None, "payload": {}}
        usage = self._load_snapshot("usage") or {"status": "UNKNOWN", "captured_at": None, "payload": {}}
        thresholds = self.usage_thresholds()
        snapshot = rate_limits["payload"] if rate_limits["status"] == "AVAILABLE" else None
        state_evidence = account_state_details_from_snapshot(snapshot, thresholds)
        return {
            "account": {"status": account["status"], "captured_at": account["captured_at"], **account["payload"]},
            "rate_limits": {"status": rate_limits["status"], "captured_at": rate_limits["captured_at"], **rate_limits["payload"]},
            "usage": {"status": usage["status"], "captured_at": usage["captured_at"], **usage["payload"]},
            "thresholds": thresholds,
            "account_state": state_evidence["status"],
            "account_state_evidence": state_evidence,
        }

    def save_model_catalog(self, models: list[dict[str, Any]]) -> None:
        captured_at = _now()
        normalized: list[dict[str, Any]] = []
        for item in models:
            model_id = item.get("id")
            if not isinstance(model_id, str) or not model_id:
                continue
            efforts = [
                option["reasoningEffort"]
                for option in item.get("supportedReasoningEfforts", [])
                if isinstance(option, Mapping) and isinstance(option.get("reasoningEffort"), str)
            ]
            service_tiers = [
                {"id": tier.get("id"), "name": tier.get("name")}
                for tier in item.get("serviceTiers", [])
                if isinstance(tier, Mapping) and isinstance(tier.get("id"), str) and isinstance(tier.get("name"), str)
            ]
            if not service_tiers:
                service_tiers = [
                    {"id": tier, "name": tier}
                    for tier in item.get("additionalSpeedTiers", [])
                    if isinstance(tier, str)
                ]
            normalized.append({
                "id": model_id,
                "model": item.get("model") if isinstance(item.get("model"), str) else model_id,
                "display_name": item.get("displayName") if isinstance(item.get("displayName"), str) else model_id,
                "hidden": bool(item.get("hidden")),
                "default_effort": item.get("defaultReasoningEffort") if isinstance(item.get("defaultReasoningEffort"), str) else None,
                "efforts": efforts,
                "speed_tiers": service_tiers,
            })
        with self._connection() as conn:
            conn.execute("DELETE FROM model_catalog")
            conn.executemany(
                "INSERT INTO model_catalog (model_id, position, payload, captured_at) VALUES (?, ?, ?, ?)",
                [
                    (entry["id"], position, json.dumps(entry, ensure_ascii=False), captured_at)
                    for position, entry in enumerate(normalized)
                ],
            )

    def set_model_status(self, model_id: str, status: str) -> None:
        normalized = status.upper()
        if normalized not in MODEL_STATUSES:
            raise PolicyError("model status is not supported")
        with self._connection() as conn:
            exists = conn.execute("SELECT 1 FROM model_catalog WHERE model_id = ?", (model_id,)).fetchone()
            if not exists:
                raise PolicyError("model is not present in the current catalog")
            conn.execute(
                """INSERT INTO model_manual_status (model_id, status, updated_at) VALUES (?, ?, ?)
                   ON CONFLICT(model_id) DO UPDATE SET status=excluded.status, updated_at=excluded.updated_at""",
                (model_id, normalized, _now()),
            )

    def model_catalog(self) -> list[dict[str, Any]]:
        with self._connection() as conn:
            rows = conn.execute(
                """SELECT catalog.payload, status.status
                   FROM model_catalog AS catalog
                   LEFT JOIN model_manual_status AS status ON status.model_id = catalog.model_id
                   ORDER BY catalog.position"""
            ).fetchall()
        result = []
        for payload, manual_status in rows:
            entry = json.loads(payload)
            entry["manual_status"] = manual_status
            entry["status"] = manual_status or "AVAILABLE"
            result.append(entry)
        return result

    def router_models(self) -> list[dict[str, Any]]:
        return [
            {
                "id": item["id"],
                "model": item["model"],
                "displayName": item["display_name"],
                "hidden": item["hidden"],
                "defaultReasoningEffort": item["default_effort"],
                "supportedReasoningEfforts": [{"reasoningEffort": effort} for effort in item["efforts"]],
                "manual_status": item["status"],
            }
            for item in self.model_catalog()
        ]

    def create_route_plan(self, payload: Mapping[str, Any], ttl_seconds: int = 600) -> dict[str, Any]:
        if ttl_seconds <= 0:
            raise PolicyError("Route Plan TTL must be positive")
        bridge_key = payload.get("bridge_idempotency_key")
        if bridge_key is not None:
            if not isinstance(bridge_key, str) or not bridge_key:
                raise PolicyError("Bridge idempotency key is invalid")
            with self._connection() as conn:
                existing = conn.execute("SELECT plan_id FROM route_plans WHERE bridge_idempotency_key = ?", (bridge_key,)).fetchone()
            if existing:
                return self.load_route_plan(existing[0])
        plan_id = str(uuid.uuid4())
        created = datetime.now(timezone.utc)
        record = {
            **dict(payload),
            "plan_id": plan_id,
            "created_at": created.isoformat(),
            "expires_at": (created + timedelta(seconds=ttl_seconds)).isoformat(),
        }
        required = {
            "decision_canonical_json", "decision_hash", "task_hash", "root", "project_id", "account_snapshot_at",
            "model_catalog_hash", "status", "final", "decision", "candidate_ladder", "task", "permission",
            "budget_level", "budget", "evidence_files", "evidence_ranges", "evidence_sources",
        }
        missing = sorted(required - record.keys())
        if missing:
            raise PolicyError(f"Route Plan is missing fields: {', '.join(missing)}")
        project_id = validate_project_id(str(record["project_id"]))
        record["project_id"] = project_id
        final = record.get("final")
        final_model = final.get("model") if isinstance(final, Mapping) else None
        final_effort = final.get("effort") if isinstance(final, Mapping) else None
        integrity_hash = sha256_json(record)
        with self._connection() as conn:
            conn.execute(
                """INSERT INTO route_plans (
                    plan_id, created_at, expires_at, decision_hash, task_hash, root, project_id,
                    account_snapshot_at, model_catalog_hash, status, final_model, final_effort, bridge_idempotency_key,
                    payload, integrity_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    plan_id,
                    record["created_at"],
                    record["expires_at"],
                    record["decision_hash"],
                    record["task_hash"],
                    record["root"],
                    project_id,
                    record["account_snapshot_at"],
                    record["model_catalog_hash"],
                    record["status"],
                    final_model,
                    final_effort,
                    bridge_key,
                    json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
                    integrity_hash,
                ),
            )
        return {**record, "integrity_hash": integrity_hash, "used": False}

    def load_route_plan(self, plan_id: str) -> dict[str, Any]:
        try:
            normalized_id = str(uuid.UUID(plan_id))
        except (ValueError, TypeError) as exc:
            raise PolicyError("route_plan_id must be a UUID") from exc
        with self._connection() as conn:
            row = conn.execute(
                """SELECT created_at, expires_at, decision_hash, task_hash, root, project_id,
                          account_snapshot_at, model_catalog_hash, status, final_model, final_effort,
                          payload, integrity_hash
                   FROM route_plans WHERE plan_id = ?""",
                (normalized_id,),
            ).fetchone()
            use = conn.execute(
                """SELECT used_at, run_id, status, claimed_at, started_at, failed_at, completed_at, error
                   FROM route_plan_uses WHERE plan_id = ?""", (normalized_id,)
            ).fetchone()
        if not row:
            raise PolicyError("Route Plan was not found")
        try:
            record = json.loads(row[11])
        except json.JSONDecodeError as exc:
            raise PolicyError("Route Plan payload was modified") from exc
        columns = {
            "plan_id": normalized_id,
            "created_at": row[0],
            "expires_at": row[1],
            "decision_hash": row[2],
            "task_hash": row[3],
            "root": row[4],
            "project_id": row[5],
            "account_snapshot_at": row[6],
            "model_catalog_hash": row[7],
            "status": row[8],
        }
        final = record.get("final") if isinstance(record, dict) else None
        if (final.get("model") if isinstance(final, dict) else None) != row[9]:
            raise PolicyError("Route Plan final model was modified")
        if (final.get("effort") if isinstance(final, dict) else None) != row[10]:
            raise PolicyError("Route Plan final effort was modified")
        if not isinstance(record, dict) or any(record.get(key) != value for key, value in columns.items()):
            raise PolicyError("Route Plan metadata was modified")
        if sha256_json(record) != row[12]:
            raise PolicyError("Route Plan integrity check failed")
        decision = record.get("decision")
        if (
            not isinstance(decision, dict)
            or canonical_json(decision) != record.get("decision_canonical_json")
            or sha256_json(decision) != record.get("decision_hash")
        ):
            raise PolicyError("Route Plan decision was modified")
        return {
            **record,
            "integrity_hash": row[12],
            "used": use is not None,
            "used_at": use[0] if use else None,
            "run_id": use[1] if use else None,
            "use_status": use[2] if use else None,
            "claimed_at": use[3] if use else None,
            "started_at": use[4] if use else None,
            "failed_at": use[5] if use else None,
            "completed_at": use[6] if use else None,
            "use_error": use[7] if use else None,
        }

    def load_evidence_capsule(self, plan_id: str) -> dict[str, Any] | None:
        try:
            normalized_id = str(uuid.UUID(plan_id))
        except (ValueError, TypeError) as exc:
            raise PolicyError("route_plan_id must be a UUID") from exc
        with self._connection() as conn:
            row = conn.execute(
                """SELECT capsule_id, status, capsule_hash, payload, integrity_hash
                   FROM evidence_capsules WHERE plan_id = ?""",
                (normalized_id,),
            ).fetchone()
        if not row:
            return None
        try:
            payload = json.loads(row[3])
        except json.JSONDecodeError as exc:
            raise PolicyError("Evidence Capsule payload was modified") from exc
        if (
            not isinstance(payload, dict)
            or payload.get("plan_id") != normalized_id
            or payload.get("capsule_id") != row[0]
            or payload.get("status") != row[1]
            or payload.get("capsule_hash") != row[2]
            or sha256_json(payload) != row[4]
        ):
            raise PolicyError("Evidence Capsule integrity check failed")
        return {**payload, "integrity_hash": row[4]}

    def save_evidence_capsule(self, plan_id: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        try:
            normalized_id = str(uuid.UUID(plan_id))
        except (ValueError, TypeError) as exc:
            raise PolicyError("route_plan_id must be a UUID") from exc
        record = dict(payload)
        if record.get("plan_id") != normalized_id:
            raise PolicyError("Evidence Capsule plan_id does not match the Route Plan")
        if record.get("status") not in {"READY", "HOLD", "INVALID"}:
            raise PolicyError("Evidence Capsule status is not supported")
        capsule_id = record.get("capsule_id")
        capsule_hash = record.get("capsule_hash")
        evidence_fingerprint = record.get("evidence_fingerprint")
        if not isinstance(capsule_id, str) or not capsule_id:
            raise PolicyError("Evidence Capsule is missing capsule_id")
        if capsule_hash is not None and not isinstance(capsule_hash, str):
            raise PolicyError("Evidence Capsule hash is invalid")
        if not isinstance(evidence_fingerprint, str) or not evidence_fingerprint:
            raise PolicyError("Evidence Capsule fingerprint is invalid")
        integrity_hash = sha256_json(record)
        with self._connection() as conn:
            conn.execute(
                """INSERT INTO evidence_capsules
                   (plan_id, capsule_id, status, capsule_hash, payload, integrity_hash)
                   VALUES (?, ?, ?, ?, ?, ?)
                   ON CONFLICT(plan_id) DO UPDATE SET
                     capsule_id=excluded.capsule_id,
                     status=excluded.status,
                     capsule_hash=excluded.capsule_hash,
                     payload=excluded.payload,
                     integrity_hash=excluded.integrity_hash""",
                (
                    normalized_id,
                    capsule_id,
                    record["status"],
                    capsule_hash,
                    json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
                    integrity_hash,
                ),
            )
        return {**record, "integrity_hash": integrity_hash}

    def claim_route_plan(self, plan_id: str, run_id: str) -> None:
        try:
            normalized_id = str(uuid.UUID(plan_id))
        except (ValueError, TypeError) as exc:
            raise PolicyError("route_plan_id must be a UUID") from exc
        normalized_run_id = validate_task_id(run_id)
        claimed_at = _now()
        with self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.execute(
                    """INSERT INTO route_plan_uses
                       (plan_id, used_at, run_id, status, claimed_at)
                       VALUES (?, ?, ?, 'claimed', ?)""",
                    (normalized_id, claimed_at, normalized_run_id, claimed_at),
                )
            except sqlite3.IntegrityError as exc:
                raise PolicyError("Route Plan has already been used") from exc

    def update_route_plan_use(self, plan_id: str, status: str, error: str | None = None) -> None:
        allowed = {"started", "failed", "completed"}
        if status not in allowed:
            raise PolicyError("Route Plan use status is not supported")
        timestamp_column = f"{status}_at"
        allowed_previous = {"started": ("claimed",), "failed": ("claimed", "started"), "completed": ("started",)}[status]
        placeholders = ", ".join("?" for _ in allowed_previous)
        with self._connection() as conn:
            cursor = conn.execute(
                f"""UPDATE route_plan_uses
                    SET status = ?, {timestamp_column} = ?, error = ?
                    WHERE plan_id = ? AND status IN ({placeholders})""",
                (status, _now(), error, plan_id, *allowed_previous),
            )
        if cursor.rowcount != 1:
            raise PolicyError("Route Plan use state transition was rejected")
