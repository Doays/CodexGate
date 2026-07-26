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
            self._migrate_route_plan_uses(conn)

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
            "budget_level", "budget",
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
                    account_snapshot_at, model_catalog_hash, status, final_model, final_effort,
                    payload, integrity_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
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
