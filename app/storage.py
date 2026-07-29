from __future__ import annotations

import json
import re
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
    validate_source_alias,
    validate_task_id,
    validate_wsl_codex_binary_path,
    validate_wsl_distro,
)
from .token_ledger import build_report, normalize_baseline_payload, normalize_run_record, normalize_usage_event, render_markdown


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
                """CREATE TABLE IF NOT EXISTS ledger_runs (
                    run_id TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL,
                    route_plan_id TEXT,
                    comparison_key TEXT NOT NULL,
                    success_criteria_hash TEXT NOT NULL,
                    task_class TEXT NOT NULL,
                    planned_model TEXT,
                    actual_model TEXT,
                    effort TEXT,
                    status TEXT NOT NULL,
                    quality TEXT NOT NULL,
                    input_tokens INTEGER,
                    cached_input_tokens INTEGER,
                    output_tokens INTEGER,
                    reasoning_tokens INTEGER,
                    provider_total_tokens INTEGER,
                    processed_tokens INTEGER,
                    non_cached_input_tokens INTEGER,
                    cache_ratio REAL,
                    codex_context_bytes INTEGER,
                    web_packet_bytes INTEGER,
                    evidence_bytes INTEGER,
                    source_bytes INTEGER,
                    catalog_source_bytes INTEGER,
                    probe_bytes INTEGER,
                    model_turns INTEGER,
                    high_model_turns INTEGER,
                    retries INTEGER,
                    reroutes INTEGER,
                    compactions INTEGER,
                    subagent_count INTEGER,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    finished_at TEXT,
                    payload TEXT NOT NULL,
                    integrity_hash TEXT NOT NULL
                )"""
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS ledger_usage_events (
                    event_id TEXT PRIMARY KEY,
                    source_event_id TEXT NOT NULL UNIQUE,
                    source TEXT NOT NULL,
                    quality TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    run_id TEXT,
                    task_id TEXT,
                    route_plan_id TEXT,
                    comparison_key TEXT,
                    success_criteria_hash TEXT,
                    task_class TEXT,
                    planned_model TEXT,
                    actual_model TEXT,
                    effort TEXT,
                    status TEXT,
                    input_tokens INTEGER,
                    cached_input_tokens INTEGER,
                    output_tokens INTEGER,
                    reasoning_tokens INTEGER,
                    provider_total_tokens INTEGER,
                    codex_context_bytes INTEGER,
                    web_packet_bytes INTEGER,
                    evidence_bytes INTEGER,
                    source_bytes INTEGER,
                    catalog_source_bytes INTEGER,
                    probe_bytes INTEGER,
                    model_turns INTEGER,
                    high_model_turns INTEGER,
                    retries INTEGER,
                    reroutes INTEGER,
                    compactions INTEGER,
                    subagent_count INTEGER,
                    occurred_at TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    integrity_hash TEXT NOT NULL
                )"""
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS ledger_baselines (
                    baseline_id TEXT PRIMARY KEY,
                    task_id TEXT,
                    route_plan_id TEXT,
                    comparison_key TEXT NOT NULL,
                    success_criteria_hash TEXT NOT NULL,
                    task_class TEXT NOT NULL,
                    planned_model TEXT NOT NULL,
                    actual_model TEXT,
                    effort TEXT NOT NULL,
                    status TEXT NOT NULL,
                    quality TEXT NOT NULL,
                    input_tokens INTEGER,
                    cached_input_tokens INTEGER,
                    output_tokens INTEGER,
                    reasoning_tokens INTEGER,
                    provider_total_tokens INTEGER,
                    processed_tokens INTEGER,
                    non_cached_input_tokens INTEGER,
                    cache_ratio REAL,
                    codex_context_bytes INTEGER,
                    web_packet_bytes INTEGER,
                    evidence_bytes INTEGER,
                    source_bytes INTEGER,
                    catalog_source_bytes INTEGER,
                    probe_bytes INTEGER,
                    model_turns INTEGER,
                    high_model_turns INTEGER,
                    retries INTEGER,
                    reroutes INTEGER,
                    compactions INTEGER,
                    subagent_count INTEGER,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    integrity_hash TEXT NOT NULL
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
                """CREATE TABLE IF NOT EXISTS wsl_isolation_config (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    distro TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )"""
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS wsl_codex_runtime_config (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    binary_path TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )"""
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS wsl_codex_runtime_results (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    status TEXT NOT NULL,
                    checked_at TEXT NOT NULL,
                    config_hash TEXT,
                    runtime_fingerprint TEXT,
                    launch_spec_hash TEXT,
                    payload TEXT NOT NULL,
                    integrity_hash TEXT NOT NULL
                )"""
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS sealed_egress_contracts (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    status TEXT NOT NULL,
                    checked_at TEXT NOT NULL,
                    contract_hash TEXT,
                    runtime_fingerprint TEXT,
                    isolation_cache_key TEXT,
                    payload TEXT NOT NULL,
                    integrity_hash TEXT NOT NULL
                )"""
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS wsl_isolation_probe_results (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    backend TEXT NOT NULL,
                    distro TEXT,
                    config_hash TEXT,
                    tool_fingerprint TEXT,
                    cache_key TEXT,
                    probe_version TEXT,
                    status TEXT NOT NULL,
                    checked_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    integrity_hash TEXT NOT NULL
                )"""
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS wsl_isolation_preflight_cache (
                    config_hash TEXT PRIMARY KEY,
                    tool_fingerprint TEXT NOT NULL,
                    status TEXT NOT NULL,
                    checked_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    integrity_hash TEXT NOT NULL
                )"""
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS wsl_isolation_repro_runs (
                    repro_id TEXT PRIMARY KEY,
                    cache_key TEXT NOT NULL UNIQUE,
                    config_hash TEXT NOT NULL,
                    tool_fingerprint TEXT NOT NULL,
                    status TEXT NOT NULL,
                    requested_runs INTEGER NOT NULL,
                    completed_runs INTEGER NOT NULL DEFAULT 0,
                    success_count INTEGER NOT NULL DEFAULT 0,
                    result_hash TEXT,
                    duration_ms INTEGER NOT NULL DEFAULT 0,
                    started_at TEXT NOT NULL,
                    finished_at TEXT,
                    error_code TEXT,
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
            conn.execute(
                """CREATE TABLE IF NOT EXISTS catalog_sources (
                    source_id TEXT PRIMARY KEY,
                    alias TEXT NOT NULL UNIQUE,
                    root TEXT NOT NULL,
                    generation INTEGER NOT NULL DEFAULT 0,
                    status TEXT NOT NULL DEFAULT 'READY',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )"""
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS catalog_scans (
                    scan_id TEXT PRIMARY KEY,
                    source_id TEXT NOT NULL REFERENCES catalog_sources(source_id),
                    generation INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    finished_at TEXT,
                    cursor TEXT,
                    cancel_requested INTEGER NOT NULL DEFAULT 0,
                    payload TEXT NOT NULL
                )"""
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS catalog_entries (
                    entry_id TEXT PRIMARY KEY,
                    source_id TEXT NOT NULL REFERENCES catalog_sources(source_id),
                    relative_path TEXT NOT NULL,
                    normalized_path TEXT NOT NULL,
                    extension TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    mtime_ns INTEGER NOT NULL,
                    file_id TEXT NOT NULL,
                    asset_kind TEXT NOT NULL,
                    status TEXT NOT NULL,
                    scan_generation INTEGER NOT NULL,
                    fingerprint_state TEXT NOT NULL DEFAULT 'QUEUED',
                    UNIQUE(source_id, normalized_path)
                )"""
            )
            self._create_format_probe_schema(conn)
            conn.execute("CREATE INDEX IF NOT EXISTS catalog_entries_source_generation ON catalog_entries(source_id, scan_generation)")
            conn.execute("CREATE INDEX IF NOT EXISTS catalog_scans_source_status ON catalog_scans(source_id, status)")
            conn.execute("CREATE INDEX IF NOT EXISTS format_probes_entry_status ON format_probes(entry_id, status)")
            self._migrate_route_plan_uses(conn)
            self._migrate_route_plans(conn)
            self._migrate_bridge_nonces(conn)
            self._migrate_format_probes(conn)
            self._migrate_wsl_isolation_probe_results(conn)

    def _connection(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    # Asset Catalog storage deliberately keeps the source root private.  These
    # methods return aliases and project-relative paths only.
    def create_catalog_source(self, alias: str, root: Path) -> dict[str, Any]:
        clean_alias = validate_source_alias(alias)
        source_id = str(uuid.uuid4())
        now = _now()
        with self._connection() as conn:
            try:
                conn.execute(
                    """INSERT INTO catalog_sources
                       (source_id, alias, root, generation, status, created_at, updated_at)
                       VALUES (?, ?, ?, 0, 'READY', ?, ?)""",
                    (source_id, clean_alias, str(root), now, now),
                )
            except sqlite3.IntegrityError as exc:
                raise PolicyError("catalog source alias is already registered") from exc
        return {"source_id": source_id, "alias": clean_alias, "generation": 0, "status": "READY", "created_at": now}

    def catalog_source_private(self, source_id: str) -> dict[str, Any]:
        try:
            uuid.UUID(source_id)
        except (ValueError, TypeError) as exc:
            raise PolicyError("catalog source id is invalid") from exc
        with self._connection() as conn:
            row = conn.execute(
                "SELECT source_id, alias, root, generation, status, created_at, updated_at FROM catalog_sources WHERE source_id=?",
                (source_id,),
            ).fetchone()
        if not row:
            raise PolicyError("catalog source was not found")
        return dict(zip(("source_id", "alias", "root", "generation", "status", "created_at", "updated_at"), row))

    @staticmethod
    def _catalog_public_source(record: Mapping[str, Any]) -> dict[str, Any]:
        return {key: record[key] for key in ("source_id", "alias", "generation", "status", "created_at", "updated_at") if key in record}

    def catalog_sources(self) -> list[dict[str, Any]]:
        with self._connection() as conn:
            rows = conn.execute(
                "SELECT source_id, alias, generation, status, created_at, updated_at FROM catalog_sources ORDER BY alias COLLATE NOCASE"
            ).fetchall()
        return [dict(zip(("source_id", "alias", "generation", "status", "created_at", "updated_at"), row)) for row in rows]

    def begin_catalog_scan(self, source_id: str, *, resume: bool = False) -> dict[str, Any]:
        source = self.catalog_source_private(source_id)
        with self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            active = conn.execute(
                "SELECT scan_id FROM catalog_scans WHERE source_id=? AND status='SCANNING'", (source_id,)
            ).fetchone()
            if active:
                raise PolicyError("a catalog scan is already running for this source")
            interrupted = conn.execute(
                "SELECT scan_id, generation, cursor, payload FROM catalog_scans WHERE source_id=? AND status='INTERRUPTED' ORDER BY started_at DESC LIMIT 1",
                (source_id,),
            ).fetchone() if resume else None
            now = _now()
            if interrupted:
                scan_id, generation, cursor, payload = interrupted
                conn.execute("UPDATE catalog_scans SET status='SCANNING', cancel_requested=0, finished_at=NULL WHERE scan_id=?", (scan_id,))
                return {"scan_id": scan_id, "source": source, "generation": generation, "cursor": json.loads(cursor) if cursor else None, "payload": json.loads(payload), "resumed": True}
            generation = int(source["generation"]) + 1
            scan_id = str(uuid.uuid4())
            payload = {"files_seen": 0, "bytes_indexed": 0, "content_bytes_read": 0, "added": 0, "modified": 0, "missing": 0, "moved_candidates": 0, "rejected": 0, "unchanged": 0, "duration": 0.0}
            conn.execute("UPDATE catalog_sources SET generation=?, status='SCANNING', updated_at=? WHERE source_id=?", (generation, now, source_id))
            conn.execute("INSERT INTO catalog_scans (scan_id, source_id, generation, status, started_at, cursor, payload) VALUES (?, ?, ?, 'SCANNING', ?, ?, ?)", (scan_id, source_id, generation, now, json.dumps([""], separators=(",", ":")), json.dumps(payload, separators=(",", ":"))))
            return {"scan_id": scan_id, "source": source, "generation": generation, "cursor": [""], "payload": payload, "resumed": False}

    def catalog_scan_cancel_requested(self, scan_id: str) -> bool:
        with self._connection() as conn:
            row = conn.execute("SELECT cancel_requested FROM catalog_scans WHERE scan_id=?", (scan_id,)).fetchone()
        return bool(row and row[0])

    def request_catalog_scan_cancel(self, source_id: str) -> None:
        with self._connection() as conn:
            conn.execute("UPDATE catalog_scans SET cancel_requested=1 WHERE source_id=? AND status='SCANNING'", (source_id,))

    def apply_catalog_batch(self, scan_id: str, source_id: str, generation: int, entries: list[Mapping[str, Any]], rejected: list[Mapping[str, Any]], cursor: list[str], counters: Mapping[str, Any]) -> None:
        """Commit at most one scanner batch. Metadata only; file content is never accepted."""
        with self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            for record in entries:
                old = conn.execute("SELECT entry_id, size, mtime_ns, file_id FROM catalog_entries WHERE source_id=? AND normalized_path=?", (source_id, record["normalized_path"])).fetchone()
                status = record["status"]
                if old:
                    status = "UNCHANGED" if tuple(old[1:]) == (record["size"], record["mtime_ns"], record["file_id"]) else "MODIFIED"
                    conn.execute("UPDATE catalog_entries SET relative_path=?, extension=?, size=?, mtime_ns=?, file_id=?, asset_kind=?, status=?, scan_generation=?, fingerprint_state='QUEUED' WHERE entry_id=?", (record["relative_path"], record["extension"], record["size"], record["mtime_ns"], record["file_id"], record["asset_kind"], status, generation, old[0]))
                else:
                    conn.execute("INSERT INTO catalog_entries (entry_id, source_id, relative_path, normalized_path, extension, size, mtime_ns, file_id, asset_kind, status, scan_generation, fingerprint_state) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'QUEUED')", (str(uuid.uuid4()), source_id, record["relative_path"], record["normalized_path"], record["extension"], record["size"], record["mtime_ns"], record["file_id"], record["asset_kind"], status, generation))
            # Reparse points never get followed or turned into ordinary entries.
            for record in rejected:
                normalized = str(record["normalized_path"])
                old = conn.execute("SELECT entry_id FROM catalog_entries WHERE source_id=? AND normalized_path=?", (source_id, normalized)).fetchone()
                values = (record["relative_path"], record["extension"], 0, 0, "", "unknown", "REJECTED", generation)
                if old:
                    conn.execute("UPDATE catalog_entries SET relative_path=?, extension=?, size=?, mtime_ns=?, file_id=?, asset_kind=?, status=?, scan_generation=? WHERE entry_id=?", (*values, old[0]))
                else:
                    conn.execute("INSERT INTO catalog_entries (entry_id, source_id, relative_path, normalized_path, extension, size, mtime_ns, file_id, asset_kind, status, scan_generation, fingerprint_state) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'QUEUED')", (str(uuid.uuid4()), source_id, record["relative_path"], normalized, record["extension"], 0, 0, "", "unknown", "REJECTED", generation))
            conn.execute("UPDATE catalog_scans SET cursor=?, payload=? WHERE scan_id=?", (json.dumps(cursor, separators=(",", ":")), json.dumps(dict(counters), separators=(",", ":")), scan_id))

    def finish_catalog_scan(self, scan_id: str, source_id: str, generation: int, status: str, counters: Mapping[str, Any], cursor: list[str] | None = None) -> dict[str, Any]:
        if status not in {"COMPLETED", "INTERRUPTED", "FAILED"}:
            raise PolicyError("catalog scan state is invalid")
        now = _now()
        with self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            if status == "COMPLETED":
                # Anything not encountered in this full generation is retained as MISSING.
                missing = conn.execute("SELECT COUNT(*) FROM catalog_entries WHERE source_id=? AND scan_generation < ? AND status NOT IN ('REJECTED', 'MISSING')", (source_id, generation)).fetchone()[0]
                conn.execute("UPDATE catalog_entries SET status='MISSING' WHERE source_id=? AND scan_generation < ? AND status NOT IN ('REJECTED', 'MISSING')", (source_id, generation))
                values = dict(counters)
                values["missing"] = int(values.get("missing", 0)) + int(missing)
                counters = values
                # A new path with identical stable metadata is only a candidate; the old missing record is retained.
                rows = conn.execute("SELECT entry_id, size, mtime_ns, file_id FROM catalog_entries WHERE source_id=? AND scan_generation=? AND status='ADDED'", (source_id, generation)).fetchall()
                moved = 0
                for entry_id, size, mtime_ns, file_id in rows:
                    old = conn.execute("SELECT 1 FROM catalog_entries WHERE source_id=? AND scan_generation < ? AND status='MISSING' AND size=? AND mtime_ns=? AND file_id=?", (source_id, generation, size, mtime_ns, file_id)).fetchone()
                    if old:
                        conn.execute("UPDATE catalog_entries SET status='MOVED_CANDIDATE' WHERE entry_id=?", (entry_id,))
                        moved += 1
                values = dict(counters)
                values["moved_candidates"] = int(values.get("moved_candidates", 0)) + moved
                counters = values
            conn.execute("UPDATE catalog_scans SET status=?, finished_at=?, cursor=?, payload=? WHERE scan_id=?", (status, now, json.dumps(cursor or [], separators=(",", ":")), json.dumps(dict(counters), separators=(",", ":")), scan_id))
            conn.execute("UPDATE catalog_sources SET status=?, updated_at=? WHERE source_id=?", ("READY" if status == "COMPLETED" else status, now, source_id))
        return self.catalog_scan(scan_id)

    def catalog_scan(self, scan_id: str) -> dict[str, Any]:
        with self._connection() as conn:
            row = conn.execute("SELECT scan_id, source_id, generation, status, started_at, finished_at, payload FROM catalog_scans WHERE scan_id=?", (scan_id,)).fetchone()
        if not row:
            raise PolicyError("catalog scan was not found")
        result = dict(zip(("scan_id", "source_id", "generation", "status", "started_at", "finished_at", "metrics"), (*row[:6], json.loads(row[6]))))
        return result

    def catalog_entries(self, source_id: str, *, status: str | None = None, asset_kind: str | None = None, extension: str | None = None, min_size: int | None = None, max_size: int | None = None) -> list[dict[str, Any]]:
        self.catalog_source_private(source_id)
        clauses = ["source_id=?"]
        values: list[Any] = [source_id]
        for column, value in (("status", status), ("asset_kind", asset_kind), ("extension", extension.casefold() if extension else None)):
            if value:
                clauses.append(f"{column}=?")
                values.append(value)
        if min_size is not None:
            clauses.append("size>=?")
            values.append(min_size)
        if max_size is not None:
            clauses.append("size<=?")
            values.append(max_size)
        with self._connection() as conn:
            rows = conn.execute("SELECT entry_id, relative_path, extension, size, mtime_ns, file_id, asset_kind, status, scan_generation, fingerprint_state FROM catalog_entries WHERE " + " AND ".join(clauses) + " ORDER BY normalized_path", values).fetchall()
        keys = ("entry_id", "relative_path", "extension", "size", "mtime_ns", "file_id", "asset_kind", "status", "scan_generation", "fingerprint_state")
        return [dict(zip(keys, row)) for row in rows]

    def catalog_entry_metadata(self, source_id: str) -> dict[str, dict[str, Any]]:
        """Private scan helper; only metadata and no source root leaves SQLite."""
        with self._connection() as conn:
            rows = conn.execute("SELECT normalized_path, size, mtime_ns, file_id, scan_generation, status FROM catalog_entries WHERE source_id=?", (source_id,)).fetchall()
        return {row[0]: {"size": row[1], "mtime_ns": row[2], "file_id": row[3], "scan_generation": row[4], "status": row[5]} for row in rows}

    def catalog_entry_private(self, entry_id: str) -> dict[str, Any]:
        try:
            normalized_id = str(uuid.UUID(entry_id))
        except (ValueError, TypeError) as exc:
            raise PolicyError("catalog entry id is invalid") from exc
        with self._connection() as conn:
            row = conn.execute(
                """SELECT entry.entry_id, entry.source_id, source.alias, source.root, entry.relative_path,
                          entry.normalized_path, entry.extension, entry.size, entry.mtime_ns, entry.file_id,
                          entry.asset_kind, entry.status, entry.scan_generation
                   FROM catalog_entries AS entry
                   JOIN catalog_sources AS source ON source.source_id = entry.source_id
                   WHERE entry.entry_id=?""",
                (normalized_id,),
            ).fetchone()
        if not row:
            raise PolicyError("catalog entry was not found")
        keys = (
            "entry_id", "source_id", "alias", "root", "relative_path", "normalized_path",
            "extension", "size", "mtime_ns", "file_id", "asset_kind", "status", "scan_generation",
        )
        return dict(zip(keys, row))

    def begin_format_probe(
        self,
        entry_id: str,
        probe_version: str,
        cache_identity: str,
        sample_sha256: str,
        payload: Mapping[str, Any],
    ) -> dict[str, Any]:
        entry = self.catalog_entry_private(entry_id)
        if not isinstance(probe_version, str) or not probe_version:
            raise PolicyError("format probe version is invalid")
        if not isinstance(cache_identity, str) or not cache_identity:
            raise PolicyError("format probe cache identity is invalid")
        if not isinstance(sample_sha256, str) or not sample_sha256:
            raise PolicyError("format probe sample hash is invalid")
        now = _now()
        with self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute(
                """SELECT probe_id FROM format_probes
                   WHERE entry_id=? AND probe_version=? AND cache_identity=? AND status='COMPLETED'
                   ORDER BY attempt DESC, created_at DESC LIMIT 1""",
                (entry["entry_id"], probe_version, cache_identity),
            ).fetchone()
            if existing:
                snapshot = self.load_format_probe(existing[0])
                snapshot["reused"] = True
                return snapshot
            active = conn.execute(
                "SELECT probe_id FROM format_probes WHERE entry_id=? AND status IN ('PENDING', 'PROBING')",
                (entry["entry_id"],),
            ).fetchone()
            if active:
                raise PolicyError("a format probe is already running for this catalog entry")
            row = conn.execute("SELECT COALESCE(MAX(attempt), 0) FROM format_probes WHERE entry_id=?", (entry["entry_id"],)).fetchone()
            attempt = int(row[0]) + 1
            probe_id = str(uuid.uuid4())
            record = {
                **dict(payload),
                "probe_id": probe_id,
                "entry_id": entry["entry_id"],
                "source_id": entry["source_id"],
                "probe_version": probe_version,
                "cache_identity": cache_identity,
                "sample_sha256": sample_sha256,
                "attempt": attempt,
                "status": "PENDING",
                "created_at": now,
                "updated_at": now,
                "finished_at": None,
            }
            integrity_hash = sha256_json(record)
            conn.execute(
                """INSERT INTO format_probes
                   (probe_id, entry_id, source_id, probe_version, cache_identity, sample_sha256, attempt, status, created_at, updated_at, finished_at, payload, integrity_hash)
                   VALUES (?, ?, ?, ?, ?, ?, ?, 'PENDING', ?, ?, NULL, ?, ?)""",
                (
                    probe_id,
                    entry["entry_id"],
                    entry["source_id"],
                    probe_version,
                    cache_identity,
                    sample_sha256,
                    attempt,
                    now,
                    now,
                    json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
                    integrity_hash,
                ),
            )
        return {**record, "integrity_hash": integrity_hash, "reused": False}

    def mark_format_probe_probing(self, probe_id: str) -> dict[str, Any]:
        now = _now()
        probe = self.load_format_probe(probe_id)
        if probe["status"] != "PENDING":
            raise PolicyError("format probe is not pending")
        record = dict(probe)
        record["status"] = "PROBING"
        record["updated_at"] = now
        record.pop("integrity_hash", None)
        record.pop("reused", None)
        integrity_hash = sha256_json(record)
        with self._connection() as conn:
            cursor = conn.execute(
                """UPDATE format_probes
                   SET status='PROBING', updated_at=?, payload=?, integrity_hash=?
                   WHERE probe_id=? AND status='PENDING'""",
                (
                    now,
                    json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
                    integrity_hash,
                    probe_id,
                ),
            )
        if cursor.rowcount != 1:
            raise PolicyError("format probe could not start")
        return {**record, "integrity_hash": integrity_hash, "reused": False}

    def complete_format_probe(self, probe_id: str, status: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        if status not in {"COMPLETED", "STALE", "REJECTED", "FAILED"}:
            raise PolicyError("format probe state is invalid")
        current = self.load_format_probe(probe_id)
        if current["status"] not in {"PENDING", "PROBING"}:
            raise PolicyError("format probe is already finished")
        now = _now()
        record_payload = dict(payload)
        record_payload.pop("integrity_hash", None)
        record_payload.pop("reused", None)
        record = {
            **record_payload,
            "probe_id": current["probe_id"],
            "entry_id": current["entry_id"],
            "source_id": current["source_id"],
            "probe_version": current["probe_version"],
            "cache_identity": current["cache_identity"],
            "sample_sha256": current["sample_sha256"],
            "attempt": current["attempt"],
            "status": status,
            "created_at": current["created_at"],
            "updated_at": now,
            "finished_at": now,
        }
        integrity_hash = sha256_json(record)
        with self._connection() as conn:
            cursor = conn.execute(
                """UPDATE format_probes
                   SET status=?, updated_at=?, finished_at=?, payload=?, integrity_hash=?
                   WHERE probe_id=? AND status IN ('PENDING', 'PROBING')""",
                (
                    status,
                    now,
                    now,
                    json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
                    integrity_hash,
                    probe_id,
                ),
            )
        if cursor.rowcount != 1:
            raise PolicyError("format probe could not be completed")
        return {**record, "integrity_hash": integrity_hash, "reused": False}

    def load_format_probe(self, probe_id: str) -> dict[str, Any]:
        try:
            normalized_id = str(uuid.UUID(probe_id))
        except (ValueError, TypeError) as exc:
            raise PolicyError("format probe id is invalid") from exc
        with self._connection() as conn:
            row = conn.execute(
                """SELECT probe_id, entry_id, source_id, probe_version, cache_identity, sample_sha256, attempt, status, created_at, updated_at, finished_at, payload, integrity_hash
                   FROM format_probes WHERE probe_id=?""",
                (normalized_id,),
            ).fetchone()
        if not row:
            raise PolicyError("format probe was not found")
        try:
            payload = json.loads(row[11])
        except json.JSONDecodeError as exc:
            raise PolicyError("format probe payload was modified") from exc
        expected = {
            "probe_id": row[0],
            "entry_id": row[1],
            "source_id": row[2],
            "probe_version": row[3],
            "cache_identity": row[4],
            "sample_sha256": row[5],
            "attempt": row[6],
            "status": row[7],
            "created_at": row[8],
            "updated_at": row[9],
            "finished_at": row[10],
        }
        if not isinstance(payload, dict) or any(payload.get(key) != value for key, value in expected.items()):
            raise PolicyError("format probe metadata was modified")
        if sha256_json(payload) != row[12]:
            raise PolicyError("format probe integrity check failed")
        return {**payload, "integrity_hash": row[12]}

    def recover_interrupted_format_probes(self) -> int:
        now = _now()
        with self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            rows = conn.execute(
                """SELECT probe_id, payload
                   FROM format_probes
                   WHERE status IN ('PENDING', 'PROBING')"""
            ).fetchall()
            recovered = 0
            for probe_id, raw_payload in rows:
                try:
                    payload = json.loads(raw_payload)
                except json.JSONDecodeError:
                    payload = {"probe_id": probe_id}
                payload = dict(payload)
                payload.update({
                    "status": "FAILED",
                    "updated_at": now,
                    "finished_at": now,
                    "reason_code": "probe_interrupted",
                    "next_inspector": "NONE",
                })
                integrity_hash = sha256_json(payload)
                cursor = conn.execute(
                    """UPDATE format_probes
                       SET status='FAILED', updated_at=?, finished_at=?, payload=?, integrity_hash=?
                       WHERE probe_id=? AND status IN ('PENDING', 'PROBING')""",
                    (
                        now,
                        now,
                        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
                        integrity_hash,
                        probe_id,
                    ),
                )
                recovered += int(cursor.rowcount)
        return recovered

    @staticmethod
    def _create_format_probe_schema(conn: sqlite3.Connection, table_name: str = "format_probes") -> None:
        conn.execute(
            f"""CREATE TABLE IF NOT EXISTS {table_name} (
                probe_id TEXT PRIMARY KEY,
                entry_id TEXT NOT NULL REFERENCES catalog_entries(entry_id),
                source_id TEXT NOT NULL REFERENCES catalog_sources(source_id),
                probe_version TEXT NOT NULL,
                cache_identity TEXT NOT NULL,
                sample_sha256 TEXT NOT NULL,
                attempt INTEGER NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                finished_at TEXT,
                payload TEXT NOT NULL,
                integrity_hash TEXT NOT NULL
            )"""
        )
        conn.execute(f"CREATE INDEX IF NOT EXISTS {table_name}_entry_status ON {table_name}(entry_id, status)")
        conn.execute(f"CREATE INDEX IF NOT EXISTS {table_name}_cache_lookup ON {table_name}(entry_id, probe_version, cache_identity, status)")

    @classmethod
    def _migrate_format_probes(cls, conn: sqlite3.Connection) -> None:
        existing = [row[1] for row in conn.execute("PRAGMA table_info(format_probes)")]
        required = {
            "probe_id", "entry_id", "source_id", "probe_version", "cache_identity", "sample_sha256",
            "attempt", "status", "created_at", "updated_at", "finished_at", "payload", "integrity_hash",
        }
        if required.issubset(existing):
            conn.execute("CREATE INDEX IF NOT EXISTS format_probes_entry_status ON format_probes(entry_id, status)")
            conn.execute("CREATE INDEX IF NOT EXISTS format_probes_cache_lookup ON format_probes(entry_id, probe_version, cache_identity, status)")
            return
        if not existing:
            cls._create_format_probe_schema(conn)
            return

        conn.execute("ALTER TABLE format_probes RENAME TO format_probes_legacy")
        cls._create_format_probe_schema(conn)
        legacy_rows = conn.execute(
            """SELECT probe_id, entry_id, source_id, probe_version, metadata_key, status, created_at, updated_at, payload, integrity_hash
               FROM format_probes_legacy
               ORDER BY created_at, probe_id"""
        ).fetchall()
        attempts: dict[str, int] = {}
        for probe_id, entry_id, source_id, probe_version, metadata_key, status, created_at, updated_at, payload_json, _ in legacy_rows:
            try:
                payload = json.loads(payload_json)
            except json.JSONDecodeError:
                payload = {}
            payload = dict(payload) if isinstance(payload, dict) else {}
            attempts[entry_id] = attempts.get(entry_id, 0) + 1
            sample_sha256 = str(payload.get("sample_sha256") or "")
            cache_identity = str(payload.get("cache_identity") or metadata_key or "")
            if sample_sha256 and sample_sha256 not in cache_identity:
                cache_identity = f"{cache_identity}|{sample_sha256}" if cache_identity else sample_sha256
            finished_at = updated_at if status in {"COMPLETED", "STALE", "REJECTED", "FAILED"} else None
            normalized = {
                **payload,
                "probe_id": probe_id,
                "entry_id": entry_id,
                "source_id": source_id,
                "probe_version": probe_version,
                "cache_identity": cache_identity,
                "sample_sha256": sample_sha256,
                "attempt": attempts[entry_id],
                "status": status,
                "created_at": created_at,
                "updated_at": updated_at,
                "finished_at": finished_at,
            }
            conn.execute(
                """INSERT INTO format_probes
                   (probe_id, entry_id, source_id, probe_version, cache_identity, sample_sha256, attempt, status, created_at, updated_at, finished_at, payload, integrity_hash)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    probe_id,
                    entry_id,
                    source_id,
                    probe_version,
                    cache_identity,
                    sample_sha256,
                    attempts[entry_id],
                    status,
                    created_at,
                    updated_at,
                    finished_at,
                    json.dumps(normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
                    sha256_json(normalized),
                ),
            )
        conn.execute("DROP TABLE format_probes_legacy")

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

    def save_wsl_codex_runtime_config(self, binary_path: str) -> dict[str, Any]:
        """Persist the explicit WSL binary selection without returning its path."""
        clean_path = validate_wsl_codex_binary_path(binary_path)
        updated_at = _now()
        with self._connection() as conn:
            conn.execute(
                """INSERT INTO wsl_codex_runtime_config (singleton, binary_path, updated_at)
                   VALUES (1, ?, ?)
                   ON CONFLICT(singleton) DO UPDATE SET
                       binary_path=excluded.binary_path, updated_at=excluded.updated_at""",
                (clean_path, updated_at),
            )
        return {"backend": "WSL2_BWRAP", "binary_configured": True, "updated_at": updated_at}

    def wsl_codex_runtime_config_private(self) -> dict[str, Any] | None:
        """Internal-only lookup.  Callers must not pass this record to an API."""
        with self._connection() as conn:
            row = conn.execute(
                "SELECT binary_path, updated_at FROM wsl_codex_runtime_config WHERE singleton=1"
            ).fetchone()
        if not row:
            return None
        return {"binary_path": row[0], "updated_at": row[1]}

    def wsl_codex_runtime_config(self) -> dict[str, Any]:
        private = self.wsl_codex_runtime_config_private()
        if private is None:
            return {"backend": "WSL2_BWRAP", "status": "UNCONFIGURED", "binary_configured": False}
        return {
            "backend": "WSL2_BWRAP", "status": "CONFIGURED", "binary_configured": True,
            "updated_at": private["updated_at"],
        }

    def save_wsl_codex_runtime_result(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        """Store a redacted runtime preflight result, never argv, paths, env, or auth."""
        record = dict(payload)
        required = {
            "status", "checked_at", "config_hash", "runtime_fingerprint", "launch_spec_hash",
            "binary_configured", "version_match", "isolation_match", "egress_blocked",
            "start_allowed", "error_code", "local_duration_ms",
        }
        missing = required - record.keys()
        if missing:
            raise PolicyError(f"WSL Codex runtime result is missing fields: {', '.join(sorted(missing))}")
        allowed = required | {"preflight_status", "binary_size", "binary_sha256"}
        if set(record) - allowed:
            raise PolicyError("WSL Codex runtime result contains unsupported fields")
        statuses = {
            "UNCONFIGURED", "BINARY_MISSING", "INVALID_BINARY", "VERSION_MISMATCH",
            "EGRESS_UNCONFIGURED", "READY_CANDIDATE", "BLOCKED", "ERROR",
        }
        if record["status"] not in statuses:
            raise PolicyError("WSL Codex runtime status is invalid")
        for field in ("config_hash", "runtime_fingerprint", "launch_spec_hash", "binary_sha256"):
            value = record.get(field)
            if value is not None and (not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value)):
                raise PolicyError("WSL Codex runtime digest is invalid")
        for field in ("binary_configured", "version_match", "isolation_match", "egress_blocked", "start_allowed"):
            if not isinstance(record[field], bool):
                raise PolicyError("WSL Codex runtime flags are invalid")
        if record["egress_blocked"] is not True or record["start_allowed"] is not False:
            raise PolicyError("WSL Codex runtime must remain fail-closed")
        if not isinstance(record["checked_at"], str) or not record["checked_at"]:
            raise PolicyError("WSL Codex runtime timestamp is invalid")
        if record["error_code"] is not None and (
            not isinstance(record["error_code"], str)
            or not re.fullmatch(r"[a-z0-9_]{1,80}", record["error_code"])
        ):
            raise PolicyError("WSL Codex runtime error code is invalid")
        if not isinstance(record["local_duration_ms"], int) or record["local_duration_ms"] < 0:
            raise PolicyError("WSL Codex runtime duration is invalid")
        if record.get("preflight_status") is not None and record.get("preflight_status") != "READY_CANDIDATE":
            raise PolicyError("WSL Codex runtime preflight status is invalid")
        if record.get("binary_size") is not None and (
            not isinstance(record["binary_size"], int) or record["binary_size"] < 0
        ):
            raise PolicyError("WSL Codex runtime binary size is invalid")
        if record.get("binary_sha256") is not None and not record.get("binary_configured"):
            raise PolicyError("WSL Codex runtime binary digest requires a configured binary")
        forbidden = ("path", "argv", "environment", "auth", "token", "stdout", "stderr", "command", "secret")
        if any(any(fragment in key.casefold() for fragment in forbidden) for key in record):
            raise PolicyError("WSL Codex runtime result includes sensitive data")
        integrity_hash = sha256_json(record)
        with self._connection() as conn:
            conn.execute(
                """INSERT INTO wsl_codex_runtime_results
                   (singleton, status, checked_at, config_hash, runtime_fingerprint, launch_spec_hash, payload, integrity_hash)
                   VALUES (1, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(singleton) DO UPDATE SET
                       status=excluded.status, checked_at=excluded.checked_at,
                       config_hash=excluded.config_hash, runtime_fingerprint=excluded.runtime_fingerprint,
                       launch_spec_hash=excluded.launch_spec_hash, payload=excluded.payload,
                       integrity_hash=excluded.integrity_hash""",
                (
                    record["status"], record["checked_at"], record["config_hash"],
                    record["runtime_fingerprint"], record["launch_spec_hash"],
                    json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")), integrity_hash,
                ),
            )
        return {**record, "integrity_hash": integrity_hash}

    def wsl_codex_runtime_result(self) -> dict[str, Any] | None:
        with self._connection() as conn:
            row = conn.execute(
                """SELECT status, checked_at, config_hash, runtime_fingerprint, launch_spec_hash, payload, integrity_hash
                   FROM wsl_codex_runtime_results WHERE singleton=1"""
            ).fetchone()
        if not row:
            return None
        try:
            record = json.loads(row[5])
        except json.JSONDecodeError as exc:
            raise PolicyError("WSL Codex runtime result payload was modified") from exc
        expected = {
            "status": row[0], "checked_at": row[1], "config_hash": row[2],
            "runtime_fingerprint": row[3], "launch_spec_hash": row[4],
        }
        if not isinstance(record, dict) or any(record.get(key) != value for key, value in expected.items()):
            raise PolicyError("WSL Codex runtime result metadata was modified")
        if sha256_json(record) != row[6]:
            raise PolicyError("WSL Codex runtime result integrity check failed")
        return {**record, "integrity_hash": row[6]}

    def save_sealed_egress_contract(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        """Store a closed, redacted egress contract and never config TOML or auth."""
        record = dict(payload)
        required = {
            "status", "checked_at", "contract_hash", "runtime_fingerprint", "isolation_cache_key",
            "binary_sha256", "provider_config_hash", "contract_policy_version", "endpoint_type",
            "provider_snapshot", "relay_status", "broker_status", "auth_status", "start_allowed",
            "error_code", "local_duration_ms",
        }
        if set(record) != required:
            raise PolicyError("sealed egress contract fields are invalid")
        statuses = {
            "UNCONFIGURED", "CONTRACT_READY", "RELAY_MISSING", "BROKER_MISSING",
            "AUTH_UNCONFIGURED", "READY_CANDIDATE", "BLOCKED", "ERROR",
        }
        if record["status"] not in statuses:
            raise PolicyError("sealed egress contract status is invalid")
        for field in ("contract_hash", "runtime_fingerprint", "isolation_cache_key", "binary_sha256", "provider_config_hash"):
            value = record[field]
            if value is not None and (not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value)):
                raise PolicyError("sealed egress contract digest is invalid")
        if record["contract_policy_version"] != "sealed-egress-contract-v1":
            raise PolicyError("sealed egress contract policy version is invalid")
        if record["endpoint_type"] not in {"UNCONFIGURED", "LOOPBACK_HTTP_V1"}:
            raise PolicyError("sealed egress endpoint type is invalid")
        if record["relay_status"] not in {"CONTRACT_READY", "RELAY_MISSING", "BLOCKED", "ERROR"}:
            raise PolicyError("sealed egress relay state is invalid")
        if record["broker_status"] not in {"CONTRACT_READY", "BROKER_MISSING", "BLOCKED", "ERROR"}:
            raise PolicyError("sealed egress broker state is invalid")
        if record["auth_status"] not in {"AUTH_UNCONFIGURED", "READY_CANDIDATE", "BLOCKED", "ERROR"}:
            raise PolicyError("sealed egress auth state is invalid")
        if record["start_allowed"] is not False:
            raise PolicyError("sealed egress contract must remain start-blocked")
        if not isinstance(record["checked_at"], str) or not record["checked_at"]:
            raise PolicyError("sealed egress contract timestamp is invalid")
        if record["error_code"] is not None and (
            not isinstance(record["error_code"], str) or not re.fullmatch(r"[a-z0-9_]{1,80}", record["error_code"])
        ):
            raise PolicyError("sealed egress contract error code is invalid")
        if not isinstance(record["local_duration_ms"], int) or record["local_duration_ms"] < 0:
            raise PolicyError("sealed egress contract duration is invalid")
        snapshot = record["provider_snapshot"]
        expected_snapshot = {
            "provider_id", "endpoint_type", "wire_api", "requires_openai_auth", "env_key_name",
            "supports_websockets", "request_max_retries", "stream_max_retries",
        }
        if snapshot is not None and (not isinstance(snapshot, dict) or set(snapshot) != expected_snapshot):
            raise PolicyError("sealed egress provider snapshot is invalid")
        if snapshot is not None and (
            snapshot.get("provider_id") != "codexgate-sealed"
            or snapshot.get("endpoint_type") != "LOOPBACK_HTTP_V1"
            or snapshot.get("wire_api") != "responses"
            or snapshot.get("requires_openai_auth") is not False
            or snapshot.get("env_key_name") != "CODEXGATE_EPHEMERAL_TOKEN"
            or snapshot.get("supports_websockets") is not False
            or snapshot.get("request_max_retries") != 0
            or snapshot.get("stream_max_retries") != 0
        ):
            raise PolicyError("sealed egress provider snapshot is not closed")
        serialized = json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        forbidden = ("authorization", "cookie", "proxy-", "config_toml", "credential", "api_key", "secret")
        if any(value in serialized.casefold() for value in forbidden):
            raise PolicyError("sealed egress contract includes sensitive material")
        integrity_hash = sha256_json(record)
        with self._connection() as conn:
            conn.execute(
                """INSERT INTO sealed_egress_contracts
                   (singleton, status, checked_at, contract_hash, runtime_fingerprint, isolation_cache_key, payload, integrity_hash)
                   VALUES (1, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(singleton) DO UPDATE SET
                       status=excluded.status, checked_at=excluded.checked_at, contract_hash=excluded.contract_hash,
                       runtime_fingerprint=excluded.runtime_fingerprint, isolation_cache_key=excluded.isolation_cache_key,
                       payload=excluded.payload, integrity_hash=excluded.integrity_hash""",
                (
                    record["status"], record["checked_at"], record["contract_hash"],
                    record["runtime_fingerprint"], record["isolation_cache_key"], serialized, integrity_hash,
                ),
            )
        return {**record, "integrity_hash": integrity_hash}

    def sealed_egress_contract(self) -> dict[str, Any] | None:
        with self._connection() as conn:
            row = conn.execute(
                """SELECT status, checked_at, contract_hash, runtime_fingerprint, isolation_cache_key, payload, integrity_hash
                   FROM sealed_egress_contracts WHERE singleton=1"""
            ).fetchone()
        if not row:
            return None
        try:
            record = json.loads(row[5])
        except json.JSONDecodeError as exc:
            raise PolicyError("sealed egress contract payload was modified") from exc
        metadata = {
            "status": row[0], "checked_at": row[1], "contract_hash": row[2],
            "runtime_fingerprint": row[3], "isolation_cache_key": row[4],
        }
        if not isinstance(record, dict) or any(record.get(key) != value for key, value in metadata.items()):
            raise PolicyError("sealed egress contract metadata was modified")
        if sha256_json(record) != row[6]:
            raise PolicyError("sealed egress contract integrity check failed")
        return {**record, "integrity_hash": row[6]}

    def record_sealed_egress_contract_ledger(self, result: Mapping[str, Any]) -> dict[str, Any]:
        """Account for local contract construction only; tokens and RPCs stay zero."""
        checked_at = result.get("checked_at") if isinstance(result.get("checked_at"), str) else _now()
        contract_hash = result.get("contract_hash") if isinstance(result.get("contract_hash"), str) else "unconfigured"
        record = {
            "source_event_id": f"sealed-egress-contract:{contract_hash}:{checked_at}",
            "source": "LOCAL_ESTIMATE", "quality": "OBSERVED", "event_type": "SEALED_EGRESS_CONTRACT",
            "status": result.get("status") if isinstance(result.get("status"), str) else "ERROR",
            "contract_hash": contract_hash,
            "contract_executions": 1,
            "contract_duration_ms": int(result.get("local_duration_ms") or 0),
            "tokens": 0, "app_server_rpc_calls": 0, "occurred_at": checked_at,
        }
        digest = sha256_json(record)
        with self._connection() as conn:
            existing = conn.execute(
                "SELECT payload, integrity_hash FROM ledger_usage_events WHERE source_event_id=?", (record["source_event_id"],)
            ).fetchone()
            if existing:
                if existing[1] != digest:
                    raise PolicyError("sealed egress contract ledger event id was reused with different content")
                return {**json.loads(existing[0]), "integrity_hash": existing[1]}
            conn.execute(
                """INSERT INTO ledger_usage_events (
                    event_id, source_event_id, source, quality, event_type, run_id, task_id, route_plan_id,
                    comparison_key, success_criteria_hash, task_class, planned_model, actual_model, effort, status,
                    input_tokens, cached_input_tokens, output_tokens, reasoning_tokens, provider_total_tokens,
                    codex_context_bytes, web_packet_bytes, evidence_bytes, source_bytes, catalog_source_bytes,
                    probe_bytes, model_turns, high_model_turns, retries, reroutes, compactions, subagent_count,
                    occurred_at, payload, integrity_hash
                ) VALUES (?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, ?, NULL, NULL, NULL, NULL, NULL,
                    NULL, NULL, NULL, NULL, NULL, 0, 0, 0, 0, 0, 0, 0, ?, ?, ?)""",
                (
                    str(uuid.uuid4()), record["source_event_id"], record["source"], record["quality"], record["event_type"],
                    record["status"], record["occurred_at"],
                    json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")), digest,
                ),
            )
        return {**record, "integrity_hash": digest}

    def record_wsl_codex_runtime_preflight_ledger(self, result: Mapping[str, Any]) -> dict[str, Any]:
        """Account for local metadata work only; it cannot consume a model token or RPC."""
        checked_at = result.get("checked_at") if isinstance(result.get("checked_at"), str) else _now()
        config_hash = result.get("config_hash") if isinstance(result.get("config_hash"), str) else "unconfigured"
        fingerprint = result.get("runtime_fingerprint") if isinstance(result.get("runtime_fingerprint"), str) else "unknown"
        record = {
            "source_event_id": f"wsl-codex-runtime-preflight:{config_hash}:{fingerprint}:{checked_at}",
            "source": "LOCAL_ESTIMATE", "quality": "OBSERVED", "event_type": "WSL_CODEX_RUNTIME_PREFLIGHT",
            "status": result.get("status") if isinstance(result.get("status"), str) else "ERROR",
            "config_hash": config_hash, "runtime_fingerprint": fingerprint,
            "runtime_preflight_executions": 1,
            "runtime_preflight_duration_ms": int(result.get("local_duration_ms") or 0),
            "tokens": 0, "app_server_rpc_calls": 0, "occurred_at": checked_at,
        }
        digest = sha256_json(record)
        with self._connection() as conn:
            existing = conn.execute(
                "SELECT payload, integrity_hash FROM ledger_usage_events WHERE source_event_id=?", (record["source_event_id"],)
            ).fetchone()
            if existing:
                if existing[1] != digest:
                    raise PolicyError("WSL Codex runtime ledger event id was reused with different content")
                return {**json.loads(existing[0]), "integrity_hash": existing[1]}
            conn.execute(
                """INSERT INTO ledger_usage_events (
                    event_id, source_event_id, source, quality, event_type, run_id, task_id, route_plan_id,
                    comparison_key, success_criteria_hash, task_class, planned_model, actual_model, effort, status,
                    input_tokens, cached_input_tokens, output_tokens, reasoning_tokens, provider_total_tokens,
                    codex_context_bytes, web_packet_bytes, evidence_bytes, source_bytes, catalog_source_bytes,
                    probe_bytes, model_turns, high_model_turns, retries, reroutes, compactions, subagent_count,
                    occurred_at, payload, integrity_hash
                ) VALUES (?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, ?, NULL, NULL, NULL, NULL, NULL,
                    NULL, NULL, NULL, NULL, NULL, 0, 0, 0, 0, 0, 0, 0, ?, ?, ?)""",
                (
                    str(uuid.uuid4()), record["source_event_id"], record["source"], record["quality"], record["event_type"],
                    record["status"], record["occurred_at"],
                    json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")), digest,
                ),
            )
        return {**record, "integrity_hash": digest}

    def save_wsl_isolation_config(self, distro: str) -> dict[str, Any]:
        clean_distro = validate_wsl_distro(distro)
        updated_at = _now()
        with self._connection() as conn:
            conn.execute(
                """INSERT INTO wsl_isolation_config (singleton, distro, updated_at)
                   VALUES (1, ?, ?)
                   ON CONFLICT(singleton) DO UPDATE SET distro=excluded.distro, updated_at=excluded.updated_at""",
                (clean_distro, updated_at),
            )
        return {"backend": "WSL2_BWRAP", "distro": clean_distro, "updated_at": updated_at}

    def wsl_isolation_config(self) -> dict[str, Any]:
        with self._connection() as conn:
            row = conn.execute("SELECT distro, updated_at FROM wsl_isolation_config WHERE singleton=1").fetchone()
        if not row:
            return {"backend": "WSL2_BWRAP", "status": "UNCONFIGURED", "distro": None}
        return {"backend": "WSL2_BWRAP", "status": "CONFIGURED", "distro": row[0], "updated_at": row[1]}

    def save_wsl_isolation_preflight(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        """Store only a successful, short-lived preflight cache entry."""
        record = dict(payload)
        required = {"config_hash", "tool_fingerprint", "status", "checked_at", "expires_at"}
        if required - record.keys():
            raise PolicyError("WSL preflight cache is missing fields")
        if record.get("status") != "READY":
            raise PolicyError("only successful WSL preflights may be cached")
        for field in ("config_hash", "tool_fingerprint", "checked_at", "expires_at"):
            if not isinstance(record.get(field), str) or not record[field]:
                raise PolicyError("WSL preflight cache metadata is invalid")
        if any(key in record for key in ("stdout", "stderr", "raw_stdout", "raw_stderr", "argv", "command", "path")):
            raise PolicyError("WSL preflight cache includes sensitive data")
        digest = sha256_json(record)
        with self._connection() as conn:
            conn.execute(
                """INSERT INTO wsl_isolation_preflight_cache
                   (config_hash, tool_fingerprint, status, checked_at, expires_at, payload, integrity_hash)
                   VALUES (?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(config_hash) DO UPDATE SET
                     tool_fingerprint=excluded.tool_fingerprint, status=excluded.status,
                     checked_at=excluded.checked_at, expires_at=excluded.expires_at,
                     payload=excluded.payload, integrity_hash=excluded.integrity_hash""",
                (
                    record["config_hash"], record["tool_fingerprint"], record["status"],
                    record["checked_at"], record["expires_at"],
                    json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")), digest,
                ),
            )
        return {**record, "integrity_hash": digest}

    def wsl_isolation_preflight(self, config_hash: str) -> dict[str, Any] | None:
        with self._connection() as conn:
            row = conn.execute(
                """SELECT config_hash, tool_fingerprint, status, checked_at, expires_at, payload, integrity_hash
                   FROM wsl_isolation_preflight_cache WHERE config_hash=?""",
                (config_hash,),
            ).fetchone()
        if not row:
            return None
        try:
            record = json.loads(row[5])
        except json.JSONDecodeError as exc:
            raise PolicyError("WSL preflight cache payload was modified") from exc
        expected = {
            "config_hash": row[0], "tool_fingerprint": row[1], "status": row[2],
            "checked_at": row[3], "expires_at": row[4],
        }
        if not isinstance(record, dict) or any(record.get(key) != value for key, value in expected.items()):
            raise PolicyError("WSL preflight cache metadata was modified")
        if sha256_json(record) != row[6]:
            raise PolicyError("WSL preflight cache integrity check failed")
        return {**record, "integrity_hash": row[6]}

    # Explicit aliases keep the storage API discoverable without coupling callers
    # to the cache table's shorter internal name.
    save_wsl_isolation_preflight_result = save_wsl_isolation_preflight
    wsl_isolation_preflight_result = wsl_isolation_preflight

    def save_wsl_isolation_result(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        """Persist only redacted WSL probe metadata, never paths, canaries, commands, or process output."""
        record = dict(payload)
        required = {"backend", "status", "checked_at", "expires_at", "tool_versions"}
        missing = required - record.keys()
        if missing:
            raise PolicyError(f"WSL isolation result is missing fields: {', '.join(sorted(missing))}")
        statuses = {
            "UNCONFIGURED", "UNAVAILABLE", "MISCONFIGURED", "PROBING", "SAFE_CANDIDATE",
            "UNSAFE_HOST_FS", "UNSAFE_WRITE", "UNSAFE_NETWORK", "ERROR",
        }
        if record.get("backend") != "WSL2_BWRAP" or record.get("status") not in statuses:
            raise PolicyError("WSL isolation result is not supported")
        if record.get("distro") is not None:
            record["distro"] = validate_wsl_distro(record["distro"])
        if record.get("config_hash") is not None and not isinstance(record["config_hash"], str):
            raise PolicyError("WSL isolation config hash is invalid")
        for field in ("tool_fingerprint", "cache_key", "probe_version"):
            if record.get(field) is not None and not isinstance(record[field], str):
                raise PolicyError(f"WSL isolation {field} is invalid")
        if not isinstance(record.get("tool_versions"), Mapping):
            raise PolicyError("WSL isolation tool versions are invalid")
        for name, value in record["tool_versions"].items():
            if (
                not isinstance(name, str)
                or not (isinstance(value, str) or (isinstance(value, bool) and name in {"wsl2", "bwrap_present"}))
                or not value
                or (isinstance(value, str) and (
                    len(value) > 120
                    or "\n" in value
                    or "\r" in value
                    or "/" in value
                    or "\\" in value
                    or re.search(r"\b[A-Za-z]:", value)
                ))
            ):
                raise PolicyError("WSL isolation tool version is not sanitized")
        forbidden = (
            "inside_path", "outside_path", "host_path", "probe_root", "capsule_root",
            "command", "argv", "stdout", "stderr", "raw_stdout", "raw_stderr",
            "canary", "canary_bytes", "windows_path", "wsl_path",
        )
        if any(key in record for key in forbidden):
            raise PolicyError("WSL isolation result includes sensitive probe data")
        integrity_hash = sha256_json(record)
        with self._connection() as conn:
            conn.execute(
                """INSERT INTO wsl_isolation_probe_results
                   (singleton, backend, distro, config_hash, tool_fingerprint, cache_key, probe_version,
                    status, checked_at, expires_at, payload, integrity_hash)
                   VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(singleton) DO UPDATE SET
                     backend=excluded.backend, distro=excluded.distro, config_hash=excluded.config_hash,
                     tool_fingerprint=excluded.tool_fingerprint, cache_key=excluded.cache_key,
                     probe_version=excluded.probe_version,
                     status=excluded.status, checked_at=excluded.checked_at, expires_at=excluded.expires_at,
                     payload=excluded.payload, integrity_hash=excluded.integrity_hash""",
                (
                    record["backend"], record.get("distro"), record.get("config_hash"),
                    record.get("tool_fingerprint"), record.get("cache_key"), record.get("probe_version"),
                    record["status"], record["checked_at"], record["expires_at"],
                    json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")), integrity_hash,
                ),
            )
        return {**record, "integrity_hash": integrity_hash}

    def wsl_isolation_result(
        self,
        config_hash: str | None = None,
        tool_fingerprint: str | None = None,
        cache_key: str | None = None,
    ) -> dict[str, Any]:
        with self._connection() as conn:
            row = conn.execute(
                """SELECT backend, distro, config_hash, tool_fingerprint, cache_key, probe_version,
                          status, checked_at, expires_at, payload, integrity_hash
                   FROM wsl_isolation_probe_results WHERE singleton=1"""
            ).fetchone()
        if not row:
            return {"backend": "WSL2_BWRAP", "status": "UNCONFIGURED", "distro": None}
        try:
            record = json.loads(row[9])
        except json.JSONDecodeError as exc:
            raise PolicyError("WSL isolation result payload was modified") from exc
        expected = {
            "backend": row[0], "distro": row[1], "config_hash": row[2],
            "tool_fingerprint": row[3], "cache_key": row[4], "probe_version": row[5],
            "status": row[6], "checked_at": row[7], "expires_at": row[8],
        }
        if not isinstance(record, dict) or any(record.get(key) != value for key, value in expected.items()):
            raise PolicyError("WSL isolation result metadata was modified")
        if sha256_json(record) != row[10]:
            raise PolicyError("WSL isolation result integrity check failed")
        if config_hash is not None and record.get("config_hash") != config_hash:
            return {"backend": "WSL2_BWRAP", "status": "UNCONFIGURED", "distro": record.get("distro")}
        if tool_fingerprint is not None and record.get("tool_fingerprint") != tool_fingerprint:
            return {"backend": "WSL2_BWRAP", "status": "UNCONFIGURED", "distro": record.get("distro")}
        if cache_key is not None and record.get("cache_key") != cache_key:
            return {"backend": "WSL2_BWRAP", "status": "UNCONFIGURED", "distro": record.get("distro")}
        if config_hash is None:
            current_config = self.wsl_isolation_config()
            current_distro = current_config.get("distro")
            if isinstance(current_distro, str) and current_distro != record.get("distro"):
                return {"backend": "WSL2_BWRAP", "status": "UNCONFIGURED", "distro": current_distro}
        return {**record, "integrity_hash": row[10]}

    @staticmethod
    def _migrate_wsl_isolation_probe_results(conn: sqlite3.Connection) -> None:
        """Add environment identity columns without changing legacy payloads."""
        columns = {row[1] for row in conn.execute("PRAGMA table_info(wsl_isolation_probe_results)")}
        for name, declaration in (("tool_fingerprint", "TEXT"), ("cache_key", "TEXT"), ("probe_version", "TEXT")):
            if name not in columns:
                conn.execute(f"ALTER TABLE wsl_isolation_probe_results ADD COLUMN {name} {declaration}")

    def recover_interrupted_wsl_isolation_probes(self) -> int:
        now = _now()
        with self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT payload, integrity_hash FROM wsl_isolation_probe_results WHERE singleton=1 AND status='PROBING'"
            ).fetchone()
            if not row:
                return 0
            try:
                record = json.loads(row[0])
            except json.JSONDecodeError:
                record = {"backend": "WSL2_BWRAP"}
            record = dict(record)
            record.update({
                "status": "ERROR", "checked_at": now, "expires_at": now,
                "error_code": "probe_interrupted", "reused": False,
            })
            digest = sha256_json(record)
            cursor = conn.execute(
                """UPDATE wsl_isolation_probe_results
                   SET status='ERROR', checked_at=?, expires_at=?, payload=?, integrity_hash=?
                   WHERE singleton=1 AND status='PROBING'""",
                (now, now, json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")), digest),
            )
        return int(cursor.rowcount)

    def save_wsl_isolation_repro(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        """Persist a redacted deterministic reproducibility summary."""
        record = dict(payload)
        required = {"repro_id", "cache_key", "config_hash", "tool_fingerprint", "status",
                    "requested_runs", "completed_runs", "success_count", "duration_ms", "started_at"}
        if required - record.keys():
            raise PolicyError("WSL reproducibility result is missing fields")
        allowed = {"RUNNING", "COMPLETED", "SAFE_REPRODUCIBLE", "NONDETERMINISTIC", "UNSAFE_HOST_FS", "UNSAFE_WRITE",
                   "UNSAFE_NETWORK", "ERROR", "REJECTED"}
        if record.get("status") not in allowed:
            raise PolicyError("WSL reproducibility status is invalid")
        for name in ("repro_id", "cache_key", "config_hash", "tool_fingerprint", "started_at"):
            if not isinstance(record.get(name), str) or not record[name] or len(record[name]) > 256:
                raise PolicyError("WSL reproducibility identity is invalid")
        for name in ("requested_runs", "completed_runs", "success_count", "duration_ms"):
            if not isinstance(record.get(name), int) or record[name] < 0:
                raise PolicyError("WSL reproducibility counters are invalid")
        if record["requested_runs"] != 10 or record["completed_runs"] > record["requested_runs"]:
            raise PolicyError("WSL reproducibility run count is invalid")
        if record.get("error_code") is not None and (not isinstance(record["error_code"], str) or len(record["error_code"]) > 80):
            raise PolicyError("WSL reproducibility error is invalid")
        if record.get("result_hash") is not None and (not isinstance(record["result_hash"], str) or len(record["result_hash"]) != 64):
            raise PolicyError("WSL reproducibility result hash is invalid")
        diagnostic = record.get("diagnostic")
        if diagnostic is not None:
            if not isinstance(diagnostic, Mapping) or set(diagnostic) != {"exit_code", "stdout_bytes", "stderr_bytes", "frame_count", "error_code", "fixture_bytes"}:
                raise PolicyError("WSL reproducibility diagnostic is invalid")
            if diagnostic["exit_code"] is not None and not isinstance(diagnostic["exit_code"], int):
                raise PolicyError("WSL reproducibility diagnostic is invalid")
            for name in ("stdout_bytes", "stderr_bytes", "frame_count"):
                if not isinstance(diagnostic[name], int) or diagnostic[name] < 0 or diagnostic[name] > 8192:
                    raise PolicyError("WSL reproducibility diagnostic is invalid")
            if diagnostic["stdout_bytes"] + diagnostic["stderr_bytes"] > 8192:
                raise PolicyError("WSL reproducibility diagnostic is invalid")
            if diagnostic["fixture_bytes"] is not None and (not isinstance(diagnostic["fixture_bytes"], int) or diagnostic["fixture_bytes"] < 0 or diagnostic["fixture_bytes"] > 8192):
                raise PolicyError("WSL reproducibility diagnostic is invalid")
            if diagnostic["error_code"] is not None and (not isinstance(diagnostic["error_code"], str) or len(diagnostic["error_code"]) > 80):
                raise PolicyError("WSL reproducibility diagnostic is invalid")
        forbidden = ("path", "root", "fixture", "canary", "stdout", "stderr", "raw", "argv", "command", "content")
        if any(any(token in str(key).casefold() for token in forbidden) for key in record):
            raise PolicyError("WSL reproducibility result includes sensitive data")
        allowed_keys = required | {"result_hash", "finished_at", "error_code", "diagnostic"}
        if set(record) - allowed_keys:
            raise PolicyError("WSL reproducibility result contains unsupported fields")
        digest = sha256_json(record)
        with self._connection() as conn:
            conn.execute(
                """INSERT INTO wsl_isolation_repro_runs
                   (repro_id, cache_key, config_hash, tool_fingerprint, status, requested_runs,
                    completed_runs, success_count, result_hash, duration_ms, started_at, finished_at,
                    error_code, payload, integrity_hash)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(cache_key) DO UPDATE SET
                     repro_id=excluded.repro_id, config_hash=excluded.config_hash,
                     tool_fingerprint=excluded.tool_fingerprint, status=excluded.status,
                     requested_runs=excluded.requested_runs, completed_runs=excluded.completed_runs,
                     success_count=excluded.success_count, result_hash=excluded.result_hash,
                     duration_ms=excluded.duration_ms, started_at=excluded.started_at,
                     finished_at=excluded.finished_at, error_code=excluded.error_code,
                     payload=excluded.payload, integrity_hash=excluded.integrity_hash""",
                (record["repro_id"], record["cache_key"], record["config_hash"], record["tool_fingerprint"],
                 record["status"], record["requested_runs"], record["completed_runs"], record["success_count"],
                 record.get("result_hash"), record["duration_ms"], record["started_at"], record.get("finished_at"),
                 record.get("error_code"), json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")), digest),
            )
        return {**record, "integrity_hash": digest}

    def wsl_isolation_repro(self, cache_key: str) -> dict[str, Any] | None:
        with self._connection() as conn:
            row = conn.execute(
                "SELECT payload, integrity_hash FROM wsl_isolation_repro_runs WHERE cache_key=?", (cache_key,)
            ).fetchone()
        if not row:
            return None
        try:
            record = json.loads(row[0])
        except json.JSONDecodeError as exc:
            raise PolicyError("WSL reproducibility payload was modified") from exc
        if not isinstance(record, dict) or sha256_json(record) != row[1]:
            raise PolicyError("WSL reproducibility integrity check failed")
        return {**record, "integrity_hash": row[1]}

    save_wsl_isolation_repro_result = save_wsl_isolation_repro
    wsl_isolation_repro_result = wsl_isolation_repro

    def recover_interrupted_wsl_isolation_repros(self) -> int:
        now = _now()
        with self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            rows = conn.execute(
                "SELECT repro_id, payload FROM wsl_isolation_repro_runs WHERE status='RUNNING'"
            ).fetchall()
            count = 0
            for repro_id, payload in rows:
                try:
                    record = json.loads(payload)
                except json.JSONDecodeError:
                    record = {}
                record = dict(record)
                record.update({"status": "ERROR", "finished_at": now, "error_code": "repro_interrupted"})
                digest = sha256_json(record)
                cursor = conn.execute(
                    """UPDATE wsl_isolation_repro_runs SET status='ERROR', finished_at=?, error_code=?, payload=?, integrity_hash=?
                       WHERE repro_id=? AND status='RUNNING'""",
                    (now, "repro_interrupted", json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")), digest, repro_id),
                )
                count += int(cursor.rowcount)
        return count

    recover_interrupted_isolation_repros = recover_interrupted_wsl_isolation_repros

    def record_wsl_isolation_repro_ledger(self, result: Mapping[str, Any]) -> dict[str, Any]:
        checked_at = result.get("finished_at") if isinstance(result.get("finished_at"), str) else _now()
        key = result.get("cache_key") if isinstance(result.get("cache_key"), str) else "unknown"
        record = {
            "source_event_id": f"wsl-repro:{key}:{checked_at}", "source": "LOCAL_ESTIMATE", "quality": "OBSERVED",
            "event_type": "WSL_ISOLATION_REPRO", "status": result.get("status", "ERROR"),
            "cache_key": key, "local_executions": int(result.get("completed_runs") or 0),
            "local_duration_ms": int(result.get("duration_ms") or 0), "tokens": 0, "app_server_rpc_calls": 0,
            "occurred_at": checked_at,
        }
        digest = sha256_json(record)
        with self._connection() as conn:
            existing = conn.execute("SELECT payload, integrity_hash FROM ledger_usage_events WHERE source_event_id=?", (record["source_event_id"],)).fetchone()
            if existing:
                if existing[1] != digest:
                    raise PolicyError("WSL reproducibility ledger event was reused with different content")
                return {**json.loads(existing[0]), "integrity_hash": existing[1]}
            conn.execute(
                """INSERT INTO ledger_usage_events
                   (event_id, source_event_id, source, quality, event_type, status, payload, integrity_hash, occurred_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (str(uuid.uuid4()), record["source_event_id"], record["source"], record["quality"], record["event_type"],
                 record["status"], json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")), digest, checked_at),
            )
        return {**record, "integrity_hash": digest}

    def record_wsl_isolation_probe_ledger(self, result: Mapping[str, Any]) -> dict[str, Any]:
        """Store only local probe count/time; token and app-server counters remain exactly zero."""
        checked_at = result.get("checked_at") if isinstance(result.get("checked_at"), str) else _now()
        duration = result.get("local_duration_ms")
        duration = duration if isinstance(duration, int) and duration >= 0 else 0
        config_hash = result.get("config_hash") if isinstance(result.get("config_hash"), str) else "unconfigured"
        record = {
            "source_event_id": f"wsl-isolation:{config_hash}:{checked_at}",
            "source": "LOCAL_ESTIMATE",
            "quality": "OBSERVED",
            "event_type": "WSL_ISOLATION_PROBE",
            "status": result.get("status") if isinstance(result.get("status"), str) else "ERROR",
            "config_hash": config_hash,
            "tool_fingerprint": result.get("tool_fingerprint") if isinstance(result.get("tool_fingerprint"), str) else None,
            "input_tokens": None,
            "cached_input_tokens": None,
            "output_tokens": None,
            "reasoning_tokens": None,
            "provider_total_tokens": None,
            "probe_bytes": 0,
            "model_turns": 0,
            "high_model_turns": 0,
            "retries": 0,
            "reroutes": 0,
            "compactions": 0,
            "subagent_count": 0,
            "probe_executions": 1,
            "preflight_executions": 0,
            "preflight_duration_ms": 0,
            "local_duration_ms": duration,
            "tokens": 0,
            "app_server_rpc_calls": 0,
            "occurred_at": checked_at,
        }
        digest = sha256_json(record)
        with self._connection() as conn:
            existing = conn.execute(
                "SELECT payload, integrity_hash FROM ledger_usage_events WHERE source_event_id=?", (record["source_event_id"],)
            ).fetchone()
            if existing:
                if existing[1] != digest:
                    raise PolicyError("WSL isolation ledger event id was reused with different content")
                return {**json.loads(existing[0]), "integrity_hash": existing[1]}
            conn.execute(
                """INSERT INTO ledger_usage_events (
                    event_id, source_event_id, source, quality, event_type, run_id, task_id, route_plan_id,
                    comparison_key, success_criteria_hash, task_class, planned_model, actual_model, effort, status,
                    input_tokens, cached_input_tokens, output_tokens, reasoning_tokens, provider_total_tokens,
                    codex_context_bytes, web_packet_bytes, evidence_bytes, source_bytes, catalog_source_bytes,
                    probe_bytes, model_turns, high_model_turns, retries, reroutes, compactions, subagent_count,
                    occurred_at, payload, integrity_hash
                ) VALUES (?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, ?, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, 0, 0, 0, 0, 0, 0, ?, ?, ?)""",
                (
                    str(uuid.uuid4()), record["source_event_id"], record["source"], record["quality"],
                    record["event_type"], record["status"], record["occurred_at"],
                    json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")), digest,
                ),
            )
        return {**record, "integrity_hash": digest}

    def record_wsl_isolation_preflight_ledger(self, result: Mapping[str, Any]) -> dict[str, Any]:
        """Record the fixed metadata preflight separately from canary executions."""
        checked_at = _now()
        config_hash = result.get("config_hash") if isinstance(result.get("config_hash"), str) else "unconfigured"
        tool_fp = result.get("tool_fingerprint") if isinstance(result.get("tool_fingerprint"), str) else "unknown"
        duration = result.get("preflight_duration_ms")
        duration = duration if isinstance(duration, int) and duration >= 0 else 0
        record = {
            "source_event_id": f"wsl-isolation-preflight:{config_hash}:{tool_fp}:{checked_at}",
            "source": "LOCAL_ESTIMATE",
            "quality": "OBSERVED",
            "event_type": "WSL_ISOLATION_PREFLIGHT",
            "status": result.get("status") if isinstance(result.get("status"), str) else "ERROR",
            "config_hash": config_hash,
            "tool_fingerprint": tool_fp,
            "preflight_executions": 1,
            "preflight_duration_ms": duration,
            "stages": list(result.get("stages")) if isinstance(result.get("stages"), list) else [],
            "error_code": result.get("error_code") if isinstance(result.get("error_code"), str) else None,
            "probe_executions": 0,
            "local_duration_ms": 0,
            "tokens": 0,
            "app_server_rpc_calls": 0,
            "occurred_at": checked_at,
        }
        digest = sha256_json(record)
        with self._connection() as conn:
            existing = conn.execute(
                "SELECT payload, integrity_hash FROM ledger_usage_events WHERE source_event_id=?",
                (record["source_event_id"],),
            ).fetchone()
            if existing:
                if existing[1] != digest:
                    raise PolicyError("WSL preflight ledger event id was reused with different content")
                return {**json.loads(existing[0]), "integrity_hash": existing[1]}
            conn.execute(
                """INSERT INTO ledger_usage_events (
                    event_id, source_event_id, source, quality, event_type, run_id, task_id, route_plan_id,
                    comparison_key, success_criteria_hash, task_class, planned_model, actual_model, effort, status,
                    input_tokens, cached_input_tokens, output_tokens, reasoning_tokens, provider_total_tokens,
                    codex_context_bytes, web_packet_bytes, evidence_bytes, source_bytes, catalog_source_bytes,
                    probe_bytes, model_turns, high_model_turns, retries, reroutes, compactions, subagent_count,
                    occurred_at, payload, integrity_hash
                ) VALUES (?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, ?, NULL, NULL, NULL, NULL, NULL,
                    NULL, NULL, NULL, NULL, NULL, 0, 0, 0, 0, 0, 0, 0, ?, ?, ?)""",
                (
                    str(uuid.uuid4()), record["source_event_id"], record["source"], record["quality"],
                    record["event_type"], record["status"], record["occurred_at"],
                    json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")), digest,
                ),
            )
        return {**record, "integrity_hash": digest}

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

    def record_ledger_run(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        record = normalize_run_record(payload)
        if record["status"] in {"SUCCESS", "FAILED"} and not record.get("finished_at"):
            record["finished_at"] = _now()
        integrity_hash = sha256_json(record)
        with self._connection() as conn:
            conn.execute(
                """INSERT INTO ledger_runs (
                    run_id, task_id, route_plan_id, comparison_key, success_criteria_hash, task_class,
                    planned_model, actual_model, effort, status, quality, input_tokens, cached_input_tokens,
                    output_tokens, reasoning_tokens, provider_total_tokens, processed_tokens,
                    non_cached_input_tokens, cache_ratio, codex_context_bytes, web_packet_bytes,
                    evidence_bytes, source_bytes, catalog_source_bytes, probe_bytes, model_turns,
                    high_model_turns, retries, reroutes, compactions, subagent_count, created_at, updated_at,
                    finished_at, payload, integrity_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(run_id) DO UPDATE SET
                    task_id=excluded.task_id,
                    route_plan_id=excluded.route_plan_id,
                    comparison_key=excluded.comparison_key,
                    success_criteria_hash=excluded.success_criteria_hash,
                    task_class=excluded.task_class,
                    planned_model=excluded.planned_model,
                    actual_model=excluded.actual_model,
                    effort=excluded.effort,
                    status=excluded.status,
                    quality=excluded.quality,
                    input_tokens=excluded.input_tokens,
                    cached_input_tokens=excluded.cached_input_tokens,
                    output_tokens=excluded.output_tokens,
                    reasoning_tokens=excluded.reasoning_tokens,
                    provider_total_tokens=excluded.provider_total_tokens,
                    processed_tokens=excluded.processed_tokens,
                    non_cached_input_tokens=excluded.non_cached_input_tokens,
                    cache_ratio=excluded.cache_ratio,
                    codex_context_bytes=excluded.codex_context_bytes,
                    web_packet_bytes=excluded.web_packet_bytes,
                    evidence_bytes=excluded.evidence_bytes,
                    source_bytes=excluded.source_bytes,
                    catalog_source_bytes=excluded.catalog_source_bytes,
                    probe_bytes=excluded.probe_bytes,
                    model_turns=excluded.model_turns,
                    high_model_turns=excluded.high_model_turns,
                    retries=excluded.retries,
                    reroutes=excluded.reroutes,
                    compactions=excluded.compactions,
                    subagent_count=excluded.subagent_count,
                    updated_at=excluded.updated_at,
                    finished_at=excluded.finished_at,
                    payload=excluded.payload,
                    integrity_hash=excluded.integrity_hash""",
                (
                    record["run_id"],
                    record["task_id"],
                    record["route_plan_id"],
                    record["comparison_key"],
                    record["success_criteria_hash"],
                    record["task_class"],
                    record["planned_model"],
                    record["actual_model"],
                    record["effort"],
                    record["status"],
                    record["quality"],
                    record["input_tokens"],
                    record["cached_input_tokens"],
                    record["output_tokens"],
                    record["reasoning_tokens"],
                    record["provider_total_tokens"],
                    record["processed_tokens"],
                    record["non_cached_input_tokens"],
                    record["cache_ratio"],
                    record["codex_context_bytes"],
                    record["web_packet_bytes"],
                    record["evidence_bytes"],
                    record["source_bytes"],
                    record["catalog_source_bytes"],
                    record["probe_bytes"],
                    record["model_turns"],
                    record["high_model_turns"],
                    record["retries"],
                    record["reroutes"],
                    record["compactions"],
                    record["subagent_count"],
                    record["created_at"],
                    record["updated_at"],
                    record["finished_at"],
                    json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
                    integrity_hash,
                ),
            )
        return {**record, "integrity_hash": integrity_hash}

    def record_ledger_usage_event(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        record = normalize_usage_event(payload)
        integrity_hash = sha256_json(record)
        with self._connection() as conn:
            existing = conn.execute(
                "SELECT payload, integrity_hash FROM ledger_usage_events WHERE source_event_id = ?",
                (record["source_event_id"],),
            ).fetchone()
            if existing:
                if existing[1] != integrity_hash:
                    raise PolicyError("usage event source_event_id was reused with different content")
                return {**json.loads(existing[0]), "integrity_hash": existing[1]}
            try:
                conn.execute(
                    """INSERT INTO ledger_usage_events (
                        event_id, source_event_id, source, quality, event_type, run_id, task_id, route_plan_id,
                        comparison_key, success_criteria_hash, task_class, planned_model, actual_model, effort, status,
                        input_tokens, cached_input_tokens, output_tokens, reasoning_tokens, provider_total_tokens,
                        codex_context_bytes, web_packet_bytes, evidence_bytes, source_bytes, catalog_source_bytes,
                        probe_bytes, model_turns, high_model_turns, retries, reroutes, compactions, subagent_count,
                        occurred_at, payload, integrity_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        str(uuid.uuid4()),
                        record["source_event_id"],
                        record["source"],
                        record["quality"],
                        record["event_type"],
                        record.get("run_id"),
                        record.get("task_id"),
                        record.get("route_plan_id"),
                        record.get("comparison_key"),
                        record.get("success_criteria_hash"),
                        record.get("task_class"),
                        record.get("planned_model"),
                        record.get("actual_model"),
                        record.get("effort"),
                        record.get("status"),
                        record["input_tokens"],
                        record["cached_input_tokens"],
                        record["output_tokens"],
                        record["reasoning_tokens"],
                        record["provider_total_tokens"],
                        record["codex_context_bytes"],
                        record["web_packet_bytes"],
                        record["evidence_bytes"],
                        record["source_bytes"],
                        record["catalog_source_bytes"],
                        record["probe_bytes"],
                        record["model_turns"],
                        record["high_model_turns"],
                        record["retries"],
                        record["reroutes"],
                        record["compactions"],
                        record["subagent_count"],
                        record["occurred_at"],
                        json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
                        integrity_hash,
                    ),
                )
            except sqlite3.IntegrityError:
                existing = conn.execute(
                    "SELECT payload, integrity_hash FROM ledger_usage_events WHERE source_event_id = ?",
                    (record["source_event_id"],),
                ).fetchone()
                if not existing:
                    raise
                if existing[1] != integrity_hash:
                    raise PolicyError("usage event source_event_id was reused with different content")
                return {**json.loads(existing[0]), "integrity_hash": existing[1]}
        return {**record, "integrity_hash": integrity_hash}

    def record_ledger_baseline(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        record = normalize_baseline_payload(payload)
        integrity_hash = sha256_json(record)
        with self._connection() as conn:
            conn.execute(
                """INSERT INTO ledger_baselines (
                    baseline_id, task_id, route_plan_id, comparison_key, success_criteria_hash, task_class,
                    planned_model, actual_model, effort, status, quality, input_tokens, cached_input_tokens,
                    output_tokens, reasoning_tokens, provider_total_tokens, processed_tokens,
                    non_cached_input_tokens, cache_ratio, codex_context_bytes, web_packet_bytes,
                    evidence_bytes, source_bytes, catalog_source_bytes, probe_bytes, model_turns,
                    high_model_turns, retries, reroutes, compactions, subagent_count, created_at, updated_at,
                    payload, integrity_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(baseline_id) DO UPDATE SET
                    task_id=excluded.task_id,
                    route_plan_id=excluded.route_plan_id,
                    comparison_key=excluded.comparison_key,
                    success_criteria_hash=excluded.success_criteria_hash,
                    task_class=excluded.task_class,
                    planned_model=excluded.planned_model,
                    actual_model=excluded.actual_model,
                    effort=excluded.effort,
                    status=excluded.status,
                    quality=excluded.quality,
                    input_tokens=excluded.input_tokens,
                    cached_input_tokens=excluded.cached_input_tokens,
                    output_tokens=excluded.output_tokens,
                    reasoning_tokens=excluded.reasoning_tokens,
                    provider_total_tokens=excluded.provider_total_tokens,
                    processed_tokens=excluded.processed_tokens,
                    non_cached_input_tokens=excluded.non_cached_input_tokens,
                    cache_ratio=excluded.cache_ratio,
                    codex_context_bytes=excluded.codex_context_bytes,
                    web_packet_bytes=excluded.web_packet_bytes,
                    evidence_bytes=excluded.evidence_bytes,
                    source_bytes=excluded.source_bytes,
                    catalog_source_bytes=excluded.catalog_source_bytes,
                    probe_bytes=excluded.probe_bytes,
                    model_turns=excluded.model_turns,
                    high_model_turns=excluded.high_model_turns,
                    retries=excluded.retries,
                    reroutes=excluded.reroutes,
                    compactions=excluded.compactions,
                    subagent_count=excluded.subagent_count,
                    updated_at=excluded.updated_at,
                    payload=excluded.payload,
                    integrity_hash=excluded.integrity_hash""",
                (
                    record["baseline_id"],
                    record["task_id"],
                    record["route_plan_id"],
                    record["comparison_key"],
                    record["success_criteria_hash"],
                    record["task_class"],
                    record["planned_model"],
                    record["actual_model"],
                    record["effort"],
                    record["status"],
                    record["quality"],
                    record["input_tokens"],
                    record["cached_input_tokens"],
                    record["output_tokens"],
                    record["reasoning_tokens"],
                    record["provider_total_tokens"],
                    record["processed_tokens"],
                    record["non_cached_input_tokens"],
                    record["cache_ratio"],
                    record["codex_context_bytes"],
                    record["web_packet_bytes"],
                    record["evidence_bytes"],
                    record["source_bytes"],
                    record["catalog_source_bytes"],
                    record["probe_bytes"],
                    record["model_turns"],
                    record["high_model_turns"],
                    record["retries"],
                    record["reroutes"],
                    record["compactions"],
                    record["subagent_count"],
                    record["created_at"],
                    _now(),
                    json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
                    integrity_hash,
                ),
            )
        return {**record, "integrity_hash": integrity_hash}

    def ledger_runs(self) -> list[dict[str, Any]]:
        with self._connection() as conn:
            rows = conn.execute("SELECT payload, integrity_hash FROM ledger_runs ORDER BY updated_at DESC, run_id DESC").fetchall()
        return [{**json.loads(payload), "integrity_hash": integrity_hash} for payload, integrity_hash in rows]

    def ledger_baselines(self) -> list[dict[str, Any]]:
        with self._connection() as conn:
            rows = conn.execute("SELECT payload, integrity_hash FROM ledger_baselines ORDER BY updated_at DESC, baseline_id DESC").fetchall()
        return [{**json.loads(payload), "integrity_hash": integrity_hash} for payload, integrity_hash in rows]

    def ledger_usage_events(self) -> list[dict[str, Any]]:
        with self._connection() as conn:
            rows = conn.execute("SELECT payload, integrity_hash FROM ledger_usage_events ORDER BY occurred_at DESC, source_event_id DESC").fetchall()
        return [{**json.loads(payload), "integrity_hash": integrity_hash} for payload, integrity_hash in rows]

    def token_ledger_report(self) -> dict[str, Any]:
        usage_events = self.ledger_usage_events()
        report = build_report(self.ledger_runs(), self.ledger_baselines(), usage_events)
        wsl_events = [event for event in usage_events if event.get("event_type") in {"WSL_ISOLATION_PROBE", "WSL_ISOLATION_PREFLIGHT", "WSL_ISOLATION_REPRO"}]
        report["wsl_isolation_probes"] = {
            "executions": sum(int(event.get("probe_executions") or 0) for event in wsl_events),
            "local_duration_ms": sum(int(event.get("local_duration_ms") or 0) for event in wsl_events),
            "tokens": 0,
            "app_server_rpc_calls": 0,
        }
        report["wsl_isolation_preflight"] = {
            "executions": sum(int(event.get("preflight_executions") or 0) for event in wsl_events),
            "local_duration_ms": sum(int(event.get("preflight_duration_ms") or 0) for event in wsl_events),
            "tokens": 0,
            "app_server_rpc_calls": 0,
        }
        repro_events = [event for event in usage_events if event.get("event_type") == "WSL_ISOLATION_REPRO"]
        report["wsl_isolation_repro"] = {
            "executions": sum(int(event.get("local_executions") or 0) for event in repro_events),
            "local_duration_ms": sum(int(event.get("local_duration_ms") or 0) for event in repro_events),
            "tokens": 0,
            "app_server_rpc_calls": 0,
        }
        runtime_events = [event for event in usage_events if event.get("event_type") == "WSL_CODEX_RUNTIME_PREFLIGHT"]
        report["wsl_codex_runtime_preflight"] = {
            "executions": sum(int(event.get("runtime_preflight_executions") or 0) for event in runtime_events),
            "local_duration_ms": sum(int(event.get("runtime_preflight_duration_ms") or 0) for event in runtime_events),
            "tokens": 0,
            "app_server_rpc_calls": 0,
        }
        contract_events = [event for event in usage_events if event.get("event_type") == "SEALED_EGRESS_CONTRACT"]
        report["sealed_egress_contract"] = {
            "executions": sum(int(event.get("contract_executions") or 0) for event in contract_events),
            "local_duration_ms": sum(int(event.get("contract_duration_ms") or 0) for event in contract_events),
            "tokens": 0,
            "app_server_rpc_calls": 0,
        }
        return report

    def export_token_ledger_report(self, format: str = "json") -> str:
        report = self.token_ledger_report()
        if format == "markdown":
            return render_markdown(report)
        if format != "json":
            raise PolicyError("Token ledger export format is not supported")
        return canonical_json(report)

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
