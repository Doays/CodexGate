from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Mapping

from jsonschema import Draft7Validator

from .policy import PolicyError, bridge_packet_safety_reason, canonical_json, sha256_json


LEDGER_SOURCES = frozenset({"MANUAL_BASELINE", "CODEX_APP_SERVER", "OPENAI_API", "LOCAL_ESTIMATE", "LOCAL_OBSERVED"})
LEDGER_QUALITIES = frozenset({"OBSERVED", "IMPORTED", "ESTIMATED"})
SUCCESS_STATUSES = frozenset({"SUCCESS"})
HIGH_EFFORTS = frozenset({"high", "very-high", "very high", "xhigh", "x-high", "max", "ultra"})
# These locally simulated verification events are deliberately not evidence of
# provider usage.  They remain ESTIMATED and cannot make savings comparable.
LOCAL_ONLY_EVENT_TYPES = frozenset({"SEALED_OFFLINE_CODEX_PROCESS_CANARY", "SEALED_OFFLINE_CODEX_PROCESS_CANARY_PLAN"})

BASELINE_IMPORT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "comparison_key",
        "success_criteria_hash",
        "task_class",
        "planned_model",
        "effort",
        "status",
        "quality",
        "source",
    ],
    "properties": {
        "baseline_id": {"type": "string", "minLength": 1},
        "task_id": {"type": "string", "minLength": 1},
        "route_plan_id": {"type": "string", "minLength": 1},
        "comparison_key": {"type": "string", "minLength": 1},
        "success_criteria_hash": {"type": "string", "minLength": 1},
        "task_class": {"type": "string", "minLength": 1},
        "planned_model": {"type": "string", "minLength": 1},
        "actual_model": {"type": ["string", "null"]},
        "effort": {"type": "string", "minLength": 1},
        "status": {"type": "string", "minLength": 1},
        "source": {"enum": sorted(LEDGER_SOURCES)},
        "quality": {"enum": sorted(LEDGER_QUALITIES)},
        "input_tokens": {"type": ["integer", "null"], "minimum": 0},
        "cached_input_tokens": {"type": ["integer", "null"], "minimum": 0},
        "output_tokens": {"type": ["integer", "null"], "minimum": 0},
        "reasoning_tokens": {"type": ["integer", "null"], "minimum": 0},
        "provider_total_tokens": {"type": ["integer", "null"], "minimum": 0},
        "codex_context_bytes": {"type": ["integer", "null"], "minimum": 0},
        "web_packet_bytes": {"type": ["integer", "null"], "minimum": 0},
        "evidence_bytes": {"type": ["integer", "null"], "minimum": 0},
        "source_bytes": {"type": ["integer", "null"], "minimum": 0},
        "catalog_source_bytes": {"type": ["integer", "null"], "minimum": 0},
        "probe_bytes": {"type": ["integer", "null"], "minimum": 0},
        "model_turns": {"type": ["integer", "null"], "minimum": 0},
        "high_model_turns": {"type": ["integer", "null"], "minimum": 0},
        "retries": {"type": ["integer", "null"], "minimum": 0},
        "reroutes": {"type": ["integer", "null"], "minimum": 0},
        "compactions": {"type": ["integer", "null"], "minimum": 0},
        "subagent_count": {"type": ["integer", "null"], "minimum": 0},
        "note": {"type": ["string", "null"]},
        "created_at": {"type": ["string", "null"]},
    },
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ensure_mapping(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise PolicyError(f"{field} must be an object")
    return value


def _string_field(record: Mapping[str, Any], field: str, *, required: bool = True) -> str | None:
    value = record.get(field)
    if value is None:
        if required:
            raise PolicyError(f"{field} is required")
        return None
    if not isinstance(value, str) or not value.strip():
        raise PolicyError(f"{field} must be a non-empty string")
    return value.strip()


def _optional_int(record: Mapping[str, Any], field: str) -> int | None:
    value = record.get(field)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise PolicyError(f"{field} must be a non-negative integer")
    return int(value)


def _require_source(value: Any) -> str:
    if not isinstance(value, str) or value not in LEDGER_SOURCES:
        raise PolicyError("source is not supported")
    return value


def _require_quality(value: Any) -> str:
    if not isinstance(value, str) or value not in LEDGER_QUALITIES:
        raise PolicyError("quality is not supported")
    return value


def _validate_source_quality(source: str, quality: str) -> None:
    if source == "LOCAL_ESTIMATE" and quality != "ESTIMATED":
        raise PolicyError("LOCAL_ESTIMATE requires ESTIMATED quality")
    if source == "LOCAL_OBSERVED" and quality != "OBSERVED":
        raise PolicyError("LOCAL_OBSERVED requires OBSERVED quality")


def _reject_sensitive_text(record: Mapping[str, Any]) -> None:
    reason = bridge_packet_safety_reason(canonical_json(record))
    if reason:
        raise PolicyError("Token ledger import contains sensitive content")


def _normalize_tokens(record: dict[str, Any]) -> None:
    input_tokens = _optional_int(record, "input_tokens")
    cached_input_tokens = _optional_int(record, "cached_input_tokens")
    output_tokens = _optional_int(record, "output_tokens")
    reasoning_tokens = _optional_int(record, "reasoning_tokens")
    provider_total_tokens = _optional_int(record, "provider_total_tokens")
    if input_tokens is not None and cached_input_tokens is not None and cached_input_tokens > input_tokens:
        raise PolicyError("cached_input_tokens cannot exceed input_tokens")
    record["input_tokens"] = input_tokens
    record["cached_input_tokens"] = cached_input_tokens
    record["output_tokens"] = output_tokens
    record["reasoning_tokens"] = reasoning_tokens
    record["provider_total_tokens"] = provider_total_tokens
    record["processed_tokens"] = provider_total_tokens if provider_total_tokens is not None else (
        input_tokens + output_tokens if input_tokens is not None and output_tokens is not None else None
    )
    record["non_cached_input_tokens"] = (
        None
        if input_tokens is None
        else max(input_tokens - (cached_input_tokens or 0), 0)
    )
    record["cache_ratio"] = (
        None
        if input_tokens in (None, 0) or cached_input_tokens is None
        else round(cached_input_tokens / input_tokens, 6)
    )


def normalize_usage_event(payload: Mapping[str, Any]) -> dict[str, Any]:
    record = dict(_ensure_mapping(payload, "usage event"))
    allowed = {
        "source_event_id",
        "source",
        "quality",
        "event_type",
        "run_id",
        "task_id",
        "route_plan_id",
        "comparison_key",
        "success_criteria_hash",
        "task_class",
        "planned_model",
        "actual_model",
        "effort",
        "status",
        "input_tokens",
        "cached_input_tokens",
        "output_tokens",
        "reasoning_tokens",
        "provider_total_tokens",
        "codex_context_bytes",
        "web_packet_bytes",
        "evidence_bytes",
        "source_bytes",
        "catalog_source_bytes",
        "probe_bytes",
        "model_turns",
        "high_model_turns",
        "retries",
        "reroutes",
        "compactions",
        "subagent_count",
        "occurred_at",
        "note",
    }
    unexpected = sorted(set(record) - allowed)
    if unexpected:
        raise PolicyError(f"usage event has unsupported fields: {', '.join(unexpected)}")
    record["source_event_id"] = _string_field(record, "source_event_id")
    record["source"] = _require_source(record.get("source"))
    record["quality"] = _require_quality(record.get("quality"))
    _validate_source_quality(record["source"], record["quality"])
    record["event_type"] = _string_field(record, "event_type")
    for field in ("run_id", "task_id", "route_plan_id", "comparison_key", "success_criteria_hash", "task_class", "planned_model", "actual_model", "effort", "status", "note"):
        if field in record and record[field] is not None:
            record[field] = _string_field(record, field, required=False)
    _normalize_tokens(record)
    for field in ("codex_context_bytes", "web_packet_bytes", "evidence_bytes", "source_bytes", "catalog_source_bytes", "probe_bytes", "model_turns", "high_model_turns", "retries", "reroutes", "compactions", "subagent_count"):
        record[field] = _optional_int(record, field)
    record["occurred_at"] = record.get("occurred_at") if isinstance(record.get("occurred_at"), str) and record["occurred_at"].strip() else _now()
    _reject_sensitive_text(record)
    return record


def normalize_run_record(payload: Mapping[str, Any]) -> dict[str, Any]:
    record = dict(_ensure_mapping(payload, "ledger run"))
    required = {"run_id", "task_id", "comparison_key", "success_criteria_hash", "task_class", "planned_model", "effort", "status"}
    unexpected = sorted(set(record) - {
        "run_id",
        "task_id",
        "route_plan_id",
        "comparison_key",
        "success_criteria_hash",
        "task_class",
        "planned_model",
        "actual_model",
        "effort",
        "status",
        "quality",
        "input_tokens",
        "cached_input_tokens",
        "output_tokens",
        "reasoning_tokens",
        "provider_total_tokens",
        "codex_context_bytes",
        "web_packet_bytes",
        "evidence_bytes",
        "source_bytes",
        "catalog_source_bytes",
        "probe_bytes",
        "model_turns",
        "high_model_turns",
        "retries",
        "reroutes",
        "compactions",
        "subagent_count",
        "created_at",
        "updated_at",
        "finished_at",
        "note",
    })
    if unexpected:
        raise PolicyError(f"ledger run has unsupported fields: {', '.join(unexpected)}")
    for field in required:
        record[field] = _string_field(record, field)
    record["route_plan_id"] = _string_field(record, "route_plan_id", required=False)
    record["actual_model"] = _string_field(record, "actual_model", required=False)
    record["quality"] = _require_quality(record.get("quality", "OBSERVED"))
    _normalize_tokens(record)
    for field in ("codex_context_bytes", "web_packet_bytes", "evidence_bytes", "source_bytes", "catalog_source_bytes", "probe_bytes", "model_turns", "high_model_turns", "retries", "reroutes", "compactions", "subagent_count"):
        record[field] = _optional_int(record, field)
    record["created_at"] = record.get("created_at") if isinstance(record.get("created_at"), str) and record["created_at"].strip() else _now()
    record["updated_at"] = record.get("updated_at") if isinstance(record.get("updated_at"), str) and record["updated_at"].strip() else _now()
    record["finished_at"] = record.get("finished_at") if isinstance(record.get("finished_at"), str) and record["finished_at"].strip() else None
    _reject_sensitive_text(record)
    return record


def normalize_baseline_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    record = dict(_ensure_mapping(payload, "baseline import"))
    Draft7Validator(BASELINE_IMPORT_SCHEMA).validate(record)
    record["baseline_id"] = str(record.get("baseline_id") or uuid.uuid4())
    record["task_id"] = _string_field(record, "task_id", required=False)
    record["route_plan_id"] = _string_field(record, "route_plan_id", required=False)
    record["comparison_key"] = _string_field(record, "comparison_key")
    record["success_criteria_hash"] = _string_field(record, "success_criteria_hash")
    record["task_class"] = _string_field(record, "task_class")
    record["planned_model"] = _string_field(record, "planned_model")
    record["actual_model"] = _string_field(record, "actual_model", required=False)
    record["effort"] = _string_field(record, "effort")
    record["status"] = _string_field(record, "status")
    record["source"] = _require_source(record.get("source"))
    record["quality"] = _require_quality(record.get("quality"))
    _validate_source_quality(record["source"], record["quality"])
    _normalize_tokens(record)
    for field in ("codex_context_bytes", "web_packet_bytes", "evidence_bytes", "source_bytes", "catalog_source_bytes", "probe_bytes", "model_turns", "high_model_turns", "retries", "reroutes", "compactions", "subagent_count"):
        record[field] = _optional_int(record, field)
    record["created_at"] = record.get("created_at") if isinstance(record.get("created_at"), str) and record["created_at"].strip() else _now()
    _reject_sensitive_text(record)
    return record


def processed_tokens(record: Mapping[str, Any]) -> int | None:
    provider_total = record.get("provider_total_tokens")
    if isinstance(provider_total, int):
        return provider_total
    input_tokens = record.get("input_tokens")
    output_tokens = record.get("output_tokens")
    if isinstance(input_tokens, int) and isinstance(output_tokens, int):
        return input_tokens + output_tokens
    return None


def non_cached_input_tokens(record: Mapping[str, Any]) -> int | None:
    input_tokens = record.get("input_tokens")
    if not isinstance(input_tokens, int):
        return None
    cached = record.get("cached_input_tokens")
    cached_tokens = cached if isinstance(cached, int) else 0
    return max(input_tokens - cached_tokens, 0)


def cache_ratio(record: Mapping[str, Any]) -> float | None:
    input_tokens = record.get("input_tokens")
    cached = record.get("cached_input_tokens")
    if not isinstance(input_tokens, int) or input_tokens <= 0 or not isinstance(cached, int):
        return None
    return round(cached / input_tokens, 6)


def _measure_for_compare(record: Mapping[str, Any]) -> dict[str, Any]:
    payload = dict(record)
    payload["processed_tokens"] = processed_tokens(payload)
    payload["non_cached_input_tokens"] = non_cached_input_tokens(payload)
    payload["cache_ratio"] = cache_ratio(payload)
    return payload


def _quality_label(record: Mapping[str, Any]) -> str:
    return str(record.get("quality") or "OBSERVED")


def _status_value(record: Mapping[str, Any]) -> str:
    return str(record.get("status") or "UNKNOWN")


def _latest_by_identity(records: list[Mapping[str, Any]]) -> dict[tuple[str, str], Mapping[str, Any]]:
    latest: dict[tuple[str, str], Mapping[str, Any]] = {}
    for record in sorted(records, key=lambda item: (str(item.get("updated_at") or item.get("finished_at") or item.get("created_at") or ""), str(item.get("baseline_id") or item.get("run_id") or ""))):
        key = (str(record.get("comparison_key") or ""), str(record.get("success_criteria_hash") or ""))
        if not key[0] or not key[1]:
            continue
        latest[key] = record
    return latest


def compare_records(baseline: Mapping[str, Any] | None, actual: Mapping[str, Any] | None) -> dict[str, Any]:
    if not baseline and not actual:
        return {"status": "NOT_COMPARABLE", "reason": "No baseline or actual run is available."}
    if not baseline:
        actual_view = _measure_for_compare(actual or {})
        return {"status": "NOT_COMPARABLE", "reason": "A baseline has not been registered yet.", "actual": actual_view}
    if not actual:
        baseline_view = _measure_for_compare(baseline)
        return {"status": "NOT_COMPARABLE", "reason": "No successful actual run has been recorded yet.", "baseline": baseline_view}
    if baseline.get("comparison_key") != actual.get("comparison_key"):
        return {"status": "NOT_COMPARABLE", "reason": "comparison_key does not match.", "baseline": _measure_for_compare(baseline), "actual": _measure_for_compare(actual)}
    if baseline.get("success_criteria_hash") != actual.get("success_criteria_hash"):
        return {"status": "NOT_COMPARABLE", "reason": "success_criteria_hash does not match.", "baseline": _measure_for_compare(baseline), "actual": _measure_for_compare(actual)}
    if _status_value(baseline) != "SUCCESS" or _status_value(actual) != "SUCCESS":
        return {"status": "NOT_COMPARABLE", "reason": "Both baseline and actual run must be SUCCESS.", "baseline": _measure_for_compare(baseline), "actual": _measure_for_compare(actual)}

    baseline_view = _measure_for_compare(baseline)
    actual_view = _measure_for_compare(actual)
    if baseline_view["processed_tokens"] is None or actual_view["processed_tokens"] is None:
        return {"status": "NOT_COMPARABLE", "reason": "Processed token totals are missing.", "baseline": baseline_view, "actual": actual_view}
    if baseline_view["processed_tokens"] == 0:
        return {"status": "NOT_COMPARABLE", "reason": "Baseline processed tokens are zero.", "baseline": baseline_view, "actual": actual_view}
    if baseline_view["non_cached_input_tokens"] is None or actual_view["non_cached_input_tokens"] is None:
        return {"status": "NOT_COMPARABLE", "reason": "Non-cached input totals are missing.", "baseline": baseline_view, "actual": actual_view}
    if baseline_view["non_cached_input_tokens"] == 0:
        return {"status": "NOT_COMPARABLE", "reason": "Baseline non-cached input tokens are zero.", "baseline": baseline_view, "actual": actual_view}
    if baseline_view["quality"] == "ESTIMATED" or actual_view["quality"] == "ESTIMATED":
        return {"status": "ESTIMATE_ONLY", "reason": "Estimated values are present.", "baseline": baseline_view, "actual": actual_view}

    baseline_processed = baseline_view["processed_tokens"]
    actual_processed = actual_view["processed_tokens"]
    baseline_non_cached = baseline_view["non_cached_input_tokens"]
    actual_non_cached = actual_view["non_cached_input_tokens"]
    baseline_high = int(baseline_view.get("high_model_turns") or 0)
    actual_high = int(actual_view.get("high_model_turns") or 0)
    comparison = {
        "status": "COMPARABLE",
        "baseline": baseline_view,
        "actual": actual_view,
        "processed_savings": round(1 - (actual_processed / baseline_processed), 6),
        "non_cached_input_savings": round(1 - (actual_non_cached / baseline_non_cached), 6),
        "high_model_turn_reduction": None if baseline_high == 0 else round(1 - (actual_high / baseline_high), 6),
    }
    return comparison


def build_report(runs: list[Mapping[str, Any]], baselines: list[Mapping[str, Any]], usage_events: list[Mapping[str, Any]]) -> dict[str, Any]:
    normalized_runs = [_measure_for_compare(run) for run in runs]
    normalized_baselines = [_measure_for_compare(baseline) for baseline in baselines]
    actual_by_key = _latest_by_identity([run for run in normalized_runs if _status_value(run) == "SUCCESS"])
    baseline_by_key = _latest_by_identity([baseline for baseline in normalized_baselines if _status_value(baseline) == "SUCCESS"])

    comparisons: list[dict[str, Any]] = []
    all_keys = sorted(set(baseline_by_key) | set(actual_by_key))
    for key in all_keys:
        comparison = compare_records(baseline_by_key.get(key), actual_by_key.get(key))
        comparison["comparison_key"] = key[0]
        comparison["success_criteria_hash"] = key[1]
        comparisons.append(comparison)

    totals: dict[str, int] = {
        "web_packet_bytes": 0,
        "evidence_bytes": 0,
        "source_bytes": 0,
        "catalog_source_bytes": 0,
        "probe_bytes": 0,
    }
    latest_events: list[dict[str, Any]] = []
    warnings: list[str] = []
    for event in sorted(usage_events, key=lambda item: str(item.get("occurred_at") or "")):
        latest_events.append({
            "source": event.get("source"),
            "quality": event.get("quality"),
            "event_type": event.get("event_type"),
            "source_event_id": event.get("source_event_id"),
            "run_id": event.get("run_id"),
            "comparison_key": event.get("comparison_key"),
            "web_packet_bytes": event.get("web_packet_bytes"),
            "evidence_bytes": event.get("evidence_bytes"),
            "source_bytes": event.get("source_bytes"),
            "catalog_source_bytes": event.get("catalog_source_bytes"),
            "probe_bytes": event.get("probe_bytes"),
            "occurred_at": event.get("occurred_at"),
        })
        for field in totals:
            value = event.get(field)
            if isinstance(value, int):
                totals[field] += value
    for run in normalized_runs:
        if int(run.get("subagent_count") or 0) != 0:
            warnings.append("subagent_count is non-zero for at least one run.")

    comparable = [item for item in comparisons if item["status"] == "COMPARABLE"]
    estimate_only = [item for item in comparisons if item["status"] == "ESTIMATE_ONLY"]
    not_comparable = [item for item in comparisons if item["status"] == "NOT_COMPARABLE"]
    summary_message = "실제 토큰 절감 미측정" if not comparable else f"{len(comparable)} comparison(s) with observed savings"
    if estimate_only and not comparable:
        summary_message = "ESTIMATE_ONLY: estimated values are present; no actual savings were confirmed."
    report = {
        "generated_at": _now(),
        "summary": {
            "message": summary_message,
            "run_count": len(normalized_runs),
            "baseline_count": len(normalized_baselines),
            "comparison_count": len(comparisons),
            "comparable_count": len(comparable),
            "estimate_only_count": len(estimate_only),
            "not_comparable_count": len(not_comparable),
            "warnings": warnings,
        },
        "usage_totals": totals,
        "runs": normalized_runs,
        "baselines": normalized_baselines,
        "comparisons": comparisons,
        "recent_events": latest_events[-25:],
    }
    local_only = [event for event in usage_events if event.get("event_type") in LOCAL_ONLY_EVENT_TYPES]
    report["sealed_offline_codex_process_canary"] = {
        "executions": sum(int(event.get("local_executions") or 0) for event in local_only),
        "estimated_planned_processes": sum(
            int(event.get("planned_local_processes") or 0)
            for event in local_only if event.get("quality") == "ESTIMATED"
        ),
        "observed_executions": sum(
            int(event.get("local_executions") or 0)
            for event in local_only if event.get("quality") == "OBSERVED"
        ),
        "local_processes": sum(
            int(event.get("local_processes") or 0)
            for event in local_only if event.get("quality") == "OBSERVED"
        ),
        "observed_duration_ms": sum(
            int(event.get("local_duration_ms") or 0)
            for event in local_only if event.get("quality") == "OBSERVED"
        ),
        "external_tokens": 0,
        "app_server_rpc_calls": 0,
        "measurement": "NOT_COMPARABLE",
    }
    return report


def render_markdown(report: Mapping[str, Any]) -> str:
    summary = report.get("summary", {})
    usage = report.get("usage_totals", {})
    lines = [
        "# Token Savings Ledger Report",
        "",
        f"- Generated at: {report.get('generated_at', 'UNKNOWN')}",
        f"- {summary.get('message', '실제 토큰 절감 미측정')}",
        f"- Runs: {summary.get('run_count', 0)}",
        f"- Baselines: {summary.get('baseline_count', 0)}",
        f"- Comparisons: {summary.get('comparison_count', 0)}",
        f"- Comparable: {summary.get('comparable_count', 0)}",
        f"- Estimate only: {summary.get('estimate_only_count', 0)}",
        f"- Not comparable: {summary.get('not_comparable_count', 0)}",
        "",
        "## Usage totals",
        f"- Bridge packet bytes: {usage.get('web_packet_bytes', 0)}",
        f"- Evidence bytes: {usage.get('evidence_bytes', 0)}",
        f"- Source bytes: {usage.get('source_bytes', 0)}",
        f"- Catalog source bytes: {usage.get('catalog_source_bytes', 0)}",
        f"- Probe bytes: {usage.get('probe_bytes', 0)}",
        "",
        "## Comparisons",
    ]
    comparisons = report.get("comparisons", [])
    if not comparisons:
        lines.append("- No comparable baseline/actual pairs were recorded.")
    for item in comparisons:
        baseline = item.get("baseline") or {}
        actual = item.get("actual") or {}
        lines.extend([
            f"- `{item.get('comparison_key', '')}` / `{item.get('success_criteria_hash', '')}`",
            f"  - Status: {item.get('status')}",
            f"  - Baseline: {baseline.get('processed_tokens', 'UNKNOWN')} ({baseline.get('quality', 'UNKNOWN')})",
            f"  - Actual: {actual.get('processed_tokens', 'UNKNOWN')} ({actual.get('quality', 'UNKNOWN')})",
            f"  - Savings: {item.get('processed_savings', 'UNKNOWN')}",
            f"  - Non-cached input savings: {item.get('non_cached_input_savings', 'UNKNOWN')}",
            f"  - High model turn reduction: {item.get('high_model_turn_reduction', 'UNKNOWN')}",
        ])
    return "\n".join(lines) + "\n"
