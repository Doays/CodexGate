from __future__ import annotations

import json
import sqlite3

import pytest

from app.policy import PolicyError, sha256_json
from app.storage import Store
from app.token_ledger import compare_records, normalize_baseline_payload, normalize_run_record, normalize_usage_event


def run_record(**overrides):
    record = {
        "run_id": "run-1",
        "task_id": "task-1",
        "comparison_key": "key-1",
        "success_criteria_hash": "hash-1",
        "task_class": "T3",
        "planned_model": "model-a",
        "actual_model": "model-a",
        "effort": "high",
        "status": "SUCCESS",
        "quality": "OBSERVED",
        "input_tokens": 100,
        "cached_input_tokens": 25,
        "output_tokens": 40,
        "reasoning_tokens": 30,
        "provider_total_tokens": 150,
        "created_at": "2026-07-28T00:00:00+00:00",
        "updated_at": "2026-07-28T00:00:00+00:00",
        "finished_at": "2026-07-28T00:00:00+00:00",
    }
    record.update(overrides)
    return normalize_run_record(record)


def baseline_record(**overrides):
    record = {
        "baseline_id": "baseline-1",
        "task_id": "task-1",
        "route_plan_id": "plan-1",
        "comparison_key": "key-1",
        "success_criteria_hash": "hash-1",
        "task_class": "T3",
        "planned_model": "model-a",
        "actual_model": "model-a",
        "effort": "high",
        "status": "SUCCESS",
        "quality": "IMPORTED",
        "source": "MANUAL_BASELINE",
        "input_tokens": 100,
        "cached_input_tokens": 25,
        "output_tokens": 40,
        "reasoning_tokens": 30,
        "provider_total_tokens": 150,
        "created_at": "2026-07-28T00:00:00+00:00",
    }
    record.update(overrides)
    return normalize_baseline_payload(record)


def test_provider_total_precedence_and_non_cached_calculation():
    record = normalize_run_record(
        {
            "run_id": "run-1",
            "task_id": "task-1",
            "comparison_key": "key-1",
            "success_criteria_hash": "hash-1",
            "task_class": "T3",
            "planned_model": "model-a",
            "actual_model": "model-a",
            "effort": "high",
            "status": "SUCCESS",
            "quality": "OBSERVED",
            "input_tokens": 80,
            "cached_input_tokens": 20,
            "output_tokens": 10,
            "reasoning_tokens": 40,
            "provider_total_tokens": 123,
            "created_at": "2026-07-28T00:00:00+00:00",
            "updated_at": "2026-07-28T00:00:00+00:00",
            "finished_at": "2026-07-28T00:00:00+00:00",
        }
    )
    assert record["processed_tokens"] == 123
    assert record["non_cached_input_tokens"] == 60
    assert record["cache_ratio"] == 0.25
    assert record["reasoning_tokens"] == 40


def test_compare_records_requires_matching_keys_and_succeeds_only_for_matching_observed_rows():
    baseline = baseline_record()
    actual = run_record()
    matched = compare_records(baseline, actual)
    assert matched["status"] == "COMPARABLE"
    assert matched["processed_savings"] == 0.0
    mismatch = compare_records({**baseline, "comparison_key": "key-2"}, actual)
    assert mismatch["status"] == "NOT_COMPARABLE"
    mismatch_hash = compare_records(baseline, {**actual, "success_criteria_hash": "hash-2"})
    assert mismatch_hash["status"] == "NOT_COMPARABLE"


def test_estimated_values_trigger_estimate_only():
    estimated = baseline_record(quality="ESTIMATED")
    actual = run_record()
    comparison = compare_records(estimated, actual)
    assert comparison["status"] == "ESTIMATE_ONLY"


def test_failed_actual_run_does_not_confirm_savings():
    baseline = baseline_record()
    actual = run_record(status="FAILED")
    comparison = compare_records(baseline, actual)
    assert comparison["status"] == "NOT_COMPARABLE"


def test_usage_events_are_idempotent_and_reject_conflicts(tmp_path):
    store = Store(tmp_path / "data")
    event = {
        "source_event_id": "bridge:1",
        "source": "LOCAL_ESTIMATE",
        "quality": "OBSERVED",
        "event_type": "bridge_packet",
        "run_id": "run-1",
        "comparison_key": "key-1",
        "web_packet_bytes": 222,
        "occurred_at": "2026-07-28T00:00:00+00:00",
    }
    first = store.record_ledger_usage_event(event)
    second = store.record_ledger_usage_event(event)
    assert first["integrity_hash"] == second["integrity_hash"]
    with pytest.raises(PolicyError):
        store.record_ledger_usage_event({**event, "web_packet_bytes": 333})


def test_local_source_quality_contract_is_strict_and_observed_is_explicit():
    base = {"source_event_id": "local:1", "event_type": "local_metric", "input_tokens": None}
    with pytest.raises(PolicyError):
        normalize_usage_event({**base, "source": "LOCAL_ESTIMATE", "quality": "OBSERVED"})
    with pytest.raises(PolicyError):
        normalize_usage_event({**base, "source": "LOCAL_OBSERVED", "quality": "ESTIMATED"})
    observed = normalize_usage_event({**base, "source": "LOCAL_OBSERVED", "quality": "OBSERVED"})
    assert observed["source"] == "LOCAL_OBSERVED" and observed["quality"] == "OBSERVED"


def test_legacy_harness_event_is_labeled_without_counting_as_observed(tmp_path):
    store = Store(tmp_path / "data")
    event = store.record_egress_harness_ledger({
        "status": "PASSED", "contract_hash": "a" * 64, "runner_kind": "WSL_SUPERVISOR",
        "runner_version": "sealed-egress-wsl-v1", "runner_implementation_hash": "b" * 64,
        "local_processes": 3, "local_duration_ms": 9,
    })
    with sqlite3.connect(store.db_path) as conn:
        row = conn.execute("SELECT payload FROM ledger_usage_events WHERE source_event_id=?", (event["source_event_id"],)).fetchone()
        payload = json.loads(row[0])
        payload.update({"source": "LOCAL_ESTIMATE", "quality": "OBSERVED"})
        conn.execute(
            "UPDATE ledger_usage_events SET source='LOCAL_ESTIMATE', quality='OBSERVED', payload=?, integrity_hash=? WHERE source_event_id=?",
            (json.dumps(payload, sort_keys=True, separators=(",", ":")), sha256_json(payload), event["source_event_id"]),
        )
        before = conn.execute("SELECT payload, integrity_hash FROM ledger_usage_events WHERE source_event_id=?", (event["source_event_id"],)).fetchone()
    report = store.token_ledger_report()
    listed = next(item for item in store.ledger_usage_events() if item["source_event_id"] == event["source_event_id"])
    assert listed["legacy_estimate"] is True
    assert report["sealed_egress_harness"]["legacy_estimate"] is True
    assert report["sealed_egress_harness"]["local_processes"] == 0
    with sqlite3.connect(store.db_path) as conn:
        after = conn.execute("SELECT payload, integrity_hash FROM ledger_usage_events WHERE source_event_id=?", (event["source_event_id"],)).fetchone()
    assert before == after


def test_new_local_observed_harness_event_is_counted_separately(tmp_path):
    store = Store(tmp_path / "data")
    store.record_egress_harness_ledger({
        "status": "PASSED", "contract_hash": "c" * 64, "runner_kind": "WSL_SUPERVISOR",
        "runner_version": "sealed-egress-wsl-v1", "runner_implementation_hash": "d" * 64,
        "local_processes": 2, "local_duration_ms": 11,
    })
    report = store.token_ledger_report()["sealed_egress_harness"]
    assert report["legacy_estimate"] is False
    assert report["observed_executions"] == 1 and report["local_processes"] == 2
    assert report["local_duration_ms"] == 11 and report["measurement"] == "NOT_COMPARABLE"


def test_imports_reject_negative_cached_secret_and_absolute_path():
    with pytest.raises(PolicyError):
        normalize_baseline_payload(
            {
                "comparison_key": "key-1",
                "success_criteria_hash": "hash-1",
                "task_class": "T3",
                "planned_model": "model-a",
                "effort": "high",
                "status": "SUCCESS",
                "quality": "IMPORTED",
                "source": "MANUAL_BASELINE",
                "cached_input_tokens": 999,
                "input_tokens": 10,
            }
        )
    with pytest.raises(PolicyError):
        normalize_baseline_payload(
            {
                "comparison_key": "key-1",
                "success_criteria_hash": "hash-1",
                "task_class": "T3",
                "planned_model": "model-a",
                "effort": "high",
                "status": "SUCCESS",
                "quality": "IMPORTED",
                "source": "MANUAL_BASELINE",
                "input_tokens": 10,
                "output_tokens": 10,
                "note": r"C:\\Users\\82109\\secrets.txt",
            }
        )


def test_bridge_evidence_catalog_and_probe_bytes_are_reported(tmp_path):
    store = Store(tmp_path / "data")
    store.record_ledger_usage_event({"source_event_id": "bridge:1", "source": "LOCAL_ESTIMATE", "quality": "OBSERVED", "event_type": "bridge_packet", "web_packet_bytes": 101})
    store.record_ledger_usage_event({"source_event_id": "evidence:1", "source": "LOCAL_ESTIMATE", "quality": "OBSERVED", "event_type": "evidence_collection", "evidence_bytes": 202})
    store.record_ledger_usage_event({"source_event_id": "catalog:1", "source": "LOCAL_ESTIMATE", "quality": "OBSERVED", "event_type": "catalog_scan", "source_bytes": 303, "catalog_source_bytes": 303})
    store.record_ledger_usage_event({"source_event_id": "probe:1", "source": "LOCAL_ESTIMATE", "quality": "OBSERVED", "event_type": "format_probe", "probe_bytes": 404})
    report = store.token_ledger_report()
    assert report["usage_totals"] == {
        "web_packet_bytes": 101,
        "evidence_bytes": 202,
        "source_bytes": 303,
        "catalog_source_bytes": 303,
        "probe_bytes": 404,
    }


def test_export_omits_raw_prompt_and_response_and_marks_missing_live_run(tmp_path):
    store = Store(tmp_path / "data")
    report = store.token_ledger_report()
    assert report["summary"]["message"] == "실제 토큰 절감 미측정"
    exported_json = store.export_token_ledger_report("json")
    exported_md = store.export_token_ledger_report("markdown")
    assert "raw_prompt" not in exported_json
    assert "raw_response" not in exported_json
    assert "raw_prompt" not in exported_md
    assert "raw_response" not in exported_md
    parsed = json.loads(exported_json)
    assert parsed["summary"]["message"] == "실제 토큰 절감 미측정"
