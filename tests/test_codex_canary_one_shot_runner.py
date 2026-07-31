from __future__ import annotations

import asyncio
import hashlib
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.codex_process_canary import (
    CANARY_RUNNER_KIND,
    ERROR,
    PASSED,
    CanaryExecution,
    CodexCanaryExecutionPermitGate,
    EXPECTED_CONFIG_HASH,
    EXPECTED_OUTPUT_HASH,
    EXPECTED_PROMPT_HASH,
    EXPECTED_REQUEST_HASH,
    EXPECTED_RESPONSE_HASH,
    RUNNER_IMPLEMENTATION_HASH,
    RUNNER_VERSION,
    SUCCESS_MARKER,
    SealedOfflineCodexProcessCanary,
    WSLCodexProcessCanaryRunner,
)
from app.codex_process_executor_wsl import (
    EXECUTOR_IMPLEMENTATION_HASH,
    EXPECTED_CONFIG_HASH as EXECUTOR_CONFIG_HASH,
    EXPECTED_OUTPUT_HASH as EXECUTOR_OUTPUT_HASH,
    EXPECTED_PROMPT_HASH as EXECUTOR_PROMPT_HASH,
    EXPECTED_REQUEST_HASH as EXECUTOR_REQUEST_HASH,
    EXPECTED_RESPONSE_HASH as EXECUTOR_RESPONSE_HASH,
    synthetic_relay_broker_roundtrip,
    encode_supervisor_frame,
    WSLCodexProcessCanaryExecutor,
)
from app.isolation_wsl import ProcessResult, SAFE_CANDIDATE
from app.policy import canonical_json
from app.policy import PolicyError

from tests.test_codex_process_canary import CONFIG_HASH, ISOLATION_KEY, ready_canary


class NoIoSupervisor:
    """A WSL command runner double; it never creates a child process."""

    def __init__(self, *, bad_frame: bool = False):
        self.bad_frame = bad_frame
        self.calls = 0

    def find_wsl(self):
        return "wsl.exe"

    async def run(self, args, *, payload, timeout_seconds, on_started=None):
        self.calls += 1
        if on_started is not None:
            on_started()
        proof = synthetic_relay_broker_roundtrip()
        event_types = [] if self.bad_frame else ["thread.started", "turn.started", "item.completed", "turn.completed"]
        event_counts = {} if self.bad_frame else {
            "thread.started": 1, "turn.started": 1, "item.completed": 1, "turn.completed": 1,
        }
        payload = {
            "status": "ERROR" if self.bad_frame else "PASSED", "stage": "CLEANUP", "substage": None,
            "error_code": "cleanup_failed" if self.bad_frame else None,
            "process_counts": {"supervisor": 1, "broker_bwrap": 1, "relay_codex_bwrap": 1, "codex_cli": 1},
            "cleanup_ok": not self.bad_frame, "implementation_hash": EXECUTOR_IMPLEMENTATION_HASH,
            "request_seen": 0 if self.bad_frame else proof["request_seen"],
            "request_validated": 0 if self.bad_frame else proof["request_validated"],
            "response_sent": 0 if self.bad_frame else proof["response_sent"],
            "accepted_post": 0 if self.bad_frame else proof["accepted_post"],
            "request_hash": None if self.bad_frame else proof["request_hash"],
            "response_hash": None if self.bad_frame else proof["response_hash"],
            "response_byte_count": 0 if self.bad_frame else proof["response_byte_count"],
            "output_hash": None if self.bad_frame else proof["output_hash"],
            "sensitive_headers_removed": False if self.bad_frame else proof["sensitive_headers_removed"],
            "event_types": event_types,
            "event_counts": event_counts,
            "event_sequence_hash": hashlib.sha256(
                canonical_json({"event_types": event_types, "event_counts": event_counts}).encode("utf-8")
            ).hexdigest(),
            "last_message_exists": not self.bad_frame,
            "last_message_regular": not self.bad_frame,
            "last_message_size": 0 if self.bad_frame else len(SUCCESS_MARKER.encode("utf-8")),
            "last_message_sha256": None if self.bad_frame else proof["output_hash"],
            "last_message_match": not self.bad_frame,
            "last_message_marker_match": not self.bad_frame,
            "marker_match": not self.bad_frame,
            "agent_message_count": 0 if self.bad_frame else 1,
            "output_byte_count": 0 if self.bad_frame else len(SUCCESS_MARKER.encode("utf-8")),
            "output_sha256": None if self.bad_frame else proof["output_hash"],
            "eof_stdout_drained": not self.bad_frame,
            "eof_stderr_drained": not self.bad_frame,
            "readers_joined": not self.bad_frame,
            "usage": None if self.bad_frame else {
                "input_tokens": 7,
                "cached_input_tokens": 2,
                "cache_write_input_tokens": 0,
                "output_tokens": 3,
                "reasoning_output_tokens": 1,
            },
            "child_schema_diagnostic": None,
            "codex_exit_code": None if self.bad_frame else 0,
        }
        return ProcessResult(exit_code=0, stdout=encode_supervisor_frame(payload), stderr="")


def one_shot_gate(tmp_path, *, supervisor: NoIoSupervisor | None = None, changed_runner_hash: str | None = None):
    store, contracts, _, _ = ready_canary(tmp_path)
    created = {"runner": 0, "executor": 0}

    def make_executor(claim_id):
        created["executor"] += 1
        if supervisor is None:
            raise AssertionError("executor must not be created")
        return WSLCodexProcessCanaryExecutor(store, claim_id, supervisor)

    def make_runner():
        created["runner"] += 1
        runner = WSLCodexProcessCanaryRunner(make_executor if supervisor is not None else None)
        if changed_runner_hash is not None:
            runner.runner_implementation_hash = changed_runner_hash
            runner.runner_version = f"sealed-offline-codex-{changed_runner_hash[:16]}"
        return runner

    service = SealedOfflineCodexProcessCanary(store, contracts, runner_factory=make_runner)
    return store, service, CodexCanaryExecutionPermitGate(store, service), created


def arm_pair(gate):
    permit = asyncio.run(gate.issue())
    window = asyncio.run(gate.arm(permit["permit_nonce"]))
    return permit, window


def test_default_endpoint_path_is_still_disabled_without_runner_materialization(tmp_path):
    _, _, gate, created = one_shot_gate(tmp_path)
    permit, window = arm_pair(gate)
    with pytest.raises(PolicyError, match="codex_canary_execution_disabled"):
        asyncio.run(gate.run(permit["permit_nonce"], window["canary_nonce"]))
    assert created == {"runner": 0, "executor": 0}


def test_one_shot_claim_precedes_runner_and_executor_creation(tmp_path):
    supervisor = NoIoSupervisor()
    store, _, gate, created = one_shot_gate(tmp_path, supervisor=supervisor)
    permit, window = arm_pair(gate)
    assert created == {"runner": 0, "executor": 0}
    result = asyncio.run(gate.run_one_shot(permit["permit_nonce"], window["canary_nonce"]))
    assert result["status"] == PASSED
    assert created == {"runner": 1, "executor": 1} and supervisor.calls == 1
    claim = store.codex_canary_execution_claim()
    assert claim["status"] == PASSED and claim["runner_implementation_hash"] == RUNNER_IMPLEMENTATION_HASH
    assert permit["permit_nonce"] not in repr(claim) and window["canary_nonce"] not in repr(claim)
    assert store.codex_canary_execution_permit()["status"] == "CONSUMED"
    assert store.codex_process_canary_window()["status"] == "CONSUMED"
    assert {
        field: result[field]
        for field in (
            "request_seen", "request_validated", "response_sent", "accepted_post",
        )
    } == {
        "request_seen": 1, "request_validated": 1,
        "response_sent": 1, "accepted_post": 1,
    }
    stored = store.codex_process_canary_result(
        result["contract_hash"], result["runner_kind"], result["runner_version"],
        result["runner_implementation_hash"],
    )
    assert stored["request_count"] == stored["accepted_post"] == 1
    ledger = next(
        event for event in store.ledger_usage_events()
        if event.get("action") == "RUN"
    )
    assert {
        field: ledger[field]
        for field in (
            "request_seen", "request_validated", "response_sent", "accepted_post",
        )
    } == {
        "request_seen": 1, "request_validated": 1,
        "response_sent": 1, "accepted_post": 1,
    }
    assert ledger["request_count"] == ledger["accepted_post"] == 1
    for proof in (result, stored, ledger):
        assert {
            field: proof[field]
            for field in (
                "agent_message_count", "output_byte_count", "output_sha256",
                "last_message_exists", "last_message_sha256", "last_message_match", "marker_match",
            )
        } == {
            "agent_message_count": 1,
            "output_byte_count": len(SUCCESS_MARKER.encode("utf-8")),
            "output_sha256": EXPECTED_OUTPUT_HASH,
            "last_message_exists": True,
            "last_message_sha256": EXPECTED_OUTPUT_HASH,
            "last_message_match": True,
            "marker_match": True,
        }
        assert SUCCESS_MARKER not in repr(proof)


@pytest.mark.parametrize("permit_nonce,window_nonce,error", [
    (None, None, "codex_canary_permit_required"),
    ("invalid", "invalid", "codex_canary_permit_required"),
])
def test_one_shot_requires_both_capabilities(tmp_path, permit_nonce, window_nonce, error):
    _, _, gate, created = one_shot_gate(tmp_path)
    with pytest.raises(PolicyError, match=error):
        asyncio.run(gate.run_one_shot(permit_nonce, window_nonce))
    assert created == {"runner": 0, "executor": 0}


def test_one_shot_consumes_pair_once_under_concurrency(tmp_path):
    supervisor = NoIoSupervisor()
    _, _, gate, created = one_shot_gate(tmp_path, supervisor=supervisor)
    permit, window = arm_pair(gate)

    async def twice():
        return await asyncio.gather(
            gate.run_one_shot(permit["permit_nonce"], window["canary_nonce"]),
            gate.run_one_shot(permit["permit_nonce"], window["canary_nonce"]),
            return_exceptions=True,
        )

    outcomes = asyncio.run(twice())
    assert sum(isinstance(value, dict) and value.get("status") == PASSED for value in outcomes) == 1
    assert sum(isinstance(value, PolicyError) and "reused" in str(value) for value in outcomes) == 1
    assert created == {"runner": 1, "executor": 1} and supervisor.calls == 1


def test_binding_change_consumes_capabilities_without_spawn(tmp_path):
    store, _, gate, created = one_shot_gate(tmp_path)
    permit, window = arm_pair(gate)
    now = datetime.now(timezone.utc)
    isolation = store.wsl_isolation_result()
    store.save_wsl_isolation_result({
        **isolation,
        "status": SAFE_CANDIDATE,
        "checked_at": now.isoformat(),
        "expires_at": (now + timedelta(minutes=30)).isoformat(),
        "tool_fingerprint": "9" * 64,
    })
    with pytest.raises(PolicyError, match="execution_binding_changed"):
        asyncio.run(gate.run_one_shot(permit["permit_nonce"], window["canary_nonce"]))
    assert created == {"runner": 0, "executor": 0}
    event = next(event for event in store.ledger_usage_events() if event.get("action") == "BLOCKED")
    assert event["source"] == "LOCAL_OBSERVED" and event["local_processes"] == 0


def test_claim_transaction_rechecks_current_identity_before_consuming(tmp_path):
    store, _, gate, created = one_shot_gate(tmp_path)
    expected = gate._sealed_binding()
    permit, window = arm_pair(gate)
    now = datetime.now(timezone.utc)
    isolation = store.wsl_isolation_result()
    store.save_wsl_isolation_result({
        **isolation,
        "status": SAFE_CANDIDATE,
        "checked_at": now.isoformat(),
        "expires_at": (now + timedelta(minutes=30)).isoformat(),
        "tool_fingerprint": "8" * 64,
    })
    with pytest.raises(PolicyError, match="execution_binding_changed"):
        store.claim_codex_canary_one_shot_execution(permit["permit_nonce"], window["canary_nonce"], expected)
    assert store.codex_canary_execution_permit()["status"] == "CONSUMED"
    assert store.codex_process_canary_window()["status"] == "CONSUMED"
    assert store.codex_canary_execution_claim()["status"] == "DISABLED"
    assert created == {"runner": 0, "executor": 0}


def test_wrong_actual_implementation_blocks_before_executor_spawn(tmp_path):
    supervisor = NoIoSupervisor()
    _, _, gate, created = one_shot_gate(tmp_path, supervisor=supervisor, changed_runner_hash="a" * 64)
    permit, window = arm_pair(gate)
    with pytest.raises(PolicyError, match="actual_runner_policy_violation"):
        asyncio.run(gate.run_one_shot(permit["permit_nonce"], window["canary_nonce"]))
    assert created == {"runner": 1, "executor": 0} and supervisor.calls == 0


def test_partial_failure_records_only_observed_started_processes(tmp_path):
    supervisor = NoIoSupervisor(bad_frame=True)
    store, _, gate, _ = one_shot_gate(tmp_path, supervisor=supervisor)
    permit, window = arm_pair(gate)
    result = asyncio.run(gate.run_one_shot(permit["permit_nonce"], window["canary_nonce"]))
    assert result["status"] == ERROR
    assert result["error_code"] == "cleanup_failed"
    event = next(event for event in store.ledger_usage_events() if event.get("action") == "RUN")
    assert event["source"] == "LOCAL_OBSERVED" and event["quality"] == "OBSERVED"
    assert event["local_processes"] == 4 and event["local_duration_ms"] >= 0
    assert (event["supervisor_processes"], event["bwrap_processes"], event["codex_processes"]) == (1, 2, 1)
    assert {
        field: event[field]
        for field in (
            "request_seen", "request_validated", "response_sent", "accepted_post",
        )
    } == {
        "request_seen": 0, "request_validated": 0,
        "response_sent": 0, "accepted_post": 0,
    }
    assert event["request_count"] == event["accepted_post"] == 0
    assert event["provider_total_tokens"] is None and event["external_model_requests"] == 0
    assert event["app_server_rpc_calls"] == 0 and event["ignored_usage"] is True


def test_one_shot_returns_exact_supervisor_substage(tmp_path):
    class RelayFailureSupervisor(NoIoSupervisor):
        async def run(self, args, *, payload, timeout_seconds, on_started=None):
            self.calls += 1
            if on_started is not None:
                on_started()
            payload = {
                "status": "ERROR",
                "stage": "RELAY_CODEX_SPAWN",
                "substage": "CODEX_BINARY_VALIDATE",
                "error_code": "runtime_binary_sha_mismatch",
                "process_counts": {"supervisor": 1, "broker_bwrap": 1, "relay_codex_bwrap": 0, "codex_cli": 0},
                "cleanup_ok": True,
                "implementation_hash": EXECUTOR_IMPLEMENTATION_HASH,
                "request_hash": None,
                "response_hash": None,
                "output_hash": None,
                "sensitive_headers_removed": False,
            }
            return ProcessResult(exit_code=0, stdout=encode_supervisor_frame(payload), stderr="")

    store, _, gate, _ = one_shot_gate(tmp_path, supervisor=RelayFailureSupervisor())
    permit, window = arm_pair(gate)
    result = asyncio.run(gate.run_one_shot(permit["permit_nonce"], window["canary_nonce"]))
    assert result["status"] == ERROR
    assert result["stage"] == "RELAY_CODEX_SPAWN"
    assert result["substage"] == "CODEX_BINARY_VALIDATE"
    assert result["error_code"] == "runtime_binary_sha_mismatch"
    event = next(event for event in store.ledger_usage_events() if event.get("action") == "RUN")
    assert event["local_processes"] == 2


def test_claim_recovery_blocks_reexecution(tmp_path):
    store, _, gate, created = one_shot_gate(tmp_path)
    permit, window = arm_pair(gate)
    claim = store.claim_codex_canary_one_shot_execution(
        permit["permit_nonce"], window["canary_nonce"], gate._sealed_binding(),
    )
    assert store.recover_interrupted_codex_canary_execution_claims() == 1
    assert store.codex_canary_execution_claim()["status"] == ERROR
    with pytest.raises(PolicyError, match="reused"):
        asyncio.run(gate.run_one_shot(permit["permit_nonce"], window["canary_nonce"]))
    assert claim["execution_claim_id"] and created == {"runner": 0, "executor": 0}


def test_one_shot_endpoint_keeps_ipv4_host_origin_policy(tmp_path, monkeypatch):
    from app import main

    monkeypatch.setattr(main, "DATA_ROOT", tmp_path / "api-data")
    with TestClient(main.app, base_url="http://127.0.0.1:8787") as client:
        allowed = client.post(
            "/api/isolation/wsl/codex-process-canary/one-shot",
            headers={"Origin": "http://127.0.0.1:8787"}, json={},
        )
        assert allowed.status_code == 409
    with TestClient(main.app) as client:
        denied = client.post("/api/isolation/wsl/codex-process-canary/one-shot", headers={"Origin": "http://testserver"}, json={})
        assert denied.status_code == 403


def test_server_handoff_endpoint_accepts_empty_body_and_never_returns_nonce(tmp_path, monkeypatch):
    from app import main

    supervisor = NoIoSupervisor()
    store, _, gate, created = one_shot_gate(tmp_path, supervisor=supervisor)
    monkeypatch.setattr(main, "DATA_ROOT", tmp_path / "api-data")
    with TestClient(main.app, base_url="http://127.0.0.1:8787") as client:
        main.app.state.codex_canary_execution_permit_gate = gate
        response = client.post(
            "/api/isolation/wsl/codex-process-canary/execute-one-shot",
            headers={"Origin": "http://127.0.0.1:8787"},
        )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == PASSED
    assert "permit_nonce" not in repr(body) and "canary_nonce" not in repr(body)
    assert created == {"runner": 1, "executor": 1} and supervisor.calls == 1
    assert store.codex_canary_execution_permit()["status"] == "CONSUMED"
    assert store.codex_process_canary_window()["status"] == "CONSUMED"


def test_server_handoff_rejects_request_body_without_creating_capability(tmp_path, monkeypatch):
    from app import main

    store, _, gate, created = one_shot_gate(tmp_path)
    monkeypatch.setattr(main, "DATA_ROOT", tmp_path / "api-data")
    with TestClient(main.app, base_url="http://127.0.0.1:8787") as client:
        main.app.state.codex_canary_execution_permit_gate = gate
        response = client.post(
            "/api/isolation/wsl/codex-process-canary/execute-one-shot",
            headers={"Origin": "http://127.0.0.1:8787"},
            json={"permit_nonce": "not-accepted"},
        )
    assert response.status_code == 422
    assert store.codex_canary_execution_permit()["status"] == "DISABLED"
    assert created == {"runner": 0, "executor": 0}
