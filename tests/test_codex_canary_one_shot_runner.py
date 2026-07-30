from __future__ import annotations

import asyncio
from dataclasses import replace
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
from app.isolation_wsl import SAFE_CANDIDATE
from app.policy import PolicyError

from tests.test_codex_process_canary import CONFIG_HASH, ISOLATION_KEY, ready_canary


class NoIoExecutor:
    """A deterministic test double; it never starts a child process."""

    def __init__(self, *, processes: int = 2, marker: str = SUCCESS_MARKER):
        self.processes = processes
        self.marker = marker
        self.calls = 0

    async def run(self, binding, launch_spec) -> CanaryExecution:
        self.calls += 1
        return CanaryExecution(
            request_count=1,
            request_hash=EXPECTED_REQUEST_HASH,
            response_hash=EXPECTED_RESPONSE_HASH,
            config_hash=EXPECTED_CONFIG_HASH,
            prompt_hash=EXPECTED_PROMPT_HASH,
            expected_output_hash=EXPECTED_OUTPUT_HASH,
            exit_code=0,
            stdout_bytes=len(self.marker.encode("utf-8")),
            stderr_bytes=0,
            local_processes=self.processes,
            marker=self.marker,
            runner_kind=CANARY_RUNNER_KIND,
            runner_version=RUNNER_VERSION,
            runner_implementation_hash=RUNNER_IMPLEMENTATION_HASH,
        )


def one_shot_gate(tmp_path, *, executor: NoIoExecutor | None = None, changed_runner_hash: str | None = None):
    store, contracts, _, _ = ready_canary(tmp_path)
    created = {"runner": 0, "executor": 0}

    def make_executor():
        created["executor"] += 1
        if executor is None:
            raise AssertionError("executor must not be created")
        return executor

    def make_runner():
        created["runner"] += 1
        runner = WSLCodexProcessCanaryRunner(make_executor if executor is not None else None)
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
    executor = NoIoExecutor()
    store, _, gate, created = one_shot_gate(tmp_path, executor=executor)
    permit, window = arm_pair(gate)
    assert created == {"runner": 0, "executor": 0}
    result = asyncio.run(gate.run_one_shot(permit["permit_nonce"], window["canary_nonce"]))
    assert result["status"] == PASSED
    assert created == {"runner": 1, "executor": 1} and executor.calls == 1
    claim = store.codex_canary_execution_claim()
    assert claim["status"] == PASSED and claim["runner_implementation_hash"] == RUNNER_IMPLEMENTATION_HASH
    assert permit["permit_nonce"] not in repr(claim) and window["canary_nonce"] not in repr(claim)
    assert store.codex_canary_execution_permit()["status"] == "CONSUMED"
    assert store.codex_process_canary_window()["status"] == "CONSUMED"


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
    executor = NoIoExecutor()
    _, _, gate, created = one_shot_gate(tmp_path, executor=executor)
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
    assert created == {"runner": 1, "executor": 1} and executor.calls == 1


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
    executor = NoIoExecutor()
    _, _, gate, created = one_shot_gate(tmp_path, executor=executor, changed_runner_hash="a" * 64)
    permit, window = arm_pair(gate)
    with pytest.raises(PolicyError, match="actual_runner_policy_violation"):
        asyncio.run(gate.run_one_shot(permit["permit_nonce"], window["canary_nonce"]))
    assert created == {"runner": 1, "executor": 0} and executor.calls == 0


def test_partial_failure_records_only_observed_started_processes(tmp_path):
    executor = NoIoExecutor(processes=1, marker="wrong")
    store, _, gate, _ = one_shot_gate(tmp_path, executor=executor)
    permit, window = arm_pair(gate)
    result = asyncio.run(gate.run_one_shot(permit["permit_nonce"], window["canary_nonce"]))
    assert result["status"] == ERROR
    event = next(event for event in store.ledger_usage_events() if event.get("action") == "RUN")
    assert event["source"] == "LOCAL_OBSERVED" and event["quality"] == "OBSERVED"
    assert event["local_processes"] == 1 and event["local_duration_ms"] >= 0
    assert event["provider_total_tokens"] is None and event["external_model_requests"] == 0
    assert event["app_server_rpc_calls"] == 0 and event["ignored_usage"] is True


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
