from __future__ import annotations

import asyncio
import json
import sqlite3
import uuid
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.codex_process_canary import (
    BLOCKED,
    CANARY_RUNNER_KIND,
    ERROR,
    PASSED,
    PROCESS_OUTPUT_LIMIT_BYTES,
    RUNNER_IMPLEMENTATION_HASH,
    RUNNER_VERSION,
    SUCCESS_MARKER,
    FakeCodexProcessCanaryRunner,
    SealedOfflineCodexProcessCanary,
    build_runner_implementation_hash,
)
from app.egress_contract import AUTH_UNCONFIGURED, SealedEgressContractService, expected_repro_key
from app.egress_harness import HarnessExecution, SealedEgressHarnessService, WSL_RUNNER_KIND
from app.egress_harness_wsl import RUNNER_IMPLEMENTATION_HASH as HARNESS_IMPLEMENTATION_HASH
from app.egress_harness_wsl import WSL_EGRESS_RUNNER_VERSION
from app.isolation_repro import REPRO_RUNS, SAFE_REPRODUCIBLE
from app.isolation_wsl import ProcessResult, SAFE_CANDIDATE
from app.policy import PolicyError
from app.storage import Store
from app.wsl_codex_runtime import EGRESS_UNCONFIGURED, EXPECTED_CODEX_VERSION, WSLCodexRuntime


CONFIG_HASH = "1" * 64
TOOL_FINGERPRINT = "2" * 64
ISOLATION_KEY = "3" * 64
REPRO_RESULT_HASH = "4" * 64


class RuntimeMetadataRunner:
    def find_wsl(self) -> str:
        return "wsl.exe"

    async def run(self, args: list[str], *, timeout_seconds: float) -> ProcessResult:
        return ProcessResult(
            exit_code=0,
            stdout=json.dumps({
                "status": "OK", "sha256": "a" * 64, "version": EXPECTED_CODEX_VERSION,
                "size": 42, "mtime_ns": 1, "error": None,
            }, sort_keys=True, separators=(",", ":")) + "\n",
            stderr="",
        )


class ActualHarnessFake:
    runner_kind = WSL_RUNNER_KIND
    runner_version = WSL_EGRESS_RUNNER_VERSION
    runner_implementation_hash = HARNESS_IMPLEMENTATION_HASH
    requires_host_temp = False

    async def run(self, contract, launch_spec) -> HarnessExecution:
        return HarnessExecution(
            relay_connections=1, broker_connections=1, relay_requests=1, broker_requests=1,
            request_bytes=1, response_bytes=1, response_hash="b" * 64, request_hash="c" * 64,
            status_code=200, sensitive_headers_removed=True, socket_counts={}, local_processes=2,
            broker_socket_counts={"pathname_af_unix": 1, "inet_attempts": 0, "udp_attempts": 0, "dns_attempts": 0},
            relay_socket_counts={
                "af_unix_connections": 1, "loopback_tcp_listeners": 1, "loopback_tcp_connections": 1,
                "non_loopback_attempts": 0, "udp_attempts": 0, "dns_attempts": 0,
            },
            runner_kind=self.runner_kind, runner_version=self.runner_version,
            runner_implementation_hash=self.runner_implementation_hash,
        )


def ready_canary(tmp_path, runner: FakeCodexProcessCanaryRunner | None = None):
    store = Store(tmp_path / "data")
    now = datetime.now(timezone.utc)
    store.save_wsl_isolation_config("Ubuntu")
    store.save_wsl_isolation_result({
        "backend": "WSL2_BWRAP", "distro": "Ubuntu", "status": SAFE_CANDIDATE,
        "checked_at": now.isoformat(), "expires_at": (now + timedelta(minutes=30)).isoformat(),
        "config_hash": CONFIG_HASH, "tool_fingerprint": TOOL_FINGERPRINT, "cache_key": ISOLATION_KEY,
        "probe_version": "wsl2-bwrap-v1", "tool_versions": {"wsl2": True, "bwrap_present": True},
    })
    repro_key = expected_repro_key(CONFIG_HASH, TOOL_FINGERPRINT)
    store.save_wsl_isolation_repro({
        "repro_id": str(uuid.uuid4()), "cache_key": repro_key, "config_hash": CONFIG_HASH,
        "tool_fingerprint": TOOL_FINGERPRINT, "status": SAFE_REPRODUCIBLE,
        "requested_runs": REPRO_RUNS, "completed_runs": REPRO_RUNS, "success_count": REPRO_RUNS,
        "result_hash": REPRO_RESULT_HASH, "duration_ms": 1, "started_at": now.isoformat(),
        "finished_at": now.isoformat(), "error_code": None,
    })
    store.save_wsl_codex_runtime_config("/usr/local/bin/codex")
    assert asyncio.run(WSLCodexRuntime(store, RuntimeMetadataRunner()).preflight())["status"] == EGRESS_UNCONFIGURED
    contracts = SealedEgressContractService(store, proof_required=True)
    assert contracts.create()["status"] == AUTH_UNCONFIGURED
    actual = SealedEgressHarnessService(store, contracts, ActualHarnessFake())
    assert asyncio.run(actual.run())["status"] == PASSED
    runner = runner or FakeCodexProcessCanaryRunner()
    return store, contracts, runner, SealedOfflineCodexProcessCanary(store, contracts, runner)


def test_requires_complete_runtime_contract_and_actual_harness(tmp_path):
    store, contracts, _, service = ready_canary(tmp_path)
    assert service.ready()["status"] == "READY"
    contract = contracts.current()
    assert contract is not None
    # A fake result exists under its separate identity but cannot satisfy the
    # actual WSL harness prerequisite.
    store.begin_egress_harness({
        "harness_id": str(uuid.uuid4()), "contract_hash": contract["contract_hash"], "status": "RUNNING",
        "started_at": datetime.now(timezone.utc).isoformat(), "finished_at": None, "error_code": None,
        "request_bytes": 0, "response_bytes": 0, "response_hash": None, "status_code": None,
        "relay_connections": 0, "broker_connections": 0, "relay_requests": 0, "broker_requests": 0,
        "local_duration_ms": 0, "resources_cleaned": False, "start_allowed": False,
        "runner_kind": "FAKE", "runner_version": "sealed-egress-fake-runner-v1",
        "runner_implementation_hash": "0" * 64,
    })
    store.finish_egress_harness({
        "harness_id": store.egress_harness_result(contract["contract_hash"], "FAKE", "sealed-egress-fake-runner-v1", "0" * 64)["harness_id"],
        "contract_hash": contract["contract_hash"], "status": PASSED,
        "started_at": store.egress_harness_result(contract["contract_hash"], "FAKE", "sealed-egress-fake-runner-v1", "0" * 64)["started_at"],
        "finished_at": datetime.now(timezone.utc).isoformat(), "error_code": None,
        "request_bytes": 1, "response_bytes": 1, "response_hash": "a" * 64, "status_code": 200,
        "relay_connections": 1, "broker_connections": 1, "relay_requests": 1, "broker_requests": 1,
        "local_duration_ms": 1, "resources_cleaned": True, "start_allowed": False,
        "runner_kind": "FAKE", "runner_version": "sealed-egress-fake-runner-v1", "runner_implementation_hash": "0" * 64,
    })
    # Breaking the only actual record leaves the fake one irrelevant.
    with sqlite3.connect(store.db_path) as conn:
        conn.execute("DELETE FROM egress_harness_runs WHERE runner_kind=?", (WSL_RUNNER_KIND,))
    assert service.ready() == {"status": BLOCKED, "start_allowed": False, "error_code": "actual_harness_required"}


def test_stale_canary_and_incomplete_repro_are_blocked(tmp_path):
    store, _, _, service = ready_canary(tmp_path)
    isolation = store.wsl_isolation_result()
    assert isolation is not None
    store.save_wsl_isolation_result({**isolation, "expires_at": (datetime.now(timezone.utc) + timedelta(seconds=299)).isoformat()})
    assert service.ready()["error_code"] == "isolation_expiring"

    store, _, _, service = ready_canary(tmp_path / "again")
    repro = store.wsl_isolation_repro(expected_repro_key(CONFIG_HASH, TOOL_FINGERPRINT))
    assert repro is not None
    allowed = {
        "repro_id", "cache_key", "config_hash", "tool_fingerprint", "status", "requested_runs",
        "completed_runs", "success_count", "result_hash", "duration_ms", "started_at", "finished_at", "error_code",
    }
    store.save_wsl_isolation_repro({key: value for key, value in repro.items() if key in allowed} | {"completed_runs": REPRO_RUNS - 1})
    assert service.ready()["error_code"] == "repro_incomplete"


def test_window_nonce_is_hashed_single_use_and_restart_expires(tmp_path):
    store, _, _, service = ready_canary(tmp_path)
    armed = asyncio.run(service.arm())
    assert armed["status"] == "ARMED" and armed["remaining_seconds"] == 120
    assert armed["canary_nonce"] not in repr(store.codex_process_canary_window())
    with sqlite3.connect(store.db_path) as conn:
        assert armed["canary_nonce"] not in {row[0] for row in conn.execute("SELECT nonce_hash FROM codex_process_canary_windows")}
    assert store.recover_armed_codex_process_canary_windows() == 1
    assert store.codex_process_canary_window()["status"] == "EXPIRED"
    with pytest.raises(PolicyError, match="codex_canary_nonce_reused"):
        asyncio.run(service.run(armed["canary_nonce"]))


def test_fixed_hashes_and_sealed_launch_spec_do_not_expose_private_inputs(tmp_path):
    assert RUNNER_VERSION.endswith(RUNNER_IMPLEMENTATION_HASH[:16])
    assert build_runner_implementation_hash(broker_code=b"changed") != RUNNER_IMPLEMENTATION_HASH
    store, _, _, service = ready_canary(tmp_path)
    readiness = service.ready()
    assert readiness["implementation_hash"] == RUNNER_IMPLEMENTATION_HASH
    assert "CODEXGATE_EPHEMERAL_TOKEN" not in repr(readiness)
    assert "Return exactly" not in repr(readiness)


def test_success_allows_exactly_one_request_and_records_estimated_zero_token_event(tmp_path):
    store, _, runner, service = ready_canary(tmp_path)
    armed = asyncio.run(service.arm())
    result = asyncio.run(service.run(armed["canary_nonce"]))
    assert result["status"] == PASSED and runner.calls == 1 and result["request_count"] == 1
    events = [event for event in store.ledger_usage_events() if event.get("event_type", "").startswith("SEALED_OFFLINE_CODEX_PROCESS_CANARY")]
    run_event = next(event for event in events if event.get("action") == "RUN")
    assert run_event["source"] == "LOCAL_ESTIMATE" and run_event["quality"] == "ESTIMATED"
    assert run_event["external_tokens"] == 0 and run_event["app_server_rpc_calls"] == 0
    assert run_event["local_processes"] == 0 and run_event["planned_local_processes"] == 1
    assert store.token_ledger_report()["sealed_offline_codex_process_canary"]["measurement"] == "NOT_COMPARABLE"
    with sqlite3.connect(store.db_path) as conn:
        stored = "\n".join(row[0] for row in conn.execute("SELECT payload FROM codex_process_canary_runs"))
    assert SUCCESS_MARKER not in stored and "Return exactly" not in stored and "config_toml" not in stored


def test_arm_and_fake_run_keep_processes_planned_not_observed(tmp_path):
    store, _, _, service = ready_canary(tmp_path)
    armed = asyncio.run(service.arm())
    events = store.ledger_usage_events()
    assert any(event["event_type"] == "SEALED_OFFLINE_CODEX_PROCESS_CANARY_PLAN" for event in events)
    assert all(int(event.get("local_processes") or 0) == 0 for event in events if event["event_type"].startswith("SEALED_OFFLINE_CODEX_PROCESS_CANARY"))
    asyncio.run(service.run(armed["canary_nonce"]))
    events = [event for event in store.ledger_usage_events() if event["event_type"].startswith("SEALED_OFFLINE_CODEX_PROCESS_CANARY")]
    assert any(event["action"] == "RUN" and event["source"] == "LOCAL_ESTIMATE" and event["quality"] == "ESTIMATED" for event in events)


class ObservedProcessRunner(FakeCodexProcessCanaryRunner):
    runner_kind = CANARY_RUNNER_KIND
    is_fake = False

    async def run(self, binding, launch_spec):
        return replace(await super().run(binding, launch_spec), local_processes=2)


def test_observed_runner_records_only_spawned_processes_and_duration(tmp_path):
    store, _, _, service = ready_canary(tmp_path, ObservedProcessRunner())
    armed = asyncio.run(service.arm())
    result = asyncio.run(service.run(armed["canary_nonce"]))
    assert result["status"] == PASSED
    event = next(event for event in store.ledger_usage_events() if event.get("action") == "RUN")
    assert event["source"] == "LOCAL_OBSERVED" and event["quality"] == "OBSERVED"
    assert event["local_processes"] == 2 and event["planned_local_processes"] == 0
    assert event["local_duration_ms"] >= 0
    assert event["external_model_requests"] == 0 and event["app_server_rpc_calls"] == 0
    assert event["provider_total_tokens"] is None and event["ignored_usage"] is True


def test_binding_block_before_spawn_records_observed_zero(tmp_path):
    store, _, _, service = ready_canary(tmp_path, ObservedProcessRunner())
    armed = asyncio.run(service.arm())
    now = datetime.now(timezone.utc)
    store.save_wsl_isolation_result({
        "backend": "WSL2_BWRAP", "distro": "Ubuntu", "status": SAFE_CANDIDATE,
        "checked_at": now.isoformat(), "expires_at": (now + timedelta(minutes=30)).isoformat(),
        "config_hash": CONFIG_HASH, "tool_fingerprint": "9" * 64, "cache_key": ISOLATION_KEY,
        "probe_version": "wsl2-bwrap-v1", "tool_versions": {"wsl2": True, "bwrap_present": True},
    })
    with pytest.raises(PolicyError, match="canary_binding_changed"):
        asyncio.run(service.run(armed["canary_nonce"]))
    event = next(event for event in store.ledger_usage_events() if event.get("action") == "BLOCKED")
    assert event["source"] == "LOCAL_OBSERVED" and event["quality"] == "OBSERVED" and event["local_processes"] == 0


def test_unexpected_fixed_request_or_response_hash_is_rejected(tmp_path):
    class ChangedResponseRunner(FakeCodexProcessCanaryRunner):
        async def run(self, binding, launch_spec):
            return replace(await super().run(binding, launch_spec), response_hash="f" * 64)

    _, _, _, service = ready_canary(tmp_path, ChangedResponseRunner())
    armed = asyncio.run(service.arm())
    result = asyncio.run(service.run(armed["canary_nonce"]))
    assert result["status"] == "POLICY_VIOLATION"
    assert result["error_code"] == "canary_request_policy_violation"


@pytest.mark.parametrize("kwargs,error", [
    ({"tool_calls": 1}, "canary_tool_policy_violation"),
    ({"second_requests": 1}, "canary_request_policy_violation"),
    ({"different_models": 1}, "canary_model_policy_violation"),
    ({"websockets": 1}, "canary_websocket_policy_violation"),
    ({"retries": 1}, "canary_tool_policy_violation"),
    ({"sensitive_headers_removed": False}, "canary_header_policy_violation"),
])
def test_tools_second_request_model_and_websocket_are_rejected(tmp_path, kwargs, error):
    _, _, _, service = ready_canary(tmp_path, FakeCodexProcessCanaryRunner(**kwargs))
    armed = asyncio.run(service.arm())
    result = asyncio.run(service.run(armed["canary_nonce"]))
    assert result["status"] == "POLICY_VIOLATION" and result["error_code"] == error


@pytest.mark.parametrize("kwargs,error", [
    ({"marker": "wrong"}, "canary_marker_invalid"),
    ({"exit_code": 7}, "canary_exit_invalid"),
    ({"stdout_bytes": PROCESS_OUTPUT_LIMIT_BYTES + 1}, "canary_output_limit"),
])
def test_marker_exit_and_output_limits_fail_closed(tmp_path, kwargs, error):
    _, _, _, service = ready_canary(tmp_path, FakeCodexProcessCanaryRunner(**kwargs))
    armed = asyncio.run(service.arm())
    result = asyncio.run(service.run(armed["canary_nonce"]))
    assert result["status"] == ERROR and result["error_code"] == error


def test_changed_implementation_cannot_reuse_passed_or_window(tmp_path):
    store, contracts, first_runner, first = ready_canary(tmp_path)
    first_window = asyncio.run(first.arm())
    assert asyncio.run(first.run(first_window["canary_nonce"]))["status"] == PASSED
    changed_runner = FakeCodexProcessCanaryRunner(implementation_hash="e" * 64)
    changed = SealedOfflineCodexProcessCanary(store, contracts, changed_runner)
    assert changed.ready()["status"] == "READY"
    changed_window = asyncio.run(changed.arm())
    assert asyncio.run(changed.run(changed_window["canary_nonce"]))["status"] == PASSED
    assert first_runner.calls == 1 and changed_runner.calls == 1


def test_interrupted_run_recovers_without_raw_process_material(tmp_path):
    store, _, _, service = ready_canary(tmp_path)
    binding = service._binding()
    store.begin_codex_process_canary({
        "canary_id": str(uuid.uuid4()), "contract_hash": binding["contract_hash"], "binding_hash": binding["binding_hash"],
        "status": "RUNNING", "started_at": datetime.now(timezone.utc).isoformat(), "finished_at": None, "error_code": None,
        "request_count": 0, "request_hash": None, "response_hash": None, "config_hash": binding["config_hash"],
        "prompt_hash": "a" * 64, "expected_output_hash": "b" * 64, "exit_code": None, "output_bytes": 0,
        "local_processes": 0, "local_duration_ms": 0, "runner_kind": CANARY_RUNNER_KIND,
        "runner_version": RUNNER_VERSION, "runner_implementation_hash": RUNNER_IMPLEMENTATION_HASH,
        "implementation_hash": RUNNER_IMPLEMENTATION_HASH, "start_allowed": False,
    })
    assert store.recover_interrupted_codex_process_canaries() == 1
    result = store.codex_process_canary_result(binding["contract_hash"], CANARY_RUNNER_KIND, RUNNER_VERSION, RUNNER_IMPLEMENTATION_HASH)
    assert result is not None and result["error_code"] == "canary_interrupted"
    assert SUCCESS_MARKER not in repr(result)


def test_api_keeps_canary_disabled_and_preserves_local_host_origin_gate(tmp_path, monkeypatch):
    from app import main

    monkeypatch.setattr(main, "DATA_ROOT", tmp_path / "api-data")
    with TestClient(main.app, base_url="http://127.0.0.1:8787") as client:
        result = client.get("/api/isolation/wsl/codex-process-canary")
        assert result.status_code == 200 and result.json()["status"] == "DISABLED"
        arm = client.post("/api/isolation/wsl/codex-process-canary/arm", headers={"Origin": "http://127.0.0.1:8787"})
        assert arm.status_code == 409 and arm.json()["detail"] == "codex_canary_execution_disabled"
    with TestClient(main.app) as client:
        denied = client.post("/api/isolation/wsl/codex-process-canary/arm", headers={"Origin": "http://testserver"})
        assert denied.status_code == 403
