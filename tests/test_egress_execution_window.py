from __future__ import annotations

import asyncio
import json
import sqlite3
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

import app.main as app_main
from app.egress_contract import AUTH_UNCONFIGURED, SealedEgressContractService, expected_repro_key
from app.egress_harness import (
    ActualWSLHarnessGate,
    HarnessExecution,
    SealedEgressHarnessService,
    WSL_RUNNER_KIND,
)
from app.egress_harness_wsl import RUNNER_IMPLEMENTATION_HASH, WSLEgressHarnessRunner, WSL_EGRESS_RUNNER_VERSION
from app.isolation_repro import REPRO_RUNS, REPRO_VERSION, SAFE_REPRODUCIBLE
from app.isolation_wsl import ProcessResult, SAFE_CANDIDATE
from app.policy import PolicyError
from app.storage import Store
from app.wsl_codex_runtime import EGRESS_UNCONFIGURED, EXPECTED_CODEX_VERSION, WSLCodexRuntime


CONFIG_HASH = "1" * 64
TOOL_FINGERPRINT = "2" * 64
ISOLATION_KEY = "3" * 64
REPRO_RESULT_HASH = "4" * 64


class RuntimeMetadataRunner:
    def __init__(self, binary_sha: str = "a" * 64):
        self.binary_sha = binary_sha

    def find_wsl(self) -> str:
        return "wsl.exe"

    async def run(self, args: list[str], *, timeout_seconds: float) -> ProcessResult:
        return ProcessResult(
            exit_code=0,
            stdout=json.dumps({
                "status": "OK", "sha256": self.binary_sha, "version": EXPECTED_CODEX_VERSION,
                "size": 42, "mtime_ns": 1, "error": None,
            }, sort_keys=True, separators=(",", ":")) + "\n",
            stderr="",
        )


class WindowProcessExecutor(WSLEgressHarnessRunner):
    """A no-I/O test double for the WSL runner's fixed process boundary."""

    def __init__(self):
        self.calls = 0

    async def run(self, contract, launch_spec) -> HarnessExecution:
        self.calls += 1
        return HarnessExecution(
            relay_connections=1,
            broker_connections=1,
            relay_requests=1,
            broker_requests=1,
            request_bytes=2,
            response_bytes=2,
            response_hash="a" * 64,
            request_hash="b" * 64,
            status_code=200,
            sensitive_headers_removed=True,
            socket_counts={},
            broker_socket_counts={"pathname_af_unix": 1, "inet_attempts": 0, "udp_attempts": 0, "dns_attempts": 0},
            relay_socket_counts={
                "af_unix_connections": 1, "loopback_tcp_listeners": 1, "loopback_tcp_connections": 1,
                "non_loopback_attempts": 0, "udp_attempts": 0, "dns_attempts": 0,
            },
            runner_kind=self.runner_kind,
            runner_version=self.runner_version,
            runner_implementation_hash=self.runner_implementation_hash,
        )


class ChangedWindowProcessExecutor(WindowProcessExecutor):
    runner_implementation_hash = "e" * 64
    runner_version = f"sealed-egress-wsl-{runner_implementation_hash[:16]}"


def ready_gate(tmp_path):
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
        "repro_id": str(uuid.uuid4()), "cache_key": repro_key,
        "config_hash": CONFIG_HASH, "tool_fingerprint": TOOL_FINGERPRINT,
        "status": SAFE_REPRODUCIBLE, "requested_runs": REPRO_RUNS,
        "completed_runs": REPRO_RUNS, "success_count": REPRO_RUNS,
        "result_hash": REPRO_RESULT_HASH, "duration_ms": 1,
        "started_at": now.isoformat(), "finished_at": now.isoformat(), "error_code": None,
    })
    store.save_wsl_codex_runtime_config("/usr/local/bin/codex")
    assert asyncio.run(WSLCodexRuntime(store, RuntimeMetadataRunner()).preflight())["status"] == EGRESS_UNCONFIGURED
    contracts = SealedEgressContractService(store, proof_required=True)
    assert contracts.create()["status"] == AUTH_UNCONFIGURED
    runner = WindowProcessExecutor()
    return store, runner, ActualWSLHarnessGate(store, SealedEgressHarnessService(store, contracts, runner))


def test_execution_window_defaults_disabled_and_stores_nonce_hashes_only(tmp_path):
    store, _, gate = ready_gate(tmp_path)
    assert gate.window_status()["status"] == "DISABLED"
    armed = gate.arm()
    assert armed["status"] == "ARMED"
    assert armed["remaining_seconds"] == 120
    assert armed["window_nonce"] not in repr(store.egress_execution_window())
    with sqlite3.connect(store.db_path) as conn:
        rows = conn.execute("SELECT nonce_hash FROM egress_execution_windows").fetchall()
        arm_rows = conn.execute("SELECT nonce_hash FROM egress_harness_arms").fetchall()
    assert rows and arm_rows
    assert armed["window_nonce"] not in {item[0] for item in rows}
    assert armed["arm_nonce"] not in {item[0] for item in arm_rows}


def test_window_expiry_and_restart_expire_without_extension(tmp_path):
    store, _, gate = ready_gate(tmp_path)
    now = datetime.now(timezone.utc)
    binding = gate._sealed_binding()
    expired = store.issue_egress_execution_window(binding, now=now)
    with pytest.raises(PolicyError, match="execution_window_expired"):
        store.consume_egress_execution_window(expired["window_nonce"], expired["arm_nonce"], now=now + timedelta(seconds=121))

    armed = gate.arm()
    assert armed["status"] == "ARMED"
    assert store.recover_armed_egress_execution_windows() == 1
    assert store.egress_execution_window()["status"] == "EXPIRED"


def test_changed_proof_consumes_window_before_blocking_execution(tmp_path):
    store, runner, gate = ready_gate(tmp_path)
    armed = gate.arm()
    changed = store.wsl_isolation_result()
    assert changed is not None
    store.save_wsl_isolation_result({**changed, "tool_fingerprint": "5" * 64})
    with pytest.raises(PolicyError, match="execution_window_binding_changed"):
        asyncio.run(gate.run(armed["window_nonce"], armed["arm_nonce"]))
    assert store.egress_execution_window()["status"] == "CONSUMED"
    assert runner.calls == 0


@pytest.mark.parametrize("change", ["contract", "repro", "runner"])
def test_contract_repro_or_runner_change_consumes_and_blocks_window(tmp_path, change):
    store, runner, gate = ready_gate(tmp_path)
    armed = gate.arm()
    active_gate = gate
    if change == "contract":
        # A new sealed runtime fingerprint invalidates the stored Contract.
        assert asyncio.run(WSLCodexRuntime(store, RuntimeMetadataRunner("f" * 64)).preflight())["status"] == EGRESS_UNCONFIGURED
    elif change == "repro":
        now = datetime.now(timezone.utc)
        store.save_wsl_isolation_repro({
            "repro_id": str(uuid.uuid4()), "cache_key": expected_repro_key(CONFIG_HASH, TOOL_FINGERPRINT),
            "config_hash": CONFIG_HASH, "tool_fingerprint": TOOL_FINGERPRINT,
            "status": SAFE_REPRODUCIBLE, "requested_runs": REPRO_RUNS,
            "completed_runs": REPRO_RUNS, "success_count": REPRO_RUNS,
            "result_hash": "f" * 64, "duration_ms": 1,
            "started_at": now.isoformat(), "finished_at": now.isoformat(), "error_code": None,
        })
    else:
        changed = ChangedWindowProcessExecutor()
        active_gate = ActualWSLHarnessGate(
            store, SealedEgressHarnessService(store, gate.service.contract_service, changed),
        )

    with pytest.raises(PolicyError, match="execution_window_binding_changed"):
        asyncio.run(active_gate.run(armed["window_nonce"], armed["arm_nonce"]))
    assert store.egress_execution_window()["status"] == "CONSUMED"
    assert runner.calls == 0


def test_one_window_claims_two_nonces_and_allows_one_concurrent_run(tmp_path):
    store, runner, gate = ready_gate(tmp_path)
    armed = gate.arm()

    async def attempt():
        try:
            return await gate.run(armed["window_nonce"], armed["arm_nonce"])
        except PolicyError as exc:
            return str(exc)

    async def both():
        return await asyncio.gather(attempt(), attempt())

    first, second = asyncio.run(both())
    outcomes = [first, second]
    assert sum(isinstance(item, dict) and item["status"] == "PASSED" for item in outcomes) == 1
    assert "execution_window_reused" in outcomes
    assert runner.calls == 1
    assert store.egress_execution_window()["status"] == "CONSUMED"


def test_concurrent_arm_allows_exactly_one_window(tmp_path):
    _, _, gate = ready_gate(tmp_path)

    def arm_once():
        try:
            return gate.arm()["status"]
        except PolicyError as exc:
            return str(exc)

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda _: arm_once(), range(2)))
    assert outcomes.count("ARMED") == 1
    assert any(value in {"execution_window_arm_in_progress", "execution_window_already_armed"} for value in outcomes)


def test_fake_runner_cannot_mint_actual_window_and_runtime_stays_locked(tmp_path):
    store, _, gate = ready_gate(tmp_path)
    from app.egress_harness import FakeHarnessRunner

    assert gate.arm()["status"] == "ARMED"
    assert store.wsl_codex_runtime_result()["start_allowed"] is False
    fake_gate = ActualWSLHarnessGate(
        store, SealedEgressHarnessService(store, gate.service.contract_service, FakeHarnessRunner()),
    )
    with pytest.raises(PolicyError, match="actual_runner_policy_violation"):
        fake_gate.arm()
    assert store.wsl_codex_runtime_result()["start_allowed"] is False


def test_window_arm_and_consume_are_counted_without_tokens_or_rpc(tmp_path):
    store, _, gate = ready_gate(tmp_path)
    armed = gate.arm()
    assert asyncio.run(gate.run(armed["window_nonce"], armed["arm_nonce"]))["status"] == "PASSED"
    events = [event for event in store.ledger_usage_events() if event.get("event_type") == "WSL_EGRESS_EXECUTION_WINDOW"]
    assert {event["action"] for event in events} == {"ARM", "CONSUME"}
    assert all(event["tokens"] == 0 and event["app_server_rpc_calls"] == 0 for event in events)


def test_execution_window_arm_requires_ipv4_loopback_and_matching_origin(tmp_path, monkeypatch):
    monkeypatch.setattr(app_main, "DATA_ROOT", tmp_path / "http-data")
    with TestClient(app_main.app) as default_client:
        assert default_client.post("/api/isolation/wsl/egress-harness/actual/arm").status_code == 403
    with TestClient(app_main.app, base_url="http://127.0.0.1:8787") as local_client:
        assert local_client.post("/api/isolation/wsl/egress-harness/actual/arm").status_code == 403
        # Matching local Origin passes the host/origin guard and then fails
        # closed because this fresh test store lacks a sealed proof.
        response = local_client.post(
            "/api/isolation/wsl/egress-harness/actual/arm",
            headers={"origin": "http://127.0.0.1:8787"},
        )
        assert response.status_code == 409
