from __future__ import annotations

import asyncio
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.codex_process_canary import (
    CANARY_RUNNER_KIND,
    CodexCanaryExecutionPermitGate,
    FakeCodexProcessCanaryRunner,
    RUNNER_IMPLEMENTATION_HASH,
    RUNNER_VERSION,
    SealedOfflineCodexProcessCanary,
    WSLCodexProcessCanaryRunner,
)
from app.isolation_wsl import SAFE_CANDIDATE
from app.policy import PolicyError

from tests.test_codex_process_canary import CONFIG_HASH, ISOLATION_KEY, TOOL_FINGERPRINT, ready_canary


def ready_permit_gate(tmp_path):
    store, contracts, _, _ = ready_canary(tmp_path)
    service = SealedOfflineCodexProcessCanary(store, contracts, WSLCodexProcessCanaryRunner())
    return store, contracts, service, CodexCanaryExecutionPermitGate(store, service)


def test_permit_defaults_disabled_and_requires_actual_runner_and_nonce(tmp_path):
    store, _, service, gate = ready_permit_gate(tmp_path)
    assert service.ready()["status"] == "DISABLED"
    assert store.codex_canary_execution_permit()["status"] == "DISABLED"
    assert gate.ready()["status"] == "READY"
    with pytest.raises(PolicyError, match="codex_canary_permit_required"):
        asyncio.run(gate.arm(None))
    with pytest.raises(PolicyError, match="codex_canary_permit_required"):
        asyncio.run(gate.run(None, None))


def test_permit_is_hashed_single_use_and_restart_expires(tmp_path):
    store, _, _, gate = ready_permit_gate(tmp_path)
    permit = asyncio.run(gate.issue())
    assert permit["status"] == "ARMED" and permit["remaining_seconds"] == 120
    assert permit["permit_nonce"] not in repr(store.codex_canary_execution_permit())
    with sqlite3.connect(store.db_path) as conn:
        assert permit["permit_nonce"] not in {row[0] for row in conn.execute("SELECT nonce_hash FROM codex_canary_execution_permits")}
    assert store.recover_armed_codex_canary_execution_permits() == 1
    assert store.codex_canary_execution_permit()["status"] == "EXPIRED"
    with pytest.raises(PolicyError, match="codex_canary_permit_reused"):
        asyncio.run(gate.arm(permit["permit_nonce"]))


def test_permit_and_canary_window_are_consumed_before_disabled_runner(tmp_path):
    store, _, _, gate = ready_permit_gate(tmp_path)
    permit = asyncio.run(gate.issue())
    window = asyncio.run(gate.arm(permit["permit_nonce"]))
    with pytest.raises(PolicyError, match="codex_canary_execution_disabled"):
        asyncio.run(gate.run(permit["permit_nonce"], window["canary_nonce"]))
    assert store.codex_canary_execution_permit()["status"] == "CONSUMED"
    assert store.codex_process_canary_window()["status"] == "CONSUMED"
    blocked = next(event for event in store.ledger_usage_events() if event.get("action") == "BLOCKED")
    assert blocked["source"] == "LOCAL_OBSERVED" and blocked["quality"] == "OBSERVED"
    assert blocked["local_processes"] == 0 and blocked["external_model_requests"] == 0


def test_permit_remains_armed_until_the_canary_request_claims_both_nonces(tmp_path):
    store, _, _, gate = ready_permit_gate(tmp_path)
    permit = asyncio.run(gate.issue())
    window = asyncio.run(gate.arm(permit["permit_nonce"]))
    assert store.codex_canary_execution_permit()["status"] == "ARMED"
    assert window["status"] == "ARMED"


def test_binding_change_consumes_both_capabilities_before_spawn(tmp_path):
    store, _, _, gate = ready_permit_gate(tmp_path)
    permit = asyncio.run(gate.issue())
    window = asyncio.run(gate.arm(permit["permit_nonce"]))
    now = datetime.now(timezone.utc)
    store.save_wsl_isolation_result({
        "backend": "WSL2_BWRAP", "distro": "Ubuntu", "status": SAFE_CANDIDATE,
        "checked_at": now.isoformat(), "expires_at": (now + timedelta(minutes=30)).isoformat(),
        "config_hash": CONFIG_HASH, "tool_fingerprint": "9" * 64, "cache_key": ISOLATION_KEY,
        "probe_version": "wsl2-bwrap-v1", "tool_versions": {"wsl2": True, "bwrap_present": True},
    })
    with pytest.raises(PolicyError, match="execution_binding_changed"):
        asyncio.run(gate.run(permit["permit_nonce"], window["canary_nonce"]))
    assert store.codex_canary_execution_permit()["status"] == "CONSUMED"
    assert store.codex_process_canary_window()["status"] == "CONSUMED"


def test_concurrent_permit_and_execution_claim_allow_one_winner(tmp_path):
    _, _, _, gate = ready_permit_gate(tmp_path)

    async def issue_twice():
        return await asyncio.gather(gate.issue(), gate.issue(), return_exceptions=True)

    issued = asyncio.run(issue_twice())
    permit = next(value for value in issued if isinstance(value, dict))
    assert sum(isinstance(value, dict) for value in issued) == 1
    window = asyncio.run(gate.arm(permit["permit_nonce"]))

    async def run_twice():
        return await asyncio.gather(
            gate.run(permit["permit_nonce"], window["canary_nonce"]),
            gate.run(permit["permit_nonce"], window["canary_nonce"]),
            return_exceptions=True,
        )

    outcomes = asyncio.run(run_twice())
    assert sum(isinstance(value, PolicyError) and str(value) == "codex_canary_execution_disabled" for value in outcomes) == 1
    assert sum(isinstance(value, PolicyError) and "reused" in str(value) for value in outcomes) == 1


def test_fake_runner_is_rejected_by_actual_permit_gate(tmp_path):
    store, contracts, fake_runner, _ = ready_canary(tmp_path)
    service = SealedOfflineCodexProcessCanary(store, contracts, fake_runner)
    gate = CodexCanaryExecutionPermitGate(store, service)
    with pytest.raises(PolicyError, match="actual_runner_policy_violation"):
        asyncio.run(gate.issue())


def test_permit_api_keeps_ipv4_origin_and_testserver_policy(tmp_path, monkeypatch):
    from app import main

    monkeypatch.setattr(main, "DATA_ROOT", tmp_path / "api-data")
    with TestClient(main.app, base_url="http://127.0.0.1:8787") as client:
        permitted_host = client.post(
            "/api/isolation/wsl/codex-process-canary/permit",
            headers={"Origin": "http://127.0.0.1:8787"},
        )
        assert permitted_host.status_code == 409
        missing = client.post(
            "/api/isolation/wsl/codex-process-canary/arm",
            headers={"Origin": "http://127.0.0.1:8787"}, json={},
        )
        assert missing.status_code == 409 and missing.json()["detail"] == "codex_canary_permit_required"
    with TestClient(main.app) as client:
        denied = client.post("/api/isolation/wsl/codex-process-canary/permit", headers={"Origin": "http://testserver"})
        assert denied.status_code == 403


def test_permit_is_bound_to_current_sealed_identity(tmp_path):
    store, _, _, gate = ready_permit_gate(tmp_path)
    permit = asyncio.run(gate.issue())
    assert permit["canary_runner_kind"] == CANARY_RUNNER_KIND
    assert permit["canary_runner_version"] == RUNNER_VERSION
    assert permit["canary_implementation_hash"] == RUNNER_IMPLEMENTATION_HASH
    with sqlite3.connect(store.db_path) as conn:
        binding = conn.execute(
            "SELECT runtime_identity_version, runtime_fingerprint, launch_spec_hash, binary_sha256, repro_result_hash "
            "FROM codex_canary_execution_permits"
        ).fetchone()
    assert binding[0] == "runtime-identity-v1" and all(isinstance(value, str) and len(value) == 64 for value in binding[1:])
    assert not [event for event in store.ledger_usage_events() if event.get("event_type", "").startswith("SEALED_OFFLINE_CODEX_PROCESS_CANARY")]


@pytest.mark.parametrize("field,value", [
    ("runtime_fingerprint", "f" * 64),
    ("launch_spec_hash", "e" * 64),
    ("binary_sha256", "d" * 64),
    ("harness_implementation_hash", "c" * 64),
    ("repro_result_hash", "b" * 64),
    ("implementation_hash", "a" * 64),
])
def test_permit_storage_binding_rejects_changed_identity_fields(tmp_path, field, value):
    store, _, _, gate = ready_permit_gate(tmp_path)
    binding = gate._sealed_binding()
    changed = {**binding, field: value}
    if field == "implementation_hash":
        changed["canary_runner_version"] = f"sealed-offline-codex-{value[:16]}"
    with pytest.raises(PolicyError):
        store.issue_codex_canary_execution_permit(changed)
