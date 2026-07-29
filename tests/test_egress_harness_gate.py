from __future__ import annotations

import asyncio
import json
import uuid
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from app.egress_contract import (
    AUTH_UNCONFIGURED,
    BLOCKED,
    SealedEgressContractService,
    build_private_contract,
    expected_repro_key,
    validate_sealed_execution_proof,
)
from app.egress_harness import (
    ActualWSLHarnessGate,
    FAKE_RUNNER_IMPLEMENTATION_HASH,
    FAKE_RUNNER_KIND,
    FAKE_RUNNER_VERSION,
    PASSED,
    WSL_RUNNER_KIND,
    FakeHarnessRunner,
    SealedEgressHarnessService,
)
from app.egress_harness_wsl import RUNNER_IMPLEMENTATION_HASH, WSLEgressHarnessRunner, WSL_EGRESS_RUNNER_VERSION
from app.isolation_repro import REPRO_RUNS, REPRO_VERSION, SAFE_REPRODUCIBLE
from app.isolation_wsl import ProcessResult, SAFE_CANDIDATE
from app.policy import PolicyError
from app.storage import Store
from app.wsl_codex_runtime import EGRESS_UNCONFIGURED, EXPECTED_CODEX_VERSION, WSLCodexRuntime


CONFIG_HASH = "f" * 64
TOOL_FINGERPRINT = "b" * 64
ISOLATION_KEY = "c" * 64
REPRO_RESULT_HASH = "d" * 64


class FakeRuntimeRunner:
    def find_wsl(self) -> str:
        return "wsl.exe"

    async def run(self, args: list[str], *, timeout_seconds: float) -> ProcessResult:
        return ProcessResult(
            exit_code=0,
            stdout=json.dumps({
                "status": "OK", "sha256": "a" * 64, "version": EXPECTED_CODEX_VERSION,
                "size": 42, "mtime_ns": 7, "error": None,
            }, sort_keys=True, separators=(",", ":")) + "\n",
            stderr="",
        )


class InMemoryWSLRunner(WSLEgressHarnessRunner):
    def __init__(self):
        self.calls = 0

    async def run(self, contract, launch_spec):
        self.calls += 1
        result = await FakeHarnessRunner().run(contract, launch_spec)
        return replace(
            result,
            socket_counts={},
            broker_socket_counts={
                "pathname_af_unix": 1, "inet_attempts": 0, "udp_attempts": 0, "dns_attempts": 0,
            },
            relay_socket_counts={
                "af_unix_connections": 1, "loopback_tcp_listeners": 1,
                "loopback_tcp_connections": 1, "non_loopback_attempts": 0,
                "udp_attempts": 0, "dns_attempts": 0,
            },
            runner_kind=self.runner_kind,
            runner_version=self.runner_version,
            runner_implementation_hash=self.runner_implementation_hash,
        )


class InMemoryWSLRunnerV2(InMemoryWSLRunner):
    runner_version = "sealed-egress-wsl-runner-v2"


class InMemoryWSLRunnerChanged(InMemoryWSLRunner):
    runner_implementation_hash = "e" * 64
    runner_version = f"sealed-egress-wsl-{runner_implementation_hash[:16]}"


class LegacyHashlessWSLRunner(InMemoryWSLRunner):
    runner_implementation_hash = "0" * 64


def seed_isolation(store: Store, *, expires_in: int = 1800, now: datetime | None = None) -> datetime:
    current = now or datetime.now(timezone.utc)
    store.save_wsl_isolation_config("Ubuntu")
    store.save_wsl_isolation_result({
        "backend": "WSL2_BWRAP", "distro": "Ubuntu", "status": SAFE_CANDIDATE,
        "checked_at": current.isoformat(),
        "expires_at": (current + timedelta(seconds=expires_in)).isoformat(),
        "config_hash": CONFIG_HASH, "tool_fingerprint": TOOL_FINGERPRINT,
        "cache_key": ISOLATION_KEY, "probe_version": "wsl2-bwrap-v1",
        "tool_versions": {"wsl2": True, "bwrap_present": True},
    })
    return current


def seed_repro(
    store: Store,
    *,
    completed: int = REPRO_RUNS,
    config_hash: str = CONFIG_HASH,
    tool_fingerprint: str = TOOL_FINGERPRINT,
    result_hash: str = REPRO_RESULT_HASH,
    status: str = SAFE_REPRODUCIBLE,
    now: datetime | None = None,
) -> str:
    current = now or datetime.now(timezone.utc)
    key = expected_repro_key(CONFIG_HASH, TOOL_FINGERPRINT)
    store.save_wsl_isolation_repro({
        "repro_id": str(uuid.uuid4()), "cache_key": key,
        "config_hash": config_hash, "tool_fingerprint": tool_fingerprint,
        "status": status, "requested_runs": REPRO_RUNS,
        "completed_runs": completed, "success_count": completed,
        "result_hash": result_hash, "duration_ms": 1,
        "started_at": current.isoformat(), "finished_at": current.isoformat(),
        "error_code": None,
    })
    return key


def ready_store(tmp_path) -> tuple[Store, SealedEgressContractService, dict]:
    store = Store(tmp_path / "data")
    seed_isolation(store)
    seed_repro(store)
    store.save_wsl_codex_runtime_config("/usr/local/bin/codex")
    assert asyncio.run(WSLCodexRuntime(store, FakeRuntimeRunner()).preflight())["status"] == EGRESS_UNCONFIGURED
    contracts = SealedEgressContractService(store, proof_required=True)
    contract = contracts.create()
    assert contract["status"] == AUTH_UNCONFIGURED
    return store, contracts, contract


@pytest.mark.parametrize("expires_in", [-1, 329])
def test_expired_or_less_than_execution_plus_five_minutes_blocks_contract(tmp_path, expires_in):
    store = Store(tmp_path / "data")
    seed_isolation(store, expires_in=expires_in)
    seed_repro(store)
    store.save_wsl_codex_runtime_config("/usr/local/bin/codex")
    asyncio.run(WSLCodexRuntime(store, FakeRuntimeRunner()).preflight())
    result = SealedEgressContractService(store, proof_required=True).create()
    assert result["status"] == BLOCKED
    assert result["error_code"] == "isolation_expiring"


def test_only_current_environment_safe_reproducible_10_of_10_is_accepted(tmp_path):
    store = Store(tmp_path / "data")
    seed_isolation(store)
    proof, error = validate_sealed_execution_proof(store)
    assert proof is None and error == "repro_missing"

    seed_repro(store, completed=9)
    proof, error = validate_sealed_execution_proof(store)
    assert proof is None and error == "repro_incomplete"

    seed_repro(store, config_hash="e" * 64)
    proof, error = validate_sealed_execution_proof(store)
    assert proof is None and error == "repro_binding_changed"

    key = seed_repro(store)
    proof, error = validate_sealed_execution_proof(store)
    assert error is None
    assert proof == {
        "repro_version": REPRO_VERSION,
        "repro_key": key,
        "repro_result_hash": REPRO_RESULT_HASH,
    }
    assert key != ISOLATION_KEY


def test_contract_hash_is_bound_to_repro_identity(tmp_path):
    _, contracts, contract = ready_store(tmp_path)
    assert contract["repro_version"] == REPRO_VERSION
    assert contract["repro_key"] == expected_repro_key(CONFIG_HASH, TOOL_FINGERPRINT)
    first = build_private_contract(
        runtime_fingerprint=contract["runtime_fingerprint"],
        isolation_cache_key=contract["isolation_cache_key"],
        binary_sha256=contract["binary_sha256"],
        repro_key=contract["repro_key"],
        repro_result_hash=contract["repro_result_hash"],
    )
    changed = build_private_contract(
        runtime_fingerprint=contract["runtime_fingerprint"],
        isolation_cache_key=contract["isolation_cache_key"],
        binary_sha256=contract["binary_sha256"],
        repro_key=contract["repro_key"],
        repro_result_hash="e" * 64,
    )
    assert first["contract_hash"] != changed["contract_hash"]
    assert contracts.current()["contract_hash"] == contract["contract_hash"]


def test_fake_pass_is_not_reused_by_wsl_or_new_runner_version(tmp_path):
    store, contracts, contract = ready_store(tmp_path)
    fake = FakeHarnessRunner()
    fake_result = asyncio.run(SealedEgressHarnessService(store, contracts, fake).run())
    assert fake_result["status"] == PASSED and fake.calls == 1

    actual = InMemoryWSLRunner()
    actual_result = asyncio.run(SealedEgressHarnessService(store, contracts, actual).run())
    assert actual_result["status"] == PASSED and actual.calls == 1
    assert actual_result["runner_kind"] == WSL_RUNNER_KIND

    upgraded = InMemoryWSLRunnerV2()
    upgraded_result = asyncio.run(SealedEgressHarnessService(store, contracts, upgraded).run())
    assert upgraded_result["status"] == PASSED and upgraded.calls == 1
    assert store.egress_harness_result(
        contract["contract_hash"], FAKE_RUNNER_KIND, FAKE_RUNNER_VERSION, FAKE_RUNNER_IMPLEMENTATION_HASH,
    )
    assert store.egress_harness_result(
        contract["contract_hash"], WSL_RUNNER_KIND, WSL_EGRESS_RUNNER_VERSION, RUNNER_IMPLEMENTATION_HASH,
    )
    assert store.egress_harness_result(
        contract["contract_hash"], WSL_RUNNER_KIND, upgraded.runner_version, upgraded.runner_implementation_hash,
    )


def test_implementation_hash_change_needs_new_result_and_arm(tmp_path):
    store, contracts, contract = ready_store(tmp_path)
    first = InMemoryWSLRunner()
    assert asyncio.run(SealedEgressHarnessService(store, contracts, first).run())["status"] == PASSED

    changed = InMemoryWSLRunnerChanged()
    changed_result = asyncio.run(SealedEgressHarnessService(store, contracts, changed).run())
    assert changed_result["status"] == PASSED and changed.calls == 1
    assert changed_result["runner_implementation_hash"] == changed.runner_implementation_hash

    old_arm = store.issue_egress_harness_arm(
        contract["contract_hash"], WSL_RUNNER_KIND, WSL_EGRESS_RUNNER_VERSION,
        RUNNER_IMPLEMENTATION_HASH,
    )
    with pytest.raises(PolicyError, match="arm_binding_changed"):
        store.consume_egress_harness_arm(
            old_arm["arm_nonce"], contract["contract_hash"], WSL_RUNNER_KIND,
            changed.runner_version, changed.runner_implementation_hash,
        )


def test_hashless_legacy_wsl_pass_is_not_reused(tmp_path):
    store, contracts, _ = ready_store(tmp_path)
    legacy = LegacyHashlessWSLRunner()
    assert asyncio.run(SealedEgressHarnessService(store, contracts, legacy).run())["status"] == PASSED
    current = InMemoryWSLRunner()
    result = asyncio.run(SealedEgressHarnessService(store, contracts, current).run())
    assert result["status"] == PASSED
    assert current.calls == 1
    assert result["runner_implementation_hash"] == RUNNER_IMPLEMENTATION_HASH


def test_arm_nonce_is_expiring_one_time_and_binding_specific(tmp_path):
    store, _, contract = ready_store(tmp_path)
    now = datetime.now(timezone.utc)
    expired = store.issue_egress_harness_arm(
        contract["contract_hash"], WSL_RUNNER_KIND, WSL_EGRESS_RUNNER_VERSION,
        RUNNER_IMPLEMENTATION_HASH,
        ttl_seconds=1, now=now,
    )
    with pytest.raises(PolicyError, match="arm_expired"):
        store.consume_egress_harness_arm(
            expired["arm_nonce"], contract["contract_hash"], WSL_RUNNER_KIND,
            WSL_EGRESS_RUNNER_VERSION, RUNNER_IMPLEMENTATION_HASH,
            now=now + timedelta(seconds=2),
        )

    armed = store.issue_egress_harness_arm(
        contract["contract_hash"], WSL_RUNNER_KIND, WSL_EGRESS_RUNNER_VERSION,
        RUNNER_IMPLEMENTATION_HASH,
    )
    store.consume_egress_harness_arm(
        armed["arm_nonce"], contract["contract_hash"], WSL_RUNNER_KIND,
        WSL_EGRESS_RUNNER_VERSION, RUNNER_IMPLEMENTATION_HASH,
    )
    with pytest.raises(PolicyError, match="arm_reused"):
        store.consume_egress_harness_arm(
            armed["arm_nonce"], contract["contract_hash"], WSL_RUNNER_KIND,
            WSL_EGRESS_RUNNER_VERSION, RUNNER_IMPLEMENTATION_HASH,
        )


def test_actual_gate_requires_arm_and_never_accepts_fake_runner(tmp_path):
    store, contracts, _ = ready_store(tmp_path)
    fake_gate = ActualWSLHarnessGate(store, SealedEgressHarnessService(store, contracts, FakeHarnessRunner()))
    with pytest.raises(PolicyError, match="actual_runner_policy_violation"):
        fake_gate.arm()

    runner = InMemoryWSLRunner()
    service = SealedEgressHarnessService(store, contracts, runner)
    gate = ActualWSLHarnessGate(store, service)
    with pytest.raises(PolicyError, match="execution_window_required"):
        asyncio.run(gate.run(None, None))
    arm = gate.arm()
    result = asyncio.run(gate.run(arm["window_nonce"], arm["arm_nonce"]))
    assert result["status"] == PASSED
    assert runner.calls == 1


def test_execution_window_defaults_disabled_and_invalid_run_does_not_start(tmp_path):
    store, contracts, _ = ready_store(tmp_path)
    runner = InMemoryWSLRunner()
    gate = ActualWSLHarnessGate(store, SealedEgressHarnessService(store, contracts, runner))
    assert gate.window_status()["status"] == "DISABLED"
    with pytest.raises(PolicyError, match="execution_window_required"):
        asyncio.run(gate.run(None, None))
    assert runner.calls == 0
