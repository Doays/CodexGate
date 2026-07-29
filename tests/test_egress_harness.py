from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone

import pytest

from app.egress_broker import FakeUnixBroker, deterministic_response_metadata, fixed_client_request
from app.egress_contract import AUTH_UNCONFIGURED, SealedEgressContractService, validate_broker_request
from app.egress_harness import (
    ERROR,
    HARNESS_BLOCKED,
    PASSED,
    READY,
    DisabledHarnessRunner,
    FakeHarnessRunner,
    SealedEgressHarnessService,
)
from app.egress_relay import PROCESS_OUTPUT_LIMIT_BYTES, FakeLoopbackRelay, build_relay_launch_spec
from app.isolation_wsl import SAFE_CANDIDATE
from app.policy import PolicyError
from app.storage import Store
from app.wsl_codex_runtime import EGRESS_UNCONFIGURED, EXPECTED_CODEX_VERSION, WSLCodexRuntime


class FakeRuntimeRunner:
    def __init__(self, sha256: str = "a" * 64):
        self.sha256 = sha256

    def find_wsl(self) -> str:
        return "wsl.exe"

    async def run(self, args: list[str], *, timeout_seconds: float):
        from app.isolation_wsl import ProcessResult
        return ProcessResult(
            exit_code=0,
            stdout=json.dumps({"status": "OK", "sha256": self.sha256, "version": EXPECTED_CODEX_VERSION,
                               "size": 42, "mtime_ns": 7, "error": None}, sort_keys=True, separators=(",", ":")) + "\n",
            stderr="",
        )


def ready_harness(tmp_path, runner: FakeHarnessRunner | None = None):
    store = Store(tmp_path / "data")
    now = datetime.now(timezone.utc)
    store.save_wsl_isolation_config("Ubuntu")
    store.save_wsl_isolation_result({
        "backend": "WSL2_BWRAP", "distro": "Ubuntu", "status": SAFE_CANDIDATE,
        "checked_at": now.isoformat(), "expires_at": (now + timedelta(minutes=30)).isoformat(),
        "config_hash": "f" * 64, "tool_fingerprint": "b" * 64, "cache_key": "c" * 64,
        "probe_version": "wsl2-bwrap-v1", "tool_versions": {"wsl2": True, "bwrap_present": True},
    })
    store.save_wsl_codex_runtime_config("/usr/local/bin/codex")
    runtime = WSLCodexRuntime(store, FakeRuntimeRunner())
    assert asyncio.run(runtime.preflight())["status"] == EGRESS_UNCONFIGURED
    contracts = SealedEgressContractService(store)
    contract = contracts.create()
    assert contract["status"] == AUTH_UNCONFIGURED
    return store, runtime, contracts, contract, SealedEgressHarnessService(store, contracts, runner or FakeHarnessRunner())


def test_contract_preview_hash_matches_created_instance_and_reuses_identity(tmp_path):
    store, _, contracts, first, _ = ready_harness(tmp_path)
    second = contracts.create()
    assert first["preview_hash"] == first["contract_hash"]
    assert second["reused"] is True
    assert second["contract_id"] == first["contract_id"]
    assert store.egress_contract_instance(first["contract_hash"])["contract_id"] == first["contract_id"]


def test_fake_relay_broker_path_is_deterministic_and_contract_remains_auth_unconfigured(tmp_path):
    store, runtime, contracts, contract, service = ready_harness(tmp_path)
    result = asyncio.run(service.run())
    assert result["status"] == PASSED
    assert result["relay_connections"] == result["broker_connections"] == 1
    assert result["relay_requests"] == result["broker_requests"] == 1
    assert result["response_hash"] == deterministic_response_metadata()["response_hash"]
    assert contracts.current()["status"] == AUTH_UNCONFIGURED
    with pytest.raises(PolicyError, match="egress"):
        runtime.start()
    ledger = store.token_ledger_report()["sealed_egress_harness"]
    assert ledger["executions"] == 1
    assert ledger["local_processes"] == 0
    assert ledger["tokens"] == ledger["app_server_rpc_calls"] == 0


def test_launch_spec_is_loopback_only_and_does_not_bind_host_data(tmp_path):
    _, _, _, contract, _ = ready_harness(tmp_path)
    spec = build_relay_launch_spec(contract)
    serialized = json.dumps(spec, sort_keys=True)
    assert spec["listen"] == {"host": "127.0.0.1", "port": 8788}
    assert spec["network"] == "sandbox_loopback_only"
    assert spec["timeouts"] == {"start_seconds": 10, "request_seconds": 15, "total_seconds": 30}
    assert spec["output_limit_bytes"] == PROCESS_OUTPUT_LIMIT_BYTES
    assert spec["clearenv"] is True
    assert set(spec["environment"]) == {"PATH", "HOME", "TMPDIR", "LANG"}
    assert "--share-net" not in spec["argv"]
    assert "/mnt" not in serialized and "DATA_ROOT" not in serialized and "Source Root" not in serialized


def test_broker_rejects_network_socket_policy_and_second_connection_or_request(tmp_path):
    _, _, _, contract, _ = ready_harness(tmp_path)
    broker = FakeUnixBroker(contract, socket_counts={"af_unix": 1, "tcp": 1, "udp": 0, "dns": 0})
    with pytest.raises(PolicyError, match="socket policy"):
        broker.accept_connection()
    broker = FakeUnixBroker(contract)
    broker.accept_connection()
    method, path, headers, body = fixed_client_request()
    first = broker.handle_request(method, path, headers, body)
    assert "Authorization" not in first.sanitized_headers and "Cookie" not in first.sanitized_headers
    with pytest.raises(PolicyError, match="second request"):
        broker.handle_request(method, path, headers, body)
    with pytest.raises(PolicyError, match="second connection"):
        broker.accept_connection()


def test_sensitive_headers_are_removed_before_the_broker_boundary(tmp_path):
    _, _, _, contract, _ = ready_harness(tmp_path)

    class RecordingBroker(FakeUnixBroker):
        received_headers = None

        def handle_request(self, method, path, headers, body):
            self.received_headers = dict(headers)
            return super().handle_request(method, path, headers, body)

    broker = RecordingBroker(contract)
    relay = FakeLoopbackRelay(broker)
    relay.accept_connection()
    method, path, headers, body = fixed_client_request()
    response = relay.forward(method, path, headers, body)
    assert response.sensitive_headers_removed is True
    assert "Authorization" not in broker.received_headers
    assert "Cookie" not in broker.received_headers
    assert not any(key.casefold().startswith("proxy-") for key in broker.received_headers)


@pytest.mark.parametrize("method,path,host", [
    ("CONNECT", "/v1/responses", "127.0.0.1:8788"),
    ("POST", "http://127.0.0.1:8788/v1/responses", "127.0.0.1:8788"),
    ("POST", "/v1/chat/completions", "127.0.0.1:8788"),
    ("POST", "/v1/responses", "example.invalid"),
])
def test_fake_boundary_rejects_other_method_path_host_and_absolute_form(method, path, host):
    with pytest.raises(PolicyError):
        validate_broker_request(method, path, {"Host": host}, 0)


def test_harness_errors_on_output_limit_and_failed_process_termination(tmp_path):
    _, _, _, _, service = ready_harness(tmp_path, FakeHarnessRunner(stdout_bytes=PROCESS_OUTPUT_LIMIT_BYTES + 1))
    assert asyncio.run(service.run())["error_code"] == "output_limit"
    _, _, _, _, service = ready_harness(tmp_path / "termination", FakeHarnessRunner(terminate=False))
    assert asyncio.run(service.run())["error_code"] == "process_termination_failed"


def test_harness_total_timeout_is_fail_closed(tmp_path, monkeypatch):
    import app.egress_harness as harness_module
    monkeypatch.setattr(harness_module, "HARNESS_TOTAL_TIMEOUT_SECONDS", 0.001)
    _, _, _, _, service = ready_harness(tmp_path, FakeHarnessRunner(delay_seconds=0.02))
    result = asyncio.run(service.run())
    assert result["status"] == ERROR and result["error_code"] == "harness_timeout"


def test_harness_cleans_private_temp_directory_and_never_stores_raw_data(tmp_path, monkeypatch):
    import app.egress_harness as harness_module
    temporary = tmp_path / "private-temp"
    monkeypatch.setattr(harness_module.tempfile, "mkdtemp", lambda prefix: str(temporary))
    store, _, _, _, service = ready_harness(tmp_path)
    result = asyncio.run(service.run())
    assert result["status"] == PASSED
    assert not temporary.exists()
    serialized = json.dumps({"result": result, "stored": store.egress_harness_result(result["contract_hash"])})
    assert "removed-before-broker" not in serialized
    assert "private-temp" not in serialized
    assert "Authorization" not in serialized and "Cookie" not in serialized


def test_harness_singleflight_reuses_one_fake_execution(tmp_path):
    runner = FakeHarnessRunner(delay_seconds=0.01)
    _, _, _, _, service = ready_harness(tmp_path, runner)

    async def run_twice():
        return await asyncio.gather(service.run(), service.run())

    first, second = asyncio.run(run_twice())
    assert runner.calls == 1
    assert first["status"] == second["status"] == PASSED
    assert {first.get("reused"), second.get("reused")} <= {None, True}


def test_orphan_running_harness_is_recovered_once(tmp_path):
    store, _, contracts, contract, _ = ready_harness(tmp_path)
    running = {
        "harness_id": "11111111-1111-1111-1111-111111111111", "contract_hash": contract["contract_hash"],
        "status": "RUNNING", "started_at": datetime.now(timezone.utc).isoformat(), "finished_at": None,
        "error_code": None, "request_bytes": 0, "response_bytes": 0, "response_hash": None, "status_code": None,
        "relay_connections": 0, "broker_connections": 0, "relay_requests": 0, "broker_requests": 0,
        "local_duration_ms": 0, "resources_cleaned": False, "start_allowed": False,
    }
    store.begin_egress_harness(running)
    assert store.recover_interrupted_egress_harnesses() == 1
    assert store.recover_interrupted_egress_harnesses() == 0
    recovered = store.egress_harness_result(contract["contract_hash"])
    assert recovered["status"] == ERROR and recovered["error_code"] == "harness_interrupted"
    assert contracts.current()["status"] == AUTH_UNCONFIGURED


def test_harness_blocks_when_contract_identity_is_missing_or_default_runner_is_inert(tmp_path):
    store = Store(tmp_path / "missing")
    contracts = SealedEgressContractService(store)
    service = SealedEgressHarnessService(store, contracts, DisabledHarnessRunner())
    assert service.ready()["status"] == HARNESS_BLOCKED
    _, _, _, _, service = ready_harness(tmp_path / "disabled")
    service.runner = DisabledHarnessRunner()
    result = asyncio.run(service.run())
    assert result["status"] == ERROR and result["error_code"] == "fake_runner_required"
