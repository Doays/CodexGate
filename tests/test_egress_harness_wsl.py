from __future__ import annotations

import asyncio
import base64
import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.egress_broker import deterministic_request_metadata, deterministic_response_metadata
from app.egress_contract import AUTH_UNCONFIGURED, SealedEgressContractService, expected_repro_key
from app.egress_harness import ERROR, PASSED, POLICY_VIOLATION, SealedEgressHarnessService
from app.egress_harness_wsl import (
    BROKER_CHILD_ARGV_TEMPLATE,
    BROKER_CHILD_CODE,
    PROCESS_OUTPUT_LIMIT_BYTES,
    RELAY_CHILD_ARGV_TEMPLATE,
    RELAY_CHILD_CODE,
    RUNNER_IMPLEMENTATION_HASH,
    SUPERVISOR_CODE,
    SUPERVISOR_FRAME_PREFIX,
    WSL_EGRESS_RUNNER_VERSION,
    WSLEgressHarnessRunner,
    build_wsl_broker_launch_spec,
    build_wsl_relay_client_launch_spec,
    build_wsl_supervisor_argv,
    compute_runner_implementation,
    validate_role_socket_boundaries,
)
from app.isolation_wsl import ProcessResult, SAFE_CANDIDATE
from app.isolation_repro import REPRO_RUNS, SAFE_REPRODUCIBLE
from app.policy import PolicyError, canonical_json
from app.storage import Store
from app.wsl_codex_runtime import EGRESS_UNCONFIGURED, EXPECTED_CODEX_VERSION, WSLCodexRuntime


class FakeRuntimeRunner:
    def find_wsl(self) -> str:
        return "wsl.exe"

    async def run(self, args: list[str], *, timeout_seconds: float) -> ProcessResult:
        return ProcessResult(
            exit_code=0,
            stdout=json.dumps({"status": "OK", "sha256": "a" * 64, "version": EXPECTED_CODEX_VERSION,
                               "size": 42, "mtime_ns": 7, "error": None}, sort_keys=True, separators=(",", ":")) + "\n",
            stderr="",
        )


def valid_payload(**changes):
    payload = {
        "schema_version": "1", "status": "PASSED",
        "runner_implementation_hash": RUNNER_IMPLEMENTATION_HASH,
        **deterministic_request_metadata(), **deterministic_response_metadata(),
        "relay_connections": 1, "broker_connections": 1, "relay_requests": 1, "broker_requests": 1,
        "sensitive_headers_removed": True,
        "broker_sockets": {"pathname_af_unix": 1, "inet_attempts": 0, "udp_attempts": 0, "dns_attempts": 0},
        "relay_sockets": {
            "af_unix_connections": 1, "loopback_tcp_listeners": 1, "loopback_tcp_connections": 1,
            "non_loopback_attempts": 0, "udp_attempts": 0, "dns_attempts": 0,
        },
        "child_processes": 2, "resources_cleaned": True, "children_terminated": True,
    }
    payload.update(changes)
    return payload


def framed(payload: dict, *, stderr: bytes = b"") -> ProcessResult:
    raw = canonical_json(payload).encode("utf-8")
    line = SUPERVISOR_FRAME_PREFIX + base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") + "\n"
    return ProcessResult(exit_code=0, stdout=line, stderr=stderr.decode("utf-8", "replace"),
                         stdout_bytes=line.encode("ascii"), stderr_bytes=stderr)


class FakeSupervisor:
    def __init__(self, result: ProcessResult | None = None, *, delay: float = 0.0):
        self.result = result or framed(valid_payload())
        self.delay = delay
        self.calls: list[list[str]] = []

    def find_wsl(self) -> str:
        return "wsl.exe"

    async def run(self, args: list[str], *, timeout_seconds: float) -> ProcessResult:
        self.calls.append(args)
        if self.delay:
            await asyncio.sleep(self.delay)
        return self.result


def ready(tmp_path, supervisor: FakeSupervisor | None = None):
    store = Store(tmp_path / "data")
    now = datetime.now(timezone.utc)
    store.save_wsl_isolation_config("Ubuntu")
    store.save_wsl_isolation_result({
        "backend": "WSL2_BWRAP", "distro": "Ubuntu", "status": SAFE_CANDIDATE,
        "checked_at": now.isoformat(), "expires_at": (now + timedelta(minutes=30)).isoformat(),
        "config_hash": "f" * 64, "tool_fingerprint": "b" * 64, "cache_key": "c" * 64,
        "probe_version": "wsl2-bwrap-v1", "tool_versions": {"wsl2": True, "bwrap_present": True},
    })
    repro_key = expected_repro_key("f" * 64, "b" * 64)
    store.save_wsl_isolation_repro({
        "repro_id": str(uuid.uuid4()), "cache_key": repro_key,
        "config_hash": "f" * 64, "tool_fingerprint": "b" * 64,
        "status": SAFE_REPRODUCIBLE, "requested_runs": REPRO_RUNS,
        "completed_runs": REPRO_RUNS, "success_count": REPRO_RUNS,
        "result_hash": "d" * 64, "duration_ms": 1,
        "started_at": now.isoformat(), "finished_at": now.isoformat(),
        "error_code": None,
    })
    store.save_wsl_codex_runtime_config("/usr/local/bin/codex")
    assert asyncio.run(WSLCodexRuntime(store, FakeRuntimeRunner()).preflight())["status"] == EGRESS_UNCONFIGURED
    contracts = SealedEgressContractService(store, proof_required=True)
    contract = contracts.create()
    assert contract["status"] == AUTH_UNCONFIGURED
    supervisor = supervisor or FakeSupervisor()
    runner = WSLEgressHarnessRunner(store, supervisor)
    return store, contracts, contract, supervisor, SealedEgressHarnessService(store, contracts, runner)


def test_preview_only_is_blocked_before_any_wsl_supervisor_is_called(tmp_path):
    store, _, contract, supervisor, service = ready(tmp_path)
    # A copy that resembles a preview but is not the immutable SQLite instance
    # cannot cross the runner boundary.
    with pytest.raises(PolicyError, match="stored_contract_required"):
        asyncio.run(WSLEgressHarnessRunner(store, supervisor).run({"contract_hash": contract["contract_hash"]}, {}))
    assert supervisor.calls == []
    assert service.ready()["status"] == "READY"


def test_two_bwrap_specs_have_separate_read_only_boundaries(tmp_path):
    _, _, contract, _, _ = ready(tmp_path)
    broker = build_wsl_broker_launch_spec(contract)
    relay = build_wsl_relay_client_launch_spec(contract)
    for spec in (broker, relay):
        serialized = json.dumps(spec, sort_keys=True)
        assert spec["clearenv"] is True and "--unshare-all" in spec["argv"] and "--share-net" not in spec["argv"]
        assert set(spec["environment"]) == {"PATH", "HOME", "TMPDIR", "LANG"}
        assert "/mnt" not in serialized and "DATA_ROOT" not in serialized and "Source Root" not in serialized
    assert broker["allowed_socket_families"] == ["AF_UNIX_PATHNAME"]
    assert broker["socket_directory_bind"]["mode"] == "rw"
    assert relay["socket_directory_bind"]["mode"] == relay["fixture_bind"]["mode"] == "ro"
    assert relay["loopback_listener"] == {"host": "127.0.0.1", "port": 8788}
    assert broker["argv_template"] == list(BROKER_CHILD_ARGV_TEMPLATE)
    assert relay["argv_template"] == list(RELAY_CHILD_ARGV_TEMPLATE)
    assert broker["argv"][-2:] == ["-c", BROKER_CHILD_CODE]
    assert relay["argv"][-2:] == ["-c", RELAY_CHILD_CODE]


def test_supervisor_and_launch_specs_share_exact_argv_templates():
    argv = build_wsl_supervisor_argv("wsl.exe", "Ubuntu")
    assert argv[-3:] == ["-c", SUPERVISOR_CODE.decode("utf-8"), RUNNER_IMPLEMENTATION_HASH]
    source = SUPERVISOR_CODE.decode("utf-8")
    assert json.dumps(list(BROKER_CHILD_ARGV_TEMPLATE), separators=(",", ":")) in source
    assert json.dumps(list(RELAY_CHILD_ARGV_TEMPLATE), separators=(",", ":")) in source


def test_child_code_or_argv_byte_change_changes_implementation_hash():
    assert compute_runner_implementation(supervisor_code=SUPERVISOR_CODE + b" ")[0] != RUNNER_IMPLEMENTATION_HASH
    assert compute_runner_implementation(broker_child_code=BROKER_CHILD_CODE + " ")[0] != RUNNER_IMPLEMENTATION_HASH
    assert compute_runner_implementation(relay_child_code=RELAY_CHILD_CODE + "\n")[0] != RUNNER_IMPLEMENTATION_HASH
    changed = list(BROKER_CHILD_ARGV_TEMPLATE)
    changed[-2] = "-m"
    assert compute_runner_implementation(broker_argv=changed)[0] != RUNNER_IMPLEMENTATION_HASH
    assert WSL_EGRESS_RUNNER_VERSION.endswith(RUNNER_IMPLEMENTATION_HASH[:16])


def test_fixed_supervisor_has_no_shell_or_user_supplied_command_surface():
    source = SUPERVISOR_CODE.decode("utf-8")
    assert "subprocess.Popen" in source and "--unshare-all" in source and "--clearenv" in source
    assert "shell=True" not in source and "bash -c" not in source and "sh -c" not in source
    assert "HTTP_PROXY" not in source and "HTTPS_PROXY" not in source and "--share-net" not in source


def test_fake_supervisor_passes_stored_contract_with_deterministic_hashes(tmp_path):
    store, contracts, contract, supervisor, service = ready(tmp_path)
    result = asyncio.run(service.run())
    assert result["status"] == PASSED
    assert result["response_hash"] == deterministic_response_metadata()["response_hash"]
    stored = store.egress_harness_result(contract["contract_hash"])
    assert stored["request_hash"] == deterministic_request_metadata()["request_hash"]
    assert stored["runner_kind"] == "WSL_SUPERVISOR" and stored["local_processes"] == 3
    assert stored["runner_implementation_hash"] == RUNNER_IMPLEMENTATION_HASH
    assert len(supervisor.calls) == 1 and supervisor.calls[0][1:5] == ["-d", "Ubuntu", "--exec", "/usr/bin/python3"]
    assert contracts.current()["status"] == AUTH_UNCONFIGURED


def test_runtime_or_isolation_binding_drift_blocks_before_supervisor(tmp_path):
    store, _, contract, supervisor, _ = ready(tmp_path)
    current = store.wsl_isolation_result()
    assert current is not None
    store.save_wsl_isolation_result({**current, "cache_key": "d" * 64})
    runner = WSLEgressHarnessRunner(store, supervisor)
    with pytest.raises(PolicyError, match="contract_binding_changed"):
        asyncio.run(runner.run(contract, {}))
    assert supervisor.calls == []


@pytest.mark.parametrize("changes", [
    {"relay_connections": 2}, {"broker_requests": 2},
    {"relay_sockets": {
        "af_unix_connections": 1, "loopback_tcp_listeners": 1, "loopback_tcp_connections": 1,
        "non_loopback_attempts": 1, "udp_attempts": 0, "dns_attempts": 0,
    }},
    {"sensitive_headers_removed": False}, {"status": "POLICY_VIOLATION"},
])
def test_second_connection_sensitive_headers_or_network_socket_are_fail_closed(tmp_path, changes):
    _, _, _, _, service = ready(tmp_path, FakeSupervisor(framed(valid_payload(**changes))))
    result = asyncio.run(service.run())
    assert result["status"] in {ERROR, POLICY_VIOLATION}


def test_broker_and_relay_socket_policies_are_role_specific():
    broker = valid_payload()["broker_sockets"]
    relay = valid_payload()["relay_sockets"]
    validate_role_socket_boundaries(broker, relay)
    # A real relay uses loopback TCP; it must not be misreported or rejected as tcp=0.
    assert relay["loopback_tcp_listeners"] == relay["loopback_tcp_connections"] == 1
    for field in ("inet_attempts", "udp_attempts", "dns_attempts"):
        changed = dict(broker)
        changed[field] = 1
        with pytest.raises(PolicyError, match="broker_socket_policy_violation"):
            validate_role_socket_boundaries(changed, relay)
    for field in ("non_loopback_attempts", "udp_attempts", "dns_attempts"):
        changed = dict(relay)
        changed[field] = 1
        with pytest.raises(PolicyError, match="relay_socket_policy_violation"):
            validate_role_socket_boundaries(broker, changed)


def test_frame_implementation_hash_mismatch_is_policy_violation(tmp_path):
    _, _, _, _, service = ready(
        tmp_path,
        FakeSupervisor(framed(valid_payload(runner_implementation_hash="e" * 64))),
    )
    result = asyncio.run(service.run())
    assert result["status"] == POLICY_VIOLATION
    assert result["error_code"] == "runner_implementation_mismatch"


@pytest.mark.parametrize("result,code", [
    (ProcessResult(exit_code=1, stdout="", stderr=""), "supervisor_process_error"),
    (ProcessResult(exit_code=0, stdout="x\n", stderr=""), "supervisor_frame_missing"),
    (framed(valid_payload(), stderr=b"x" * (PROCESS_OUTPUT_LIMIT_BYTES + 1)), "output_limit"),
    (framed(valid_payload(children_terminated=False)), "process_termination_failed"),
    (framed(valid_payload(resources_cleaned=False)), "resource_cleanup_failed"),
])
def test_output_process_and_resource_failures_are_sanitized(tmp_path, result, code):
    _, _, _, _, service = ready(tmp_path, FakeSupervisor(result))
    outcome = asyncio.run(service.run())
    assert outcome["status"] == ERROR and outcome["error_code"] == code


def test_supervisor_singleflight_and_orphan_recovery(tmp_path):
    supervisor = FakeSupervisor(delay=0.01)
    store, _, contract, _, service = ready(tmp_path, supervisor)

    async def twice():
        return await asyncio.gather(service.run(), service.run())

    first, second = asyncio.run(twice())
    assert first["status"] == second["status"] == PASSED and len(supervisor.calls) == 1
    # The existing DB recovery routine is deterministic and does not alter a
    # completed stored-contract result.
    assert store.recover_interrupted_egress_harnesses() == 0
    assert store.egress_harness_result(contract["contract_hash"])["status"] == PASSED


def test_result_and_ledger_never_store_raw_frame_body_or_path(tmp_path):
    store, _, contract, _, service = ready(tmp_path)
    result = asyncio.run(service.run())
    text = json.dumps({"result": result, "stored": store.egress_harness_result(contract["contract_hash"]),
                       "ledger": store.token_ledger_report()})
    assert "sealed-harness" not in text and "CODEXGATE_EGRESS_HARNESS" not in text
    assert "/runtime/broker" not in text and "Authorization" not in text
    ledger = store.token_ledger_report()["sealed_egress_harness"]
    assert ledger["tokens"] == ledger["app_server_rpc_calls"] == 0
