from __future__ import annotations

import asyncio
import base64
import json
import sys

import pytest

from app.codex_process_canary import (
    ERROR,
    PASSED,
    WSLCodexProcessCanaryRunner,
    build_canary_launch_spec,
)
from app.codex_process_executor_wsl import (
    BROKER_CHILD_ARGV_TEMPLATE,
    CODEX_CHILD_FRAME_PREFIX,
    FIXED_REQUEST_BODY_BYTES,
    EXECUTOR_IMPLEMENTATION_HASH,
    RELAY_CODEX_CHILD_CODE,
    RELAY_CODEX_CHILD_ARGV_TEMPLATE,
    RELAY_FRAME_PREFIX,
    RELAY_SPAWN_SUBSTAGES,
    SUPERVISOR_BOOTSTRAP_CODE,
    SUPERVISOR_BOOTSTRAP_MAX_BYTES,
    SUPERVISOR_BOOTSTRAP_PREFIX,
    SUPERVISOR_ARGV_TEMPLATE,
    SUPERVISOR_CODE,
    _SUPERVISOR_SOURCE,
    _SUPERVISOR_BOOTSTRAP_LOGIC,
    WINDOWS_QUOTED_COMMAND_LINE_MAX_BYTES,
    CodexExecutorFailure,
    WSLCodexProcessCanaryExecutor,
    _codex_argv_diagnostic,
    build_sealed_codex_argv,
    build_codex_executor_launch_spec,
    build_codex_supervisor_argv,
    build_supervisor_bootstrap_payload,
    compute_executor_implementation,
    production_executor_factory,
    _fixed_http_request_bytes,
    parse_sealed_loopback_request,
    synthetic_relay_broker_roundtrip,
    encode_supervisor_frame,
    parse_supervisor_frame,
    parse_supervisor_bootstrap_payload,
    windows_quoted_command_line_bytes,
)
from app.egress_contract import LOOPBACK_HOST, LOOPBACK_PORT, SEALED_BASE_URL, SEALED_LOOPBACK_AUTHORITY
from app.isolation_wsl import ProcessResult
from app.policy import PolicyError

from tests.test_codex_canary_one_shot_runner import NoIoSupervisor, arm_pair, one_shot_gate


def running_claim(tmp_path, *, supervisor=None):
    store, service, gate, _ = one_shot_gate(tmp_path, supervisor=supervisor or NoIoSupervisor())
    binding = gate._sealed_binding()
    permit, window = arm_pair(gate)
    claim = store.claim_codex_canary_one_shot_execution(
        permit["permit_nonce"], window["canary_nonce"], binding,
    )
    running = store.begin_codex_canary_execution_claim(claim["execution_claim_id"], binding)
    return store, service.contract_service, binding, running


def test_factory_and_executor_do_not_exist_before_running_claim(tmp_path):
    store, _, gate, created = one_shot_gate(tmp_path)
    permit, window = arm_pair(gate)
    claim = store.claim_codex_canary_one_shot_execution(
        permit["permit_nonce"], window["canary_nonce"], gate._sealed_binding(),
    )
    with pytest.raises(PolicyError, match="not_runnable"):
        WSLCodexProcessCanaryExecutor(store, claim["execution_claim_id"], NoIoSupervisor())
    assert created == {"runner": 0, "executor": 0}


def test_running_claim_builds_fresh_executor_and_allows_one_supervisor_spawn(tmp_path):
    supervisor = NoIoSupervisor()
    store, contracts, binding, claim = running_claim(tmp_path, supervisor=supervisor)
    # The production factory constructs a fresh object but this test never
    # calls it: the injected supervisor below is the no-I/O execution seam.
    factory = production_executor_factory(store)
    first = factory(claim["execution_claim_id"])
    second = factory(claim["execution_claim_id"])
    assert first is not second and supervisor.calls == 0
    executor = WSLCodexProcessCanaryExecutor(store, claim["execution_claim_id"], supervisor)
    result = asyncio.run(executor.run(binding, build_canary_launch_spec(contracts.current())))
    assert result.local_processes == 4
    stored = store.codex_canary_execution_claim_by_id(claim["execution_claim_id"])
    assert stored["spawn_attempted"] == 1 and stored["spawn_count"] == 1 and supervisor.calls == 1
    with pytest.raises(PolicyError, match="not_runnable"):
        WSLCodexProcessCanaryExecutor(store, claim["execution_claim_id"], supervisor)


def test_binding_or_implementation_change_blocks_before_spawn(tmp_path):
    supervisor = NoIoSupervisor()
    store, contracts, binding, claim = running_claim(tmp_path, supervisor=supervisor)
    executor = WSLCodexProcessCanaryExecutor(store, claim["execution_claim_id"], supervisor)
    changed = {**binding, "implementation_hash": "a" * 64}
    with pytest.raises(PolicyError, match="binding"):
        asyncio.run(executor.run(changed, build_canary_launch_spec(contracts.current())))
    assert store.codex_canary_execution_claim_by_id(claim["execution_claim_id"])["spawn_count"] == 0
    assert supervisor.calls == 0


def test_production_runner_rejects_non_executor_factory_before_spawn(tmp_path):
    store, base_service, _, _ = one_shot_gate(tmp_path)
    service = __import__("app.codex_process_canary", fromlist=["SealedOfflineCodexProcessCanary"]).SealedOfflineCodexProcessCanary(
        store, base_service.contract_service, runner_factory=lambda: WSLCodexProcessCanaryRunner(lambda claim_id: object()),
    )
    from app.codex_process_canary import CodexCanaryExecutionPermitGate

    gate = CodexCanaryExecutionPermitGate(store, service)
    permit, window = arm_pair(gate)
    result = asyncio.run(gate.run_one_shot(permit["permit_nonce"], window["canary_nonce"]))
    assert result["status"] == "POLICY_VIOLATION" and result["error_code"] == "actual_runner_policy_violation"
    assert store.codex_canary_execution_claim()["spawn_count"] == 0


def test_launch_spec_and_supervisor_argv_share_one_sealed_source():
    spec = build_codex_executor_launch_spec(
        "/usr/local/bin/codex", runtime_binary_sha256="a" * 64
    )
    sealed = list(build_sealed_codex_argv())
    assert spec["supervisor_argv_template"] == list(SUPERVISOR_ARGV_TEMPLATE)
    assert spec["broker_argv_template"] == list(BROKER_CHILD_ARGV_TEMPLATE)
    assert spec["relay_codex_argv_template"] == list(RELAY_CODEX_CHILD_ARGV_TEMPLATE)
    assert spec["codex_argv"] == sealed
    assert spec["relay_codex"]["argv"] == sealed
    assert spec["broker"]["unshare_all"] is True and spec["relay_codex"]["work_read_only"] is True
    assert spec["relay_codex"]["tmpfs"] == ["/tmp", "/home", "/runtime-state", "/runtime/codex-home"]
    assert spec["relay_codex"]["sealed_config"] == "read_only_source_copy"
    assert spec["runtime_binary_sha256"] == "a" * 64
    assert spec["relay_codex"]["environment"] == {
        "PATH": "/usr/bin:/bin", "HOME": "/home/codex", "TMPDIR": "/tmp", "LANG": "C.UTF-8",
    }
    assert set(spec["forbidden_binds"]) == {"/mnt", "WINDOWS", "SOURCE_ROOT", "DATA_ROOT", "USER_HOME"}
    argv = build_codex_supervisor_argv("wsl.exe")
    assert argv[:5] == ["wsl.exe", "-d", "Ubuntu", "--exec", "/usr/bin/python3"]
    assert argv[-1] == EXECUTOR_IMPLEMENTATION_HASH
    assert SUPERVISOR_CODE.decode("utf-8") not in argv
    assert "00000000-0000-0000-0000-000000000001" not in argv
    assert windows_quoted_command_line_bytes(argv) <= WINDOWS_QUOTED_COMMAND_LINE_MAX_BYTES


def test_supervisor_child_or_argv_change_changes_executor_implementation_hash():
    assert compute_executor_implementation(supervisor_code=b"changed")[0] != EXECUTOR_IMPLEMENTATION_HASH
    assert compute_executor_implementation(broker_child_code=b"changed")[0] != EXECUTOR_IMPLEMENTATION_HASH
    assert compute_executor_implementation(codex_argv=("exec", "--json"))[0] != EXECUTOR_IMPLEMENTATION_HASH
    assert compute_executor_implementation(supervisor_bootstrap_code=b"changed")[0] != EXECUTOR_IMPLEMENTATION_HASH


def test_bootstrap_payload_is_single_canonical_stdin_line_and_never_windows_argv():
    spec = build_codex_executor_launch_spec("/usr/local/bin/codex", runtime_binary_sha256="a" * 64)
    payload = build_supervisor_bootstrap_payload("00000000-0000-0000-0000-000000000001", spec)
    parsed = parse_supervisor_bootstrap_payload(payload)
    assert payload.startswith(SUPERVISOR_BOOTSTRAP_PREFIX.encode("ascii")) and payload.endswith(b"\n")
    assert len(payload) <= SUPERVISOR_BOOTSTRAP_MAX_BYTES
    assert parsed["implementation_hash"] == EXECUTOR_IMPLEMENTATION_HASH
    argv = build_codex_supervisor_argv("wsl.exe")
    assert SUPERVISOR_BOOTSTRAP_CODE.decode("utf-8") in argv
    assert parsed["supervisor_code_b64"] not in argv


def test_bootstrap_failure_frame_is_a_normal_boot_substage_and_exec_namespace_is_sealed():
    assert "except BaseException:" in _SUPERVISOR_BOOTSTRAP_LOGIC
    assert "'__name__':'__main__'" in _SUPERVISOR_BOOTSTRAP_LOGIC
    assert "'__file__':'<sealed-supervisor>'" in _SUPERVISOR_BOOTSTRAP_LOGIC
    assert "'__package__':None" in _SUPERVISOR_BOOTSTRAP_LOGIC
    assert "'__builtins__':builtins" in _SUPERVISOR_BOOTSTRAP_LOGIC
    payload = {
        "status": "ERROR", "stage": "BOOT", "substage": "PAYLOAD_SCHEMA",
        "error_code": "bootstrap_payload_invalid",
        "process_counts": {"supervisor": 1, "broker_bwrap": 0, "relay_codex_bwrap": 0, "codex_cli": 0},
        "cleanup_ok": True, "implementation_hash": EXECUTOR_IMPLEMENTATION_HASH,
        "request_count": 0, "request_hash": None, "response_hash": None, "output_hash": None,
        "sensitive_headers_removed": False,
    }
    frame = parse_supervisor_frame(ProcessResult(exit_code=0, stdout=encode_supervisor_frame(payload), stderr=""))
    assert frame.stage == "BOOT" and frame.substage == "PAYLOAD_SCHEMA"


@pytest.mark.parametrize("mutate", [
    lambda payload: payload[:-1],
    lambda payload: payload + b"x\n",
    lambda payload: payload.replace(b"CODEXGATE_SUPERVISOR_BOOTSTRAP_V1:", b"bad:", 1),
])
def test_bootstrap_payload_rejects_missing_extra_or_wrong_prefix(mutate):
    spec = build_codex_executor_launch_spec("/usr/local/bin/codex")
    payload = build_supervisor_bootstrap_payload("00000000-0000-0000-0000-000000000001", spec)
    with pytest.raises(PolicyError, match="bootstrap_payload_invalid"):
        parse_supervisor_bootstrap_payload(mutate(payload))


def test_codex_argv_builder_is_exact_and_immutable():
    assert build_sealed_codex_argv() == (
        "exec", "--ephemeral", "--skip-git-repo-check", "--sandbox", "read-only",
        "--model", "codexgate-sealed", "-",
    )
    assert isinstance(build_sealed_codex_argv(), tuple)
    assert build_sealed_codex_argv()[-1] == "-"
    assert "--ignore-user-config" not in build_sealed_codex_argv()
    assert "--help" not in build_sealed_codex_argv()
    assert "--version" not in build_sealed_codex_argv()


@pytest.mark.parametrize(
    ("actual", "expected"),
    [
        (("exec", "--ephemeral", "--skip-git-repo-check", "--sandbox"), {"argc": 4, "mismatch_index": 4, "reason_code": "argc_mismatch"}),
        (("exec", "--skip-git-repo-check", "--ephemeral", "--sandbox", "read-only", "--model", "codexgate-sealed", "-"), {"argc": 8, "mismatch_index": 1, "reason_code": "token_mismatch"}),
        (("exec", "--ephemeral", "--skip-git-repo-check", "--sandbox", "read-only", "--model", "codexgate-sealed", "-", "-"), {"argc": 9, "mismatch_index": 8, "reason_code": "argc_mismatch"}),
        (("exec", "--ephemeral", "--ephemeral", "--sandbox", "read-only", "--model", "codexgate-sealed", "-"), {"argc": 8, "mismatch_index": 2, "reason_code": "token_mismatch"}),
    ],
)
def test_codex_argv_diagnostic_rejects_order_missing_extra_and_duplicate_tokens(actual, expected):
    assert _codex_argv_diagnostic(actual) == expected


def test_codex_argv_diagnostic_compares_tokens_not_shell_quoted_strings():
    assert _codex_argv_diagnostic("exec --ephemeral --skip-git-repo-check --sandbox read-only --model codexgate-sealed -") == {
        "argc": 0,
        "mismatch_index": 0,
        "reason_code": "argv_type_invalid",
    }


class TimeoutSupervisor(NoIoSupervisor):
    async def run(self, args, *, payload, timeout_seconds, on_started=None):
        self.calls += 1
        if on_started is not None:
            on_started()
        raise TimeoutError()


class InvalidFrameSupervisor(NoIoSupervisor):
    async def run(self, args, *, payload, timeout_seconds, on_started=None):
        self.calls += 1
        if on_started is not None:
            on_started()
        return ProcessResult(exit_code=0, stdout="invalid\n", stderr="")


@pytest.mark.parametrize("supervisor,error", [
    (TimeoutSupervisor(), "supervisor_transport_timeout"),
    (InvalidFrameSupervisor(), "supervisor_frame_extra_output"),
])
def test_timeout_or_bad_frame_are_fail_closed_with_only_actual_supervisor_count(tmp_path, supervisor, error):
    store, contracts, binding, claim = running_claim(tmp_path, supervisor=supervisor)
    executor = WSLCodexProcessCanaryExecutor(store, claim["execution_claim_id"], supervisor)
    with pytest.raises(CodexExecutorFailure, match=error) as failure:
        asyncio.run(executor.run(binding, build_canary_launch_spec(contracts.current())))
    assert failure.value.local_processes == 1
    stored = store.codex_canary_execution_claim_by_id(claim["execution_claim_id"])
    assert stored["spawn_count"] == 1 and stored["spawn_attempted"] == 1


def test_executor_output_never_contains_private_launch_inputs(tmp_path):
    store, contracts, binding, claim = running_claim(tmp_path)
    executor = WSLCodexProcessCanaryExecutor(store, claim["execution_claim_id"], NoIoSupervisor())
    result = asyncio.run(executor.run(binding, build_canary_launch_spec(contracts.current())))
    assert result.runner_implementation_hash == EXECUTOR_IMPLEMENTATION_HASH
    text = repr(store.codex_canary_execution_claim_by_id(claim["execution_claim_id"]))
    assert "Return exactly" not in text and "CODEXGATE_EPHEMERAL_TOKEN" not in text and "/usr/local/bin/codex" not in text


def test_provider_relay_and_broker_use_the_one_sealed_endpoint():
    from app.codex_process_executor_wsl import BROKER_CHILD_CODE, RELAY_CODEX_CHILD_CODE
    spec = build_codex_executor_launch_spec("/usr/local/bin/codex")
    assert SEALED_BASE_URL == f"http://{LOOPBACK_HOST}:{LOOPBACK_PORT}/v1"
    assert spec["relay_codex"]["endpoint"] == {"host": LOOPBACK_HOST, "port": LOOPBACK_PORT, "path": "/v1/responses"}
    assert SEALED_LOOPBACK_AUTHORITY.encode("ascii") in BROKER_CHILD_CODE
    assert str(LOOPBACK_PORT).encode("ascii") in RELAY_CODEX_CHILD_CODE
    assert b"8789" not in BROKER_CHILD_CODE + RELAY_CODEX_CHILD_CODE


def test_ephemeral_codex_home_prompt_and_token_are_sealed_in_child_spec():
    assert "{CODEX_HOME_SOURCE}" not in RELAY_CODEX_CHILD_ARGV_TEMPLATE
    assert "{SEALED_CONFIG_SOURCE}" in RELAY_CODEX_CHILD_ARGV_TEMPLATE
    assert "--tmpfs" in RELAY_CODEX_CHILD_ARGV_TEMPLATE
    assert "/runtime/codex-home" in RELAY_CODEX_CHILD_ARGV_TEMPLATE
    assert "/runtime/sealed/config.toml" in RELAY_CODEX_CHILD_ARGV_TEMPLATE
    assert "CODEX_HOME" in RELAY_CODEX_CHILD_ARGV_TEMPLATE
    assert b"CODEX_HOME" in RELAY_CODEX_CHILD_CODE
    assert b"PROMPT" in RELAY_CODEX_CHILD_CODE
    assert b"CODEXGATE_EPHEMERAL_TOKEN" in RELAY_CODEX_CHILD_CODE
    assert b"os.urandom(32).hex()" in RELAY_CODEX_CHILD_CODE


def test_relay_child_control_frame_confirms_spawn_only_after_popen_returns():
    from app.codex_process_executor_wsl import CODEX_CHILD_FRAME_PREFIX

    assert "{EXECUTOR_IMPLEMENTATION_HASH}" in RELAY_CODEX_CHILD_ARGV_TEMPLATE
    assert CODEX_CHILD_FRAME_PREFIX.encode("ascii") in RELAY_CODEX_CHILD_CODE
    assert b"spawn_confirmed=False" in RELAY_CODEX_CHILD_CODE
    assert b"spawn_confirmed=True; control_stage='SPAWN_CONFIRMED'" in RELAY_CODEX_CHILD_CODE
    assert b"codex_binary_missing" in RELAY_CODEX_CHILD_CODE
    assert b"codex_permission_denied" in RELAY_CODEX_CHILD_CODE
    assert b"codex_spawn_os_error" in RELAY_CODEX_CHILD_CODE
    assert b"codex_spawned_early_exit" in RELAY_CODEX_CHILD_CODE
    compile(RELAY_CODEX_CHILD_CODE.decode("utf-8"), "sealed-relay-child", "exec")
    assert b"codex.stdin.write(PROMPT); codex.stdin.flush(); codex.stdin.close()" in RELAY_CODEX_CHILD_CODE
    assert b"cli_no_request_exit" in RELAY_CODEX_CHILD_CODE
    assert b"codex_config_provider_invalid" in RELAY_CODEX_CHILD_CODE
    assert b".codexgate-write-probe" in RELAY_CODEX_CHILD_CODE
    assert b"os.fsync(fp.fileno())" in RELAY_CODEX_CHILD_CODE
    assert b"os.fsync(dirfd)" in RELAY_CODEX_CHILD_CODE
    assert b"arg0_init_failed" in RELAY_CODEX_CHILD_CODE


def test_generated_supervisor_parser_imports_re_and_parses_sealed_child_frames_without_io():
    """Execute only generated definitions; never enter the supervisor runtime."""
    source = _SUPERVISOR_SOURCE.split("root=None; broker=None; relay=None;", 1)[0]
    namespace = {"__name__": "__main__", "__file__": "<sealed-supervisor>", "__package__": None}
    original_argv = sys.argv
    sys.argv = ["supervisor", "00000000-0000-4000-8000-000000000000", EXECUTOR_IMPLEMENTATION_HASH, "spec"]
    try:
        exec(compile(source, "<sealed-supervisor>", "exec"), namespace, namespace)
    finally:
        sys.argv = original_argv

    def frame(prefix, payload):
        raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        encoded = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
        return prefix + encoded

    child = frame(CODEX_CHILD_FRAME_PREFIX, {
        "stage": "SPAWN_CONFIRMED", "error_code": None, "spawn_confirmed": True,
        "process_counts": {"codex_cli": 1}, "cleanup_ok": True,
        "implementation_hash": EXECUTOR_IMPLEMENTATION_HASH,
    })
    assert namespace["parse_child_control"]((child + "\n").encode("ascii"))["spawn_confirmed"] is True
    assert namespace["parse_child_control"]((child + "\n").encode("ascii"))["process_counts"] == {"codex_cli": 1}

    common = {
        "error_code": None, "request_hash": "a" * 64, "response_hash": "b" * 64,
        "output_hash": "c" * 64, "sensitive_headers_removed": True,
        "connection_delay_ms": 0, "connection_delay_warning": False,
        "child_stderr_bytes": 0, "child_stderr_sha256": None,
        "child_exit_category": None, "prompt_mode": "STDIN_FORCED",
        "config_loaded_expected": True, "argc": 1,
    }
    ready = {**common, "status": "READY", "substage": "READY_EMIT", "codex_cli": 0, "request_count": 0}
    passed = {**common, "status": "PASSED", "substage": "CODEX_SPAWN", "codex_cli": 1, "request_count": 1}
    parsed = namespace["parse_relay_frame"]((frame(RELAY_FRAME_PREFIX, ready) + "\n" + frame(RELAY_FRAME_PREFIX, passed) + "\n").encode("ascii"))
    assert parsed["status"] == "PASSED" and parsed["codex_cli"] == 1


def test_relay_binds_listens_signals_ready_and_delivers_prompt_before_accept():
    """The Codex client cannot request before it receives the fixed prompt."""
    source = RELAY_CODEX_CHILD_CODE.decode("utf-8")
    bind = source.index("listener.bind((HOST,PORT))")
    listen = source.index("listener.listen(1)")
    ready = source.index("emit('READY','READY_EMIT')")
    spawn = source.index("codex=subprocess.Popen")
    prompt = source.index("codex.stdin.write(PROMPT)")
    accept = source.index("events.put(('ACCEPT',listener.accept()))")
    assert bind < listen < ready < spawn < prompt < accept
    assert "time.sleep" not in source
    assert {"CHILD_START", "ENV_VALIDATE", "SOCKET_VALIDATE", "LOOPBACK_BIND", "LOOPBACK_LISTEN", "READY_EMIT", "CODEX_SPAWN", "LOOPBACK_ACCEPT"} <= RELAY_SPAWN_SUBSTAGES


def test_relay_waits_for_first_endpoint_or_child_exit_event_without_polling():
    source = RELAY_CODEX_CHILD_CODE.decode("utf-8")
    assert "threading.Thread(target=await_accept,daemon=True).start()" in source
    assert "threading.Thread(target=await_exit,daemon=True).start()" in source
    assert "events.get(timeout=DEADLINE)" in source
    assert "codex_spawned_early_exit" in source
    assert "codex_endpoint_not_reached" in source
    assert "while codex.poll()" not in source
    assert "listener.settimeout(None)" in source
    assert "codex.communicate" not in source
    assert "codex.stdout.read(); err=codex.stderr.read()" in source
    assert source.index("broker_stat=os.lstat(broker_socket)") < source.index("emit('READY','READY_EMIT')")


def test_loopback_accept_failure_retains_a_proven_codex_spawn_count():
    result = ProcessResult(
        exit_code=0,
        stdout=encode_supervisor_frame({
            "status": "ERROR", "stage": "RELAY_CODEX_SPAWN", "substage": "LOOPBACK_ACCEPT",
            "error_code": "loopback_accept_timeout",
            "process_counts": {"supervisor": 1, "broker_bwrap": 1, "relay_codex_bwrap": 1, "codex_cli": 1},
            "cleanup_ok": True, "implementation_hash": EXECUTOR_IMPLEMENTATION_HASH,
            "request_count": 0, "request_hash": None, "response_hash": None,
            "output_hash": None, "sensitive_headers_removed": False,
        }),
        stderr="",
    )
    frame = parse_supervisor_frame(result)
    assert frame.substage == "LOOPBACK_ACCEPT"
    assert frame.error_code == "loopback_accept_timeout"
    assert frame.process_counts == {"supervisor": 1, "broker_bwrap": 1, "relay_codex_bwrap": 1, "codex_cli": 1}


def test_synthetic_single_relay_to_broker_roundtrip_strips_sensitive_headers_without_io():
    request = _fixed_http_request_bytes({"Authorization": "redacted", "Cookie": "redacted", "Proxy-Connection": "redacted"})
    parsed = parse_sealed_loopback_request(request)
    proof = synthetic_relay_broker_roundtrip(request)
    assert parsed["clean_headers"] == {
        "Host": SEALED_LOOPBACK_AUTHORITY,
        "Content-Type": "application/json",
        "Content-Length": str(len(FIXED_REQUEST_BODY_BYTES)),
    }
    assert proof["request_count"] == 1 and proof["sensitive_headers_removed"] is True
    with pytest.raises(PolicyError, match="request_policy"):
        synthetic_relay_broker_roundtrip(second_request=True)


def _proof_frame(*, counts=None, request_hash="a" * 64, response_hash="b" * 64, output_hash="c" * 64):
    return ProcessResult(
        exit_code=0,
        stdout=encode_supervisor_frame({
            "status": "PASSED", "stage": "CLEANUP", "substage": None, "error_code": None,
            "process_counts": counts or {"supervisor": 1, "broker_bwrap": 1, "relay_codex_bwrap": 1, "codex_cli": 1},
            "cleanup_ok": True, "implementation_hash": EXECUTOR_IMPLEMENTATION_HASH,
            "request_count": 1, "request_hash": request_hash, "response_hash": response_hash,
            "output_hash": output_hash, "sensitive_headers_removed": True,
        }), stderr="",
    )


@pytest.mark.parametrize("counts", [
    {"supervisor": 1, "broker_bwrap": 0, "relay_codex_bwrap": 0, "codex_cli": 0},
    {"supervisor": 1, "broker_bwrap": 1, "relay_codex_bwrap": 1, "codex_cli": 0},
])
def test_passed_supervisor_frame_requires_all_observed_children(counts):
    with pytest.raises(CodexExecutorFailure, match="success_proof_invalid"):
        parse_supervisor_frame(_proof_frame(counts=counts))


@pytest.mark.parametrize("field", ["request_hash", "response_hash", "output_hash"])
def test_passed_supervisor_frame_rejects_missing_or_unproven_hashes(field):
    values = {"request_hash": "a" * 64, "response_hash": "b" * 64, "output_hash": "c" * 64}
    values[field] = None
    with pytest.raises(CodexExecutorFailure, match="success_proof_invalid"):
        parse_supervisor_frame(_proof_frame(**values))


def test_supervisor_cleanup_is_not_short_circuited_and_limit_is_fail_closed():
    from app.codex_process_executor_wsl import SUPERVISOR_CODE, SUPERVISOR_OUTPUT_LIMIT_BYTES
    assert b"relay_stopped=stop(relay); broker_stopped=stop(broker)" in SUPERVISOR_CODE
    oversized = ProcessResult(exit_code=0, stdout=b"x" * (SUPERVISOR_OUTPUT_LIMIT_BYTES + 1), stderr=b"")
    with pytest.raises(CodexExecutorFailure, match="output_limit"):
        parse_supervisor_frame(oversized)


def test_relay_spawn_failure_frame_exposes_exact_substage():
    result = ProcessResult(
        exit_code=0,
        stdout=encode_supervisor_frame({
            "status": "ERROR",
            "stage": "RELAY_CODEX_SPAWN",
            "substage": "RUNTIME_BIND_VALIDATE",
            "error_code": "runtime_bind_missing",
            "process_counts": {"supervisor": 1, "broker_bwrap": 1, "relay_codex_bwrap": 0, "codex_cli": 0},
            "cleanup_ok": True,
            "implementation_hash": EXECUTOR_IMPLEMENTATION_HASH,
            "request_count": 0,
            "request_hash": None,
            "response_hash": None,
            "output_hash": None,
            "sensitive_headers_removed": False,
        }),
        stderr="",
    )
    frame = parse_supervisor_frame(result)
    assert frame.stage == "RELAY_CODEX_SPAWN"
    assert frame.substage == "RUNTIME_BIND_VALIDATE"
    assert frame.error_code == "runtime_bind_missing"
