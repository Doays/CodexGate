from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import random
import re
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
    CODEX_CHILD_CONTROL_SCHEMA,
    CODEX_CHILD_CONTROL_SCHEMA_VERSION,
    CODEX_TURN_COMPLETED_USAGE_FIELDS,
    FIXED_REQUEST_BODY_BYTES,
    EXECUTOR_COMPONENT_HASHES,
    EXECUTOR_IMPLEMENTATION_HASH,
    EXPECTED_OUTPUT_HASH,
    EXPECTED_REQUEST_HASH,
    EXPECTED_RESPONSE_HASH,
    RELAY_CODEX_CHILD_CODE,
    RELAY_CODEX_CHILD_ARGV_TEMPLATE,
    RELAY_BOOT_FRAME_PREFIX,
    RELAY_FRAME_PREFIX,
    CODEX_CHILD_STAGES,
    CODEX_LAST_MESSAGE_PATH,
    SUCCESS_MARKER,
    RELAY_SPAWN_SUBSTAGES,
    RELAY_COUNTER_FIELDS,
    SEALED_HTTP_RESPONSE_BYTES,
    SEALED_HTTP_RESPONSE_PREFIX,
    SEALED_RESPONSE_BODY_BYTES,
    SUPERVISOR_RELAY_SUBSTAGES,
    SUPERVISOR_BOOTSTRAP_CODE,
    SUPERVISOR_BOOTSTRAP_MAX_BYTES,
    SUPERVISOR_BOOTSTRAP_PREFIX,
    SUPERVISOR_FRAME_ERROR_CODES,
    SUPERVISOR_FRAME_SCHEMA,
    SUPERVISOR_FRAME_SCHEMA_VERSION,
    SUPERVISOR_STAGES,
    SUPERVISOR_ARGV_TEMPLATE,
    SUPERVISOR_CODE,
    _SUPERVISOR_SOURCE,
    _SUPERVISOR_BOOTSTRAP_LOGIC,
    WINDOWS_QUOTED_COMMAND_LINE_MAX_BYTES,
    CodexExecutorFailure,
    WSLCodexProcessCanaryExecutor,
    _codex_argv_diagnostic,
    build_sealed_codex_argv,
    build_sealed_http_response_bytes,
    build_codex_executor_launch_spec,
    build_codex_child_control_payload,
    build_codex_supervisor_argv,
    build_supervisor_frame_payload,
    build_supervisor_bootstrap_payload,
    compute_executor_implementation,
    canonicalize_implementation_input,
    implementation_json_hash,
    production_executor_factory,
    _fixed_http_request_bytes,
    parse_sealed_loopback_request,
    strict_http_reject_diagnostic,
    parse_codex_jsonl,
    parse_codex_child_control_frame,
    synthetic_relay_broker_roundtrip,
    encode_supervisor_frame,
    parse_supervisor_frame,
    parse_supervisor_bootstrap_payload,
    classify_codex_last_message,
    classify_codex_last_message_metadata,
    stdout_marker_diagnostic,
    windows_quoted_command_line_bytes,
)
from app.egress_contract import LOOPBACK_HOST, LOOPBACK_PORT, SEALED_BASE_URL, SEALED_LOOPBACK_AUTHORITY
from app.codex_wire_contract import full_turn_fixture_bytes, responses_parser_fixture_hash
from app.isolation_wsl import ProcessResult
from app.policy import PolicyError

from tests.test_codex_canary_one_shot_runner import NoIoSupervisor, arm_pair, one_shot_gate


def test_strict_http_reject_diagnostic_is_first_failure_and_sanitized():
    raw = _fixed_http_request_bytes()
    accepted = strict_http_reject_diagnostic(raw)
    assert accepted["reason"] is None
    assert accepted["header_count"] >= 2
    assert accepted["body_bytes"] == len(FIXED_REQUEST_BODY_BYTES)
    assert set(accepted) == {"reason", "header_count", "body_bytes", "body_sha256", "json_keyset_hash"}
    bad = raw.replace(b"Host: 127.0.0.1:8788", b"Host: 127.0.0.1:9999", 1)
    rejected = strict_http_reject_diagnostic(bad)
    assert rejected["reason"] == "host"
    assert b"9999" not in json.dumps(rejected, sort_keys=True).encode()


def _mutate_model_request(raw):
    head, sep, body = raw.partition(b"\r\n\r\n")
    body = body.replace(b'"model":"codexgate-sealed"', b'"model":"other"', 1)
    head = re.sub(rb"Content-Length: [0-9]+", b"Content-Length: " + str(len(body)).encode(), head)
    return head + sep + body


@pytest.mark.parametrize("mutation,expected", [
    (lambda raw: raw.replace(b"POST /v1/responses", b"GET /v1/responses", 1), "method"),
    (lambda raw: raw.replace(b"/v1/responses HTTP", b"/v1/other HTTP", 1), "path"),
    (lambda raw: raw.replace(b"Content-Type: application/json", b"Content-Type: text/plain", 1), "content_type"),
    (lambda raw: raw.replace(b"Content-Length: ", b"Content-Length: nope", 1), "content_length"),
    (_mutate_model_request, "model"),
])
def test_strict_http_reject_reason_enum_is_deterministic(mutation, expected):
    result = strict_http_reject_diagnostic(mutation(_fixed_http_request_bytes()))
    assert result["reason"] == expected
    assert set(result) == {"reason", "header_count", "body_bytes", "body_sha256", "json_keyset_hash"}


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
    changed_schema = dict(CODEX_CHILD_CONTROL_SCHEMA)
    changed_schema["version"] = "3"
    assert compute_executor_implementation(
        child_control_schema=changed_schema
    )[0] != EXECUTOR_IMPLEMENTATION_HASH


def test_implementation_hash_is_canonical_for_100_mapping_and_set_orders():
    expected = implementation_json_hash({
        "schema": {
            "fields": frozenset({"alpha", "beta", "gamma", "delta"}),
            "nested": {"first": 1, "second": (2, 3)},
        },
        "ordered": ["left", "right"],
    })
    for seed in range(100):
        rng = random.Random(seed)
        field_values = ["alpha", "beta", "gamma", "delta"]
        rng.shuffle(field_values)
        nested_items = [("first", 1), ("second", (2, 3))]
        rng.shuffle(nested_items)
        root_items = [
            ("schema", {
                "nested": dict(nested_items),
                "fields": set(field_values),
            }),
            ("ordered", ["left", "right"]),
        ]
        rng.shuffle(root_items)
        assert implementation_json_hash(dict(root_items)) == expected
    assert implementation_json_hash({
        "schema": {
            "fields": {"alpha", "beta", "gamma", "changed"},
            "nested": {"first": 1, "second": (2, 3)},
        },
        "ordered": ["left", "right"],
    }) != expected
    assert canonicalize_implementation_input(("left", "right")) == ["left", "right"]


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


def test_host_bootstrap_supervisor_and_relay_use_one_full_implementation_hash():
    spec = build_codex_executor_launch_spec(
        "/usr/local/bin/codex", runtime_binary_sha256="a" * 64,
    )
    bootstrap = parse_supervisor_bootstrap_payload(
        build_supervisor_bootstrap_payload(
            "00000000-0000-0000-0000-000000000001", spec,
        )
    )
    assert spec["executor_implementation_hash"] == EXECUTOR_IMPLEMENTATION_HASH
    assert bootstrap["implementation_hash"] == EXECUTOR_IMPLEMENTATION_HASH
    assert build_codex_supervisor_argv("wsl.exe")[-1] == EXECUTOR_IMPLEMENTATION_HASH
    assert "{EXECUTOR_IMPLEMENTATION_HASH}" in RELAY_CODEX_CHILD_ARGV_TEMPLATE
    assert "implementation=sys.argv[2]" in _SUPERVISOR_SOURCE


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
        "request_hash": None, "response_hash": None, "output_hash": None,
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
        "--model", "codexgate-sealed", "--strict-config", "--json", "--output-last-message", "/tmp/codexgate-final-message", "-",
    )
    assert isinstance(build_sealed_codex_argv(), tuple)
    assert build_sealed_codex_argv()[-1] == "-"
    assert "--ignore-user-config" not in build_sealed_codex_argv()
    assert "--help" not in build_sealed_codex_argv()
    assert "--version" not in build_sealed_codex_argv()


def test_output_last_message_argv_is_sealed_once_and_stdout_is_only_auxiliary():
    argv = build_sealed_codex_argv()
    assert argv.count("--output-last-message") == 1
    assert argv[argv.index("--output-last-message") + 1] == CODEX_LAST_MESSAGE_PATH
    assert stdout_marker_diagnostic((SUCCESS_MARKER + "\r\n").encode())["allowed"] is True
    assert stdout_marker_diagnostic(("prefix" + SUCCESS_MARKER).encode())["allowed"] is False


@pytest.mark.parametrize("value", [SUCCESS_MARKER.encode(), (SUCCESS_MARKER + "\n").encode(), (SUCCESS_MARKER + "\r\n").encode()])
def test_last_message_exact_marker_and_stdout_forms(tmp_path, value):
    path = tmp_path / "codexgate-final-message"
    path.write_bytes(value)
    expected = "ok" if value == SUCCESS_MARKER.encode() else "codex_final_message_mismatch"
    assert classify_codex_last_message(str(path)) == expected


@pytest.mark.parametrize("case", ["missing", "symlink", "oversize", "mismatch"])
def test_last_message_missing_symlink_oversize_and_mismatch_fail_closed(tmp_path, case):
    path = tmp_path / "codexgate-final-message"
    if case == "symlink":
        assert classify_codex_last_message_metadata(True, True, len(SUCCESS_MARKER)) == "codex_final_message_symlink"
        return
    elif case == "oversize":
        path.write_bytes(b"x" * 4097)
    elif case == "mismatch":
        path.write_bytes(b"different")
    expected = {
        "missing": "codex_final_message_missing",
        "oversize": "codex_final_message_oversize",
        "mismatch": "codex_final_message_mismatch",
    }
    assert classify_codex_last_message(str(path)) == expected[case]


@pytest.mark.parametrize(
    ("actual", "expected"),
    [
        (("exec", "--ephemeral", "--skip-git-repo-check", "--sandbox"), {"argc": 4, "mismatch_index": 4, "reason_code": "argc_mismatch"}),
            (("exec", "--skip-git-repo-check", "--ephemeral", "--sandbox", "read-only", "--model", "codexgate-sealed", "--strict-config", "--json", "--output-last-message", "/tmp/codexgate-final-message", "-"), {"argc": 12, "mismatch_index": 1, "reason_code": "token_mismatch"}),
            (("exec", "--ephemeral", "--skip-git-repo-check", "--sandbox", "read-only", "--model", "codexgate-sealed", "--strict-config", "--json", "--output-last-message", "/tmp/codexgate-final-message", "-", "-"), {"argc": 13, "mismatch_index": 12, "reason_code": "argc_mismatch"}),
            (("exec", "--ephemeral", "--ephemeral", "--sandbox", "read-only", "--model", "codexgate-sealed", "--strict-config", "--json", "--output-last-message", "/tmp/codexgate-final-message", "-"), {"argc": 12, "mismatch_index": 2, "reason_code": "token_mismatch"}),
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


def test_codex_home_tmpfs_permissions_and_arg0_hierarchy_are_sealed():
    args = list(RELAY_CODEX_CHILD_ARGV_TEMPLATE)
    perms = args.index("--perms")
    assert args[perms:perms + 3] == ["--perms", "0700", "--tmpfs"]
    assert args[perms + 3] == "/runtime/codex-home"
    assert [args[i - 1:i + 1] for i, value in enumerate(args) if value == "/runtime/codex-home"] == [["--tmpfs", "/runtime/codex-home"], ["CODEX_HOME", "/runtime/codex-home"]]
    source = RELAY_CODEX_CHILD_CODE.decode("utf-8")
    assert "tmp_path=os.path.join(codex_home,'tmp')" in source
    assert "arg0_path=os.path.join(tmp_path,'arg0')" in source
    assert "os.path.exists(os.path.join(codex_home,'arg0'))" in source
    assert "codex_home_mode_invalid" in source
    assert "config_copy_failed" in source
    assert "codex_home_write_probe_failed" in source
    assert "arg0_init_failed" in source


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
    assert b"cli_no_event_exit" in RELAY_CODEX_CHILD_CODE
    assert b"codex_config_provider_invalid" in RELAY_CODEX_CHILD_CODE
    assert b".codexgate-write-probe" in RELAY_CODEX_CHILD_CODE
    assert b"os.fsync(fp.fileno())" in RELAY_CODEX_CHILD_CODE
    assert b"os.fsync(dirfd)" in RELAY_CODEX_CHILD_CODE
    assert b"arg0_init_failed" in RELAY_CODEX_CHILD_CODE


def _decode_sealed_child_frame(line: bytes, prefix: str) -> dict[str, object]:
    encoded = line.decode("ascii")[len(prefix):].strip()
    return json.loads(base64.urlsafe_b64decode(encoded + "=" * ((4 - len(encoded) % 4) % 4)))


def _child_observations(*, events=(), counts=None, exit_code=None, request_seen=0, request_validated=0,
                        response_sent=0, accepted_post=0, marker=False, usage=None,
                        include_response_sha256=True):
    event_types = list(events)
    event_counts = dict(counts or {})
    sequence_hash = hashlib.sha256(
        json.dumps(
            {"event_types": event_types, "event_counts": event_counts},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    observations = {
        "codex_exit_code": exit_code,
        "event_types": event_types,
        "event_counts": event_counts,
        "event_sequence_hash": sequence_hash,
        "tool_event_count": 0,
        "agent_message_count": 1 if marker else 0,
        "output_byte_count": len(SUCCESS_MARKER.encode("utf-8")) if marker else 0,
        "output_sha256": EXPECTED_OUTPUT_HASH if marker else None,
        "stderr_byte_count": 0,
        "stderr_sha256": hashlib.sha256(b"").hexdigest(),
        "stderr_category": None,
        "last_message_exists": marker,
        "last_message_regular": marker,
        "last_message_size": len(SUCCESS_MARKER.encode("utf-8")) if marker else 0,
        "last_message_sha256": EXPECTED_OUTPUT_HASH if marker else None,
        "last_message_match": marker,
        "last_message_marker_match": marker,
        "marker_match": marker,
        "request_seen": request_seen,
        "request_validated": request_validated,
        "response_sent": response_sent,
        "accepted_post": accepted_post,
        "request_hash": EXPECTED_REQUEST_HASH if request_seen else None,
        "sensitive_headers_removed": bool(request_validated),
        "removed_count": 0,
        "post_filter_count": 0,
        "response_byte_count": len(SEALED_RESPONSE_BODY_BYTES) if response_sent else 0,
        "eof_stdout_drained": exit_code is not None,
        "eof_stderr_drained": exit_code is not None,
        "readers_joined": exit_code is not None,
        "usage": usage,
        "strict_http_reject_reason": "host" if request_seen and not request_validated else None,
        "request_header_count": 0,
        "request_body_bytes": 0,
        "request_body_sha256": hashlib.sha256(b"").hexdigest(),
        "request_json_keyset_hash": None,
        "input_shape": None,
    }
    if include_response_sha256:
        observations["response_sha256"] = (
            EXPECTED_RESPONSE_HASH
            if response_sent
            else hashlib.sha256(b"").hexdigest()
        )
    return observations


def _child_control_payload(*, events=(), counts=None, exit_code=0, request_seen=0,
                           request_validated=0, response_sent=0, accepted_post=0,
                           marker=False, error_code="response_proof_invalid", tool_event_count=0):
    if counts and counts.get("turn.completed") and not isinstance(counts.get("turn.completed"), bool):
        usage = {
            "input_tokens": 7, "cached_input_tokens": 2,
            "cache_write_input_tokens": 0, "output_tokens": 3,
            "reasoning_output_tokens": 1,
        }
    else:
        usage = None
    value = {
        "schema_version": CODEX_CHILD_CONTROL_SCHEMA_VERSION,
        "stage": "CHILD_EXIT",
        "error_code": error_code,
        "spawn_confirmed": True,
        "process_counts": {"codex_cli": 1},
        "cleanup_ok": True,
        "implementation_hash": EXECUTOR_IMPLEMENTATION_HASH,
        **_child_observations(
            events=events,
            counts=counts,
            exit_code=exit_code,
            request_seen=request_seen,
            request_validated=request_validated,
            response_sent=response_sent,
            accepted_post=accepted_post,
            marker=marker,
            usage=usage,
        ),
        "stdout_sha256": hashlib.sha256(b"").hexdigest(),
    }
    value["tool_event_count"] = tool_event_count
    return value


def test_generated_relay_child_emits_one_boot_and_one_terminal_frame_on_pre_spawn_failure(monkeypatch):
    """Directly execute the generated child with fake I/O only."""

    writes: list[tuple[int, bytes]] = []

    class FakeListener:
        def setsockopt(self, *_args):
            return None

        def bind(self, *_args):
            return None

        def listen(self, *_args):
            return None

        def close(self):
            return None

        def fileno(self):
            return -1

    import socket

    monkeypatch.delenv("CODEX_HOME", raising=False)
    monkeypatch.setattr(socket, "socket", lambda *_args, **_kwargs: FakeListener())
    monkeypatch.setattr(os, "write", lambda fd, data: writes.append((fd, bytes(data))) or len(data))
    original_argv = sys.argv
    sys.argv = ["sealed-relay", EXECUTOR_IMPLEMENTATION_HASH]
    try:
        with pytest.raises(SystemExit) as exited:
            exec(compile(RELAY_CODEX_CHILD_CODE, "<sealed-relay-child>", "exec"), {"__name__": "__main__"})
    finally:
        sys.argv = original_argv
    assert exited.value.code == 0
    boot = [data for fd, data in writes if fd == 2 and data.startswith(RELAY_BOOT_FRAME_PREFIX.encode("ascii"))]
    relay = [data for fd, data in writes if fd == 2 and data.startswith(RELAY_FRAME_PREFIX.encode("ascii"))]
    terminal = [data for fd, data in writes if fd == 1 and data.startswith(CODEX_CHILD_FRAME_PREFIX.encode("ascii"))]
    assert len(boot) == len(relay) == len(terminal) == 1
    assert _decode_sealed_child_frame(boot[0], RELAY_BOOT_FRAME_PREFIX) == {
        "implementation_hash": EXECUTOR_IMPLEMENTATION_HASH,
        "stage": "CHILD_START",
    }
    payload = _decode_sealed_child_frame(terminal[0], CODEX_CHILD_FRAME_PREFIX)
    assert payload["spawn_confirmed"] is False and payload["process_counts"] == {"codex_cli": 0}
    assert parse_codex_child_control_frame(
        terminal[0], EXECUTOR_IMPLEMENTATION_HASH
    ) == payload
    assert _generated_relay_parser()["parse_child_control"](terminal[0]) == payload


@pytest.mark.parametrize(
    ("stage", "error", "spawn_confirmed", "exit_code", "cleanup_ok"),
    [
        ("SPEC_VALIDATE", "codex_config_missing", False, None, True),
        ("SPAWN_CALL", "codex_spawn_os_error", False, None, True),
        ("CHILD_EXIT", "codex_spawned_early_exit", True, 1, True),
        ("CHILD_EXIT", None, True, 0, True),
        ("CHILD_EXIT", "cleanup_failed", True, 0, False),
    ],
)
def test_generated_relay_terminal_emitter_writes_exactly_once_for_every_terminal_outcome(
    monkeypatch, stage, error, spawn_confirmed, exit_code, cleanup_ok,
):
    writes: list[tuple[int, bytes]] = []
    monkeypatch.setattr(os, "write", lambda fd, data: writes.append((fd, bytes(data))) or len(data))
    source = RELAY_CODEX_CHILD_CODE.decode("utf-8").split("listener=None; codex=None;", 1)[0]
    original_argv = sys.argv
    sys.argv = ["sealed-relay", EXECUTOR_IMPLEMENTATION_HASH]
    namespace = {"__name__": "__main__"}
    try:
        exec(compile(source, "<sealed-relay-definitions>", "exec"), namespace, namespace)
    finally:
        sys.argv = original_argv
    namespace.update({
        "control_stage": stage,
        "control_error": error,
        "spawn_confirmed": spawn_confirmed,
        "codex_exit_code": exit_code,
        "cleanup_ok": cleanup_ok,
        "event_types": [],
        "event_counts": {},
        "event_sequence_hash": hashlib.sha256(
            b'{"event_counts":{},"event_types":[]}'
        ).hexdigest(),
        "tool_event_count": 0,
        "observed_usage": None,
        "codex_stdout_sha256": hashlib.sha256(b"").hexdigest(),
        "stderr_byte_count": 0,
        "stderr_sha256": hashlib.sha256(b"").hexdigest(),
        "stderr_category": None,
        "agent_message_count": 0,
        "output_byte_count": 0,
        "output_sha256": None,
        "last_message_exists": False,
        "last_message_regular": False,
        "last_message_size": 0,
        "last_message_sha256": None,
        "last_message_match": False,
        "last_message_marker_match": False,
        "marker_match": False,
        "request_seen": 0,
        "request_validated": 0,
        "response_sent": 0,
        "accepted_post": 0,
        "response_byte_count": 0,
        "response_sha256": hashlib.sha256(b"").hexdigest(),
        "stdout_eof": exit_code is not None,
        "stderr_eof": exit_code is not None,
        "readers_joined": exit_code is not None,
    })
    namespace["emit_terminal_child_frame"]()
    namespace["emit_terminal_child_frame"]()
    terminal = [data for fd, data in writes if fd == 1 and data.startswith(CODEX_CHILD_FRAME_PREFIX.encode("ascii"))]
    assert len(terminal) == 1
    payload = _decode_sealed_child_frame(terminal[0], CODEX_CHILD_FRAME_PREFIX)
    assert payload["stage"] == stage and payload["error_code"] == error
    assert payload["spawn_confirmed"] is spawn_confirmed
    assert payload["process_counts"] == {"codex_cli": int(spawn_confirmed)}
    assert payload["cleanup_ok"] is cleanup_ok
    assert set(payload) == set(CODEX_CHILD_CONTROL_SCHEMA["fields"])
    parsed_host = parse_codex_child_control_frame(
        terminal[0], EXECUTOR_IMPLEMENTATION_HASH
    )
    parsed_supervisor = _generated_relay_parser()["parse_child_control"](
        terminal[0]
    )
    assert parsed_host == parsed_supervisor == payload

    outer = _supervisor_error_payload(
        substage=stage,
        error_code=error or "supervisor_error",
    )
    outer.update({
        "process_counts": {
            "supervisor": 1,
            "broker_bwrap": 1,
            "relay_codex_bwrap": 1,
            "codex_cli": int(spawn_confirmed),
        },
        "cleanup_ok": cleanup_ok,
        "request_seen": payload["request_seen"],
        "request_validated": payload["request_validated"],
        "response_sent": payload["response_sent"],
        "accepted_post": payload["accepted_post"],
        "response_byte_count": payload["response_byte_count"],
        "response_hash": payload["response_sha256"] if payload["response_sent"] else None,
        "event_types": payload["event_types"],
        "event_counts": payload["event_counts"],
        "event_sequence_hash": payload["event_sequence_hash"],
        "tool_event_count": payload["tool_event_count"],
        "agent_message_count": payload["agent_message_count"],
        "output_byte_count": payload["output_byte_count"],
        "output_sha256": payload["output_sha256"],
        "usage": payload["usage"],
        "last_message_exists": payload["last_message_exists"],
        "last_message_regular": payload["last_message_regular"],
        "last_message_size": payload["last_message_size"],
        "last_message_sha256": payload["last_message_sha256"],
        "last_message_match": payload["last_message_match"],
        "last_message_marker_match": payload["last_message_marker_match"],
        "marker_match": payload["marker_match"],
        "eof_stdout_drained": payload["eof_stdout_drained"],
        "eof_stderr_drained": payload["eof_stderr_drained"],
        "readers_joined": payload["readers_joined"],
        "codex_exit_code": payload["codex_exit_code"],
        "stderr_byte_count": payload["stderr_byte_count"],
        "stderr_sha256": payload["stderr_sha256"],
        "stderr_category": payload["stderr_category"],
        "codex_stdout_sha256": payload["stdout_sha256"],
    })
    parsed_outer = parse_supervisor_frame(
        ProcessResult(
            exit_code=0,
            stdout=encode_supervisor_frame(outer),
            stderr="",
        )
    )
    assert parsed_outer.substage == stage
    assert parsed_outer.codex_processes == int(spawn_confirmed)
    assert parsed_outer.eof_stdout_drained is payload["eof_stdout_drained"]
    assert parsed_outer.eof_stderr_drained is payload["eof_stderr_drained"]
    assert parsed_outer.readers_joined is payload["readers_joined"]
    assert RELAY_CODEX_CHILD_CODE.count(CODEX_CHILD_FRAME_PREFIX.encode("ascii")) == 1


def test_child_control_schema_statically_identifies_the_legacy_terminal_shape():
    current = _child_control_payload(exit_code=0)
    legacy = dict(current)
    legacy["stdout_eof"] = legacy.pop("eof_stdout_drained")
    legacy["stderr_eof"] = legacy.pop("eof_stderr_drained")
    for field in (
        "schema_version", "readers_joined", "stdout_sha256", "usage",
            "response_byte_count", "response_sha256", "input_shape",
    ):
        legacy.pop(field)
    assert set(CODEX_CHILD_CONTROL_SCHEMA["fields"]) - set(legacy) == {
        "schema_version",
            "eof_stdout_drained",
            "eof_stderr_drained",
            "readers_joined",
            "stdout_sha256",
            "usage",
            "response_byte_count",
            "response_sha256",
            "input_shape",
        }
    assert set(legacy) - set(CODEX_CHILD_CONTROL_SCHEMA["fields"]) == {
        "stdout_eof",
        "stderr_eof",
    }
    from app.codex_process_executor_wsl import codex_child_control_schema_diagnostic

    assert codex_child_control_schema_diagnostic(
        legacy, EXECUTOR_IMPLEMENTATION_HASH
    ) == "missing_fields"


def test_child_emitter_and_supervisor_parser_load_the_same_schema_literal(monkeypatch):
    child_namespace, _ = _generated_child_definitions(monkeypatch)
    supervisor_namespace = _generated_relay_parser()
    expected = json.loads(
        json.dumps(CODEX_CHILD_CONTROL_SCHEMA, sort_keys=True)
    )
    assert child_namespace["CHILD_SCHEMA"] == expected
    assert supervisor_namespace["CHILD_SCHEMA"] == expected
    assert (
        child_namespace["CHILD_SCHEMA"]["version"]
        == CODEX_CHILD_CONTROL_SCHEMA_VERSION
        == "2"
    )


@pytest.mark.parametrize(
    ("diagnostic", "mutate"),
    [
        ("missing_fields", lambda value: value.pop("usage")),
        ("extra_fields", lambda value: value.update({"raw_event": "forbidden"})),
        ("bad_type_fields", lambda value: value.update({"readers_joined": 1})),
        ("bad_enum_fields", lambda value: value.update({"stage": "UNKNOWN"})),
        ("hash_mismatch", lambda value: value.update({"implementation_hash": "0" * 64})),
    ],
)
def test_child_control_schema_diagnostics_are_sanitized(diagnostic, mutate):
    from app.codex_process_executor_wsl import codex_child_control_schema_diagnostic

    payload = _child_control_payload(exit_code=0)
    mutate(payload)
    assert codex_child_control_schema_diagnostic(
        payload, EXECUTOR_IMPLEMENTATION_HASH
    ) == diagnostic


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

    child_payload = _child_control_payload(exit_code=0, error_code=None)
    child_payload["stage"] = "SPAWN_CONFIRMED"
    child = frame(CODEX_CHILD_FRAME_PREFIX, child_payload)
    assert namespace["parse_child_control"]((child + "\n").encode("ascii"))["spawn_confirmed"] is True
    assert namespace["parse_child_control"]((child + "\n").encode("ascii"))["process_counts"] == {"codex_cli": 1}
    boot = frame(RELAY_BOOT_FRAME_PREFIX, {
        "stage": "CHILD_START",
        "implementation_hash": EXECUTOR_IMPLEMENTATION_HASH,
    })
    assert namespace["parse_relay_boot"]((boot + "\n").encode("ascii"))["stage"] == "CHILD_START"

    common = {
        "error_code": None, "request_hash": None, "response_hash": None,
            "request_seen": 0, "request_validated": 0, "response_sent": 0, "accepted_post": 0,
            "response_byte_count": 0,
            "codex_stdout_bytes": 0, "codex_stdout_sha256": None, "codex_stdout_terminal_newline": False,
            "output_hash": None, "sensitive_headers_removed": False,
        "connection_delay_ms": 0, "connection_delay_warning": False,
        "stderr_byte_count": 0, "stderr_sha256": hashlib.sha256(b"").hexdigest(),
        "stderr_category": None, "prompt_mode": "STDIN_FORCED",
            "config_loaded_expected": True, "argc": 1,
            **_child_observations(include_response_sha256=False),
    }
    ready = {**common, "status": "READY", "substage": "READY_EMIT", "codex_cli": 0}
    passed = {
        **common, "status": "PASSED", "substage": "CODEX_SPAWN", "codex_cli": 1,
        "request_seen": 1, "request_validated": 1, "response_sent": 1, "accepted_post": 1,
        "request_hash": EXPECTED_REQUEST_HASH, "response_hash": EXPECTED_RESPONSE_HASH,
        "response_byte_count": len(SEALED_RESPONSE_BODY_BYTES),
        "output_hash": EXPECTED_OUTPUT_HASH, "sensitive_headers_removed": True,
    }
    stderr = (boot + "\n" + frame(RELAY_FRAME_PREFIX, ready) + "\n" + frame(RELAY_FRAME_PREFIX, passed) + "\n").encode("ascii")
    parsed = namespace["parse_relay_frame"](stderr)
    assert parsed["status"] == "PASSED" and parsed["codex_cli"] == 1


@pytest.mark.parametrize(
    ("raw", "error"),
    [
        (b"", "relay_boot_missing"),
        (b"CODEXGATE_RELAY_BOOT_V1:bad\nCODEXGATE_RELAY_BOOT_V1:bad\n", "relay_boot_duplicate"),
        (b"CODEXGATE_RELAY_BOOT_V1:bad\n", "relay_boot_invalid"),
    ],
)
def test_generated_supervisor_distinguishes_boot_frame_missing_duplicate_and_invalid(raw, error):
    with pytest.raises(ValueError, match=error):
        _generated_relay_parser()["parse_relay_boot"](raw)


@pytest.mark.parametrize(
    ("control", "expected"),
    [
        (_child_control_payload(), "cli_no_event_exit"),
        (_child_control_payload(events=("thread.started",), counts={"thread.started": 1}), "cli_no_turn"),
        (
            _child_control_payload(
                events=("thread.started", "turn.started"),
                counts={"thread.started": 1, "turn.started": 1},
            ),
            "provider_endpoint_not_reached",
        ),
        (
            _child_control_payload(
                events=("thread.started", "turn.started"),
                counts={"thread.started": 1, "turn.started": 1},
                request_seen=1,
            ),
            "strict_http_rejected",
        ),
        (
            _child_control_payload(
                events=("thread.started", "turn.started"),
                counts={"thread.started": 1, "turn.started": 1},
                request_seen=1,
                request_validated=1,
                accepted_post=1,
            ),
            "fake_response_not_sent",
        ),
        (
            _child_control_payload(
                events=("thread.started", "turn.started"),
                counts={"thread.started": 1, "turn.started": 1},
                request_seen=1,
                request_validated=1,
                response_sent=1,
                accepted_post=1,
            ),
            "response_not_consumed",
        ),
        (
            _child_control_payload(
                events=("thread.started", "turn.started", "item.completed", "turn.completed"),
                counts={"thread.started": 1, "turn.started": 1, "item.completed": 1, "turn.completed": 1},
                request_seen=1,
                request_validated=1,
                response_sent=1,
                accepted_post=1,
                marker=True,
                tool_event_count=1,
            ),
            "tool_event_policy_violation",
        ),
    ],
)
def test_generated_supervisor_classifies_lifecycle_before_generic_response_proof(control, expected):
    namespace = _generated_relay_parser()
    assert namespace["classify_child_lifecycle"](
        control, EXPECTED_RESPONSE_HASH, EXPECTED_OUTPUT_HASH
    ) == expected


def test_completed_lifecycle_succeeds_and_not_consumed_requires_full_response_proof():
    namespace = _generated_relay_parser()
    completed = _child_control_payload(
        events=("thread.started", "turn.started", "item.completed", "turn.completed"),
        counts={
            "thread.started": 1, "turn.started": 1,
            "item.completed": 1, "turn.completed": 1,
        },
        request_seen=1, request_validated=1, response_sent=1,
        accepted_post=1, marker=True, error_code=None,
    )
    assert namespace["classify_child_lifecycle"](
        completed, EXPECTED_RESPONSE_HASH, EXPECTED_OUTPUT_HASH
    ) is None

    incomplete = _child_control_payload(
        events=("thread.started", "turn.started"),
        counts={"thread.started": 1, "turn.started": 1},
        request_seen=1, request_validated=1, response_sent=1,
        accepted_post=1,
    )
    assert namespace["classify_child_lifecycle"](
        incomplete, EXPECTED_RESPONSE_HASH, EXPECTED_OUTPUT_HASH
    ) == "response_not_consumed"
    incomplete["response_sha256"] = "0" * 64
    assert namespace["classify_child_lifecycle"](
        incomplete, EXPECTED_RESPONSE_HASH, EXPECTED_OUTPUT_HASH
    ) == "response_proof_invalid"


def test_child_terminal_observations_round_trip_through_generated_and_host_parsers():
    events = ("thread.started", "turn.started")
    control = _child_control_payload(
        events=events,
        counts={"thread.started": 1, "turn.started": 1},
        request_seen=1,
        error_code="strict_http_rejected",
    )
    raw = json.dumps(control, sort_keys=True, separators=(",", ":")).encode("utf-8")
    encoded = CODEX_CHILD_FRAME_PREFIX + base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") + "\n"
    parsed_control = _generated_relay_parser()["parse_child_control"](encoded.encode("ascii"))
    assert parsed_control == control

    outer = _supervisor_error_payload(
        substage=parsed_control["stage"],
        error_code="strict_http_rejected",
    )
    outer.update({
        "process_counts": {"supervisor": 1, "broker_bwrap": 1, "relay_codex_bwrap": 1, "codex_cli": 1},
        "request_seen": parsed_control["request_seen"],
        "request_validated": parsed_control["request_validated"],
        "response_sent": parsed_control["response_sent"],
        "accepted_post": parsed_control["accepted_post"],
        "response_byte_count": parsed_control["response_byte_count"],
        "response_hash": (
            parsed_control["response_sha256"]
            if parsed_control["response_sent"]
            else None
        ),
        "event_types": parsed_control["event_types"],
        "event_counts": parsed_control["event_counts"],
        "event_sequence_hash": parsed_control["event_sequence_hash"],
        "tool_event_count": parsed_control["tool_event_count"],
        "last_message_exists": parsed_control["last_message_exists"],
        "last_message_regular": parsed_control["last_message_regular"],
        "last_message_size": parsed_control["last_message_size"],
        "last_message_marker_match": parsed_control["last_message_marker_match"],
        "codex_exit_code": parsed_control["codex_exit_code"],
        "stderr_byte_count": parsed_control["stderr_byte_count"],
        "stderr_sha256": parsed_control["stderr_sha256"],
        "stderr_category": parsed_control["stderr_category"],
        "eof_stdout_drained": parsed_control["eof_stdout_drained"],
        "eof_stderr_drained": parsed_control["eof_stderr_drained"],
            "readers_joined": parsed_control["readers_joined"],
            "strict_http_reject_reason": parsed_control["strict_http_reject_reason"],
            "request_header_count": parsed_control["request_header_count"],
            "request_body_bytes": parsed_control["request_body_bytes"],
            "request_body_sha256": parsed_control["request_body_sha256"],
            "request_json_keyset_hash": parsed_control["request_json_keyset_hash"],
        })
    parsed_host = parse_supervisor_frame(
        ProcessResult(exit_code=0, stdout=encode_supervisor_frame(outer), stderr="")
    )
    assert parsed_host.event_types == events
    assert parsed_host.event_counts == {"thread.started": 1, "turn.started": 1}
    assert parsed_host.event_sequence_hash == parsed_control["event_sequence_hash"]
    assert parsed_host.request_seen == 1 and parsed_host.accepted_post == 0
    assert parsed_host.codex_exit_code == 0 and parsed_host.tool_event_count == 0


def test_codex_child_substages_are_a_strict_subset_of_supervisor_relay_substages():
    assert CODEX_CHILD_STAGES <= SUPERVISOR_RELAY_SUBSTAGES


@pytest.mark.parametrize("substage", sorted(CODEX_CHILD_STAGES))
def test_child_substage_round_trips_through_generated_and_host_supervisor_parsers(substage):
    payload = _supervisor_error_payload(substage=substage, error_code="supervisor_error")
    parsed = parse_supervisor_frame(ProcessResult(exit_code=0, stdout=encode_supervisor_frame(payload), stderr=""))
    assert parsed.substage == substage
    assert parsed.process_counts == {"supervisor": 1, "broker_bwrap": 0, "relay_codex_bwrap": 0, "codex_cli": 0}


def _generated_relay_parser():
    source = _SUPERVISOR_SOURCE.split("root=None; broker=None; relay=None;", 1)[0]
    namespace = {"__name__": "__main__", "__file__": "<sealed-supervisor>", "__package__": None}
    original_argv = sys.argv
    sys.argv = ["supervisor", "00000000-0000-4000-8000-000000000000", EXECUTOR_IMPLEMENTATION_HASH, "spec"]
    try:
        exec(compile(source, "<sealed-supervisor>", "exec"), namespace, namespace)
    finally:
        sys.argv = original_argv
    return namespace


def _generated_relay_frame(payload):
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return RELAY_FRAME_PREFIX + base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _generated_relay_payload(*, status="ERROR", substage="LOOPBACK_BIND", error_code="loopback_bind_failed", codex_cli=0, request_count=0):
    return {
        "status": status, "substage": substage, "error_code": error_code,
        "codex_cli": codex_cli,
        "request_seen": 1 if request_count else 0, "request_validated": 1 if request_count else 0,
        "response_sent": 1 if request_count else 0, "accepted_post": 1 if request_count else 0,
        "codex_stdout_bytes": 0, "codex_stdout_sha256": None, "codex_stdout_terminal_newline": False,
        "request_hash": EXPECTED_REQUEST_HASH if request_count else None,
        "response_hash": EXPECTED_RESPONSE_HASH if request_count else None,
        "output_hash": EXPECTED_OUTPUT_HASH if request_count else None,
        "sensitive_headers_removed": bool(request_count), "connection_delay_ms": 0,
        "removed_count": 0, "post_filter_count": 0,
        "connection_delay_warning": False, "stderr_byte_count": 0,
        "stderr_sha256": hashlib.sha256(b"").hexdigest(), "stderr_category": None,
        "prompt_mode": "STDIN_FORCED", "config_loaded_expected": True, "argc": 12,
        **_child_observations(
            exit_code=0 if codex_cli else None,
            request_seen=1 if request_count else 0,
            request_validated=1 if request_count else 0,
            response_sent=1 if request_count else 0,
            accepted_post=1 if request_count else 0,
            marker=bool(request_count),
            include_response_sha256=False,
        ),
    }


@pytest.mark.parametrize("substage", ["LOOPBACK_BIND", "LOOPBACK_LISTEN", "CODEX_HOME_PREPARE", "CONFIG_VALIDATE", "SOCKET_VALIDATE"])
def test_generated_relay_parser_accepts_single_pre_ready_failure_with_relay_error_code(substage):
    parser = _generated_relay_parser()["parse_relay_frame"]
    parsed = parser((_generated_relay_frame(_generated_relay_payload(substage=substage)) + "\n").encode("ascii"))
    assert parsed["status"] == "ERROR" and parsed["substage"] == substage


@pytest.mark.parametrize("payload", [
    _generated_relay_payload(status="READY", substage="READY_EMIT", error_code=None),
    _generated_relay_payload(status="PASSED", substage="CODEX_SPAWN", error_code=None, codex_cli=1, request_count=1),
])
def test_generated_relay_parser_rejects_single_ready_or_passed_frame(payload):
    with pytest.raises(ValueError, match="relay_proof_invalid"):
        _generated_relay_parser()["parse_relay_frame"]((_generated_relay_frame(payload) + "\n").encode("ascii"))


def test_generated_relay_parser_distinguishes_child_control_and_relay_proof_errors():
    namespace = _generated_relay_parser()
    parser = namespace["parse_relay_frame"]
    with pytest.raises(ValueError, match="codex_child_control_missing"):
        namespace["parse_child_control"](b"")
    with pytest.raises(ValueError, match="relay_proof_missing"):
        parser(b"\n")
    ready = _generated_relay_payload(status="READY", substage="READY_EMIT", error_code=None)
    failure = _generated_relay_payload(substage="CODEX_HOME_PREPARE", error_code="codex_home_write_failed")
    passed = _generated_relay_payload(status="PASSED", substage="CODEX_SPAWN", error_code=None, codex_cli=1, request_count=1)
    assert parser((_generated_relay_frame(ready) + "\n" + _generated_relay_frame(failure) + "\n").encode("ascii"))["error_code"] == "codex_home_write_failed"
    assert parser((_generated_relay_frame(ready) + "\n" + _generated_relay_frame(passed) + "\n").encode("ascii"))["status"] == "PASSED"


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
    assert source.index("stdout_reader.start(); stderr_reader.start()") < source.index("codex.stdin.write(PROMPT)")
    assert source.index("reader.join(") < source.index("parse_jsonl(out)")
    assert source.index("collect_codex_observations(timeout=3)") < source.rindex("emit_terminal_child_frame()")
    assert source.index("broker_stat=os.lstat(broker_socket)") < source.index("emit('READY','READY_EMIT')")


def _official_completed_jsonl(*, usage=None, trailing_newline=True):
    completed_usage = {
        "input_tokens": 7,
        "cached_input_tokens": 2,
        "cache_write_input_tokens": 0,
        "output_tokens": 3,
        "reasoning_output_tokens": 1,
    } if usage is None else usage
    events = [
        {"type": "thread.started", "thread_id": "sealed-thread"},
        {"type": "turn.started"},
        {"type": "item.completed", "item": {"type": "reasoning", "text": "discarded"}},
        {"type": "item.completed", "item": {"type": "agent_message", "text": SUCCESS_MARKER}},
        {"type": "turn.completed", "usage": completed_usage},
    ]
    value = b"\n".join(
        json.dumps(event, sort_keys=True, separators=(",", ":")).encode("utf-8")
        for event in events
    )
    return value + (b"\n" if trailing_newline else b"")


def _generated_child_definitions(monkeypatch):
    captured = []
    monkeypatch.setattr(os, "write", lambda fd, data: captured.append((fd, bytes(data))) or len(data))
    source = RELAY_CODEX_CHILD_CODE.decode("utf-8")
    definitions, runtime = source.split("listener=None; codex=None;", 1)
    initialization = "listener=None; codex=None;" + runtime.split("\ntry:\n", 1)[0]
    original_argv = sys.argv
    sys.argv = ["sealed-relay", EXECUTOR_IMPLEMENTATION_HASH]
    namespace = {"__name__": "__main__"}
    try:
        exec(compile(definitions, "<sealed-relay-definitions>", "exec"), namespace, namespace)
        exec(compile(initialization, "<sealed-relay-state>", "exec"), namespace, namespace)
    finally:
        sys.argv = original_argv
    return namespace, captured


def test_generated_stream_reader_reassembles_turn_completed_across_pipe_chunks_at_eof(monkeypatch):
    namespace, _ = _generated_child_definitions(monkeypatch)
    complete = _official_completed_jsonl()
    split = complete.index(b"turn.completed") + 7

    class ChunkPipe:
        def __init__(self):
            self.chunks = [complete[:split], complete[split:split + 5], complete[split + 5:], b""]

        def read(self, _size):
            return self.chunks.pop(0)

        def close(self):
            return None

    namespace["drain_pipe"](ChunkPipe(), "stdout")
    state = namespace["stream_state"]["stdout"]
    assert state["eof"] is True and state["error"] is False
    assert bytes(state["buffer"]) == complete
    assert namespace["parse_jsonl"](bytes(state["buffer"])) is None
    assert namespace["event_counts"]["turn.completed"] == 1


def test_terminal_observation_waits_for_both_reader_joins_and_late_final_line(monkeypatch):
    namespace, captured = _generated_child_definitions(monkeypatch)
    complete = _official_completed_jsonl()
    prefix, final = complete.rsplit(b"\n", 2)[0:2]
    stdout_state = namespace["stream_state"]["stdout"]
    stderr_state = namespace["stream_state"]["stderr"]
    stdout_state["buffer"].extend(prefix + b"\n")
    stdout_state["bytes"] = len(prefix) + 1
    stdout_state["hash"].update(prefix + b"\n")
    order = []

    class Reader:
        def __init__(self, name):
            self.name = name
            self.alive = True

        def join(self, timeout=None):
            order.append(self.name + "_join")
            if self.name == "stdout":
                late = final + b"\n"
                stdout_state["buffer"].extend(late)
                stdout_state["bytes"] += len(late)
                stdout_state["hash"].update(late)
                stdout_state["eof"] = True
            else:
                stderr_state["eof"] = True
            self.alive = False

        def is_alive(self):
            return self.alive

    class Codex:
        returncode = 0

        @staticmethod
        def poll():
            return 0

    original_parse = namespace["parse_jsonl"]

    def parse_after_join(value):
        order.append("parse")
        return original_parse(value)

    namespace.update({
        "codex": Codex(),
        "stdout_reader": Reader("stdout"),
        "stderr_reader": Reader("stderr"),
        "parse_jsonl": parse_after_join,
    })
    assert namespace["collect_codex_observations"](timeout=1) is True
    order.append("terminal")
    namespace["emit_terminal_child_frame"]()
    assert order == ["stdout_join", "stderr_join", "parse", "terminal"]
    assert namespace["stdout_eof"] is namespace["stderr_eof"] is True
    terminal = [data for fd, data in captured if fd == 1 and data.startswith(CODEX_CHILD_FRAME_PREFIX.encode("ascii"))]
    assert len(terminal) == 1
    assert _decode_sealed_child_frame(terminal[0], CODEX_CHILD_FRAME_PREFIX)["event_counts"]["turn.completed"] == 1


def test_official_turn_completed_usage_round_trips_without_retaining_text():
    parsed = parse_codex_jsonl(_official_completed_jsonl())
    assert parsed["event_counts"] == {
        "thread.started": 1,
        "turn.started": 1,
        "item.completed": 2,
        "turn.completed": 1,
    }
    assert parsed["event_types"][-1] == "turn.completed"
    assert set(parsed) == {
        "event_types", "event_counts", "stream_hash", "usage",
        "agent_message_count", "output_byte_count", "output_sha256",
    }
    assert parsed["agent_message_count"] == 1
    assert parsed["output_byte_count"] == len(SUCCESS_MARKER.encode("utf-8"))
    assert parsed["output_sha256"] == EXPECTED_OUTPUT_HASH
    assert SUCCESS_MARKER not in repr(parsed)
    assert parsed["usage"]["input_tokens"] == 7
    assert CODEX_TURN_COMPLETED_USAGE_FIELDS == {
        "input_tokens", "cached_input_tokens", "cache_write_input_tokens",
        "output_tokens", "reasoning_output_tokens",
    }


@pytest.mark.parametrize(
    "usage",
    [
        {
            "input_tokens": True, "cached_input_tokens": 0, "cache_write_input_tokens": 0,
            "output_tokens": 0, "reasoning_output_tokens": 0,
        },
        {
            "input_tokens": 1, "cached_input_tokens": 0, "cache_write_input_tokens": 0,
            "output_tokens": 0,
        },
        {
            "input_tokens": 1, "cached_input_tokens": 0, "cache_write_input_tokens": 0,
            "output_tokens": 0, "reasoning_output_tokens": 0, "extra": 0,
        },
    ],
)
def test_turn_completed_usage_bad_type_missing_and_extra_are_rejected(usage):
    with pytest.raises(PolicyError, match="jsonl_turn_completed_schema_invalid"):
        parse_codex_jsonl(_official_completed_jsonl(usage=usage))


def test_jsonl_final_line_requires_newline_and_terminal_event_is_never_synthesized():
    with pytest.raises(PolicyError, match="jsonl_final_line_incomplete"):
        parse_codex_jsonl(_official_completed_jsonl(trailing_newline=False))
    without_terminal = b"\n".join(_official_completed_jsonl().splitlines()[:-1]) + b"\n"
    with pytest.raises(PolicyError, match="jsonl_terminal_event_missing"):
        parse_codex_jsonl(without_terminal)
    duplicated_terminal = _official_completed_jsonl().splitlines()
    duplicated_terminal.insert(-1, duplicated_terminal[-1])
    with pytest.raises(PolicyError, match="jsonl_turn_completed_schema_invalid"):
        parse_codex_jsonl(b"\n".join(duplicated_terminal) + b"\n")


@pytest.mark.parametrize(
    ("mutation", "error"),
    [
        (
            lambda lines: [
                line.replace(b'"agent_message"', b'"reasoning"', 1)
                if b'"agent_message"' in line else line
                for line in lines
            ],
            "jsonl_agent_message_missing",
        ),
        (
            lambda lines: [*lines[:-1], next(line for line in lines if b'"agent_message"' in line), lines[-1]],
            "jsonl_agent_message_duplicate",
        ),
        (
            lambda lines: [
                line.replace(SUCCESS_MARKER.encode("utf-8"), b"different", 1)
                if b'"agent_message"' in line else line
                for line in lines
            ],
            "jsonl_output_mismatch",
        ),
    ],
)
def test_agent_message_proof_is_exact_and_never_retains_text(mutation, error):
    value = b"\n".join(mutation(_official_completed_jsonl().splitlines())) + b"\n"
    with pytest.raises(PolicyError, match=error):
        parse_codex_jsonl(value)


def test_turn_completed_with_unreached_output_proof_has_a_dedicated_error():
    namespace = _generated_relay_parser()
    control = _child_control_payload(
        events=("thread.started", "turn.started", "item.completed", "turn.completed"),
        counts={
            "thread.started": 1, "turn.started": 1,
            "item.completed": 1, "turn.completed": 1,
        },
        request_seen=1, request_validated=1, response_sent=1,
        accepted_post=1, marker=False,
    )
    assert namespace["classify_child_lifecycle"](
        control, EXPECTED_RESPONSE_HASH, EXPECTED_OUTPUT_HASH
    ) == "output_proof_field_missing"


def test_jsonl_and_last_message_hash_disagreement_is_fail_closed():
    namespace = _generated_relay_parser()
    control = _child_control_payload(
        events=("thread.started", "turn.started", "item.completed", "turn.completed"),
        counts={
            "thread.started": 1, "turn.started": 1,
            "item.completed": 1, "turn.completed": 1,
        },
        request_seen=1, request_validated=1, response_sent=1,
        accepted_post=1, marker=True, error_code="jsonl_output_mismatch",
    )
    control["last_message_sha256"] = "0" * 64
    control["marker_match"] = False
    raw = json.dumps(control, sort_keys=True, separators=(",", ":")).encode("utf-8")
    frame = CODEX_CHILD_FRAME_PREFIX.encode("ascii") + base64.urlsafe_b64encode(raw).rstrip(b"=") + b"\n"
    assert parse_codex_child_control_frame(frame, EXECUTOR_IMPLEMENTATION_HASH) == control
    assert namespace["classify_child_lifecycle"](
        control, EXPECTED_RESPONSE_HASH, EXPECTED_OUTPUT_HASH
    ) == "jsonl_output_mismatch"


def test_output_proof_is_sealed_before_last_message_cleanup():
    source = RELAY_CODEX_CHILD_CODE.decode("utf-8")
    assert source.index("parse_jsonl(out)") < source.index("message_stat=os.lstat(LAST_MESSAGE)")
    assert source.index("message_stat=os.lstat(LAST_MESSAGE)") < source.rindex("try: seal_terminal_child_proof()")
    assert source.rindex("try: seal_terminal_child_proof()") < source.rindex("try: os.unlink(LAST_MESSAGE)")
    assert source.rindex("try: os.unlink(LAST_MESSAGE)") < source.rindex("emit_terminal_child_frame()")


def test_last_message_match_does_not_replace_missing_turn_completed():
    namespace = _generated_relay_parser()
    control = _child_control_payload(
        events=("thread.started", "turn.started", "item.completed"),
        counts={"thread.started": 1, "turn.started": 1, "item.completed": 1},
        request_seen=1,
        request_validated=1,
        response_sent=1,
        accepted_post=1,
        marker=True,
        error_code="jsonl_terminal_event_missing",
    )
    assert namespace["classify_child_lifecycle"](
        control, EXPECTED_RESPONSE_HASH, EXPECTED_OUTPUT_HASH
    ) == "response_not_consumed"


def test_loopback_accept_failure_retains_a_proven_codex_spawn_count():
    result = ProcessResult(
        exit_code=0,
        stdout=encode_supervisor_frame({
            "status": "ERROR", "stage": "RELAY_CODEX_SPAWN", "substage": "LOOPBACK_ACCEPT",
            "error_code": "loopback_accept_timeout",
            "process_counts": {"supervisor": 1, "broker_bwrap": 1, "relay_codex_bwrap": 1, "codex_cli": 1},
            "cleanup_ok": True, "implementation_hash": EXECUTOR_IMPLEMENTATION_HASH,
            "request_hash": None, "response_hash": None,
            "output_hash": None, "sensitive_headers_removed": False,
        }),
        stderr="",
    )
    frame = parse_supervisor_frame(result)
    assert frame.substage == "LOOPBACK_ACCEPT"
    assert frame.error_code == "loopback_accept_timeout"
    assert frame.process_counts == {"supervisor": 1, "broker_bwrap": 1, "relay_codex_bwrap": 1, "codex_cli": 1}


def _raw_supervisor_frame(payload):
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "CODEXGATE_CODEX_SUPERVISOR_V1:" + base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") + "\n"


def _supervisor_error_payload(*, stage="RELAY_CODEX_SPAWN", substage="CODEX_HOME_PREPARE", error_code="codex_home_mode_invalid"):
    return {
        "schema_version": SUPERVISOR_FRAME_SCHEMA_VERSION,
        "status": "ERROR", "stage": stage, "substage": substage, "error_code": error_code,
        "process_counts": {"supervisor": 1, "broker_bwrap": 0, "relay_codex_bwrap": 0, "codex_cli": 0},
        "cleanup_ok": True, "implementation_hash": EXECUTOR_IMPLEMENTATION_HASH,
        "request_hash": None, "response_hash": None, "response_byte_count": 0,
        "output_hash": None,
        "request_seen": 0, "request_validated": 0, "response_sent": 0, "accepted_post": 0,
        "codex_stdout_bytes": 0, "codex_stdout_sha256": None, "codex_stdout_terminal_newline": False,
        "child_schema_diagnostic": None,
        "sensitive_headers_removed": False, "connection_delay_ms": 0, "connection_delay_warning": False,
        "stderr_byte_count": 0, "stderr_sha256": hashlib.sha256(b"").hexdigest(), "stderr_category": None,
        "prompt_mode": "STDIN_FORCED", "config_loaded_expected": True, "argc": 12,
        **_child_observations(include_response_sha256=False),
    }


def test_supervisor_frame_builder_parser_round_trip_uses_one_schema_source():
    payload = _supervisor_error_payload()
    encoded = encode_supervisor_frame(payload)
    parsed = parse_supervisor_frame(ProcessResult(exit_code=0, stdout=encoded, stderr=""))
    assert parsed.status == "ERROR"
    assert parsed.error_code == "codex_home_mode_invalid"
    assert SUPERVISOR_FRAME_SCHEMA["version"] == SUPERVISOR_FRAME_SCHEMA_VERSION == "2"
    assert "schema_version" in _SUPERVISOR_SOURCE
    assert "payload['schema_version']=FRAME_SCHEMA_VERSION" in _SUPERVISOR_SOURCE


def test_generated_supervisor_emitter_round_trips_through_host_parser(monkeypatch):
    source = _SUPERVISOR_SOURCE.split("root=None; broker=None; relay=None;", 1)[0]
    namespace = {"__name__": "__main__", "__file__": "<sealed-supervisor>", "__package__": None}
    original_argv = sys.argv
    captured = []
    sys.argv = ["supervisor", "00000000-0000-4000-8000-000000000000", EXECUTOR_IMPLEMENTATION_HASH, "spec"]
    monkeypatch.setattr(os, "write", lambda fd, data: captured.append(data) or len(data))
    try:
        exec(compile(source, "<sealed-supervisor>", "exec"), namespace, namespace)
        namespace["emit"]("ERROR", "RELAY_CODEX_SPAWN", "relay_child_error", True, "CODEX_SPAWN")
    finally:
        sys.argv = original_argv
    assert len(captured) == 1
    parsed = parse_supervisor_frame(ProcessResult(exit_code=0, stdout=captured[0], stderr=""))
    assert parsed.stage == "RELAY_CODEX_SPAWN" and parsed.substage == "CODEX_SPAWN"
    assert parsed.error_code == "relay_child_error"


def test_generated_bootstrap_failure_frame_round_trips_through_host_parser(monkeypatch):
    class _Input:
        class _Buffer:
            @staticmethod
            def read(_limit):
                return b"invalid\n"
        buffer = _Buffer()

    captured = []
    original_argv = sys.argv
    monkeypatch.setattr(os, "write", lambda fd, data: captured.append(data) or len(data))
    monkeypatch.setattr(sys, "stdin", _Input())
    sys.argv = ["", EXECUTOR_IMPLEMENTATION_HASH]
    try:
        exec(compile(_SUPERVISOR_BOOTSTRAP_LOGIC, "<sealed-bootstrap>", "exec"), {"__name__": "__main__"}, None)
    finally:
        sys.argv = original_argv
    assert len(captured) == 1
    parsed = parse_supervisor_frame(ProcessResult(exit_code=0, stdout=captured[0], stderr=""))
    assert parsed.stage == "BOOT" and parsed.substage == "STDIN_READ"
    assert parsed.error_code == "bootstrap_payload_invalid"


@pytest.mark.parametrize("stage", ["BOOT", "CLAIM_VALIDATE", "SPEC_VALIDATE", "RUNTIME_VALIDATE", "BROKER_SPAWN"])
def test_pre_bwrap_failure_frames_round_trip_with_exact_process_counts(stage):
    substage = "STDIN_READ" if stage == "BOOT" else None
    payload = _supervisor_error_payload(stage=stage, substage=substage, error_code="supervisor_error")
    parsed = parse_supervisor_frame(ProcessResult(exit_code=0, stdout=encode_supervisor_frame(payload), stderr=""))
    assert parsed.process_counts == {"supervisor": 1, "broker_bwrap": 0, "relay_codex_bwrap": 0, "codex_cli": 0}


@pytest.mark.parametrize("error_code", [
    "codex_home_mode_invalid", "config_copy_failed", "codex_home_write_probe_failed", "arg0_init_failed",
])
def test_supervisor_frame_new_codex_home_errors_round_trip(error_code):
    payload = _supervisor_error_payload(error_code=error_code)
    parsed = parse_supervisor_frame(ProcessResult(exit_code=0, stdout=encode_supervisor_frame(payload), stderr=""))
    assert parsed.error_code == error_code
    assert error_code in SUPERVISOR_FRAME_ERROR_CODES


@pytest.mark.parametrize("stage", sorted(SUPERVISOR_STAGES))
def test_supervisor_frame_stage_error_schema_round_trip(stage):
    substage = "CODEX_HOME_PREPARE" if stage == "RELAY_CODEX_SPAWN" else None
    payload = _supervisor_error_payload(stage=stage, substage=substage, error_code="supervisor_error")
    parsed = parse_supervisor_frame(ProcessResult(exit_code=0, stdout=encode_supervisor_frame(payload), stderr=""))
    assert parsed.stage == stage and parsed.error_code == "supervisor_error"


@pytest.mark.parametrize(("diagnostic", "mutate"), [
    ("missing_fields", lambda value: value.pop("error_code")),
    ("extra_fields", lambda value: value.update({"unexpected": True})),
    ("bad_type_fields", lambda value: value.update({"cleanup_ok": "true"})),
    ("bad_enum_fields", lambda value: value.update({"status": "UNKNOWN"})),
    ("hash_mismatch", lambda value: value.update({"implementation_hash": "0" * 64})),
])
def test_supervisor_frame_schema_diagnostics_are_sanitized(diagnostic, mutate):
    payload = _supervisor_error_payload()
    mutate(payload)
    with pytest.raises(CodexExecutorFailure) as caught:
        parse_supervisor_frame(ProcessResult(exit_code=0, stdout=_raw_supervisor_frame(payload), stderr=""))
    assert caught.value.schema_diagnostic == diagnostic
    assert "unexpected" not in str(caught.value)


def test_synthetic_single_relay_to_broker_roundtrip_strips_sensitive_headers_without_io():
    request = _fixed_http_request_bytes({"Authorization": "redacted", "Cookie": "redacted", "Proxy-Connection": "redacted"})
    parsed = parse_sealed_loopback_request(request)
    proof = synthetic_relay_broker_roundtrip(request)
    assert parsed["clean_headers"] == {
        "Host": SEALED_LOOPBACK_AUTHORITY,
        "Content-Type": "application/json",
        "Content-Length": str(len(FIXED_REQUEST_BODY_BYTES)),
    }
    assert {field: proof[field] for field in RELAY_COUNTER_FIELDS} == {
        field: 1 for field in RELAY_COUNTER_FIELDS
    }
    assert proof["sensitive_headers_removed"] is True
    assert proof["removed_count"] == 3
    assert proof["post_filter_count"] == 0
    with pytest.raises(PolicyError, match="request_policy"):
        synthetic_relay_broker_roundtrip(second_request=True)


def test_relay_http_response_is_the_exact_proven_wire_fixture_and_closes():
    fixture = full_turn_fixture_bytes()
    assert SEALED_RESPONSE_BODY_BYTES == fixture
    assert build_sealed_http_response_bytes() == SEALED_HTTP_RESPONSE_BYTES
    assert SEALED_HTTP_RESPONSE_BYTES == SEALED_HTTP_RESPONSE_PREFIX + fixture
    head, separator, body = SEALED_HTTP_RESPONSE_BYTES.partition(b"\r\n\r\n")
    assert separator == b"\r\n\r\n" and body == fixture
    assert head.split(b"\r\n") == [
        b"HTTP/1.1 200 OK",
        b"Content-Type: text/event-stream",
        b"Cache-Control: no-cache",
        f"Content-Length: {len(fixture)}".encode("ascii"),
        b"Connection: close",
    ]
    proof = synthetic_relay_broker_roundtrip()
    assert proof["response_byte_count"] == len(fixture)
    assert proof["response_content_length"] == len(fixture)
    assert proof["response_hash"] == hashlib.sha256(fixture).hexdigest()
    source = RELAY_CODEX_CHILD_CODE.decode("utf-8")
    assert "conn.sendall(envelope); conn.shutdown(socket.SHUT_WR)" in source
    assert "upstream.shutdown(socket.SHUT_WR)" in source


def test_implementation_seals_distinct_parser_full_turn_and_http_hashes():
    assert EXECUTOR_COMPONENT_HASHES["responses_parser_fixture_sha256"] == responses_parser_fixture_hash()
    assert EXECUTOR_COMPONENT_HASHES["full_turn_fixture_sha256"] == hashlib.sha256(
        full_turn_fixture_bytes()
    ).hexdigest()
    assert EXECUTOR_COMPONENT_HASHES["full_turn_http_envelope_sha256"] == hashlib.sha256(
        SEALED_HTTP_RESPONSE_BYTES
    ).hexdigest()


def _http_request_with_headers(header_lines):
    return (
        "POST /v1/responses HTTP/1.1\r\n"
        + "\r\n".join(header_lines)
        + "\r\n\r\n"
    ).encode("ascii") + FIXED_REQUEST_BODY_BYTES


@pytest.mark.parametrize("host_name,length_name", [
    ("host", "content-length"),
    ("HoSt", "CoNtEnT-LeNgTh"),
    ("Host", "Content-Length"),
])
def test_loopback_headers_are_case_insensitive_and_forward_canonical_names(host_name, length_name):
    raw = _http_request_with_headers([
        f"{host_name}: {SEALED_LOOPBACK_AUTHORITY}",
        "Content-Type: application/json",
        f"{length_name}: {len(FIXED_REQUEST_BODY_BYTES)}",
    ])
    parsed = parse_sealed_loopback_request(raw)
    assert parsed["clean_headers"]["Host"] == SEALED_LOOPBACK_AUTHORITY
    assert parsed["clean_headers"]["Content-Length"] == str(len(FIXED_REQUEST_BODY_BYTES))
    assert "host" not in parsed["clean_headers"]
    assert "content-length" not in parsed["clean_headers"]


def test_case_insensitive_duplicate_headers_are_rejected():
    raw = _http_request_with_headers([
        f"Host: {SEALED_LOOPBACK_AUTHORITY}",
        f"host: {SEALED_LOOPBACK_AUTHORITY}",
        f"Content-Length: {len(FIXED_REQUEST_BODY_BYTES)}",
    ])
    with pytest.raises(PolicyError):
        parse_sealed_loopback_request(raw)


@pytest.mark.parametrize("host_value", ["127.0.0.1", "127.0.0.1:8787", " 127.0.0.1:8788"])
def test_host_authority_must_match_exactly(host_value):
    raw = _http_request_with_headers([
        f"Host: {host_value}",
        f"Content-Length: {len(FIXED_REQUEST_BODY_BYTES)}",
    ])
    with pytest.raises(PolicyError):
        parse_sealed_loopback_request(raw)


@pytest.mark.parametrize("length_value", [None, "not-an-int", "0"])
def test_content_length_is_required_integer_and_exact(length_value):
    headers = [f"Host: {SEALED_LOOPBACK_AUTHORITY}"]
    if length_value is not None:
        headers.append(f"Content-Length: {length_value}")
    raw = _http_request_with_headers(headers)
    with pytest.raises(PolicyError):
        parse_sealed_loopback_request(raw)


def test_case_insensitive_sensitive_headers_are_removed_before_broker_forwarding():
    raw = _http_request_with_headers([
        f"hOsT: {SEALED_LOOPBACK_AUTHORITY}",
        f"cOnTeNt-LeNgTh: {len(FIXED_REQUEST_BODY_BYTES)}",
        "aUtHoRiZaTiOn: redacted",
        "pRoXy-Connection: redacted",
    ])
    parsed = parse_sealed_loopback_request(raw)
    assert parsed["sensitive_headers_removed"] is True
    assert parsed["removed_count"] == 2
    assert parsed["post_filter_count"] == 0
    assert parsed["clean_headers"] == {
        "Host": SEALED_LOOPBACK_AUTHORITY,
        "Content-Length": str(len(FIXED_REQUEST_BODY_BYTES)),
    }


def test_request_proof_hash_is_canonical_and_sensitive_clean_requests_are_true():
    from app.codex_process_executor_wsl import canonical_request_proof_hash

    request = json.loads(FIXED_REQUEST_BODY_BYTES.decode("utf-8"))
    reordered = {key: request[key] for key in reversed(list(request))}
    assert canonical_request_proof_hash(request) == canonical_request_proof_hash(reordered)
    changed = dict(request)
    changed["store"] = True
    assert canonical_request_proof_hash(request) != canonical_request_proof_hash(changed)
    clean = parse_sealed_loopback_request(_fixed_http_request_bytes())
    assert clean["sensitive_headers_removed"] is True
    assert clean["removed_count"] == 0
    assert clean["post_filter_count"] == 0


def test_generated_relay_hashes_canonical_request_bytes_without_reencoding():
    source = RELAY_CODEX_CHILD_CODE.decode("utf-8")
    assert "request_hash=hashlib.sha256(canon(parsed)).hexdigest()" in source
    assert "request_hash=hashlib.sha256(cj(parsed).encode" not in source


def _proof_frame(
    *,
    counts=None,
    request_hash=EXPECTED_REQUEST_HASH,
    response_hash=EXPECTED_RESPONSE_HASH,
    output_hash=EXPECTED_OUTPUT_HASH,
):
    event_types = [
        "thread.started", "turn.started", "item.completed", "turn.completed",
    ]
    event_counts = {
        "thread.started": 1, "turn.started": 1,
        "item.completed": 1, "turn.completed": 1,
    }
    return ProcessResult(
        exit_code=0,
        stdout=encode_supervisor_frame({
            "status": "PASSED", "stage": "CLEANUP", "substage": None, "error_code": None,
            "process_counts": counts or {"supervisor": 1, "broker_bwrap": 1, "relay_codex_bwrap": 1, "codex_cli": 1},
            "cleanup_ok": True, "implementation_hash": EXECUTOR_IMPLEMENTATION_HASH,
            "request_seen": 1, "request_validated": 1,
            "response_sent": 1, "accepted_post": 1,
            "request_hash": request_hash, "response_hash": response_hash,
            "response_byte_count": len(SEALED_RESPONSE_BODY_BYTES),
            "output_hash": output_hash, "sensitive_headers_removed": True,
            "event_types": event_types, "event_counts": event_counts,
            "event_sequence_hash": hashlib.sha256(
                json.dumps(
                    {"event_types": event_types, "event_counts": event_counts},
                    sort_keys=True, separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest(),
            "last_message_exists": True, "last_message_regular": True,
            "last_message_size": len(SUCCESS_MARKER.encode("utf-8")),
            "last_message_sha256": EXPECTED_OUTPUT_HASH,
            "last_message_match": True,
            "last_message_marker_match": True,
            "marker_match": True,
            "agent_message_count": 1,
            "output_byte_count": len(SUCCESS_MARKER.encode("utf-8")),
            "output_sha256": EXPECTED_OUTPUT_HASH,
            "eof_stdout_drained": True, "eof_stderr_drained": True,
            "readers_joined": True, "codex_exit_code": 0,
            "usage": {
                "input_tokens": 7, "cached_input_tokens": 2,
                "cache_write_input_tokens": 0, "output_tokens": 3,
                "reasoning_output_tokens": 1,
            },
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
    values = {
        "request_hash": EXPECTED_REQUEST_HASH,
        "response_hash": EXPECTED_RESPONSE_HASH,
        "output_hash": EXPECTED_OUTPUT_HASH,
    }
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
