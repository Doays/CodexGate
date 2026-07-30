from __future__ import annotations

import asyncio

import pytest

from app.codex_process_canary import (
    ERROR,
    PASSED,
    WSLCodexProcessCanaryRunner,
    build_canary_launch_spec,
)
from app.codex_process_executor_wsl import (
    BROKER_CHILD_ARGV_TEMPLATE,
    EXECUTOR_IMPLEMENTATION_HASH,
    RELAY_CODEX_CHILD_ARGV_TEMPLATE,
    SUPERVISOR_ARGV_TEMPLATE,
    CodexExecutorFailure,
    WSLCodexProcessCanaryExecutor,
    build_codex_executor_launch_spec,
    build_codex_supervisor_argv,
    compute_executor_implementation,
    production_executor_factory,
)
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
    spec = build_codex_executor_launch_spec("/usr/local/bin/codex")
    assert spec["supervisor_argv_template"] == list(SUPERVISOR_ARGV_TEMPLATE)
    assert spec["broker_argv_template"] == list(BROKER_CHILD_ARGV_TEMPLATE)
    assert spec["relay_codex_argv_template"] == list(RELAY_CODEX_CHILD_ARGV_TEMPLATE)
    assert spec["broker"]["unshare_all"] is True and spec["relay_codex"]["work_read_only"] is True
    assert spec["relay_codex"]["tmpfs"] == ["/tmp", "/home", "/runtime-state"]
    assert spec["relay_codex"]["environment"] == {
        "PATH": "/usr/bin:/bin", "HOME": "/home/codex", "TMPDIR": "/tmp", "LANG": "C.UTF-8",
    }
    assert set(spec["forbidden_binds"]) == {"/mnt", "WINDOWS", "SOURCE_ROOT", "DATA_ROOT", "USER_HOME"}
    argv = build_codex_supervisor_argv("wsl.exe", "00000000-0000-0000-0000-000000000001")
    assert argv[:5] == ["wsl.exe", "-d", "Ubuntu", "--exec", "/usr/bin/python3"]
    assert argv[-1] == EXECUTOR_IMPLEMENTATION_HASH


def test_supervisor_child_or_argv_change_changes_executor_implementation_hash():
    assert compute_executor_implementation(supervisor_code=b"changed")[0] != EXECUTOR_IMPLEMENTATION_HASH
    assert compute_executor_implementation(broker_child_code=b"changed")[0] != EXECUTOR_IMPLEMENTATION_HASH
    assert compute_executor_implementation(codex_argv=("exec", "--json"))[0] != EXECUTOR_IMPLEMENTATION_HASH


class TimeoutSupervisor(NoIoSupervisor):
    async def run(self, args, *, timeout_seconds, on_started=None):
        self.calls += 1
        if on_started is not None:
            on_started()
        raise TimeoutError()


class InvalidFrameSupervisor(NoIoSupervisor):
    async def run(self, args, *, timeout_seconds, on_started=None):
        self.calls += 1
        if on_started is not None:
            on_started()
        return ProcessResult(exit_code=0, stdout="invalid\n", stderr="")


@pytest.mark.parametrize("supervisor,error", [
    (TimeoutSupervisor(), "canary_timeout"),
    (InvalidFrameSupervisor(), "canary_marker_invalid"),
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
