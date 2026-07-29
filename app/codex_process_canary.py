"""Sealed, offline Codex-process canary.

The real runner boundary is specified here but deliberately disabled in the
application.  Unit tests use :class:`FakeCodexProcessCanaryRunner`, which is
purely in-memory and never starts WSL, bubblewrap, Codex, or a socket.
"""
from __future__ import annotations

import asyncio
import hashlib
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping, Protocol

from .egress_contract import AUTH_UNCONFIGURED, canonical_provider_toml, provider_config_hash, validate_sealed_execution_proof
from .egress_harness import WSL_RUNNER_KIND
from .egress_harness_wsl import RUNNER_IMPLEMENTATION_HASH as HARNESS_IMPLEMENTATION_HASH
from .egress_harness_wsl import WSL_EGRESS_RUNNER_VERSION
from .policy import PolicyError, canonical_json, sha256_json
from .storage import RUNTIME_IDENTITY_VERSION


DISABLED = "DISABLED"
READY = "READY"
ARMED = "ARMED"
RUNNING = "RUNNING"
PASSED = "PASSED"
BLOCKED = "BLOCKED"
POLICY_VIOLATION = "POLICY_VIOLATION"
ERROR = "ERROR"

CANARY_POLICY_VERSION = "sealed-offline-codex-process-canary-v1"
CANARY_RUNNER_KIND = "WSL_CODEX_CANARY"
FAKE_CANARY_RUNNER_KIND = "FAKE_CODEX_CANARY"
WINDOW_TTL_SECONDS = 120
PROCESS_TIMEOUT_SECONDS = 45
PROCESS_OUTPUT_LIMIT_BYTES = 16 * 1024
SUCCESS_MARKER = "CODEXGATE_OFFLINE_CANARY_OK"

# These are private process inputs.  They are only represented outside this
# module by SHA-256 digests and must never be returned from an API or stored.
FIXED_PROMPT = "Return exactly the offline CodexGate canary marker."
FIXED_FAKE_RESPONSE = {
    "id": "sealed-offline-canary",
    "object": "response",
    "output": [{"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": SUCCESS_MARKER}]}],
}
FIXED_CODEX_ARGV = ("exec", "--json", "--skip-git-repo-check", "--sandbox", "read-only")
REQUIRED_EXEC_OPTIONS = frozenset({"--json", "--skip-git-repo-check", "--sandbox", "read-only"})

# The eventual fixed child programs are data rather than user-provided source.
# Keeping them as bytes makes all implementation inputs independently sealed.
BROKER_CHILD_CODE = b"codexgate-offline-broker-v1"
RELAY_CODEX_CHILD_CODE = b"codexgate-offline-relay-codex-v1"
SUPERVISOR_CODE = b"codexgate-offline-codex-supervisor-v1"


def _digest(value: bytes | str) -> str:
    return hashlib.sha256(value.encode("utf-8") if isinstance(value, str) else value).hexdigest()


EXPECTED_REQUEST_HASH = sha256_json({"method": "POST", "path": "/v1/responses", "model": "codexgate-sealed"})
EXPECTED_RESPONSE_HASH = sha256_json(FIXED_FAKE_RESPONSE)
EXPECTED_CONFIG_HASH = provider_config_hash(canonical_provider_toml())
EXPECTED_PROMPT_HASH = _digest(FIXED_PROMPT)
EXPECTED_OUTPUT_HASH = _digest(SUCCESS_MARKER)


def build_runner_implementation_hash(
    *,
    broker_code: bytes = BROKER_CHILD_CODE,
    relay_codex_code: bytes = RELAY_CODEX_CHILD_CODE,
    supervisor_code: bytes = SUPERVISOR_CODE,
    argv: tuple[str, ...] = FIXED_CODEX_ARGV,
    fake_response: Mapping[str, Any] = FIXED_FAKE_RESPONSE,
) -> str:
    """Seal every private execution input without returning any raw value."""
    return sha256_json({
        "policy_version": CANARY_POLICY_VERSION,
        "broker_child_sha256": _digest(broker_code),
        "relay_codex_child_sha256": _digest(relay_codex_code),
        "supervisor_sha256": _digest(supervisor_code),
        "argv_template_sha256": sha256_json(list(argv)),
        "fake_response_sha256": sha256_json(dict(fake_response)),
        "prompt_sha256": _digest(FIXED_PROMPT),
    })


RUNNER_IMPLEMENTATION_HASH = build_runner_implementation_hash()
RUNNER_VERSION = f"sealed-offline-codex-{RUNNER_IMPLEMENTATION_HASH[:16]}"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_hash(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(char in "0123456789abcdef" for char in value)


@dataclass(frozen=True)
class CanaryExecution:
    request_count: int
    request_hash: str
    response_hash: str
    config_hash: str
    prompt_hash: str
    expected_output_hash: str
    exit_code: int
    stdout_bytes: int
    stderr_bytes: int
    local_processes: int
    marker: str
    tool_calls: int = 0
    second_requests: int = 0
    websockets: int = 0
    different_models: int = 0
    command_executions: int = 0
    file_changes: int = 0
    network_tools: int = 0
    subagents: int = 0
    retries: int = 0
    reroutes: int = 0
    sensitive_headers_removed: bool = True
    process_terminated: bool = True
    resources_cleaned: bool = True
    runner_kind: str = CANARY_RUNNER_KIND
    runner_version: str = RUNNER_VERSION
    runner_implementation_hash: str = RUNNER_IMPLEMENTATION_HASH


class CodexProcessCanaryRunner(Protocol):
    runner_kind: str
    runner_version: str
    runner_implementation_hash: str
    enabled: bool
    supported_options: frozenset[str]

    async def run(self, binding: Mapping[str, str], launch_spec: Mapping[str, Any]) -> CanaryExecution: ...


class DisabledCodexProcessCanaryRunner:
    """Production default: no process can be started by this release."""

    runner_kind = CANARY_RUNNER_KIND
    runner_version = RUNNER_VERSION
    runner_implementation_hash = RUNNER_IMPLEMENTATION_HASH
    enabled = False
    is_fake = False
    supported_options = REQUIRED_EXEC_OPTIONS

    async def run(self, binding: Mapping[str, str], launch_spec: Mapping[str, Any]) -> CanaryExecution:
        raise PolicyError("codex_canary_execution_disabled")


class WSLCodexProcessCanaryRunner(DisabledCodexProcessCanaryRunner):
    """Sealed WSL runner identity reserved for a later execution release.

    It intentionally inherits the disabled ``run`` method in Phase 4.0.  This
    gives review code one implementation identity without providing a path to
    start a child process prematurely.
    """


class FakeCodexProcessCanaryRunner:
    """Deterministic no-I/O test runner; never a proof of a live Codex run."""

    runner_kind = FAKE_CANARY_RUNNER_KIND
    runner_version = RUNNER_VERSION
    runner_implementation_hash = RUNNER_IMPLEMENTATION_HASH
    enabled = True
    is_fake = True
    supported_options = REQUIRED_EXEC_OPTIONS

    def __init__(
        self,
        *,
        request_count: int = 1,
        marker: str = SUCCESS_MARKER,
        exit_code: int = 0,
        stdout_bytes: int | None = None,
        stderr_bytes: int = 0,
        tool_calls: int = 0,
        second_requests: int = 0,
        websockets: int = 0,
        different_models: int = 0,
        command_executions: int = 0,
        file_changes: int = 0,
        network_tools: int = 0,
        subagents: int = 0,
        retries: int = 0,
        reroutes: int = 0,
        sensitive_headers_removed: bool = True,
        delay_seconds: float = 0.0,
        process_terminated: bool = True,
        resources_cleaned: bool = True,
        implementation_hash: str | None = None,
    ):
        self.request_count = request_count
        self.marker = marker
        self.exit_code = exit_code
        self.stdout_bytes = len(marker.encode("utf-8")) if stdout_bytes is None else stdout_bytes
        self.stderr_bytes = stderr_bytes
        self.tool_calls = tool_calls
        self.second_requests = second_requests
        self.websockets = websockets
        self.different_models = different_models
        self.command_executions = command_executions
        self.file_changes = file_changes
        self.network_tools = network_tools
        self.subagents = subagents
        self.retries = retries
        self.reroutes = reroutes
        self.sensitive_headers_removed = sensitive_headers_removed
        self.delay_seconds = delay_seconds
        self.process_terminated = process_terminated
        self.resources_cleaned = resources_cleaned
        if implementation_hash is not None:
            self.runner_implementation_hash = implementation_hash
            self.runner_version = f"sealed-offline-codex-{implementation_hash[:16]}"
        self.calls = 0

    async def run(self, binding: Mapping[str, str], launch_spec: Mapping[str, Any]) -> CanaryExecution:
        self.calls += 1
        if self.delay_seconds:
            await asyncio.sleep(self.delay_seconds)
        return CanaryExecution(
            request_count=self.request_count,
            request_hash=EXPECTED_REQUEST_HASH,
            response_hash=EXPECTED_RESPONSE_HASH,
            config_hash=EXPECTED_CONFIG_HASH,
            prompt_hash=EXPECTED_PROMPT_HASH,
            expected_output_hash=EXPECTED_OUTPUT_HASH,
            exit_code=self.exit_code,
            stdout_bytes=self.stdout_bytes,
            stderr_bytes=self.stderr_bytes,
            local_processes=1,
            marker=self.marker,
            tool_calls=self.tool_calls,
            second_requests=self.second_requests,
            websockets=self.websockets,
            different_models=self.different_models,
            command_executions=self.command_executions,
            file_changes=self.file_changes,
            network_tools=self.network_tools,
            subagents=self.subagents,
            retries=self.retries,
            reroutes=self.reroutes,
            sensitive_headers_removed=self.sensitive_headers_removed,
            process_terminated=self.process_terminated,
            resources_cleaned=self.resources_cleaned,
            runner_kind=self.runner_kind,
            runner_version=self.runner_version,
            runner_implementation_hash=self.runner_implementation_hash,
        )


def build_canary_launch_spec(contract: Mapping[str, Any]) -> dict[str, Any]:
    """Private launch plan, represented publicly only by its digest.

    It deliberately contains no Windows mount, source root, DATA_ROOT,
    credential, or general-network bind.  The canonical provider TOML is
    written only to an execution-local tmpfs CODEX_HOME by a future runner.
    """
    if contract.get("status") != AUTH_UNCONFIGURED:
        raise PolicyError("contract_not_auth_unconfigured")
    config_bytes = canonical_provider_toml()
    if contract.get("provider_config_hash") != provider_config_hash(config_bytes):
        raise PolicyError("contract_provider_changed")
    return {
        "broker": {"unshare_all": True, "clearenv": True, "tmpfs": ("/tmp", "/runtime-state"), "socket": "single_af_unix"},
        "relay_codex": {
            "unshare_all": True,
            "clearenv": True,
            "work_read_only": True,
            "codex_home": "tmpfs",
            "tmpfs": ("/tmp", "/runtime-state"),
            "network": "sealed_loopback_only",
            "argv": list(FIXED_CODEX_ARGV),
        },
        "contract_hash": contract.get("contract_hash"),
        # This private byte value is the only file materialized in the tmpfs
        # CODEX_HOME; it is never persisted or returned from this function's
        # callers.
        "config_toml_bytes": config_bytes,
    }


def public_canary_result(result: Mapping[str, Any] | None) -> dict[str, Any]:
    if not isinstance(result, Mapping):
        return {"status": DISABLED, "start_allowed": False, "error_code": "canary_not_run"}
    fields = (
        "canary_id", "contract_hash", "status", "started_at", "finished_at", "error_code",
        "request_count", "request_hash", "response_hash", "config_hash", "prompt_hash",
        "expected_output_hash", "exit_code", "output_bytes", "local_processes",
        "local_duration_ms", "runner_kind", "runner_version", "runner_implementation_hash",
        "implementation_hash", "reused", "start_allowed",
    )
    return {field: result.get(field) for field in fields if field in result}


class SealedOfflineCodexProcessCanary:
    """One-time offline verification gate with no durable enable state."""

    _locks: dict[str, asyncio.Lock] = {}

    def __init__(self, store, contract_service, runner: CodexProcessCanaryRunner | None = None):
        self.store = store
        self.contract_service = contract_service
        self.runner = runner or DisabledCodexProcessCanaryRunner()
        self._arm_lock = asyncio.Lock()
        self.runner_kind = getattr(self.runner, "runner_kind", None)
        self.runner_version = getattr(self.runner, "runner_version", None)
        self.runner_implementation_hash = getattr(self.runner, "runner_implementation_hash", None)
        if self.runner_kind not in {CANARY_RUNNER_KIND, FAKE_CANARY_RUNNER_KIND} or not isinstance(self.runner_version, str) or not _is_hash(self.runner_implementation_hash):
            raise PolicyError("codex_canary_runner_invalid")

    def _binding(self) -> dict[str, str]:
        if not bool(getattr(self.runner, "enabled", False)):
            raise PolicyError("codex_canary_execution_disabled")
        if not REQUIRED_EXEC_OPTIONS <= set(getattr(self.runner, "supported_options", frozenset())):
            raise PolicyError("codex_canary_required_option_missing")
        runtime = self.store.wsl_codex_runtime_result()
        if not isinstance(runtime, Mapping) or runtime.get("identity_version") != RUNTIME_IDENTITY_VERSION:
            raise PolicyError("runtime_identity_missing")
        required_runtime = ("runtime_fingerprint", "launch_spec_hash", "binary_sha256", "isolation_cache_key")
        if runtime.get("status") != "EGRESS_UNCONFIGURED" or runtime.get("egress_blocked") is not True or runtime.get("start_allowed") is not False or not all(_is_hash(runtime.get(key)) for key in required_runtime):
            raise PolicyError("runtime_identity_missing")
        contract, error_code = self.contract_service.immutable_execution_contract()
        if contract is None:
            raise PolicyError(error_code or "stored_contract_required")
        if contract.get("status") != AUTH_UNCONFIGURED:
            raise PolicyError("contract_not_auth_unconfigured")
        if any(contract.get(key) != runtime.get(key) for key in ("runtime_fingerprint", "launch_spec_hash", "binary_sha256", "isolation_cache_key")):
            raise PolicyError("contract_binding_changed")
        proof, proof_error = validate_sealed_execution_proof(self.store)
        if proof is None:
            raise PolicyError(proof_error or "repro_missing")
        isolation = self.store.wsl_isolation_result()
        if not isinstance(isolation, Mapping):
            raise PolicyError("isolation_identity_missing")
        harness = self.store.egress_harness_result(
            contract["contract_hash"], WSL_RUNNER_KIND, WSL_EGRESS_RUNNER_VERSION, HARNESS_IMPLEMENTATION_HASH,
        )
        if not isinstance(harness, Mapping) or harness.get("status") != PASSED:
            raise PolicyError("actual_harness_required")
        fields: dict[str, Any] = {
            "contract_id": contract.get("contract_id"), "contract_hash": contract.get("contract_hash"),
            "runtime_identity_version": runtime.get("identity_version"), "runtime_fingerprint": runtime.get("runtime_fingerprint"),
            "launch_spec_hash": runtime.get("launch_spec_hash"), "binary_sha256": runtime.get("binary_sha256"),
            "isolation_config_hash": isolation.get("config_hash"), "tool_fingerprint": isolation.get("tool_fingerprint"),
            "isolation_cache_key": isolation.get("cache_key"),
            "harness_runner_kind": harness.get("runner_kind"), "harness_runner_version": harness.get("runner_version"),
            "harness_implementation_hash": harness.get("runner_implementation_hash"),
            "canary_runner_kind": self.runner_kind, "canary_runner_version": self.runner_version,
            "implementation_hash": self.runner_implementation_hash,
            "config_hash": EXPECTED_CONFIG_HASH,
            **proof,
        }
        if not all(isinstance(value, str) and value for value in fields.values()):
            raise PolicyError("codex_canary_binding_invalid")
        return {"binding_hash": sha256_json(fields), **fields}  # type: ignore[arg-type]

    def ready(self) -> dict[str, Any]:
        if not bool(getattr(self.runner, "enabled", False)):
            return {
                "status": DISABLED, "runner_kind": self.runner_kind, "runner_version": self.runner_version,
                "runner_implementation_hash": self.runner_implementation_hash,
                "implementation_hash": self.runner_implementation_hash,
                "start_allowed": False, "error_code": "codex_canary_execution_disabled",
            }
        try:
            binding = self._binding()
        except PolicyError as exc:
            return {"status": BLOCKED, "start_allowed": False, "error_code": str(exc)}
        return {
            "status": READY, "contract_hash": binding["contract_hash"], "binding_hash": binding["binding_hash"],
            "runner_kind": self.runner_kind, "runner_version": self.runner_version,
            "runner_implementation_hash": self.runner_implementation_hash,
            "implementation_hash": self.runner_implementation_hash, "start_allowed": False, "error_code": None,
        }

    async def arm(self) -> dict[str, Any]:
        async with self._arm_lock:
            binding = self._binding()
            window = self.store.issue_codex_process_canary_window(binding, ttl_seconds=WINDOW_TTL_SECONDS)
            self.store.record_codex_process_canary_ledger(window, "ARM")
            return window

    async def run(self, canary_nonce: str | None) -> dict[str, Any]:
        # Claim happens before validation/execution.  A failed request cannot
        # leave the capability reusable.
        claimed = self.store.consume_codex_process_canary_window(canary_nonce or "")
        claim_started = time.monotonic()
        # This is an authorization-consume plan event only; it is never a
        # process execution measurement.
        self.store.record_codex_process_canary_ledger(claimed, "CONSUME")
        try:
            current = self._binding()
        except PolicyError as exc:
            blocked = {**claimed, "status": BLOCKED, "local_processes": 0, "local_duration_ms": max(0, round((time.monotonic() - claim_started) * 1000))}
            self.store.record_codex_process_canary_ledger(blocked, "BLOCKED", source="LOCAL_OBSERVED", quality="OBSERVED")
            self.store.mark_codex_process_canary_window_blocked(claimed["window_id"], "canary_binding_changed")
            raise PolicyError("canary_binding_changed") from exc
        if current["binding_hash"] != claimed["binding_hash"]:
            blocked = {**claimed, "status": BLOCKED, "local_processes": 0, "local_duration_ms": max(0, round((time.monotonic() - claim_started) * 1000))}
            self.store.record_codex_process_canary_ledger(blocked, "BLOCKED", source="LOCAL_OBSERVED", quality="OBSERVED")
            self.store.mark_codex_process_canary_window_blocked(claimed["window_id"], "canary_binding_changed")
            raise PolicyError("canary_binding_changed")
        key = f"{self.store.db_path}:{current['contract_hash']}:{self.runner_implementation_hash}"
        lock = self._locks.setdefault(key, asyncio.Lock())
        async with lock:
            existing = self.store.codex_process_canary_result(current["contract_hash"], self.runner_kind, self.runner_version, self.runner_implementation_hash)
            if isinstance(existing, Mapping) and existing.get("status") == PASSED:
                return public_canary_result({**existing, "reused": True})
            return await self._run_once(current)

    async def _run_once(self, binding: Mapping[str, str]) -> dict[str, Any]:
        started_at = _now()
        running = {
            "canary_id": str(uuid.uuid4()), "contract_hash": binding["contract_hash"], "binding_hash": binding["binding_hash"],
            "status": RUNNING, "started_at": started_at, "finished_at": None, "error_code": None,
            "request_count": 0, "request_hash": None, "response_hash": None, "config_hash": binding["config_hash"],
            "prompt_hash": EXPECTED_PROMPT_HASH, "expected_output_hash": EXPECTED_OUTPUT_HASH,
            "exit_code": None, "output_bytes": 0, "local_processes": 0, "local_duration_ms": 0,
            "runner_kind": self.runner_kind, "runner_version": self.runner_version,
            "runner_implementation_hash": self.runner_implementation_hash, "implementation_hash": self.runner_implementation_hash,
            "start_allowed": False,
        }
        self.store.begin_codex_process_canary(running)
        began = time.monotonic()
        result: dict[str, Any]
        execution: CanaryExecution | None = None
        try:
            contract, error_code = self.contract_service.immutable_execution_contract()
            if contract is None:
                raise PolicyError(error_code or "stored_contract_required")
            execution = await asyncio.wait_for(self.runner.run(binding, build_canary_launch_spec(contract)), timeout=PROCESS_TIMEOUT_SECONDS)
            self._validate_execution(execution)
            result = {
                **running, "status": PASSED, "request_count": execution.request_count,
                "request_hash": execution.request_hash, "response_hash": execution.response_hash,
                "config_hash": execution.config_hash, "prompt_hash": execution.prompt_hash,
                "expected_output_hash": execution.expected_output_hash, "exit_code": execution.exit_code,
                "output_bytes": execution.stdout_bytes + execution.stderr_bytes, "local_processes": execution.local_processes,
                "error_code": None,
            }
        except asyncio.TimeoutError:
            result = {**running, "status": ERROR, "error_code": "canary_timeout"}
        except PolicyError as exc:
            code = str(exc)
            status = POLICY_VIOLATION if code in {
                "canary_request_policy_violation", "canary_tool_policy_violation", "canary_model_policy_violation",
                "canary_websocket_policy_violation", "canary_header_policy_violation", "canary_implementation_mismatch",
            } else ERROR
            result = {**running, "status": status, "error_code": code if code in {
                "canary_timeout", "canary_output_limit", "canary_marker_invalid", "canary_exit_invalid",
                "canary_process_termination_failed", "canary_resource_cleanup_failed", "canary_request_policy_violation",
                "canary_tool_policy_violation", "canary_model_policy_violation", "canary_websocket_policy_violation",
                "canary_header_policy_violation",
                "canary_implementation_mismatch", "canary_runner_identity_mismatch",
            } else "canary_policy_error"}
        except Exception:
            result = {**running, "status": ERROR, "error_code": "canary_error"}
        if execution is not None:
            result.update({
                "request_count": execution.request_count,
                "output_bytes": execution.stdout_bytes + execution.stderr_bytes,
                "local_processes": execution.local_processes,
                "exit_code": execution.exit_code,
            })
        result = {
            **result, "finished_at": _now(), "local_duration_ms": max(0, round((time.monotonic() - began) * 1000)),
            "start_allowed": False,
        }
        saved = self.store.finish_codex_process_canary(result)
        ledger_source = "LOCAL_ESTIMATE" if bool(getattr(self.runner, "is_fake", False)) else "LOCAL_OBSERVED"
        ledger_quality = "ESTIMATED" if ledger_source == "LOCAL_ESTIMATE" else "OBSERVED"
        self.store.record_codex_process_canary_ledger(saved, "RUN", source=ledger_source, quality=ledger_quality)
        return public_canary_result(saved)

    def _validate_execution(self, execution: CanaryExecution) -> None:
        if (execution.runner_kind, execution.runner_version, execution.runner_implementation_hash) != (
            self.runner_kind, self.runner_version, self.runner_implementation_hash,
        ):
            raise PolicyError("canary_runner_identity_mismatch")
        if execution.runner_implementation_hash != self.runner_implementation_hash:
            raise PolicyError("canary_implementation_mismatch")
        if execution.stdout_bytes < 0 or execution.stderr_bytes < 0 or execution.stdout_bytes + execution.stderr_bytes > PROCESS_OUTPUT_LIMIT_BYTES:
            raise PolicyError("canary_output_limit")
        if execution.exit_code != 0:
            raise PolicyError("canary_exit_invalid")
        if (
            execution.marker != SUCCESS_MARKER
            or execution.stdout_bytes != len(SUCCESS_MARKER.encode("utf-8"))
            or execution.stderr_bytes != 0
        ):
            raise PolicyError("canary_marker_invalid")
        if not execution.process_terminated:
            raise PolicyError("canary_process_termination_failed")
        if not execution.resources_cleaned:
            raise PolicyError("canary_resource_cleanup_failed")
        if execution.request_count != 1 or execution.second_requests != 0:
            raise PolicyError("canary_request_policy_violation")
        if execution.websockets != 0:
            raise PolicyError("canary_websocket_policy_violation")
        if execution.different_models != 0:
            raise PolicyError("canary_model_policy_violation")
        if any(getattr(execution, field) != 0 for field in (
            "tool_calls", "command_executions", "file_changes", "network_tools", "subagents", "retries", "reroutes",
        )):
            raise PolicyError("canary_tool_policy_violation")
        if not execution.sensitive_headers_removed:
            raise PolicyError("canary_header_policy_violation")
        if not all(_is_hash(getattr(execution, field)) for field in ("request_hash", "response_hash", "config_hash", "prompt_hash", "expected_output_hash")):
            raise PolicyError("canary_request_policy_violation")
        if (
            execution.request_hash != EXPECTED_REQUEST_HASH or execution.response_hash != EXPECTED_RESPONSE_HASH
            or execution.config_hash != EXPECTED_CONFIG_HASH or execution.prompt_hash != EXPECTED_PROMPT_HASH
            or execution.expected_output_hash != EXPECTED_OUTPUT_HASH
        ):
            raise PolicyError("canary_request_policy_violation")

    def window_status(self) -> dict[str, Any]:
        return self.store.codex_process_canary_window()
