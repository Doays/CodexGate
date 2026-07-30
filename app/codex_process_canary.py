"""Sealed, offline Codex-process canary.

The ordinary Canary endpoint remains disabled.  Only a persisted, running
one-shot claim can materialize the sealed WSL executor; unit tests inject a
no-I/O supervisor and never start WSL, bubblewrap, Codex, or a socket.
"""
from __future__ import annotations

import asyncio
import hashlib
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Mapping, Protocol

from .codex_process_executor_wsl import (
    BROKER_CHILD_CODE,
    EXPECTED_REQUEST_HASH as SEALED_REQUEST_HASH,
    EXECUTOR_IMPLEMENTATION_HASH,
    EXECUTOR_VERSION,
    FIXED_CODEX_ARGV,
    FIXED_FAKE_RESPONSE,
    FIXED_PROMPT,
    RELAY_CODEX_CHILD_CODE,
    REQUIRED_EXEC_OPTIONS,
    SUCCESS_MARKER,
    SUPERVISOR_CODE,
    WSLCodexProcessCanaryExecutor,
    compute_executor_implementation,
)
from .codex_wire_contract import WIRE_CONTRACT_HASH, WIRE_CONTRACT_STATUS, fixture_stream_hash
from .egress_contract import (
    AUTH_UNCONFIGURED, BROKER_REQUEST_PATH, LOOPBACK_HOST, LOOPBACK_PORT,
    canonical_provider_toml, provider_config_hash, validate_sealed_execution_proof,
)
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


def _digest(value: bytes | str) -> str:
    return hashlib.sha256(value.encode("utf-8") if isinstance(value, str) else value).hexdigest()


EXPECTED_REQUEST_HASH = SEALED_REQUEST_HASH
EXPECTED_RESPONSE_HASH = fixture_stream_hash()
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
    """Expose the executor seal through the existing Canary API.

    One canonical computation covers the actual supervisor/child argv as
    well as the fixed prompt and fake response.  Tests can perturb any input
    without creating a process.
    """
    from .codex_process_executor_wsl import (
        BROKER_CHILD_ARGV_TEMPLATE,
        RELAY_CODEX_CHILD_ARGV_TEMPLATE,
        SUPERVISOR_ARGV_TEMPLATE,
    )
    return compute_executor_implementation(
        supervisor_code=supervisor_code,
        broker_child_code=broker_code,
        relay_codex_child_code=relay_codex_code,
        broker_argv=BROKER_CHILD_ARGV_TEMPLATE,
        relay_codex_argv=RELAY_CODEX_CHILD_ARGV_TEMPLATE,
        supervisor_argv=SUPERVISOR_ARGV_TEMPLATE,
        codex_argv=argv,
        prompt=FIXED_PROMPT,
        fake_response=fake_response,
    )[0]


RUNNER_IMPLEMENTATION_HASH = EXECUTOR_IMPLEMENTATION_HASH
RUNNER_VERSION = EXECUTOR_VERSION


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
    marker: str | None
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
    supervisor_processes: int = 0
    bwrap_processes: int = 0
    codex_processes: int = 0
    supervisor_stage: str | None = None
    cleanup_ok: bool | None = None
    # These are observed sealed-frame digests, never reconstructed output.
    output_hash: str | None = None
    marker_verified: bool = False


class CodexProcessCanaryRunner(Protocol):
    runner_kind: str
    runner_version: str
    runner_implementation_hash: str
    enabled: bool
    supported_options: frozenset[str]

    async def run(self, binding: Mapping[str, str], launch_spec: Mapping[str, Any]) -> CanaryExecution: ...


class CodexProcessCanaryExecutor(Protocol):
    """Execution seam used only after a sealed one-shot claim.

    Production deliberately supplies no executor in this release.  The small
    protocol lets tests prove the selection and accounting path without
    creating a WSL, bubblewrap, Codex, socket, or network process.
    """

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
    """The only runner identity accepted by the sealed one-shot endpoint.

    Its ordinary ``run`` method remains disabled.  A process executor is
    constructed lazily *after* a valid execution claim is stored and marked
    running.  Production supplies no executor in Phase 4.2, while tests use a
    no-I/O executor to exercise the exact same identity and accounting path.
    """

    def __init__(self, executor_factory: Callable[[str], CodexProcessCanaryExecutor] | None = None):
        self._executor_factory = executor_factory
        self.executor_creations = 0
        self.one_shot_calls = 0

    @property
    def execution_available(self) -> bool:
        """Only a post-claim factory can make the sealed executor available."""
        return self._executor_factory is not None

    async def run_one_shot(
        self,
        claim: Mapping[str, str],
        binding: Mapping[str, str],
        launch_spec: Mapping[str, Any],
    ) -> CanaryExecution:
        required = {
            "execution_claim_id", "binding_hash", "contract_hash",
            "runner_kind", "runner_version", "runner_implementation_hash",
        }
        if not required <= set(claim):
            raise PolicyError("canary_execution_claim_invalid")
        if (
            claim["runner_kind"] != self.runner_kind
            or claim["runner_version"] != self.runner_version
            or claim["runner_implementation_hash"] != self.runner_implementation_hash
            or claim["binding_hash"] != binding.get("binding_hash")
            or claim["contract_hash"] != binding.get("contract_hash")
        ):
            raise PolicyError("canary_implementation_mismatch")
        self.one_shot_calls += 1
        if self._executor_factory is None:
            raise PolicyError("codex_canary_execution_disabled")
        executor = self._executor_factory(claim["execution_claim_id"])
        self.executor_creations += 1
        if not isinstance(executor, WSLCodexProcessCanaryExecutor) or not bool(getattr(executor, "is_production_executor", False)):
            raise PolicyError("actual_runner_policy_violation")
        return await executor.run(binding, launch_spec)


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
            output_hash=EXPECTED_OUTPUT_HASH,
            marker_verified=True,
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
            "endpoint": {"host": LOOPBACK_HOST, "port": LOOPBACK_PORT, "path": BROKER_REQUEST_PATH},
        },
        "contract_hash": contract.get("contract_hash"),
        "wire_contract_hash": WIRE_CONTRACT_HASH,
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
        "expected_output_hash", "output_hash", "sensitive_headers_removed", "marker_verified", "exit_code", "output_bytes", "local_processes",
        "stdout_bytes", "stderr_bytes", "stage", "cleanup_ok", "legacy_error",
        "local_duration_ms", "runner_kind", "runner_version", "runner_implementation_hash",
        "implementation_hash", "reused", "start_allowed",
    )
    value = {field: result.get(field) for field in fields if field in result}
    if "legacy_error" not in value:
        value["legacy_error"] = result.get("error_code") == "canary_exit_invalid" and not all(
            field in result for field in ("stage", "stdout_bytes", "stderr_bytes", "cleanup_ok")
        )
    return value


class SealedOfflineCodexProcessCanary:
    """One-time offline verification gate with no durable enable state."""

    _locks: dict[str, asyncio.Lock] = {}

    def __init__(
        self,
        store,
        contract_service,
        runner: CodexProcessCanaryRunner | None = None,
        *,
        runner_factory: Callable[[], CodexProcessCanaryRunner] | None = None,
    ):
        self.store = store
        self.contract_service = contract_service
        # A factory is used by the production one-shot route so neither the
        # runner nor its process executor exists before SQLite has atomically
        # consumed both capabilities.  Existing fake-runner tests continue to
        # inject a concrete in-memory runner.
        self.runner = runner
        self._runner_factory = runner_factory
        if self.runner is None and self._runner_factory is None:
            self.runner = DisabledCodexProcessCanaryRunner()
        self._arm_lock = asyncio.Lock()
        if self.runner is None:
            self.runner_kind = CANARY_RUNNER_KIND
            self.runner_version = RUNNER_VERSION
            self.runner_implementation_hash = RUNNER_IMPLEMENTATION_HASH
        else:
            self.runner_kind = getattr(self.runner, "runner_kind", None)
            self.runner_version = getattr(self.runner, "runner_version", None)
            self.runner_implementation_hash = getattr(self.runner, "runner_implementation_hash", None)
        if self.runner_kind not in {CANARY_RUNNER_KIND, FAKE_CANARY_RUNNER_KIND} or not isinstance(self.runner_version, str) or not _is_hash(self.runner_implementation_hash):
            raise PolicyError("codex_canary_runner_invalid")

    def _runner_enabled(self) -> bool:
        return bool(self.runner is not None and getattr(self.runner, "enabled", False))

    def is_sealed_actual_runner_candidate(self) -> bool:
        """Check identity without materializing a lazy production runner."""
        if self.runner is not None:
            return (
                isinstance(self.runner, WSLCodexProcessCanaryRunner)
                and self.runner_kind == CANARY_RUNNER_KIND
                and not bool(getattr(self.runner, "is_fake", False))
                and self.runner_version == RUNNER_VERSION
                and self.runner_implementation_hash == RUNNER_IMPLEMENTATION_HASH
            )
        return self._runner_factory is not None and (
            self.runner_kind,
            self.runner_version,
            self.runner_implementation_hash,
        ) == (CANARY_RUNNER_KIND, RUNNER_VERSION, RUNNER_IMPLEMENTATION_HASH)

    def _materialize_sealed_actual_runner(self) -> WSLCodexProcessCanaryRunner:
        runner = self.runner
        if runner is None:
            if self._runner_factory is None:
                raise PolicyError("actual_runner_policy_violation")
            runner = self._runner_factory()
        if (
            not isinstance(runner, WSLCodexProcessCanaryRunner)
            or runner.runner_kind != CANARY_RUNNER_KIND
            or bool(getattr(runner, "is_fake", False))
            or runner.runner_version != RUNNER_VERSION
            or runner.runner_implementation_hash != RUNNER_IMPLEMENTATION_HASH
        ):
            raise PolicyError("actual_runner_policy_violation")
        return runner

    def _binding(self, *, allow_disabled_runner: bool = False) -> dict[str, str]:
        if not self._runner_enabled() and not allow_disabled_runner:
            raise PolicyError("codex_canary_execution_disabled")
        supported_options = (
            REQUIRED_EXEC_OPTIONS if self.runner is None
            else set(getattr(self.runner, "supported_options", frozenset()))
        )
        if not REQUIRED_EXEC_OPTIONS <= set(supported_options):
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
            "wire_contract_hash": WIRE_CONTRACT_HASH,
            "config_hash": EXPECTED_CONFIG_HASH,
            **proof,
        }
        if not all(isinstance(value, str) and value for value in fields.values()):
            raise PolicyError("codex_canary_binding_invalid")
        return {"binding_hash": sha256_json(fields), **fields}  # type: ignore[arg-type]

    def ready(self) -> dict[str, Any]:
        if not self._runner_enabled():
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

    async def arm_from_execution_permit(self, permit_binding: Mapping[str, str]) -> dict[str, Any]:
        """Create the existing Canary window only after a Permit validation.

        The Permit gate is the sole caller allowed to bypass ordinary endpoint
        readiness for the purpose of minting a one-use window; it does not
        enable a general runner or start a child process.
        """
        async with self._arm_lock:
            binding = self._binding(allow_disabled_runner=True)
            if binding.get("binding_hash") != permit_binding.get("binding_hash"):
                raise PolicyError("execution_binding_changed")
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

    def record_blocked_execution_attempt(self, claimed_window: Mapping[str, Any], error_code: str) -> None:
        """Record a pre-spawn denial as an observed zero-process metric."""
        blocked = {
            **claimed_window,
            "status": BLOCKED,
            "local_processes": 0,
            "local_duration_ms": 0,
            "implementation_hash": self.runner_implementation_hash,
        }
        self.store.record_codex_process_canary_ledger(
            blocked, "BLOCKED", source="LOCAL_OBSERVED", quality="OBSERVED",
        )
        window_id = claimed_window.get("window_id")
        if isinstance(window_id, str):
            self.store.mark_codex_process_canary_window_blocked(window_id, error_code)

    async def run_claimed_execution_permit(
        self, claimed_window: Mapping[str, Any], expected_binding: Mapping[str, str],
    ) -> dict[str, Any]:
        """Run only after the Permit and Canary window have been atomically consumed."""
        try:
            current = self._binding(allow_disabled_runner=True)
        except PolicyError as exc:
            self.record_blocked_execution_attempt(claimed_window, "execution_binding_changed")
            raise PolicyError("execution_binding_changed") from exc
        if current.get("binding_hash") != expected_binding.get("binding_hash"):
            self.record_blocked_execution_attempt(claimed_window, "execution_binding_changed")
            raise PolicyError("execution_binding_changed")
        if not self._runner_enabled():
            self.record_blocked_execution_attempt(claimed_window, "codex_canary_execution_disabled")
            raise PolicyError("codex_canary_execution_disabled")
        key = f"{self.store.db_path}:{current['contract_hash']}:{self.runner_implementation_hash}"
        lock = self._locks.setdefault(key, asyncio.Lock())
        async with lock:
            existing = self.store.codex_process_canary_result(
                current["contract_hash"], self.runner_kind, self.runner_version, self.runner_implementation_hash,
            )
            if isinstance(existing, Mapping) and existing.get("status") == PASSED:
                return public_canary_result({**existing, "reused": True})
            return await self._run_once(current)

    async def run_one_shot_execution_claim(
        self,
        claim: Mapping[str, str],
        expected_binding: Mapping[str, str],
    ) -> dict[str, Any]:
        """Run the concrete sealed runner only after an immutable claim exists.

        This is deliberately distinct from ``run_claimed_execution_permit``:
        the ordinary endpoint remains disabled, whereas this method admits a
        lazy ``WSLCodexProcessCanaryRunner`` only after storage has consumed
        both capabilities and recorded a claim.  No fake runner can enter this
        path.
        """
        claim_id = claim.get("execution_claim_id")
        if not isinstance(claim_id, str):
            raise PolicyError("canary_execution_claim_invalid")
        try:
            current = self._binding(allow_disabled_runner=True)
        except PolicyError as exc:
            self.store.finish_codex_canary_execution_claim(claim_id, ERROR, "execution_binding_changed")
            self.record_blocked_execution_attempt(claim, "execution_binding_changed")
            raise PolicyError("execution_binding_changed") from exc
        if (
            current.get("binding_hash") != expected_binding.get("binding_hash")
            or current.get("binding_hash") != claim.get("binding_hash")
            or current.get("implementation_hash") != claim.get("runner_implementation_hash")
        ):
            self.store.finish_codex_canary_execution_claim(claim_id, ERROR, "execution_binding_changed")
            self.record_blocked_execution_attempt(claim, "execution_binding_changed")
            raise PolicyError("execution_binding_changed")
        # A second request cannot get beyond this compare-and-set.  It occurs
        # before the runner factory (and, consequently, any executor factory)
        # is touched.
        claimed = self.store.begin_codex_canary_execution_claim(claim_id, current)
        existing = self.store.codex_process_canary_result(
            current["contract_hash"], CANARY_RUNNER_KIND, RUNNER_VERSION, RUNNER_IMPLEMENTATION_HASH,
        )
        if isinstance(existing, Mapping) and existing.get("status") == PASSED:
            self.store.finish_codex_canary_execution_claim(claim_id, PASSED, None)
            return public_canary_result({**existing, "reused": True})
        try:
            active_runner = self._materialize_sealed_actual_runner()
        except PolicyError as exc:
            self.store.finish_codex_canary_execution_claim(claim_id, POLICY_VIOLATION, str(exc))
            self.record_blocked_execution_attempt(claimed, str(exc))
            raise
        if (
            active_runner.runner_kind != claim.get("runner_kind")
            or active_runner.runner_version != claim.get("runner_version")
            or active_runner.runner_implementation_hash != claim.get("runner_implementation_hash")
        ):
            self.store.finish_codex_canary_execution_claim(claim_id, POLICY_VIOLATION, "canary_implementation_mismatch")
            self.record_blocked_execution_attempt(claimed, "canary_implementation_mismatch")
            raise PolicyError("canary_implementation_mismatch")
        if not active_runner.execution_available:
            self.store.finish_codex_canary_execution_claim(claim_id, ERROR, "codex_canary_execution_disabled")
            self.record_blocked_execution_attempt(claimed, "codex_canary_execution_disabled")
            raise PolicyError("codex_canary_execution_disabled")
        try:
            result = await self._run_once(current, runner=active_runner, execution_claim=claimed)
        except Exception:
            self.store.finish_codex_canary_execution_claim(claim_id, ERROR, "canary_error")
            raise
        final_status = result.get("status") if result.get("status") in {PASSED, POLICY_VIOLATION, ERROR} else ERROR
        self.store.finish_codex_canary_execution_claim(claim_id, final_status, result.get("error_code"))
        return result

    async def _run_once(
        self,
        binding: Mapping[str, str],
        *,
        runner: CodexProcessCanaryRunner | None = None,
        execution_claim: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        active_runner = runner or self.runner
        if active_runner is None:
            raise PolicyError("codex_canary_execution_disabled")
        runner_kind = getattr(active_runner, "runner_kind", None)
        runner_version = getattr(active_runner, "runner_version", None)
        runner_implementation_hash = getattr(active_runner, "runner_implementation_hash", None)
        if (
            runner_kind != self.runner_kind
            or runner_version != self.runner_version
            or runner_implementation_hash != self.runner_implementation_hash
        ):
            raise PolicyError("actual_runner_policy_violation")
        started_at = _now()
        running = {
            "canary_id": str(uuid.uuid4()), "contract_hash": binding["contract_hash"], "binding_hash": binding["binding_hash"],
            "status": RUNNING, "started_at": started_at, "finished_at": None, "error_code": None,
            "request_count": 0, "request_hash": None, "response_hash": None, "config_hash": binding["config_hash"],
            "prompt_hash": EXPECTED_PROMPT_HASH, "expected_output_hash": EXPECTED_OUTPUT_HASH,
            "exit_code": None, "output_bytes": 0, "local_processes": 0, "local_duration_ms": 0,
            "stdout_bytes": 0, "stderr_bytes": 0, "stage": "BOOT", "cleanup_ok": None,
            "output_hash": None, "sensitive_headers_removed": False, "marker_verified": False,
            "supervisor_processes": 0, "bwrap_processes": 0, "codex_processes": 0,
            "runner_kind": runner_kind, "runner_version": runner_version,
            "runner_implementation_hash": runner_implementation_hash, "implementation_hash": runner_implementation_hash,
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
            launch_spec = build_canary_launch_spec(contract)
            if execution_claim is not None:
                if not isinstance(active_runner, WSLCodexProcessCanaryRunner):
                    raise PolicyError("actual_runner_policy_violation")
                execution = await asyncio.wait_for(
                    active_runner.run_one_shot(execution_claim, binding, launch_spec),
                    timeout=PROCESS_TIMEOUT_SECONDS,
                )
            else:
                execution = await asyncio.wait_for(active_runner.run(binding, launch_spec), timeout=PROCESS_TIMEOUT_SECONDS)
            try:
                self._validate_execution(execution, active_runner)
            except PolicyError as exc:
                # A supervisor can have started even when its frame, cleanup,
                # or policy result fails.  Preserve only numeric observed
                # counters for the Ledger; never retain its output.
                exc.local_processes = execution.local_processes
                exc.supervisor_processes = execution.supervisor_processes
                exc.bwrap_processes = execution.bwrap_processes
                exc.codex_processes = execution.codex_processes
                raise
            result = {
                **running, "status": PASSED, "request_count": execution.request_count,
                "request_hash": execution.request_hash, "response_hash": execution.response_hash,
                "config_hash": execution.config_hash, "prompt_hash": execution.prompt_hash,
                "expected_output_hash": execution.expected_output_hash, "exit_code": execution.exit_code,
                "output_hash": execution.output_hash, "sensitive_headers_removed": execution.sensitive_headers_removed,
                "marker_verified": execution.marker_verified,
                "output_bytes": execution.stdout_bytes + execution.stderr_bytes, "local_processes": execution.local_processes,
                "supervisor_processes": execution.supervisor_processes, "bwrap_processes": execution.bwrap_processes,
                "codex_processes": execution.codex_processes,
                "error_code": None, "stdout_bytes": execution.stdout_bytes, "stderr_bytes": execution.stderr_bytes,
                "stage": execution.supervisor_stage or "CLEANUP", "cleanup_ok": execution.cleanup_ok if execution.cleanup_ok is not None else execution.resources_cleaned,
            }
        except asyncio.TimeoutError:
            result = {**running, "status": ERROR, "error_code": "canary_timeout", "stage": "BOOT", "cleanup_ok": False}
        except PolicyError as exc:
            code = str(exc)
            observed_counts = {
                "local_processes": max(0, int(getattr(exc, "local_processes", 0) or 0)),
                "supervisor_processes": max(0, int(getattr(exc, "supervisor_processes", 0) or 0)),
                "bwrap_processes": max(0, int(getattr(exc, "bwrap_processes", 0) or 0)),
                "codex_processes": max(0, int(getattr(exc, "codex_processes", 0) or 0)),
            }
            status = POLICY_VIOLATION if code in {
                "canary_request_policy_violation", "canary_tool_policy_violation", "canary_model_policy_violation",
                "canary_websocket_policy_violation", "canary_header_policy_violation", "canary_implementation_mismatch",
                "actual_runner_policy_violation", "supervisor_implementation_mismatch", "supervisor_policy_violation",
            } else ERROR
            result = {**running, **observed_counts, "status": status, "error_code": code if code in {
                "canary_timeout", "canary_output_limit", "canary_marker_invalid", "canary_process_exit_nonzero",
                "canary_process_termination_failed", "canary_resource_cleanup_failed", "canary_request_policy_violation",
                "canary_tool_policy_violation", "canary_model_policy_violation", "canary_websocket_policy_violation",
                "canary_header_policy_violation",
                "canary_implementation_mismatch", "canary_runner_identity_mismatch",
                "actual_runner_policy_violation",
            } else (code if isinstance(code, str) and len(code) <= 80 and code.replace("_", "").isalnum() else "canary_policy_error"),
                "stage": getattr(exc, "stage", None) or running.get("stage"),
                "cleanup_ok": getattr(exc, "cleanup_ok", None), "stdout_bytes": getattr(exc, "stdout_bytes", 0),
                "stderr_bytes": getattr(exc, "stderr_bytes", 0), "exit_code": getattr(exc, "exit_code", None),
                "output_bytes": int(getattr(exc, "stdout_bytes", 0) or 0) + int(getattr(exc, "stderr_bytes", 0) or 0)}
        except Exception:
            result = {**running, "status": ERROR, "error_code": "canary_error", "stage": "BOOT", "cleanup_ok": False}
        if execution is not None:
            result.update({
                "request_count": execution.request_count,
                "output_bytes": execution.stdout_bytes + execution.stderr_bytes,
                "local_processes": execution.local_processes,
                "supervisor_processes": execution.supervisor_processes,
                "bwrap_processes": execution.bwrap_processes,
                "codex_processes": execution.codex_processes,
                "exit_code": execution.exit_code,
                "stdout_bytes": execution.stdout_bytes, "stderr_bytes": execution.stderr_bytes,
                "stage": execution.supervisor_stage or result.get("stage"),
                "cleanup_ok": execution.cleanup_ok if execution.cleanup_ok is not None else execution.resources_cleaned,
                "output_hash": execution.output_hash, "sensitive_headers_removed": execution.sensitive_headers_removed,
                "marker_verified": execution.marker_verified,
            })
        result = {
            **result, "finished_at": _now(), "local_duration_ms": max(0, round((time.monotonic() - began) * 1000)),
            "start_allowed": False,
        }
        saved = self.store.finish_codex_process_canary(result)
        ledger_source = "LOCAL_ESTIMATE" if bool(getattr(active_runner, "is_fake", False)) else "LOCAL_OBSERVED"
        ledger_quality = "ESTIMATED" if ledger_source == "LOCAL_ESTIMATE" else "OBSERVED"
        self.store.record_codex_process_canary_ledger(saved, "RUN", source=ledger_source, quality=ledger_quality)
        return public_canary_result(saved)

    def _validate_execution(self, execution: CanaryExecution, active_runner: CodexProcessCanaryRunner) -> None:
        if (execution.runner_kind, execution.runner_version, execution.runner_implementation_hash) != (
            active_runner.runner_kind, active_runner.runner_version, active_runner.runner_implementation_hash,
        ):
            raise PolicyError("canary_runner_identity_mismatch")
        if execution.runner_implementation_hash != active_runner.runner_implementation_hash:
            raise PolicyError("canary_implementation_mismatch")
        if execution.stdout_bytes < 0 or execution.stderr_bytes < 0 or execution.stdout_bytes + execution.stderr_bytes > PROCESS_OUTPUT_LIMIT_BYTES:
            raise PolicyError("canary_output_limit")
        if execution.exit_code != 0:
            raise PolicyError("canary_exit_invalid" if bool(getattr(active_runner, "is_fake", False)) else "canary_process_exit_nonzero")
        observed_marker = execution.marker == SUCCESS_MARKER or (
            not bool(getattr(active_runner, "is_fake", False))
            and execution.marker_verified and execution.output_hash == EXPECTED_OUTPUT_HASH
        )
        if not observed_marker:
            raise PolicyError("canary_marker_invalid" if bool(getattr(active_runner, "is_fake", False)) else "canary_marker_mismatch")
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
        if not all(_is_hash(getattr(execution, field)) for field in ("request_hash", "response_hash", "config_hash", "prompt_hash", "expected_output_hash", "output_hash")):
            raise PolicyError("canary_request_policy_violation")
        if (
            execution.request_hash != EXPECTED_REQUEST_HASH or execution.response_hash != EXPECTED_RESPONSE_HASH
            or execution.config_hash != EXPECTED_CONFIG_HASH or execution.prompt_hash != EXPECTED_PROMPT_HASH
            or execution.expected_output_hash != EXPECTED_OUTPUT_HASH
        ):
            raise PolicyError("canary_request_policy_violation")
        if isinstance(active_runner, WSLCodexProcessCanaryRunner):
            if (
                (execution.supervisor_processes, execution.bwrap_processes, execution.codex_processes) != (1, 2, 1)
                or execution.local_processes != 4 or execution.output_hash != EXPECTED_OUTPUT_HASH
            ):
                raise PolicyError("canary_success_proof_invalid")

    def window_status(self) -> dict[str, Any]:
        return self.store.codex_process_canary_window()


class CodexCanaryExecutionPermitGate:
    """One-use local Permit in front of the sealed Offline Canary window.

    A Permit is a narrower capability than a Runtime start: it can authorize
    only this fixed Offline Canary's existing arm/window protocol.  It neither
    changes global runner state nor opens an egress or live-run path.
    """

    PERMIT_TTL_SECONDS = 120

    def __init__(self, store, service: SealedOfflineCodexProcessCanary):
        self.store = store
        self.service = service
        self._permit_lock = asyncio.Lock()

    def _require_actual_runner(self) -> None:
        if not self.service.is_sealed_actual_runner_candidate():
            raise PolicyError("actual_runner_policy_violation")

    def _sealed_binding(self) -> dict[str, str]:
        self._require_actual_runner()
        return self.service._binding(allow_disabled_runner=True)

    def ready(self) -> dict[str, Any]:
        try:
            binding = self._sealed_binding()
        except PolicyError as exc:
            return {"status": BLOCKED, "start_allowed": False, "error_code": str(exc)}
        return {
            "status": READY,
            "start_allowed": False,
            "binding_hash": binding["binding_hash"],
            "runner_kind": self.service.runner_kind,
            "runner_version": self.service.runner_version,
            "runner_implementation_hash": self.service.runner_implementation_hash,
            "implementation_hash": self.service.runner_implementation_hash,
            "error_code": None,
        }

    async def issue(self) -> dict[str, Any]:
        async with self._permit_lock:
            binding = self._sealed_binding()
            return self.store.issue_codex_canary_execution_permit(binding, ttl_seconds=self.PERMIT_TTL_SECONDS)

    async def arm(self, permit_nonce: str | None) -> dict[str, Any]:
        if not isinstance(permit_nonce, str) or not permit_nonce:
            raise PolicyError("codex_canary_permit_required")
        binding = self._sealed_binding()
        self.store.validate_codex_canary_execution_permit(permit_nonce, binding)
        try:
            return await self.service.arm_from_execution_permit(binding)
        except PolicyError as exc:
            if str(exc) == "execution_binding_changed":
                self.store.invalidate_codex_canary_execution_permit(permit_nonce, "execution_binding_changed")
            raise

    async def run(self, permit_nonce: str | None, canary_nonce: str | None) -> dict[str, Any]:
        """The legacy endpoint stays disabled in Phase 4.2."""
        return await self._run_consumed_capabilities(permit_nonce, canary_nonce, one_shot=False)

    async def run_one_shot(self, permit_nonce: str | None, canary_nonce: str | None) -> dict[str, Any]:
        """Select the sealed WSL runner for one already-authorized request."""
        return await self._run_consumed_capabilities(permit_nonce, canary_nonce, one_shot=True)

    async def _run_consumed_capabilities(
        self,
        permit_nonce: str | None,
        canary_nonce: str | None,
        *,
        one_shot: bool,
    ) -> dict[str, Any]:
        # Both capabilities are claimed before any new binding check or runner
        # selection.  Thus failures cannot leave an authorization reusable.
        # The one-shot transaction additionally creates an immutable execution
        # claim.  It contains only IDs and sealed hashes, never either nonce.
        expected: dict[str, str] | None = None
        try:
            expected = self._sealed_binding()
        except PolicyError:
            # Still consume a valid capability pair before reporting an
            # environment change.  It cannot be retried after a failed
            # revalidation.
            claimed = self.store.consume_codex_canary_execution_permit_and_window(permit_nonce, canary_nonce)
            window = claimed["window"]
            self.service.record_blocked_execution_attempt(window, "execution_binding_changed")
            self.store.mark_codex_canary_execution_permit_blocked(claimed["permit"]["permit_id"], "execution_binding_changed")
            raise PolicyError("execution_binding_changed")
        if one_shot:
            claim = self.store.claim_codex_canary_one_shot_execution(permit_nonce, canary_nonce, expected)
            # A claim is authorization bookkeeping, not a spawn measurement.
            # It remains an ESTIMATED plan event with zero actual processes.
            self.store.record_codex_process_canary_ledger(claim, "CLAIM")
            return await self.service.run_one_shot_execution_claim(claim, expected)
        claimed = self.store.consume_codex_canary_execution_permit_and_window(permit_nonce, canary_nonce)
        permit = claimed["permit"]
        window = claimed["window"]
        try:
            current = self._sealed_binding()
        except PolicyError as exc:
            self.service.record_blocked_execution_attempt(window, "execution_binding_changed")
            self.store.mark_codex_canary_execution_permit_blocked(permit["permit_id"], "execution_binding_changed")
            raise PolicyError("execution_binding_changed") from exc
        if current["binding_hash"] != claimed["binding_hash"]:
            self.service.record_blocked_execution_attempt(window, "execution_binding_changed")
            self.store.mark_codex_canary_execution_permit_blocked(permit["permit_id"], "execution_binding_changed")
            raise PolicyError("execution_binding_changed")
        return await self.service.run_claimed_execution_permit(window, current)

    def permit_status(self) -> dict[str, Any]:
        return self.store.codex_canary_execution_permit()
