"""Verification service for the sealed local egress contract.

No code in this module opens a network socket, creates an AF_UNIX listener,
launches WSL/bubblewrap, or starts Codex.  Phase 3 adds a fixed-argv WSL
runner, but the application deliberately continues to select this fake runner
until a separately authorized execution stage.
"""
from __future__ import annotations

import asyncio
import hashlib
import shutil
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Protocol

from .egress_broker import FakeUnixBroker, fixed_client_request
from .egress_contract import AUTH_UNCONFIGURED
from .egress_relay import (
    HARNESS_TOTAL_TIMEOUT_SECONDS,
    PROCESS_OUTPUT_LIMIT_BYTES,
    RELAY_REQUEST_TIMEOUT_SECONDS,
    RELAY_START_TIMEOUT_SECONDS,
    FakeLoopbackRelay,
    build_relay_launch_spec,
)
from .policy import PolicyError


READY = "READY"
RUNNING = "RUNNING"
PASSED = "PASSED"
ERROR = "ERROR"
HARNESS_BLOCKED = "BLOCKED"
POLICY_VIOLATION = "POLICY_VIOLATION"
HARNESS_POLICY_VERSION = "sealed-egress-harness-v3"
FAKE_RUNNER_KIND = "FAKE"
FAKE_RUNNER_VERSION = "sealed-egress-fake-runner-v1"
FAKE_RUNNER_IMPLEMENTATION_HASH = hashlib.sha256(FAKE_RUNNER_VERSION.encode("ascii")).hexdigest()
WSL_RUNNER_KIND = "WSL_SUPERVISOR"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class HarnessExecution:
    relay_connections: int
    broker_connections: int
    relay_requests: int
    broker_requests: int
    request_bytes: int
    response_bytes: int
    response_hash: str
    status_code: int
    sensitive_headers_removed: bool
    socket_counts: Mapping[str, int]
    broker_socket_counts: Mapping[str, int] = field(default_factory=dict)
    relay_socket_counts: Mapping[str, int] = field(default_factory=dict)
    stdout_bytes: int = 0
    stderr_bytes: int = 0
    process_terminated: bool = True
    resources_cleaned: bool = True
    local_processes: int = 0
    request_hash: str | None = None
    runner_kind: str = FAKE_RUNNER_KIND
    runner_version: str = FAKE_RUNNER_VERSION
    runner_implementation_hash: str = FAKE_RUNNER_IMPLEMENTATION_HASH


class HarnessRunner(Protocol):
    async def run(self, contract: Mapping[str, Any], launch_spec: Mapping[str, Any]) -> HarnessExecution: ...


class DisabledHarnessRunner:
    """The production API is deliberately inert until a later authorization."""

    runner_kind = FAKE_RUNNER_KIND
    runner_version = FAKE_RUNNER_VERSION
    runner_implementation_hash = FAKE_RUNNER_IMPLEMENTATION_HASH

    async def run(self, contract: Mapping[str, Any], launch_spec: Mapping[str, Any]) -> HarnessExecution:
        raise PolicyError("fake_runner_required")


class FakeHarnessRunner:
    """A deterministic no-I/O runner for unit tests and this implementation stage."""

    runner_kind = FAKE_RUNNER_KIND
    runner_version = FAKE_RUNNER_VERSION
    runner_implementation_hash = FAKE_RUNNER_IMPLEMENTATION_HASH

    def __init__(self, *, socket_counts: Mapping[str, int] | None = None, stdout_bytes: int = 0,
                 stderr_bytes: int = 0, delay_seconds: float = 0.0, terminate: bool = True):
        self.socket_counts = dict(socket_counts or {"af_unix": 1, "tcp": 0, "udp": 0, "dns": 0})
        self.stdout_bytes = stdout_bytes
        self.stderr_bytes = stderr_bytes
        self.delay_seconds = delay_seconds
        self.terminate = terminate
        self.calls = 0

    async def run(self, contract: Mapping[str, Any], launch_spec: Mapping[str, Any]) -> HarnessExecution:
        self.calls += 1
        if self.delay_seconds:
            await asyncio.sleep(self.delay_seconds)
        broker = FakeUnixBroker(contract, socket_counts=self.socket_counts)
        relay = FakeLoopbackRelay(broker)
        relay.accept_connection()
        method, path, headers, body = fixed_client_request()
        result = relay.forward(method, path, headers, body)
        return HarnessExecution(
            relay_connections=relay.connections,
            broker_connections=broker.connections,
            relay_requests=relay.requests,
            broker_requests=broker.requests,
            request_bytes=result.request_bytes,
            response_bytes=result.response_bytes,
            response_hash=result.response_hash,
            status_code=result.status_code,
            sensitive_headers_removed=result.sensitive_headers_removed,
            socket_counts=self.socket_counts,
            stdout_bytes=self.stdout_bytes,
            stderr_bytes=self.stderr_bytes,
            process_terminated=self.terminate,
            resources_cleaned=True,
            local_processes=0,
            request_hash=None,
            runner_kind=self.runner_kind,
            runner_version=self.runner_version,
            runner_implementation_hash=self.runner_implementation_hash,
        )


def public_harness_result(result: Mapping[str, Any] | None) -> dict[str, Any]:
    if not isinstance(result, Mapping):
        return {"status": HARNESS_BLOCKED, "start_allowed": False, "error_code": "harness_not_run"}
    fields = (
        "harness_id", "contract_hash", "status", "started_at", "finished_at", "error_code",
        "request_bytes", "response_bytes", "response_hash", "status_code", "relay_connections",
        "broker_connections", "relay_requests", "broker_requests", "local_duration_ms",
        "resources_cleaned", "local_processes", "runner_kind", "runner_version",
        "runner_implementation_hash", "reused", "start_allowed",
    )
    return {field: result.get(field) for field in fields if field in result}


class SealedEgressHarnessService:
    _locks: dict[str, asyncio.Lock] = {}

    def __init__(self, store, contract_service, runner: HarnessRunner | None = None):
        self.store = store
        self.contract_service = contract_service
        self.runner = runner or DisabledHarnessRunner()
        self.runner_kind = getattr(self.runner, "runner_kind", None)
        self.runner_version = getattr(self.runner, "runner_version", None)
        self.runner_implementation_hash = getattr(self.runner, "runner_implementation_hash", None)
        if self.runner_kind not in {FAKE_RUNNER_KIND, WSL_RUNNER_KIND}:
            raise PolicyError("harness runner kind is invalid")
        if not isinstance(self.runner_version, str) or not self.runner_version:
            raise PolicyError("harness runner version is invalid")
        if (
            not isinstance(self.runner_implementation_hash, str)
            or len(self.runner_implementation_hash) != 64
            or any(char not in "0123456789abcdef" for char in self.runner_implementation_hash)
        ):
            raise PolicyError("harness runner implementation hash is invalid")

    def ready(self) -> dict[str, Any]:
        contract = self.contract_service.current()
        if not isinstance(contract, Mapping):
            return {"status": HARNESS_BLOCKED, "start_allowed": False, "error_code": "contract_missing"}
        if contract.get("status") != AUTH_UNCONFIGURED:
            return {"status": HARNESS_BLOCKED, "start_allowed": False, "error_code": "contract_not_auth_unconfigured"}
        if not isinstance(contract.get("contract_hash"), str) or contract.get("preview_hash") != contract.get("contract_hash"):
            return {"status": HARNESS_BLOCKED, "start_allowed": False, "error_code": "contract_hash_mismatch"}
        if not isinstance(contract.get("runtime_fingerprint"), str) or not isinstance(contract.get("isolation_cache_key"), str):
            return {"status": HARNESS_BLOCKED, "start_allowed": False, "error_code": "contract_binding_missing"}
        stored, error_code = self.contract_service.immutable_execution_contract()
        if stored is None:
            return {"status": HARNESS_BLOCKED, "start_allowed": False, "error_code": error_code or "stored_contract_required"}
        return {
            "status": READY,
            "contract_hash": contract["contract_hash"],
            "runner_kind": self.runner_kind,
            "runner_version": self.runner_version,
            "runner_implementation_hash": self.runner_implementation_hash,
            "start_allowed": False,
            "error_code": None,
        }

    async def run(self) -> dict[str, Any]:
        readiness = self.ready()
        if readiness["status"] != READY:
            return readiness
        contract, error_code = self.contract_service.immutable_execution_contract()
        if contract is None:
            return {"status": HARNESS_BLOCKED, "start_allowed": False, "error_code": error_code or "stored_contract_required"}
        contract_hash = contract["contract_hash"]
        lock_key = (
            f"{self.store.db_path}:{contract_hash}:{self.runner_kind}:"
            f"{self.runner_version}:{self.runner_implementation_hash}"
        )
        lock = self._locks.setdefault(lock_key, asyncio.Lock())
        async with lock:
            existing = self.store.egress_harness_result(
                contract_hash, self.runner_kind, self.runner_version, self.runner_implementation_hash,
            )
            if existing and existing.get("status") == PASSED:
                return public_harness_result({**existing, "reused": True})
            return await self._run_once(contract)

    async def _run_once(self, contract: Mapping[str, Any]) -> dict[str, Any]:
        started_at = _now()
        harness_id = str(uuid.uuid4())
        running = {
            "harness_id": harness_id, "contract_hash": contract["contract_hash"], "status": RUNNING,
            "started_at": started_at, "finished_at": None, "error_code": None,
            "request_bytes": 0, "response_bytes": 0, "response_hash": None, "status_code": None,
            "relay_connections": 0, "broker_connections": 0, "relay_requests": 0, "broker_requests": 0,
            "local_duration_ms": 0, "resources_cleaned": False, "local_processes": 0,
            "runner_kind": self.runner_kind, "runner_version": self.runner_version,
            "runner_implementation_hash": self.runner_implementation_hash,
            "request_hash": None, "start_allowed": False,
        }
        self.store.begin_egress_harness(running)
        began = time.monotonic()
        temp_root: Path | None = None
        result: dict[str, Any]
        try:
            # Phase 2's fake runner gets a private local sentinel directory.
            # The Phase 3 WSL supervisor creates its private 0700 directory
            # inside WSL instead, so no Windows temp path is ever bound.
            if getattr(self.runner, "requires_host_temp", True):
                temp_root = Path(tempfile.mkdtemp(prefix="codexgate-egress-harness-"))
                temp_root.mkdir(mode=0o700, exist_ok=True)
                (temp_root / "socket").mkdir(mode=0o700)
            launch_spec = build_relay_launch_spec(contract)
            execution = await asyncio.wait_for(
                self.runner.run(contract, launch_spec), timeout=HARNESS_TOTAL_TIMEOUT_SECONDS,
            )
            self._validate_execution(execution)
            result = {
                **running,
                "status": PASSED,
                "request_bytes": execution.request_bytes,
                "response_bytes": execution.response_bytes,
                "response_hash": execution.response_hash,
                "status_code": execution.status_code,
                "relay_connections": execution.relay_connections,
                "broker_connections": execution.broker_connections,
                "relay_requests": execution.relay_requests,
                "broker_requests": execution.broker_requests,
                "request_hash": execution.request_hash,
                "local_processes": execution.local_processes,
                "runner_kind": execution.runner_kind,
                "runner_version": execution.runner_version,
                "runner_implementation_hash": execution.runner_implementation_hash,
                "error_code": None,
            }
        except asyncio.TimeoutError:
            result = {**running, "status": ERROR, "error_code": "harness_timeout"}
        except PolicyError as exc:
            code = str(exc)
            final_status = POLICY_VIOLATION if code in {
                "policy_violation", "runner_implementation_mismatch",
                "broker_socket_policy_violation", "relay_socket_policy_violation",
                "sensitive_headers_not_removed",
            } else ERROR
            result = {**running, "status": final_status, "error_code": code if code in {
                "fake_runner_required", "sealed_broker_socket_policy_was_violated", "socket_policy_violation",
                "output_limit", "process_termination_failed", "connection_count_invalid", "request_count_invalid",
                "response_invalid", "sensitive_headers_not_removed", "stored_contract_required", "stored_contract_invalid",
                "contract_provider_changed", "contract_binding_changed", "runtime_not_ready", "runtime_not_sealed",
                "isolation_not_safe", "runtime_identity_missing", "isolation_identity_missing", "distro_not_ubuntu",
                "isolation_expiring", "isolation_expiry_invalid", "repro_missing", "repro_not_safe",
                "repro_incomplete", "repro_binding_changed", "repro_result_invalid", "repro_key_invalid",
                "runner_identity_mismatch",
                "runner_implementation_mismatch", "broker_socket_policy_violation",
                "relay_socket_policy_violation",
                "wsl_unavailable", "wsl_executable_invalid", "supervisor_process_error",
                "supervisor_frame_encoding", "supervisor_frame_count", "supervisor_frame_missing",
                "supervisor_frame_base64", "supervisor_frame_json", "supervisor_frame_schema",
                "supervisor_frame_not_canonical", "supervisor_frame_status", "supervisor_frame_digest",
                "supervisor_frame_hash", "supervisor_frame_bytes", "resource_cleanup_failed", "policy_violation",
            } else "harness_policy_error"}
        except Exception:
            result = {**running, "status": ERROR, "error_code": "harness_error"}
        finally:
            if temp_root is not None:
                shutil.rmtree(temp_root, ignore_errors=True)
            cleaned = temp_root is None or not temp_root.exists()
            result = {
                **result,
                "finished_at": _now(),
                "local_duration_ms": max(0, round((time.monotonic() - began) * 1000)),
                "resources_cleaned": cleaned,
                "start_allowed": False,
            }
        saved = self.store.finish_egress_harness(result)
        self.store.record_egress_harness_ledger(saved)
        return public_harness_result(saved)

    def _validate_execution(self, execution: HarnessExecution) -> None:
        if execution.runner_kind != self.runner_kind or execution.runner_version != self.runner_version:
            raise PolicyError("runner_identity_mismatch")
        if execution.runner_implementation_hash != self.runner_implementation_hash:
            raise PolicyError("runner_implementation_mismatch")
        if execution.stdout_bytes < 0 or execution.stderr_bytes < 0 or execution.stdout_bytes + execution.stderr_bytes > PROCESS_OUTPUT_LIMIT_BYTES:
            raise PolicyError("output_limit")
        if not execution.process_terminated:
            raise PolicyError("process_termination_failed")
        if not execution.resources_cleaned:
            raise PolicyError("resource_cleanup_failed")
        if not isinstance(execution.local_processes, int) or isinstance(execution.local_processes, bool) or execution.local_processes < 0:
            raise PolicyError("process_termination_failed")
        if (execution.relay_connections, execution.broker_connections) != (1, 1):
            raise PolicyError("connection_count_invalid")
        if (execution.relay_requests, execution.broker_requests) != (1, 1):
            raise PolicyError("request_count_invalid")
        if self.runner_kind == WSL_RUNNER_KIND:
            broker = execution.broker_socket_counts
            relay = execution.relay_socket_counts
            if (
                broker.get("pathname_af_unix") != 1
                or any(broker.get(name, 0) != 0 for name in ("inet_attempts", "udp_attempts", "dns_attempts"))
            ):
                raise PolicyError("broker_socket_policy_violation")
            if (
                relay.get("af_unix_connections") != 1
                or relay.get("loopback_tcp_listeners") != 1
                or relay.get("loopback_tcp_connections") != 1
                or any(relay.get(name, 0) != 0 for name in ("non_loopback_attempts", "udp_attempts", "dns_attempts"))
            ):
                raise PolicyError("relay_socket_policy_violation")
        else:
            counts = execution.socket_counts
            if counts.get("af_unix") != 1 or any(counts.get(name, 0) != 0 for name in ("tcp", "udp", "dns")):
                raise PolicyError("socket_policy_violation")
        if execution.status_code != 200 or not isinstance(execution.response_hash, str) or len(execution.response_hash) != 64:
            raise PolicyError("response_invalid")
        if not execution.sensitive_headers_removed:
            raise PolicyError("sensitive_headers_not_removed")


class ActualWSLHarnessGate:
    """One-time local authorization in front of the actual WSL runner.

    Production keeps ``enabled`` false in Phase 3.1.  Tests may enable the
    gate with an injected non-process runner to exercise the capability
    lifecycle without starting WSL.
    """

    def __init__(self, store, service: SealedEgressHarnessService, *, enabled: bool = False):
        self.store = store
        self.service = service
        self.enabled = bool(enabled)
        if service.runner_kind != WSL_RUNNER_KIND:
            raise PolicyError("actual harness requires the WSL runner")

    def arm(self) -> dict[str, Any]:
        if not self.enabled:
            raise PolicyError("actual_wsl_harness_disabled")
        readiness = self.service.ready()
        if readiness.get("status") != READY:
            raise PolicyError(str(readiness.get("error_code") or "actual_harness_not_ready"))
        return self.store.issue_egress_harness_arm(
            readiness["contract_hash"],
            self.service.runner_kind,
            self.service.runner_version,
            self.service.runner_implementation_hash,
            ttl_seconds=300,
        )

    async def run(self, arm_nonce: str | None) -> dict[str, Any]:
        if not self.enabled:
            raise PolicyError("actual_wsl_harness_disabled")
        readiness = self.service.ready()
        if readiness.get("status") != READY:
            raise PolicyError(str(readiness.get("error_code") or "actual_harness_not_ready"))
        self.store.consume_egress_harness_arm(
            arm_nonce or "",
            readiness["contract_hash"],
            self.service.runner_kind,
            self.service.runner_version,
            self.service.runner_implementation_hash,
        )
        return await self.service.run()
