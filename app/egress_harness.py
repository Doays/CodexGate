"""Fake-runner-only verification for the sealed local egress contract.

No code in this module opens a network socket, creates an AF_UNIX listener,
launches WSL/bubblewrap, or starts Codex.  The interfaces make the exact future
runtime boundary testable while keeping Phase 2 strictly local and inert.
"""
from __future__ import annotations

import asyncio
import shutil
import tempfile
import time
import uuid
from dataclasses import dataclass
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
HARNESS_POLICY_VERSION = "sealed-egress-harness-v2"


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
    stdout_bytes: int = 0
    stderr_bytes: int = 0
    process_terminated: bool = True


class HarnessRunner(Protocol):
    async def run(self, contract: Mapping[str, Any], launch_spec: Mapping[str, Any]) -> HarnessExecution: ...


class DisabledHarnessRunner:
    """The production API is deliberately inert until a later authorization."""

    async def run(self, contract: Mapping[str, Any], launch_spec: Mapping[str, Any]) -> HarnessExecution:
        raise PolicyError("fake_runner_required")


class FakeHarnessRunner:
    """A deterministic no-I/O runner for unit tests and this implementation stage."""

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
        )


def public_harness_result(result: Mapping[str, Any] | None) -> dict[str, Any]:
    if not isinstance(result, Mapping):
        return {"status": HARNESS_BLOCKED, "start_allowed": False, "error_code": "harness_not_run"}
    fields = (
        "harness_id", "contract_hash", "status", "started_at", "finished_at", "error_code",
        "request_bytes", "response_bytes", "response_hash", "status_code", "relay_connections",
        "broker_connections", "relay_requests", "broker_requests", "local_duration_ms",
        "resources_cleaned", "reused", "start_allowed",
    )
    return {field: result.get(field) for field in fields if field in result}


class SealedEgressHarnessService:
    _locks: dict[str, asyncio.Lock] = {}

    def __init__(self, store, contract_service, runner: HarnessRunner | None = None):
        self.store = store
        self.contract_service = contract_service
        self.runner = runner or DisabledHarnessRunner()

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
        return {"status": READY, "contract_hash": contract["contract_hash"], "start_allowed": False, "error_code": None}

    async def run(self) -> dict[str, Any]:
        readiness = self.ready()
        if readiness["status"] != READY:
            return readiness
        contract = self.contract_service.current()
        assert isinstance(contract, Mapping)
        contract_hash = contract["contract_hash"]
        lock = self._locks.setdefault(f"{self.store.db_path}:{contract_hash}", asyncio.Lock())
        async with lock:
            existing = self.store.egress_harness_result(contract_hash)
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
            "local_duration_ms": 0, "resources_cleaned": False, "start_allowed": False,
        }
        self.store.begin_egress_harness(running)
        began = time.monotonic()
        temp_root: Path | None = None
        result: dict[str, Any]
        try:
            temp_root = Path(tempfile.mkdtemp(prefix="codexgate-egress-harness-"))
            # A real runner would receive only this private socket directory.
            # The actual host path remains private and is represented only by
            # the fixed placeholder in the pure launch specification.
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
                "error_code": None,
            }
        except asyncio.TimeoutError:
            result = {**running, "status": ERROR, "error_code": "harness_timeout"}
        except PolicyError as exc:
            code = str(exc)
            result = {**running, "status": ERROR, "error_code": code if code in {
                "fake_runner_required", "sealed_broker_socket_policy_was_violated", "socket_policy_violation",
                "output_limit", "process_termination_failed", "connection_count_invalid", "request_count_invalid",
                "response_invalid", "sensitive_headers_not_removed",
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

    @staticmethod
    def _validate_execution(execution: HarnessExecution) -> None:
        if execution.stdout_bytes < 0 or execution.stderr_bytes < 0 or execution.stdout_bytes + execution.stderr_bytes > PROCESS_OUTPUT_LIMIT_BYTES:
            raise PolicyError("output_limit")
        if not execution.process_terminated:
            raise PolicyError("process_termination_failed")
        if (execution.relay_connections, execution.broker_connections) != (1, 1):
            raise PolicyError("connection_count_invalid")
        if (execution.relay_requests, execution.broker_requests) != (1, 1):
            raise PolicyError("request_count_invalid")
        counts = execution.socket_counts
        if counts.get("af_unix") != 1 or any(counts.get(name, 0) != 0 for name in ("tcp", "udp", "dns")):
            raise PolicyError("socket_policy_violation")
        if execution.status_code != 200 or not isinstance(execution.response_hash, str) or len(execution.response_hash) != 64:
            raise PolicyError("response_invalid")
        if not execution.sensitive_headers_removed:
            raise PolicyError("sensitive_headers_not_removed")
