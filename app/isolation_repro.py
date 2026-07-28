"""Deterministic, local-only repeatability checks for the WSL2 bubblewrap probe.

This module deliberately has no app-server integration.  It only exercises a fixed
read-only workload and persists a redacted summary.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import re
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .isolation_wsl import (
    MAX_CAPTURED_OUTPUT_BYTES,
    ProcessResult,
    LocalWSLCommandRunner,
    WSLCommandRunner,
    WSL2_BWRAP,
    SAFE_CANDIDATE,
)
from .policy import PolicyError, forbidden_workspace_reason, sha256_json

REPRO_VERSION = "wsl2-bwrap-repro-v1"
REPRO_RUNS = 10
RUN_TIMEOUT_SECONDS = 15
TOTAL_TIMEOUT_SECONDS = 180

SAFE_REPRODUCIBLE = "SAFE_REPRODUCIBLE"
NONDETERMINISTIC = "NONDETERMINISTIC"
UNSAFE_HOST_FS = "UNSAFE_HOST_FS"
UNSAFE_WRITE = "UNSAFE_WRITE"
UNSAFE_NETWORK = "UNSAFE_NETWORK"
ERROR = "ERROR"
RUNNING = "RUNNING"
REJECTED = "REJECTED"

FIXTURE_RELATIVE_PATH = "fixture.bin"
WRITE_DENIAL_RELATIVE_PATH = "write-canary"


def build_repro_fixture_bytes() -> bytes:
    """Return the one immutable, LF-terminated UTF-8 fixture byte sequence."""
    return (
        b"CodexGate reproducibility fixture v1\n"
        b"UTF-8: \xce\xa9\xe7\x8c\x97\n"
        b'{"fixture":"codexgate-repro-v1","version":1}\n'
    )


_FIXTURE_BYTES = build_repro_fixture_bytes()
_FIXTURE_HASH = hashlib.sha256(_FIXTURE_BYTES).hexdigest()
FRAME_PREFIX = "CODEXGATE_REPRO_V1:"
FRAME_SCHEMA_VERSION = "1"
_FRAME_FIELDS = ("schema_version", "iteration", "fixture_sha256", "capsule_read", "outside_read",
                 "host_read", "capsule_write", "tmp_write", "network")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_B64URL = re.compile(r"^[A-Za-z0-9_-]+={0,2}$")

_WORKLOAD_TEMPLATE = r'''from pathlib import Path
import base64, errno, hashlib, json, os, socket, sys

def read(path):
    try:
        Path(path).read_bytes()
        return "READ_OK"
    except (PermissionError, FileNotFoundError):
        return "READ_DENIED"
    except Exception:
        return "READ_ERROR"

def write(path):
    try:
        Path(path).write_bytes(b"x")
        return "WRITE_OK"
    except PermissionError:
        return "WRITE_DENIED"
    except OSError as exc:
        return "WRITE_DENIED" if exc.errno in (errno.EACCES, errno.EPERM, errno.EROFS) else "WRITE_ERROR"
    except Exception:
        return "WRITE_ERROR"

inside = Path("/work/__FIXTURE_RELATIVE_PATH__").open("rb").read()
payload = {
    "schema_version": "1",
    "iteration": int(sys.argv[1]),
    "fixture_sha256": hashlib.sha256(inside).hexdigest(),
    "capsule_read": read("/work/__FIXTURE_RELATIVE_PATH__"),
    "outside_read": read("/outside-data/canary"),
    "host_read": read("/mnt/c/canary"),
    "capsule_write": write("/work/__WRITE_DENIAL_RELATIVE_PATH__"),
}
try:
    p = Path("/tmp/repro-canary")
    p.write_bytes(b"x")
    _ = p.read_bytes()
    p.unlink()
    tmp = "TMP_WRITE_OK"
except Exception:
    tmp = "TMP_WRITE_ERROR"
payload["tmp_write"] = tmp
try:
    socket.create_connection(("127.0.0.1", 9), timeout=1)
    net = "NETWORK_OK"
except Exception:
    net = "NETWORK_DENIED"
payload["network"] = net
encoded = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
frame = b"CODEXGATE_REPRO_V1:" + base64.urlsafe_b64encode(encoded).rstrip(b"=") + b"\n"
os.write(1, frame)
'''
_WORKLOAD = _WORKLOAD_TEMPLATE.replace("__FIXTURE_RELATIVE_PATH__", FIXTURE_RELATIVE_PATH).replace(
    "__WRITE_DENIAL_RELATIVE_PATH__", WRITE_DENIAL_RELATIVE_PATH
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ReproProtocolError(ValueError):
    def __init__(self, code: str, diagnostic: dict[str, Any]):
        super().__init__(code)
        self.code = code
        self.diagnostic = diagnostic


def _stream_bytes(result: ProcessResult, stream: str) -> bytes:
    raw = getattr(result, f"{stream}_bytes", None)
    if isinstance(raw, bytes):
        return raw
    value = getattr(result, stream)
    return value.encode("utf-8", errors="strict")


def _diagnostic(result: ProcessResult, *, frame_count: int, error_code: str | None, fixture_bytes: int | None = None) -> dict[str, Any]:
    stdout = _stream_bytes(result, "stdout")
    stderr = _stream_bytes(result, "stderr")
    return {
        "exit_code": result.exit_code,
        "stdout_bytes": len(stdout),
        "stderr_bytes": len(stderr),
        "frame_count": frame_count,
        "error_code": error_code,
        "fixture_bytes": fixture_bytes,
    }


def _decode_frame(token: str) -> dict[str, Any]:
    if not _B64URL.fullmatch(token):
        raise ValueError("frame_base64_invalid")
    padding = len(token) - len(token.rstrip("="))
    core = token.rstrip("=")
    if padding > 2 or len(core) % 4 == 1 or padding and (len(token) % 4):
        raise ValueError("frame_base64_invalid")
    padded = core + "=" * ((4 - len(core) % 4) % 4)
    try:
        decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
        text = decoded.decode("utf-8", errors="strict")
        payload = json.loads(text, parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
    except (ValueError, UnicodeError, json.JSONDecodeError):
        raise ValueError("frame_json_invalid")
    if not isinstance(payload, dict) or set(payload) != set(_FRAME_FIELDS):
        raise ValueError("frame_schema_invalid")
    canonical = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if canonical != decoded:
        raise ValueError("frame_json_invalid")
    return payload


def parse_frame(result: ProcessResult, *, expected_iteration: int, expected_fixture_sha256: str = _FIXTURE_HASH,
                expected_fixture_bytes: int = len(_FIXTURE_BYTES)) -> tuple[dict[str, Any], dict[str, Any]]:
    """Strictly parse one frame from stdout; stderr is only diagnostic metadata."""
    try:
        stdout = _stream_bytes(result, "stdout")
        stderr = _stream_bytes(result, "stderr")
    except UnicodeError:
        raise ReproProtocolError("frame_utf8_invalid", {"exit_code": result.exit_code, "stdout_bytes": 0,
                                                         "stderr_bytes": 0, "frame_count": 0,
                                                         "error_code": "frame_utf8_invalid"})
    if len(stdout) + len(stderr) > MAX_CAPTURED_OUTPUT_BYTES:
        raise ReproProtocolError("output_limit", _diagnostic(result, frame_count=0, error_code="output_limit"))
    if result.exit_code != 0:
        raise ReproProtocolError("process_error", _diagnostic(result, frame_count=0, error_code="process_error"))
    try:
        text = stdout.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise ReproProtocolError("frame_utf8_invalid", _diagnostic(result, frame_count=0, error_code="frame_utf8_invalid"))
    raw_lines = text.splitlines()
    nonempty_raw = [line for line in raw_lines if line.strip()]
    if any(line != line.strip() for line in nonempty_raw):
        raise ReproProtocolError("frame_extra_output", _diagnostic(result, frame_count=0, error_code="frame_extra_output"))
    nonempty = list(nonempty_raw)
    frame_lines = [line for line in nonempty if line.startswith(FRAME_PREFIX)]
    frame_count = len(frame_lines)
    if frame_count == 0:
        code = "frame_missing" if not nonempty else "frame_extra_output"
        raise ReproProtocolError(code, _diagnostic(result, frame_count=0, error_code=code))
    if frame_count > 1:
        raise ReproProtocolError("frame_duplicate", _diagnostic(result, frame_count=frame_count, error_code="frame_duplicate"))
    if len(nonempty) != 1:
        raise ReproProtocolError("frame_extra_output", _diagnostic(result, frame_count=frame_count, error_code="frame_extra_output"))
    try:
        payload = _decode_frame(frame_lines[0][len(FRAME_PREFIX):])
    except ValueError as exc:
        code = str(exc)
        raise ReproProtocolError(code, _diagnostic(result, frame_count=1, error_code=code)) from exc
    if payload["schema_version"] != FRAME_SCHEMA_VERSION:
        raise ReproProtocolError("frame_schema_invalid", _diagnostic(result, frame_count=1, error_code="frame_schema_invalid"))
    if isinstance(payload["iteration"], bool) or not isinstance(payload["iteration"], int):
        raise ReproProtocolError("frame_schema_invalid", _diagnostic(result, frame_count=1, error_code="frame_schema_invalid"))
    if any(not isinstance(payload[field], str) for field in _FRAME_FIELDS if field not in {"iteration"}):
        raise ReproProtocolError("frame_schema_invalid", _diagnostic(result, frame_count=1, error_code="frame_schema_invalid"))
    if payload["iteration"] != expected_iteration:
        raise ReproProtocolError("frame_iteration_mismatch", _diagnostic(result, frame_count=1, error_code="frame_iteration_mismatch"))
    if (not _HEX64.fullmatch(payload["fixture_sha256"])
            or not hmac.compare_digest(payload["fixture_sha256"], expected_fixture_sha256)):
        raise ReproProtocolError("frame_fixture_mismatch", _diagnostic(result, frame_count=1, error_code="frame_fixture_mismatch", fixture_bytes=expected_fixture_bytes))
    expected = {"capsule_read": "READ_OK", "outside_read": "READ_DENIED", "host_read": "READ_DENIED",
                "capsule_write": "WRITE_DENIED", "tmp_write": "TMP_WRITE_OK", "network": "NETWORK_DENIED"}
    if any(payload[key] != value for key, value in expected.items()):
        raise ReproProtocolError("frame_value_invalid", _diagnostic(result, frame_count=1, error_code="frame_value_invalid"))
    return payload, _diagnostic(result, frame_count=1, error_code=None)


parse_repro_frame = parse_frame
ReproFrameError = ReproProtocolError


def canonical_result_hash(markers: dict[str, Any]) -> str:
    """Hash only normalized marker values; no output or paths are retained."""
    if set(markers) != set(_FRAME_FIELDS):
        raise ValueError("frame_schema_invalid")
    # Only the fixture identity and six boundary outcomes define stability;
    # schema version and iteration are protocol metadata.
    stable_fields = ("fixture_sha256", "capsule_read", "outside_read", "host_read",
                     "capsule_write", "tmp_write", "network")
    return sha256_json({key: markers[key] for key in stable_fields})


def public_repro_result(result: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(result, dict):
        return {"status": "UNCONFIGURED", "requested_runs": REPRO_RUNS, "completed_runs": 0, "success_count": 0}
    fields = ("repro_id", "cache_key", "config_hash", "tool_fingerprint", "status", "requested_runs",
              "completed_runs", "success_count", "result_hash", "duration_ms", "started_at", "finished_at",
              "error_code", "diagnostic", "reused")
    return {field: result.get(field) for field in fields if field in result}


class IsolationReproService:
    _locks: dict[str, asyncio.Lock] = {}

    def __init__(self, store, isolation_service=None, runner: WSLCommandRunner | None = None):
        self.store = store
        self.isolation_service = isolation_service
        self.runner = runner or LocalWSLCommandRunner()

    async def run(self, *, config_hash: str | None = None, tool_fingerprint: str | None = None) -> dict[str, Any]:
        if forbidden_workspace_reason(self.store.root):
            return self._rejected("data_root_forbidden")
        isolation = self.store.wsl_isolation_result()
        if isolation.get("status") != SAFE_CANDIDATE:
            return self._rejected("isolation_not_safe")
        try:
            if datetime.fromisoformat(str(isolation.get("expires_at"))) <= datetime.now(timezone.utc):
                return self._rejected("isolation_expired")
        except (TypeError, ValueError):
            return self._rejected("isolation_expiry_invalid")
        current_config = isolation.get("config_hash")
        current_tool = isolation.get("tool_fingerprint")
        if not isinstance(current_config, str) or not isinstance(current_tool, str):
            return self._rejected("isolation_identity_missing")
        if config_hash is not None and config_hash != current_config:
            return self._rejected("config_hash_mismatch")
        if tool_fingerprint is not None and tool_fingerprint != current_tool:
            return self._rejected("tool_fingerprint_mismatch")
        config_hash, tool_fingerprint = current_config, current_tool
        key = sha256_json({"config_hash": config_hash, "tool_fingerprint": tool_fingerprint, "repro_version": REPRO_VERSION})
        lock = self._locks.setdefault(f"{self.store.db_path}:{key}", asyncio.Lock())
        async with lock:
            cached = self.store.wsl_isolation_repro(key)
            if cached and cached.get("status") == SAFE_REPRODUCIBLE:
                return {**public_repro_result(cached), "reused": True}
            started_at = _now()
            repro_id = str(uuid.uuid4())
            running = {"repro_id": repro_id, "cache_key": key, "config_hash": config_hash,
                       "tool_fingerprint": tool_fingerprint, "status": RUNNING, "requested_runs": REPRO_RUNS,
                       "completed_runs": 0, "success_count": 0, "duration_ms": 0, "started_at": started_at}
            self.store.save_wsl_isolation_repro(running)
            started = time.monotonic()
            result = await self._execute(repro_id, config_hash, tool_fingerprint, key)
            result.update({"repro_id": repro_id, "cache_key": key, "config_hash": config_hash,
                           "tool_fingerprint": tool_fingerprint, "started_at": started_at,
                           "duration_ms": max(0, round((time.monotonic() - started) * 1000)),
                           "finished_at": _now()})
            saved = self.store.save_wsl_isolation_repro(result)
            self.store.record_wsl_isolation_repro_ledger(saved)
            return public_repro_result(saved)

    reproduce = run
    run_repro = run

    def _rejected(self, code: str) -> dict[str, Any]:
        return {"status": REJECTED, "requested_runs": REPRO_RUNS, "completed_runs": 0, "success_count": 0, "error_code": code}

    async def _execute(self, repro_id: str, config_hash: str, tool_fingerprint: str, key: str) -> dict[str, Any]:
        hashes: list[str] = []
        completed = 0
        last_diagnostic: dict[str, Any] | None = None
        try:
            async with asyncio.timeout(TOTAL_TIMEOUT_SECONDS):
                for index in range(REPRO_RUNS):
                    markers = await self._run_once(index)
                    last_diagnostic = getattr(self, "_last_diagnostic", None)
                    completed += 1
                    canonical = canonical_result_hash(markers)
                    hashes.append(canonical)
                    failure = self._failure_status(markers)
                    if failure:
                        return {"status": failure, "requested_runs": REPRO_RUNS, "completed_runs": completed,
                                "success_count": completed - 1, "result_hash": canonical, "error_code": failure.casefold(),
                                "diagnostic": last_diagnostic}
        except asyncio.TimeoutError:
            return {"status": ERROR, "requested_runs": REPRO_RUNS, "completed_runs": completed,
                    "success_count": 0, "result_hash": None, "error_code": "repro_timeout",
                    "diagnostic": {"exit_code": None, "stdout_bytes": 0, "stderr_bytes": 0, "frame_count": 0, "error_code": "repro_timeout", "fixture_bytes": None}}
        except ReproProtocolError as exc:
            return {"status": ERROR, "requested_runs": REPRO_RUNS, "completed_runs": completed,
                    "success_count": 0, "result_hash": None, "error_code": exc.code,
                    "diagnostic": exc.diagnostic}
        except ValueError as exc:
            return {"status": ERROR, "requested_runs": REPRO_RUNS, "completed_runs": completed,
                    "success_count": 0, "result_hash": None, "error_code": str(exc),
                    "diagnostic": {"exit_code": None, "stdout_bytes": 0, "stderr_bytes": 0, "frame_count": 0, "error_code": str(exc), "fixture_bytes": None}}
        except Exception:
            return {"status": ERROR, "requested_runs": REPRO_RUNS, "completed_runs": completed,
                    "success_count": 0, "result_hash": None, "error_code": "process_error",
                    "diagnostic": {"exit_code": None, "stdout_bytes": 0, "stderr_bytes": 0, "frame_count": 0, "error_code": "process_error", "fixture_bytes": None}}
        if len(set(hashes)) != 1:
            return {"status": NONDETERMINISTIC, "requested_runs": REPRO_RUNS, "completed_runs": completed,
                    "success_count": completed, "result_hash": None, "error_code": "result_hash_mismatch"}
        return {"status": SAFE_REPRODUCIBLE, "requested_runs": REPRO_RUNS, "completed_runs": completed,
                "success_count": completed, "result_hash": hashes[0], "error_code": None, "diagnostic": last_diagnostic}

    @staticmethod
    def _failure_status(markers: dict[str, Any]) -> str | None:
        if markers["outside_read"] == "READ_OK" or markers["host_read"] == "READ_OK":
            return UNSAFE_HOST_FS
        if markers["capsule_write"] == "WRITE_OK":
            return UNSAFE_WRITE
        if markers["network"] == "NETWORK_OK":
            return UNSAFE_NETWORK
        expected = {"capsule_read": "READ_OK", "outside_read": "READ_DENIED", "host_read": "READ_DENIED",
                    "capsule_write": "WRITE_DENIED", "tmp_write": "TMP_WRITE_OK", "network": "NETWORK_DENIED"}
        return ERROR if any(markers.get(k) != v for k, v in expected.items()) else None

    async def _run_once(self, index: int) -> dict[str, Any]:
        wsl = self.runner.find_wsl()
        if not wsl:
            raise ValueError("wsl_unavailable")
        config = self.store.wsl_isolation_config()
        distro = config.get("distro")
        if not isinstance(distro, str):
            raise ValueError("distro_not_selected")
        probe_root = self.store.root / "wsl-repro" / f"run-{uuid.uuid4()}"
        capsule = probe_root / "capsule"
        home = probe_root / "home"
        try:
            capsule.mkdir(parents=True)
            home.mkdir(parents=True)
            fixture_path = capsule / FIXTURE_RELATIVE_PATH
            fixture_bytes = build_repro_fixture_bytes()
            with fixture_path.open("wb") as handle:
                handle.write(fixture_bytes)
                handle.flush()
                import os
                os.fsync(handle.fileno())
            if fixture_path.read_bytes() != fixture_bytes:
                raise ValueError("fixture_write_failed")
            converted = await self.runner.run([wsl, "--distribution", distro, "--exec", "/usr/bin/wslpath", "-a", str(capsule)], timeout_seconds=RUN_TIMEOUT_SECONDS)
            if converted.exit_code != 0 or "\n" in converted.stdout.strip() or not converted.stdout.strip():
                raise ValueError("wslpath_failed")
            home_converted = await self.runner.run([wsl, "--distribution", distro, "--exec", "/usr/bin/wslpath", "-a", str(home)], timeout_seconds=RUN_TIMEOUT_SECONDS)
            if home_converted.exit_code != 0 or "\n" in home_converted.stdout.strip() or not home_converted.stdout.strip():
                raise ValueError("wslpath_failed")
            command = [wsl, "--distribution", distro, "--exec", "/usr/bin/bwrap", "--unshare-all", "--new-session", "--die-with-parent",
                       "--ro-bind", "/usr", "/usr", "--ro-bind", "/bin", "/bin", "--ro-bind", "/lib", "/lib",
                       "--ro-bind", "/lib64", "/lib64", "--ro-bind", "/etc", "/etc", "--proc", "/proc", "--dev", "/dev",
                       "--tmpfs", "/tmp", "--ro-bind", home_converted.stdout.strip(), "/home", "--dir", "/work", "--ro-bind", converted.stdout.strip(), "/work",
                       "--chdir", "/work", "--clearenv", "--setenv", "HOME", "/home", "--setenv", "PATH", "/usr/bin:/bin", "--setenv", "LANG", "C",
                       "/usr/bin/python3", "-I", "-S", "-u", "-c", _WORKLOAD, str(index)]
            work_bind = next((position for position, value in enumerate(command)
                              if value == "--ro-bind" and position + 2 < len(command)
                              and command[position + 2] == "/work"), None)
            if work_bind is None or command[work_bind + 1] != converted.stdout.strip():
                raise ValueError("work_bind_invalid")
            outcome = await self.runner.run(command, timeout_seconds=RUN_TIMEOUT_SECONDS)
            payload, diagnostic = parse_frame(outcome, expected_iteration=index,
                                              expected_fixture_sha256=hashlib.sha256(fixture_bytes).hexdigest(),
                                              expected_fixture_bytes=len(fixture_bytes))
            self._last_diagnostic = diagnostic
            return payload
        finally:
            import shutil
            shutil.rmtree(probe_root, ignore_errors=True)
