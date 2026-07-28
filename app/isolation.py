from __future__ import annotations

import asyncio
import hashlib
import secrets
import shutil
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Protocol


SAFE_CAPSULE_ONLY = "SAFE_CAPSULE_ONLY"
SAFE_CANDIDATE = "SAFE_CANDIDATE"
UNSAFE_FULL_DISK_READ = "UNSAFE_FULL_DISK_READ"
ERROR = "ERROR"
UNKNOWN = "UNKNOWN"

READ_OK = "READ_OK"
READ_DENIED = "READ_DENIED"
READ_ERROR = "READ_ERROR"

READ_OK_EXIT_CODE = 0
READ_DENIED_EXIT_CODE = 13
READ_ERROR_EXIT_CODE = 17

PROBE_TTL_SECONDS = 24 * 60 * 60
MAX_CAPTURED_OUTPUT_BYTES = 1024
TIMEOUT_SECONDS = 10
CANARY_BYTES = 32

NATIVE_WINDOWS_APP_SERVER = "NATIVE_WINDOWS_APP_SERVER"
WSL2_BWRAP = "WSL2_BWRAP"
ISOLATION_BACKENDS = frozenset({NATIVE_WINDOWS_APP_SERVER, WSL2_BWRAP})

_PROBE_SCRIPT = (
    "from pathlib import Path\n"
    "import sys\n"
    "try:\n"
    "    Path(sys.argv[1]).read_bytes()\n"
    "except PermissionError:\n"
    "    print('READ_DENIED')\n"
    "    raise SystemExit(13)\n"
    "except Exception:\n"
    "    print('READ_ERROR')\n"
    "    raise SystemExit(17)\n"
    "print('READ_OK')\n"
)


class IsolationCommandClient(Protocol):
    async def prepare_for_command_exec(self, schema_dir: Path) -> dict[str, str]: ...
    async def connect_for_command_exec(self) -> None: ...
    def read_only_sandbox_policy(self) -> dict[str, Any]: ...
    async def command_exec(self, params: dict[str, Any], *, timeout_seconds: float = 10) -> dict[str, Any]: ...
    async def close(self) -> None: ...


class IsolationBackend(Protocol):
    """A backend returns only a redacted preflight result and never authorizes a live turn by itself."""

    backend: str

    async def probe(self) -> dict[str, Any]: ...


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def public_result(result: dict[str, Any]) -> dict[str, Any]:
    """The API deliberately exposes no canary path, command, or raw output."""
    return {
        "status": result.get("status", UNKNOWN),
        "checked_at": result.get("checked_at"),
        "expires_at": result.get("expires_at"),
        "outside_read_succeeded": bool(result.get("outside_read_succeeded")),
        "outside_denied_explicitly": bool(result.get("outside_denied_explicitly")),
        "error_code": result.get("error_code"),
        "reason": result.get("reason"),
    }


async def run_isolation_probe(store, client: IsolationCommandClient) -> dict[str, Any]:
    """Probe standalone read sandboxing using only temporary DATA_ROOT canaries.

    The probe uses only command/exec with a fixed Python command. It never starts
    a thread or turn, and it never stores raw paths, raw stdout, or raw stderr.
    """
    probe_root = store.root / "isolation-probes" / str(uuid.uuid4())
    capsule_root = probe_root / "capsule"
    outside_root = probe_root / "outside"
    schema_root = probe_root / "schema"
    inside_path = capsule_root / f"{secrets.token_hex(16)}.canary"
    outside_path = outside_root / f"{secrets.token_hex(16)}.canary"
    inside_value = secrets.token_bytes(CANARY_BYTES)
    outside_value = secrets.token_bytes(CANARY_BYTES)
    now = _now()
    result: dict[str, Any] = {
        "status": ERROR,
        "checked_at": now.isoformat(),
        "expires_at": (now + timedelta(seconds=PROBE_TTL_SECONDS)).isoformat(),
        "inside_read_succeeded": False,
        "outside_read_succeeded": False,
        "outside_denied_explicitly": False,
        "inside_result": None,
        "outside_result": None,
        "inside_exit_code": None,
        "outside_exit_code": None,
        "inside_canary_sha256": _sha256_bytes(inside_value),
        "outside_canary_sha256": _sha256_bytes(outside_value),
        "codex_version": None,
        "schema_sha256": None,
        "error_code": None,
        "reason": None,
    }
    try:
        capsule_root.mkdir(parents=True)
        outside_root.mkdir(parents=True)
        inside_path.write_bytes(inside_value)
        outside_path.write_bytes(outside_value)

        metadata = await client.prepare_for_command_exec(schema_root)
        version = metadata.get("codex_version")
        schema_hash = metadata.get("schema_sha256")
        if not isinstance(version, str) or not isinstance(schema_hash, str):
            raise RuntimeError("incomplete_metadata")
        result["codex_version"] = version
        result["schema_sha256"] = schema_hash

        await client.connect_for_command_exec()
        policy = client.read_only_sandbox_policy()

        inside = await _exec_read(client, inside_path, capsule_root, policy)
        outside = await _exec_read(client, outside_path, capsule_root, policy)

        result["inside_result"] = inside["result_code"]
        result["inside_exit_code"] = inside["exit_code"]
        result["outside_result"] = outside["result_code"]
        result["outside_exit_code"] = outside["exit_code"]
        result["inside_read_succeeded"] = inside["result_code"] == READ_OK
        result["outside_read_succeeded"] = outside["result_code"] == READ_OK
        result["outside_denied_explicitly"] = outside["result_code"] == READ_DENIED

        if inside["result_code"] != READ_OK:
            result["status"] = ERROR
            result["error_code"] = _inside_error_code(inside["result_code"])
            result["reason"] = result["error_code"]
        elif outside["result_code"] == READ_OK:
            result["status"] = UNSAFE_FULL_DISK_READ
            result["reason"] = "outside_readable"
        elif outside["result_code"] == READ_DENIED:
            result["status"] = SAFE_CANDIDATE
            result["reason"] = "outside_denied_explicitly"
        else:
            result["status"] = ERROR
            result["error_code"] = _outside_error_code(outside["result_code"])
            result["reason"] = result["error_code"]
    except Exception as exc:
        result["status"] = ERROR
        result["error_code"] = _classify_exec_error(exc)
        result["reason"] = result["error_code"]
    finally:
        try:
            await client.close()
        except Exception:
            if result["status"] == SAFE_CANDIDATE:
                result["status"] = ERROR
                result["error_code"] = "command_error"
                result["reason"] = "command_error"
        shutil.rmtree(probe_root, ignore_errors=True)
    return store.save_isolation_result(result)


async def _exec_read(
    client: IsolationCommandClient,
    target: Path,
    cwd: Path,
    sandbox_policy: dict[str, Any],
) -> dict[str, Any]:
    params = {
        "command": [sys.executable, "-I", "-S", "-c", _PROBE_SCRIPT, str(target)],
        "cwd": str(cwd),
        "sandboxPolicy": sandbox_policy,
        "timeoutMs": TIMEOUT_SECONDS * 1000,
    }
    try:
        response = await asyncio.wait_for(
            client.command_exec(params, timeout_seconds=TIMEOUT_SECONDS),
            timeout=TIMEOUT_SECONDS + 1,
        )
    except Exception as exc:
        return {"result_code": _classify_exec_error(exc), "exit_code": None}
    return _interpret_response(response)


def _interpret_response(response: dict[str, Any]) -> dict[str, Any]:
    exit_code = response.get("exitCode")
    stdout = response.get("stdout", "")
    stderr = response.get("stderr", "")
    if not isinstance(exit_code, int) or not isinstance(stdout, str) or not isinstance(stderr, str):
        return {"result_code": "command_error", "exit_code": exit_code if isinstance(exit_code, int) else None}
    if _output_size(stdout, stderr) > MAX_CAPTURED_OUTPUT_BYTES:
        return {"result_code": "output_too_large", "exit_code": exit_code}

    lines = [line.strip() for line in stdout.splitlines() if line.strip()]
    if lines == [READ_OK] and exit_code == READ_OK_EXIT_CODE:
        return {"result_code": READ_OK, "exit_code": exit_code}
    if lines == [READ_DENIED] and exit_code == READ_DENIED_EXIT_CODE:
        return {"result_code": READ_DENIED, "exit_code": exit_code}
    if lines == [READ_ERROR] and exit_code == READ_ERROR_EXIT_CODE:
        return {"result_code": READ_ERROR, "exit_code": exit_code}
    return {"result_code": "command_error", "exit_code": exit_code}


def _output_size(stdout: str, stderr: str) -> int:
    return len(stdout.encode("utf-8", errors="replace")) + len(stderr.encode("utf-8", errors="replace"))


def _classify_exec_error(exc: Exception) -> str:
    if isinstance(exc, asyncio.TimeoutError):
        return "timeout"
    text = f"{type(exc).__name__} {exc}".casefold()
    if "outputbytescap" in text or "disableoutputcap" in text or "unsupported parameter" in text:
        return "unsupported_parameter"
    if "timed out" in text or "timeout" in text or "초과" in text:
        return "timeout"
    if "schema" in text:
        return "schema_error"
    return "command_error"


def _inside_error_code(result_code: str | None) -> str:
    if result_code == READ_DENIED:
        return "inside_read_denied"
    if result_code == READ_ERROR:
        return "inside_read_error"
    if isinstance(result_code, str):
        return result_code
    return "command_error"


def _outside_error_code(result_code: str | None) -> str:
    if result_code == READ_ERROR:
        return "outside_read_error"
    if isinstance(result_code, str):
        return result_code
    return "command_error"
