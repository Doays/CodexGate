"""Phase 0 sealed WSL Codex runtime preparation.

This module validates an explicitly selected WSL-native binary and creates a
private, immutable bubblewrap launch description.  It never starts Codex,
app-server, login, or a model turn.
"""
from __future__ import annotations

import asyncio
import json
import re
import time
from datetime import datetime, timezone
from typing import Any

from .isolation_wsl import (
    MAX_CAPTURED_OUTPUT_BYTES,
    SEALED_READ_ONLY_BINDS,
    LocalWSLCommandRunner,
    ProcessResult,
    WSLCommandRunner,
)
from .policy import PolicyError, sha256_json, validate_wsl_codex_binary_path, validate_wsl_distro
from .storage import RUNTIME_IDENTITY_VERSION


UNCONFIGURED = "UNCONFIGURED"
BINARY_MISSING = "BINARY_MISSING"
INVALID_BINARY = "INVALID_BINARY"
VERSION_MISMATCH = "VERSION_MISMATCH"
EGRESS_UNCONFIGURED = "EGRESS_UNCONFIGURED"
READY_CANDIDATE = "READY_CANDIDATE"
BLOCKED = "BLOCKED"
ERROR = "ERROR"

RUNTIME_POLICY_VERSION = "sealed-wsl-codex-runtime-v0"
EXPECTED_CODEX_VERSION = "codex-cli 0.145.0"
RUNTIME_TIMEOUT_SECONDS = 15
_SAFE_VERSION = re.compile(r"^codex-cli 0\.145\.0$")

_BINARY_PREFLIGHT_SCRIPT = r'''import hashlib
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

binary = Path(sys.argv[1])
result = {"status": "ERROR", "sha256": None, "version": None, "size": None,
          "mtime_ns": None, "error": "runtime_error"}
try:
    current = Path("/")
    for part in binary.parts[1:]:
        current = current / part
        if current.is_symlink():
            result.update(status="INVALID_BINARY", error="binary_symlink")
            print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
            raise SystemExit(0)
    try:
        fd = os.open(str(binary), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        result.update(status="BINARY_MISSING", error="binary_missing")
        print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        raise SystemExit(0)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            result.update(status="INVALID_BINARY", error="binary_not_file")
        elif not (info.st_mode & 0o111):
            result.update(status="INVALID_BINARY", error="binary_not_executable")
        else:
            digest = hashlib.sha256()
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
            completed = subprocess.run([str(binary), "--version"], stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10, check=False,
                text=True, encoding="utf-8", errors="strict")
            output = completed.stdout.strip()
            if completed.returncode != 0 or len(output) > 120 or "\n" in output or "\r" in output:
                result.update(status="ERROR", error="version_query_failed")
            else:
                result.update(status="OK", sha256=digest.hexdigest(), version=output,
                              size=info.st_size, mtime_ns=info.st_mtime_ns, error=None)
    finally:
        os.close(fd)
except subprocess.TimeoutExpired:
    result.update(status="ERROR", error="version_timeout")
except (OSError, UnicodeError):
    result.update(status="ERROR", error="runtime_error")
print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
'''


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _output_bytes(result: ProcessResult) -> int:
    stdout = result.stdout_bytes if isinstance(result.stdout_bytes, bytes) else result.stdout.encode("utf-8", errors="replace")
    stderr = result.stderr_bytes if isinstance(result.stderr_bytes, bytes) else result.stderr.encode("utf-8", errors="replace")
    return len(stdout) + len(stderr)


def _runtime_config_hash(distro: str, binary_path: str) -> str:
    return sha256_json({"runtime_policy_version": RUNTIME_POLICY_VERSION, "distro": distro, "binary_path": binary_path})


def sealed_runtime_execution_policy() -> dict[str, Any]:
    """The reusable in-memory mount/environment policy for sealed children.

    This intentionally contains no configured binary path or host path.  It
    is shared by the future process executor so review specs cannot drift
    from the Runtime Phase 0 policy.
    """
    return {
        "read_only_binds": list(SEALED_READ_ONLY_BINDS),
        "tmpfs": ["/tmp", "/runtime-state", "/home"],
        "environment": {"PATH": "/usr/bin:/bin", "HOME": "/home/codex", "TMPDIR": "/tmp", "LANG": "C.UTF-8"},
        "cwd": "/work",
        "network": "blocked",
    }


def build_sealed_launch_spec(binary_path: str, isolation_cache_key: str | None = None) -> dict[str, Any]:
    """Create a private immutable spec; callers must never expose it verbatim."""
    binary_path = validate_wsl_codex_binary_path(binary_path)
    if isolation_cache_key is not None and not re.fullmatch(r"[0-9a-f]{64}", isolation_cache_key):
        raise PolicyError("WSL isolation cache key is invalid")
    binds = [{"source": item, "target": item, "mode": "ro"} for item in SEALED_READ_ONLY_BINDS]
    binds.extend([
        {"source": binary_path, "target": "/runtime/codex", "mode": "ro"},
        {"source": "CAPSULE_SOURCE", "target": "/work", "mode": "ro"},
    ])
    environment = {"PATH": "/usr/bin:/bin", "HOME": "/home/codex", "TMPDIR": "/tmp", "LANG": "C.UTF-8"}
    argv = [
        "/usr/bin/bwrap", "--unshare-all", "--new-session", "--die-with-parent", "--clearenv",
        "--proc", "/proc", "--dev", "/dev",
        "--tmpfs", "/tmp", "--tmpfs", "/runtime-state", "--tmpfs", "/home", "--dir", "/home/codex",
        "--dir", "/runtime", "--dir", "/work",
    ]
    for item in SEALED_READ_ONLY_BINDS:
        argv.extend(["--ro-bind", item, item])
    argv.extend([
        "--ro-bind", binary_path, "/runtime/codex", "--ro-bind", "CAPSULE_SOURCE", "/work", "--chdir", "/work",
        "--setenv", "PATH", environment["PATH"], "--setenv", "HOME", environment["HOME"],
        "--setenv", "TMPDIR", environment["TMPDIR"], "--setenv", "LANG", environment["LANG"],
        "/runtime/codex", "app-server",
    ])
    return {
        "runtime_policy_version": RUNTIME_POLICY_VERSION,
        "backend": "WSL2_BWRAP",
        "isolation_cache_key": isolation_cache_key,
        "network": "blocked",
        "cwd": "/work",
        "binds": binds,
        "tmpfs": ["/tmp", "/runtime-state", "/home"],
        "home": "/home/codex",
        "environment": environment,
        "argv": argv,
    }


def runtime_fingerprint(binary_sha256: str, version: str, isolation_cache_key: str) -> str:
    return sha256_json({
        "binary_sha256": binary_sha256,
        "version": version,
        "isolation_cache_key": isolation_cache_key,
        "runtime_policy_version": RUNTIME_POLICY_VERSION,
    })


def public_runtime_result(result: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(result, dict):
        return {"status": UNCONFIGURED, "binary_configured": False, "start_allowed": False, "egress_blocked": True}
    fields = ("status", "checked_at", "config_hash", "runtime_fingerprint", "launch_spec_hash",
              "binary_configured", "version_match", "isolation_match", "egress_blocked", "start_allowed", "error_code",
              "identity_version", "identity_complete")
    return {field: result.get(field) for field in fields if field in result}


class WSLCodexRuntime:
    """Fail-closed metadata preflight for a future sealed Codex launch."""

    _locks: dict[str, asyncio.Lock] = {}

    def __init__(self, store, runner: WSLCommandRunner | None = None):
        self.store = store
        self.runner = runner or LocalWSLCommandRunner()

    async def preflight(self) -> dict[str, Any]:
        config = self.store.wsl_codex_runtime_config_private()
        if not config:
            return self._save(self._base(UNCONFIGURED, None, None, None, "binary_not_configured"))
        binary_path = config["binary_path"]
        distro = self.store.wsl_isolation_config().get("distro")
        if not isinstance(distro, str):
            return self._save(self._base(BLOCKED, None, None, None, "distro_not_configured", binary_configured=True))
        try:
            distro = validate_wsl_distro(distro)
            binary_path = validate_wsl_codex_binary_path(binary_path)
        except PolicyError:
            return self._save(self._base(INVALID_BINARY, None, None, None, "binary_path_invalid"))
        config_hash = _runtime_config_hash(distro, binary_path)
        isolation = self.store.wsl_isolation_result()
        isolation_key = isolation.get("cache_key")
        if isolation.get("status") != "SAFE_CANDIDATE" or not isinstance(isolation_key, str):
            return self._save(self._base(BLOCKED, config_hash, None, None, "isolation_not_safe", binary_configured=True))
        lock = self._locks.setdefault(f"{self.store.db_path}:{config_hash}:{isolation_key}", asyncio.Lock())
        async with lock:
            started = time.monotonic()
            try:
                result = await self._inspect_binary(distro, binary_path)
            except asyncio.TimeoutError:
                return self._save(self._base(ERROR, config_hash, None, None, "preflight_timeout", started, binary_configured=True))
            except Exception:
                return self._save(self._base(ERROR, config_hash, None, None, "preflight_error", started, binary_configured=True))
            status = result["status"]
            if status != "OK":
                mapped = BINARY_MISSING if status == BINARY_MISSING else INVALID_BINARY if status == INVALID_BINARY else ERROR
                return self._save(self._base(mapped, config_hash, None, None, result["error"], started, binary_configured=True))
            version = result["version"]
            binary_sha = result["sha256"]
            if version != EXPECTED_CODEX_VERSION:
                return self._save(self._base(
                    VERSION_MISMATCH, config_hash, None, None, "version_mismatch", started,
                    version_match=False, binary_configured=True,
                ))
            spec = build_sealed_launch_spec(binary_path, isolation_key)
            launch_hash = sha256_json(spec)
            fingerprint = runtime_fingerprint(binary_sha, version, isolation_key)
            # Network remains unshared: the binary is ready only in principle,
            # and actual Codex startup is deliberately unavailable in Phase 0.
            ready = self._base(EGRESS_UNCONFIGURED, config_hash, fingerprint, launch_hash, "egress_unconfigured", started,
                               version_match=True, isolation_match=True, binary_configured=True)
            ready["preflight_status"] = READY_CANDIDATE
            ready["binary_size"] = result["size"]
            # This digest is sealed local metadata.  It is needed to bind a
            # later egress contract, but public API results still omit it.
            ready["binary_sha256"] = binary_sha
            ready["isolation_cache_key"] = isolation_key
            ready["identity_version"] = RUNTIME_IDENTITY_VERSION
            ready["identity_complete"] = True
            return self._save(ready)

    def start(self) -> None:
        """The sealed contract never unlocks startup before broker auth exists."""
        contract = self.store.sealed_egress_contract()
        if not contract:
            raise PolicyError("WSL Codex runtime start is blocked: egress contract is unconfigured")
        if contract.get("preview_hash") is not None and contract.get("preview_hash") != contract.get("contract_hash"):
            raise PolicyError("WSL Codex runtime start is blocked: egress contract hash mismatch")
        if contract.get("status") == "AUTH_UNCONFIGURED":
            raise PolicyError("WSL Codex runtime start is blocked: egress authentication is unconfigured")
        raise PolicyError("WSL Codex runtime start is blocked: sealed egress is not ready")

    async def _inspect_binary(self, distro: str, binary_path: str) -> dict[str, Any]:
        wsl = self.runner.find_wsl()
        if not wsl:
            return {"status": ERROR, "error": "wsl_unavailable"}
        outcome = await self.runner.run(
            [wsl, "-d", distro, "--exec", "/usr/bin/python3", "-I", "-S", "-c", _BINARY_PREFLIGHT_SCRIPT, binary_path],
            timeout_seconds=RUNTIME_TIMEOUT_SECONDS,
        )
        if _output_bytes(outcome) > MAX_CAPTURED_OUTPUT_BYTES:
            return {"status": ERROR, "error": "output_limit"}
        if outcome.exit_code != 0 or outcome.stderr.strip():
            return {"status": ERROR, "error": "preflight_command_error"}
        stdout_bytes = outcome.stdout_bytes if isinstance(outcome.stdout_bytes, bytes) else outcome.stdout.encode("utf-8")
        try:
            stdout = stdout_bytes.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            return {"status": ERROR, "error": "preflight_output_invalid"}
        lines = stdout.splitlines()
        if len(lines) != 1:
            return {"status": ERROR, "error": "preflight_output_invalid"}
        try:
            payload = json.loads(lines[0])
        except ValueError:
            return {"status": ERROR, "error": "preflight_output_invalid"}
        expected = {"status", "sha256", "version", "size", "mtime_ns", "error"}
        if not isinstance(payload, dict) or set(payload) != expected:
            return {"status": ERROR, "error": "preflight_output_invalid"}
        if payload["status"] not in {"OK", BINARY_MISSING, INVALID_BINARY, ERROR}:
            return {"status": ERROR, "error": "preflight_output_invalid"}
        if payload["error"] not in {None, "binary_missing", "binary_symlink", "binary_not_file", "binary_not_executable", "version_query_failed", "version_timeout", "runtime_error"}:
            return {"status": ERROR, "error": "preflight_output_invalid"}
        if payload["status"] == "OK":
            if (not isinstance(payload["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", payload["sha256"])
                    or not isinstance(payload["version"], str) or not isinstance(payload["size"], int)
                    or not isinstance(payload["mtime_ns"], int)):
                return {"status": ERROR, "error": "preflight_output_invalid"}
        return payload

    def _base(self, status: str, config_hash: str | None, fingerprint: str | None, launch_hash: str | None,
              error_code: str | None, started: float | None = None, *, version_match: bool = False,
              isolation_match: bool = False, binary_configured: bool = False) -> dict[str, Any]:
        duration = max(0, round((time.monotonic() - started) * 1000)) if started is not None else 0
        return {
            "status": status, "checked_at": _now(), "config_hash": config_hash,
            "runtime_fingerprint": fingerprint, "launch_spec_hash": launch_hash,
            "binary_configured": binary_configured, "version_match": version_match,
            "isolation_match": isolation_match, "egress_blocked": True,
            "start_allowed": False, "error_code": error_code, "local_duration_ms": duration,
            "identity_version": RUNTIME_IDENTITY_VERSION, "identity_complete": False,
            "isolation_cache_key": None,
        }

    def _save(self, record: dict[str, Any]) -> dict[str, Any]:
        saved = self.store.save_wsl_codex_runtime_result(record)
        self.store.record_wsl_codex_runtime_preflight_ledger(saved)
        return saved
