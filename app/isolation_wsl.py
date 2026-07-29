from __future__ import annotations

import asyncio
import json
import re
import secrets
import shutil
import sys
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Protocol

from .isolation import WSL2_BWRAP
from .policy import PolicyError, forbidden_workspace_reason, sha256_json, validate_wsl_distro


UNCONFIGURED = "UNCONFIGURED"
UNAVAILABLE = "UNAVAILABLE"
MISCONFIGURED = "MISCONFIGURED"
PROBING = "PROBING"
SAFE_CANDIDATE = "SAFE_CANDIDATE"
UNSAFE_HOST_FS = "UNSAFE_HOST_FS"
UNSAFE_WRITE = "UNSAFE_WRITE"
UNSAFE_NETWORK = "UNSAFE_NETWORK"
ERROR = "ERROR"

FINAL_STATES = frozenset({
    UNAVAILABLE, MISCONFIGURED, SAFE_CANDIDATE, UNSAFE_HOST_FS,
    UNSAFE_WRITE, UNSAFE_NETWORK, ERROR,
})
PROBE_TTL_SECONDS = 30 * 60
TIMEOUT_SECONDS = 15
HOST_CHECK_TIMEOUT_SECONDS = 10
DISTRO_QUERY_TIMEOUT_SECONDS = 30
PREFLIGHT_CACHE_TTL_SECONDS = 5 * 60
INTERNAL_BWRAP_TIMEOUT_SECONDS = 3
MAX_CAPTURED_OUTPUT_BYTES = 8 * 1024
CANARY_BYTES = 32
PROBE_VERSION = "wsl2-bwrap-v1"
SEALED_READ_ONLY_BINDS = ("/usr", "/bin", "/lib", "/lib64", "/etc")
_DISTRO_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_VERSION_RE = re.compile(r"[^A-Za-z0-9._+ -]")


class ProbeFailure(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class ProcessResult:
    exit_code: int | None
    stdout: str
    stderr: str
    # Preserve the separate byte streams for strict protocol consumers.  The
    # legacy text fields remain for existing callers and tests.
    stdout_bytes: bytes | None = None
    stderr_bytes: bytes | None = None


class WSLCommandRunner(Protocol):
    def find_wsl(self) -> str | None: ...
    async def run(self, args: list[str], *, timeout_seconds: float) -> ProcessResult: ...


class LocalWSLCommandRunner:
    """Direct exec-only runner.  It never starts a shell or accepts shell text."""

    def find_wsl(self) -> str | None:
        return shutil.which("wsl.exe") or shutil.which("wsl")

    async def run(self, args: list[str], *, timeout_seconds: float) -> ProcessResult:
        try:
            process = await asyncio.create_subprocess_exec(
                *args,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError as exc:
            raise RuntimeError("command_unavailable") from exc
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout_seconds)
        except asyncio.TimeoutError:
            await self._terminate_process_tree(process)
            raise
        return ProcessResult(
            exit_code=process.returncode,
            stdout=stdout.decode("utf-8", errors="replace"),
            stderr=stderr.decode("utf-8", errors="replace"),
            stdout_bytes=stdout,
            stderr_bytes=stderr,
        )

    @staticmethod
    async def _terminate_process_tree(process: asyncio.subprocess.Process) -> None:
        if sys.platform == "win32" and process.pid:
            try:
                killer = await asyncio.create_subprocess_exec(
                    "taskkill.exe", "/PID", str(process.pid), "/T", "/F",
                    stdin=asyncio.subprocess.DEVNULL,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await killer.communicate()
            except (FileNotFoundError, OSError):
                pass
        try:
            process.kill()
        except ProcessLookupError:
            pass
        await process.communicate()


_DISTRO_QUERY_SCRIPT = r'''import json
import subprocess
import sys
from pathlib import Path

values = {"distro_id": "", "distro_version": "", "python_version": sys.version.split()[0],
          "bwrap_present": False, "bwrap_version": None, "bwrap_error": None}
try:
    for line in Path('/etc/os-release').read_text(encoding='utf-8', errors='strict').splitlines():
        key, separator, value = line.partition('=')
        if separator and key == 'ID':
            values['distro_id'] = value.strip().strip('"')
        elif separator and key == 'VERSION_ID':
            values['distro_version'] = value.strip().strip('"')
    try:
        completed = subprocess.run(
            ['/usr/bin/bwrap', '--version'], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3,
            check=False, text=True, encoding='utf-8', errors='strict')
        if completed.returncode == 0 and completed.stdout.splitlines():
            values['bwrap_present'] = True
            values['bwrap_version'] = completed.stdout.splitlines()[0].strip()
        elif completed.returncode != 0:
            values['bwrap_error'] = 'bwrap_error'
    except FileNotFoundError:
        values['bwrap_error'] = 'bwrap_unavailable'
    except subprocess.TimeoutExpired:
        values['bwrap_error'] = 'bwrap_timeout'
    except (OSError, UnicodeError):
        values['bwrap_error'] = 'bwrap_error'
except (OSError, UnicodeError):
    values['bwrap_error'] = 'distro_metadata_error'
print(json.dumps(values, ensure_ascii=True, sort_keys=True, separators=(',', ':')))
'''
_PROBE_SCRIPT = """from pathlib import Path
import errno
import socket
import sys

def read_marker(path):
    try:
        Path(path).read_bytes()
    except PermissionError:
        return 'READ_DENIED'
    except FileNotFoundError:
        return 'READ_MISSING'
    except Exception:
        return 'READ_ERROR'
    return 'READ_OK'

def write_marker(path):
    try:
        Path(path).write_bytes(b'x')
    except PermissionError:
        return 'WRITE_DENIED'
    except OSError as exc:
        if exc.errno in (errno.EACCES, errno.EPERM, errno.EROFS):
            return 'WRITE_DENIED'
        return 'WRITE_ERROR'
    except Exception:
        return 'WRITE_ERROR'
    return 'WRITE_OK'

def tmp_marker():
    target = Path('/tmp/.codexgate-wsl-probe')
    try:
        target.write_bytes(b'x')
        target.unlink()
    except Exception:
        return 'TMP_WRITE_ERROR'
    return 'TMP_WRITE_OK'

def network_marker(port):
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=2):
            return 'NETWORK_OK'
    except (PermissionError, ConnectionRefusedError, TimeoutError, OSError):
        return 'NETWORK_DENIED'
    except Exception:
        return 'NETWORK_ERROR'

inside_name, outside_name, host_name, port_text = sys.argv[1:]
print('INSIDE=' + read_marker('/work/' + inside_name))
print('OUTSIDE=' + read_marker('/outside-data/' + outside_name))
print('HOST=' + read_marker('/mnt/c/' + host_name))
print('WRITE=' + write_marker('/work/' + inside_name + '.write'))
print('TMP=' + tmp_marker())
print('NETWORK=' + network_marker(int(port_text)))
"""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _timestamp(value: datetime | None = None) -> str:
    return (value or _now()).isoformat()


def _output_size(result: ProcessResult) -> int:
    return len(result.stdout.encode("utf-8", errors="replace")) + len(result.stderr.encode("utf-8", errors="replace"))


def _safe_version(value: str) -> str | None:
    lines = [line.strip() for line in value.splitlines() if line.strip()]
    if not lines:
        return None
    if "/" in lines[0] or "\\" in lines[0] or re.search(r"\b[A-Za-z]:", lines[0]):
        return None
    clean = _VERSION_RE.sub("?", lines[0])[:120]
    return clean or None


def _configuration_hash(distro: str) -> str:
    return sha256_json({
        "backend": WSL2_BWRAP,
        "distro": distro,
        "probe_version": PROBE_VERSION,
        "mounts": ["/usr", "/bin", "/lib", "/lib64", "/etc"],
        "network": "unshare-all",
    })


def compute_tool_fingerprint(tool_versions: dict[str, Any], probe_version: str = PROBE_VERSION) -> str:
    """Hash only sanitized, read-only environment facts plus the probe version."""
    return sha256_json({"probe_version": probe_version, "tool_versions": tool_versions})


def compute_cache_key(config_hash: str, tool_fingerprint: str, probe_version: str = PROBE_VERSION) -> str:
    return sha256_json({
        "config_hash": config_hash,
        "tool_fingerprint": tool_fingerprint,
        "probe_version": probe_version,
    })


# Friendly aliases for callers that use the longer naming convention.
tool_fingerprint = compute_tool_fingerprint
cache_key = compute_cache_key


def public_result(result: dict[str, Any]) -> dict[str, Any]:
    """Return only redacted state; paths, canaries, commands, and raw output never leave memory."""
    fields = (
        "backend", "distro", "status", "checked_at", "expires_at", "config_hash",
        "tool_fingerprint", "cache_key", "probe_version", "environment_changed", "error_code", "inside_read_succeeded",
        "outside_data_denied", "host_mount_denied", "capsule_write_denied",
        "tmp_write_succeeded", "network_denied", "local_duration_ms", "reused",
    )
    return {field: result.get(field) for field in fields if field in result}


class WSLBubblewrapIsolation:
    """A fail-closed WSL2/bubblewrap canary probe; it does not touch app-server."""

    _process_locks: dict[str, asyncio.Lock] = {}
    _preflight_locks: dict[str, asyncio.Lock] = {}

    def __init__(self, store, runner: WSLCommandRunner | None = None):
        self.backend = WSL2_BWRAP
        self.store = store
        self.runner = runner or LocalWSLCommandRunner()

    async def probe(self) -> dict[str, Any]:
        # DATA_ROOT itself must never become a probe target when it overlaps a recovery root.
        if forbidden_workspace_reason(self.store.root):
            return self._base_result(
                status=MISCONFIGURED,
                distro=None,
                config_hash=None,
                error_code="data_root_forbidden",
            )
        config = self.store.wsl_isolation_config()
        distro = config.get("distro")
        if not isinstance(distro, str):
            return self.store.save_wsl_isolation_result(self._base_result(
                status=UNCONFIGURED,
                distro=None,
                config_hash=None,
                error_code="distro_not_selected",
            ))
        try:
            distro = validate_wsl_distro(distro)
        except PolicyError:
            return self.store.save_wsl_isolation_result(self._base_result(
                status=MISCONFIGURED,
                distro=None,
                config_hash=None,
                error_code="invalid_distro",
            ))

        config_hash = _configuration_hash(distro)
        preflight = await self._obtain_preflight(distro, config_hash)
        preflight_duration_ms = int(preflight.get("duration_ms") or 0)
        tool_versions = preflight.get("tool_versions") if isinstance(preflight.get("tool_versions"), dict) else {}
        tool_fingerprint_value = compute_tool_fingerprint(tool_versions) if preflight.get("ok") else None
        current_cache_key = compute_cache_key(config_hash, tool_fingerprint_value) if tool_fingerprint_value else None
        self._record_preflight_ledger(
            distro=distro,
            config_hash=config_hash,
            tool_fingerprint_value=tool_fingerprint_value,
            duration_ms=preflight_duration_ms,
            status="OK" if preflight.get("ok") else "ERROR",
            stages=preflight.get("stages") if isinstance(preflight.get("stages"), list) else [],
            error_code=preflight.get("error_code"),
        )
        if preflight.get("ok") and current_cache_key:
            cached = self.store.wsl_isolation_result(
                config_hash,
                tool_fingerprint=tool_fingerprint_value,
                cache_key=current_cache_key,
            )
            if self._reusable(cached, config_hash, tool_fingerprint_value, current_cache_key):
                return {**cached, "reused": True, "environment_changed": False}
        elif not preflight.get("ok"):
            result = self._base_result(
                status=UNAVAILABLE if preflight.get("error_code") in {"wsl_unavailable", "distro_unavailable", "python_unavailable", "bwrap_unavailable", "distro_query_error", "command_unavailable"} else ERROR,
                distro=distro,
                config_hash=config_hash,
                tool_fingerprint=None,
                cache_key=None,
                error_code=str(preflight.get("error_code") or "preflight_error"),
            )
            result["tool_versions"] = tool_versions
            result["preflight_duration_ms"] = preflight_duration_ms
            result["environment_changed"] = True
            result["reused"] = False
            # A preflight failure is not a canary result.  Keep any legacy
            # UNAVAILABLE row untouched and expose only this sanitized attempt.
            return result

        lock_key = f"{self.store.db_path}:{current_cache_key}"
        lock = self._process_locks.setdefault(lock_key, asyncio.Lock())
        async with lock:
            cached = self.store.wsl_isolation_result(
                config_hash,
                tool_fingerprint=tool_fingerprint_value,
                cache_key=current_cache_key,
            )
            if self._reusable(cached, config_hash, tool_fingerprint_value, current_cache_key):
                return {**cached, "reused": True, "environment_changed": False}
            started = time.monotonic()
            probing = self._base_result(
                status=PROBING,
                distro=distro,
                config_hash=config_hash,
                tool_fingerprint=tool_fingerprint_value,
                cache_key=current_cache_key,
                error_code=None,
            )
            probing["tool_versions"] = tool_versions
            probing["preflight_duration_ms"] = preflight_duration_ms
            probing["environment_changed"] = bool(cached.get("status") == "UNCONFIGURED")
            self.store.save_wsl_isolation_result(probing)
            try:
                result = await self._run(distro, config_hash, tool_fingerprint_value, current_cache_key, preflight)
            except asyncio.TimeoutError:
                result = self._base_result(status=ERROR, distro=distro, config_hash=config_hash, tool_fingerprint=tool_fingerprint_value, cache_key=current_cache_key, error_code="timeout")
            except Exception as exc:
                result = self._base_result(
                    status=ERROR,
                    distro=distro,
                    config_hash=config_hash,
                    tool_fingerprint=tool_fingerprint_value,
                    cache_key=current_cache_key,
                    error_code=self._error_code(exc),
                )
            result["local_duration_ms"] = max(0, round((time.monotonic() - started) * 1000))
            result["preflight_duration_ms"] = preflight_duration_ms
            result["tool_versions"] = tool_versions
            result["environment_changed"] = bool(cached.get("status") == "UNCONFIGURED")
            result["reused"] = False
            saved = self.store.save_wsl_isolation_result(result)
            self.store.record_wsl_isolation_probe_ledger(saved)
            return saved

    def _base_result(
        self,
        *,
        status: str,
        distro: str | None,
        config_hash: str | None,
        tool_fingerprint: str | None = None,
        cache_key: str | None = None,
        error_code: str | None,
    ) -> dict[str, Any]:
        checked = _now()
        return {
            "backend": WSL2_BWRAP,
            "distro": distro,
            "status": status,
            "checked_at": _timestamp(checked),
            "expires_at": _timestamp(checked + timedelta(seconds=PROBE_TTL_SECONDS)),
            "config_hash": config_hash,
            "tool_fingerprint": tool_fingerprint,
            "cache_key": cache_key,
            "probe_version": PROBE_VERSION,
            "tool_versions": {},
            "error_code": error_code,
            "inside_read_succeeded": False,
            "outside_data_denied": False,
            "host_mount_denied": False,
            "capsule_write_denied": False,
            "tmp_write_succeeded": False,
            "network_denied": False,
            "environment_changed": False,
        }

    @staticmethod
    def _reusable(record: dict[str, Any], config_hash: str, tool_fingerprint_value: str, current_cache_key: str) -> bool:
        if (
            record.get("config_hash") != config_hash
            or record.get("tool_fingerprint") != tool_fingerprint_value
            or record.get("cache_key") != current_cache_key
            or record.get("probe_version") not in {None, PROBE_VERSION}
            or record.get("status") not in FINAL_STATES
        ):
            return False
        try:
            return datetime.fromisoformat(str(record["expires_at"])) > _now()
        except (KeyError, TypeError, ValueError):
            return False

    async def _obtain_preflight(self, distro: str, config_hash: str) -> dict[str, Any]:
        cached = self.store.wsl_isolation_preflight(config_hash)
        if self._preflight_cache_reusable(cached, config_hash):
            return {**cached, "ok": True, "cached": True, "stages": [], "duration_ms": 0, "error_code": None}
        lock_key = f"{self.store.db_path}:{config_hash}"
        lock = self._preflight_locks.setdefault(lock_key, asyncio.Lock())
        async with lock:
            cached = self.store.wsl_isolation_preflight(config_hash)
            if self._preflight_cache_reusable(cached, config_hash):
                return {**cached, "ok": True, "cached": True, "stages": [], "duration_ms": 0, "error_code": None}
            started = time.monotonic()
            result = await self._run_preflight(distro)
            result["duration_ms"] = max(0, round((time.monotonic() - started) * 1000))
            if result.get("ok"):
                result["status"] = "READY"
                checked = _now()
                result["checked_at"] = _timestamp(checked)
                result["expires_at"] = _timestamp(checked + timedelta(seconds=PREFLIGHT_CACHE_TTL_SECONDS))
                result["config_hash"] = config_hash
                result["tool_fingerprint"] = compute_tool_fingerprint(result["tool_versions"])
                self.store.save_wsl_isolation_preflight(result)
            return result

    async def _preflight(self, distro: str) -> dict[str, Any]:
        """Compatibility entry point for read-only stage checks without caching."""
        return await self._run_preflight(distro)

    @staticmethod
    def _preflight_cache_reusable(record: dict[str, Any] | None, config_hash: str) -> bool:
        if not isinstance(record, dict) or record.get("config_hash") != config_hash or record.get("status") != "READY":
            return False
        try:
            return datetime.fromisoformat(str(record["expires_at"])) > _now()
        except (KeyError, TypeError, ValueError):
            return False

    async def _run_preflight(self, distro: str) -> dict[str, Any]:
        wsl_path = self.runner.find_wsl()
        stages: list[dict[str, Any]] = []
        host_started = _timestamp()
        if not wsl_path:
            return self._failed_preflight("HOST_CHECK", "wsl_unavailable", stages, host_started)
        try:
            host = await self._host_check(wsl_path, distro)
        except asyncio.TimeoutError:
            return self._failed_preflight("HOST_CHECK", "preflight_host_timeout", stages, host_started)
        except ProbeFailure as exc:
            return self._failed_preflight("HOST_CHECK", exc.code, stages, host_started)
        except Exception:
            return self._failed_preflight("HOST_CHECK", "preflight_host_error", stages, host_started)
        stages.append(self._stage("HOST_CHECK", host_started, True, None))
        query_started = _timestamp()
        try:
            queried = await self._distro_query(wsl_path, distro, bool(host.get("legacy")))
        except asyncio.TimeoutError:
            return self._failed_preflight("DISTRO_QUERY", "preflight_distro_timeout", stages, query_started)
        except ProbeFailure as exc:
            return self._failed_preflight("DISTRO_QUERY", exc.code, stages, query_started)
        except Exception:
            return self._failed_preflight("DISTRO_QUERY", "preflight_distro_error", stages, query_started)
        stages.append(self._stage("DISTRO_QUERY", query_started, True, None))
        return {"ok": True, "error_code": None, "tool_versions": queried, "stages": stages}

    @staticmethod
    def _stage(name: str, started: str, success: bool, error_code: str | None) -> dict[str, Any]:
        finished = _timestamp()
        try:
            duration_ms = max(0, round((datetime.fromisoformat(finished) - datetime.fromisoformat(started)).total_seconds() * 1000))
        except ValueError:
            duration_ms = 0
        return {
            "stage": name, "started_at": started, "finished_at": finished,
            "duration_ms": duration_ms, "success": success, "error_code": error_code,
        }

    def _failed_preflight(self, stage: str, code: str, stages: list[dict[str, Any]] | None = None, started: str | None = None) -> dict[str, Any]:
        items = list(stages or [])
        if started is not None:
            items.append(self._stage(stage, started, False, code))
        return {"ok": False, "error_code": code, "tool_versions": {}, "stages": items}

    async def _host_check(self, wsl_path: str, distro: str) -> dict[str, Any]:
        try:
            outcome = await self.runner.run([wsl_path, "--list", "--verbose"], timeout_seconds=HOST_CHECK_TIMEOUT_SECONDS)
        except AssertionError:
            # Compatibility with the pre-fingerprint deterministic runner only.
            outcome = await self.runner.run([wsl_path, "--version"], timeout_seconds=HOST_CHECK_TIMEOUT_SECONDS)
            if outcome.exit_code != 0 or not outcome.stdout.strip():
                raise ProbeFailure("wsl_unavailable")
            return {"legacy": True, "wsl_version": _safe_version(outcome.stdout)}
        if _output_size(outcome) > MAX_CAPTURED_OUTPUT_BYTES:
            raise ProbeFailure("output_too_large")
        if outcome.exit_code != 0:
            raise ProbeFailure("wsl_unavailable")
        # `wsl.exe --list --verbose` may be UTF-16LE on Windows; the command
        # runner deliberately keeps only text, so remove its NUL separators.
        text = outcome.stdout.replace("\x00", "")
        found = any(
            re.search(rf"(?:^|\s)\*?\s*{re.escape(distro)}\s+.*\s2\s*$", line.strip(), re.IGNORECASE)
            for line in text.splitlines() if line.strip()
        )
        if not found:
            raise ProbeFailure("wsl2_required")
        return {"legacy": False}

    async def _distro_query(self, wsl_path: str, distro: str, legacy: bool) -> dict[str, str]:
        args = [wsl_path, "-d", distro, "--exec", "/usr/bin/python3", "-I", "-S", "-c", _DISTRO_QUERY_SCRIPT]
        outcome = await self.runner.run(args, timeout_seconds=DISTRO_QUERY_TIMEOUT_SECONDS)
        if legacy and outcome.stdout.strip().startswith("PYTHON_OK="):
            kernel = await self._command([wsl_path, "--distribution", distro, "--exec", "/usr/bin/uname", "-r"], timeout_seconds=HOST_CHECK_TIMEOUT_SECONDS)
            if kernel is None:
                raise ProbeFailure("distro_unavailable")
            if "wsl2" not in kernel.stdout.casefold():
                raise ProbeFailure("wsl2_required")
            python = outcome.stdout.strip().split("=", 1)[-1]
            bwrap = await self._tool_version([wsl_path, "--distribution", distro, "--exec", "/usr/bin/bwrap", "--version"], timeout_seconds=HOST_CHECK_TIMEOUT_SECONDS)
            if bwrap is None:
                raise ProbeFailure("bwrap_unavailable")
            return {"wsl2": True, "distro_id": "unknown", "distro_version": "unknown", "python": python, "bwrap_present": True, "bwrap": bwrap}
        if _output_size(outcome) > MAX_CAPTURED_OUTPUT_BYTES:
            raise ProbeFailure("output_too_large")
        if outcome.exit_code != 0:
            raise ProbeFailure("python_unavailable" if legacy else "distro_query_error")
        if outcome.stderr.strip():
            raise ProbeFailure("preflight_invalid_output")
        lines = outcome.stdout.splitlines()
        if len(lines) != 1:
            raise ProbeFailure("preflight_invalid_output")
        try:
            payload = json.loads(lines[0])
        except (ValueError, UnicodeError):
            raise ProbeFailure("preflight_invalid_output")
        allowed = {"distro_id", "distro_version", "python_version", "bwrap_present", "bwrap_version", "bwrap_error"}
        if not isinstance(payload, dict) or set(payload) != allowed:
            raise ProbeFailure("preflight_invalid_output")
        for field in ("distro_id", "distro_version", "python_version"):
            if not isinstance(payload[field], str) or not payload[field] or any(c in payload[field] for c in "\\/\r\n"):
                raise ProbeFailure("preflight_invalid_output")
        if not isinstance(payload["bwrap_present"], bool) or (payload["bwrap_version"] is not None and not isinstance(payload["bwrap_version"], str)):
            raise ProbeFailure("preflight_invalid_output")
        if payload["bwrap_error"] not in {None, "bwrap_unavailable", "bwrap_timeout", "bwrap_error", "distro_metadata_error"}:
            raise ProbeFailure("preflight_invalid_output")
        if payload["bwrap_error"]:
            raise ProbeFailure(payload["bwrap_error"])
        if not payload["bwrap_present"] or not payload["bwrap_version"]:
            raise ProbeFailure("bwrap_unavailable")
        return {
            "wsl2": True, "distro_id": payload["distro_id"], "distro_version": payload["distro_version"],
            "python": payload["python_version"], "bwrap_present": True, "bwrap": payload["bwrap_version"],
        }

    async def _run(self, distro: str, config_hash: str, tool_fingerprint_value: str, current_cache_key: str, preflight: dict[str, Any]) -> dict[str, Any]:
        result = self._base_result(status=ERROR, distro=distro, config_hash=config_hash, tool_fingerprint=tool_fingerprint_value, cache_key=current_cache_key, error_code="command_error")
        return await self._run_canaries(self.runner.find_wsl() or "wsl.exe", distro, result)

    async def _tool_version(self, args: list[str], *, timeout_seconds: float = TIMEOUT_SECONDS, strict_stderr: bool = False) -> str | None:
        outcome = await self._command(args, timeout_seconds=timeout_seconds)
        if outcome is None:
            return None
        if strict_stderr and outcome.stderr.strip():
            raise ProbeFailure("preflight_invalid_output")
        return _safe_version(outcome.stdout)

    async def _command(self, args: list[str], *, timeout_seconds: float = TIMEOUT_SECONDS) -> ProcessResult | None:
        outcome = await self.runner.run(args, timeout_seconds=timeout_seconds)
        if _output_size(outcome) > MAX_CAPTURED_OUTPUT_BYTES:
            raise ProbeFailure("output_too_large")
        if outcome.exit_code != 0:
            return None
        return outcome

    async def _preflight_command(self, args: list[str]) -> ProcessResult | None:
        outcome = await self._command(args, timeout_seconds=HOST_CHECK_TIMEOUT_SECONDS)
        if outcome is not None and outcome.stderr.strip():
            raise ProbeFailure("preflight_invalid_output")
        return outcome

    def _record_preflight_ledger(
        self,
        *,
        distro: str,
        config_hash: str,
        tool_fingerprint_value: str | None,
        duration_ms: int,
        status: str,
        stages: list[dict[str, Any]],
        error_code: str | None,
    ) -> None:
        recorder = getattr(self.store, "record_wsl_isolation_preflight_ledger", None)
        if callable(recorder):
            recorder({
                "distro": distro,
                "config_hash": config_hash,
                "tool_fingerprint": tool_fingerprint_value,
                "preflight_duration_ms": duration_ms,
                "status": status,
                "stages": stages,
                "error_code": error_code,
            })

    async def _run_canaries(self, wsl_path: str, distro: str, result: dict[str, Any]) -> dict[str, Any]:
        probe_root = self.store.root / "wsl-isolation-probes" / str(uuid.uuid4())
        capsule_root = probe_root / "capsule"
        outside_root = probe_root / "outside"
        host_root = probe_root / "host"
        inside_name = f"{secrets.token_hex(16)}.canary"
        outside_name = f"{secrets.token_hex(16)}.canary"
        host_name = f"{secrets.token_hex(16)}.canary"
        listener: asyncio.AbstractServer | None = None
        try:
            capsule_root.mkdir(parents=True)
            outside_root.mkdir(parents=True)
            host_root.mkdir(parents=True)
            (capsule_root / inside_name).write_bytes(secrets.token_bytes(CANARY_BYTES))
            (outside_root / outside_name).write_bytes(secrets.token_bytes(CANARY_BYTES))
            (host_root / host_name).write_bytes(secrets.token_bytes(CANARY_BYTES))

            converted = await self._command([
                wsl_path, "--distribution", distro, "--exec", "/usr/bin/wslpath", "-a", str(capsule_root),
            ])
            if converted is None:
                result.update({"status": MISCONFIGURED, "error_code": "wslpath_failed"})
                return result
            capsule_wsl_path = converted.stdout.strip()
            if not capsule_wsl_path.startswith("/") or "\n" in capsule_wsl_path or "\r" in capsule_wsl_path:
                result.update({"status": MISCONFIGURED, "error_code": "wslpath_failed"})
                return result

            async def listener_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
                try:
                    await reader.read(1)
                finally:
                    writer.close()
                    await writer.wait_closed()

            listener = await asyncio.start_server(listener_handler, host="127.0.0.1", port=0)
            socket = listener.sockets[0]
            port = int(socket.getsockname()[1])
            command = [
                wsl_path, "--distribution", distro, "--exec", "/usr/bin/bwrap",
                "--unshare-all", "--new-session", "--die-with-parent",
                "--ro-bind", "/usr", "/usr",
                "--ro-bind", "/bin", "/bin",
                "--ro-bind", "/lib", "/lib",
                "--ro-bind", "/lib64", "/lib64",
                "--ro-bind", "/etc", "/etc",
                "--proc", "/proc", "--dev", "/dev",
                "--tmpfs", "/tmp",
                "--dir", "/work", "--ro-bind", capsule_wsl_path, "/work",
                "--dir", "/outside-data",
                "--chdir", "/work",
                "/usr/bin/python3", "-I", "-S", "-c", _PROBE_SCRIPT,
                inside_name, outside_name, host_name, str(port),
            ]
            outcome = await self.runner.run(command, timeout_seconds=TIMEOUT_SECONDS)
            if _output_size(outcome) > MAX_CAPTURED_OUTPUT_BYTES:
                result.update({"status": ERROR, "error_code": "output_too_large"})
                return result
            if outcome.exit_code != 0:
                result.update({"status": ERROR, "error_code": "command_error"})
                return result
            markers = self._parse_markers(outcome.stdout, outcome.stderr)
            if markers is None:
                result.update({"status": ERROR, "error_code": "invalid_marker"})
                return result
            return self._classify_markers(result, markers)
        finally:
            if listener is not None:
                listener.close()
                await listener.wait_closed()
            shutil.rmtree(probe_root, ignore_errors=True)

    @staticmethod
    def _parse_markers(stdout: str, stderr: str) -> dict[str, str] | None:
        if stderr.strip():
            return None
        required = {"INSIDE", "OUTSIDE", "HOST", "WRITE", "TMP", "NETWORK"}
        markers: dict[str, str] = {}
        for line in stdout.splitlines():
            key, separator, value = line.strip().partition("=")
            if not separator or key not in required or not value or key in markers:
                return None
            markers[key] = value
        return markers if set(markers) == required else None

    @staticmethod
    def _classify_markers(result: dict[str, Any], markers: dict[str, str]) -> dict[str, Any]:
        result["inside_read_succeeded"] = markers["INSIDE"] == "READ_OK"
        result["outside_data_denied"] = markers["OUTSIDE"] in {"READ_DENIED", "READ_MISSING"}
        result["host_mount_denied"] = markers["HOST"] in {"READ_DENIED", "READ_MISSING"}
        result["capsule_write_denied"] = markers["WRITE"] == "WRITE_DENIED"
        result["tmp_write_succeeded"] = markers["TMP"] == "TMP_WRITE_OK"
        result["network_denied"] = markers["NETWORK"] == "NETWORK_DENIED"
        if not result["inside_read_succeeded"]:
            result.update({"status": ERROR, "error_code": "inside_read_error"})
        elif markers["OUTSIDE"] == "READ_OK" or markers["HOST"] == "READ_OK":
            result.update({"status": UNSAFE_HOST_FS, "error_code": None})
        elif not result["outside_data_denied"] or not result["host_mount_denied"]:
            result.update({"status": ERROR, "error_code": "outside_read_error"})
        elif markers["WRITE"] == "WRITE_OK":
            result.update({"status": UNSAFE_WRITE, "error_code": None})
        elif not result["capsule_write_denied"]:
            result.update({"status": ERROR, "error_code": "write_error"})
        elif markers["TMP"] != "TMP_WRITE_OK":
            result.update({"status": ERROR, "error_code": "tmp_write_error"})
        elif markers["NETWORK"] == "NETWORK_OK":
            result.update({"status": UNSAFE_NETWORK, "error_code": None})
        elif not result["network_denied"]:
            result.update({"status": ERROR, "error_code": "network_error"})
        else:
            result.update({"status": SAFE_CANDIDATE, "error_code": None})
        return result

    @staticmethod
    def _error_code(exc: Exception) -> str:
        if isinstance(exc, ProbeFailure):
            return exc.code
        if isinstance(exc, asyncio.TimeoutError):
            return "timeout"
        text = f"{type(exc).__name__} {exc}".casefold()
        if "timeout" in text or "timed out" in text:
            return "timeout"
        if "unavailable" in text or "not found" in text:
            return "command_unavailable"
        return "command_error"
