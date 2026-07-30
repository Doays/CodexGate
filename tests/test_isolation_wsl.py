from __future__ import annotations

import asyncio
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app.gateway import Gate
from app.isolation_wsl import (
    ERROR,
    MISCONFIGURED,
    OFFLINE_CANARY_MIN_REMAINING_SECONDS,
    SAFE_CANDIDATE,
    UNAVAILABLE,
    UNSAFE_HOST_FS,
    UNSAFE_NETWORK,
    UNSAFE_WRITE,
    ProcessResult,
    WSLBubblewrapIsolation,
    public_result,
)
from app.policy import PolicyError
from app.storage import Store


def outcome(stdout: str = "", *, exit_code: int = 0, stderr: str = "") -> ProcessResult:
    return ProcessResult(exit_code=exit_code, stdout=stdout, stderr=stderr)


def markers(**values: str) -> str:
    base = {
        "INSIDE": "READ_OK",
        "OUTSIDE": "READ_MISSING",
        "HOST": "READ_MISSING",
        "WRITE": "WRITE_DENIED",
        "TMP": "TMP_WRITE_OK",
        "NETWORK": "NETWORK_DENIED",
    }
    base.update(values)
    return "".join(f"{key}={value}\n" for key, value in base.items())


class FakeRunner:
    def __init__(self, *, available: bool = True, probe: ProcessResult | Exception | None = None, delay: float = 0):
        self.available = available
        self.probe = probe or outcome(markers())
        self.delay = delay
        self.calls: list[list[str]] = []
        self.python_available = True
        self.bwrap_available = True
        self.distro_available = True
        self.kernel = "5.15.153.1-microsoft-standard-WSL2\n"

    def find_wsl(self) -> str | None:
        return "wsl.exe" if self.available else None

    async def run(self, args: list[str], *, timeout_seconds: float) -> ProcessResult:
        self.calls.append(args)
        if args == ["wsl.exe", "--version"]:
            return outcome("WSL version: 2.1.5\n")
        if "/usr/bin/uname" in args:
            return outcome(self.kernel) if self.distro_available else outcome("", exit_code=1)
        if "/usr/bin/python3" in args and "--unshare-all" not in args:
            return outcome("PYTHON_OK=3.11.2\n") if self.python_available else outcome("", exit_code=127)
        if "/usr/bin/bwrap" in args and "--unshare-all" not in args:
            return outcome("bubblewrap 0.8.0\n") if self.bwrap_available else outcome("", exit_code=127)
        if "/usr/bin/wslpath" in args:
            return outcome("/mnt/c/CodexGate/capsule\n")
        if "--unshare-all" in args:
            if self.delay:
                await asyncio.sleep(self.delay)
            if isinstance(self.probe, Exception):
                raise self.probe
            return self.probe
        raise AssertionError(f"unexpected fixed command: {args}")


def configured(tmp_path, runner: FakeRunner | None = None):
    store = Store(tmp_path / "data")
    store.save_wsl_isolation_config("Ubuntu-24.04")
    return store, WSLBubblewrapIsolation(store, runner or FakeRunner())


def test_unconfigured_never_autoselects_a_distro(tmp_path):
    store = Store(tmp_path / "data")
    runner = FakeRunner()
    result = asyncio.run(WSLBubblewrapIsolation(store, runner).probe())
    assert result["status"] == "UNCONFIGURED"
    assert runner.calls == []


def test_forbidden_data_root_is_not_used_for_a_wsl_probe():
    class ForbiddenStore:
        root = Path(r"E:\.codex")

        def wsl_isolation_config(self):
            raise AssertionError("forbidden DATA_ROOT must not be read")

    runner = FakeRunner()
    result = asyncio.run(WSLBubblewrapIsolation(ForbiddenStore(), runner).probe())
    assert result["status"] == MISCONFIGURED
    assert result["error_code"] == "data_root_forbidden"
    assert runner.calls == []


@pytest.mark.parametrize("attribute", ["available", "distro_available", "python_available", "bwrap_available"])
def test_missing_wsl_distro_python_or_bwrap_fails_closed(tmp_path, attribute):
    runner = FakeRunner()
    setattr(runner, attribute, False)
    _, service = configured(tmp_path, runner)
    result = asyncio.run(service.probe())
    assert result["status"] == UNAVAILABLE
    assert result["status"] != SAFE_CANDIDATE


@pytest.mark.parametrize("distro", ["Ubuntu;id", "Ubuntu $(id)", "Ubuntu/../../x", "", "Ubuntu\nwhoami"])
def test_distro_shell_injection_input_is_rejected(tmp_path, distro):
    store = Store(tmp_path / "data")
    with pytest.raises(PolicyError):
        store.save_wsl_isolation_config(distro)


def test_fixed_bwrap_probe_checks_read_write_tmp_network_and_mount_policy(tmp_path):
    store, service = configured(tmp_path)
    result = asyncio.run(service.probe())
    assert result["status"] == SAFE_CANDIDATE
    assert result["inside_read_succeeded"] is True
    assert result["outside_data_denied"] is True
    assert result["host_mount_denied"] is True
    assert result["capsule_write_denied"] is True
    assert result["tmp_write_succeeded"] is True
    assert result["network_denied"] is True
    command = next(call for call in service.runner.calls if "--unshare-all" in call)
    assert "--unshare-all" in command
    assert "--tmpfs" in command and "/tmp" in command
    assert command.count("--ro-bind") >= 6
    assert "/mnt" not in command
    assert command[command.index("--ro-bind") + 2] == "/usr"
    assert len([call for call in service.runner.calls if "/usr/bin/wslpath" in call]) == 1
    assert store.token_ledger_report()["wsl_isolation_probes"] == {
        "executions": 1, "local_duration_ms": result["local_duration_ms"], "tokens": 0, "app_server_rpc_calls": 0,
    }
    ledger_event = next(event for event in store.ledger_usage_events() if event["event_type"] == "WSL_ISOLATION_PROBE")
    assert ledger_event["tokens"] == 0 and ledger_event["app_server_rpc_calls"] == 0


@pytest.mark.parametrize(
    "probe, expected",
    [
        (outcome(markers(OUTSIDE="READ_OK")), UNSAFE_HOST_FS),
        (outcome(markers(HOST="READ_OK")), UNSAFE_HOST_FS),
        (outcome(markers(WRITE="WRITE_OK")), UNSAFE_WRITE),
        (outcome(markers(NETWORK="NETWORK_OK")), UNSAFE_NETWORK),
    ],
)
def test_visible_escape_markers_are_never_safe(tmp_path, probe, expected):
    _, service = configured(tmp_path, FakeRunner(probe=probe))
    assert asyncio.run(service.probe())["status"] == expected


@pytest.mark.parametrize(
    "probe",
    [
        outcome("INSIDE=READ_OK\n"),
        outcome(markers() + "NETWORK=NETWORK_DENIED\n"),
        outcome("x" * (8 * 1024 + 1)),
        asyncio.TimeoutError(),
        outcome(markers(), stderr="unexpected"),
    ],
)
def test_ambiguous_marker_timeout_and_excess_output_are_errors(tmp_path, probe):
    _, service = configured(tmp_path, FakeRunner(probe=probe))
    result = asyncio.run(service.probe())
    assert result["status"] == ERROR


def test_same_config_ttl_is_reused_and_concurrent_probe_runs_once(tmp_path):
    store, service = configured(tmp_path, FakeRunner(delay=0.02))
    async def concurrent_probe():
        return await asyncio.gather(service.probe(), service.probe())

    first, second = asyncio.run(concurrent_probe())
    assert {first["status"], second["status"]} == {SAFE_CANDIDATE}
    assert sum("--unshare-all" in call for call in service.runner.calls) == 1
    third = asyncio.run(service.probe())
    assert third["reused"] is True
    assert sum("--unshare-all" in call for call in service.runner.calls) == 1
    assert store.wsl_isolation_result()["status"] == SAFE_CANDIDATE


def test_offline_canary_refresh_bypasses_a_near_expiry_cache_once(tmp_path):
    store, service = configured(tmp_path)
    first = asyncio.run(service.probe())
    stale = {
        **first,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": (datetime.now(timezone.utc) + timedelta(
            seconds=OFFLINE_CANARY_MIN_REMAINING_SECONDS - 1
        )).isoformat(),
        "reused": False,
    }
    store.save_wsl_isolation_result(stale)
    before = sum("--unshare-all" in call for call in service.runner.calls)
    refreshed = asyncio.run(service.probe(offline_canary_refresh=True))
    after = sum("--unshare-all" in call for call in service.runner.calls)
    assert refreshed["status"] == SAFE_CANDIDATE
    assert refreshed["reused"] is False
    assert after == before + 1
    assert datetime.fromisoformat(refreshed["expires_at"]) - datetime.now(timezone.utc) > timedelta(
        seconds=OFFLINE_CANARY_MIN_REMAINING_SECONDS
    )


def test_orphaned_probing_record_is_recovered_once(tmp_path):
    store = Store(tmp_path / "data")
    now = datetime.now(timezone.utc).isoformat()
    store.save_wsl_isolation_result({
        "backend": "WSL2_BWRAP", "distro": "Ubuntu", "status": "PROBING", "checked_at": now,
        "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat(), "config_hash": "a" * 64,
        "tool_versions": {}, "error_code": None, "inside_read_succeeded": False, "outside_data_denied": False,
        "host_mount_denied": False, "capsule_write_denied": False, "tmp_write_succeeded": False, "network_denied": False,
    })
    assert store.recover_interrupted_wsl_isolation_probes() == 1
    assert store.recover_interrupted_wsl_isolation_probes() == 0
    result = store.wsl_isolation_result()
    assert result["status"] == ERROR
    assert result["error_code"] == "probe_interrupted"


def test_result_hides_paths_canaries_and_raw_output(tmp_path):
    store, service = configured(tmp_path)
    result = asyncio.run(service.probe())
    with sqlite3.connect(store.db_path) as conn:
        payload = conn.execute("SELECT payload FROM wsl_isolation_probe_results").fetchone()[0]
    assert "wsl-isolation-probes" not in payload
    assert "CodexGate/capsule" not in payload
    assert "READ_OK" not in payload
    exposed = public_result(result)
    assert "stdout" not in exposed and "stderr" not in exposed
    assert "canary" not in " ".join(exposed)


def test_safe_candidate_does_not_unlock_gate_start(tmp_path):
    store, service = configured(tmp_path)
    assert asyncio.run(service.probe())["status"] == SAFE_CANDIDATE
    gate = Gate(store)
    with pytest.raises(PolicyError, match="UNKNOWN"):
        asyncio.run(gate.start_run({"route_plan_id": "00000000-0000-4000-8000-000000000000"}))
