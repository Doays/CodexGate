from __future__ import annotations

import asyncio
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app.gateway import Gate
from app.isolation import (
    ERROR,
    READ_DENIED,
    READ_ERROR,
    READ_OK,
    SAFE_CANDIDATE,
    UNKNOWN,
    UNSAFE_FULL_DISK_READ,
    public_result,
    run_isolation_probe,
)
from app.policy import PolicyError
from app.storage import Store


class ProbeClient:
    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.calls = []
        self.closed = False

    async def prepare_for_command_exec(self, schema_dir: Path):
        schema_dir.mkdir(parents=True, exist_ok=True)
        return {"codex_version": "codex 0.145.0", "schema_sha256": "schema-145"}

    async def connect_for_command_exec(self):
        self.calls.append("connect")

    def read_only_sandbox_policy(self):
        return {"type": "readOnly", "networkAccess": False}

    async def command_exec(self, params, *, timeout_seconds=10):
        self.calls.append(("command/exec", params, timeout_seconds))
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    async def close(self):
        self.closed = True


class MetadataClient:
    def __init__(self, *, version="test", schema="test-schema"):
        self.version = version
        self.schema = schema
        self.installation_metadata_calls = 0
        self.connected = False

    async def installation_metadata(self, schema_dir):
        self.installation_metadata_calls += 1
        return {"codex_version": self.version, "schema_sha256": self.schema}


def response(marker: str | None, *, exit_code: int | None = None, newline: str = "\n", stderr: str = ""):
    defaults = {READ_OK: 0, READ_DENIED: 13, READ_ERROR: 17}
    code = defaults.get(marker, 1) if exit_code is None else exit_code
    stdout = f"{marker}{newline}" if marker else ""
    return {"exitCode": code, "stdout": stdout, "stderr": stderr}


def saved_result(status: str, *, days=1, outside_read_succeeded=False, outside_denied_explicitly=False):
    now = datetime.now(timezone.utc)
    return {
        "status": status,
        "checked_at": now.isoformat(),
        "expires_at": (now + timedelta(days=days)).isoformat(),
        "codex_version": "test",
        "schema_sha256": "test-schema",
        "inside_read_succeeded": status in {"SAFE_CAPSULE_ONLY", SAFE_CANDIDATE, UNSAFE_FULL_DISK_READ},
        "outside_read_succeeded": outside_read_succeeded,
        "outside_denied_explicitly": outside_denied_explicitly,
        "reason": None,
    }


def test_command_exec_omits_output_caps_and_uses_isolated_python_command(tmp_path):
    store = Store(tmp_path / "data")
    client = ProbeClient([response(READ_OK), response(READ_DENIED)])

    result = asyncio.run(run_isolation_probe(store, client))

    assert result["status"] == SAFE_CANDIDATE
    commands = [entry for entry in client.calls if isinstance(entry, tuple)]
    assert len(commands) == 2
    assert all(entry[0] == "command/exec" for entry in commands)
    for _, params, timeout_seconds in commands:
        assert params["command"][:4] == [sys.executable, "-I", "-S", "-c"]
        assert params["timeoutMs"] == 10_000
        assert timeout_seconds == 10
        assert "outputBytesCap" not in params
        assert "disableOutputCap" not in params
        assert params["cwd"].endswith("capsule")
        assert params["sandboxPolicy"] == {"type": "readOnly", "networkAccess": False}
    assert client.closed is True
    assert not list((store.root / "isolation-probes").glob("**/*"))


@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_lf_and_crlf_read_ok_are_both_accepted(tmp_path, newline):
    result = asyncio.run(run_isolation_probe(Store(tmp_path / "data"), ProbeClient([
        response(READ_OK, newline=newline),
        response(READ_DENIED, newline=newline),
    ])))
    assert result["status"] == SAFE_CANDIDATE
    assert result["inside_read_succeeded"] is True
    assert result["outside_denied_explicitly"] is True


def test_only_explicit_read_denied_is_safe_candidate(tmp_path):
    result = asyncio.run(run_isolation_probe(Store(tmp_path / "data"), ProbeClient([
        response(READ_OK),
        response(READ_DENIED),
    ])))
    assert result["status"] == SAFE_CANDIDATE
    assert result["outside_read_succeeded"] is False
    assert result["outside_denied_explicitly"] is True
    assert result["reason"] == "outside_denied_explicitly"


def test_general_exit_one_and_empty_output_is_error(tmp_path):
    result = asyncio.run(run_isolation_probe(Store(tmp_path / "data"), ProbeClient([
        response(READ_OK),
        response(None, exit_code=1),
    ])))
    assert result["status"] == ERROR
    assert result["outside_result"] == "command_error"
    assert result["outside_denied_explicitly"] is False


@pytest.mark.parametrize(
    "outcomes, expected_code",
    [
        ([response(READ_OK), response(READ_ERROR)], "outside_read_error"),
        ([asyncio.TimeoutError()], "timeout"),
        ([RuntimeError("schema validation failed")], "schema_error"),
    ],
)
def test_read_error_timeout_and_schema_error_become_error(tmp_path, outcomes, expected_code):
    result = asyncio.run(run_isolation_probe(Store(tmp_path / "data"), ProbeClient(outcomes)))
    assert result["status"] == ERROR
    assert result["error_code"] == expected_code


def test_outside_read_ok_is_unsafe(tmp_path):
    result = asyncio.run(run_isolation_probe(Store(tmp_path / "data"), ProbeClient([
        response(READ_OK),
        response(READ_OK),
    ])))
    assert result["status"] == UNSAFE_FULL_DISK_READ
    assert result["outside_read_succeeded"] is True
    assert result["outside_denied_explicitly"] is False


def test_safe_candidate_still_blocks_start_run(tmp_path):
    store = Store(tmp_path / "data")
    store.save_isolation_result(saved_result(SAFE_CANDIDATE, outside_denied_explicitly=True))
    gate = Gate(store)
    gate.client = MetadataClient()

    with pytest.raises(PolicyError, match="SAFE_CANDIDATE"):
        asyncio.run(gate.start_run({"route_plan_id": "00000000-0000-4000-8000-000000000000"}))
    assert gate.client.installation_metadata_calls == 1


def test_stored_unsafe_blocks_before_metadata_lookup(tmp_path):
    store = Store(tmp_path / "data")
    store.save_isolation_result(saved_result(UNSAFE_FULL_DISK_READ, outside_read_succeeded=True))
    gate = Gate(store)
    gate.client = MetadataClient()

    with pytest.raises(PolicyError, match="UNSAFE_FULL_DISK_READ"):
        asyncio.run(gate.start_run({"route_plan_id": "00000000-0000-4000-8000-000000000000"}))
    assert gate.client.installation_metadata_calls == 0


def test_version_or_schema_change_invalidates_safe_candidate(tmp_path):
    store = Store(tmp_path / "data")
    store.save_isolation_result(saved_result(SAFE_CANDIDATE, outside_denied_explicitly=True))
    assert store.isolation_result("new", "test-schema")["status"] == UNKNOWN
    store.save_isolation_result(saved_result(SAFE_CANDIDATE, outside_denied_explicitly=True))
    assert store.isolation_result("test", "new-schema")["status"] == UNKNOWN


def test_canary_path_and_raw_stderr_are_not_stored_or_exposed(tmp_path):
    store = Store(tmp_path / "data")
    result = asyncio.run(run_isolation_probe(store, ProbeClient([
        response(READ_OK),
        response(READ_DENIED, stderr="TOP SECRET STDERR"),
    ])))

    with sqlite3.connect(store.db_path) as conn:
        raw = conn.execute("SELECT payload FROM isolation_probe_results").fetchone()[0]
    assert "TOP SECRET STDERR" not in raw
    assert "isolation-probes" not in raw
    assert "outside_path" not in raw
    exposed = public_result(result)
    assert "inside_canary_sha256" not in exposed
    assert "outside_canary_sha256" not in exposed
    assert "inside_result" not in exposed


def test_probe_never_starts_thread_or_turn(tmp_path):
    client = ProbeClient([response(READ_OK), response(READ_DENIED)])

    asyncio.run(run_isolation_probe(Store(tmp_path / "data"), client))

    methods = [entry[0] for entry in client.calls if isinstance(entry, tuple)]
    assert methods == ["command/exec", "command/exec"]
