from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

import app.main as app_main
from app.isolation_wsl import ProcessResult, SAFE_CANDIDATE
from app.policy import PolicyError, validate_wsl_codex_binary_path
from app.storage import Store
from app.wsl_codex_runtime import (
    BINARY_MISSING,
    BLOCKED,
    EGRESS_UNCONFIGURED,
    ERROR,
    EXPECTED_CODEX_VERSION,
    INVALID_BINARY,
    UNCONFIGURED,
    VERSION_MISMATCH,
    WSLCodexRuntime,
    build_sealed_launch_spec,
    public_runtime_result,
    RUNTIME_IDENTITY_VERSION,
)


def _output(payload: dict, *, exit_code: int = 0, stderr: str = "") -> ProcessResult:
    return ProcessResult(
        exit_code=exit_code,
        stdout=json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
        stderr=stderr,
    )


class FakeRuntimeRunner:
    def __init__(self, result: dict | None = None):
        self.result = result or {
            "status": "OK",
            "sha256": "a" * 64,
            "version": EXPECTED_CODEX_VERSION,
            "size": 42,
            "mtime_ns": 7,
            "error": None,
        }
        self.calls: list[list[str]] = []
        self.available = True

    def find_wsl(self) -> str | None:
        return "wsl.exe" if self.available else None

    async def run(self, args: list[str], *, timeout_seconds: float) -> ProcessResult:
        self.calls.append(args)
        assert args[:7] == ["wsl.exe", "-d", "Ubuntu", "--exec", "/usr/bin/python3", "-I", "-S"]
        assert args[7] == "-c"
        assert args[-1] in {"/usr/local/bin/codex", "/home/alice/.local/bin/codex"}
        assert "app-server" not in args
        return _output(self.result)


def _safe_isolation(store: Store, *, cache_key: str = "c" * 64) -> None:
    now = datetime.now(timezone.utc)
    store.save_wsl_isolation_config("Ubuntu")
    store.save_wsl_isolation_result({
        "backend": "WSL2_BWRAP",
        "distro": "Ubuntu",
        "status": SAFE_CANDIDATE,
        "checked_at": now.isoformat(),
        "expires_at": (now + timedelta(minutes=30)).isoformat(),
        "config_hash": "f" * 64,
        "tool_fingerprint": "b" * 64,
        "cache_key": cache_key,
        "probe_version": "wsl2-bwrap-v1",
        "tool_versions": {"wsl2": True, "bwrap_present": True},
    })


def _service(tmp_path, runner: FakeRuntimeRunner | None = None) -> tuple[Store, WSLCodexRuntime, FakeRuntimeRunner]:
    store = Store(tmp_path / "data")
    _safe_isolation(store)
    fake = runner or FakeRuntimeRunner()
    return store, WSLCodexRuntime(store, fake), fake


@pytest.mark.parametrize("value", [
    "", "codex", "../codex", "/mnt/c/codex", "/usr/bin/codex", "/usr/local/bin/codex;id",
    "/usr/local/bin/codex --version", "/usr/local/bin/codex\n", r"C:\\codex.cmd",
])
def test_binary_path_policy_rejects_shell_and_allowlist_escapes(value):
    with pytest.raises(PolicyError):
        validate_wsl_codex_binary_path(value)


def test_runtime_is_unconfigured_without_a_private_binary_selection(tmp_path):
    store, service, runner = _service(tmp_path)
    result = asyncio.run(service.preflight())
    assert result["status"] == UNCONFIGURED
    assert result["binary_configured"] is False
    assert result["start_allowed"] is False
    assert runner.calls == []


def test_runtime_requires_matching_safe_wsl_isolation_before_any_binary_command(tmp_path):
    store = Store(tmp_path / "data")
    store.save_wsl_isolation_config("Ubuntu")
    store.save_wsl_codex_runtime_config("/usr/local/bin/codex")
    runner = FakeRuntimeRunner()
    result = asyncio.run(WSLCodexRuntime(store, runner).preflight())
    assert result["status"] == BLOCKED
    assert result["error_code"] == "isolation_not_safe"
    assert result["binary_configured"] is True
    assert runner.calls == []


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        ({"status": BINARY_MISSING, "sha256": None, "version": None, "size": None, "mtime_ns": None, "error": "binary_missing"}, BINARY_MISSING),
        ({"status": INVALID_BINARY, "sha256": None, "version": None, "size": None, "mtime_ns": None, "error": "binary_symlink"}, INVALID_BINARY),
        ({"status": INVALID_BINARY, "sha256": None, "version": None, "size": None, "mtime_ns": None, "error": "binary_not_file"}, INVALID_BINARY),
        ({"status": INVALID_BINARY, "sha256": None, "version": None, "size": None, "mtime_ns": None, "error": "binary_not_executable"}, INVALID_BINARY),
    ],
)
def test_missing_directory_symlink_and_non_executable_binaries_fail_closed(tmp_path, payload, expected):
    store, service, _ = _service(tmp_path, FakeRuntimeRunner(payload))
    store.save_wsl_codex_runtime_config("/usr/local/bin/codex")
    result = asyncio.run(service.preflight())
    assert result["status"] == expected
    assert result["binary_configured"] is True


def test_expected_version_forms_private_ready_candidate_but_egress_blocks_start(tmp_path):
    store, service, runner = _service(tmp_path)
    store.save_wsl_codex_runtime_config("/usr/local/bin/codex")
    result = asyncio.run(service.preflight())
    assert result["status"] == EGRESS_UNCONFIGURED
    assert result["preflight_status"] == "READY_CANDIDATE"
    assert result["version_match"] is True
    assert result["isolation_match"] is True
    assert result["egress_blocked"] is True
    assert result["start_allowed"] is False
    assert len(runner.calls) == 1
    with pytest.raises(PolicyError, match="egress"):
        service.start()


def test_version_mismatch_does_not_regenerate_schema_or_build_launch_spec(tmp_path):
    runner = FakeRuntimeRunner({
        "status": "OK", "sha256": "a" * 64, "version": "codex-cli 0.146.0",
        "size": 42, "mtime_ns": 7, "error": None,
    })
    store, service, _ = _service(tmp_path, runner)
    store.save_wsl_codex_runtime_config("/usr/local/bin/codex")
    result = asyncio.run(service.preflight())
    assert result["status"] == VERSION_MISMATCH
    assert result["launch_spec_hash"] is None
    assert result["version_match"] is False


def test_binary_or_isolation_change_changes_runtime_identity_and_spec_binding(tmp_path):
    store, service, runner = _service(tmp_path)
    store.save_wsl_codex_runtime_config("/usr/local/bin/codex")
    first = asyncio.run(service.preflight())
    runner.result = {**runner.result, "sha256": "d" * 64}
    second = asyncio.run(service.preflight())
    assert first["runtime_fingerprint"] != second["runtime_fingerprint"]
    _safe_isolation(store, cache_key="e" * 64)
    third = asyncio.run(service.preflight())
    assert third["runtime_fingerprint"] != second["runtime_fingerprint"]
    assert third["launch_spec_hash"] != second["launch_spec_hash"]


def test_private_launch_spec_is_read_only_minimal_and_does_not_inherit_environment():
    spec = build_sealed_launch_spec("/home/alice/.local/bin/codex")
    assert spec["cwd"] == "/work"
    assert spec["network"] == "blocked"
    assert spec["tmpfs"] == ["/tmp", "/runtime-state", "/home"]
    assert spec["home"] == "/home/codex"
    assert spec["environment"] == {
        "PATH": "/usr/bin:/bin", "HOME": "/home/codex", "TMPDIR": "/tmp", "LANG": "C.UTF-8",
    }
    assert "--unshare-all" in spec["argv"] and "--clearenv" in spec["argv"]
    assert all(item not in spec["argv"] for item in ("/mnt", "C:\\Users", "DATA_ROOT"))
    assert any(bind == {"source": "CAPSULE_SOURCE", "target": "/work", "mode": "ro"} for bind in spec["binds"])
    assert all(bind["mode"] == "ro" for bind in spec["binds"])


def test_public_storage_api_and_ledger_do_not_reveal_binary_paths_argv_or_auth(tmp_path):
    store, service, _ = _service(tmp_path)
    store.save_wsl_codex_runtime_config("/usr/local/bin/codex")
    result = asyncio.run(service.preflight())
    public = public_runtime_result(store.wsl_codex_runtime_result())
    serialized = json.dumps({"result": result, "public": public, "ledger": store.token_ledger_report()})
    assert "/usr/local/bin/codex" not in serialized
    assert "argv" not in public and "environment" not in public and "auth" not in public
    ledger = store.token_ledger_report()["wsl_codex_runtime_preflight"]
    assert ledger["executions"] == 1
    assert ledger["tokens"] == ledger["app_server_rpc_calls"] == 0


def test_http_runtime_config_and_status_never_return_the_selected_binary_path(tmp_path, monkeypatch):
    monkeypatch.setattr(app_main, "DATA_ROOT", tmp_path / "data")
    with TestClient(app_main.app, base_url="http://127.0.0.1:8787") as client:
        configured = client.post(
            "/api/isolation/wsl/runtime/config", json={"binary_path": "/usr/local/bin/codex"}
        )
        status = client.get("/api/isolation/wsl/runtime")
        overall = client.get("/api/status")
    assert configured.status_code == status.status_code == overall.status_code == 200
    serialized = json.dumps([configured.json(), status.json(), overall.json()])
    assert "/usr/local/bin/codex" not in serialized
    assert "argv" not in status.json() and "environment" not in status.json() and "auth" not in status.json()


def test_invalid_runner_output_fails_closed_without_a_codex_process(tmp_path):
    store, service, runner = _service(tmp_path, FakeRuntimeRunner({"bad": "output"}))
    store.save_wsl_codex_runtime_config("/usr/local/bin/codex")
    result = asyncio.run(service.preflight())
    assert result["status"] == ERROR
    assert result["error_code"] == "preflight_output_invalid"
    assert len(runner.calls) == 1
    assert all("app-server" not in call for call in runner.calls)


def test_result_integrity_detects_tampering(tmp_path):
    store, service, _ = _service(tmp_path)
    store.save_wsl_codex_runtime_config("/usr/local/bin/codex")
    asyncio.run(service.preflight())
    with store._connection() as conn:
        conn.execute("UPDATE wsl_codex_runtime_results SET integrity_hash=? WHERE singleton=1", ("0" * 64,))
    with pytest.raises(PolicyError, match="integrity"):
        store.wsl_codex_runtime_result()


def test_legacy_success_row_without_binary_sha_is_read_only_blocked(tmp_path):
    store, service, _ = _service(tmp_path)
    store.save_wsl_codex_runtime_config("/usr/local/bin/codex")
    asyncio.run(service.preflight())
    with store._connection() as conn:
        row = conn.execute("SELECT payload FROM wsl_codex_runtime_results WHERE singleton=1").fetchone()
        payload = json.loads(row[0])
        for field in ("binary_sha256", "identity_version", "identity_complete", "isolation_cache_key"):
            payload.pop(field, None)
        payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        from app.policy import sha256_json
        before = payload_json
        conn.execute(
            "UPDATE wsl_codex_runtime_results SET identity_version=NULL, payload=?, integrity_hash=? WHERE singleton=1",
            (payload_json, sha256_json(payload)),
        )
    result = store.wsl_codex_runtime_result()
    assert result["status"] == BLOCKED
    assert result["error_code"] == "runtime_identity_incomplete"
    assert result["identity_complete"] is False
    with store._connection() as conn:
        after = conn.execute("SELECT payload FROM wsl_codex_runtime_results WHERE singleton=1").fetchone()[0]
    assert after == before


def test_runtime_identity_version_and_binary_sha_are_required_for_success_write(tmp_path):
    store, service, _ = _service(tmp_path)
    store.save_wsl_codex_runtime_config("/usr/local/bin/codex")
    complete = asyncio.run(service.preflight())
    assert complete["identity_version"] == RUNTIME_IDENTITY_VERSION
    assert complete["identity_complete"] is True
    assert complete["isolation_cache_key"] == "c" * 64
    missing = dict(complete)
    missing.pop("binary_sha256")
    missing.pop("integrity_hash", None)
    with pytest.raises(PolicyError, match="identity"):
        store.save_wsl_codex_runtime_result(missing)
    for bad_sha in ("z" * 64, "a" * 63, "a" * 65):
        invalid = dict(complete, binary_sha256=bad_sha)
        invalid.pop("integrity_hash", None)
        with pytest.raises(PolicyError, match="digest"):
            store.save_wsl_codex_runtime_result(invalid)


def test_identity_migration_is_repeatable_without_legacy_backfill(tmp_path):
    store, service, _ = _service(tmp_path)
    store.save_wsl_codex_runtime_config("/usr/local/bin/codex")
    asyncio.run(service.preflight())
    with store._connection() as conn:
        row = conn.execute("SELECT payload FROM wsl_codex_runtime_results WHERE singleton=1").fetchone()
        payload = json.loads(row[0])
        for field in ("binary_sha256", "identity_version", "identity_complete", "isolation_cache_key"):
            payload.pop(field, None)
        from app.policy import sha256_json
        payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        conn.execute(
            "UPDATE wsl_codex_runtime_results SET identity_version=NULL, payload=?, integrity_hash=? WHERE singleton=1",
            (payload_json, sha256_json(payload)),
        )
    Store(tmp_path / "data")
    Store(tmp_path / "data")
    with store._connection() as conn:
        persisted = json.loads(conn.execute("SELECT payload FROM wsl_codex_runtime_results WHERE singleton=1").fetchone()[0])
    assert "binary_sha256" not in persisted
    assert "identity_version" not in persisted
