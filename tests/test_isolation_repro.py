import asyncio
import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest

from app.isolation_repro import (
    ERROR,
    NONDETERMINISTIC,
    SAFE_REPRODUCIBLE,
    IsolationReproService,
    FRAME_PREFIX,
    FRAME_SCHEMA_VERSION,
    _FIXTURE_HASH,
    parse_frame,
    ReproProtocolError,
    build_repro_fixture_bytes,
    FIXTURE_RELATIVE_PATH,
    WRITE_DENIAL_RELATIVE_PATH,
    canonical_result_hash,
)
from app.isolation_wsl import ProcessResult, SAFE_CANDIDATE
from app.storage import Store


def _safe(store):
    now = datetime.now(timezone.utc)
    store.save_wsl_isolation_config("Ubuntu")
    return store.save_wsl_isolation_result({
        "backend": "WSL2_BWRAP", "distro": "Ubuntu", "status": SAFE_CANDIDATE,
        "checked_at": now.isoformat(), "expires_at": (now + timedelta(minutes=30)).isoformat(),
        "config_hash": "c" * 64, "tool_fingerprint": "t" * 64, "cache_key": "k" * 64,
        "probe_version": "wsl2-bwrap-v1", "tool_versions": {"wsl2": True, "bwrap_present": True},
    })


def _payload(iteration=0, **overrides):
    values = {"schema_version": FRAME_SCHEMA_VERSION, "iteration": iteration, "fixture_sha256": _FIXTURE_HASH,
              "capsule_read": "READ_OK", "outside_read": "READ_DENIED", "host_read": "READ_DENIED",
              "capsule_write": "WRITE_DENIED", "tmp_write": "TMP_WRITE_OK", "network": "NETWORK_DENIED"}
    values.update(overrides)
    return values


def _frame(payload, *, newline="\n"):
    raw = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return FRAME_PREFIX + base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") + newline


def test_fixture_bytes_are_immutable_and_raw_hashes_are_line_ending_sensitive():
    first = build_repro_fixture_bytes()
    assert first == build_repro_fixture_bytes()
    assert b"\r" not in first
    assert hashlib.sha256(first).hexdigest() == _FIXTURE_HASH
    assert hashlib.sha256(first.replace(b"\n", b"\r\n")).hexdigest() != _FIXTURE_HASH
    assert hashlib.sha256(b"\xef\xbb\xbf" + first).hexdigest() != _FIXTURE_HASH
    assert hashlib.sha256(first + b"\n").hexdigest() != _FIXTURE_HASH


def test_fixture_and_write_denial_paths_are_distinct():
    assert FIXTURE_RELATIVE_PATH != WRITE_DENIAL_RELATIVE_PATH


def test_iteration_does_not_change_fixture_or_stable_result_hash():
    one = _payload(1)
    ten = _payload(10)
    assert one["fixture_sha256"] == ten["fixture_sha256"]
    assert canonical_result_hash(one) == canonical_result_hash(ten)
    assert canonical_result_hash(_payload(1, network="NETWORK_OK")) != canonical_result_hash(one)


def test_safe_candidate_runs_ten_fixed_attempts(tmp_path):
    store = Store(tmp_path)
    _safe(store)
    service = IsolationReproService(store)
    calls = []

    async def once(index):
        calls.append(index)
        return _payload(index)

    service._run_once = once
    result = asyncio.run(service.run())
    assert result["status"] == SAFE_REPRODUCIBLE
    assert result["completed_runs"] == result["success_count"] == 10
    assert len(calls) == 10
    assert result["result_hash"]
    assert store.wsl_isolation_result()["status"] == SAFE_CANDIDATE
    assert store.token_ledger_report()["wsl_isolation_repro"]["executions"] == 10


def test_non_safe_state_is_rejected_without_execution(tmp_path):
    store = Store(tmp_path)
    service = IsolationReproService(store)
    service._run_once = lambda index: pytest.fail("must not execute")
    result = asyncio.run(service.run())
    assert result["status"] == "REJECTED"


def test_boundary_failure_is_classified_and_stops(tmp_path):
    store = Store(tmp_path)
    _safe(store)
    service = IsolationReproService(store)
    calls = []

    async def once(index):
        calls.append(index)
        return _payload(index, outside_read="READ_OK")

    service._run_once = once
    result = asyncio.run(service.run())
    assert result["status"] == "UNSAFE_HOST_FS"
    assert result["completed_runs"] == 1
    assert len(calls) == 1


def test_hash_mismatch_is_non_deterministic(tmp_path):
    store = Store(tmp_path)
    _safe(store)
    service = IsolationReproService(store)

    async def once(index):
        return _payload(index, fixture_sha256=_FIXTURE_HASH if index != 4 else "0" * 64)

    service._run_once = once
    result = asyncio.run(service.run())
    assert result["status"] in {ERROR, NONDETERMINISTIC}
    assert result["completed_runs"] == 10


def test_parser_accepts_lf_crlf_and_separate_stderr():
    for newline in ("\n", "\r\n"):
        parsed, diagnostic = parse_frame(ProcessResult(0, _frame(_payload(3), newline=newline), "warning\n"), expected_iteration=3)
        assert parsed["iteration"] == 3
        assert diagnostic["stderr_bytes"] > 0


def test_parser_rejects_duplicate_missing_and_extra_output():
    frame = _frame(_payload(0))
    with pytest.raises(ReproProtocolError) as duplicate:
        parse_frame(ProcessResult(0, frame + frame, ""), expected_iteration=0)
    assert duplicate.value.code == "frame_duplicate"
    with pytest.raises(ReproProtocolError) as missing:
        parse_frame(ProcessResult(0, "", ""), expected_iteration=0)
    assert missing.value.code == "frame_missing"
    with pytest.raises(ReproProtocolError) as extra:
        parse_frame(ProcessResult(0, "noise\n" + frame, ""), expected_iteration=0)
    assert extra.value.code == "frame_extra_output"


def test_parser_rejects_bad_base64_json_schema_iteration_and_hash():
    with pytest.raises(ReproProtocolError) as bad_b64:
        parse_frame(ProcessResult(0, FRAME_PREFIX + "%%%\n", ""), expected_iteration=0)
    assert bad_b64.value.code == "frame_base64_invalid"
    raw = base64.urlsafe_b64encode(b"not-json").decode().rstrip("=")
    with pytest.raises(ReproProtocolError) as bad_json:
        parse_frame(ProcessResult(0, FRAME_PREFIX + raw + "\n", ""), expected_iteration=0)
    assert bad_json.value.code == "frame_json_invalid"
    with pytest.raises(ReproProtocolError) as bad_iteration:
        parse_frame(ProcessResult(0, _frame(_payload(1)), ""), expected_iteration=0)
    assert bad_iteration.value.code == "frame_iteration_mismatch"
    with pytest.raises(ReproProtocolError) as bad_hash:
        parse_frame(ProcessResult(0, _frame(_payload(0, fixture_sha256="0" * 64)), ""), expected_iteration=0)
    assert bad_hash.value.code == "frame_fixture_mismatch"


def test_nonzero_exit_and_output_limit_are_fail_closed():
    with pytest.raises(ReproProtocolError) as nonzero:
        parse_frame(ProcessResult(1, _frame(_payload(0)), ""), expected_iteration=0)
    assert nonzero.value.code == "process_error"
    with pytest.raises(ReproProtocolError) as too_large:
        parse_frame(ProcessResult(0, "x" * 8193, ""), expected_iteration=0)
    assert too_large.value.code == "output_limit"


def test_same_cache_key_is_singleflight(tmp_path):
    store = Store(tmp_path)
    _safe(store)
    service = IsolationReproService(store)
    calls = 0

    async def once(index):
        nonlocal calls
        calls += 1
        await asyncio.sleep(0)
        return _payload(index)

    service._run_once = once
    async def both():
        return await asyncio.gather(service.run(), service.run())

    first, second = asyncio.run(both())
    assert calls == 10
    assert first["status"] == second["status"] == SAFE_REPRODUCIBLE
