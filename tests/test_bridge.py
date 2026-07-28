from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from time import sleep

import pytest

from app.bridge import (
    ARCHITECT_READY,
    ARCHITECT_RESPONSE,
    BEGIN_MARKER,
    END_MARKER,
    HOLD,
    NEED_MORE_EVIDENCE,
    PROCESSING_RESPONSE,
    REDESIGN,
    REVIEW_RESPONSE,
    ROUTE_READY,
    WAITING_ARCHITECT,
    WAITING_REVIEW,
    BridgeService,
    parse_bridge_packet,
)
from app.policy import BRIDGE_SCHEMA_VERSION, PolicyError, sha256_json
from app.storage import Store


def decision():
    return {
        "decision": "execute",
        "task_class": "T3",
        "recommended_model": "gpt-terra",
        "recommended_effort": "high",
        "allowed_files": [],
        "forbidden_files": [],
        "validation_commands": [],
        "stop_conditions": [],
        "evidence_files": [],
        "evidence_ranges": [],
        "risk": "medium",
        "parallel_audit": False,
        "independent_axes": 0,
    }


def evidence(label="test output", *, required=True, kind="file_metadata"):
    return {"type": kind, "label": label, "reason": "bounded local context", "required": required, "target_hint": "user maps a local file"}


class PlanCreator:
    def __init__(self, *, fail: bool = False, delay: float = 0):
        self.calls, self.fail, self.delay = [], fail, delay

    def __call__(self, payload):
        self.calls.append(payload)
        if self.delay:
            sleep(self.delay)
        if self.fail:
            raise RuntimeError("local plan error")
        return {"plan_id": "00000000-0000-4000-8000-000000000001", "status": "PREVIEW"}


def service(tmp_path: Path, **kwargs):
    creator = PlanCreator(**kwargs)
    return BridgeService(Store(tmp_path / "data"), creator), creator


def started(bridge: BridgeService):
    return bridge.create({"project_name": "Demo", "project_id": "demo", "root": str(Path.cwd()), "task": "Inspect a bounded local scope", "permission": "read-only", "chat_url": "https://chatgpt.com/"})


def reply(kind, task, body, *, nonce=None, phase=None, prose=False):
    envelope = {"TYPE": kind, "TASK_ID": task["task_id"], "PHASE": phase or task["phase"], "NONCE": nonce or task["pending_nonce"], "SCHEMA_VERSION": BRIDGE_SCHEMA_VERSION, "BODY": body}
    packet = f"{BEGIN_MARKER}\n{json.dumps(envelope, ensure_ascii=False)}\n{END_MARKER}"
    return f"Here is the response:\n```json\n{packet}\n```\nThanks." if prose else packet


def waiting_architect(bridge: BridgeService):
    task = started(bridge)
    assert bridge.packet(task["task_id"]) == bridge.packet(task["task_id"])
    return bridge.copied(task["task_id"])


def plan_ready(bridge: BridgeService):
    waiting = waiting_architect(bridge)
    return bridge.import_response(waiting["task_id"], reply(ARCHITECT_RESPONSE, waiting, {"outcome": "execute", "decision": decision()}))


def nonce_row(bridge: BridgeService, task_id: str, nonce: str):
    with bridge.store._connection() as conn:  # noqa: SLF001 - test-only direct check
        return conn.execute(
            """SELECT consumed_at, claimed_at, completed_at, failed_at, error_code, response_hash
               FROM bridge_nonces WHERE task_id = ? AND nonce = ?""",
            (task_id, nonce),
        ).fetchone()


def mark_processing(bridge: BridgeService, waiting: dict[str, str], *, minutes_old: int = 3):
    raw = reply(ARCHITECT_RESPONSE, waiting, {"outcome": "execute", "decision": decision()})
    envelope = parse_bridge_packet(raw)
    response_hash = sha256_json(envelope)
    old_time = (datetime.now(timezone.utc) - timedelta(minutes=minutes_old)).isoformat()
    processing = {
        **bridge.store.load_bridge_task(waiting["task_id"]),
        "status": PROCESSING_RESPONSE,
        "active_action": "processing_response",
        "updated_at": old_time,
    }
    bridge.store.claim_bridge_response(
        waiting["task_id"],
        waiting["pending_nonce"],
        response_hash,
        task_payload=processing,
        received_hash=response_hash,
    )
    return response_hash


def test_v2_request_is_stable_and_response_needs_no_hash(tmp_path):
    bridge, _ = service(tmp_path)
    task = started(bridge)
    first, second = bridge.packet(task["task_id"]), bridge.packet(task["task_id"])
    assert first == second
    envelope = json.loads(first.splitlines()[1])
    assert {"CREATED_AT", "EXPIRES_AT", "REQUEST_SHA256"} <= set(envelope)
    assert "BODY_SHA256" not in envelope
    waiting = bridge.copied(task["task_id"])
    result = bridge.import_response(waiting["task_id"], reply(ARCHITECT_RESPONSE, waiting, {"outcome": "execute", "decision": decision()}))
    row = nonce_row(bridge, waiting["task_id"], waiting["pending_nonce"])
    assert result["status"] == ROUTE_READY and result["response_hash"]
    assert row[1] is not None and row[2] is not None and row[3] is None and row[4] is None


def test_contract_has_architect_and_all_review_examples(tmp_path):
    bridge, _ = service(tmp_path)
    body = json.loads(bridge.packet(started(bridge)["task_id"]).splitlines()[1])["BODY"]
    contract = body["RESPONSE_CONTRACT"]
    assert set(contract) >= {"architect_execute", "architect_need_more_evidence"}
    ready = plan_ready(bridge)
    review = bridge.prepare_review(ready["task_id"], {"result": "local"}, {"tests": "not run"})
    review_contract = json.loads(bridge.packet(review["task_id"]).splitlines()[1])["BODY"]["RESPONSE_CONTRACT"]
    assert set(review_contract["review_verdicts"]) == {"SUCCESS", "HOLD", "RETRY", "REDESIGN", "ROLLBACK"}


def test_single_marker_accepts_code_fence_and_prose_but_rejects_duplicate_truncated_and_nonce(tmp_path):
    bridge, _ = service(tmp_path)
    waiting = waiting_architect(bridge)
    raw = reply(ARCHITECT_RESPONSE, waiting, {"outcome": "execute", "decision": decision()}, prose=True)
    assert parse_bridge_packet(raw)["TYPE"] == ARCHITECT_RESPONSE
    with pytest.raises(PolicyError, match="exactly one"):
        parse_bridge_packet(raw + "\n" + raw)
    with pytest.raises(PolicyError):
        parse_bridge_packet(f"{BEGIN_MARKER}\n{{}}")
    with pytest.raises(PolicyError, match="does not match"):
        bridge.import_response(waiting["task_id"], reply(ARCHITECT_RESPONSE, waiting, {"outcome": "execute", "decision": decision()}, nonce="00000000-0000-4000-8000-000000000099"))


def test_concurrent_architect_import_claims_nonce_and_creates_one_plan(tmp_path):
    bridge, creator = service(tmp_path, delay=0.1)
    waiting = waiting_architect(bridge)
    raw = reply(ARCHITECT_RESPONSE, waiting, {"outcome": "execute", "decision": decision()})
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: bridge.import_response(waiting["task_id"], raw), range(2)))
    assert len(creator.calls) == 1
    assert all(result["status"] != WAITING_ARCHITECT for result in results)
    assert bridge.get(waiting["task_id"])["status"] == ROUTE_READY
    assert creator.calls[0]["bridge_idempotency_key"].startswith("bridge:")


def test_same_response_replay_is_idempotent(tmp_path):
    bridge, creator = service(tmp_path)
    waiting = waiting_architect(bridge)
    raw = reply(ARCHITECT_RESPONSE, waiting, {"outcome": "execute", "decision": decision()})
    first = bridge.import_response(waiting["task_id"], raw)
    second = bridge.import_response(waiting["task_id"], raw)
    assert first["task_id"] == second["task_id"] and len(creator.calls) == 1 and second["status"] == ROUTE_READY


def test_route_plan_failure_consumes_nonce_and_requires_new_cycle(tmp_path):
    bridge, _ = service(tmp_path, fail=True)
    waiting = waiting_architect(bridge)
    raw = reply(ARCHITECT_RESPONSE, waiting, {"outcome": "execute", "decision": decision()})
    with pytest.raises(PolicyError, match="creation failed"):
        bridge.import_response(waiting["task_id"], raw)
    failed = bridge.get(waiting["task_id"])
    row = nonce_row(bridge, waiting["task_id"], waiting["pending_nonce"])
    assert failed["status"] == HOLD
    assert bridge.import_response(waiting["task_id"], raw)["status"] == HOLD
    assert row[3] is not None and row[4] == "route_plan_failed" and row[2] is None
    restarted = bridge.restart(waiting["task_id"])
    assert restarted["status"] == ARCHITECT_READY and restarted["pending_nonce"] != waiting["pending_nonce"]


def test_retry_keeps_review_notes_and_redesign_feedback_persists(tmp_path):
    bridge, _ = service(tmp_path)
    ready = plan_ready(bridge)
    review = bridge.prepare_review(ready["task_id"], {"result": "local"}, {"tests": "not run"})
    waiting = bridge.copied(review["task_id"])
    retried = bridge.import_response(waiting["task_id"], reply(REVIEW_RESPONSE, waiting, {"verdict": "RETRY", "notes": "fix validation", "requested_evidence": [evidence("stale evidence")] }))
    assert retried["status"] == ARCHITECT_READY and retried["requested_evidence"] == []
    packet = json.loads(bridge.packet(retried["task_id"]).splitlines()[1])
    assert packet["BODY"]["review_feedback"]["notes"] == "fix validation"

    ready = plan_ready(bridge)
    review = bridge.prepare_review(ready["task_id"], {"result": "local"}, {"tests": "not run"})
    waiting = bridge.copied(review["task_id"])
    redesigned = bridge.import_response(waiting["task_id"], reply(REVIEW_RESPONSE, waiting, {"verdict": "REDESIGN", "notes": "redesign path", "requested_evidence": [evidence("diagram")] }))
    assert redesigned["status"] == REDESIGN
    restarted = bridge.restart(redesigned["task_id"])
    packet = json.loads(bridge.packet(restarted["task_id"]).splitlines()[1])
    assert packet["BODY"]["review_feedback"]["notes"] == "redesign path"
    assert packet["BODY"]["review_feedback"]["requested_evidence"][0]["label"] == "diagram"


def test_need_more_evidence_is_flag_only_and_cannot_copy(tmp_path):
    bridge, _ = service(tmp_path)
    waiting = waiting_architect(bridge)
    task = bridge.import_response(waiting["task_id"], reply(ARCHITECT_RESPONSE, waiting, {"outcome": "need_more_evidence", "requested_evidence": [evidence()] }))
    assert task["status"] == NEED_MORE_EVIDENCE and task["evidence_required"] is True
    with pytest.raises(PolicyError, match="EVIDENCE_REQUIRED"):
        bridge.packet(task["task_id"])


def test_v1_pending_task_is_restart_required_not_converted(tmp_path):
    store = Store(tmp_path / "data")
    store.create_bridge_task({"task_id": "00000000-0000-4000-8000-000000000002", "project_id": "demo", "status": "ARCHITECT_READY", "active_action": "copy_architect_request", "phase": "ARCHITECT", "packet_type": "ARCHITECT_REQUEST", "pending_nonce": "00000000-0000-4000-8000-000000000003", "created_at": "2026-01-01T00:00:00+00:00", "updated_at": "2026-01-01T00:00:00+00:00"})
    bridge = BridgeService(store, PlanCreator())
    assert bridge.latest()["restart_required"] is True
    with pytest.raises(PolicyError, match="restart-required"):
        bridge.restart("00000000-0000-4000-8000-000000000002")


def test_read_only_only_and_no_app_server_rpc(tmp_path):
    bridge, creator = service(tmp_path)
    with pytest.raises(PolicyError, match="Read Only"):
        bridge.create({"project_id": "demo", "root": "C:\\local", "task": "bounded", "permission": "workspace-write"})
    ready = plan_ready(bridge)
    assert len(creator.calls) == 1  # The fake local callback has no RPC transport.


def test_history_stores_hash_not_raw_response_and_frontend_has_clipboard_fallback(tmp_path):
    bridge, _ = service(tmp_path)
    waiting = waiting_architect(bridge)
    raw = reply(ARCHITECT_RESPONSE, waiting, {"outcome": "execute", "decision": decision()})
    bridge.import_response(waiting["task_id"], raw)
    assert raw not in json.dumps(bridge.store.bridge_history(waiting["task_id"]))
    source = (Path(__file__).parents[1] / "app" / "static" / "app.js").read_text(encoding="utf-8")
    assert "navigator.clipboard.writeText" in source and "navigator.clipboard.readText" in source and "restoreBridge" in source
    assert source.count("function bridgePresentation(") == 1
    assert source.count("function renderBridge(") == 1
    assert "bridgePresentationLegacy" not in source
    assert "renderBridgeLegacy" not in source
    assert "processing_response" in source


@pytest.mark.parametrize("verdict,expected", [("SUCCESS", "SUCCESS"), ("HOLD", "HOLD"), ("RETRY", ARCHITECT_READY), ("REDESIGN", "REDESIGN"), ("ROLLBACK", "ROLLBACK")])
def test_all_review_verdicts_are_strict_and_transition(tmp_path, verdict, expected):
    bridge, _ = service(tmp_path)
    ready = plan_ready(bridge)
    review = bridge.prepare_review(ready["task_id"], {"result": "local"}, {"tests": "not run"})
    waiting = bridge.copied(review["task_id"])
    result = bridge.import_response(waiting["task_id"], reply(REVIEW_RESPONSE, waiting, {"verdict": verdict, "notes": "bounded", "requested_evidence": []}))
    assert result["status"] == expected
    if verdict == "REDESIGN":
        restarted = bridge.restart(result["task_id"])
        packet = json.loads(bridge.packet(restarted["task_id"]).splitlines()[1])
        assert packet["BODY"]["review_feedback"]["notes"] == "bounded"
        assert packet["BODY"]["review_feedback"]["requested_evidence"] == []


def test_unknown_response_fields_and_limits_are_rejected(tmp_path):
    bridge, _ = service(tmp_path)
    waiting = waiting_architect(bridge)
    bad = {"outcome": "execute", "decision": decision(), "extra": True}
    with pytest.raises(PolicyError, match="unsupported"):
        bridge.import_response(waiting["task_id"], reply(ARCHITECT_RESPONSE, waiting, bad))
    assert bridge.get(waiting["task_id"])["status"] == WAITING_ARCHITECT
    corrected = bridge.import_response(waiting["task_id"], reply(ARCHITECT_RESPONSE, waiting, {"outcome": "execute", "decision": decision()}))
    assert corrected["status"] == ROUTE_READY

    ready = plan_ready(bridge)
    review = bridge.prepare_review(ready["task_id"], {"result": "local"}, {"tests": "not run"})
    waiting_review = bridge.copied(review["task_id"])
    with pytest.raises(PolicyError, match="notes"):
        bridge.import_response(waiting_review["task_id"], reply(REVIEW_RESPONSE, waiting_review, {"verdict": "HOLD", "notes": "x" * 5000, "requested_evidence": []}))
    assert bridge.get(waiting_review["task_id"])["status"] == WAITING_REVIEW
    resolved = bridge.import_response(waiting_review["task_id"], reply(REVIEW_RESPONSE, waiting_review, {"verdict": "HOLD", "notes": "bounded", "requested_evidence": []}))
    assert resolved["status"] == HOLD


def test_expired_response_is_rejected(tmp_path):
    bridge, _ = service(tmp_path)
    task = started(bridge)
    record = bridge.store.load_bridge_task(task["task_id"])
    BridgeService._seal_request(record, datetime.now(timezone.utc) - timedelta(hours=1))
    bridge.store.update_bridge_task(task["task_id"], record)
    waiting = bridge.copied(task["task_id"])
    with pytest.raises(PolicyError, match="expired"):
        bridge.import_response(waiting["task_id"], reply(ARCHITECT_RESPONSE, waiting, {"outcome": "execute", "decision": decision()}))
    expired = bridge.get(task["task_id"])
    row = nonce_row(bridge, waiting["task_id"], waiting["pending_nonce"])
    assert expired["status"] == HOLD and expired["active_action"] == "restart"
    assert "expired" in expired["hold_reason"]
    assert row[3] is not None and row[4] == "expired_response" and row[2] is None


def test_unsafe_architect_body_is_rejected_before_claim_and_same_nonce_can_succeed(tmp_path):
    bridge, _ = service(tmp_path)
    waiting = waiting_architect(bridge)
    with pytest.raises(PolicyError, match="absolute user paths"):
        bridge.import_response(
            waiting["task_id"],
            reply(
                ARCHITECT_RESPONSE,
                waiting,
                {"outcome": "need_more_evidence", "requested_evidence": [evidence(r"C:\Users\Alice\secret.txt")]},
            ),
        )
    row = nonce_row(bridge, waiting["task_id"], waiting["pending_nonce"])
    assert bridge.get(waiting["task_id"])["status"] == WAITING_ARCHITECT
    assert row[0] is None and row[1] is None and row[2] is None and row[3] is None
    corrected = bridge.import_response(waiting["task_id"], reply(ARCHITECT_RESPONSE, waiting, {"outcome": "execute", "decision": decision()}))
    assert corrected["status"] == ROUTE_READY


def test_unsafe_review_body_is_rejected_before_claim_and_same_nonce_can_succeed(tmp_path):
    bridge, _ = service(tmp_path)
    ready = plan_ready(bridge)
    review = bridge.prepare_review(ready["task_id"], {"result": "local"}, {"tests": "not run"})
    waiting = bridge.copied(review["task_id"])
    with pytest.raises(PolicyError, match="may contain a secret"):
        bridge.import_response(
            waiting["task_id"],
            reply(REVIEW_RESPONSE, waiting, {"verdict": "HOLD", "notes": "sk_1234567890123456", "requested_evidence": []}),
        )
    row = nonce_row(bridge, waiting["task_id"], waiting["pending_nonce"])
    assert bridge.get(waiting["task_id"])["status"] == WAITING_REVIEW
    assert row[0] is None and row[1] is None and row[2] is None and row[3] is None
    resolved = bridge.import_response(waiting["task_id"], reply(REVIEW_RESPONSE, waiting, {"verdict": "HOLD", "notes": "bounded", "requested_evidence": []}))
    assert resolved["status"] == HOLD


def test_snapshot_get_and_recent_are_pure_reads_for_processing_state(tmp_path):
    bridge, _ = service(tmp_path)
    waiting = waiting_architect(bridge)
    response_hash = mark_processing(bridge, waiting)
    before = nonce_row(bridge, waiting["task_id"], waiting["pending_nonce"])

    direct = bridge.snapshot(bridge.store.load_bridge_task(waiting["task_id"]))
    fetched = bridge.get(waiting["task_id"])
    recent = bridge.recent()

    after = nonce_row(bridge, waiting["task_id"], waiting["pending_nonce"])
    assert direct["status"] == PROCESSING_RESPONSE
    assert fetched["status"] == PROCESSING_RESPONSE
    assert recent[0]["status"] == PROCESSING_RESPONSE
    assert before == after
    assert after[3] is None and after[5] == response_hash


def test_startup_recovery_holds_processing_task_once_and_marks_failed_nonce(tmp_path):
    bridge, _ = service(tmp_path)
    waiting = waiting_architect(bridge)
    mark_processing(bridge, waiting)

    first = bridge.recover_processing_on_startup()
    row_after_first = nonce_row(bridge, waiting["task_id"], waiting["pending_nonce"])
    second = bridge.recover_processing_on_startup()
    row_after_second = nonce_row(bridge, waiting["task_id"], waiting["pending_nonce"])

    assert first["status"] == HOLD and first["active_action"] == "restart"
    assert second["status"] == HOLD and second["active_action"] == "restart"
    assert "interrupted" in first["hold_reason"]
    assert row_after_first == row_after_second
    assert row_after_first[3] is not None and row_after_first[4] == "processing_interrupted" and row_after_first[2] is None


def test_concurrent_startup_recovery_returns_same_hold_snapshot(tmp_path):
    bridge, _ = service(tmp_path)
    waiting = waiting_architect(bridge)
    mark_processing(bridge, waiting)

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: bridge.recover_processing_on_startup(), range(4)))

    assert {result["task_id"] for result in results} == {waiting["task_id"]}
    assert all(result["status"] == HOLD and result["active_action"] == "restart" for result in results)
    row = nonce_row(bridge, waiting["task_id"], waiting["pending_nonce"])
    assert row[3] is not None and row[4] == "processing_interrupted"


def test_completed_nonce_is_not_recovered_again_on_startup(tmp_path):
    bridge, _ = service(tmp_path)
    waiting = waiting_architect(bridge)
    response_hash = mark_processing(bridge, waiting)
    processing = bridge.store.load_bridge_task(waiting["task_id"])
    bridge.store.update_bridge_task(
        waiting["task_id"],
        processing,
        complete_nonce=waiting["pending_nonce"],
        complete_nonce_response_hash=response_hash,
    )

    before = nonce_row(bridge, waiting["task_id"], waiting["pending_nonce"])
    result = bridge.recover_processing_on_startup()
    after = nonce_row(bridge, waiting["task_id"], waiting["pending_nonce"])

    assert result["status"] == PROCESSING_RESPONSE
    assert bridge.get(waiting["task_id"])["status"] == PROCESSING_RESPONSE
    assert before == after


def test_request_excludes_local_root_and_keeps_response_contract(tmp_path):
    bridge, _ = service(tmp_path)
    task = started(bridge)
    packet = bridge.packet(task["task_id"])
    assert str(Path.cwd()) not in packet
    assert "RESPONSE_CONTRACT" in packet and "REQUEST_SHA256" in packet
