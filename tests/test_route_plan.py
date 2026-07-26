from __future__ import annotations

import asyncio
import json
import sqlite3
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import app.main as app_main
from app.gateway import Gate
from app.policy import Decision, PolicyError
from app.storage import Store


MODELS = [{
    "id": "gpt-terra",
    "model": "gpt-terra",
    "displayName": "Terra",
    "hidden": False,
    "defaultReasoningEffort": "high",
    "supportedReasoningEfforts": [
        {"reasoningEffort": "medium"},
        {"reasoningEffort": "high"},
        {"reasoningEffort": "xhigh"},
        {"reasoningEffort": "max"},
        {"reasoningEffort": "ultra"},
    ],
}]


class RouteClient:
    def __init__(self):
        self.models = MODELS
        self.requests = []
        self.protocol = None
        self.returned_model = None
        self.connect_calls = 0
        self.fail_thread_start = None
        self.fail_turn_start = None

    async def connect(self):
        self.connect_calls += 1
        return self.models

    async def request(self, method, params):
        self.requests.append((method, params))
        if method == "thread/start":
            if self.fail_thread_start:
                raise RuntimeError(self.fail_thread_start)
            return {"thread": {"id": "thread-1"}}
        if method == "turn/start":
            if self.fail_turn_start:
                raise RuntimeError(self.fail_turn_start)
            return {"turn": {"id": "turn-1", "model": self.returned_model or params["model"]}}
        return {}

    async def close(self):
        return None


def decision(**updates):
    value = {
        "decision": "execute",
        "task_class": "T3",
        "recommended_model": "gpt-terra",
        "recommended_effort": "high",
        "allowed_files": [],
        "forbidden_files": [],
        "validation_commands": [],
        "stop_conditions": [],
        "risk": "medium",
        "parallel_audit": False,
        "independent_axes": 0,
    }
    value.update(updates)
    return value


def make_gate(tmp_path: Path):
    store = Store(tmp_path / "data")
    store.save_model_catalog(MODELS)
    gate = Gate(store)
    gate.client = RouteClient()
    return gate


def plan_payload(root: Path, **updates):
    value = {
        "project_name": "Demo",
        "project_id": "demo",
        "root": str(root),
        "task": "Inspect the requested scope",
        "decision": decision(),
        "permission": "read-only",
        "explicit_ultra_approval": False,
    }
    value.update(updates)
    return value


def run_payload(root: Path, plan):
    return {"route_plan_id": plan["plan_id"]}


def test_planned_file_count_uses_unique_exact_allowed_files_and_not_task_text(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "a.py").write_text("", encoding="utf-8")
    gate = make_gate(tmp_path)
    payload = plan_payload(root, task="Please test this text only")
    payload["decision"] = decision(allowed_files=["a.py", "./a.py"])

    plan = gate.create_route_plan(payload)

    assert plan["planned_file_count"] == 1
    assert plan["allowed_files"] == ["a.py"]
    assert plan["validation_evidence"]["validation_commands_present"] is False
    assert plan["validation_evidence"]["local_test_target_exists"] is False
    assert plan["validation_evidence"]["has_tests"] is False


@pytest.mark.parametrize("entry", ["*.py", "../escape.py"])
def test_unresolved_glob_and_root_escape_scopes_hold(tmp_path, entry):
    root = tmp_path / "project"
    root.mkdir()
    gate = make_gate(tmp_path)
    payload = plan_payload(root)
    payload["decision"] = decision(allowed_files=[entry])
    assert gate.create_route_plan(payload)["status"] == "HOLD"


def test_directory_and_absolute_allowed_file_scopes_hold(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "folder").mkdir()
    gate = make_gate(tmp_path)
    for entry in ("folder", str(root / "absolute.py")):
        payload = plan_payload(root)
        payload["decision"] = decision(allowed_files=[entry])
        assert gate.create_route_plan(payload)["status"] == "HOLD"


def test_canonical_decision_hash_changes_with_decision(tmp_path):
    first = Decision.from_json(decision()).sha256()
    second = Decision.from_json(decision(risk="high")).sha256()
    assert first != second
    assert Decision.from_json({**decision(), "allowed_files": []}).canonical_json().startswith('{"allowed_files"')


def test_route_plan_rejects_unknown_decision_fields(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    gate = make_gate(tmp_path)
    payload = plan_payload(root)
    payload["decision"]["untrusted_override"] = "critical"
    with pytest.raises(PolicyError, match="unknown fields"):
        gate.create_route_plan(payload)


def test_expired_and_tampered_route_plans_are_rejected(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    gate = make_gate(tmp_path)
    expired = gate.create_route_plan(plan_payload(root), ttl_seconds=1)
    time.sleep(1.05)
    with pytest.raises(PolicyError, match="expired"):
        asyncio.run(gate.start_run(run_payload(root, expired)))

    tampered = gate.create_route_plan(plan_payload(root))
    with gate.store._connection() as conn:
        raw = conn.execute("SELECT payload FROM route_plans WHERE plan_id = ?", (tampered["plan_id"],)).fetchone()[0]
        changed = json.loads(raw)
        changed["final"]["model"] = "forged"
        conn.execute(
            "UPDATE route_plans SET payload = ? WHERE plan_id = ?",
            (json.dumps(changed), tampered["plan_id"]),
        )
    with pytest.raises(PolicyError, match="modified|integrity"):
        gate.store.load_route_plan(tampered["plan_id"])


def test_route_plan_is_single_use_and_drives_thread_and_turn_models(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    gate = make_gate(tmp_path)
    plan = gate.create_route_plan(plan_payload(root))
    gate.client.returned_model = "server-rerouted-model"

    run = asyncio.run(gate.start_run(run_payload(root, plan)))

    thread_params = next(params for method, params in gate.client.requests if method == "thread/start")
    turn_params = next(params for method, params in gate.client.requests if method == "turn/start")
    assert (thread_params["model"], turn_params["model"], turn_params["effort"]) == (
        plan["final"]["model"], plan["final"]["model"], plan["final"]["effort"],
    )
    assert run.route_plan_id == plan["plan_id"]
    assert run.decision_hash == plan["decision_hash"]
    assert run.requested_model == plan["final"]["model"]
    assert run.actual_model == "server-rerouted-model"
    with pytest.raises(PolicyError, match="already been used"):
        asyncio.run(gate.start_run(run_payload(root, plan)))


def test_account_worsening_and_depleted_model_invalidate_plans(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    gate = make_gate(tmp_path)
    gate.store.save_rate_limits({"rateLimits": {"primary": {"usedPercent": 10}}})
    account_plan = gate.create_route_plan(plan_payload(root))
    gate.store.save_rate_limits({"rateLimits": {"secondary": {"usedPercent": 95}}})
    with pytest.raises(PolicyError, match="worsened"):
        asyncio.run(gate.start_run(run_payload(root, account_plan)))

    gate.store.save_rate_limits({"rateLimits": {"primary": {"usedPercent": 10}}})
    model_plan = gate.create_route_plan(plan_payload(root))
    gate.store.set_model_status("gpt-terra", "DEPLETED")
    with pytest.raises(PolicyError, match="DEPLETED"):
        asyncio.run(gate.start_run(run_payload(root, model_plan)))


def test_hold_ultra_and_workspace_write_plans_cannot_execute(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    gate = make_gate(tmp_path)

    hold_payload = plan_payload(root)
    hold_payload["decision"] = decision(allowed_files=["*.py"])
    hold = gate.create_route_plan(hold_payload)
    with pytest.raises(PolicyError, match="HOLD"):
        asyncio.run(gate.start_run(run_payload(root, hold)))

    ultra_payload = plan_payload(root, explicit_ultra_approval=True)
    ultra_payload["decision"] = decision(
        recommended_effort="ultra", parallel_audit=True, independent_axes=3,
    )
    ultra = gate.create_route_plan(ultra_payload)
    assert ultra["final"]["effort"] == "ultra"
    with pytest.raises(PolicyError, match="Ultra"):
        asyncio.run(gate.start_run(run_payload(root, ultra)))

    write_payload = plan_payload(root, permission="workspace-write")
    write_plan = gate.create_route_plan(write_payload)
    with pytest.raises(PolicyError, match="HOLD"):
        asyncio.run(gate.start_run(run_payload(root, write_plan)))


def test_route_plan_preview_calls_no_execution_rpc(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    gate = make_gate(tmp_path)
    plan = gate.create_route_plan(plan_payload(root))
    assert plan["status"] == "PREVIEW"
    assert gate.client.requests == []


def test_http_run_rejects_manual_model_effort_and_budget_overrides(tmp_path, monkeypatch):
    monkeypatch.setattr(app_main, "DATA_ROOT", tmp_path / "data")
    with TestClient(app_main.app, base_url="http://127.0.0.1:8787") as client:
        response = client.post("/api/run", json={
            "route_plan_id": "00000000-0000-4000-8000-000000000000",
            "budget_level": "tiny",
            "model": "gpt-terra",
            "effort": "high",
        })
    assert response.status_code == 422


def test_gate_rejects_missing_or_extra_execution_inputs_before_connecting(tmp_path):
    gate = make_gate(tmp_path)
    with pytest.raises(PolicyError, match="route_plan_id"):
        asyncio.run(gate.start_run({}))
    with pytest.raises(PolicyError, match="only route_plan_id"):
        asyncio.run(gate.start_run({"route_plan_id": "x", "budget_level": "critical"}))
    assert gate.client.connect_calls == 0


def test_route_plan_budgets_are_fixed_by_task_class_and_cannot_be_supplied(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    gate = make_gate(tmp_path)
    expected = {
        "T0": ("tiny", 250_000), "T1": ("tiny", 250_000),
        "T2": ("standard", 750_000), "T3": ("standard", 750_000),
        "T4": ("complex", 2_000_000), "T5": ("critical", 4_000_000),
    }
    for task_class, (level, tokens) in expected.items():
        payload = plan_payload(root)
        payload["decision"] = decision(task_class=task_class)
        plan = gate.create_route_plan(payload)
        assert (plan["budget_level"], plan["budget"]["tokens"]) == (level, tokens)
    with pytest.raises(PolicyError, match="unsupported fields"):
        gate.create_route_plan({**plan_payload(root), "budget_level": "critical"})


def test_only_one_concurrent_execution_claim_succeeds(tmp_path):
    async def scenario():
        root = tmp_path / "project"
        root.mkdir()
        gate = make_gate(tmp_path)
        plan = gate.create_route_plan(plan_payload(root))
        outcomes = await asyncio.gather(
            gate.start_run(run_payload(root, plan)),
            gate.start_run(run_payload(root, plan)),
            return_exceptions=True,
        )
        assert sum(not isinstance(item, Exception) for item in outcomes) == 1
        assert sum(isinstance(item, PolicyError) for item in outcomes) == 1
        assert gate.store.load_route_plan(plan["plan_id"])["use_status"] == "started"
    asyncio.run(scenario())


def test_start_failures_are_recorded_and_partial_threads_are_cleaned_up(tmp_path):
    async def scenario():
        root = tmp_path / "project"
        root.mkdir()
        gate = make_gate(tmp_path)
        thread_plan = gate.create_route_plan(plan_payload(root))
        gate.client.fail_thread_start = "thread unavailable"
        failed_thread = await gate.start_run(run_payload(root, thread_plan))
        assert failed_thread.status == "failed"
        stored = gate.store.load_route_plan(thread_plan["plan_id"])
        assert stored["use_status"] == "failed"
        assert "thread unavailable" in (stored["use_error"] or "")

        gate = make_gate(tmp_path)
        turn_plan = gate.create_route_plan(plan_payload(root))
        gate.client.fail_turn_start = "turn unavailable"
        failed_turn = await gate.start_run(run_payload(root, turn_plan))
        assert failed_turn.status == "failed"
        assert gate.store.load_route_plan(turn_plan["plan_id"])["use_status"] == "failed"
        assert any(method == "thread/unsubscribe" for method, _ in gate.client.requests)
        with pytest.raises(PolicyError, match="already been used"):
            await gate.start_run(run_payload(root, turn_plan))
    asyncio.run(scenario())


def test_reroute_compaction_and_single_token_warning_are_recorded(tmp_path):
    async def scenario():
        root = tmp_path / "project"
        root.mkdir()
        gate = make_gate(tmp_path)
        plan = gate.create_route_plan(plan_payload(root))
        run = await gate.start_run(run_payload(root, plan))
        await gate.handle_event({
            "method": "model/rerouted",
            "params": {"threadId": "thread-1", "actualModel": "gpt-terra-fallback", "reason": "capacity"},
        })
        assert (run.requested_model, run.actual_model, run.reroute_reason) == (
            plan["final"]["model"], "gpt-terra-fallback", "capacity",
        )
        await gate.handle_event({
            "method": "thread/tokenUsage/updated",
            "params": {"threadId": "thread-1", "tokenUsage": {"total": {"totalTokens": 600_000}}},
        })
        await gate.handle_event({
            "method": "thread/tokenUsage/updated",
            "params": {"threadId": "thread-1", "tokenUsage": {"total": {"totalTokens": 700_000}}},
        })
        assert run.events.count("경고: 토큰 예산 80%에 도달했습니다.") == 1
        await gate.handle_event({"method": "thread/compacted", "params": {"threadId": "thread-1"}})
        assert run.stop_reason == "thread compacted"
        assert any(method == "turn/interrupt" for method, _ in gate.client.requests)
    asyncio.run(scenario())


def test_existing_route_plan_use_table_is_migrated_without_releasing_a_used_plan(tmp_path):
    root = tmp_path / "data"
    root.mkdir()
    db_path = root / "app.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute("CREATE TABLE route_plan_uses (plan_id TEXT PRIMARY KEY, used_at TEXT NOT NULL, run_id TEXT NOT NULL)")
        conn.execute("INSERT INTO route_plan_uses VALUES ('old-plan', '2026-01-01T00:00:00+00:00', 'old-run')")
    Store(root)
    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            "SELECT status, claimed_at FROM route_plan_uses WHERE plan_id = 'old-plan'"
        ).fetchone()
    assert row == ("completed", "2026-01-01T00:00:00+00:00")
