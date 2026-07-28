import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app.gateway import Gate, thread_is_ephemeral
from app.policy import PolicyError
from app.storage import Store


class LifecycleClient:
    def __init__(self):
        self.requests = []
        self.responses = []
        self.unsubscribe_error = None
        self.protocol = None

    async def connect(self):
        return [{
            "id": "gpt-terra",
            "hidden": False,
            "defaultReasoningEffort": "high",
            "supportedReasoningEfforts": [{"reasoningEffort": "high"}],
        }]

    async def installation_metadata(self, schema_dir):
        return {"codex_version": "test", "schema_sha256": "test-schema"}

    async def request(self, method, params):
        self.requests.append((method, params))
        if method == "thread/start":
            return {"thread": {"id": "thread-1"}}
        if method == "turn/start":
            return {"turn": {"id": "turn-1"}}
        if method == "thread/unsubscribe":
            if self.unsubscribe_error:
                raise RuntimeError(self.unsubscribe_error)
            return {"status": "unsubscribed"}
        return {}

    async def respond(self, request_id, result):
        self.responses.append((request_id, result))

    async def unsubscribe_thread(self, thread_id):
        return await self.request("thread/unsubscribe", {"threadId": thread_id})


def _plan_payload(root: Path):
    return {
        "project_id": "project",
        "root": str(root),
        "task": "Inspect the workspace safely",
        "permission": "read-only",
        "decision": {
            "decision": "execute",
            "task_class": "T3",
            "recommended_model": "gpt-terra",
            "recommended_effort": "high",
            "allowed_files": [],
            "forbidden_files": [],
            "validation_commands": [],
            "stop_conditions": [],
        },
    }


def _run_payload(gate: Gate, root: Path):
    return {"route_plan_id": gate.create_route_plan(_plan_payload(root))["plan_id"]}


def _gate(tmp_path):
    store = Store(tmp_path)
    store.save_model_catalog([{
        "id": "gpt-terra",
        "hidden": False,
        "defaultReasoningEffort": "high",
        "supportedReasoningEfforts": [{"reasoningEffort": "high"}],
    }])
    now = datetime.now(timezone.utc)
    store.save_isolation_result({
        "status": "SAFE_CAPSULE_ONLY", "checked_at": now.isoformat(),
        "expires_at": (now + timedelta(days=1)).isoformat(), "codex_version": "test",
        "schema_sha256": "test-schema", "inside_read_succeeded": True,
        "outside_read_succeeded": False, "outside_denied_explicitly": True, "reason": None,
    })
    gate = Gate(store)
    gate.client = LifecycleClient()
    return gate


def test_read_only_thread_start_is_ephemeral_and_workspace_write_policy_stays_durable(tmp_path):
    async def scenario():
        root = tmp_path / "project"
        root.mkdir()
        gate = _gate(tmp_path)
        run = await gate.start_run(_run_payload(gate, root))
        assert run.status == "running"
        assert thread_is_ephemeral("read-only") is True
        assert thread_is_ephemeral("workspace-write") is False
        method, params = gate.client.requests[0]
        assert method == "thread/start"
        assert params["ephemeral"] is True
    asyncio.run(scenario())


def test_forbidden_root_reference_in_task_or_decision_holds_before_thread_start(tmp_path):
    async def scenario():
        root = tmp_path / "project"
        root.mkdir()

        gate = _gate(tmp_path)
        payload = _plan_payload(root)
        payload["task"] = r"Inspect E:\.codex safely"
        plan = gate.create_route_plan(payload)
        assert plan["status"] == "HOLD"
        with pytest.raises(PolicyError, match="HOLD"):
            await gate.start_run({"route_plan_id": plan["plan_id"]})
        assert gate.client.requests == []

        gate = _gate(tmp_path)
        payload = _plan_payload(root)
        payload["decision"]["allowed_files"] = [r"E:\.codex\secret.txt"]
        plan = gate.create_route_plan(payload)
        assert plan["status"] == "HOLD"
        with pytest.raises(PolicyError, match="HOLD"):
            await gate.start_run({"route_plan_id": plan["plan_id"]})
        assert gate.client.requests == []
    asyncio.run(scenario())


def test_read_only_turn_completion_attempts_unsubscribe(tmp_path):
    async def scenario():
        root = tmp_path / "project"
        root.mkdir()
        gate = _gate(tmp_path)
        payload = _run_payload(gate, root)
        await gate.start_run(payload)
        await gate.handle_event({"method": "turn/completed", "params": {"threadId": "thread-1", "turn": {"status": "completed"}}})
        assert any(method == "thread/unsubscribe" for method, _ in gate.client.requests)
        assert gate.store.load_route_plan(payload["route_plan_id"])["use_status"] == "completed"
    asyncio.run(scenario())


def test_unsubscribe_failure_only_records_warning(tmp_path):
    async def scenario():
        root = tmp_path / "project"
        root.mkdir()
        gate = _gate(tmp_path)
        gate.client.unsubscribe_error = "offline"
        run = await gate.start_run(_run_payload(gate, root))
        await gate.handle_event({"method": "turn/completed", "params": {"threadId": "thread-1", "turn": {"status": "completed"}}})
        assert run.status == "completed"
        assert any("unsubscribe warning" in event.lower() for event in run.events)
    asyncio.run(scenario())


def test_forbidden_root_reference_in_command_request_is_rejected_and_interrupted(tmp_path):
    async def scenario():
        root = tmp_path / "project"
        root.mkdir()
        gate = _gate(tmp_path)
        run = await gate.start_run(_run_payload(gate, root))
        await gate.handle_server_request({
            "id": "approval-1",
            "method": "item/commandExecution/requestApproval",
            "params": {
                "threadId": "thread-1",
                "turnId": "turn-1",
                "itemId": "item-1",
                "startedAtMs": 1,
                "command": r"type E:\.codex\secret.txt",
                "cwd": str(root),
            },
        })
        assert gate.client.responses[-1] == ("approval-1", {"decision": "cancel"})
        assert any(method == "turn/interrupt" for method, _ in gate.client.requests)
        assert r"E:\.codex" in (run.stop_reason or "")
    asyncio.run(scenario())
