import asyncio
import json
from pathlib import Path

from app.gateway import Gate, thread_is_ephemeral
from app.storage import Store


class LifecycleClient:
    def __init__(self):
        self.requests = []
        self.responses = []
        self.unsubscribe_error = None
        self.protocol = None

    async def connect(self):
        return [{
            "id": "model",
            "hidden": False,
            "defaultReasoningEffort": "high",
            "supportedReasoningEfforts": [{"reasoningEffort": "high"}],
        }]

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


def _payload(root: Path):
    return {
        "project_id": "project",
        "root": str(root),
        "task": "Inspect the workspace safely",
        "permission": "read-only",
        "budget_level": "tiny",
        "model": "model",
        "effort": "high",
        "decision": {
            "decision": "execute",
            "task_class": "inspect",
            "recommended_model": "model",
            "recommended_effort": "high",
            "allowed_files": [],
            "forbidden_files": [],
            "validation_commands": [],
            "stop_conditions": [],
        },
    }


def _gate(tmp_path):
    gate = Gate(Store(tmp_path))
    gate.client = LifecycleClient()
    return gate


def test_read_only_thread_start_is_ephemeral_and_workspace_write_policy_stays_durable(tmp_path):
    async def scenario():
        root = tmp_path / "project"
        root.mkdir()
        gate = _gate(tmp_path)
        run = await gate.start_run(_payload(root))
        assert run.status == "running"
        assert thread_is_ephemeral("read-only") is True
        assert thread_is_ephemeral("workspace-write") is False
        method, params = gate.client.requests[0]
        assert method == "thread/start"
        assert params["ephemeral"] is True
    asyncio.run(scenario())


def test_forbidden_root_reference_in_task_or_decision_is_rejected_before_thread_start(tmp_path):
    async def scenario():
        root = tmp_path / "project"
        root.mkdir()

        gate = _gate(tmp_path)
        payload = _payload(root)
        payload["task"] = r"Inspect E:\.codex safely"
        run = await gate.start_run(payload)
        assert run.status == "failed"
        assert r"E:\.codex" in (run.stop_reason or "")
        assert gate.client.requests == []

        gate = _gate(tmp_path)
        payload = _payload(root)
        payload["decision"]["allowed_files"] = [r"E:\.codex\secret.txt"]
        run = await gate.start_run(payload)
        assert run.status == "failed"
        assert r"E:\.codex" in (run.stop_reason or "")
        assert gate.client.requests == []

        result_path = tmp_path / "projects" / "project" / "tasks" / run.id / "result.json"
        stored = json.loads(result_path.read_text(encoding="utf-8"))
        assert r"E:\.codex" in stored["stop_reason"]
    asyncio.run(scenario())


def test_read_only_turn_completion_attempts_unsubscribe(tmp_path):
    async def scenario():
        root = tmp_path / "project"
        root.mkdir()
        gate = _gate(tmp_path)
        await gate.start_run(_payload(root))
        await gate.handle_event({"method": "turn/completed", "params": {"threadId": "thread-1", "turn": {"status": "completed"}}})
        assert any(method == "thread/unsubscribe" for method, _ in gate.client.requests)
    asyncio.run(scenario())


def test_unsubscribe_failure_only_records_warning(tmp_path):
    async def scenario():
        root = tmp_path / "project"
        root.mkdir()
        gate = _gate(tmp_path)
        gate.client.unsubscribe_error = "offline"
        run = await gate.start_run(_payload(root))
        await gate.handle_event({"method": "turn/completed", "params": {"threadId": "thread-1", "turn": {"status": "completed"}}})
        assert run.status == "completed"
        assert any("unsubscribe warning" in event.lower() for event in run.events)
    asyncio.run(scenario())


def test_forbidden_root_reference_in_command_request_is_rejected_and_interrupted(tmp_path):
    async def scenario():
        root = tmp_path / "project"
        root.mkdir()
        gate = _gate(tmp_path)
        run = await gate.start_run(_payload(root))
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
