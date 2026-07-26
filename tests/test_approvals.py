import asyncio
from pathlib import Path

import pytest

from app.gateway import Gate, Run
from app.policy import PolicyError
from app.protocol import ProtocolSchema
from app.storage import Store


class FakeClient:
    def __init__(self, workspace_write_available=True):
        self.responses = []
        self.requests = []
        self.fail_response = False
        self.workspace_write_available = workspace_write_available
        self.protocol = ProtocolSchema(
            root=Path("."),
            approval_methods=frozenset({
                "item/commandExecution/requestApproval",
                "item/fileChange/requestApproval",
                "item/permissions/requestApproval",
            }),
            decisions={"command": ("accept", "acceptForSession", "decline", "cancel"), "fileChange": ("accept", "acceptForSession", "decline", "cancel"), "permissions": ("accept", "acceptForSession", "decline", "cancel")},
            workspace_write_supported=workspace_write_available,
            on_request_supported=True,
        )

    async def connect(self):
        return [{"id": "model", "hidden": False, "defaultReasoningEffort": "high", "supportedReasoningEfforts": [{"reasoningEffort": "high"}]}]

    async def respond(self, request_id, result):
        if self.fail_response:
            raise RuntimeError("transport failed")
        self.responses.append((request_id, result))

    async def request(self, method, params):
        self.requests.append((method, params))
        return {}


def _run():
    return Run("run-1", "project", str(Path.cwd()), "task", "model", "high", "workspace-write", "tiny", {"tokens": 1, "tools": 1, "changed_files": 1}, {"allowed_files": []}, thread_id="thread-1", turn_id="turn-1", status="running")


def _gate(tmp_path, timeout=120):
    gate = Gate(Store(tmp_path), approval_timeout_seconds=timeout)
    gate.client = FakeClient()
    gate.runs["run-1"] = _run()
    return gate


async def _request(gate, request_id, method, params):
    await gate.handle_server_request({"id": request_id, "method": method, "params": {"threadId": "thread-1", "turnId": "turn-1", "itemId": "item-1", "startedAtMs": 1, **params}})


def test_command_accept_and_decline_are_forwarded(tmp_path):
    async def scenario():
        gate = _gate(tmp_path)
        await _request(gate, "a1", "item/commandExecution/requestApproval", {"command": "pytest", "cwd": "C:/work", "reason": "test"})
        assert gate.snapshot("run-1")["approvals"][0]["command"] == "pytest"
        await gate.resolve_approval("run-1", "a1", "accept")
        await _request(gate, "a2", "item/commandExecution/requestApproval", {"command": "rm", "cwd": "C:/work"})
        await gate.resolve_approval("run-1", "a2", "decline")
        assert gate.client.responses == [("a1", {"decision": "accept"}), ("a2", {"decision": "decline"})]
    asyncio.run(scenario())


def test_file_change_approval_and_duplicate_response_rejection(tmp_path):
    async def scenario():
        gate = _gate(tmp_path)
        await _request(gate, "f1", "item/fileChange/requestApproval", {"grantRoot": "C:/work/src", "reason": "edit"})
        approval = gate.snapshot("run-1")["approvals"][0]
        assert approval["paths"] == ["C:/work/src"]
        await gate.resolve_approval("run-1", "f1", "acceptForSession")
        with pytest.raises(PolicyError, match="이미 처리"):
            await gate.resolve_approval("run-1", "f1", "accept")
    asyncio.run(scenario())


def test_server_available_decisions_are_enforced_and_disconnect_cancels(tmp_path):
    async def scenario():
        gate = _gate(tmp_path)
        await _request(gate, "a3", "item/commandExecution/requestApproval", {"command": "dir", "availableDecisions": ["decline", "cancel"]})
        with pytest.raises(PolicyError, match="허용하지 않은"):
            await gate.resolve_approval("run-1", "a3", "accept")
        await gate.handle_disconnect("fake server closed")
        assert gate.runs["run-1"].approvals["a3"].status == "cancel"
        assert gate.snapshot("run-1")["approvals"] == []
    asyncio.run(scenario())


def test_permissions_grant_must_be_a_subset(tmp_path):
    async def scenario():
        gate = _gate(tmp_path)
        requested = {"fileSystem": {"write": ["C:/work"]}, "network": {"enabled": False}}
        await _request(gate, "p1", "item/permissions/requestApproval", {"cwd": "C:/work", "permissions": requested})
        with pytest.raises(PolicyError, match="벗어난"):
            await gate.resolve_approval("run-1", "p1", "accept", {"fileSystem": {"write": ["C:/other"]}})
        await gate.resolve_approval("run-1", "p1", "accept", {"fileSystem": {"write": []}})
        assert gate.client.responses[-1] == ("p1", {"permissions": {"fileSystem": {"write": []}}, "scope": "turn"})
    asyncio.run(scenario())


def test_approval_timeout_sends_cancel(tmp_path):
    async def scenario():
        gate = _gate(tmp_path, timeout=0.01)
        await _request(gate, "t1", "item/commandExecution/requestApproval", {"command": "dir", "cwd": "C:/work"})
        await asyncio.sleep(0.04)
        assert gate.client.responses == [("t1", {"decision": "cancel"})]
        assert gate.snapshot("run-1")["approvals"] == []
    asyncio.run(scenario())


def test_workspace_write_is_blocked_when_approval_protocol_is_unavailable(tmp_path):
    async def scenario():
        gate = _gate(tmp_path)
        gate.client = FakeClient(workspace_write_available=False)
        payload = {
            "project_id": "project", "root": str(tmp_path), "task": "small patch", "permission": "workspace-write",
            "budget_level": "tiny", "model": "model", "effort": "high",
            "decision": {"decision": "execute", "task_class": "patch", "recommended_model": "model", "recommended_effort": "high", "allowed_files": ["a.py"], "forbidden_files": [], "validation_commands": [], "stop_conditions": []},
        }
        with pytest.raises(PolicyError, match="Workspace Write"):
            await gate.start_run(payload)
    asyncio.run(scenario())


def test_unmatched_request_is_cancelled_and_response_failure_restores_pending(tmp_path):
    async def scenario():
        gate = _gate(tmp_path)
        await gate.handle_server_request({"id":"orphan", "method":"item/commandExecution/requestApproval", "params":{"threadId":"none", "turnId":"u", "itemId":"i", "startedAtMs":1}})
        assert gate.client.responses == [("orphan", {"decision":"cancel"})]
        await _request(gate, "retry", "item/commandExecution/requestApproval", {"command":"dir"})
        gate.client.fail_response = True
        with pytest.raises(RuntimeError, match="transport"):
            await gate.resolve_approval("run-1", "retry", "accept")
        assert gate.runs["run-1"].approvals["retry"].status == "pending"
    asyncio.run(scenario())


def test_concurrent_clicks_and_permissions_cancel_difference(tmp_path):
    async def scenario():
        gate = _gate(tmp_path)
        await _request(gate, "double", "item/commandExecution/requestApproval", {"command":"dir"})
        results = await asyncio.gather(gate.resolve_approval("run-1", "double", "accept"), gate.resolve_approval("run-1", "double", "accept"), return_exceptions=True)
        assert sum(not isinstance(result, Exception) for result in results) == 1
        requested = {"fileSystem": {"write": ["C:/work"]}}
        await _request(gate, "decline", "item/permissions/requestApproval", {"cwd":"C:/work", "permissions":requested})
        await gate.resolve_approval("run-1", "decline", "decline")
        assert gate.client.responses[-1] == ("decline", {"permissions": {}})
        await _request(gate, "cancel", "item/permissions/requestApproval", {"cwd":"C:/work", "permissions":requested})
        await gate.resolve_approval("run-1", "cancel", "cancel")
        assert gate.client.responses[-1] == ("cancel", {"permissions": {}})
        assert gate.client.requests[-1][0] == "turn/interrupt"
    asyncio.run(scenario())


def test_server_request_resolved_and_collab_spawn_are_cleaned_or_blocked(tmp_path):
    async def scenario():
        gate = _gate(tmp_path)
        await _request(gate, "resolved", "item/commandExecution/requestApproval", {"command":"dir"})
        await gate.handle_event({"method":"serverRequest/resolved", "params":{"threadId":"thread-1", "requestId":"resolved"}})
        assert gate.snapshot("run-1")["approvals"] == []
        await gate._handle_item(gate.runs["run-1"], {"type":"collabToolCall", "tool":"spawn_agent"}, False)
        assert gate.runs["run-1"].status == "interrupting"
    asyncio.run(scenario())
