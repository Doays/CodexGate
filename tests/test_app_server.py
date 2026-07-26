import asyncio
import json

import pytest

from app.app_server import AppServerClient, AppServerError
from app.protocol import ProtocolSchema


class FakeWriter:
    def __init__(self):
        self.messages = []
        self.closed = False

    def write(self, data):
        self.messages.append(json.loads(data.decode("utf-8")))

    async def drain(self):
        return None

    def close(self):
        self.closed = True

    async def wait_closed(self):
        return None


class FakeProcess:
    def __init__(self):
        self.stdin = FakeWriter()
        self.stdout = asyncio.StreamReader()
        self.stderr = asyncio.StreamReader()
        self.returncode = None

    def send(self, message):
        self.stdout.feed_data((json.dumps(message) + "\n").encode("utf-8"))

    def end(self):
        self.stdout.feed_eof()


async def _wait():
    await asyncio.sleep(0.01)


async def _wait_for_messages(process, count):
    for _ in range(50):
        if len(process.stdin.messages) >= count:
            return
        await asyncio.sleep(0.002)
    raise AssertionError(f"expected {count} RPC messages, got {len(process.stdin.messages)}")


def _client(events, requests, disconnects):
    client = AppServerClient(
        lambda message: _append(events, message),
        lambda message: _append(requests, message),
        lambda reason: _append(disconnects, reason),
        retry_base_seconds=0.001,
    )
    process = FakeProcess()
    client.process = process
    client.protocol = ProtocolSchema.load(__import__("pathlib").Path("schemas"))
    client.reader_task = asyncio.create_task(client._read_stdout())
    return client, process


async def _append(target, value):
    target.append(value)


def test_notification_and_server_request_are_distinguished():
    async def scenario():
        events, requests, disconnects = [], [], []
        client, process = _client(events, requests, disconnects)
        process.send({"method": "turn/started", "params": {"threadId": "t"}})
        process.send({"id": "approval-1", "method": "item/commandExecution/requestApproval", "params": {"threadId":"t", "turnId":"u", "itemId":"i", "startedAtMs":1}})
        await _wait()
        assert events[0]["method"] == "turn/started"
        assert requests[0]["id"] == "approval-1"
        client.reader_task.cancel()
        await asyncio.gather(client.reader_task, return_exceptions=True)
    asyncio.run(scenario())


def test_server_request_can_be_responded_to_bidirectionally():
    async def scenario():
        client, process = _client([], [], [])
        client.server_request_methods["approval-1"] = "item/commandExecution/requestApproval"
        await client.respond("approval-1", {"decision": "accept"})
        assert process.stdin.messages == [{"id": "approval-1", "result": {"decision": "accept"}}]
        client.reader_task.cancel()
        await asyncio.gather(client.reader_task, return_exceptions=True)
    asyncio.run(scenario())


def test_unsupported_server_request_receives_method_not_supported_error():
    async def scenario():
        client, process = _client([], [], [])
        process.send({"id": "unsupported-1", "method": "item/tool/requestUserInput", "params": {"threadId":"t", "turnId":"u", "itemId":"i", "questions":[]}})
        await _wait()
        assert process.stdin.messages[-1] == {"id": "unsupported-1", "error": {"code": -32601, "message": "Method not supported: item/tool/requestUserInput"}}
        client.reader_task.cancel()
        await asyncio.gather(client.reader_task, return_exceptions=True)
    asyncio.run(scenario())


def test_overloaded_response_is_retried_up_to_three_times():
    async def scenario():
        client, process = _client([], [], [])
        task = asyncio.create_task(client.request("model/list", {}))
        await _wait_for_messages(process, 1)
        for expected_count in (2, 3, 4):
            process.send({"id": process.stdin.messages[-1]["id"], "error": {"code": -32001, "message": "busy"}})
            await _wait_for_messages(process, expected_count)
        process.send({"id": process.stdin.messages[-1]["id"], "result": {"data": []}})
        assert await task == {"data": []}
        assert len(process.stdin.messages) == 4
        client.reader_task.cancel()
        await asyncio.gather(client.reader_task, return_exceptions=True)
    asyncio.run(scenario())


def test_server_shutdown_rejects_pending_futures_and_notifies():
    async def scenario():
        events, requests, disconnects = [], [], []
        client, process = _client(events, requests, disconnects)
        task = asyncio.create_task(client.request("model/list", {}))
        await _wait()
        process.end()
        with pytest.raises(AppServerError, match="종료"):
            await task
        await _wait()
        assert disconnects
        assert client.pending == {}
    asyncio.run(scenario())
