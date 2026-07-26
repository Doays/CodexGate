from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from .protocol import APPROVAL_METHODS, ProtocolSchema, ProtocolValidationError


class AppServerError(RuntimeError):
    def __init__(self, message: str, code: int | None = None):
        super().__init__(message)
        self.code = code


MessageHandler = Callable[[dict[str, Any]], Awaitable[None]]
DisconnectHandler = Callable[[str], Awaitable[None]]


class AppServerClient:
    """Version-aware JSONL RPC client for ``codex app-server --stdio``."""

    def __init__(
        self,
        event_handler: MessageHandler,
        server_request_handler: MessageHandler | None = None,
        disconnect_handler: DisconnectHandler | None = None,
        *,
        schema_dir: Path | None = None,
        retry_base_seconds: float = 0.25,
    ):
        self.event_handler = event_handler
        self.server_request_handler = server_request_handler
        self.disconnect_handler = disconnect_handler
        self.schema_dir = schema_dir or (Path.cwd() / "schemas")
        self.retry_base_seconds = retry_base_seconds
        self.process: asyncio.subprocess.Process | None = None
        self.pending: dict[int | str, asyncio.Future[Any]] = {}
        self.request_id = 0
        self.reader_task: asyncio.Task[None] | None = None
        self.stderr_task: asyncio.Task[None] | None = None
        self.stderr_lines: list[str] = []
        self.write_lock = asyncio.Lock()
        self.models: list[dict[str, Any]] = []
        self.command: str | None = None
        self.version: str | None = None
        self.protocol: ProtocolSchema | None = None
        self.schema_error: str | None = None
        self.server_request_methods: dict[int | str, str] = {}
        self.server_request_tasks: set[asyncio.Task[None]] = set()
        self.server_request_errors: list[str] = []

    @property
    def connected(self) -> bool:
        return self.process is not None and self.process.returncode is None

    @property
    def workspace_write_available(self) -> bool:
        return False

    @property
    def workspace_write_schema_ready(self) -> bool:
        return bool(
            self.protocol
            and self.protocol.workspace_write_supported
            and self.protocol.approvals_supported
            and self.protocol.on_request_supported
            and self.protocol.approvals_reviewer_user_supported
        )

    async def connect(self) -> list[dict[str, Any]]:
        if self.connected:
            return self.models
        self.command = self._find_command()
        self.version = await asyncio.to_thread(self._read_version, self.command)
        await self._generate_schema()
        try:
            self.process = await asyncio.create_subprocess_exec(
                self.command,
                "app-server",
                "--stdio",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except OSError as exc:
            raise AppServerError(f"Codex app-server를 시작하지 못했습니다: {exc}") from exc
        self.reader_task = asyncio.create_task(self._read_stdout())
        self.stderr_task = asyncio.create_task(self._read_stderr())
        await self.request("initialize", {
            "clientInfo": {"name": "codex_gate", "title": "Codex Gate", "version": "0.2.0"},
        })
        await self.notify("initialized", {})
        self.models = await self.list_models()
        return self.models

    def _find_command(self) -> str:
        command = shutil.which("codex.cmd") if os.name == "nt" else shutil.which("codex")
        command = command or shutil.which("codex")
        if not command:
            raise AppServerError("`codex` 명령을 찾을 수 없습니다. Codex CLI 설치와 PATH를 확인하세요.")
        return command

    @staticmethod
    def _read_version(command: str) -> str:
        result = subprocess.run([command, "--version"], capture_output=True, text=True, timeout=10, check=False)
        if result.returncode:
            raise AppServerError("Codex 버전을 조회하지 못했습니다.")
        return result.stdout.strip() or result.stderr.strip()

    async def _generate_schema(self) -> None:
        assert self.command
        self.schema_error = None
        try:
            result = await asyncio.to_thread(
                subprocess.run,
                [self.command, "app-server", "generate-json-schema", "--out", str(self.schema_dir)],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if result.returncode:
                raise AppServerError(result.stderr.strip() or "Schema 생성 명령이 실패했습니다.")
            self.protocol = ProtocolSchema.load(self.schema_dir)
        except (OSError, ValueError, json.JSONDecodeError, AppServerError) as exc:
            self.protocol = None
            self.schema_error = str(exc)

    async def close(self) -> None:
        if not self.process:
            return
        process = self.process
        if process.stdin:
            process.stdin.close()
            try:
                await process.stdin.wait_closed()
            except (AttributeError, ConnectionError):
                pass
        if process.returncode is None:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=3)
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
        tasks = [task for task in (self.reader_task, self.stderr_task) if task]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self.process = None
        self.reader_task = None
        self.stderr_task = None

    async def list_models(self) -> list[dict[str, Any]]:
        collected: list[dict[str, Any]] = []
        cursor: str | None = None
        while True:
            response = await self.request("model/list", {"cursor": cursor} if cursor else {})
            collected.extend(response.get("data", []))
            cursor = response.get("nextCursor")
            if not cursor:
                return collected

    async def request(self, method: str, params: dict[str, Any]) -> Any:
        self._validate_outgoing_request(method, params)
        for retry in range(4):
            try:
                return await self._request_once(method, params)
            except AppServerError as exc:
                if exc.code != -32001 or retry == 3:
                    raise
                await asyncio.sleep(self.retry_base_seconds * (2 ** retry))
        raise AssertionError("unreachable")

    async def _request_once(self, method: str, params: dict[str, Any]) -> Any:
        if not self.connected or not self.process or not self.process.stdin:
            raise AppServerError("Codex app-server가 연결되어 있지 않습니다.")
        self.request_id += 1
        request_id = self.request_id
        future: asyncio.Future[Any] = asyncio.get_running_loop().create_future()
        self.pending[request_id] = future
        await self._send({"id": request_id, "method": method, "params": params})
        try:
            return await asyncio.wait_for(future, timeout=30)
        except asyncio.TimeoutError as exc:
            self.pending.pop(request_id, None)
            raise AppServerError(f"{method} 응답 시간이 초과되었습니다.") from exc

    async def notify(self, method: str, params: dict[str, Any]) -> None:
        await self._send({"method": method, "params": params})

    async def respond(self, request_id: int | str, result: dict[str, Any]) -> None:
        method = self.server_request_methods.get(request_id)
        if not method:
            raise AppServerError("이미 응답했거나 서버 요청으로 추적되지 않은 request입니다.")
        self._validate_approval_response(method, result)
        await self._send({"id": request_id, "result": result})
        self.server_request_methods.pop(request_id, None)

    async def respond_error(self, request_id: int | str, code: int, message: str) -> None:
        await self._send({"id": request_id, "error": {"code": code, "message": message}})
        self.server_request_methods.pop(request_id, None)

    async def unsubscribe_thread(self, thread_id: str) -> Any:
        return await self.request("thread/unsubscribe", {"threadId": thread_id})

    def _validate_outgoing_request(self, method: str, params: dict[str, Any]) -> None:
        if method not in {"thread/start", "turn/start"}:
            return
        if not self.protocol:
            raise AppServerError("생성된 schema가 없어 thread/turn 시작 payload를 검증할 수 없습니다.")
        schema_name = "thread_start" if method == "thread/start" else "turn_start"
        try:
            self.protocol.validate(schema_name, params)
        except ProtocolValidationError as exc:
            raise AppServerError(str(exc)) from exc

    def _validate_approval_response(self, method: str, result: dict[str, Any]) -> None:
        if not self.protocol:
            raise AppServerError("생성된 schema가 없어 승인 응답을 검증할 수 없습니다.")
        kind = APPROVAL_METHODS.get(method)
        if not kind:
            raise AppServerError("미지원 server request에는 승인 응답을 보낼 수 없습니다.")
        try:
            self.protocol.validate(f"{kind}_response", result)
        except ProtocolValidationError as exc:
            raise AppServerError(str(exc)) from exc

    async def _send(self, payload: dict[str, Any]) -> None:
        if not self.process or not self.process.stdin:
            raise AppServerError("Codex app-server가 연결되어 있지 않습니다.")
        raw = (json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8")
        async with self.write_lock:
            self.process.stdin.write(raw)
            await self.process.stdin.drain()

    async def _read_stdout(self) -> None:
        assert self.process and self.process.stdout
        reason = "Codex app-server 연결이 종료되었습니다."
        try:
            while line := await self.process.stdout.readline():
                try:
                    message = json.loads(line)
                except json.JSONDecodeError:
                    self.stderr_lines.append("app-server가 JSON이 아닌 stdout 메시지를 보냈습니다.")
                    continue
                if "id" in message and "method" in message:
                    self.server_request_methods[message["id"]] = message["method"]
                    self._track_server_request(message)
                elif "id" in message:
                    future = self.pending.pop(message["id"], None)
                    if future and not future.done():
                        if "error" in message:
                            error = message["error"]
                            future.set_exception(AppServerError(error.get("message", "app-server 오류"), error.get("code")))
                        else:
                            future.set_result(message.get("result", {}))
                elif "method" in message:
                    asyncio.create_task(self.event_handler(message))
        finally:
            error = AppServerError(reason)
            for future in self.pending.values():
                if not future.done():
                    future.set_exception(error)
            self.pending.clear()
            self.server_request_methods.clear()
            if self.disconnect_handler:
                await self.disconnect_handler(reason)

    def _track_server_request(self, message: dict[str, Any]) -> None:
        task = asyncio.create_task(self._dispatch_server_request(message))
        self.server_request_tasks.add(task)
        task.add_done_callback(self._finish_server_request_task)

    def _finish_server_request_task(self, task: asyncio.Task[None]) -> None:
        self.server_request_tasks.discard(task)
        if task.cancelled():
            return
        error = task.exception()
        if error:
            self.server_request_errors.append(str(error))
            del self.server_request_errors[:-30]

    async def _dispatch_server_request(self, message: dict[str, Any]) -> None:
        request_id = message["id"]
        method = message["method"]
        try:
            if not self.protocol:
                await self.respond_error(request_id, -32602, "Generated schema is unavailable.")
                return
            self.protocol.validate("server_request", message)
            if method not in APPROVAL_METHODS:
                await self.respond_error(request_id, -32601, f"Method not supported: {method}")
                return
            if not self.server_request_handler:
                await self.respond_error(request_id, -32601, "Approval handler is unavailable.")
                return
            await self.server_request_handler(message)
        except ProtocolValidationError as exc:
            await self.respond_error(request_id, -32602, str(exc))
        except Exception as exc:
            await self.respond_error(request_id, -32603, f"Approval handling failed: {exc}")
            raise

    async def _read_stderr(self) -> None:
        assert self.process and self.process.stderr
        while line := await self.process.stderr.readline():
            self.stderr_lines.append(line.decode("utf-8", errors="replace").strip())
            del self.stderr_lines[:-30]
