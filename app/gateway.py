from __future__ import annotations

import asyncio
import json
import subprocess
import uuid
from dataclasses import dataclass, field
from typing import Any

from .app_server import AppServerClient
from .policy import (
    Decision,
    PolicyError,
    budget_for,
    collect_git_paths,
    find_forbidden_root_reference,
    validate_decision_for_run,
    validate_project_file,
    validate_selection,
    validate_workspace,
)
from .protocol import APPROVAL_METHODS, is_permission_subset
from .storage import Store


def thread_is_ephemeral(permission: str) -> bool:
    return permission == "read-only"


@dataclass
class Run:
    id: str
    project_id: str
    root: str
    task: str
    model: str
    effort: str
    permission: str
    budget_level: str
    budget: dict[str, int]
    decision: dict[str, Any]
    status: str = "starting"
    thread_id: str | None = None
    turn_id: str | None = None
    tokens: int = 0
    tool_calls: int = 0
    changed_files: set[str] = field(default_factory=set)
    failed_commands: int = 0
    failed_tests: int = 0
    stop_reason: str | None = None
    events: list[str] = field(default_factory=list)
    approvals: dict[str, "Approval"] = field(default_factory=dict)
    initial_git_paths: set[str] = field(default_factory=set)
    subscribers: set[asyncio.Queue[dict[str, Any]]] = field(default_factory=set)

    def snapshot(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "project_id": self.project_id,
            "root": self.root,
            "task": self.task,
            "model": self.model,
            "effort": self.effort,
            "permission": self.permission,
            "budget_level": self.budget_level,
            "budget": self.budget,
            "decision": self.decision,
            "status": self.status,
            "thread_id": self.thread_id,
            "turn_id": self.turn_id,
            "tokens": self.tokens,
            "tool_calls": self.tool_calls,
            "changed_files": sorted(self.changed_files),
            "failed_commands": self.failed_commands,
            "failed_tests": self.failed_tests,
            "stop_reason": self.stop_reason,
            "events": self.events,
            "approvals": [approval.snapshot() for approval in self.approvals.values() if approval.status == "pending"],
        }


@dataclass
class Approval:
    request_id: int | str
    method: str
    kind: str
    thread_id: str
    turn_id: str
    item_id: str | None
    command: str | None
    cwd: str | None
    paths: list[str]
    reason: str | None
    permissions: dict[str, Any] | None
    available_decisions: tuple[str, ...]
    status: str = "pending"
    timeout_task: asyncio.Task[None] | None = None
    lock: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False)

    @property
    def key(self) -> str:
        return str(self.request_id)

    def snapshot(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "method": self.method,
            "kind": self.kind,
            "thread_id": self.thread_id,
            "turn_id": self.turn_id,
            "item_id": self.item_id,
            "command": self.command,
            "cwd": self.cwd,
            "paths": self.paths,
            "reason": self.reason,
            "permissions": self.permissions,
            "available_decisions": list(self.available_decisions),
            "status": self.status,
        }


class Gate:
    def __init__(self, store: Store, *, approval_timeout_seconds: float = 120):
        self.store = store
        self.runs: dict[str, Run] = {}
        self.approval_timeout_seconds = approval_timeout_seconds
        self.client = AppServerClient(self.handle_event, self.handle_server_request, self.handle_disconnect)

    async def connect(self) -> list[dict[str, Any]]:
        return await self.client.connect()

    def status(self) -> dict[str, Any]:
        return {
            "connected": getattr(self.client, "connected", False),
            "models": getattr(self.client, "models", []),
            "stderr": getattr(self.client, "stderr_lines", [])[-5:],
            "codex_path": getattr(self.client, "command", None),
            "codex_version": getattr(self.client, "version", None),
            "schema_path": str(self.client.schema_dir) if getattr(self.client, "protocol", None) else None,
            "schema_error": getattr(self.client, "schema_error", None),
            "workspace_write_available": False,
            "workspace_write_schema_ready": getattr(self.client, "workspace_write_schema_ready", False),
        }

    async def start_run(self, payload: dict[str, Any]) -> Run:
        models = await self.connect()
        if payload["permission"] == "workspace-write":
            raise PolicyError("Workspace Write는 실제 쓰기 검증 전까지 잠금 상태입니다.")

        decision = Decision.from_json(payload["decision"])
        root = validate_workspace(payload["root"], payload["permission"], payload["task"])
        validate_decision_for_run(decision, payload["permission"])
        validate_selection(models, payload["model"], payload["effort"])
        budget = budget_for(payload["budget_level"])

        run = Run(
            id=str(uuid.uuid4()),
            project_id=payload["project_id"],
            root=str(root),
            task=payload["task"].strip(),
            model=payload["model"],
            effort=payload["effort"],
            permission=payload["permission"],
            budget_level=payload["budget_level"],
            budget=budget,
            decision=decision.as_dict(),
        )
        self.runs[run.id] = run
        self._store_request_artifacts(run)

        blocked_reason = self._forbidden_reference_reason({"task": run.task, "decision": run.decision})
        if blocked_reason:
            return await self._reject_run_before_start(run, blocked_reason)

        run.initial_git_paths = self._git_paths(run.root)
        self._persist(run)

        thread = await self.client.request("thread/start", self._thread_start_params(run))
        run.thread_id = thread["thread"]["id"]

        turn = await self.client.request("turn/start", {
            "threadId": run.thread_id,
            "model": run.model,
            "effort": run.effort,
            "cwd": run.root,
            "approvalPolicy": "on-request",
            "approvalsReviewer": "user",
            "sandboxPolicy": self._sandbox_policy(run),
            "input": [{"type": "text", "text": self._prompt(run)}],
        })
        run.turn_id = turn["turn"]["id"]
        run.status = "running"
        await self._publish(run, "Codex 작업을 시작했습니다.")
        self._persist(run)
        return run

    def _thread_start_params(self, run: Run) -> dict[str, Any]:
        sandbox = "read-only" if run.permission == "read-only" else "workspace-write"
        return {
            "cwd": run.root,
            "sandbox": sandbox,
            "approvalPolicy": "on-request",
            "model": run.model,
            "threadSource": "codex_gate",
            "ephemeral": thread_is_ephemeral(run.permission),
            "approvalsReviewer": "user",
        }

    def _sandbox_policy(self, run: Run) -> dict[str, Any]:
        if run.permission == "read-only":
            return {"type": "readOnly", "networkAccess": False}
        return {"type": "workspaceWrite", "networkAccess": False, "writableRoots": [run.root]}

    def _prompt(self, run: Run) -> str:
        decision = run.decision
        return "\n".join([
            "# Codex Gate execution contract",
            "You are running inside a guarded local release. Stay inside the approved scope and stop when a stop condition triggers.",
            f"Task: {run.task}",
            f"Permission: {run.permission}",
            f"Allowed files: {json.dumps(decision['allowed_files'], ensure_ascii=False)}",
            f"Forbidden files: {json.dumps(decision['forbidden_files'], ensure_ascii=False)}",
            f"Validation commands: {json.dumps(decision['validation_commands'], ensure_ascii=False)}",
            f"Stop conditions: {json.dumps(decision['stop_conditions'], ensure_ascii=False)}",
            "Do not create subagents. Ultra remains locked. If a file is outside the allowed list, stop and report instead of writing.",
        ])

    async def interrupt(self, run_id: str, reason: str = "사용자 중단") -> None:
        run = self._run(run_id)
        if run.status not in {"running", "starting", "interrupting"} or not run.thread_id or not run.turn_id:
            return
        run.status = "interrupting"
        run.stop_reason = reason
        await self.client.request("turn/interrupt", {"threadId": run.thread_id, "turnId": run.turn_id})
        await self._publish(run, f"중단 요청: {reason}")

    async def handle_event(self, message: dict[str, Any]) -> None:
        params = message.get("params", {})
        run = self._run_for_thread(params.get("threadId"))
        if not run:
            return

        method = message["method"]
        if method == "serverRequest/resolved":
            self._resolve_server_request(run, params)
            await self._publish(run, "server request resolved")
            self._persist(run)
            return

        if method == "thread/tokenUsage/updated":
            run.tokens = int(params.get("tokenUsage", {}).get("total", {}).get("totalTokens", 0))
            await self._enforce(run)
        elif method in {"item/started", "item/completed"}:
            await self._handle_item(run, params.get("item", {}), count_tool=method == "item/started")
        elif method == "item/fileChange/patchUpdated":
            await self._handle_changes(run, params.get("changes", []))
        elif method == "turn/completed":
            turn = params.get("turn", {})
            self._clear_pending_approvals(run)
            run.status = turn.get("status", "completed")
            if turn.get("error"):
                run.stop_reason = turn["error"].get("message", "Codex 실행 오류")
            await self._recheck_git_paths(run)
            await self._capture_diff(run)
            await self._unsubscribe_read_only_thread(run)
            await self._publish(run, f"턴 종료: {run.status}")
            self.store.write_artifact(run.project_id, run.id, "result.json", run.snapshot())
        else:
            await self._publish(run, method)

        self._persist(run)

    async def handle_server_request(self, message: dict[str, Any]) -> None:
        method = message.get("method")
        if method not in APPROVAL_METHODS:
            return

        params = message.get("params", {})
        run = self._run_for_thread(params.get("threadId"))
        if not run:
            await self._respond_unmatched_request(message)
            return

        key = str(message["id"])
        if key in run.approvals:
            return

        kind = APPROVAL_METHODS[method]
        paths = self._approval_paths(params)
        blocked_reason = self._forbidden_reference_reason({
            "command": params.get("command"),
            "cwd": params.get("cwd"),
            "paths": paths,
            "permissions": params.get("permissions"),
            "changes": params.get("changes"),
            "commandActions": params.get("commandActions"),
        })
        if blocked_reason:
            await self._reject_forbidden_request(run, message, kind, blocked_reason)
            return

        available = params.get("availableDecisions")
        if not isinstance(available, list) or not all(isinstance(item, str) for item in available):
            protocol = getattr(self.client, "protocol", None)
            available = list(protocol.decisions_for(kind) if protocol else ())

        approval = Approval(
            request_id=message["id"],
            method=method,
            kind=kind,
            thread_id=str(params.get("threadId", "")),
            turn_id=str(params.get("turnId", "")),
            item_id=params.get("itemId"),
            command=params.get("command"),
            cwd=params.get("cwd"),
            paths=paths,
            reason=params.get("reason"),
            permissions=params.get("permissions"),
            available_decisions=tuple(available),
        )
        run.approvals[key] = approval
        approval.timeout_task = asyncio.create_task(self._expire_approval(run.id, approval.key))
        await self._publish(run, f"승인 대기: {kind}")
        self._persist(run)

    async def resolve_approval(
        self,
        run_id: str,
        request_id: int | str,
        decision: str,
        granted_permissions: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        run = self._run(run_id)
        approval = run.approvals.get(str(request_id))
        if not approval:
            raise PolicyError("이미 처리되었거나 존재하지 않는 승인 요청입니다.")

        async with approval.lock:
            if approval.status != "pending":
                raise PolicyError("이미 처리되었거나 존재하지 않는 승인 요청입니다.")
            if decision not in {"accept", "acceptForSession", "decline", "cancel"}:
                raise PolicyError("지원하지 않는 승인 응답입니다.")
            if decision not in approval.available_decisions:
                raise PolicyError("app-server가 허용하지 않은 승인 응답입니다.")

            result = self._approval_result(approval, decision, granted_permissions)
            approval.status = "responding"
            await self._publish(run, f"승인 응답 전송 중: {approval.kind} / {decision}")
            try:
                await self.client.respond(approval.request_id, result)
            except Exception:
                approval.status = "pending"
                await self._publish(run, "승인 응답 전송 실패: 다시 시도하거나 작업을 중단하세요.")
                self._persist(run)
                raise

            approval.status = "resolved"
            if approval.timeout_task and approval.timeout_task is not asyncio.current_task():
                approval.timeout_task.cancel()
            if approval.kind == "permissions" and decision == "cancel":
                await self.interrupt(run.id, "permissions 승인 취소")
            await self._publish(run, f"승인 응답 완료: {approval.kind} / {decision}")
            self._persist(run)
            return approval.snapshot()

    def _approval_result(self, approval: Approval, decision: str, granted: dict[str, Any] | None) -> dict[str, Any]:
        if approval.kind != "permissions":
            return {"decision": decision}
        if decision in {"decline", "cancel"}:
            return {"permissions": {}}

        permissions = approval.permissions if granted is None else granted
        if not isinstance(permissions, dict) or not is_permission_subset(permissions, approval.permissions or {}):
            raise PolicyError("요청된 권한 범위를 벗어난 권한은 승인할 수 없습니다.")
        return {"permissions": permissions, "scope": "session" if decision == "acceptForSession" else "turn"}

    async def _expire_approval(self, run_id: str, approval_key: str) -> None:
        try:
            await asyncio.sleep(self.approval_timeout_seconds)
            run = self._run(run_id)
            approval = run.approvals.get(approval_key)
            if approval and approval.status == "pending":
                await self.resolve_approval(run_id, approval.request_id, "cancel")
        except asyncio.CancelledError:
            return

    async def handle_disconnect(self, reason: str) -> None:
        for run in self.runs.values():
            pending = [approval for approval in run.approvals.values() if approval.status in {"pending", "responding"}]
            if not pending:
                continue
            for approval in pending:
                approval.status = "cancel"
                if approval.timeout_task:
                    approval.timeout_task.cancel()
            await self._publish(run, f"app-server 연결 종료: {reason}")
            self._persist(run)

    @staticmethod
    def _clear_pending_approvals(run: Run) -> None:
        for approval in run.approvals.values():
            if approval.status in {"pending", "responding"}:
                approval.status = "resolved"
                if approval.timeout_task:
                    approval.timeout_task.cancel()

    async def _handle_item(self, run: Run, item: dict[str, Any], count_tool: bool) -> None:
        item_type = item.get("type", "")
        blocked_reason = self._forbidden_reference_reason({
            "command": item.get("command"),
            "cwd": item.get("cwd"),
            "path": item.get("path"),
            "changes": item.get("changes"),
        })
        if blocked_reason:
            await self.interrupt(run.id, blocked_reason)
            return

        if item_type == "contextCompaction":
            await self.interrupt(run.id, "context compaction 감지")
            return
        if count_tool and item_type not in {"agentMessage", "userMessage", "reasoning", "error"}:
            run.tool_calls += 1
        if item_type in {"fileChange", "fileUpdate"}:
            await self._handle_changes(run, item.get("changes", []))
            if run.status == "interrupting":
                return
        if item_type in {"collabToolCall", "collabAgentToolCall"} and str(item.get("tool", "")).replace("_", "").lower() == "spawnagent":
            await self.interrupt(run.id, "spawn_agent 감지")
            return
        if item_type == "commandExecution" and item.get("status") == "failed":
            run.failed_commands += 1
            command = str(item.get("command", "")).lower()
            if "test" in command or "pytest" in command:
                run.failed_tests += 1
        await self._enforce(run)

    async def _handle_changes(self, run: Run, changes: list[dict[str, Any]]) -> None:
        blocked_reason = self._forbidden_reference_reason(changes)
        if blocked_reason:
            await self.interrupt(run.id, blocked_reason)
            return

        for change in changes:
            path = change.get("path")
            if not path:
                continue
            run.changed_files.add(str(path).replace("\\", "/"))
            if not self._is_allowed(run, str(path)):
                await self.interrupt(run.id, f"허용되지 않은 파일 변경 감지: {path}")
                return
        await self._enforce(run)

    def _is_allowed(self, run: Run, path: str) -> bool:
        try:
            validate_project_file(run.root, path, run.decision["allowed_files"], run.decision["forbidden_files"])
            return True
        except PolicyError:
            return False

    async def _enforce(self, run: Run) -> None:
        if run.tokens >= run.budget["tokens"]:
            await self.interrupt(run.id, "토큰 예산 100% 도달")
        elif run.tool_calls >= run.budget["tools"]:
            await self.interrupt(run.id, "도구 호출 한도 도달")
        elif len(run.changed_files) > run.budget["changed_files"]:
            await self.interrupt(run.id, "변경 파일 한도 초과")
        elif run.failed_commands >= 3:
            await self.interrupt(run.id, "명령 실패 한도 도달")
        elif run.failed_tests >= 2:
            await self.interrupt(run.id, "테스트 연속 실패 한도 도달")
        elif run.tokens >= int(run.budget["tokens"] * 0.8):
            await self._publish(run, "경고: 토큰 예산 80%에 도달했습니다.")

    async def _capture_diff(self, run: Run) -> None:
        try:
            completed = await asyncio.to_thread(
                subprocess.run,
                ["git", "diff", "--no-ext-diff"],
                cwd=run.root,
                capture_output=True,
                text=True,
                timeout=12,
                check=False,
            )
            diff = completed.stdout[:2_000_000]
        except (OSError, subprocess.TimeoutExpired):
            diff = "diff를 가져올 수 없습니다."
        self.store.write_artifact(run.project_id, run.id, "diff.patch", diff)

    def _git_paths(self, root: str) -> set[str]:
        return collect_git_paths(root)

    async def _recheck_git_paths(self, run: Run) -> None:
        for path in self._git_paths(run.root) - run.initial_git_paths:
            blocked_reason = self._forbidden_reference_reason(path)
            if blocked_reason:
                run.stop_reason = blocked_reason
                run.status = "failed"
                await self._publish(run, blocked_reason)
                return
            if not self._is_allowed(run, path):
                run.stop_reason = f"종료 후 Git 상태에서 범위 밖 변경 감지: {path}"
                run.status = "failed"
                return

    async def _unsubscribe_read_only_thread(self, run: Run) -> None:
        if run.permission != "read-only" or not run.thread_id:
            return
        try:
            unsubscribe = getattr(self.client, "unsubscribe_thread", None)
            if callable(unsubscribe):
                await unsubscribe(run.thread_id)
            else:
                await self.client.request("thread/unsubscribe", {"threadId": run.thread_id})
        except Exception as exc:
            await self._publish(run, f"Read Only unsubscribe warning: {exc}")

    async def _respond_unmatched_request(self, message: dict[str, Any]) -> None:
        kind = APPROVAL_METHODS[message["method"]]
        await self.client.respond(message["id"], self._rejection_result(kind))

    def _resolve_server_request(self, run: Run, params: dict[str, Any]) -> None:
        request_id = params.get("requestId")
        if request_id is None:
            return
        approval = run.approvals.get(str(request_id))
        if approval and approval.status in {"pending", "responding"}:
            approval.status = "resolved"
            if approval.timeout_task:
                approval.timeout_task.cancel()

    async def _publish(self, run: Run, detail: str) -> None:
        run.events.append(detail)
        del run.events[:-80]
        event = {"event": "run", "data": run.snapshot()}
        for queue in list(run.subscribers):
            await queue.put(event)

    def _persist(self, run: Run) -> None:
        self.store.save_task(run.id, run.project_id, run.status, run.snapshot(), run.thread_id, run.turn_id)

    def _run(self, run_id: str) -> Run:
        try:
            return self.runs[run_id]
        except KeyError as exc:
            raise PolicyError("작업 카드를 찾을 수 없습니다.") from exc

    def _run_for_thread(self, thread_id: str | None) -> Run | None:
        if not thread_id:
            return None
        return next((item for item in self.runs.values() if item.thread_id == thread_id), None)

    def _store_request_artifacts(self, run: Run) -> None:
        self.store.write_artifact(run.project_id, run.id, "request.md", run.task)
        self.store.write_artifact(run.project_id, run.id, "decision.json", run.decision)

    async def _reject_run_before_start(self, run: Run, reason: str) -> Run:
        run.status = "failed"
        run.stop_reason = reason
        await self._publish(run, reason)
        self.store.write_artifact(run.project_id, run.id, "result.json", run.snapshot())
        self._persist(run)
        return run

    def _approval_paths(self, params: dict[str, Any]) -> list[str]:
        paths: list[str] = []
        if params.get("grantRoot"):
            paths.append(str(params["grantRoot"]))
        for action in params.get("commandActions", []) or []:
            if isinstance(action, dict) and action.get("path"):
                paths.append(str(action["path"]))
        for change in params.get("changes", []) or []:
            if isinstance(change, dict) and change.get("path"):
                paths.append(str(change["path"]))
        return list(dict.fromkeys(paths))

    def _rejection_result(self, kind: str) -> dict[str, Any]:
        if kind == "permissions":
            return {"permissions": {}}
        return {"decision": "cancel"}

    def _forbidden_reference_reason(self, payload: Any) -> str | None:
        reference = find_forbidden_root_reference(payload)
        if not reference:
            return None
        return f"금지 루트 참조가 감지되어 실행을 거부했습니다: {reference}"

    async def _reject_forbidden_request(
        self,
        run: Run,
        message: dict[str, Any],
        kind: str,
        reason: str,
    ) -> None:
        run.stop_reason = reason
        await self._publish(run, reason)
        self._persist(run)

        response_error: Exception | None = None
        try:
            await self.client.respond(message["id"], self._rejection_result(kind))
        except Exception as exc:  # pragma: no cover - defensive transport handling
            response_error = exc

        try:
            await self.interrupt(run.id, reason)
        finally:
            self._persist(run)

        if response_error is not None:
            raise response_error

    def snapshot(self, run_id: str) -> dict[str, Any]:
        return self._run(run_id).snapshot()
