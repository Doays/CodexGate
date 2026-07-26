from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from jsonschema import Draft7Validator
from jsonschema.exceptions import ValidationError


APPROVAL_METHODS = {
    "item/commandExecution/requestApproval": "command",
    "item/fileChange/requestApproval": "fileChange",
    "item/permissions/requestApproval": "permissions",
}


class ProtocolValidationError(ValueError):
    pass


@dataclass(frozen=True)
class ProtocolSchema:
    root: Path
    approval_methods: frozenset[str]
    decisions: dict[str, tuple[str, ...]]
    workspace_write_supported: bool
    on_request_supported: bool
    validators: dict[str, Draft7Validator] = field(default_factory=dict)
    approvals_reviewer_user_supported: bool = False

    @classmethod
    def load(cls, root: Path) -> "ProtocolSchema":
        server_requests = _read_json(root / "ServerRequest.json")
        thread = _read_json(root / "v2" / "ThreadStartParams.json")
        turn = _read_json(root / "v2" / "TurnStartParams.json")
        schemas = {
            "server_request": server_requests,
            "thread_start": thread,
            "turn_start": turn,
            "command_response": _read_json(root / "CommandExecutionRequestApprovalResponse.json"),
            "fileChange_response": _read_json(root / "FileChangeRequestApprovalResponse.json"),
            "permissions_response": _read_json(root / "PermissionsRequestApprovalResponse.json"),
            "account_response": _read_json(root / "v2" / "GetAccountResponse.json"),
            "rate_limits_response": _read_json(root / "v2" / "GetAccountRateLimitsResponse.json"),
            "usage_response": _read_json(root / "v2" / "GetAccountTokenUsageResponse.json"),
            "model_list_response": _read_json(root / "v2" / "ModelListResponse.json"),
            "rate_limits_updated": _read_json(root / "v2" / "AccountRateLimitsUpdatedNotification.json"),
        }
        validators = {name: Draft7Validator(schema) for name, schema in schemas.items()}
        methods = _methods(server_requests)
        decisions = {
            "command": _decision_values(schemas["command_response"]),
            "fileChange": _decision_values(schemas["fileChange_response"]),
            "permissions": ("accept", "acceptForSession", "decline", "cancel"),
        }
        instance = cls(
            root=root,
            approval_methods=frozenset(methods & set(APPROVAL_METHODS)),
            decisions=decisions,
            validators=validators,
            workspace_write_supported=False,
            on_request_supported=False,
            approvals_reviewer_user_supported=False,
        )
        thread_ok = instance.is_valid("thread_start", {"sandbox": "workspace-write", "approvalPolicy": "on-request", "approvalsReviewer": "user"})
        turn_ok = instance.is_valid("turn_start", {
            "threadId": "schema-check", "input": [], "approvalPolicy": "on-request", "approvalsReviewer": "user",
            "sandboxPolicy": {"type": "workspaceWrite", "networkAccess": False, "writableRoots": []},
        })
        return cls(
            root=root, approval_methods=instance.approval_methods, decisions=decisions, validators=validators,
            workspace_write_supported=thread_ok and turn_ok and set(APPROVAL_METHODS).issubset(instance.approval_methods),
            on_request_supported=thread_ok and turn_ok,
            approvals_reviewer_user_supported=thread_ok and turn_ok,
        )

    @property
    def approvals_supported(self) -> bool:
        return set(APPROVAL_METHODS).issubset(self.approval_methods)

    def decisions_for(self, kind: str) -> tuple[str, ...]:
        return self.decisions.get(kind, ())

    def is_valid(self, name: str, payload: dict[str, Any]) -> bool:
        return not list(self.validators[name].iter_errors(payload))

    def validate(self, name: str, payload: dict[str, Any]) -> None:
        errors = sorted(self.validators[name].iter_errors(payload), key=lambda error: list(error.path))
        if errors:
            error = errors[0]
            location = ".".join(str(part) for part in error.path) or "payload"
            raise ProtocolValidationError(f"{name} schema 검증 실패 ({location}): {error.message}")


def _read_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def _methods(schema: dict[str, Any]) -> set[str]:
    result: set[str] = set()
    for variant in schema.get("oneOf", []):
        enum = variant.get("properties", {}).get("method", {}).get("enum", [])
        result.update(value for value in enum if isinstance(value, str))
    return result


def _decision_values(schema: dict[str, Any]) -> tuple[str, ...]:
    response = schema.get("properties", {}).get("decision", {})
    ref = response.get("$ref", "").rsplit("/", 1)[-1]
    variants = schema.get("definitions", {}).get(ref, {}).get("oneOf", [])
    return tuple(value for variant in variants for value in variant.get("enum", []) if isinstance(value, str))


def is_permission_subset(granted: Any, requested: Any) -> bool:
    if granted is None:
        return True
    if isinstance(granted, dict):
        return isinstance(requested, dict) and all(key in requested and is_permission_subset(value, requested[key]) for key, value in granted.items())
    if isinstance(granted, list):
        return isinstance(requested, list) and all(item in requested for item in granted)
    if isinstance(granted, bool):
        return isinstance(requested, bool) and (not granted or requested)
    return granted == requested
