from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit

from .policy import BRIDGE_MAX_PACKET_BYTES, BRIDGE_SCHEMA_VERSION, Decision, PolicyError, bridge_packet_safety_reason, canonical_json, sha256_json, validate_project_id, validate_task_id, validate_workspace_root
from .evidence import COLLECTOR_VERSION, MAX_TOTAL_BYTES, collect as collect_evidence, normalize_requested_evidence
from .policy import resolve_safe_evidence_mapping
from .storage import Store


BEGIN_MARKER = "----- CODEXGATE BRIDGE BEGIN -----"
END_MARKER = "----- CODEXGATE BRIDGE END -----"
ARCHITECT_REQUEST, ARCHITECT_RESPONSE = "ARCHITECT_REQUEST", "ARCHITECT_RESPONSE"
REVIEW_REQUEST, REVIEW_RESPONSE = "REVIEW_REQUEST", "REVIEW_RESPONSE"
ARCHITECT_READY, WAITING_ARCHITECT, ROUTE_READY = "ARCHITECT_READY", "WAITING_ARCHITECT", "ROUTE_READY"
NEED_MORE_EVIDENCE, REVIEW_READY, WAITING_REVIEW = "NEED_MORE_EVIDENCE", "REVIEW_READY", "WAITING_REVIEW"
PROCESSING_RESPONSE, SUCCESS, HOLD, REDESIGN, ROLLBACK, RESTART_REQUIRED = "PROCESSING_RESPONSE", "SUCCESS", "HOLD", "REDESIGN", "ROLLBACK", "RESTART_REQUIRED"
_STATES = frozenset({ARCHITECT_READY, WAITING_ARCHITECT, ROUTE_READY, NEED_MORE_EVIDENCE, REVIEW_READY, WAITING_REVIEW, PROCESSING_RESPONSE, SUCCESS, HOLD, REDESIGN, ROLLBACK, RESTART_REQUIRED})
_RESPONSE_FIELDS = {"TYPE", "TASK_ID", "PHASE", "NONCE", "SCHEMA_VERSION", "BODY"}
_RESPONSE_TTL_SECONDS = 30 * 60


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_time(value: str) -> datetime:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise PolicyError("Bridge packet timestamp is invalid") from exc


def _new_nonce() -> str:
    return str(uuid.uuid4())


def _response_contract(phase: str) -> dict[str, Any]:
    base = {"TYPE": "response type below", "TASK_ID": "copy exactly", "PHASE": phase, "NONCE": "copy exactly", "SCHEMA_VERSION": BRIDGE_SCHEMA_VERSION}
    if phase == "ARCHITECT":
        return {
            "required_envelope_fields": list(sorted(_RESPONSE_FIELDS)),
            "architect_execute": {**base, "TYPE": ARCHITECT_RESPONSE, "BODY": {"outcome": "execute", "decision": {"decision": "execute", "task_class": "T3", "recommended_model": "server model id", "recommended_effort": "server effort", "allowed_files": [], "forbidden_files": [], "validation_commands": [], "stop_conditions": []}}},
            "architect_need_more_evidence": {**base, "TYPE": ARCHITECT_RESPONSE, "BODY": {"outcome": "need_more_evidence", "requested_evidence": [{"type": "file_metadata", "label": "file summary", "reason": "needed to scope work", "required": True, "target_hint": "describe the file, not a local path"}]}},
            "rules": ["Do not add envelope or BODY fields.", "Do not calculate a hash or sort JSON keys.", "Put exactly one marked JSON block in the reply."],
        }
    examples = {}
    for verdict in ("SUCCESS", "HOLD", "RETRY", "REDESIGN", "ROLLBACK"):
        examples[verdict] = {**base, "TYPE": REVIEW_RESPONSE, "BODY": {"verdict": verdict, "notes": "short bounded rationale", "requested_evidence": []}}
    return {
        "required_envelope_fields": list(sorted(_RESPONSE_FIELDS)),
        "review_verdicts": examples,
        "rules": ["Use one of the five verdicts only.", "notes is at most 4KB; requested_evidence has at most 20 items.", "Do not add envelope or BODY fields, hashes, or key-order requirements."],
    }


def validate_architect_body(body: Any) -> dict[str, Any]:
    if not isinstance(body, dict):
        raise PolicyError("ARCHITECT_RESPONSE body is unsupported")
    if set(body) == {"outcome", "decision"} and body.get("outcome") == "execute" and isinstance(body["decision"], dict):
        return {"outcome": "execute", "decision": Decision.from_json(body["decision"]).as_dict()}
    if set(body) == {"outcome", "requested_evidence"} and body.get("outcome") == "need_more_evidence":
        return {"outcome": "need_more_evidence", "requested_evidence": normalize_requested_evidence(body["requested_evidence"])}
    raise PolicyError("ARCHITECT_RESPONSE body is unsupported")


def validate_review_body(body: Any) -> dict[str, Any]:
    if not isinstance(body, dict) or set(body) != {"verdict", "notes", "requested_evidence"} or body.get("verdict") not in {"SUCCESS", "HOLD", "RETRY", "REDESIGN", "ROLLBACK"}:
        raise PolicyError("REVIEW_RESPONSE body is unsupported")
    notes = body.get("notes")
    if not isinstance(notes, str) or len(notes.encode("utf-8")) > 4096:
        raise PolicyError("REVIEW_RESPONSE notes are invalid")
    return {"verdict": body["verdict"], "notes": notes.strip(), "requested_evidence": normalize_requested_evidence(body["requested_evidence"])}


def _request_packet(record: Mapping[str, Any], body: dict[str, Any]) -> str:
    base = {
        "TYPE": record["packet_type"], "TASK_ID": record["task_id"], "PHASE": record["phase"],
        "NONCE": record["pending_nonce"], "CREATED_AT": record["packet_created_at"],
        "EXPIRES_AT": record["packet_expires_at"], "SCHEMA_VERSION": BRIDGE_SCHEMA_VERSION, "BODY": body,
    }
    request_sha = sha256_json(base)
    if request_sha != record["request_sha256"]:
        raise PolicyError("Bridge request integrity check failed")
    return f"{BEGIN_MARKER}\n{canonical_json({**base, 'REQUEST_SHA256': request_sha})}\n{END_MARKER}"


def parse_bridge_packet(raw: str) -> dict[str, Any]:
    """Extract one response block; prose and one surrounding code fence are harmless."""
    if not isinstance(raw, str):
        raise PolicyError("Bridge response must be text")
    if len(raw.encode("utf-8")) > BRIDGE_MAX_PACKET_BYTES:
        raise PolicyError("Bridge packet exceeds 60KB.")
    starts = list(re.finditer(re.escape(BEGIN_MARKER), raw))
    ends = list(re.finditer(re.escape(END_MARKER), raw))
    if len(starts) != 1 or len(ends) != 1 or starts[0].start() >= ends[0].start():
        raise PolicyError("Bridge response must contain exactly one complete BEGIN/END packet")
    text = raw[starts[0].end():ends[0].start()].strip()
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise PolicyError("Bridge response JSON is invalid") from exc
    if not isinstance(value, dict) or set(value) != _RESPONSE_FIELDS:
        raise PolicyError("Bridge response has missing or unsupported envelope fields")
    for field in ("TYPE", "TASK_ID", "PHASE", "NONCE", "SCHEMA_VERSION"):
        if not isinstance(value[field], str) or not value[field]:
            raise PolicyError(f"Bridge response field {field} is invalid")
    if value["SCHEMA_VERSION"] != BRIDGE_SCHEMA_VERSION or not isinstance(value["BODY"], dict):
        raise PolicyError("Bridge response schema version or body is invalid")
    return value


class BridgeService:
    """Manual-only bridge. Its Route Plan callback is local and never calls app-server RPC."""

    def __init__(self, store: Store, route_plan_creator: Callable[[dict[str, Any]], dict[str, Any]]):
        self.store, self.route_plan_creator = store, route_plan_creator

    @staticmethod
    def active_action(state: str) -> str:
        actions = {
            ARCHITECT_READY: "copy_architect_request", WAITING_ARCHITECT: "import_architect_response",
            ROUTE_READY: "prepare_review_request", NEED_MORE_EVIDENCE: "prepare_evidence",
            PROCESSING_RESPONSE: "processing_response",
            REVIEW_READY: "copy_review_request", WAITING_REVIEW: "import_review_response",
            SUCCESS: "restart", HOLD: "restart", REDESIGN: "restart", ROLLBACK: "restart", RESTART_REQUIRED: "restart_required",
        }
        if state not in actions:
            raise PolicyError("Bridge state has no permitted action")
        return actions[state]

    def create(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        project_id = validate_project_id(str(payload.get("project_id", "")))
        task, root, permission = payload.get("task"), payload.get("root"), payload.get("permission")
        if not isinstance(task, str) or not task.strip() or len(task) > 12_000 or not isinstance(root, str) or not root.strip():
            raise PolicyError("Bridge task requires bounded task text and a local root")
        if permission != "read-only":
            raise PolicyError("Bridge start is Read Only only")
        if reason := bridge_packet_safety_reason(task):
            raise PolicyError(reason)
        root_path = validate_workspace_root(root)
        chat_url = payload.get("chat_url")
        if chat_url is not None and (not isinstance(chat_url, str) or len(chat_url) > 2048):
            raise PolicyError("Bridge chat URL is invalid")
        if isinstance(chat_url, str) and chat_url.strip():
            parsed = urlsplit(chat_url.strip())
            if parsed.scheme != "https" or parsed.hostname not in {"chatgpt.com", "chat.openai.com"}:
                raise PolicyError("Bridge chat URL must be an HTTPS ChatGPT URL")
        timestamp = datetime.now(timezone.utc)
        record = {
            "protocol_version": BRIDGE_SCHEMA_VERSION, "task_id": str(uuid.uuid4()), "project_id": project_id,
            "project_name": str(payload.get("project_name", project_id)).strip()[:120], "task": task.strip(), "root": str(root_path),
            "permission": "read-only", "chat_url": chat_url.strip() if isinstance(chat_url, str) and chat_url.strip() else None,
            "status": ARCHITECT_READY, "active_action": self.active_action(ARCHITECT_READY), "phase": "ARCHITECT", "packet_type": ARCHITECT_REQUEST,
            "pending_nonce": _new_nonce(), "requested_evidence": [], "collected_evidence": [], "review_feedback": None, "review_result": None, "review_validation": None,
            "route_plan_id": None, "created_at": timestamp.isoformat(), "updated_at": timestamp.isoformat(),
        }
        self._seal_request(record, timestamp)
        return self.snapshot(self.store.create_bridge_task(record))

    def snapshot(self, record: Mapping[str, Any]) -> dict[str, Any]:
        if record.get("protocol_version") != BRIDGE_SCHEMA_VERSION:
            return {"task_id": record["task_id"], "project_id": record["project_id"], "status": RESTART_REQUIRED, "active_action": self.active_action(RESTART_REQUIRED), "restart_required": True, "message": "This pending Bridge task uses protocol v1. Start a new v2 Bridge task.", "history": self.store.bridge_history(record["task_id"])}
        if record.get("status") not in _STATES:
            raise PolicyError("Bridge task state is invalid")
        keys = ("task_id", "project_id", "status", "active_action", "phase", "packet_type", "pending_nonce", "route_plan_id", "requested_evidence", "chat_url", "created_at", "updated_at", "packet_created_at", "packet_expires_at", "request_sha256", "review_feedback", "hold_reason", "error_code")
        results = self.store.evidence_results(record["task_id"])
        public_results = [{key: item.get(key) for key in ("request_id", "state", "type", "label", "path", "result_hash", "size_bytes", "error_code", "error_reason")} for item in results]
        return {**{key: record.get(key) for key in keys}, "evidence_required": record["status"] == NEED_MORE_EVIDENCE, "evidence_requests": self.store.evidence_requests(record["task_id"]), "evidence_results": public_results, "copied_at": record.get("copied_at"), "received_at": record.get("received_at"), "response_hash": record.get("response_hash"), "history": self.store.bridge_history(record["task_id"])}

    def get(self, task_id: str) -> dict[str, Any]:
        return self.snapshot(self.store.load_bridge_task(task_id))

    def recent(self) -> list[dict[str, Any]]:
        return [self.snapshot(item) for item in self.store.recent_bridge_tasks()]

    def latest(self) -> dict[str, Any] | None:
        records = self.recent()
        return records[0] if records else None

    def _current_record(self, task_id: str) -> dict[str, Any]:
        return self._v2(self.store.load_bridge_task(task_id))

    def recover_processing_on_startup(self) -> dict[str, Any] | None:
        self.store.recover_bridge_processing_tasks(
            hold_reason="Bridge response processing was interrupted; start a new cycle.",
            error_code="processing_interrupted",
        )
        return self.latest()

    def packet(self, task_id: str) -> str:
        record = self._current_record(task_id)
        if record["status"] == NEED_MORE_EVIDENCE:
            raise PolicyError("EVIDENCE_REQUIRED: required local evidence is not ready")
        if record["status"] == PROCESSING_RESPONSE:
            raise PolicyError("Bridge response is being processed")
        if record["status"] not in {ARCHITECT_READY, WAITING_ARCHITECT, REVIEW_READY, WAITING_REVIEW}:
            raise PolicyError("Bridge task is not ready to copy a packet")
        if _parse_time(record["packet_expires_at"]) <= datetime.now(timezone.utc):
            self._hold(record, "Bridge request expired; start a new cycle.")
            raise PolicyError("Bridge request expired; start a new cycle.")
        if record["packet_type"] == ARCHITECT_REQUEST:
            body = self._body_for_hash(record)
        else:
            body = {"route_plan_id": record["route_plan_id"], "result": record["review_result"], "local_validation": record["review_validation"], "constraints": ["No live Codex run occurred through this bridge."], "RESPONSE_CONTRACT": _response_contract("REVIEW")}
        if reason := bridge_packet_safety_reason(body):
            self._hold(record, reason)
            raise PolicyError(reason)
        packet = _request_packet(record, body)
        if len(packet.encode("utf-8")) > BRIDGE_MAX_PACKET_BYTES:
            self._hold(record, "Bridge packet exceeds 60KB.")
            raise PolicyError("Bridge packet exceeds 60KB.")
        return packet

    def copied(self, task_id: str) -> dict[str, Any]:
        record = self._current_record(task_id)
        if record["active_action"] == "copy_architect_request":
            state = WAITING_ARCHITECT
        elif record["active_action"] == "copy_review_request":
            state = WAITING_REVIEW
        else:
            raise PolicyError("Bridge copy is not allowed in the current state")
        return self.snapshot(self._save(record, status=state, active_action=self.active_action(state), copied=True))

    def prepare_review(self, task_id: str, result: Mapping[str, Any], validation: Mapping[str, Any]) -> dict[str, Any]:
        record = self._current_record(task_id)
        if record["status"] != ROUTE_READY or record["active_action"] != "prepare_review_request" or not result or not validation:
            raise PolicyError("Review request requires a ready Route Plan, actual result, and local validation")
        result_copy, validation_copy = dict(result), dict(validation)
        if reason := bridge_packet_safety_reason({"result": result_copy, "validation": validation_copy}):
            self._hold(record, reason)
            raise PolicyError(reason)
        timestamp = datetime.now(timezone.utc)
        updated = {**record, "status": REVIEW_READY, "active_action": self.active_action(REVIEW_READY), "phase": "REVIEW", "packet_type": REVIEW_REQUEST, "pending_nonce": _new_nonce(), "review_result": result_copy, "review_validation": validation_copy}
        self._seal_request(updated, timestamp)
        return self.snapshot(self._save(record, **{key: value for key, value in updated.items() if key not in {"task_id", "updated_at"}}))

    def import_response(self, task_id: str, raw: str) -> dict[str, Any]:
        record = self._current_record(task_id)
        envelope = parse_bridge_packet(raw)
        response_hash = sha256_json(envelope)
        if self.store.bridge_response_duplicate(record["task_id"], envelope["NONCE"], response_hash):
            return self.get(record["task_id"])
        expected = (ARCHITECT_RESPONSE, "ARCHITECT") if record["status"] == WAITING_ARCHITECT else (REVIEW_RESPONSE, "REVIEW") if record["status"] == WAITING_REVIEW else None
        if expected is None:
            if record["status"] == PROCESSING_RESPONSE:
                raise PolicyError("Bridge response is being processed")
            raise PolicyError("Bridge task is not waiting for a response")
        if envelope["TYPE"] != expected[0] or envelope["PHASE"] != expected[1] or envelope["TASK_ID"] != record["task_id"] or envelope["NONCE"] != record["pending_nonce"]:
            raise PolicyError("Bridge response task, phase, type, or nonce does not match")
        if _parse_time(record["packet_expires_at"]) <= datetime.now(timezone.utc):
            expired = {
                **record,
                "status": HOLD,
                "active_action": self.active_action(HOLD),
                "pending_nonce": None,
                "hold_reason": "Bridge request expired; start a new cycle.",
                "error_code": "expired_response",
                "updated_at": _now(),
            }
            outcome = self.store.fail_bridge_response(
                record["task_id"],
                record["pending_nonce"],
                response_hash,
                task_payload=expired,
                received_hash=response_hash,
                error_code="expired_response",
            )
            if outcome == "duplicate":
                return self.get(record["task_id"])
            raise PolicyError("Bridge response expired")
        body = validate_architect_body(envelope["BODY"]) if expected[0] == ARCHITECT_RESPONSE else validate_review_body(envelope["BODY"])
        if reason := bridge_packet_safety_reason(body):
            raise PolicyError(reason)
        processing = {**record, "status": PROCESSING_RESPONSE, "active_action": self.active_action(PROCESSING_RESPONSE), "updated_at": _now()}
        claim = self.store.claim_bridge_response(record["task_id"], record["pending_nonce"], response_hash, task_payload=processing, received_hash=response_hash)
        if claim == "duplicate":
            return self.get(record["task_id"])
        if expected[0] == ARCHITECT_RESPONSE:
            return self._import_architect(record, body, response_hash)
        return self._import_review(record, body, response_hash)

    def restart(self, task_id: str) -> dict[str, Any]:
        record = self._current_record(task_id)
        if record.get("protocol_version") != BRIDGE_SCHEMA_VERSION:
            raise PolicyError("Protocol v1 task is restart-required; start a new v2 Bridge task")
        if record["active_action"] != "restart":
            raise PolicyError("Bridge task cannot be restarted now")
        timestamp = datetime.now(timezone.utc)
        updated = {**record, "status": ARCHITECT_READY, "active_action": self.active_action(ARCHITECT_READY), "phase": "ARCHITECT", "packet_type": ARCHITECT_REQUEST, "pending_nonce": _new_nonce(), "route_plan_id": None, "requested_evidence": [], "collected_evidence": [], "review_feedback": record.get("review_feedback") if record.get("status") == REDESIGN else None, "review_result": None, "review_validation": None}
        self._seal_request(updated, timestamp)
        return self.snapshot(self._save(record, **{key: value for key, value in updated.items() if key not in {"task_id", "updated_at"}}))

    def _import_architect(self, record: dict[str, Any], body: dict[str, Any], response_hash: str) -> dict[str, Any]:
        if body.get("outcome") == "execute" and set(body) == {"outcome", "decision"} and isinstance(body["decision"], dict):
            try:
                decision = Decision.from_json(body["decision"]).as_dict()
                key = f"bridge:{record['task_id']}:{record['pending_nonce']}"
                plan = self.route_plan_creator({"project_name": record["project_name"], "project_id": record["project_id"], "root": record["root"], "task": record["task"], "decision": decision, "permission": "read-only", "explicit_ultra_approval": False, "bridge_idempotency_key": key})
            except Exception as exc:
                self._hold(record, "Route Plan creation failed; start a new cycle.", error_code="route_plan_failed", response_hash=response_hash)
                raise PolicyError("Route Plan creation failed; start a new cycle.") from exc
            state = ROUTE_READY if plan["status"] == "PREVIEW" else HOLD
            return self.snapshot(self._save(record, status=state, active_action=self.active_action(state), pending_nonce=None, route_plan_id=plan["plan_id"], architect_response={"outcome": "execute"}, complete_nonce=record["pending_nonce"], complete_nonce_response_hash=response_hash))
        if body.get("outcome") == "need_more_evidence" and set(body) == {"outcome", "requested_evidence"}:
            requested = self._requested_evidence(body["requested_evidence"])
            if reason := bridge_packet_safety_reason(requested):
                self._hold(record, reason, error_code="request_more_evidence_blocked", response_hash=response_hash)
                raise PolicyError(reason)
            requests = [{**item, "request_id": str(uuid.uuid5(uuid.UUID(record["task_id"]), f"evidence:{index}")), "state": "REQUESTED"} for index, item in enumerate(requested)]
            saved = self._save(record, status=NEED_MORE_EVIDENCE, active_action=self.active_action(NEED_MORE_EVIDENCE), pending_nonce=None, requested_evidence=requested, architect_response={"outcome": "need_more_evidence", "requested_evidence": requested}, complete_nonce=record["pending_nonce"], complete_nonce_response_hash=response_hash)
            self.store.create_evidence_requests(record["task_id"], requests)
            return self.snapshot(saved)
        raise PolicyError("ARCHITECT_RESPONSE body is unsupported")

    def _import_review(self, record: dict[str, Any], body: dict[str, Any], response_hash: str) -> dict[str, Any]:
        verdict = body["verdict"]
        notes = body["notes"]
        requested = body["requested_evidence"]
        review_feedback = {"verdict": verdict, "notes": notes, "requested_evidence": requested}
        if verdict == "RETRY":
            timestamp = datetime.now(timezone.utc)
            updated = {**record, "status": ARCHITECT_READY, "active_action": self.active_action(ARCHITECT_READY), "phase": "ARCHITECT", "packet_type": ARCHITECT_REQUEST, "pending_nonce": _new_nonce(), "route_plan_id": None, "requested_evidence": [], "collected_evidence": [], "review_feedback": review_feedback, "review_result": None, "review_validation": None}
            self._seal_request(updated, timestamp)
            return self.snapshot(self._save(record, review_response=review_feedback, **{key: value for key, value in updated.items() if key not in {"task_id", "updated_at"}} , complete_nonce=record["pending_nonce"], complete_nonce_response_hash=response_hash))
        state = {"SUCCESS": SUCCESS, "HOLD": HOLD, "REDESIGN": REDESIGN, "ROLLBACK": ROLLBACK}[verdict]
        return self.snapshot(self._save(record, status=state, active_action=self.active_action(state), pending_nonce=None, requested_evidence=requested, review_feedback=review_feedback, review_response=review_feedback, complete_nonce=record["pending_nonce"], complete_nonce_response_hash=response_hash))

    @staticmethod
    def _requested_evidence(value: Any) -> list[dict[str, Any]]:
        return normalize_requested_evidence(value)

    def map_evidence(self, task_id: str, request_id: str, mapped_path: str, options: Mapping[str, Any] | None = None) -> dict[str, Any]:
        record = self._current_record(task_id)
        if record["status"] != NEED_MORE_EVIDENCE:
            raise PolicyError("Evidence mapping is only available while evidence is required")
        if not isinstance(mapped_path, str) or not mapped_path.strip():
            raise PolicyError("Evidence mapping requires a project-relative file")
        _, relative = resolve_safe_evidence_mapping(record["root"], mapped_path)
        allowed = {"start_line", "end_line", "line", "context_before", "context_after"}
        details = dict(options or {})
        if set(details) - allowed or any(isinstance(value, bool) or not isinstance(value, int) for value in details.values()):
            raise PolicyError("Evidence mapping options are invalid")
        self.store.update_evidence_request(task_id, request_id, {"mapped_path": relative, **details, "state": "MAPPED", "error_code": None, "error_reason": None})
        return self.get(task_id)

    def collect_evidence(self, task_id: str, request_id: str) -> dict[str, Any]:
        record = self._current_record(task_id)
        if record["status"] != NEED_MORE_EVIDENCE:
            raise PolicyError("Evidence collection is only available while evidence is required")
        requests = {item["request_id"]: item for item in self.store.evidence_requests(task_id)}
        request = requests.get(request_id)
        if request is None:
            raise PolicyError("Evidence request was not found")
        existing = {item["request_id"]: item for item in self.store.evidence_results(task_id)}.get(request_id)
        if request.get("state") == "READY" and existing:
            return self._advance_if_evidence_ready(record)
        if request.get("state") not in {"MAPPED", "FAILED", "REJECTED", "COLLECTING"}:
            raise PolicyError("Evidence request must be mapped before collection")
        self.store.update_evidence_request(task_id, request_id, {"state": "COLLECTING", "error_code": None, "error_reason": None})
        try:
            result = collect_evidence({**request, "state": "COLLECTING"}, record["root"])
            prior_results = self.store.evidence_results(task_id)
            used = sum(int(item.get("size_bytes", 0)) for item in prior_results if item.get("request_id") != request_id)
            if used + int(result["size_bytes"]) > MAX_TOTAL_BYTES:
                raise PolicyError("Total web evidence exceeds 50KB")
            if result.get("type") in {"text_range", "log_excerpt"}:
                prior_lines = sum(len(item.get("lines", [])) for item in prior_results if item.get("path") == result.get("path") and item.get("type") in {"text_range", "log_excerpt"})
                if prior_lines + len(result.get("lines", [])) > 1000:
                    raise PolicyError("Text evidence exceeds 1000 lines for one file")
            self.store.finalize_evidence_collection(task_id, request_id, result, "READY")
        except PolicyError as exc:
            self.store.finalize_evidence_collection(task_id, request_id, {"type": request["type"], "label": request["label"], "error_code": "collection_rejected", "error_reason": str(exc)}, "FAILED", error_code="collection_rejected", error_reason=str(exc))
            return self.get(task_id)
        return self._advance_if_evidence_ready(record)

    def _advance_if_evidence_ready(self, record: Mapping[str, Any]) -> dict[str, Any]:
        requests = self.store.evidence_requests(record["task_id"])
        if any(item.get("required") and item.get("state") != "READY" for item in requests):
            return self.get(record["task_id"])
        results_by_id = {item["request_id"]: item for item in self.store.evidence_results(record["task_id"])}
        evidence = [results_by_id[item["request_id"]] for item in requests if item.get("state") == "READY" and item["request_id"] in results_by_id]
        timestamp = datetime.now(timezone.utc)
        updated = {**record, "status": ARCHITECT_READY, "active_action": self.active_action(ARCHITECT_READY), "phase": "ARCHITECT", "packet_type": ARCHITECT_REQUEST, "pending_nonce": _new_nonce(), "collected_evidence": evidence}
        self._seal_request(updated, timestamp)
        return self.snapshot(self._save(dict(record), **{key: value for key, value in updated.items() if key not in {"task_id", "updated_at"}}))

    def _hold(self, record: Mapping[str, Any], reason: str, *, error_code: str | None = None, response_hash: str | None = None) -> dict[str, Any]:
        fail_nonce = record.get("pending_nonce") if response_hash is not None else None
        return self._save(dict(record), status=HOLD, active_action=self.active_action(HOLD), pending_nonce=None, hold_reason=reason, error_code=error_code, fail_nonce=fail_nonce, fail_nonce_response_hash=response_hash if fail_nonce is not None else None, fail_nonce_error_code=error_code)

    @staticmethod
    def _seal_request(record: dict[str, Any], timestamp: datetime) -> None:
        record["packet_created_at"] = timestamp.isoformat()
        record["packet_expires_at"] = (timestamp + timedelta(seconds=_RESPONSE_TTL_SECONDS)).isoformat()
        body = BridgeService._body_for_hash(record)
        base = {"TYPE": record["packet_type"], "TASK_ID": record["task_id"], "PHASE": record["phase"], "NONCE": record["pending_nonce"], "CREATED_AT": record["packet_created_at"], "EXPIRES_AT": record["packet_expires_at"], "SCHEMA_VERSION": BRIDGE_SCHEMA_VERSION, "BODY": body}
        record["request_sha256"] = sha256_json(base)

    @staticmethod
    def _body_for_hash(record: Mapping[str, Any]) -> dict[str, Any]:
        if record["packet_type"] == ARCHITECT_REQUEST:
            return {"task": record["task"], "local_facts": {"scope": "No repository body, logs, or absolute paths are supplied."}, "collected_evidence": record.get("collected_evidence", []), "collector_version": COLLECTOR_VERSION, "constraints": ["Read Only only", "Workspace Write, Ultra, and live runs are locked"], "questions": ["Choose execute or need_more_evidence."], "review_feedback": record.get("review_feedback"), "RESPONSE_CONTRACT": _response_contract("ARCHITECT")}
        return {"route_plan_id": record["route_plan_id"], "result": record["review_result"], "local_validation": record["review_validation"], "constraints": ["No live Codex run occurred through this bridge."], "RESPONSE_CONTRACT": _response_contract("REVIEW")}

    def _v2(self, record: dict[str, Any]) -> dict[str, Any]:
        if record.get("protocol_version") != BRIDGE_SCHEMA_VERSION:
            raise PolicyError("Protocol v1 task is restart-required; start a new v2 Bridge task")
        return record

    def _save(self, record: dict[str, Any], *, copied: bool = False, received_hash: str | None = None, **changes: Any) -> dict[str, Any]:
        complete_nonce = changes.pop("complete_nonce", None)
        complete_nonce_response_hash = changes.pop("complete_nonce_response_hash", None)
        fail_nonce = changes.pop("fail_nonce", None)
        fail_nonce_response_hash = changes.pop("fail_nonce_response_hash", None)
        fail_nonce_error_code = changes.pop("fail_nonce_error_code", None)
        return self.store.update_bridge_task(
            record["task_id"],
            {**record, **changes, "updated_at": _now()},
            copied=copied,
            received_hash=received_hash,
            complete_nonce=complete_nonce,
            complete_nonce_response_hash=complete_nonce_response_hash,
            fail_nonce=fail_nonce,
            fail_nonce_response_hash=fail_nonce_response_hash,
            fail_nonce_error_code=fail_nonce_error_code,
        )
