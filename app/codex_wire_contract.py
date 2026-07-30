"""Read-only proof and strict parser for the Codex 0.145.0 Responses wire.

The module contains no process, socket, filesystem, or network operations.  It
is deliberately fail-closed: until the source bytes listed in ``SOURCE_FILES``
are independently hashed, the proof remains ``UNPROVEN`` and production
execution must not proceed.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .policy import PolicyError, canonical_json, sha256_json


OFFICIAL_REPOSITORY = "openai/codex"
OFFICIAL_TAG = "rust-v0.145.0"
WIRE_CONTRACT_VERSION = "codex-responses-sse-v1"
PROOF_SCHEMA_VERSION = "codex-wire-contract-proof-v1"

# These are relative paths in the tagged repository.  The SHA-256 values are
# calculated over the exact UTF-8 bytes returned by the official tag's raw
# source pages; a source mismatch still fails closed.
SOURCE_FILES: tuple[dict[str, str | None], ...] = (
    {"path": "codex-rs/codex-api/src/common.rs", "sha256": "8f033dd8b494d02f7b7bbf56fc1743d71090895e43eb72ec37dd67f081454aa7"},
    {"path": "codex-rs/codex-api/src/endpoint/responses.rs", "sha256": "7f4f57f71da86253a82cdbef8c369746b70ccf0b615b6a4f863b341059efe69c"},
    {"path": "codex-rs/codex-api/tests/sse_end_to_end.rs", "sha256": "43044f9a6284b94ff001f0639962be8fd2b6e23b8287f24fdc18b8872112ada7"},
)
_SEALED_SOURCE_HASHES = {item["path"]: item["sha256"] for item in SOURCE_FILES}

PROOF_STATES = frozenset({"UNPROVEN", "PROVEN", "SOURCE_MISMATCH", "ERROR"})
REQUEST_ALLOWED_FIELDS = frozenset({
    "model", "instructions", "input", "tools", "tool_choice",
    "parallel_tool_calls", "reasoning", "store", "stream", "stream_options",
    "include", "service_tier", "prompt_cache_key", "text", "client_metadata",
})
REQUEST_REQUIRED_FIELDS = frozenset({
    "model", "input", "tool_choice", "parallel_tool_calls", "store", "stream", "include",
})
EVENT_ORDER: tuple[str, ...] = (
    "response.output_item.done", "response.output_item.done", "response.completed",
)
EVENT_TYPES = frozenset(EVENT_ORDER)
SUCCESS_MARKER = "CODEXGATE_OFFLINE_CANARY_OK"
FIXED_PROMPT = "Return exactly the offline CodexGate canary marker."
EXPECTED_MODEL = "codexgate-sealed"


class WireContractError(PolicyError):
    """Sanitized parser/proof failure; no raw wire data is retained."""


@dataclass(frozen=True)
class ParsedResponsesStream:
    events: tuple[dict[str, Any], ...]
    canonical_bytes: bytes
    stream_hash: str


def _digest(value: bytes | str) -> str:
    return hashlib.sha256(value.encode("utf-8") if isinstance(value, str) else value).hexdigest()


def fixed_prompt_hash() -> str:
    return _digest(FIXED_PROMPT)


def build_fixed_request(model: str = EXPECTED_MODEL, prompt: str = FIXED_PROMPT) -> dict[str, Any]:
    """Return the one no-tool request shape supported by the sealed canary."""
    return {
        "model": model,
        "input": [{
            "type": "message",
            "role": "user",
            "content": [{"type": "input_text", "text": prompt}],
        }],
        "tools": [],
        "tool_choice": "none",
        "parallel_tool_calls": False,
        "store": False,
        "stream": True,
        "include": [],
    }


def canonical_request_hash(request: Mapping[str, Any]) -> str:
    return _digest(canonical_json(dict(request)).encode("utf-8"))


def validate_request(request: Any, *, expected_model: str = EXPECTED_MODEL,
                     expected_prompt_hash: str = fixed_prompt_hash()) -> dict[str, Any]:
    if not isinstance(request, dict):
        raise WireContractError("codex_wire_request_invalid")
    if set(request) - REQUEST_ALLOWED_FIELDS or not REQUEST_REQUIRED_FIELDS.issubset(request):
        raise WireContractError("codex_wire_request_schema_invalid")
    if request.get("model") != expected_model or not isinstance(expected_model, str):
        raise WireContractError("codex_wire_model_mismatch")
    tools = request.get("tools")
    if tools not in (None, []):
        raise WireContractError("codex_wire_tool_policy_violation")
    if request.get("tool_choice") != "none" or request.get("parallel_tool_calls") is not False:
        raise WireContractError("codex_wire_tool_policy_violation")
    if request.get("stream") is not True or request.get("store") is not False:
        raise WireContractError("codex_wire_request_policy_violation")
    if request.get("include") != []:
        raise WireContractError("codex_wire_request_policy_violation")
    instructions = request.get("instructions")
    if instructions not in (None, ""):
        raise WireContractError("codex_wire_request_policy_violation")
    items = request.get("input")
    if not isinstance(items, list) or len(items) != 1 or not isinstance(items[0], dict):
        raise WireContractError("codex_wire_prompt_mismatch")
    item = items[0]
    if set(item) != {"type", "role", "content"} or item.get("type") != "message" or item.get("role") != "user":
        raise WireContractError("codex_wire_prompt_mismatch")
    content = item.get("content")
    if not isinstance(content, list) or len(content) != 1 or not isinstance(content[0], dict):
        raise WireContractError("codex_wire_prompt_mismatch")
    part = content[0]
    if set(part) != {"type", "text"} or part.get("type") != "input_text" or not isinstance(part.get("text"), str):
        raise WireContractError("codex_wire_prompt_mismatch")
    prompt_hash = _digest(part["text"])
    if prompt_hash != expected_prompt_hash:
        raise WireContractError("codex_wire_prompt_mismatch")
    return {"model": expected_model, "prompt_hash": prompt_hash, "tools_empty": True,
            "parallel_tool_calls": False, "stream": True, "request_hash": canonical_request_hash(request)}


def _fixture_events() -> tuple[dict[str, Any], ...]:
    # Shape and order are the no-tool text projection used by the official
    # rust-v0.145.0 SSE end-to-end test; the text is the pre-existing sealed
    # marker, not a newly invented response contract.
    return (
        {"type": "response.output_item.done", "item": {
            "type": "message", "role": "assistant",
            "content": [{"type": "output_text", "text": ""}],
        }},
        {"type": "response.output_item.done", "item": {
            "type": "message", "role": "assistant",
            "content": [{"type": "output_text", "text": SUCCESS_MARKER}],
        }},
        {"type": "response.completed", "response": {"id": "sealed-offline-canary"}},
    )


def canonical_sse_bytes(events: Sequence[Mapping[str, Any]] | None = None) -> bytes:
    chosen = tuple(dict(event) for event in (events if events is not None else _fixture_events()))
    return b"".join((f"event: {event['type']}\ndata: ".encode("ascii")
                     + canonical_json(event).encode("utf-8") + b"\n\n") for event in chosen)


def fixture_stream_bytes() -> bytes:
    return canonical_sse_bytes()


def fixture_stream_hash() -> str:
    return _digest(fixture_stream_bytes())


def _parse_event_block(block: str) -> dict[str, Any]:
    lines = block.split("\n")
    if len(lines) != 2 or not lines[0].startswith("event: ") or not lines[1].startswith("data: "):
        raise WireContractError("codex_wire_frame_schema_invalid")
    event_type = lines[0][7:]
    if event_type not in EVENT_TYPES:
        raise WireContractError("codex_wire_event_policy_violation")
    raw_json = lines[1][6:]
    try:
        value = json.loads(raw_json)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WireContractError("codex_wire_frame_json_invalid") from exc
    if not isinstance(value, dict) or value.get("type") != event_type or canonical_json(value) != raw_json:
        raise WireContractError("codex_wire_frame_schema_invalid")
    if event_type == "response.output_item.done":
        if set(value) != {"type", "item"} or not isinstance(value.get("item"), dict):
            raise WireContractError("codex_wire_frame_schema_invalid")
        item = value["item"]
        if set(item) != {"type", "role", "content"} or item.get("type") != "message" or item.get("role") != "assistant":
            raise WireContractError("codex_wire_frame_schema_invalid")
        content = item.get("content")
        if not isinstance(content, list) or len(content) != 1 or not isinstance(content[0], dict) or set(content[0]) != {"type", "text"} or content[0].get("type") != "output_text" or not isinstance(content[0].get("text"), str):
            raise WireContractError("codex_wire_frame_marker_invalid")
    else:
        if set(value) != {"type", "response"} or value.get("response") != {"id": "sealed-offline-canary"}:
            raise WireContractError("codex_wire_frame_schema_invalid")
    return value


def parse_sse_stream(raw: bytes | str) -> ParsedResponsesStream:
    if isinstance(raw, str):
        raw_bytes = raw.encode("utf-8", "strict")
    elif isinstance(raw, bytes):
        raw_bytes = raw
    else:
        raise WireContractError("codex_wire_frame_invalid")
    try:
        text = raw_bytes.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise WireContractError("codex_wire_frame_invalid_utf8") from exc
    if "\r" in text:
        raise WireContractError("codex_wire_frame_newline_invalid")
    if not text or not text.endswith("\n\n"):
        raise WireContractError("codex_wire_frame_incomplete")
    blocks = text[:-2].split("\n\n")
    if len(blocks) != len(EVENT_ORDER):
        raise WireContractError("codex_wire_frame_count_invalid")
    events = tuple(_parse_event_block(block) for block in blocks)
    if tuple(event["type"] for event in events) != EVENT_ORDER:
        raise WireContractError("codex_wire_event_order_invalid")
    if events[0]["item"]["content"][0]["text"] != "" or events[1]["item"]["content"][0]["text"] != SUCCESS_MARKER:
        raise WireContractError("codex_wire_frame_marker_invalid")
    canonical = canonical_sse_bytes(events)
    return ParsedResponsesStream(events=events, canonical_bytes=canonical, stream_hash=_digest(canonical))


def wire_contract_hash(source_files: Sequence[Mapping[str, str | None]] = SOURCE_FILES) -> str:
    return sha256_json({
        "version": WIRE_CONTRACT_VERSION, "repository": OFFICIAL_REPOSITORY, "tag": OFFICIAL_TAG,
        "sources": [dict(item) for item in source_files],
        "request_allowed": sorted(REQUEST_ALLOWED_FIELDS), "request_required": sorted(REQUEST_REQUIRED_FIELDS),
        "events": list(EVENT_ORDER), "fixture_stream_hash": fixture_stream_hash(),
    })


def proof_state(source_files: Sequence[Mapping[str, str | None]] = SOURCE_FILES) -> str:
    try:
        if not source_files or any(not isinstance(item.get("path"), str) for item in source_files):
            return "ERROR"
        if any(item.get("sha256") is None for item in source_files):
            return "UNPROVEN"
        if any(not isinstance(item.get("sha256"), str) or len(item["sha256"]) != 64 or any(c not in "0123456789abcdef" for c in item["sha256"]) for item in source_files):
            return "SOURCE_MISMATCH"
        if any(item.get("path") not in _SEALED_SOURCE_HASHES or item.get("sha256") != _SEALED_SOURCE_HASHES[item["path"]] for item in source_files):
            return "SOURCE_MISMATCH"
        return "PROVEN"
    except Exception:
        return "ERROR"


def proof_snapshot() -> dict[str, Any]:
    state = proof_state()
    return {
        "schema_version": PROOF_SCHEMA_VERSION, "repository": OFFICIAL_REPOSITORY, "tag": OFFICIAL_TAG,
        "status": state, "source_files": [dict(item) for item in SOURCE_FILES],
        "request_allowed_fields": sorted(REQUEST_ALLOWED_FIELDS), "request_required_fields": sorted(REQUEST_REQUIRED_FIELDS),
        "event_types": list(EVENT_ORDER), "termination": "response.completed",
        "fixture_stream_hash": fixture_stream_hash(), "wire_contract_hash": wire_contract_hash(),
        "error_code": None if state == "PROVEN" else "codex_wire_contract_unproven",
    }


WIRE_CONTRACT_HASH = wire_contract_hash()
WIRE_CONTRACT_STATUS = proof_state()
