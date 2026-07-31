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

PROOF_STATES = frozenset({"UNPROVEN", "PARSER_PROVEN", "SOURCE_MISMATCH", "ERROR"})
# This is the exact top-level serde shape of ResponsesApiRequest in the
# rust-v0.145.0 tag.  Optional fields are still part of the sealed contract;
# their absence is valid, while names outside this set are never accepted.
PINNED_RESPONSES_TOP_LEVEL_KEYS_V0145 = frozenset({
    "model", "instructions", "input", "tools", "tool_choice",
    "parallel_tool_calls", "reasoning", "store", "stream", "stream_options",
    "include", "service_tier", "prompt_cache_key", "text", "client_metadata",
})
# In the tagged request builder this vector is constructed unconditionally
# (after model/config branching) with this one enum identifier and in this
# order.  It is therefore not an open-ended include vocabulary.
PINNED_INCLUDE_CONTRACT_V0145: tuple[str, ...] = ("reasoning.encrypted_content",)
# Compatibility name retained for existing callers.  There is deliberately no
# second allowlist: both names point at the same immutable source set.
REQUEST_ALLOWED_FIELDS = PINNED_RESPONSES_TOP_LEVEL_KEYS_V0145
REQUEST_REQUIRED_FIELDS = frozenset({
    "model", "input", "tool_choice", "parallel_tool_calls", "store", "stream", "include",
})
RESPONSES_PARSER_FIXTURE_VERSION = "RESPONSES_PARSER_FIXTURE_V1"
FULL_TURN_FIXTURE_VERSION = "FULL_TURN_FIXTURE_V1"
RESPONSES_PARSER_EVENT_ORDER: tuple[str, ...] = (
    "response.output_item.done", "response.output_item.done", "response.completed",
)
FULL_TURN_EVENT_ORDER: tuple[str, ...] = (
    "response.output_item.done", "response.completed",
)
# Compatibility name for callers that explicitly exercise the source-derived
# low-level parser fixture.  Production relay code must use the full-turn name.
EVENT_ORDER = RESPONSES_PARSER_EVENT_ORDER
EVENT_TYPES = frozenset(RESPONSES_PARSER_EVENT_ORDER + FULL_TURN_EVENT_ORDER)
SUCCESS_MARKER = "CODEXGATE_OFFLINE_CANARY_OK"
FIXED_PROMPT = "Return exactly the offline CodexGate canary marker."
EXPECTED_MODEL = "codexgate-sealed"

# The first-turn input contract is intentionally shape-only.  It records no
# prompt text or metadata values; those are checked by digest and discarded.
# The enum IDs below are the ResponseInputItem/ContentItem variants used by the
# sealed text-only profile.  Optional keys mirror the serde-optional fields in
# rust-v0.145.0, but are only accepted when their scalar shape is valid.
PINNED_INPUT_SCHEMA_V0145 = {
    # The first Responses turn is not just the user line.  Session startup
    # records one aggregated developer context item and one contextual-user
    # item before the user message (see the v0.145.0 context-manager builder).
    "item_count": 3,
    "item_type_ids": ("message",),
    "item_required_fields": ("type", "role", "content"),
    "item_optional_fields": ("id", "phase", "internal_chat_message_metadata_passthrough"),
    "role_sequence": ("developer", "user", "user"),
    "role_ids": ("developer", "user"),
    "content_type_ids": ("input_text",),
    "content_required_fields": ("type", "text"),
    "phase_ids": ("commentary", "final_answer"),
    "max_content_items": 16,
    "max_text_bytes": 64 * 1024,
}
INPUT_REJECT_REASONS = frozenset({
    "input_not_array", "input_count", "input_item_type", "input_item_schema",
    "input_role", "input_content_type", "input_text", "input_prompt_hash",
})
INPUT_SHAPE_FIELDS = frozenset({
    "item_count", "item_type_ids", "item_key_presence_masks", "role_ids",
    "content_type_ids", "content_counts", "text_byte_counts", "text_sha256s",
    "shape_hash",
})
_INPUT_ITEM_FIELD_BITS = {name: 1 << index for index, name in enumerate(
    PINNED_INPUT_SCHEMA_V0145["item_required_fields"] + PINNED_INPUT_SCHEMA_V0145["item_optional_fields"]
)}
_INPUT_CONTENT_FIELD_BITS = {name: 1 << index for index, name in enumerate(
    PINNED_INPUT_SCHEMA_V0145["content_required_fields"]
)}


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
        "input": [
            {"type": "message", "role": "developer",
             "content": [{"type": "input_text", "text": "sealed developer context"}]},
            {"type": "message", "role": "user",
             "content": [{"type": "input_text", "text": "sealed contextual user context"}]},
            {"type": "message", "role": "user",
             "content": [{"type": "input_text", "text": prompt}]},
        ],
        "tools": [],
        "tool_choice": "none",
        "parallel_tool_calls": False,
        "store": False,
        "stream": True,
        "include": list(PINNED_INCLUDE_CONTRACT_V0145),
    }


SEALED_REQUEST_TOP_LEVEL_KEYS = frozenset(build_fixed_request())
PINNED_REQUEST_KEY_DIFF_V0145 = frozenset(
    PINNED_RESPONSES_TOP_LEVEL_KEYS_V0145 - SEALED_REQUEST_TOP_LEVEL_KEYS
)
PINNED_REQUEST_KEY_DIFF_V0145_SORTED: tuple[str, ...] = tuple(sorted(PINNED_REQUEST_KEY_DIFF_V0145))


def _validate_optional_responses_fields(request: Mapping[str, Any]) -> str | None:
    """Validate only the official optional fields, returning a redacted reason."""
    instructions = request.get("instructions")
    if instructions is not None and not isinstance(instructions, str):
        return "instructions"
    for field in ("service_tier", "prompt_cache_key"):
        value = request.get(field)
        if value is not None and not isinstance(value, str):
            return field
    reasoning = request.get("reasoning")
    if reasoning is not None:
        if not isinstance(reasoning, dict) or not set(reasoning).issubset({"effort", "summary", "context"}):
            return "reasoning"
        if any(not isinstance(value, str) for value in reasoning.values() if value is not None):
            return "reasoning"
    stream_options = request.get("stream_options")
    if stream_options is not None:
        if (not isinstance(stream_options, dict)
                or set(stream_options) != {"reasoning_summary_delivery"}
                or stream_options.get("reasoning_summary_delivery") != "sequential_cutoff"):
            return "stream_options"
    text = request.get("text")
    if text is not None:
        if not isinstance(text, dict) or not set(text).issubset({"verbosity", "format"}):
            return "text"
        if "verbosity" in text and text["verbosity"] not in {"low", "medium", "high"}:
            return "text"
    client_metadata = request.get("client_metadata")
    if client_metadata is not None:
        if (not isinstance(client_metadata, dict)
                or any(not isinstance(key, str) or not isinstance(value, str)
                       for key, value in client_metadata.items())):
            return "client_metadata"
    return None


def canonical_request_hash(request: Mapping[str, Any]) -> str:
    return _digest(canonical_json(dict(request)).encode("utf-8"))


def _input_shape_digest(shape: Mapping[str, Any]) -> str:
    return _digest(canonical_json(dict(shape)).encode("utf-8"))


def inspect_first_turn_input(value: Any, *, expected_prompt_hash: str = fixed_prompt_hash()) -> tuple[dict[str, Any], str | None]:
    """Return shape-only evidence and the first deterministic input reason.

    No raw text, item IDs, metadata, or unknown field names leave this
    function.  Unknown variants are represented only by the enum sentinel
    ``unknown`` and by the resulting shape digest.
    """
    shape: dict[str, Any] = {
        "item_count": len(value) if isinstance(value, list) else 0,
        "item_type_ids": [], "item_key_presence_masks": [], "role_ids": [],
        "content_type_ids": [], "content_counts": [], "text_byte_counts": [],
        "text_sha256s": [], "shape_hash": "",
    }
    def finish(reason: str | None) -> tuple[dict[str, Any], str | None]:
        shape["shape_hash"] = _input_shape_digest({key: shape[key] for key in sorted(shape) if key != "shape_hash"})
        return shape, reason

    if not isinstance(value, list):
        return finish("input_not_array")
    if len(value) != PINNED_INPUT_SCHEMA_V0145["item_count"]:
        return finish("input_count")
    allowed_item = set(PINNED_INPUT_SCHEMA_V0145["item_required_fields"]) | set(PINNED_INPUT_SCHEMA_V0145["item_optional_fields"])
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            return finish("input_item_schema")
        item_type = item.get("type")
        shape["item_type_ids"].append(item_type if item_type in PINNED_INPUT_SCHEMA_V0145["item_type_ids"] else "unknown")
        item_mask = sum(_INPUT_ITEM_FIELD_BITS[name] for name in item if name in _INPUT_ITEM_FIELD_BITS)
        shape["item_key_presence_masks"].append(item_mask)
        if item_type not in PINNED_INPUT_SCHEMA_V0145["item_type_ids"]:
            return finish("input_item_type")
        if set(item) - allowed_item or any(field not in item for field in PINNED_INPUT_SCHEMA_V0145["item_required_fields"]):
            return finish("input_item_schema")
        role = item.get("role")
        shape["role_ids"].append(role if role in PINNED_INPUT_SCHEMA_V0145["role_ids"] else "unknown")
        if role != PINNED_INPUT_SCHEMA_V0145["role_sequence"][index]:
            return finish("input_role")
        if "id" in item and not isinstance(item["id"], str):
            return finish("input_item_schema")
        if "phase" in item and item["phase"] not in PINNED_INPUT_SCHEMA_V0145["phase_ids"]:
            return finish("input_item_schema")
        if "internal_chat_message_metadata_passthrough" in item:
            metadata = item["internal_chat_message_metadata_passthrough"]
            if not isinstance(metadata, dict) or set(metadata) - {"turn_id"} or (
                "turn_id" in metadata and not isinstance(metadata["turn_id"], str)
            ):
                return finish("input_item_schema")
        content = item.get("content")
        if not isinstance(content, list) or not content or len(content) > PINNED_INPUT_SCHEMA_V0145["max_content_items"]:
            return finish("input_content_type")
        shape["content_counts"].append(len(content))
        for part in content:
            if not isinstance(part, dict):
                return finish("input_content_type")
            content_type = part.get("type")
            shape["content_type_ids"].append(content_type if content_type in PINNED_INPUT_SCHEMA_V0145["content_type_ids"] else "unknown")
            if content_type not in PINNED_INPUT_SCHEMA_V0145["content_type_ids"]:
                return finish("input_content_type")
            if set(part) != set(PINNED_INPUT_SCHEMA_V0145["content_required_fields"]):
                return finish("input_item_schema")
            text = part.get("text")
            if not isinstance(text, str):
                return finish("input_text")
            try:
                text_bytes = text.encode("utf-8", "strict")
            except UnicodeEncodeError:
                return finish("input_text")
            shape["text_byte_counts"].append(len(text_bytes))
            shape["text_sha256s"].append(_digest(text_bytes))
            if not text_bytes or len(text_bytes) > PINNED_INPUT_SCHEMA_V0145["max_text_bytes"]:
                return finish("input_text")
    # The final user content is the only profile-controlled prompt.  Context
    # items are source-generated and are checked for shape, not text equality.
    if shape["text_sha256s"][-1] != expected_prompt_hash:
        return finish("input_prompt_hash")
    return finish(None)


def validate_request(request: Any, *, expected_model: str = EXPECTED_MODEL,
                     expected_prompt_hash: str = fixed_prompt_hash()) -> dict[str, Any]:
    if not isinstance(request, dict):
        raise WireContractError("codex_wire_request_invalid")
    if set(request) - PINNED_RESPONSES_TOP_LEVEL_KEYS_V0145 or not REQUEST_REQUIRED_FIELDS.issubset(request):
        raise WireContractError("codex_wire_request_schema_invalid")
    optional_error = _validate_optional_responses_fields(request)
    if optional_error is not None:
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
    include = request.get("include")
    if (not isinstance(include, list)
            or any(not isinstance(value, str) for value in include)
            or len(include) != len(set(include))
            or include != list(PINNED_INCLUDE_CONTRACT_V0145)):
        raise WireContractError("codex_wire_request_policy_violation")
    input_shape, input_reason = inspect_first_turn_input(request.get("input"), expected_prompt_hash=expected_prompt_hash)
    if input_reason is not None:
        raise WireContractError(input_reason)
    prompt_hash = input_shape["text_sha256s"][-1]
    return {"model": expected_model, "prompt_hash": prompt_hash, "tools_empty": True,
        "parallel_tool_calls": False, "stream": True,
        "request_hash": canonical_request_hash(request),
        "input_shape": input_shape,
        "client_metadata_hash": _digest(canonical_json(request["client_metadata"]).encode("utf-8"))
        if isinstance(request.get("client_metadata"), dict) else None,
    }


def _responses_parser_fixture_events() -> tuple[dict[str, Any], ...]:
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


def _full_turn_fixture_events() -> tuple[dict[str, Any], ...]:
    """Return the sealed two-event response consumed as one complete turn."""
    return (
        {"type": "response.output_item.done", "item": {
            "type": "message", "role": "assistant",
            "content": [{"type": "output_text", "text": SUCCESS_MARKER}],
        }},
        {"type": "response.completed", "response": {
            "id": "sealed-offline-canary", "end_turn": True,
        }},
    )


def canonical_sse_bytes(events: Sequence[Mapping[str, Any]] | None = None) -> bytes:
    chosen = tuple(dict(event) for event in (
        events if events is not None else _responses_parser_fixture_events()
    ))
    return b"".join((f"event: {event['type']}\ndata: ".encode("ascii")
                     + canonical_json(event).encode("utf-8") + b"\n\n") for event in chosen)


def responses_parser_fixture_bytes() -> bytes:
    return canonical_sse_bytes(_responses_parser_fixture_events())


def responses_parser_fixture_hash() -> str:
    return _digest(responses_parser_fixture_bytes())


def full_turn_fixture_bytes() -> bytes:
    return canonical_sse_bytes(_full_turn_fixture_events())


def full_turn_fixture_hash() -> str:
    return _digest(full_turn_fixture_bytes())


# Backward-compatible parser-proof aliases.  Keeping these names prevents old
# read-only proof readers from silently changing meaning; production imports
# the explicit full-turn functions below instead.
def fixture_stream_bytes() -> bytes:
    return responses_parser_fixture_bytes()


def fixture_stream_hash() -> str:
    return responses_parser_fixture_hash()


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
    return value


def _parse_fixture_stream(
    raw: bytes | str,
    *,
    expected_events: Sequence[Mapping[str, Any]],
    expected_order: tuple[str, ...],
) -> ParsedResponsesStream:
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
    if len(blocks) != len(expected_order):
        raise WireContractError("codex_wire_frame_count_invalid")
    events = tuple(_parse_event_block(block) for block in blocks)
    if tuple(event["type"] for event in events) != expected_order:
        raise WireContractError("codex_wire_event_order_invalid")
    expected = tuple(dict(event) for event in expected_events)
    if events != expected:
        observed_texts = [
            event.get("item", {}).get("content", [{}])[0].get("text")
            for event in events
            if event.get("type") == "response.output_item.done"
            and isinstance(event.get("item"), dict)
            and isinstance(event["item"].get("content"), list)
            and event["item"]["content"]
            and isinstance(event["item"]["content"][0], dict)
        ]
        expected_texts = [
            event["item"]["content"][0]["text"]
            for event in expected
            if event["type"] == "response.output_item.done"
        ]
        if observed_texts != expected_texts:
            raise WireContractError("codex_wire_frame_marker_invalid")
        raise WireContractError("codex_wire_frame_schema_invalid")
    canonical = canonical_sse_bytes(events)
    return ParsedResponsesStream(events=events, canonical_bytes=canonical, stream_hash=_digest(canonical))


def parse_sse_stream(raw: bytes | str) -> ParsedResponsesStream:
    """Parse only the source-derived three-event parser proof fixture."""
    return _parse_fixture_stream(
        raw,
        expected_events=_responses_parser_fixture_events(),
        expected_order=RESPONSES_PARSER_EVENT_ORDER,
    )


def parse_full_turn_sse_stream(raw: bytes | str) -> ParsedResponsesStream:
    """Parse the separately sealed two-event fixture used by the relay."""
    return _parse_fixture_stream(
        raw,
        expected_events=_full_turn_fixture_events(),
        expected_order=FULL_TURN_EVENT_ORDER,
    )


def wire_contract_hash(source_files: Sequence[Mapping[str, str | None]] = SOURCE_FILES) -> str:
    return sha256_json({
        "version": WIRE_CONTRACT_VERSION, "repository": OFFICIAL_REPOSITORY, "tag": OFFICIAL_TAG,
        "sources": [dict(item) for item in source_files],
        "request_allowed": sorted(PINNED_RESPONSES_TOP_LEVEL_KEYS_V0145),
        "request_required": sorted(REQUEST_REQUIRED_FIELDS),
        "sealed_request_fields": sorted(SEALED_REQUEST_TOP_LEVEL_KEYS),
        "pinned_request_key_diff": list(PINNED_REQUEST_KEY_DIFF_V0145_SORTED),
        "pinned_include_contract": list(PINNED_INCLUDE_CONTRACT_V0145),
        "parser_fixture": {
            "version": RESPONSES_PARSER_FIXTURE_VERSION,
            "events": list(RESPONSES_PARSER_EVENT_ORDER),
            "stream_hash": responses_parser_fixture_hash(),
        },
        "full_turn_fixture": {
            "version": FULL_TURN_FIXTURE_VERSION,
            "events": list(FULL_TURN_EVENT_ORDER),
            "stream_hash": full_turn_fixture_hash(),
        },
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
        return "PARSER_PROVEN"
    except Exception:
        return "ERROR"


def proof_snapshot() -> dict[str, Any]:
    state = proof_state()
    return {
        "schema_version": PROOF_SCHEMA_VERSION, "repository": OFFICIAL_REPOSITORY, "tag": OFFICIAL_TAG,
        "status": state, "source_files": [dict(item) for item in SOURCE_FILES],
        "request_allowed_fields": sorted(PINNED_RESPONSES_TOP_LEVEL_KEYS_V0145),
        "request_required_fields": sorted(REQUEST_REQUIRED_FIELDS),
        "sealed_request_fields": sorted(SEALED_REQUEST_TOP_LEVEL_KEYS),
        "pinned_request_key_diff": list(PINNED_REQUEST_KEY_DIFF_V0145_SORTED),
        "pinned_include_contract": list(PINNED_INCLUDE_CONTRACT_V0145),
        "parser_fixture_version": RESPONSES_PARSER_FIXTURE_VERSION,
        "parser_event_types": list(RESPONSES_PARSER_EVENT_ORDER),
        "parser_fixture_hash": responses_parser_fixture_hash(),
        "full_turn_fixture_version": FULL_TURN_FIXTURE_VERSION,
        "full_turn_event_types": list(FULL_TURN_EVENT_ORDER),
        "full_turn_fixture_hash": full_turn_fixture_hash(),
        "termination": "response.completed", "wire_contract_hash": wire_contract_hash(),
        "error_code": None if state == "PARSER_PROVEN" else "codex_wire_contract_unproven",
    }


WIRE_CONTRACT_HASH = wire_contract_hash()
WIRE_CONTRACT_STATUS = proof_state()
