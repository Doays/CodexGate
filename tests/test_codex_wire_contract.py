import hashlib
import json

import pytest

from app.codex_wire_contract import (
    EVENT_ORDER,
    FIXED_PROMPT,
    FULL_TURN_EVENT_ORDER,
    FULL_TURN_FIXTURE_VERSION,
    OFFICIAL_TAG,
    PINNED_RESPONSES_TOP_LEVEL_KEYS_V0145,
    PINNED_REQUEST_KEY_DIFF_V0145_SORTED,
    PINNED_INCLUDE_CONTRACT_V0145,
    PINNED_INPUT_SCHEMA_V0145,
    INPUT_SHAPE_FIELDS,
    SEALED_REQUEST_TOP_LEVEL_KEYS,
    PROOF_STATES,
    RESPONSES_PARSER_EVENT_ORDER,
    RESPONSES_PARSER_FIXTURE_VERSION,
    SOURCE_FILES,
    SUCCESS_MARKER,
    WireContractError,
    build_fixed_request,
    canonical_sse_bytes,
    full_turn_fixture_bytes,
    full_turn_fixture_hash,
    fixture_stream_bytes,
    fixture_stream_hash,
    parse_full_turn_sse_stream,
    parse_sse_stream,
    proof_snapshot,
    proof_state,
    responses_parser_fixture_bytes,
    responses_parser_fixture_hash,
    validate_request,
    inspect_first_turn_input,
    wire_contract_hash,
)


def test_official_tag_and_sanitized_source_manifest_are_fail_closed():
    assert OFFICIAL_TAG == "rust-v0.145.0"
    assert {item["path"] for item in SOURCE_FILES} == {
        "codex-rs/codex-api/src/common.rs",
        "codex-rs/codex-api/src/endpoint/responses.rs",
        "codex-rs/codex-api/tests/sse_end_to_end.rs",
    }
    assert proof_state() == "PARSER_PROVEN"
    assert proof_snapshot()["status"] in PROOF_STATES
    assert proof_snapshot()["parser_fixture_version"] == RESPONSES_PARSER_FIXTURE_VERSION
    assert proof_snapshot()["full_turn_fixture_version"] == FULL_TURN_FIXTURE_VERSION


def test_request_generator_matches_strict_no_tool_contract():
    request = build_fixed_request()
    validated = validate_request(request)
    assert request["model"] == "codexgate-sealed"
    assert request["stream"] is True and request["tools"] == []
    assert request["parallel_tool_calls"] is False
    assert request["include"] == list(PINNED_INCLUDE_CONTRACT_V0145)
    assert validated["prompt_hash"] == hashlib.sha256(FIXED_PROMPT.encode()).hexdigest()
    assert set(validated["input_shape"]) == set(INPUT_SHAPE_FIELDS)


def test_pinned_first_turn_input_shape_is_shape_only_and_deterministic():
    request = build_fixed_request()
    shape, reason = inspect_first_turn_input(request["input"])
    assert reason is None
    assert shape["item_count"] == 3
    assert shape["item_type_ids"] == ["message", "message", "message"]
    assert shape["role_ids"] == ["developer", "user", "user"]
    assert shape["content_type_ids"] == ["input_text", "input_text", "input_text"]
    assert shape["content_counts"] == [1, 1, 1]
    assert shape["text_byte_counts"][-1] == len(FIXED_PROMPT.encode())
    assert shape["text_sha256s"][-1] == hashlib.sha256(FIXED_PROMPT.encode()).hexdigest()
    assert shape["shape_hash"] == inspect_first_turn_input(request["input"])[0]["shape_hash"]
    assert PINNED_INPUT_SCHEMA_V0145["item_type_ids"] == ("message",)


@pytest.mark.parametrize(("mutator", "reason"), [
    (lambda value: value.clear(), "input_count"),
    (lambda value: value.__setitem__(0, {"type": "unknown", "role": "user", "content": []}), "input_item_type"),
    (lambda value: value.__setitem__(0, {"type": "message", "role": "assistant", "content": []}), "input_role"),
    (lambda value: value.__setitem__(0, {"type": "message", "role": "developer", "content": [{"type": "input_image", "url": "redacted"}]}), "input_content_type"),
    (lambda value: value.__setitem__(2, {"type": "message", "role": "user", "content": [{"type": "input_text", "text": ""}]}), "input_text"),
    (lambda value: value.__setitem__(2, {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "different"}]}), "input_prompt_hash"),
])
def test_first_turn_shape_rejects_variant_role_content_and_prompt_without_raw_values(mutator, reason):
    request = build_fixed_request()
    value = request["input"]
    mutator(value)
    shape, actual = inspect_first_turn_input(value)
    assert actual == reason
    assert set(shape) == set(INPUT_SHAPE_FIELDS)
    assert "different" not in json.dumps(shape)
    assert "url" not in json.dumps(shape)


def test_v0145_pinned_top_level_keys_and_static_sealed_diff_are_exact():
    assert PINNED_RESPONSES_TOP_LEVEL_KEYS_V0145 == {
        "model", "instructions", "input", "tools", "tool_choice",
        "parallel_tool_calls", "reasoning", "store", "stream", "stream_options",
        "include", "service_tier", "prompt_cache_key", "text", "client_metadata",
    }
    assert SEALED_REQUEST_TOP_LEVEL_KEYS == {
        "model", "input", "tools", "tool_choice", "parallel_tool_calls",
        "store", "stream", "include",
    }
    assert PINNED_REQUEST_KEY_DIFF_V0145_SORTED == (
        "client_metadata", "instructions", "prompt_cache_key", "reasoning",
        "service_tier", "stream_options", "text",
    )


@pytest.mark.parametrize("field,value", [
    ("instructions", "sealed instructions"),
    ("reasoning", {}),
    ("service_tier", "default"),
    ("prompt_cache_key", "sealed-session"),
    ("text", {"verbosity": "low"}),
    ("stream_options", {"reasoning_summary_delivery": "sequential_cutoff"}),
    ("client_metadata", {"sealed": "metadata"}),
])
def test_all_official_optional_fields_validate_when_present(field, value):
    request = build_fixed_request()
    request[field] = value
    assert validate_request(request)["request_hash"]


@pytest.mark.parametrize("value", [
    {"reasoning_summary_delivery": "parallel"},
    {"reasoning_summary_delivery": "sequential_cutoff", "extra": 1},
    {"extra": "sequential_cutoff"},
])
def test_stream_options_nested_contract_is_strict(value):
    request = build_fixed_request()
    request["stream_options"] = value
    with pytest.raises(WireContractError):
        validate_request(request)


def test_client_metadata_is_string_map_and_raw_values_are_not_part_of_validation_result():
    request = build_fixed_request()
    request["client_metadata"] = {"sealed-key": "sealed-value"}
    validated = validate_request(request)
    assert validated["client_metadata_hash"]
    assert "sealed-key" not in str(validated)
    assert "sealed-value" not in str(validated)
    request["client_metadata"] = {"sealed-key": 1}
    with pytest.raises(WireContractError):
        validate_request(request)


@pytest.mark.parametrize("include", [
    [],
    ["reasoning.encrypted_content", "reasoning.encrypted_content"],
    ["reasoning.summary"],
    [None],
    [1],
])
def test_include_contract_rejects_empty_duplicate_unknown_wrong_type(include):
    request = build_fixed_request()
    request["include"] = include
    with pytest.raises(WireContractError):
        validate_request(request)


def test_include_contract_is_ordered_and_generated_relay_uses_same_sequence():
    request = build_fixed_request()
    request["include"] = list(reversed(PINNED_INCLUDE_CONTRACT_V0145))
    if len(PINNED_INCLUDE_CONTRACT_V0145) > 1:
        with pytest.raises(WireContractError):
            validate_request(request)
    from app.codex_process_executor_wsl import RELAY_CODEX_CHILD_CODE
    assert b"INCLUDE_SEQUENCE" in RELAY_CODEX_CHILD_CODE
    assert PINNED_INCLUDE_CONTRACT_V0145 == ("reasoning.encrypted_content",)


@pytest.mark.parametrize("mutator", [
    lambda value: value.pop("model"),
    lambda value: value.update({"unknown": 1}),
    lambda value: value.update({"tools": [{"type": "function"}]}),
    lambda value: value.update({"parallel_tool_calls": True}),
    lambda value: value.update({"stream": False}),
    lambda value: value["input"][2]["content"][0].update({"text": "different"}),
])
def test_request_mismatch_is_rejected(mutator):
    request = build_fixed_request()
    mutator(request)
    with pytest.raises(WireContractError):
        validate_request(request)


def test_official_no_tool_event_order_and_deterministic_hash():
    parsed = parse_sse_stream(responses_parser_fixture_bytes())
    assert tuple(event["type"] for event in parsed.events) == RESPONSES_PARSER_EVENT_ORDER == EVENT_ORDER
    assert parsed.stream_hash == responses_parser_fixture_hash() == fixture_stream_hash()
    assert fixture_stream_bytes() == responses_parser_fixture_bytes()
    assert parse_sse_stream(responses_parser_fixture_bytes()).stream_hash == parsed.stream_hash


def test_full_turn_fixture_is_separate_single_message_completion_contract():
    raw = full_turn_fixture_bytes()
    parsed = parse_full_turn_sse_stream(raw)
    assert tuple(event["type"] for event in parsed.events) == FULL_TURN_EVENT_ORDER
    assert parsed.stream_hash == full_turn_fixture_hash()
    assert parsed.stream_hash != responses_parser_fixture_hash()
    assert len(parsed.events) == 2
    assert parsed.events[0] == {
        "type": "response.output_item.done",
        "item": {
            "type": "message", "role": "assistant",
            "content": [{"type": "output_text", "text": SUCCESS_MARKER}],
        },
    }
    assert parsed.events[1] == {
        "type": "response.completed",
        "response": {"id": "sealed-offline-canary", "end_turn": True},
    }
    assert raw.count(SUCCESS_MARKER.encode("utf-8")) == 1
    assert b'"text":""' not in raw


@pytest.mark.parametrize("raw", [
    full_turn_fixture_bytes().replace(SUCCESS_MARKER.encode(), b""),
    full_turn_fixture_bytes().replace(b'"end_turn":true', b'"end_turn":false'),
    responses_parser_fixture_bytes(),
])
def test_full_turn_fixture_rejects_empty_second_or_nonterminal_shapes(raw):
    with pytest.raises(WireContractError):
        parse_full_turn_sse_stream(raw)


@pytest.mark.parametrize("raw", [
    fixture_stream_bytes().replace(b"response.completed", b"response.output_item.done", 1),
    fixture_stream_bytes().replace(b"\n\n", b"\n\nevent: response.completed\ndata: {\"response\":{\"id\":\"sealed-offline-canary\"},\"type\":\"response.completed\"}\n\n", 1),
    fixture_stream_bytes().replace(b'"response":{"id":"sealed-offline-canary"}', b'"response":{"id":"sealed-offline-canary","extra":1}'),
    b"event: response.failed\ndata: {\"type\":\"response.failed\"}\n\n",
])
def test_missing_duplicate_extra_or_failed_events_are_rejected(raw):
    with pytest.raises(WireContractError):
        parse_sse_stream(raw)


def test_completed_is_required_and_crlf_is_not_a_different_contract():
    incomplete = fixture_stream_bytes().split(b"\n\nevent: response.completed", 1)[0] + b"\n\n"
    with pytest.raises(WireContractError):
        parse_sse_stream(incomplete)
    with pytest.raises(WireContractError):
        parse_sse_stream(fixture_stream_bytes().replace(b"\n", b"\r\n"))


def test_wire_hash_is_stable_and_source_change_changes_it():
    assert wire_contract_hash() == wire_contract_hash()
    changed = tuple({**item, "sha256": "a" * 64} for item in SOURCE_FILES)
    from app.codex_wire_contract import proof_state, wire_contract_hash as calc
    assert calc(changed) != calc(SOURCE_FILES)
    assert proof_state(changed) == "SOURCE_MISMATCH"
