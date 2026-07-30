import hashlib
import json

import pytest

from app.codex_wire_contract import (
    EVENT_ORDER,
    FIXED_PROMPT,
    OFFICIAL_TAG,
    PROOF_STATES,
    SOURCE_FILES,
    WireContractError,
    build_fixed_request,
    canonical_sse_bytes,
    fixture_stream_bytes,
    fixture_stream_hash,
    parse_sse_stream,
    proof_snapshot,
    proof_state,
    validate_request,
    wire_contract_hash,
)


def test_official_tag_and_sanitized_source_manifest_are_fail_closed():
    assert OFFICIAL_TAG == "rust-v0.145.0"
    assert {item["path"] for item in SOURCE_FILES} == {
        "codex-rs/codex-api/src/common.rs",
        "codex-rs/codex-api/src/endpoint/responses.rs",
        "codex-rs/codex-api/tests/sse_end_to_end.rs",
    }
    assert proof_state() == "PROVEN"
    assert proof_snapshot()["status"] in PROOF_STATES


def test_request_generator_matches_strict_no_tool_contract():
    request = build_fixed_request()
    validated = validate_request(request)
    assert request["model"] == "codexgate-sealed"
    assert request["stream"] is True and request["tools"] == []
    assert request["parallel_tool_calls"] is False
    assert validated["prompt_hash"] == hashlib.sha256(FIXED_PROMPT.encode()).hexdigest()


@pytest.mark.parametrize("mutator", [
    lambda value: value.pop("model"),
    lambda value: value.update({"unknown": 1}),
    lambda value: value.update({"tools": [{"type": "function"}]}),
    lambda value: value.update({"parallel_tool_calls": True}),
    lambda value: value.update({"stream": False}),
    lambda value: value["input"][0]["content"][0].update({"text": "different"}),
])
def test_request_mismatch_is_rejected(mutator):
    request = build_fixed_request()
    mutator(request)
    with pytest.raises(WireContractError):
        validate_request(request)


def test_official_no_tool_event_order_and_deterministic_hash():
    parsed = parse_sse_stream(fixture_stream_bytes())
    assert tuple(event["type"] for event in parsed.events) == EVENT_ORDER
    assert parsed.stream_hash == fixture_stream_hash()
    assert parse_sse_stream(fixture_stream_bytes()).stream_hash == parsed.stream_hash


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
