"""Sealed WSL supervisor executor for the offline Codex process canary.

Construction performs no WSL, bubblewrap, Codex, socket, or network I/O.
The executor is intentionally created only after a persisted one-shot claim is
``RUNNING``.  Tests inject a no-I/O ``WSLCommandRunner``; the production
factory otherwise has no alternate or fake-executor path.
"""
from __future__ import annotations

import base64
import asyncio
import errno
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import uuid
import zlib
from dataclasses import dataclass
from math import isfinite
from typing import Any, Callable, Mapping, Sequence

from .egress_contract import (
    BROKER_REQUEST_PATH,
    CUSTOM_PROVIDER_ID,
    EPHEMERAL_TOKEN_ENV,
    LOOPBACK_HOST,
    LOOPBACK_PORT,
    SEALED_LOOPBACK_AUTHORITY,
    canonical_provider_toml,
    provider_config_hash,
    sanitize_broker_headers,
    validate_broker_request,
)
from .egress_harness_wsl import BWRAP_COMMON_ARGS, sealed_bwrap_environment_args
from .codex_wire_contract import (
    FIXED_PROMPT as WIRE_FIXED_PROMPT,
    SUCCESS_MARKER as WIRE_SUCCESS_MARKER,
    WIRE_CONTRACT_HASH,
    WIRE_CONTRACT_STATUS,
    build_fixed_request,
    canonical_request_hash,
    full_turn_fixture_bytes,
    full_turn_fixture_hash,
    fixed_prompt_hash,
    PINNED_RESPONSES_TOP_LEVEL_KEYS_V0145,
    PINNED_REQUEST_KEY_DIFF_V0145_SORTED,
    PINNED_INCLUDE_CONTRACT_V0145,
    PINNED_INPUT_SCHEMA_V0145,
    INPUT_REJECT_REASONS,
    INPUT_SHAPE_FIELDS,
    REQUEST_REQUIRED_FIELDS,
    _validate_optional_responses_fields,
    inspect_first_turn_input,
    responses_parser_fixture_hash,
    validate_request,
)
from .isolation_wsl import ProcessResult, separate_stream_byte_count
from .policy import PolicyError, canonical_json, sha256_json, validate_wsl_distro
from .wsl_codex_runtime import sealed_runtime_execution_policy, validate_wsl_codex_binary_path


EXECUTOR_POLICY_VERSION = "sealed-offline-codex-executor-v4"
SUPERVISOR_FRAME_PREFIX = "CODEXGATE_CODEX_SUPERVISOR_V1:"
SUPERVISOR_FRAME_SCHEMA_VERSION = "2"
SUPERVISOR_SCHEMA_VERSION = SUPERVISOR_FRAME_SCHEMA_VERSION
SUPERVISOR_BOOTSTRAP_PREFIX = "CODEXGATE_SUPERVISOR_BOOTSTRAP_V1:"
SUPERVISOR_BOOTSTRAP_SCHEMA_VERSION = "1"
SUPERVISOR_BOOTSTRAP_MAX_BYTES = 128 * 1024
WINDOWS_QUOTED_COMMAND_LINE_MAX_BYTES = 8 * 1024
SUPERVISOR_TIMEOUT_SECONDS = 45
SUPERVISOR_OUTPUT_LIMIT_BYTES = 16 * 1024
CODEX_ENDPOINT_DEADLINE_SECONDS = 45
CODEX_CONNECTION_WARNING_MILLISECONDS = 15_000
CODEX_LAST_MESSAGE_PATH = "/tmp/codexgate-final-message"
CODEX_LAST_MESSAGE_MAX_BYTES = 4 * 1024
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_BASE64URL = re.compile(r"^[A-Za-z0-9_-]+$")

SUPERVISOR_STAGES = frozenset({
    "BOOT", "CLAIM_VALIDATE", "SPEC_VALIDATE", "RUNTIME_VALIDATE", "BROKER_SPAWN",
    "BROKER_READY", "RELAY_CODEX_SPAWN", "RESPONSE_VALIDATE", "CLEANUP",
})
CODEX_CHILD_STAGES = frozenset({
    "SPEC_VALIDATE", "BINARY_VALIDATE", "ENV_VALIDATE", "SPAWN_CALL",
    "SPAWN_CONFIRMED", "STDIN_WRITE", "STDIN_CLOSE", "ENDPOINT_WAIT", "CHILD_EXIT",
})
RELAY_SPAWN_SUBSTAGES = frozenset({
    "RELAY_BOOT",
    "LOOPBACK_BIND",
    "LOOPBACK_LISTEN",
    "LOOPBACK_READY",
    "BROKER_SOCKET_CONNECT",
    "RUNTIME_BIND_VALIDATE",
    "WORK_FIXTURE_VALIDATE",
    "CODEX_HOME_PREPARE",
    "CONFIG_VALIDATE",
    "CODEX_BINARY_VALIDATE",
    "CODEX_ARGV_VALIDATE",
    "CODEX_SPAWN",
    "LOOPBACK_ACCEPT",
    "CHILD_START",
    "ENV_VALIDATE",
    "SOCKET_VALIDATE",
    "BROKER_CONNECT",
    "READY_EMIT",
})
SUPERVISOR_RELAY_SUBSTAGES = RELAY_SPAWN_SUBSTAGES | CODEX_CHILD_STAGES
BOOTSTRAP_SUBSTAGES = frozenset({
    "STDIN_READ", "PAYLOAD_DECODE", "PAYLOAD_SCHEMA", "CODE_HASH_VALIDATE",
    "SPEC_DECODE", "EXEC_PREPARE", "EXEC_CALL",
})
SUPERVISOR_FRAME_BASE_FIELDS = frozenset({
    "schema_version", "status", "stage", "substage", "error_code", "process_counts", "cleanup_ok", "implementation_hash",
})
SUPERVISOR_FRAME_PROOF_FIELDS = frozenset({
    "request_hash", "response_hash", "response_byte_count", "output_hash", "sensitive_headers_removed",
    "removed_count", "post_filter_count",
    "request_seen", "request_validated", "response_sent", "accepted_post",
    "codex_stdout_bytes", "codex_stdout_sha256", "codex_stdout_terminal_newline",
    "eof_stdout_drained", "eof_stderr_drained", "readers_joined", "usage",
    "child_schema_diagnostic",
    "connection_delay_ms", "connection_delay_warning", "stderr_byte_count", "stderr_sha256", "stderr_category",
    "prompt_mode", "config_loaded_expected", "argc",
    "event_types", "event_counts", "event_sequence_hash", "tool_event_count",
    "agent_message_count", "output_byte_count", "output_sha256",
    "last_message_exists", "last_message_regular", "last_message_size", "last_message_sha256",
    "last_message_match", "last_message_marker_match", "marker_match",
    "codex_exit_code", "strict_http_reject_reason", "request_header_count", "request_body_bytes",
    "request_body_sha256", "request_json_keyset_hash", "input_shape",
})
SUPERVISOR_FRAME_ERROR_FIELDS = SUPERVISOR_FRAME_BASE_FIELDS | SUPERVISOR_FRAME_PROOF_FIELDS
SUPERVISOR_FRAME_PASSED_FIELDS = SUPERVISOR_FRAME_BASE_FIELDS | SUPERVISOR_FRAME_PROOF_FIELDS
SUPERVISOR_FRAME_FIELDS = SUPERVISOR_FRAME_ERROR_FIELDS
SUPERVISOR_PROCESS_FIELDS = ("supervisor", "broker_bwrap", "relay_codex_bwrap", "codex_cli")
SUPERVISOR_BOOTSTRAP_FIELDS = frozenset({
    "schema_version", "claim_id", "implementation_hash", "supervisor_code_b64",
    "supervisor_code_sha256", "supervisor_spec_b64",
})
SUPERVISOR_STATUSES = frozenset({"PASSED", "ERROR", "BLOCKED", "POLICY_VIOLATION"})
SUPERVISOR_FRAME_ERROR_CODES = frozenset({
    "bootstrap_payload_invalid", "bootstrap_code_hash_mismatch", "request_schema", "sensitive_header",
    "claim_invalid", "implementation_invalid", "supervisor_spec_invalid", "codex_wire_contract_unproven",
    "broker_not_ready", "runtime_bind_invalid", "runtime_bind_missing", "runtime_binary_not_regular",
    "runtime_binary_symlink", "runtime_binary_not_executable", "work_fixture_missing", "work_fixture_not_read_only",
    "codex_config_missing", "codex_config_hash_mismatch", "codex_config_invalid", "codex_config_provider_invalid",
    "runtime_binary_sha_mismatch", "codex_argv_invalid", "codex_model_invalid", "codex_prompt_invalid",
    "relay_codex_failed", "relay_child_transport_error", "relay_boot_missing", "relay_boot_duplicate", "relay_boot_invalid",
    "codex_child_control_missing", "codex_child_control_duplicate",
    "codex_child_control_invalid", "relay_proof_missing", "relay_proof_duplicate", "relay_proof_invalid",
    "codex_home_mode_invalid", "config_copy_failed", "config_copy_invalid", "codex_home_write_probe_failed", "codex_home_write_failed",
    "arg0_init_failed", "broker_socket_invalid", "loopback_bind_failed", "loopback_listen_failed",
    "loopback_ready_failed", "loopback_accept_failed", "loopback_accept_timeout", "codex_endpoint_not_reached",
    "broker_socket_connect_failed", "output_limit", "codex_spawn_not_proven", "codex_spawn_os_error",
    "codex_binary_missing", "codex_permission_denied", "codex_spawned_early_exit", "codex_prompt_delivery_failed",
    "codex_spawn_timeout", "codex_completion_timeout", "codex_early_exit", "cli_no_request_exit", "codex_marker",
    "codex_final_message_missing", "codex_final_message_symlink", "codex_final_message_oversize",
    "codex_final_message_mismatch", "stdout_unexpected", "request_limit",
    "request_target", "request_header", "request_host", "request_model", "response_limit", "response_proof_invalid", "sensitive_header_proof_invalid",
    "cli_no_event_exit", "cli_no_turn", "provider_endpoint_not_reached", "proof_counter_mismatch",
    "strict_http_rejected", "request_proof_invalid", "fake_response_not_sent", "response_not_consumed", "jsonl_invalid",
    "jsonl_final_line_incomplete", "jsonl_turn_completed_schema_invalid", "jsonl_terminal_event_missing",
    "jsonl_agent_message_missing", "jsonl_agent_message_duplicate", "jsonl_output_mismatch",
    "output_proof_field_missing",
    "tool_event_policy_violation", "codex_turn_failed", "codex_error_event",
    "cli_usage_error", "strict_config_error", "config_invalid", "provider_missing",
    "auth_env_missing", "child_exit_other",
    "cleanup_failed", "relay_child_error", "supervisor_timeout", "supervisor_error",
})
SUPERVISOR_FRAME_SCHEMA = {
    "version": SUPERVISOR_FRAME_SCHEMA_VERSION,
    "fields": tuple(sorted(SUPERVISOR_FRAME_FIELDS)),
    "error_fields": tuple(sorted(SUPERVISOR_FRAME_ERROR_FIELDS)),
    "passed_fields": tuple(sorted(SUPERVISOR_FRAME_PASSED_FIELDS)),
    "statuses": tuple(sorted(SUPERVISOR_STATUSES)),
    "stages": tuple(sorted(SUPERVISOR_STAGES)),
    "substage": tuple(sorted(SUPERVISOR_RELAY_SUBSTAGES | BOOTSTRAP_SUBSTAGES)),
    "error_codes": tuple(sorted(SUPERVISOR_FRAME_ERROR_CODES)),
    "process_fields": SUPERVISOR_PROCESS_FIELDS,
}
SUPERVISOR_FRAME_DEFAULTS = {
    "schema_version": SUPERVISOR_FRAME_SCHEMA_VERSION,
    "status": "ERROR",
    "stage": "BOOT",
    "substage": None,
    "error_code": None,
    "process_counts": {name: 0 for name in SUPERVISOR_PROCESS_FIELDS},
    "cleanup_ok": False,
    "implementation_hash": "",
    "request_seen": 0,
    "request_validated": 0,
    "response_sent": 0,
    "accepted_post": 0,
    "codex_stdout_bytes": 0,
    "codex_stdout_sha256": None,
    "codex_stdout_terminal_newline": False,
    "eof_stdout_drained": False,
    "eof_stderr_drained": False,
    "readers_joined": False,
    "usage": None,
    "child_schema_diagnostic": None,
    "request_hash": None,
    "response_hash": None,
    "response_byte_count": 0,
    "output_hash": None,
    "sensitive_headers_removed": False,
    "removed_count": 0,
    "post_filter_count": 0,
    "connection_delay_ms": 0,
    "connection_delay_warning": False,
    "stderr_byte_count": 0,
    "stderr_sha256": hashlib.sha256(b"").hexdigest(),
    "stderr_category": None,
    "prompt_mode": "STDIN_FORCED",
    "config_loaded_expected": True,
    "argc": 12,
    "event_types": [],
    "event_counts": {},
    "event_sequence_hash": hashlib.sha256(canonical_json({"event_types": [], "event_counts": {}}).encode("utf-8")).hexdigest(),
    "tool_event_count": 0,
    "agent_message_count": 0,
    "output_byte_count": 0,
    "output_sha256": None,
    "last_message_exists": False,
    "last_message_regular": False,
    "last_message_size": 0,
    "last_message_sha256": None,
    "last_message_match": False,
    "last_message_marker_match": False,
    "marker_match": False,
    "codex_exit_code": None,
    "strict_http_reject_reason": None,
    "request_header_count": 0,
    "request_body_bytes": 0,
    "request_body_sha256": hashlib.sha256(b"").hexdigest(),
    "request_json_keyset_hash": None,
    "input_shape": None,
}
SUPERVISOR_SCHEMA_DIAGNOSTICS = frozenset({
    "missing_fields", "extra_fields", "bad_type_fields", "bad_enum_fields", "hash_mismatch",
})
RELAY_FRAME_PREFIX = "CODEXGATE_CODEX_RELAY_V1:"
RELAY_BOOT_FRAME_PREFIX = "CODEXGATE_RELAY_BOOT_V1:"
CODEX_CHILD_FRAME_PREFIX = "CODEXGATE_CODEX_CHILD_V1:"
RELAY_BOOT_FRAME_FIELDS = frozenset({"stage", "implementation_hash"})
RELAY_FRAME_FIELDS = frozenset({
    "status",
    "substage",
    "error_code",
    "codex_cli",
    "request_seen",
    "request_validated",
    "response_sent",
    "accepted_post",
    "request_hash",
    "response_hash",
    "response_byte_count",
    "output_hash",
    "sensitive_headers_removed",
    "removed_count",
    "post_filter_count",
    "codex_stdout_bytes",
    "codex_stdout_sha256",
    "codex_stdout_terminal_newline",
    "connection_delay_ms",
    "connection_delay_warning",
    "stderr_byte_count",
    "stderr_sha256",
    "stderr_category",
    "prompt_mode",
    "config_loaded_expected",
    "argc",
    "event_types",
    "event_counts",
    "event_sequence_hash",
    "tool_event_count",
    "agent_message_count",
    "output_byte_count",
    "output_sha256",
    "last_message_exists",
    "last_message_regular",
    "last_message_size",
    "last_message_sha256",
    "last_message_match",
    "last_message_marker_match",
    "marker_match",
    "codex_exit_code",
    "eof_stdout_drained",
    "eof_stderr_drained",
    "readers_joined",
    "usage",
    "strict_http_reject_reason",
    "request_header_count",
    "request_body_bytes",
    "request_body_sha256",
    "request_json_keyset_hash",
    "input_shape",
})
RELAY_FRAME_STATUSES = frozenset({"READY", "PASSED", "ERROR", "BLOCKED", "POLICY_VIOLATION"})
STRICT_HTTP_REJECT_REASONS = frozenset({
    "request_line", "method", "path", "host", "duplicate_header",
    "content_type", "content_length", "transfer_encoding", "body_size",
    "json_decode", "json_schema", "model", "stream", "store", "input",
    *INPUT_REJECT_REASONS,
    "include", "unknown_field",
})

# These fixed process inputs are sealed into the implementation hash.  They
# are never accepted from a UI, API, environment, or caller.
SUCCESS_MARKER = WIRE_SUCCESS_MARKER
FIXED_PROMPT = WIRE_FIXED_PROMPT
CODEX_JSONL_MAX_BYTES = 16 * 1024
CODEX_JSONL_EVENT_TYPES = frozenset({
    "thread.started", "turn.started", "item.started", "item.updated",
    "item.completed", "turn.completed", "turn.failed", "error",
})
CODEX_JSONL_FORBIDDEN_ITEM_TYPES = frozenset({
    "command_execution", "file_change", "mcp_tool_call", "collab_tool_call", "web_search",
})
CODEX_TURN_COMPLETED_USAGE_FIELDS = frozenset({
    "input_tokens", "cached_input_tokens", "cache_write_input_tokens",
    "output_tokens", "reasoning_output_tokens",
})
RELAY_COUNTER_FIELDS = (
    "request_seen", "request_validated", "response_sent", "accepted_post",
)
CODEX_CHILD_CONTROL_SCHEMA_VERSION = "2"
CODEX_CHILD_PROCESS_FIELDS = ("codex_cli",)
CODEX_CHILD_EXIT_CODE_MIN = -255
CODEX_CHILD_EXIT_CODE_MAX = 255
CODEX_CHILD_STDERR_CATEGORIES = frozenset({
    "CODEX_HOME_WRITE_FAILED", "ARG0_INIT_FAILED", "CONFIG_LOAD_FAILED", "AUTH_REQUIRED",
    "CLI_USAGE_ERROR", "STRICT_CONFIG_ERROR", "CONFIG_INVALID", "PROVIDER_MISSING",
    "AUTH_ENV_MISSING", "CHILD_EXIT_OTHER",
})
CODEX_CHILD_CONTROL_FIELDS = frozenset({
    "schema_version", "stage", "error_code", "spawn_confirmed", "process_counts",
    "cleanup_ok", "implementation_hash", "codex_exit_code",
    "event_types", "event_counts", "event_sequence_hash", "tool_event_count", "usage",
    "stdout_sha256", "stderr_byte_count", "stderr_sha256", "stderr_category",
    "agent_message_count", "output_byte_count", "output_sha256",
    "last_message_exists", "last_message_regular", "last_message_size", "last_message_sha256",
    "last_message_match", "last_message_marker_match", "marker_match", "request_seen", "request_validated",
    "response_sent", "accepted_post", "response_byte_count", "response_sha256",
    "request_hash", "sensitive_headers_removed", "removed_count", "post_filter_count",
    "strict_http_reject_reason", "request_header_count", "request_body_bytes",
    "request_body_sha256", "request_json_keyset_hash", "input_shape",
    "eof_stdout_drained",
    "eof_stderr_drained", "readers_joined",
})
CODEX_CHILD_CONTROL_NULLABLE_FIELDS = frozenset({
    "error_code", "codex_exit_code", "stderr_category", "usage", "strict_http_reject_reason", "request_json_keyset_hash", "request_hash",
    "output_sha256", "last_message_sha256",
})
CODEX_CHILD_CONTROL_BOOLEAN_FIELDS = frozenset({
    "spawn_confirmed", "cleanup_ok", "last_message_exists",
    "last_message_regular", "last_message_match", "last_message_marker_match", "marker_match",
    "eof_stdout_drained", "eof_stderr_drained", "readers_joined",
})
CODEX_CHILD_CONTROL_COUNTER_FIELDS = frozenset({
    "tool_event_count", "agent_message_count", "output_byte_count", "stderr_byte_count", "last_message_size", "response_byte_count", "request_header_count", "request_body_bytes", "removed_count", "post_filter_count",
})
CODEX_CHILD_CONTROL_BINARY_COUNTER_FIELDS = frozenset(RELAY_COUNTER_FIELDS)
CODEX_CHILD_CONTROL_SCHEMA = {
    "version": CODEX_CHILD_CONTROL_SCHEMA_VERSION,
    "fields": tuple(sorted(CODEX_CHILD_CONTROL_FIELDS)),
    "nullable_fields": tuple(sorted(CODEX_CHILD_CONTROL_NULLABLE_FIELDS)),
    "boolean_fields": tuple(sorted(CODEX_CHILD_CONTROL_BOOLEAN_FIELDS)),
    "counter_fields": tuple(sorted(CODEX_CHILD_CONTROL_COUNTER_FIELDS)),
    "binary_counter_fields": tuple(sorted(CODEX_CHILD_CONTROL_BINARY_COUNTER_FIELDS)),
    "stages": tuple(sorted(CODEX_CHILD_STAGES)),
    "error_codes": tuple(sorted(SUPERVISOR_FRAME_ERROR_CODES)),
    "process_fields": CODEX_CHILD_PROCESS_FIELDS,
    "event_types": tuple(sorted(CODEX_JSONL_EVENT_TYPES)),
    "usage_fields": tuple(sorted(CODEX_TURN_COMPLETED_USAGE_FIELDS)),
    "stderr_categories": tuple(sorted(CODEX_CHILD_STDERR_CATEGORIES)),
    "strict_http_reject_reasons": tuple(sorted(STRICT_HTTP_REJECT_REASONS)),
    "input_shape_fields": tuple(sorted(INPUT_SHAPE_FIELDS)),
    "exit_code_min": CODEX_CHILD_EXIT_CODE_MIN,
    "exit_code_max": CODEX_CHILD_EXIT_CODE_MAX,
}
CODEX_CHILD_FRAME_FIELDS = CODEX_CHILD_CONTROL_FIELDS
CODEX_CHILD_CONTROL_SCHEMA_B85 = base64.b85encode(
    zlib.compress(canonical_json(CODEX_CHILD_CONTROL_SCHEMA).encode("utf-8"), 9)
)
FIXED_FAKE_RESPONSE = {
    "id": "sealed-offline-canary",
    "object": "response",
    "output": [{"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": SUCCESS_MARKER}]}],
}
SEALED_CODEX_SUBCOMMAND = "exec"
SEALED_CODEX_MODEL = CUSTOM_PROVIDER_ID
SEALED_CODEX_CONFIG_TRANSPORT = "CODEX_HOME_TOML"
SEALED_CODEX_PROMPT_TRANSPORT = "STDIN"


def build_sealed_codex_argv() -> tuple[str, ...]:
    """Return the one sealed Codex argv token sequence.

    This function is the single canonical builder for:
    - the relay/Codex execution argv,
    - the supervisor validator's expected argv,
    - the launch spec snapshot, and
    - the executor implementation hash.
    """
    return (
        SEALED_CODEX_SUBCOMMAND,
        "--ephemeral",
        "--skip-git-repo-check",
        "--sandbox",
        "read-only",
        "--model",
        SEALED_CODEX_MODEL,
        "--strict-config",
        "--json",
        "--output-last-message",
        CODEX_LAST_MESSAGE_PATH,
        "-",
    )


def _codex_argv_diagnostic(
    actual: Any, expected: Sequence[str] | None = None
) -> dict[str, int | str] | None:
    """Return only sanitized mismatch metadata for exact token validation."""
    sealed = tuple(build_sealed_codex_argv() if expected is None else expected)
    if not isinstance(actual, (list, tuple)):
        return {"argc": 0, "mismatch_index": 0, "reason_code": "argv_type_invalid"}
    tokens = tuple(actual)
    if any(not isinstance(token, str) for token in tokens):
        index = next(index for index, token in enumerate(tokens) if not isinstance(token, str))
        return {"argc": len(tokens), "mismatch_index": index, "reason_code": "argv_token_type_invalid"}
    if len(tokens) != len(sealed):
        return {"argc": len(tokens), "mismatch_index": min(len(tokens), len(sealed)), "reason_code": "argc_mismatch"}
    for index, (token, expected_token) in enumerate(zip(tokens, sealed)):
        if token != expected_token:
            return {"argc": len(tokens), "mismatch_index": index, "reason_code": "token_mismatch"}
    return None


FIXED_CODEX_ARGV: tuple[str, ...] = build_sealed_codex_argv()
REQUIRED_EXEC_OPTIONS = frozenset({"--ephemeral", "--skip-git-repo-check", "--sandbox", "read-only", "--model", SEALED_CODEX_MODEL, "-"})
FIXED_REQUEST_BODY = build_fixed_request(CUSTOM_PROVIDER_ID, FIXED_PROMPT)
FIXED_REQUEST_BODY_BYTES = canonical_json(FIXED_REQUEST_BODY).encode("utf-8")
PARSER_FIXTURE_SHA256 = responses_parser_fixture_hash()
SEALED_RESPONSE_BODY_BYTES = full_turn_fixture_bytes()
SEALED_RESPONSE_BODY_SHA256 = hashlib.sha256(SEALED_RESPONSE_BODY_BYTES).hexdigest()
SEALED_RESPONSE_STATUS_LINE = b"HTTP/1.1 200 OK\r\n"
SEALED_RESPONSE_CONTENT_TYPE = b"text/event-stream"
EXPECTED_REQUEST_HASH = canonical_request_hash(FIXED_REQUEST_BODY)


def canonical_request_proof_hash(request: Mapping[str, Any]) -> str:
    """Hash the validated parsed request, never its transport bytes."""
    if not isinstance(request, Mapping):
        raise PolicyError("request_proof_invalid")
    return hashlib.sha256(canonical_json(dict(request)).encode("utf-8")).hexdigest()
PINNED_REQUEST_KEYS = tuple(sorted(PINNED_RESPONSES_TOP_LEVEL_KEYS_V0145))
SEALED_REQUEST_KEYS = tuple(sorted(FIXED_REQUEST_BODY))
PINNED_REQUEST_REQUIRED_KEYS = tuple(sorted(REQUEST_REQUIRED_FIELDS))
PINNED_REQUEST_OPTIONAL_KEYS = tuple(PINNED_REQUEST_KEY_DIFF_V0145_SORTED)
PINNED_INCLUDE_SEQUENCE = tuple(PINNED_INCLUDE_CONTRACT_V0145)
EXPECTED_RESPONSE_HASH = full_turn_fixture_hash()
EXPECTED_CONFIG_HASH = provider_config_hash(canonical_provider_toml())
EXPECTED_PROMPT_HASH = fixed_prompt_hash()
EXPECTED_OUTPUT_HASH = hashlib.sha256(SUCCESS_MARKER.encode("utf-8")).hexdigest()
# The reviewed rust-v0.145.0 exec CLI accepts ``-`` as the forced-stdin
# positional prompt.  The sealed argv uses it with exactly one prompt write;
# both the config provider and selected model remain fixed constants.
PINNED_CODEX_WIRE_CONTRACT_PROVEN = WIRE_CONTRACT_STATUS == "PARSER_PROVEN"


def build_sealed_http_response_bytes(body: bytes = SEALED_RESPONSE_BODY_BYTES) -> bytes:
    """Return the sole HTTP envelope for the proven Responses SSE fixture."""
    if not isinstance(body, bytes) or body != SEALED_RESPONSE_BODY_BYTES:
        raise PolicyError("response_proof_invalid")
    return (
        SEALED_RESPONSE_STATUS_LINE
        + b"Content-Type: " + SEALED_RESPONSE_CONTENT_TYPE + b"\r\n"
        + b"Cache-Control: no-cache\r\n"
        + b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
        + b"Connection: close\r\n\r\n"
        + body
    )


SEALED_HTTP_RESPONSE_BYTES = build_sealed_http_response_bytes()
SEALED_HTTP_RESPONSE_PREFIX = SEALED_HTTP_RESPONSE_BYTES[:-len(SEALED_RESPONSE_BODY_BYTES)]


def classify_codex_last_message(path: str) -> str:
    """Classify the sealed last-message artifact without returning its bytes."""
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return "codex_final_message_missing"
    except OSError:
        return "codex_final_message_mismatch"
    metadata = classify_codex_last_message_metadata(
        stat.S_ISLNK(info.st_mode), stat.S_ISREG(info.st_mode), info.st_size
    )
    if metadata != "ok":
        return metadata
    try:
        with open(path, "rb") as handle:
            value = handle.read(CODEX_LAST_MESSAGE_MAX_BYTES + 1)
    except OSError:
        return "codex_final_message_mismatch"
    return "ok" if value == SUCCESS_MARKER.encode("utf-8") else "codex_final_message_mismatch"


def classify_codex_last_message_metadata(is_symlink: bool, is_regular: bool, size: int) -> str:
    if is_symlink:
        return "codex_final_message_symlink"
    if not is_regular or size < 0:
        return "codex_final_message_mismatch"
    if size > CODEX_LAST_MESSAGE_MAX_BYTES:
        return "codex_final_message_oversize"
    return "ok"


def stdout_marker_diagnostic(value: bytes) -> dict[str, Any]:
    """Return bounded stdout metadata; final response proof never uses it."""
    return {
        "bytes": len(value),
        "sha256": hashlib.sha256(value).hexdigest(),
        "terminal_newline": value.endswith(b"\n"),
        "allowed": value in (SUCCESS_MARKER.encode("utf-8"), SUCCESS_MARKER.encode("utf-8") + b"\n", SUCCESS_MARKER.encode("utf-8") + b"\r\n"),
    }


def parse_codex_jsonl(value: bytes) -> dict[str, Any]:
    """Parse the sealed no-tool Codex JSONL lifecycle without retaining events."""
    if len(value) > CODEX_JSONL_MAX_BYTES:
        raise PolicyError("output_limit")
    if value and not value.endswith(b"\n"):
        raise PolicyError("jsonl_final_line_incomplete")
    turn_completed_bytes_seen = b"turn.completed" in value
    try:
        lines = value.decode("utf-8", "strict").splitlines()
    except UnicodeDecodeError as exc:
        code = "jsonl_turn_completed_schema_invalid" if turn_completed_bytes_seen else "jsonl_invalid"
        raise PolicyError(code) from exc
    if not lines:
        raise PolicyError("cli_no_event_exit")
    if any(not line.strip() for line in lines):
        raise PolicyError("jsonl_invalid")
    types: list[str] = []
    counts: dict[str, int] = {}
    agent_message_count = 0
    output_byte_count = 0
    output_sha256: str | None = None
    completed_usage: dict[str, int] | None = None
    for line in lines:
        try:
            event = json.loads(line)
        except (TypeError, ValueError, UnicodeDecodeError) as exc:
            code = "jsonl_turn_completed_schema_invalid" if turn_completed_bytes_seen else "jsonl_invalid"
            raise PolicyError(code) from exc
        if not isinstance(event, dict) or set(event) - {"type", "thread_id", "turn_id", "item", "usage", "error", "message"}:
            code = "jsonl_turn_completed_schema_invalid" if isinstance(event, dict) and event.get("type") == "turn.completed" else "jsonl_invalid"
            raise PolicyError(code)
        kind = event.get("type")
        if kind not in CODEX_JSONL_EVENT_TYPES:
            raise PolicyError("jsonl_invalid")
        if kind == "turn.completed":
            usage = event.get("usage")
            if (
                set(event) != {"type", "usage"}
                or not isinstance(usage, dict)
                or set(usage) != CODEX_TURN_COMPLETED_USAGE_FIELDS
                or any(isinstance(item, bool) or not isinstance(item, int) or item < 0 for item in usage.values())
            ):
                raise PolicyError("jsonl_turn_completed_schema_invalid")
            completed_usage = dict(usage)
        types.append(kind)
        counts[kind] = counts.get(kind, 0) + 1
        item = event.get("item") if isinstance(event.get("item"), dict) else None
        if item and item.get("type") in CODEX_JSONL_FORBIDDEN_ITEM_TYPES:
            raise PolicyError("response_proof_invalid")
        if kind in {"turn.failed", "error"}:
            raise PolicyError("response_proof_invalid")
        if kind == "item.completed" and item and item.get("type") == "agent_message":
            text = item.get("text")
            agent_message_count += 1
            if agent_message_count > 1:
                raise PolicyError("jsonl_agent_message_duplicate")
            if not isinstance(text, str):
                raise PolicyError("jsonl_output_mismatch")
            try:
                output = text.encode("utf-8", "strict")
            except UnicodeEncodeError as exc:
                raise PolicyError("jsonl_output_mismatch") from exc
            output_byte_count = len(output)
            output_sha256 = hashlib.sha256(output).hexdigest()
            if output_sha256 != EXPECTED_OUTPUT_HASH:
                raise PolicyError("jsonl_output_mismatch")
    if counts.get("thread.started", 0) != 1:
        raise PolicyError("cli_no_event_exit")
    if counts.get("turn.started", 0) != 1:
        raise PolicyError("cli_no_turn")
    if counts.get("turn.completed", 0) == 0:
        raise PolicyError("jsonl_terminal_event_missing")
    if counts.get("turn.completed", 0) != 1:
        raise PolicyError("jsonl_turn_completed_schema_invalid")
    if agent_message_count == 0:
        raise PolicyError("jsonl_agent_message_missing")
    if types[0] != "thread.started" or types[-1] != "turn.completed" or output_sha256 is None:
        raise PolicyError("response_proof_invalid")
    stream_hash = hashlib.sha256(canonical_json({"types": types, "counts": counts, "message_hash": output_sha256}).encode("utf-8")).hexdigest()
    return {
        "event_types": tuple(types),
        "event_counts": dict(counts),
        "stream_hash": stream_hash,
        "usage": completed_usage,
        "agent_message_count": agent_message_count,
        "output_byte_count": output_byte_count,
        "output_sha256": output_sha256,
    }


def _digest_or_none(value: Any) -> bool:
    return value is None or (isinstance(value, str) and _DIGEST.fullmatch(value) is not None)


def _input_shape_valid(value: Any) -> bool:
    if value is None:
        return True
    if not isinstance(value, dict) or set(value) != set(INPUT_SHAPE_FIELDS):
        return False
    if isinstance(value.get("item_count"), bool) or not isinstance(value.get("item_count"), int) or value["item_count"] < 0:
        return False
    for field in ("item_type_ids", "role_ids", "content_type_ids"):
        if not isinstance(value.get(field), list) or any(not isinstance(item, str) or item not in {"message", "developer", "user", "unknown", "input_text"} for item in value[field]):
            return False
    for field in ("item_key_presence_masks", "content_counts", "text_byte_counts"):
        if not isinstance(value.get(field), list) or any(isinstance(item, bool) or not isinstance(item, int) or item < 0 for item in value[field]):
            return False
    for field in ("text_sha256s",):
        if not isinstance(value.get(field), list) or any(not isinstance(item, str) or not _DIGEST.fullmatch(item) for item in value[field]):
            return False
    return isinstance(value.get("shape_hash"), str) and _DIGEST.fullmatch(value["shape_hash"]) is not None


def codex_child_control_schema_diagnostic(
    payload: Any,
    expected_implementation_hash: str,
) -> str | None:
    """Return only a sealed schema diagnostic name for a terminal child payload."""
    if not isinstance(payload, dict):
        return "bad_type_fields"
    fields = set(payload)
    expected_fields = set(CODEX_CHILD_CONTROL_SCHEMA["fields"])
    if expected_fields - fields:
        return "missing_fields"
    if fields - expected_fields:
        return "extra_fields"

    boolean_fields = CODEX_CHILD_CONTROL_SCHEMA["boolean_fields"]
    if any(not isinstance(payload.get(name), bool) for name in boolean_fields):
        return "bad_type_fields"
    if any(
        isinstance(payload.get(name), bool)
        or not isinstance(payload.get(name), int)
        or payload[name] < 0
        for name in CODEX_CHILD_CONTROL_SCHEMA["counter_fields"]
    ):
        return "bad_type_fields"
    if not _input_shape_valid(payload.get("input_shape")):
        return "bad_type_fields"
    if any(
        isinstance(payload.get(name), bool)
        or not isinstance(payload.get(name), int)
        or payload[name] not in (0, 1)
        for name in CODEX_CHILD_CONTROL_SCHEMA["binary_counter_fields"]
    ):
        return "bad_type_fields"

    if (
        isinstance(payload.get("request_header_count"), bool)
        or not isinstance(payload.get("request_header_count"), int)
        or payload["request_header_count"] < 0
        or isinstance(payload.get("request_body_bytes"), bool)
        or not isinstance(payload.get("request_body_bytes"), int)
        or payload["request_body_bytes"] < 0
        or not isinstance(payload.get("request_body_sha256"), str)
        or _DIGEST.fullmatch(payload["request_body_sha256"]) is None
        or not _digest_or_none(payload.get("request_json_keyset_hash"))
    ):
        return "bad_type_fields"

    counts = payload.get("process_counts")
    if (
        not isinstance(counts, dict)
        or set(counts) != set(CODEX_CHILD_CONTROL_SCHEMA["process_fields"])
        or any(
            isinstance(counts.get(name), bool)
            or not isinstance(counts.get(name), int)
            or counts[name] not in (0, 1)
            for name in CODEX_CHILD_CONTROL_SCHEMA["process_fields"]
        )
        or counts["codex_cli"] != int(payload["spawn_confirmed"])
    ):
        return "bad_type_fields"

    exit_code = payload.get("codex_exit_code")
    if exit_code is not None and (
        isinstance(exit_code, bool)
        or not isinstance(exit_code, int)
        or not CODEX_CHILD_CONTROL_SCHEMA["exit_code_min"]
        <= exit_code
        <= CODEX_CHILD_CONTROL_SCHEMA["exit_code_max"]
    ):
        return "bad_type_fields"

    event_types = payload.get("event_types")
    event_counts = payload.get("event_counts")
    allowed_event_types = set(CODEX_CHILD_CONTROL_SCHEMA["event_types"])
    if (
        not isinstance(event_types, list)
        or any(not isinstance(kind, str) or kind not in allowed_event_types for kind in event_types)
        or not isinstance(event_counts, dict)
        or any(
            not isinstance(kind, str)
            or kind not in allowed_event_types
            or isinstance(count, bool)
            or not isinstance(count, int)
            or count < 0
            for kind, count in event_counts.items()
        )
    ):
        return "bad_type_fields"

    usage = payload.get("usage")
    if usage is not None and (
        not isinstance(usage, dict)
        or set(usage) != set(CODEX_CHILD_CONTROL_SCHEMA["usage_fields"])
        or any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in usage.values()
        )
    ):
        return "bad_type_fields"

    if any(
        not isinstance(payload.get(name), str) or _DIGEST.fullmatch(payload[name]) is None
        for name in ("event_sequence_hash", "stdout_sha256", "stderr_sha256", "response_sha256")
    ) or any(
        not _digest_or_none(payload.get(name))
        for name in ("output_sha256", "last_message_sha256")
    ):
        return "bad_type_fields"
    if not isinstance(payload.get("implementation_hash"), str) or _DIGEST.fullmatch(
        payload["implementation_hash"]
    ) is None:
        return "bad_type_fields"

    if (
        payload.get("schema_version") != CODEX_CHILD_CONTROL_SCHEMA["version"]
        or payload.get("stage") not in set(CODEX_CHILD_CONTROL_SCHEMA["stages"])
        or payload.get("error_code") not in {None, *CODEX_CHILD_CONTROL_SCHEMA["error_codes"]}
        or payload.get("stderr_category")
        not in {None, *CODEX_CHILD_CONTROL_SCHEMA["stderr_categories"]}
        or payload.get("strict_http_reject_reason")
        not in {None, *CODEX_CHILD_CONTROL_SCHEMA["strict_http_reject_reasons"]}
    ):
        return "bad_enum_fields"
    if payload["implementation_hash"] != expected_implementation_hash:
        return "hash_mismatch"

    observed_counts: dict[str, int] = {}
    for kind in event_types:
        observed_counts[kind] = observed_counts.get(kind, 0) + 1
    expected_sequence_hash = hashlib.sha256(
        canonical_json({
            "event_types": event_types,
            "event_counts": event_counts,
        }).encode("utf-8")
    ).hexdigest()
    if observed_counts != event_counts or payload["event_sequence_hash"] != expected_sequence_hash:
        return "hash_mismatch"
    if (
        payload["accepted_post"] != payload["request_validated"]
        or payload["response_sent"] > payload["accepted_post"]
        or payload["request_validated"] > payload["request_seen"]
        or payload["response_sent"] == 0 and payload["response_byte_count"] != 0
        or payload["response_sent"] == 1 and payload["response_byte_count"] <= 0
        or payload["last_message_regular"] and not payload["last_message_exists"]
        or payload["last_message_match"] != payload["last_message_marker_match"]
        or payload["last_message_match"] and (
            not payload["last_message_exists"]
            or not payload["last_message_regular"]
            or payload["last_message_sha256"] is None
        )
        or payload["last_message_marker_match"]
        and (not payload["last_message_exists"] or not payload["last_message_regular"])
        or payload["agent_message_count"] == 0 and (
            payload["output_byte_count"] != 0 or payload["output_sha256"] is not None
        )
        or payload["agent_message_count"] > 0 and (
            payload["output_byte_count"] <= 0 or payload["output_sha256"] is None
        )
        or payload["marker_match"] and (
            payload["agent_message_count"] != 1
            or payload["output_sha256"] is None
            or payload["last_message_sha256"] is None
            or not payload["last_message_match"]
            or payload["output_sha256"] != payload["last_message_sha256"]
        )
    ):
        return "bad_type_fields"
    return None


def build_codex_child_control_payload(
    values: Mapping[str, Any],
    expected_implementation_hash: str,
) -> dict[str, Any]:
    """Build one immutable-by-convention terminal payload from the shared schema."""
    payload = dict(values)
    diagnostic = codex_child_control_schema_diagnostic(
        payload, expected_implementation_hash
    )
    if diagnostic is not None:
        raise PolicyError(diagnostic)
    return payload


def encode_codex_child_control_frame(
    values: Mapping[str, Any],
    expected_implementation_hash: str,
) -> bytes:
    payload = build_codex_child_control_payload(values, expected_implementation_hash)
    encoded = base64.urlsafe_b64encode(
        canonical_json(payload).encode("utf-8")
    ).rstrip(b"=")
    return CODEX_CHILD_FRAME_PREFIX.encode("ascii") + encoded + b"\n"


def parse_codex_child_control_frame(
    frame: bytes,
    expected_implementation_hash: str,
) -> dict[str, Any]:
    """Strict host parser for exactly one canonical terminal child frame."""
    prefix = CODEX_CHILD_FRAME_PREFIX.encode("ascii")
    if (
        not isinstance(frame, bytes)
        or frame.count(b"\n") != 1
        or not frame.endswith(b"\n")
        or not frame.startswith(prefix)
    ):
        raise PolicyError("bad_type_fields")
    encoded = frame[len(prefix):-1]
    if not encoded or b"=" in encoded or re.fullmatch(br"[A-Za-z0-9_-]+", encoded) is None:
        raise PolicyError("bad_type_fields")
    try:
        raw = base64.urlsafe_b64decode(encoded + b"=" * ((4 - len(encoded) % 4) % 4))
        payload = json.loads(raw.decode("utf-8", "strict"))
    except Exception as exc:
        raise PolicyError("bad_type_fields") from exc
    if not isinstance(payload, dict) or canonical_json(payload).encode("utf-8") != raw:
        raise PolicyError("bad_type_fields")
    diagnostic = codex_child_control_schema_diagnostic(
        payload, expected_implementation_hash
    )
    if diagnostic is not None:
        raise PolicyError(diagnostic)
    return payload


CODEX_CHILD_CONTROL_GENERATED_VALIDATOR = """def child_schema_diagnostic(payload,expected):
 schema=CHILD_SCHEMA
 if not isinstance(payload,dict): return 'bad_type_fields'
 fields=set(payload); expected_fields=set(schema['fields'])
 if expected_fields-fields: return 'missing_fields'
 if fields-expected_fields: return 'extra_fields'
 if any(not isinstance(payload.get(name),bool) for name in schema['boolean_fields']): return 'bad_type_fields'
 if any(isinstance(payload.get(name),bool) or not isinstance(payload.get(name),int) or payload[name]<0 for name in schema['counter_fields']): return 'bad_type_fields'
 if payload.get('request_hash') is not None and (not isinstance(payload.get('request_hash'),str) or not re.fullmatch(r'[0-9a-f]{64}',payload['request_hash'])) or not isinstance(payload.get('sensitive_headers_removed'),bool) or isinstance(payload.get('removed_count'),bool) or not isinstance(payload.get('removed_count'),int) or payload['removed_count']<0 or isinstance(payload.get('post_filter_count'),bool) or not isinstance(payload.get('post_filter_count'),int) or payload['post_filter_count']<0: return 'bad_type_fields'
 if not isinstance(payload.get('request_header_count'),int) or isinstance(payload.get('request_header_count'),bool) or payload['request_header_count']<0 or not isinstance(payload.get('request_body_bytes'),int) or isinstance(payload.get('request_body_bytes'),bool) or payload['request_body_bytes']<0 or not isinstance(payload.get('request_body_sha256'),str) or not re.fullmatch(r'[0-9a-f]{64}',payload['request_body_sha256']) or payload.get('request_json_keyset_hash') is not None and (not isinstance(payload.get('request_json_keyset_hash'),str) or not re.fullmatch(r'[0-9a-f]{64}',payload['request_json_keyset_hash'])): return 'bad_type_fields'
 if any(isinstance(payload.get(name),bool) or not isinstance(payload.get(name),int) or payload[name] not in (0,1) for name in schema['binary_counter_fields']): return 'bad_type_fields'
 counts=payload.get('process_counts')
 if not isinstance(counts,dict) or set(counts)!=set(schema['process_fields']) or any(isinstance(counts.get(name),bool) or not isinstance(counts.get(name),int) or counts[name] not in (0,1) for name in schema['process_fields']) or counts['codex_cli']!=int(payload['spawn_confirmed']): return 'bad_type_fields'
 exit_code=payload.get('codex_exit_code')
 if exit_code is not None and (isinstance(exit_code,bool) or not isinstance(exit_code,int) or exit_code<schema['exit_code_min'] or exit_code>schema['exit_code_max']): return 'bad_type_fields'
 events=payload.get('event_types'); event_counts=payload.get('event_counts'); allowed=set(schema['event_types'])
 if not isinstance(events,list) or any(not isinstance(kind,str) or kind not in allowed for kind in events) or not isinstance(event_counts,dict) or any(not isinstance(kind,str) or kind not in allowed or isinstance(count,bool) or not isinstance(count,int) or count<0 for kind,count in event_counts.items()): return 'bad_type_fields'
 usage=payload.get('usage')
 if usage is not None and (not isinstance(usage,dict) or set(usage)!=set(schema['usage_fields']) or any(isinstance(value,bool) or not isinstance(value,int) or value<0 for value in usage.values())): return 'bad_type_fields'
 if any(not isinstance(payload.get(name),str) or not re.fullmatch(r'[0-9a-f]{64}',payload[name]) for name in ('event_sequence_hash','stdout_sha256','stderr_sha256','response_sha256','implementation_hash')) or any(payload.get(name) is not None and (not isinstance(payload.get(name),str) or not re.fullmatch(r'[0-9a-f]{64}',payload[name])) for name in ('output_sha256','last_message_sha256')): return 'bad_type_fields'
 if payload.get('schema_version')!=schema['version'] or payload.get('stage') not in set(schema['stages']) or payload.get('error_code') not in ({None}|set(schema['error_codes'])) or payload.get('stderr_category') not in ({None}|set(schema['stderr_categories'])) or payload.get('strict_http_reject_reason') not in ({None}|set(schema['strict_http_reject_reasons'])): return 'bad_enum_fields'
 if payload['implementation_hash']!=expected: return 'hash_mismatch'
 observed={}
 for kind in events: observed[kind]=observed.get(kind,0)+1
 sequence_hash=hashlib.sha256(json.dumps({'event_types':events,'event_counts':event_counts},ensure_ascii=False,sort_keys=True,separators=(',',':')).encode('utf-8')).hexdigest()
 if observed!=event_counts or payload['event_sequence_hash']!=sequence_hash: return 'hash_mismatch'
 if payload['accepted_post']!=payload['request_validated'] or payload['response_sent']>payload['accepted_post'] or payload['request_validated']>payload['request_seen'] or payload['response_sent']==0 and payload['response_byte_count']!=0 or payload['response_sent']==1 and payload['response_byte_count']<=0 or payload['last_message_regular'] and not payload['last_message_exists'] or payload['last_message_match']!=payload['last_message_marker_match'] or payload['last_message_match'] and (not payload['last_message_exists'] or not payload['last_message_regular'] or payload['last_message_sha256'] is None) or payload['last_message_marker_match'] and (not payload['last_message_exists'] or not payload['last_message_regular']) or payload['agent_message_count']==0 and (payload['output_byte_count']!=0 or payload['output_sha256'] is not None) or payload['agent_message_count']>0 and (payload['output_byte_count']<=0 or payload['output_sha256'] is None) or payload['marker_match'] and (payload['agent_message_count']!=1 or payload['output_sha256'] is None or payload['last_message_sha256'] is None or not payload['last_message_match'] or payload['output_sha256']!=payload['last_message_sha256']): return 'bad_type_fields'
 return None
"""


def _fixed_http_request_bytes(headers: Mapping[str, str] | None = None) -> bytes:
    """Construct the one sealed synthetic request for byte-level tests only."""
    merged = {"Host": SEALED_LOOPBACK_AUTHORITY, "Content-Type": "application/json"}
    if headers:
        merged.update(headers)
    lines = [f"POST {BROKER_REQUEST_PATH} HTTP/1.1", *[f"{key}: {value}" for key, value in merged.items()],
             f"Content-Length: {len(FIXED_REQUEST_BODY_BYTES)}", "", ""]
    return "\r\n".join(lines).encode("ascii") + FIXED_REQUEST_BODY_BYTES


def strict_http_reject_diagnostic(raw: bytes) -> dict[str, Any]:
    """Return only the first sealed HTTP rejection reason and safe metadata."""
    body = raw if isinstance(raw, bytes) else b""
    header_count = 0
    body_bytes = len(body)
    body_hash = hashlib.sha256(body).hexdigest()
    keyset_hash: str | None = None
    if not isinstance(raw, bytes) or len(raw) > 256 * 1024:
        reason = "body_size" if isinstance(raw, bytes) and len(raw) > 256 * 1024 else "request_line"
        return {"reason": reason, "header_count": 0, "body_bytes": body_bytes, "body_sha256": body_hash, "json_keyset_hash": None}
    head, sep, body = raw.partition(b"\r\n\r\n")
    body_bytes = len(body)
    body_hash = hashlib.sha256(body).hexdigest()
    if not sep:
        return {"reason": "request_line", "header_count": 0, "body_bytes": body_bytes, "body_sha256": body_hash, "json_keyset_hash": None}
    try:
        lines = head.decode("ascii", "strict").split("\r\n")
    except UnicodeDecodeError:
        return {"reason": "request_line", "header_count": 0, "body_bytes": body_bytes, "body_sha256": body_hash, "json_keyset_hash": None}
    header_count = max(0, len(lines) - 1)
    if not lines:
        reason = "request_line"
        return {"reason": reason, "header_count": header_count, "body_bytes": body_bytes, "body_sha256": body_hash, "json_keyset_hash": None}
    parts = lines[0].split(" ")
    if len(parts) != 3 or parts[2] != "HTTP/1.1":
        reason = "request_line"
        return {"reason": reason, "header_count": header_count, "body_bytes": body_bytes, "body_sha256": body_hash, "json_keyset_hash": None}
    if parts[0] != "POST":
        reason = "method"
        return {"reason": reason, "header_count": header_count, "body_bytes": body_bytes, "body_sha256": body_hash, "json_keyset_hash": None}
    if parts[1] != BROKER_REQUEST_PATH:
        reason = "path"
        return {"reason": reason, "header_count": header_count, "body_bytes": body_bytes, "body_sha256": body_hash, "json_keyset_hash": None}
    names: set[str] = set()
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line or ":" not in line:
            return {"reason": "request_line", "header_count": header_count, "body_bytes": body_bytes, "body_sha256": body_hash, "json_keyset_hash": None}
        name, value = line.split(":", 1)
        key = name.casefold()
        if key in names:
            return {"reason": "duplicate_header", "header_count": header_count, "body_bytes": body_bytes, "body_sha256": body_hash, "json_keyset_hash": None}
        names.add(key)
        headers[key] = value.strip()
    if "transfer-encoding" in headers:
        return {"reason": "transfer_encoding", "header_count": header_count, "body_bytes": body_bytes, "body_sha256": body_hash, "json_keyset_hash": None}
    if headers.get("host") != SEALED_LOOPBACK_AUTHORITY:
        return {"reason": "host", "header_count": header_count, "body_bytes": body_bytes, "body_sha256": body_hash, "json_keyset_hash": None}
    if headers.get("content-type", "").split(";", 1)[0].strip().casefold() != "application/json":
        return {"reason": "content_type", "header_count": header_count, "body_bytes": body_bytes, "body_sha256": body_hash, "json_keyset_hash": None}
    try:
        content_length = int(headers.get("content-length", "-1"))
    except (TypeError, ValueError):
        return {"reason": "content_length", "header_count": header_count, "body_bytes": body_bytes, "body_sha256": body_hash, "json_keyset_hash": None}
    if content_length != body_bytes:
        return {"reason": "content_length", "header_count": header_count, "body_bytes": body_bytes, "body_sha256": body_hash, "json_keyset_hash": None}
    if body_bytes > 256 * 1024:
        return {"reason": "body_size", "header_count": header_count, "body_bytes": body_bytes, "body_sha256": body_hash, "json_keyset_hash": None}
    try:
        parsed = json.loads(body.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {"reason": "json_decode", "header_count": header_count, "body_bytes": body_bytes, "body_sha256": body_hash, "json_keyset_hash": None}
    if not isinstance(parsed, dict):
        return {"reason": "json_schema", "header_count": header_count, "body_bytes": body_bytes, "body_sha256": body_hash, "json_keyset_hash": None}
    keyset_hash = hashlib.sha256(canonical_json(sorted(parsed)).encode("utf-8")).hexdigest()
    if set(parsed) - PINNED_RESPONSES_TOP_LEVEL_KEYS_V0145:
        reason = "unknown_field"
    elif not REQUEST_REQUIRED_FIELDS.issubset(parsed):
        reason = "json_schema"
    elif _validate_optional_responses_fields(parsed) is not None:
        reason = "json_schema"
    elif parsed.get("model") != CUSTOM_PROVIDER_ID:
        reason = "model"
    elif parsed.get("stream") is not True:
        reason = "stream"
    elif parsed.get("store") is not False:
        reason = "store"
    elif parsed.get("input") != FIXED_REQUEST_BODY["input"]:
        input_shape, input_reason = inspect_first_turn_input(
            parsed.get("input"), expected_prompt_hash=EXPECTED_PROMPT_HASH,
        )
        reason = input_reason or "input"
    elif (not isinstance(parsed.get("include"), list)
          or any(not isinstance(value, str) for value in parsed["include"])
          or len(parsed["include"]) != len(set(parsed["include"]))
          or parsed["include"] != list(PINNED_INCLUDE_SEQUENCE)):
        reason = "include"
    else:
        reason = None
    result = {"reason": reason, "header_count": header_count, "body_bytes": body_bytes, "body_sha256": body_hash, "json_keyset_hash": keyset_hash}
    if reason in INPUT_REJECT_REASONS or reason == "input":
        result["input_shape"] = input_shape
    return result


def parse_sealed_loopback_request(raw: bytes) -> dict[str, Any]:
    """Bounded, pure HTTP parser used by the relay review and no-I/O tests.

    It returns only metadata and digests: neither the request body nor any
    header value is persisted or returned to an API caller.
    """
    if not isinstance(raw, bytes) or len(raw) > 256 * 1024:
        raise PolicyError("canary_request_policy_violation")
    head, sep, body = raw.partition(b"\r\n\r\n")
    if not sep or len(head) > 8192:
        raise PolicyError("canary_request_policy_violation")
    try:
        lines = head.decode("ascii", "strict").split("\r\n")
        method, target, version = lines[0].split(" ")
    except (UnicodeDecodeError, ValueError, IndexError) as exc:
        raise PolicyError("canary_request_policy_violation") from exc
    if version != "HTTP/1.1" or method != "POST" or target != BROKER_REQUEST_PATH or "://" in target:
        raise PolicyError("canary_request_policy_violation")
    headers: dict[str, str] = {}
    seen_header_names: set[str] = set()
    for line in lines[1:]:
        if not line or ":" not in line:
            raise PolicyError("canary_request_policy_violation")
        name, value = line.split(":", 1)
        normalized_name = name.casefold()
        if normalized_name in seen_header_names:
            raise PolicyError("canary_request_policy_violation")
        seen_header_names.add(normalized_name)
        canonical_name = {
            "host": "Host",
            "content-length": "Content-Length",
        }.get(normalized_name, name)
        if normalized_name == "host":
            if not value.startswith(" ") or value.startswith("  ") or value.endswith(" "):
                raise PolicyError("canary_request_host")
            headers[canonical_name] = value[1:]
        else:
            headers[canonical_name] = value.strip()
    try:
        content_length = int(headers.get("Content-Length", "-1"))
    except (TypeError, ValueError) as exc:
        raise PolicyError("canary_request_policy_violation") from exc
    if content_length != len(body) or content_length < 0 or content_length > 256 * 1024:
        raise PolicyError("canary_request_policy_violation")
    try:
        request = json.loads(body.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PolicyError("canary_request_policy_violation") from exc
    if not isinstance(request, dict) or request.get("model") != CUSTOM_PROVIDER_ID:
        raise PolicyError("canary_model_policy_violation")
    try:
        request_meta = validate_request(request, expected_model=CUSTOM_PROVIDER_ID, expected_prompt_hash=EXPECTED_PROMPT_HASH)
    except PolicyError as exc:
        raise PolicyError(str(exc)) from exc
    clean = sanitize_broker_headers(headers)
    validate_broker_request(method, target, clean, len(body))
    forbidden = lambda name: name.casefold() in {"authorization", "cookie"} or name.casefold().startswith("proxy-")
    removed_count = sum(1 for name in headers if forbidden(name) and name not in clean)
    post_filter_count = sum(1 for name in clean if forbidden(name))
    body_hash = hashlib.sha256(body).hexdigest()
    return {
        "request_hash": canonical_request_proof_hash(request),
        "body_sha256": body_hash,
        "sensitive_headers_removed": post_filter_count == 0,
        "removed_count": removed_count,
        "post_filter_count": post_filter_count,
        "clean_headers": clean,
    }


def synthetic_relay_broker_roundtrip(raw: bytes | None = None, *, second_request: bool = False) -> dict[str, Any]:
    """No-I/O model of the sole relay→broker exchange used by tests."""
    if second_request:
        raise PolicyError("canary_request_policy_violation")
    request = parse_sealed_loopback_request(raw if raw is not None else _fixed_http_request_bytes())
    response_bytes = SEALED_RESPONSE_BODY_BYTES
    response_envelope = build_sealed_http_response_bytes(response_bytes)
    return {
        **{field: 1 for field in RELAY_COUNTER_FIELDS},
        "request_hash": request["request_hash"],
        "response_hash": hashlib.sha256(response_bytes).hexdigest(),
        "response_byte_count": len(response_bytes),
        "response_content_length": len(response_envelope) - len(SEALED_HTTP_RESPONSE_PREFIX),
        "output_hash": EXPECTED_OUTPUT_HASH,
        "sensitive_headers_removed": request["sensitive_headers_removed"],
        "removed_count": request["removed_count"],
        "post_filter_count": request["post_filter_count"],
    }

# The child programs use fixed paths and arguments only.  They are not
# materialized or executed during this implementation phase.
BROKER_CHILD_CODE = ("""import json,socket
HOST=%r; PATH=%r; MODEL=%r; RESPONSE=%r
s=socket.socket(socket.AF_UNIX); s.bind('/runtime/broker/broker.sock'); s.listen(1); s.settimeout(15)
c,_=s.accept(); raw=c.recv(262145)
if len(raw)>262144: raise ValueError('request_limit')
request=json.loads(raw.decode('utf-8','strict'))
if set(request)!={'method','path','host','headers','body_hex'}: raise ValueError('request_schema')
if request['method']!='POST' or request['path']!=PATH or request['host']!=HOST: raise ValueError('request_target')
if request['headers'].get('Host')!=HOST or any(k.casefold() in ('authorization','cookie') or k.casefold().startswith('proxy-') for k in request['headers']): raise ValueError('sensitive_header')
body=bytes.fromhex(request['body_hex']); parsed=json.loads(body.decode('utf-8','strict'))
if not isinstance(parsed,dict) or parsed.get('model')!=MODEL: raise ValueError('request_model')
c.sendall(json.dumps({'status':200,'body_hex':RESPONSE.hex()},sort_keys=True,separators=(',',':')).encode('utf-8')); c.close(); s.close()
""" % (SEALED_LOOPBACK_AUTHORITY, BROKER_REQUEST_PATH, CUSTOM_PROVIDER_ID, full_turn_fixture_bytes())).encode("utf-8")

RELAY_CODEX_CHILD_CODE = ("""import base64,hashlib,json,os,queue,re,socket,stat,subprocess,sys,threading,time,zlib
HOST=%r; PORT=%d; AUTHORITY=%r; PATH=%r; MODEL=%r; PROMPT=%r; INPUT=%r; MARKER=%r; LAST_MESSAGE=%r; ARGV=%r; TOKEN_ENV=%r; CONFIG=%r; CONFIG_HASH=%r; DEADLINE=%d; WARNING=%d; JSONL_MAX=%d; EVENT_TYPES=%r; FORBIDDEN_ITEMS=%r; USAGE_FIELDS=%r; CHILD_SCHEMA=json.loads(zlib.decompress(base64.b85decode(%r))); PINNED_KEYS=%r; REQUIRED_KEYS=%r; SEALED_KEYS=%r; INCLUDE_SEQUENCE=%r; WIRE_RESPONSE=%r; HTTP_RESPONSE_PREFIX=%r; IMPL=sys.argv[1] if len(sys.argv)==2 else ''
def canon(v): return json.dumps(v,ensure_ascii=True,sort_keys=True,separators=(',',':')).encode('utf-8')
 INPUT_ITEM_ALLOWED={'type','role','content','id','phase','internal_chat_message_metadata_passthrough'}
 INPUT_PHASES={'commentary','final_answer'}
 def inspect_input(value):
  shape={'item_count':len(value) if isinstance(value,list) else 0,'item_type_ids':[],'item_key_presence_masks':[],'role_ids':[],'content_type_ids':[],'content_counts':[],'text_byte_counts':[],'text_sha256s':[],'shape_hash':''}
  def finish(reason):
   shape['shape_hash']=hashlib.sha256(canon({k:shape[k] for k in sorted(shape) if k!='shape_hash'})).hexdigest(); return shape,reason
  if not isinstance(value,list): return finish('input_not_array')
  if len(value)!=3: return finish('input_count')
  roles=('developer','user','user')
  for index,item in enumerate(value):
   if not isinstance(item,dict): return finish('input_item_schema')
   typ=item.get('type'); shape['item_type_ids'].append(typ if typ=='message' else 'unknown')
   shape['item_key_presence_masks'].append(sum(1<<i for i,k in enumerate(('type','role','content','id','phase','internal_chat_message_metadata_passthrough')) if k in item))
   if typ!='message': return finish('input_item_type')
   if set(item)-INPUT_ITEM_ALLOWED or any(k not in item for k in ('type','role','content')): return finish('input_item_schema')
   role=item.get('role'); shape['role_ids'].append(role if role in ('developer','user') else 'unknown')
   if role!=roles[index]: return finish('input_role')
   if 'id' in item and not isinstance(item['id'],str): return finish('input_item_schema')
   if 'phase' in item and item['phase'] not in INPUT_PHASES: return finish('input_item_schema')
   metadata=item.get('internal_chat_message_metadata_passthrough')
   if metadata is not None and (not isinstance(metadata,dict) or set(metadata)-{'turn_id'} or ('turn_id' in metadata and not isinstance(metadata['turn_id'],str))): return finish('input_item_schema')
   content=item.get('content')
   if not isinstance(content,list) or not content or len(content)>16: return finish('input_content_type')
   shape['content_counts'].append(len(content))
   for part in content:
    if not isinstance(part,dict): return finish('input_content_type')
    ctyp=part.get('type'); shape['content_type_ids'].append(ctyp if ctyp=='input_text' else 'unknown')
    if ctyp!='input_text': return finish('input_content_type')
    if set(part)!={'type','text'}: return finish('input_item_schema')
    text=part.get('text')
    if not isinstance(text,str): return finish('input_text')
    try: encoded=text.encode('utf-8','strict')
    except UnicodeEncodeError: return finish('input_text')
    shape['text_byte_counts'].append(len(encoded)); shape['text_sha256s'].append(hashlib.sha256(encoded).hexdigest())
    if not encoded or len(encoded)>65536: return finish('input_text')
  if shape['text_sha256s'][-1]!=hashlib.sha256(PROMPT).hexdigest(): return finish('input_prompt_hash')
  return finish(None)
 def category(exit_code,stderr):
  if exit_code==2: return 'CLI_USAGE_ERROR'
  lowered=stderr.lower()
  if b'strict' in lowered and b'config' in lowered: return 'STRICT_CONFIG_ERROR'
  if b'model provider' in lowered or b'provider' in lowered and b'not found' in lowered: return 'PROVIDER_MISSING'
  if b'environment' in lowered and (b'missing' in lowered or b'not set' in lowered): return 'AUTH_ENV_MISSING'
  if b'config' in lowered and (b'invalid' in lowered or b'parse' in lowered): return 'CONFIG_INVALID'
  return 'CHILD_EXIT_OTHER'
 def seal_event_observation(events,counts):
  return hashlib.sha256(canon({'event_types':events,'event_counts':counts})).hexdigest()
 def parse_jsonl(data):
  global event_types,event_counts,event_sequence_hash,tool_event_count,jsonl_parse_error,jsonl_marker_match,observed_usage
  global agent_message_count,output_byte_count,output_sha256
  events=[]; counts={}; tool_count=0; parse_error=None; marker_match=False; agent_messages=0; output_bytes=0; output_digest=None
  turn_completed_bytes_seen=b'turn.completed' in data
  if len(data)>JSONL_MAX: parse_error='output_limit'; parse_data=b''
  elif data and not data.endswith(b'\\n'):
   parse_error='jsonl_final_line_incomplete'; split=data.rfind(b'\\n'); parse_data=data[:split+1] if split>=0 else b''
  else: parse_data=data
  try: lines=parse_data.decode('utf-8','strict').splitlines()
  except Exception: lines=[]; parse_error='jsonl_turn_completed_schema_invalid' if turn_completed_bytes_seen else 'jsonl_invalid'
  if parse_error is None and any(not line.strip() for line in lines): parse_error='jsonl_invalid'
  for line in lines:
   if parse_error is not None: break
   try: event=json.loads(line)
   except Exception:
    parse_error='jsonl_turn_completed_schema_invalid' if turn_completed_bytes_seen else 'jsonl_invalid'; break
   if not isinstance(event,dict) or set(event)-{'type','thread_id','turn_id','item','usage','error','message'}:
    parse_error='jsonl_turn_completed_schema_invalid' if isinstance(event,dict) and event.get('type')=='turn.completed' else 'jsonl_invalid'; break
   kind=event.get('type')
   if kind not in EVENT_TYPES: parse_error='jsonl_invalid'; break
   if kind=='turn.completed':
    usage=event.get('usage')
    if set(event)!={'type','usage'} or not isinstance(usage,dict) or set(usage)!=set(USAGE_FIELDS) or any(isinstance(value,bool) or not isinstance(value,int) or value<0 for value in usage.values()):
     parse_error='jsonl_turn_completed_schema_invalid'; break
    observed_usage=dict(usage)
   events.append(kind); counts[kind]=counts.get(kind,0)+1
   item=event.get('item') if isinstance(event.get('item'),dict) else None
   if item is not None and item.get('type') in FORBIDDEN_ITEMS: tool_count+=1
   if kind=='item.completed' and item is not None and item.get('type')=='agent_message':
    agent_messages+=1
    if agent_messages>1: parse_error='jsonl_agent_message_duplicate'; break
    text=item.get('text')
    if not isinstance(text,str): parse_error='jsonl_output_mismatch'; break
    try: encoded=text.encode('utf-8','strict')
    except UnicodeEncodeError: parse_error='jsonl_output_mismatch'; break
    output_bytes=len(encoded); output_digest=hashlib.sha256(encoded).hexdigest(); marker_match=output_digest==hashlib.sha256(MARKER).hexdigest(); text=None
    if not marker_match: parse_error='jsonl_output_mismatch'; break
  if parse_error is None and not events: parse_error='cli_no_event_exit'
  elif parse_error is None and counts.get('turn.completed',0)==0: parse_error='jsonl_terminal_event_missing'
  elif parse_error is None and counts.get('turn.completed',0)!=1: parse_error='jsonl_turn_completed_schema_invalid'
  elif parse_error is None and agent_messages==0: parse_error='jsonl_agent_message_missing'
  elif parse_error is None and agent_messages!=1: parse_error='jsonl_agent_message_duplicate'
  elif parse_error is None and (output_digest is None or not marker_match): parse_error='jsonl_output_mismatch'
  event_types=list(events); event_counts=dict(counts); event_sequence_hash=seal_event_observation(events,counts)
  tool_event_count=tool_count; jsonl_parse_error=parse_error; jsonl_marker_match=bool(marker_match); agent_message_count=agent_messages; output_byte_count=output_bytes; output_sha256=output_digest
  return parse_error
 def drain_pipe(pipe,name):
  state=stream_state[name]
  try:
   while True:
    chunk=pipe.read(4096)
    if not chunk: break
    if not isinstance(chunk,bytes): raise TypeError('pipe_chunk')
    state['bytes']+=len(chunk); state['hash'].update(chunk)
    remaining=max(0,JSONL_MAX-len(state['buffer']))
    if remaining: state['buffer'].extend(chunk[:remaining])
    if state['bytes']>JSONL_MAX: state['overflow']=True
   state['eof']=True
  except BaseException:
   state['error']=True
  finally:
   try: pipe.close()
   except BaseException: pass
 def start_codex_readers():
  global stdout_reader,stderr_reader
  stdout_reader=threading.Thread(target=drain_pipe,args=(codex.stdout,'stdout'),daemon=True)
  stderr_reader=threading.Thread(target=drain_pipe,args=(codex.stderr,'stderr'),daemon=True)
  stdout_reader.start(); stderr_reader.start()
 def collect_codex_observations(timeout=None):
  global observations_collected,codex_exit_code,stderr_byte_count,stderr_sha256,stderr_category
  global last_message_exists,last_message_regular,last_message_size,last_message_sha256,last_message_match,last_message_marker_match,last_message_error,marker_match
  global codex_stdout_bytes,codex_stdout_sha256,codex_stdout_terminal_newline,stdout_eof,stderr_eof,readers_joined,jsonl_parse_error
  if observations_collected or codex is None: return observations_collected
  deadline=None if timeout is None else time.monotonic()+max(0,timeout)
  try:
   if codex.poll() is None: codex.wait(timeout=None if deadline is None else max(0,deadline-time.monotonic()))
  except subprocess.TimeoutExpired: return False
  except Exception: return False
  for reader in (stdout_reader,stderr_reader):
   if reader is None: return False
   reader.join(timeout=None if deadline is None else max(0,deadline-time.monotonic()))
   if reader.is_alive(): return False
  readers_joined=True
  stdout_eof=bool(stream_state['stdout']['eof'] and not stream_state['stdout']['error'])
  stderr_eof=bool(stream_state['stderr']['eof'] and not stream_state['stderr']['error'])
  out=bytes(stream_state['stdout']['buffer']); err=bytes(stream_state['stderr']['buffer'])
  codex_exit_code=codex.returncode; stderr_byte_count=stream_state['stderr']['bytes']; stderr_sha256=stream_state['stderr']['hash'].hexdigest()
  stderr_category=category(codex_exit_code,err) if codex_exit_code not in (None,0) or err else None
  codex_stdout_bytes=stream_state['stdout']['bytes']; codex_stdout_sha256=stream_state['stdout']['hash'].hexdigest(); codex_stdout_terminal_newline=out.endswith(b'\\n')
  if not stdout_eof or not stderr_eof: jsonl_parse_error='response_proof_invalid'
  elif stream_state['stdout']['overflow']: jsonl_parse_error='output_limit'
  else: parse_jsonl(out)
  stream_state['stdout']['buffer'].clear(); stream_state['stderr']['buffer'].clear(); out=b''; err=b''
  try:
   message_stat=os.lstat(LAST_MESSAGE); last_message_exists=True; last_message_size=int(message_stat.st_size)
   if stat.S_ISLNK(message_stat.st_mode): last_message_error='codex_final_message_symlink'
   elif not stat.S_ISREG(message_stat.st_mode): last_message_error='codex_final_message_mismatch'
   elif last_message_size>4096: last_message_error='codex_final_message_oversize'
   else:
    last_message_regular=True
    with open(LAST_MESSAGE,'rb') as fp: message=fp.read(4097)
    if len(message)>4096: last_message_error='codex_final_message_oversize'
    else:
     last_message_sha256=hashlib.sha256(message).hexdigest(); last_message_match=message==MARKER; last_message_marker_match=last_message_match
     if not last_message_match: last_message_error='codex_final_message_mismatch'
    message=None
  except FileNotFoundError: last_message_error='codex_final_message_missing'
  except Exception: last_message_regular=False; last_message_match=False; last_message_marker_match=False; last_message_sha256=None; last_message_error='codex_final_message_mismatch'
  marker_match=bool(agent_message_count==1 and output_byte_count>0 and output_sha256==hashlib.sha256(MARKER).hexdigest() and last_message_exists and last_message_regular and last_message_match and last_message_sha256==output_sha256)
  observations_collected=True
  return True
 def emit_relay_boot():
  payload={'stage':'CHILD_START','implementation_hash':IMPL}
  frame=b'CODEXGATE_RELAY_BOOT_V1:'+base64.urlsafe_b64encode(canon(payload)).rstrip(b'=')+b'\\n'
  if os.write(2,frame)!=len(frame): os._exit(1)
 terminal_frame_written=False; sealed_terminal_payload=None
 def build_terminal_child_payload():
  payload={'schema_version':CHILD_SCHEMA['version'],'stage':control_stage,'error_code':control_error,'spawn_confirmed':bool(spawn_confirmed),'process_counts':{'codex_cli':int(bool(spawn_confirmed))},'cleanup_ok':bool(cleanup_ok),'implementation_hash':IMPL,'codex_exit_code':codex_exit_code,'event_types':event_types,'event_counts':event_counts,'event_sequence_hash':event_sequence_hash,'tool_event_count':tool_event_count,'usage':observed_usage,'stdout_sha256':codex_stdout_sha256,'stderr_byte_count':stderr_byte_count,'stderr_sha256':stderr_sha256,'stderr_category':stderr_category,'agent_message_count':agent_message_count,'output_byte_count':output_byte_count,'output_sha256':output_sha256,'last_message_exists':last_message_exists,'last_message_regular':last_message_regular,'last_message_size':last_message_size,'last_message_sha256':last_message_sha256,'last_message_match':last_message_match,'last_message_marker_match':last_message_marker_match,'marker_match':marker_match,'request_seen':request_seen,'request_validated':request_validated,'response_sent':response_sent,'accepted_post':accepted_post,'request_hash':globals().get('request_hash'),'sensitive_headers_removed':bool(globals().get('sensitive_headers_removed',False)),'removed_count':int(globals().get('removed_count',0)),'post_filter_count':int(globals().get('post_filter_count',0)),'response_byte_count':response_byte_count,'response_sha256':response_sha256,'eof_stdout_drained':stdout_eof,'eof_stderr_drained':stderr_eof,'readers_joined':readers_joined,'strict_http_reject_reason':globals().get('strict_http_reject_reason'),'request_header_count':globals().get('request_header_count',0),'request_body_bytes':globals().get('request_body_bytes',0),'request_body_sha256':globals().get('request_body_sha256',hashlib.sha256(b'').hexdigest()),'request_json_keyset_hash':globals().get('request_json_keyset_hash'),'input_shape':globals().get('input_shape')}
  if set(payload)!=set(CHILD_SCHEMA['fields']): raise ValueError('child_schema_builder_invalid')
  return payload
 def seal_terminal_child_proof():
  global sealed_terminal_payload
  if sealed_terminal_payload is None: sealed_terminal_payload=json.loads(canon(build_terminal_child_payload()).decode('utf-8'))
  return dict(sealed_terminal_payload)
 def emit_terminal_child_frame():
  global terminal_frame_written
  if terminal_frame_written: return
  payload=seal_terminal_child_proof(); payload['cleanup_ok']=bool(cleanup_ok)
  terminal_frame_written=True
  frame=b'CODEXGATE_CODEX_CHILD_V1:'+base64.urlsafe_b64encode(canon(payload)).rstrip(b'=')+b'\\n'
  try:
   if os.write(1,frame)!=len(frame): os._exit(1)
  except BaseException:
   os._exit(1)
 emit_relay_boot()
def emit(status,substage,error=None,request_hash=None,response_hash=None,output_hash=None,sensitive=None,codex_cli=0,delay=0,stderr=b'',exit_category=None,request_seen=None,request_validated=None,response_sent=None,stdout_bytes=0,stdout_sha256=None,stdout_terminal_newline=False,jsonl_event_types=None,jsonl_event_counts=None,jsonl_stream_sha256=None,codex_exit_code=None):
 global control_error,control_stage
 if request_seen is None: request_seen=globals().get('request_seen',0)
 if request_validated is None: request_validated=globals().get('request_validated',0)
 if response_sent is None: response_sent=globals().get('response_sent',0)
 if response_hash is None and response_sent: response_hash=globals().get('response_sha256')
 control_error=error; control_stage={'CONFIG_VALIDATE':'SPEC_VALIDATE','CODEX_HOME_PREPARE':'ENV_VALIDATE','SOCKET_VALIDATE':'ENV_VALIDATE','LOOPBACK_BIND':'ENV_VALIDATE','LOOPBACK_LISTEN':'ENV_VALIDATE','READY_EMIT':'ENV_VALIDATE','CODEX_SPAWN':'CHILD_EXIT','LOOPBACK_ACCEPT':'ENDPOINT_WAIT','BROKER_SOCKET_CONNECT':'ENDPOINT_WAIT'}.get(substage,control_stage)
 if jsonl_event_types is None: jsonl_event_types=globals().get('jsonl_event_types')
 if jsonl_event_counts is None: jsonl_event_counts=globals().get('jsonl_event_counts')
 if jsonl_stream_sha256 is None: jsonl_stream_sha256=globals().get('jsonl_stream_sha256')
 if codex_exit_code is None: codex_exit_code=globals().get('codex_exit_code')
 payload={'status':status,'substage':substage,'error_code':error,'codex_cli':codex_cli,'request_seen':request_seen,'request_validated':request_validated,'response_sent':response_sent,'accepted_post':globals().get('accepted_post',0),'request_hash':request_hash if request_hash is not None else globals().get('request_hash'),'response_hash':response_hash,'response_byte_count':globals().get('response_byte_count',0),'output_hash':output_hash,'sensitive_headers_removed':bool(globals().get('sensitive_headers_removed',False) if sensitive is None else sensitive),'removed_count':int(globals().get('removed_count',0)),'post_filter_count':int(globals().get('post_filter_count',0)),'codex_stdout_bytes':int(stdout_bytes),'codex_stdout_sha256':stdout_sha256,'codex_stdout_terminal_newline':bool(stdout_terminal_newline),'eof_stdout_drained':globals().get('stdout_eof',False),'eof_stderr_drained':globals().get('stderr_eof',False),'readers_joined':globals().get('readers_joined',False),'usage':globals().get('observed_usage'),'event_types':globals().get('event_types',[]),'event_counts':globals().get('event_counts',{}),'event_sequence_hash':globals().get('event_sequence_hash'),'tool_event_count':globals().get('tool_event_count',0),'agent_message_count':globals().get('agent_message_count',0),'output_byte_count':globals().get('output_byte_count',0),'output_sha256':globals().get('output_sha256'),'last_message_exists':globals().get('last_message_exists',False),'last_message_regular':globals().get('last_message_regular',False),'last_message_size':globals().get('last_message_size',0),'last_message_sha256':globals().get('last_message_sha256'),'last_message_match':globals().get('last_message_match',False),'last_message_marker_match':globals().get('last_message_marker_match',False),'marker_match':globals().get('marker_match',False),'codex_exit_code':codex_exit_code,'connection_delay_ms':int(delay),'connection_delay_warning':bool(delay>=WARNING),'stderr_byte_count':globals().get('stderr_byte_count',len(stderr)),'stderr_sha256':globals().get('stderr_sha256',hashlib.sha256(stderr).hexdigest()),'stderr_category':globals().get('stderr_category',exit_category),'prompt_mode':'STDIN_FORCED','config_loaded_expected':True,'argc':len(ARGV),'strict_http_reject_reason':globals().get('strict_http_reject_reason'),'request_header_count':globals().get('request_header_count',0),'request_body_bytes':globals().get('request_body_bytes',0),'request_body_sha256':globals().get('request_body_sha256',hashlib.sha256(b'').hexdigest()),'request_json_keyset_hash':globals().get('request_json_keyset_hash'),'input_shape':globals().get('input_shape')}
 os.write(2,b'CODEXGATE_CODEX_RELAY_V1:'+base64.urlsafe_b64encode(canon(payload)).rstrip(b'=')+b'\\n')
listener=None; codex=None; substage='CHILD_START'; control_stage='SPEC_VALIDATE'; control_error=None; cleanup_ok=False; request_seen=0; request_validated=0; response_sent=0; accepted_post=0; request_hash=None; sensitive_headers_removed=False; removed_count=0; post_filter_count=0; response_byte_count=0; response_sha256=hashlib.sha256(b'').hexdigest(); event_types=[]; event_counts={}; event_sequence_hash=seal_event_observation([],{}); tool_event_count=0; observed_usage=None; jsonl_parse_error=None; jsonl_marker_match=False; agent_message_count=0; output_byte_count=0; output_sha256=None; codex_exit_code=None; spawn_confirmed=False; observations_collected=False; stderr_byte_count=0; stderr_sha256=hashlib.sha256(b'').hexdigest(); stderr_category=None; codex_stdout_bytes=0; codex_stdout_sha256=hashlib.sha256(b'').hexdigest(); codex_stdout_terminal_newline=False; stdout_eof=False; stderr_eof=False; readers_joined=False; strict_http_reject_reason=None; input_shape=None; request_header_count=0; request_body_bytes=0; request_body_sha256=hashlib.sha256(b'').hexdigest(); request_json_keyset_hash=None; stdout_reader=None; stderr_reader=None; stream_state={name:{'buffer':bytearray(),'bytes':0,'hash':hashlib.sha256(),'overflow':False,'eof':False,'error':False} for name in ('stdout','stderr')}; last_message_exists=False; last_message_regular=False; last_message_size=0; last_message_sha256=None; last_message_match=False; last_message_marker_match=False; last_message_error=None; marker_match=False
try:
 substage='LOOPBACK_BIND'
 try:
  listener=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
  listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); listener.bind((HOST,PORT))
 except Exception:
  emit('ERROR','LOOPBACK_BIND','loopback_bind_failed'); sys.exit(0)
 try:
  substage='LOOPBACK_LISTEN'
  listener.listen(1); listener.settimeout(None)
 except Exception:
  emit('ERROR','LOOPBACK_LISTEN','loopback_listen_failed'); sys.exit(0)
 substage='ENV_VALIDATE'
 codex_home=os.environ.get('CODEX_HOME','')
 config_source='/runtime/sealed/config.toml'; config_path=os.path.join(codex_home,'config.toml')
 try:
  if not os.path.isdir(codex_home) or stat.S_IMODE(os.stat(codex_home).st_mode)!=0o700: raise ValueError('codex_home_mode_invalid')
 except Exception:
  emit('ERROR','CODEX_HOME_PREPARE','codex_home_mode_invalid',exit_category='CODEX_HOME_WRITE_FAILED'); sys.exit(0)
 try:
  with open(config_source,'rb') as fp: config_bytes=fp.read()
 except Exception:
  emit('ERROR','CONFIG_VALIDATE','codex_config_missing',exit_category='CONFIG_LOAD_FAILED'); sys.exit(0)
 if config_bytes!=CONFIG or hashlib.sha256(config_bytes).hexdigest()!=CONFIG_HASH:
  emit('ERROR','CONFIG_VALIDATE','codex_config_invalid',exit_category='CONFIG_LOAD_FAILED'); sys.exit(0)
 if b'model_provider = "'+MODEL.encode('ascii')+b'"\\n' not in config_bytes or b'base_url = "http://'+AUTHORITY.encode('ascii')+b'/v1"\\n' not in config_bytes or b'env_key = "'+TOKEN_ENV.encode('ascii')+b'"\\n' not in config_bytes:
  emit('ERROR','CONFIG_VALIDATE','codex_config_provider_invalid',exit_category='CONFIG_LOAD_FAILED'); sys.exit(0)
 substage='CODEX_HOME_PREPARE'
 try:
  fd=os.open(config_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600); fp=os.fdopen(fd,'wb'); fp.write(config_bytes); fp.flush(); os.fsync(fp.fileno()); fp.close(); os.chmod(config_path,0o600)
 except Exception:
  emit('ERROR','CODEX_HOME_PREPARE','config_copy_failed',exit_category='CODEX_HOME_WRITE_FAILED'); sys.exit(0)
 try:
  tmp_path=os.path.join(codex_home,'tmp'); os.mkdir(tmp_path,0o700); os.chmod(tmp_path,0o700)
  arg0_path=os.path.join(tmp_path,'arg0'); os.mkdir(arg0_path,0o700); os.chmod(arg0_path,0o700)
  if stat.S_IMODE(os.stat(tmp_path).st_mode)!=0o700 or stat.S_IMODE(os.stat(arg0_path).st_mode)!=0o700 or os.path.exists(os.path.join(codex_home,'arg0')): raise ValueError('arg0_init_failed')
 except Exception:
  emit('ERROR','CODEX_HOME_PREPARE','arg0_init_failed',exit_category='ARG0_INIT_FAILED'); sys.exit(0)
 try:
  probe=os.path.join(codex_home,'.codexgate-write-probe'); fd=os.open(probe,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600); os.write(fd,b'1'); os.fsync(fd); os.close(fd); os.unlink(probe)
  dirfd=os.open(codex_home,os.O_RDONLY|os.O_DIRECTORY); os.fsync(dirfd); os.close(dirfd)
  with open(config_path,'rb') as fp: copied_config=fp.read()
  if copied_config!=config_bytes or hashlib.sha256(copied_config).hexdigest()!=CONFIG_HASH or stat.S_IMODE(os.stat(config_path).st_mode)!=0o600: raise ValueError('config_copy_invalid')
 except Exception:
  emit('ERROR','CODEX_HOME_PREPARE','codex_home_write_probe_failed',exit_category='CODEX_HOME_WRITE_FAILED'); sys.exit(0)
 substage='SOCKET_VALIDATE'
 broker_socket='/runtime/broker/broker.sock'; broker_stat=os.lstat(broker_socket)
 if not stat.S_ISSOCK(broker_stat.st_mode) or not os.access(broker_socket,os.R_OK|os.W_OK):
  emit('ERROR','SOCKET_VALIDATE','broker_socket_invalid'); sys.exit(0)
 substage='READY_EMIT'; emit('READY','READY_EMIT')
 substage='CODEX_SPAWN'; control_stage='SPAWN_CALL'
 if ARGV.count('--json')!=1 or ARGV.count('--strict-config')!=1 or ARGV.count('--output-last-message')!=1:
  emit('ERROR','CODEX_SPAWN','codex_argv_invalid'); sys.exit(0)
 token=os.urandom(32).hex(); env={'PATH':'/usr/bin:/bin','HOME':'/home/codex','TMPDIR':'/tmp','LANG':'C.UTF-8','CODEX_HOME':os.environ['CODEX_HOME'],TOKEN_ENV:token}
 try:
  codex=subprocess.Popen(['/runtime/codex',*ARGV],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env)
 except FileNotFoundError:
  emit('ERROR','CODEX_SPAWN','codex_binary_missing'); sys.exit(0)
 except PermissionError:
  emit('ERROR','CODEX_SPAWN','codex_permission_denied'); sys.exit(0)
 except Exception:
  emit('ERROR','CODEX_SPAWN','codex_spawn_os_error'); sys.exit(0)
 spawn_confirmed=True; control_stage='SPAWN_CONFIRMED'; start_codex_readers()
 try:
  control_stage='STDIN_WRITE'
  codex.stdin.write(PROMPT); codex.stdin.flush(); codex.stdin.close(); codex.stdin=None
 except Exception:
  emit('ERROR','CODEX_SPAWN','codex_prompt_delivery_failed',codex_cli=1); sys.exit(0)
 control_stage='STDIN_CLOSE'; started=time.monotonic(); events=queue.Queue(); substage='LOOPBACK_ACCEPT'; control_stage='ENDPOINT_WAIT'
 def await_accept():
  try: events.put(('ACCEPT',listener.accept()))
  except Exception: events.put(('ACCEPT_ERROR',None))
 def await_exit():
  try: events.put(('EXIT',codex.wait()))
  except Exception: events.put(('EXIT_ERROR',None))
 threading.Thread(target=await_accept,daemon=True).start(); threading.Thread(target=await_exit,daemon=True).start()
 try: event,value=events.get(timeout=DEADLINE)
 except queue.Empty:
  emit('ERROR','LOOPBACK_ACCEPT','codex_endpoint_not_reached',codex_cli=1,delay=round((time.monotonic()-started)*1000)); sys.exit(0)
 delay=round((time.monotonic()-started)*1000)
 if event=='EXIT':
  codex_exit_code=value; collect_codex_observations(); control_stage='CHILD_EXIT'
  error='codex_spawned_early_exit' if value!=0 else (jsonl_parse_error or 'provider_endpoint_not_reached')
  emit('ERROR','CODEX_SPAWN',error,codex_cli=1,delay=delay,stdout_bytes=codex_stdout_bytes,stdout_sha256=codex_stdout_sha256,stdout_terminal_newline=codex_stdout_terminal_newline,codex_exit_code=codex_exit_code); sys.exit(0)
 if event!='ACCEPT':
  emit('ERROR','LOOPBACK_ACCEPT','loopback_accept_failed',codex_cli=1,delay=delay); sys.exit(0)
 conn,_=value; request_seen=1; raw=conn.recv(8192)
 def reject_http(reason):
  global strict_http_reject_reason
  strict_http_reject_reason=reason; emit('POLICY_VIOLATION','LOOPBACK_ACCEPT','strict_http_rejected',codex_cli=1); sys.exit(0)
 while b'\\r\\n\\r\\n' not in raw and len(raw)<=8192:
  chunk=conn.recv(8192)
  if not chunk: break
  raw+=chunk
 if len(raw)>262144 or b'\\r\\n\\r\\n' not in raw: reject_http('body_size')
 head,body=raw.split(b'\\r\\n\\r\\n',1); lines=head.decode('ascii','strict').split('\\r\\n')
 request_header_count=max(0,len(lines)-1)
 if not lines: reject_http('request_line')
 if lines[0].split(' ')[0] != 'POST': reject_http('method')
 if len(lines[0].split(' ')) < 2 or lines[0].split(' ')[1] != PATH: reject_http('path')
 if lines[0] != ('POST '+PATH+' HTTP/1.1'): reject_http('request_line')
 headers={}; header_names=set()
 for line in lines[1:]:
  if ':' not in line: reject_http('request_line')
  name,value=line.split(':',1); key=name.casefold()
  if key in header_names: reject_http('duplicate_header')
  header_names.add(key)
  if key=='host':
   if not value.startswith(' ') or value.startswith('  ') or value.endswith(' '): reject_http('host')
   headers[name]=value[1:]
  else: headers[name]=value.strip()
 normalized={}; seen=set()
 for name,value in headers.items():
  key=name.casefold()
  if key in seen: reject_http('duplicate_header')
  seen.add(key); normalized[{'host':'Host','content-length':'Content-Length'}.get(key,name)]=value
 headers=normalized
 if headers.get('Host')!=AUTHORITY: reject_http('host')
 try: content_length=int(headers.get('Content-Length','-1'))
 except (TypeError,ValueError): reject_http('content_length')
 while len(body)<content_length and len(body)<=262144:
  chunk=conn.recv(min(8192,content_length-len(body)))
  if not chunk: break
  body+=chunk
 if content_length!=len(body) or content_length<0 or content_length>262144: reject_http('content_length')
 request_body_bytes=len(body); request_body_sha256=hashlib.sha256(body).hexdigest()
 try: parsed=json.loads(body.decode('utf-8','strict'))
 except Exception: reject_http('json_decode')
 if not isinstance(parsed,dict): reject_http('json_schema')
 request_json_keyset_hash=hashlib.sha256(canon(sorted(parsed))).hexdigest()
 if set(parsed)-set(PINNED_KEYS): reject_http('unknown_field')
 if not set(REQUIRED_KEYS).issubset(parsed): reject_http('json_schema')
 if 'instructions' in parsed and not isinstance(parsed['instructions'],str): reject_http('json_schema')
 for _field in ('service_tier','prompt_cache_key'):
  if _field in parsed and parsed[_field] is not None and not isinstance(parsed[_field],str): reject_http('json_schema')
 if 'reasoning' in parsed and parsed['reasoning'] is not None:
  if not isinstance(parsed['reasoning'],dict) or not set(parsed['reasoning']).issubset({'effort','summary','context'}): reject_http('json_schema')
 if 'stream_options' in parsed and parsed['stream_options'] is not None:
  _options=parsed['stream_options']
  if not isinstance(_options,dict) or set(_options)!={'reasoning_summary_delivery'} or _options.get('reasoning_summary_delivery')!='sequential_cutoff': reject_http('json_schema')
 if 'text' in parsed and parsed['text'] is not None:
  _text=parsed['text']
  if not isinstance(_text,dict) or not set(_text).issubset({'verbosity','format'}): reject_http('json_schema')
 if 'client_metadata' in parsed and parsed['client_metadata'] is not None:
  _metadata=parsed['client_metadata']
  if not isinstance(_metadata,dict) or any(not isinstance(_k,str) or not isinstance(_v,str) for _k,_v in _metadata.items()): reject_http('json_schema')
 if parsed.get('model')!=MODEL: reject_http('model')
 if parsed.get('stream') is not True: reject_http('stream')
 if parsed.get('store') is not False: reject_http('store')
 if (not isinstance(parsed.get('include'),list) or any(not isinstance(value,str) for value in parsed['include']) or len(parsed['include'])!=len(set(parsed['include'])) or parsed['include']!=list(INCLUDE_SEQUENCE)): reject_http('include')
 input_shape,input_reason=inspect_input(parsed.get('input'))
 if input_reason is not None: reject_http(input_reason)
 request_validated=1; accepted_post=1
 request_hash=hashlib.sha256(canon(parsed)).hexdigest()
 forbidden=lambda k: k.casefold() in ('authorization','cookie') or k.casefold().startswith('proxy-')
 clean={k:v for k,v in headers.items() if not forbidden(k)}
 removed_count=sum(1 for k in headers if forbidden(k) and k not in clean); post_filter_count=sum(1 for k in clean if forbidden(k)); sensitive_headers_removed=(post_filter_count==0)
 if post_filter_count: emit('POLICY_VIOLATION','LOOPBACK_ACCEPT','sensitive_header_proof_invalid',codex_cli=1); sys.exit(0)
 try:
  upstream=socket.socket(socket.AF_UNIX); upstream.connect('/runtime/broker/broker.sock')
 except Exception:
  emit('ERROR','BROKER_SOCKET_CONNECT','broker_socket_connect_failed',codex_cli=1); sys.exit(0)
 upstream.sendall(canon({'method':'POST','path':PATH,'host':AUTHORITY,'headers':clean,'body_hex':body.hex()})); upstream.shutdown(socket.SHUT_WR); reply=upstream.recv(2097153); upstream.close()
 if len(reply)>2097152: emit('POLICY_VIOLATION','BROKER_SOCKET_CONNECT','response_limit',codex_cli=1); sys.exit(0)
 broker_reply=json.loads(reply.decode('utf-8','strict'))
 if not isinstance(broker_reply,dict) or set(broker_reply)!={'status','body_hex'} or broker_reply.get('status')!=200: emit('POLICY_VIOLATION','BROKER_SOCKET_CONNECT','response_proof_invalid',codex_cli=1); sys.exit(0)
 response=bytes.fromhex(broker_reply['body_hex'])
 if response!=WIRE_RESPONSE: emit('POLICY_VIOLATION','BROKER_SOCKET_CONNECT','response_proof_invalid',codex_cli=1); sys.exit(0)
 envelope=HTTP_RESPONSE_PREFIX+WIRE_RESPONSE
 conn.sendall(envelope); conn.shutdown(socket.SHUT_WR); response_byte_count=len(response); response_sha256=hashlib.sha256(response).hexdigest(); response_sent=1
 conn.settimeout(max(0.1,DEADLINE-(time.monotonic()-started)))
 while True:
  trailing=conn.recv(4096)
  if not trailing: break
  emit('POLICY_VIOLATION','LOOPBACK_ACCEPT','request_limit',codex_cli=1); sys.exit(0)
 conn.close(); listener.close()
 remaining=max(0.1,DEADLINE-(time.monotonic()-started))
 try:
  if not collect_codex_observations(timeout=remaining): raise subprocess.TimeoutExpired('codex',remaining)
 except subprocess.TimeoutExpired:
  emit('ERROR','CODEX_SPAWN','codex_completion_timeout',codex_cli=1,delay=delay); sys.exit(0)
 if jsonl_parse_error is not None: emit('ERROR','CODEX_SPAWN',jsonl_parse_error,codex_cli=1); sys.exit(0)
 if event_counts.get('turn.completed',0)==1 and (agent_message_count!=1 or output_byte_count<=0 or output_sha256 is None or last_message_sha256 is None): emit('ERROR','CODEX_SPAWN','output_proof_field_missing',codex_cli=1); sys.exit(0)
 if last_message_error is not None: emit('ERROR','CODEX_SPAWN',last_message_error,codex_cli=1); sys.exit(0)
 if not marker_match: emit('ERROR','CODEX_SPAWN','jsonl_output_mismatch',codex_cli=1); sys.exit(0)
 control_stage='CHILD_EXIT'; emit('PASSED','CODEX_SPAWN',None,request_hash=request_hash,response_hash=response_sha256,output_hash=output_sha256,codex_cli=1,delay=delay,request_seen=request_seen,request_validated=request_validated,response_sent=response_sent,stdout_bytes=codex_stdout_bytes,stdout_sha256=codex_stdout_sha256,stdout_terminal_newline=codex_stdout_terminal_newline,codex_exit_code=codex_exit_code)
except Exception:
 error='relay_child_error'
 if request_seen and not request_validated: error='strict_http_rejected'
 elif request_validated and not response_sent: error='fake_response_not_sent'
 if codex is not None:
  observed_exit=codex.poll()
  if observed_exit is not None:
   codex_exit_code=observed_exit; collect_codex_observations()
   if observed_exit!=0: error='codex_spawned_early_exit'
   else: error=jsonl_parse_error or 'provider_endpoint_not_reached'
 emit('ERROR',substage,error,codex_cli=1 if codex is not None else 0); sys.exit(0)
finally:
 if listener is not None:
  try: listener.close()
  except Exception: pass
 if codex is not None and codex.poll() is None:
  try: codex.terminate()
  except Exception: pass
 try:
  if codex is not None: collect_codex_observations(timeout=3)
 except Exception: pass
 try: seal_terminal_child_proof()
 except Exception:
  control_error='response_proof_invalid'; control_stage='CHILD_EXIT'; seal_terminal_child_proof()
 try: os.unlink(LAST_MESSAGE)
 except FileNotFoundError: pass
 except Exception: pass
 cleanup_ok=(listener is None or getattr(listener,'fileno',lambda:-1)()==-1) and not os.path.lexists(LAST_MESSAGE)
 emit_terminal_child_frame()
  """ % (LOOPBACK_HOST, LOOPBACK_PORT, SEALED_LOOPBACK_AUTHORITY, BROKER_REQUEST_PATH, CUSTOM_PROVIDER_ID, FIXED_PROMPT.encode('utf-8'), FIXED_REQUEST_BODY['input'], SUCCESS_MARKER.encode('utf-8'), CODEX_LAST_MESSAGE_PATH, list(FIXED_CODEX_ARGV), EPHEMERAL_TOKEN_ENV, canonical_provider_toml(), EXPECTED_CONFIG_HASH, CODEX_ENDPOINT_DEADLINE_SECONDS, CODEX_CONNECTION_WARNING_MILLISECONDS, CODEX_JSONL_MAX_BYTES, sorted(CODEX_JSONL_EVENT_TYPES), sorted(CODEX_JSONL_FORBIDDEN_ITEM_TYPES), sorted(CODEX_TURN_COMPLETED_USAGE_FIELDS), CODEX_CHILD_CONTROL_SCHEMA_B85, PINNED_REQUEST_KEYS, PINNED_REQUEST_REQUIRED_KEYS, SEALED_REQUEST_KEYS, PINNED_INCLUDE_SEQUENCE, SEALED_RESPONSE_BODY_BYTES, SEALED_HTTP_RESPONSE_PREFIX)).encode("utf-8")
_relay_lines = RELAY_CODEX_CHILD_CODE.decode("utf-8").splitlines()
_relay_emit_index = _relay_lines.index("def emit(status,substage,error=None,request_hash=None,response_hash=None,output_hash=None,sensitive=None,codex_cli=0,delay=0,stderr=b'',exit_category=None,request_seen=None,request_validated=None,response_sent=None,stdout_bytes=0,stdout_sha256=None,stdout_terminal_newline=False,jsonl_event_types=None,jsonl_event_counts=None,jsonl_stream_sha256=None,codex_exit_code=None):")
for _relay_index in range(3, _relay_emit_index):
    _relay_lines[_relay_index] = _relay_lines[_relay_index][1:]
RELAY_CODEX_CHILD_CODE = ("\n".join(_relay_lines) + "\n").encode("utf-8")

_PYTHON_C_ARGS: tuple[str, ...] = ("/usr/bin/python3", "-I", "-S", "-u", "-c")
BROKER_CHILD_ARGV_TEMPLATE: tuple[str, ...] = BWRAP_COMMON_ARGS + (
    "--tmpfs", "/runtime-state", "--dir", "/runtime", "--dir", "/runtime/broker",
    "--bind", "{EXECUTION_SOCKET_DIR}", "/runtime/broker",
    "--setenv", "HOME", "/home/broker",
) + sealed_bwrap_environment_args() + _PYTHON_C_ARGS + ("{BROKER_CHILD_CODE}",)
RELAY_CODEX_CHILD_ARGV_TEMPLATE: tuple[str, ...] = BWRAP_COMMON_ARGS + (
    "--tmpfs", "/runtime-state", "--dir", "/runtime", "--dir", "/runtime/broker", "--dir", "/runtime/sealed", "--perms", "0700", "--tmpfs", "/runtime/codex-home", "--dir", "/work", "--dir", "/home/codex",
    "--ro-bind", "{EXECUTION_SOCKET_DIR}", "/runtime/broker",
    "--ro-bind", "{FIXTURE_SOURCE}", "/work/fixture.json",
    "--ro-bind", "{SEALED_CONFIG_SOURCE}", "/runtime/sealed/config.toml",
    "--ro-bind", "{CODEX_BINARY}", "/runtime/codex", "--chdir", "/work",
    "--setenv", "HOME", "/home/codex",
    "--setenv", "CODEX_HOME", "/runtime/codex-home",
) + sealed_bwrap_environment_args() + _PYTHON_C_ARGS + ("{RELAY_CODEX_CHILD_CODE}", "{EXECUTOR_IMPLEMENTATION_HASH}")
SUPERVISOR_ARGV_TEMPLATE: tuple[str, ...] = (
    "{WSL_EXECUTABLE}", "-d", "Ubuntu", "--exec", "/usr/bin/python3", "-I", "-S", "-u", "-c",
    "{SUPERVISOR_BOOTSTRAP_CODE}", "{EXECUTOR_IMPLEMENTATION_HASH}",
)


def _template_json(value: Sequence[str]) -> str:
    return json.dumps(list(value), ensure_ascii=True, separators=(",", ":"))


def canonicalize_implementation_input(value: Any) -> Any:
    """Recursively convert seal inputs to one deterministic JSON value."""
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise PolicyError("implementation_hash_input_invalid")
        return {
            key: canonicalize_implementation_input(value[key])
            for key in sorted(value)
        }
    if isinstance(value, (set, frozenset)):
        normalized = [canonicalize_implementation_input(item) for item in value]
        return sorted(normalized, key=canonical_json)
    if isinstance(value, (tuple, list)):
        return [canonicalize_implementation_input(item) for item in value]
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float) and isfinite(value):
        return value
    raise PolicyError("implementation_hash_input_invalid")


def canonical_implementation_json(value: Any) -> str:
    return canonical_json(canonicalize_implementation_input(value))


def implementation_json_hash(value: Any) -> str:
    return hashlib.sha256(canonical_implementation_json(value).encode("utf-8")).hexdigest()


# The fixed supervisor is deliberately a single Python program.  Its only
# variable inputs are the already-claimed UUID and the computed seal hash.
# It creates all socket/config/fixture state below its private temporary root,
# terminates children, removes the root, and emits one sanitized frame.
_SUPERVISOR_SOURCE = "\n".join((
    "import base64,hashlib,json,os,re,shutil,stat,subprocess,sys,tempfile,time,uuid,zlib",
    f"P={SUPERVISOR_FRAME_PREFIX!r}; BOOT={RELAY_BOOT_FRAME_PREFIX!r}; CHILD={CODEX_CHILD_FRAME_PREFIX!r}; BROKER={BROKER_CHILD_CODE!r}; RELAY={RELAY_CODEX_CHILD_CODE!r}",
    f"BT=json.loads({_template_json(BROKER_CHILD_ARGV_TEMPLATE)!r}); RT=json.loads({_template_json(RELAY_CODEX_CHILD_ARGV_TEMPLATE)!r})",
    f"CONFIG={canonical_provider_toml()!r}; WIRE_PROVEN={PINNED_CODEX_WIRE_CONTRACT_PROVEN!r}",
    f"FRAME_SCHEMA=json.loads({canonical_implementation_json(SUPERVISOR_FRAME_SCHEMA)!r}); FRAME_SCHEMA_VERSION=FRAME_SCHEMA['version']; FRAME_FIELDS=set(FRAME_SCHEMA['fields']); FRAME_ERROR_FIELDS=set(FRAME_SCHEMA['error_fields']); FRAME_PASSED_FIELDS=set(FRAME_SCHEMA['passed_fields']); FRAME_STATUSES=set(FRAME_SCHEMA['statuses']); FRAME_STAGES=set(FRAME_SCHEMA['stages']); FRAME_SUBSTAGES=set(FRAME_SCHEMA['substage']); FRAME_ERROR_CODES=set(FRAME_SCHEMA['error_codes']); FRAME_PROCESS_FIELDS=tuple(FRAME_SCHEMA['process_fields']); FRAME_TYPES=set(json.loads({canonical_implementation_json(CODEX_JSONL_EVENT_TYPES)!r})); BOOT_FIELDS=set(json.loads({canonical_implementation_json(RELAY_BOOT_FRAME_FIELDS)!r})); CHILD_SCHEMA=json.loads(zlib.decompress(base64.b85decode({CODEX_CHILD_CONTROL_SCHEMA_B85!r}))); RELAY_FIELDS=set(json.loads({canonical_implementation_json(RELAY_FRAME_FIELDS)!r}))",
    f"FRAME_DEFAULTS=json.loads({canonical_implementation_json(SUPERVISOR_FRAME_DEFAULTS)!r})",
    "C_STAGES={'SPEC_VALIDATE','BINARY_VALIDATE','ENV_VALIDATE','SPAWN_CALL','SPAWN_CONFIRMED','STDIN_WRITE','STDIN_CLOSE','ENDPOINT_WAIT','CHILD_EXIT'}",
    "COUNTS={'supervisor':1,'broker_bwrap':0,'relay_codex_bwrap':0,'codex_cli':0}; PROOF={'request_seen':0,'request_validated':0,'response_sent':0,'accepted_post':0,'request_hash':None,'response_hash':None,'response_byte_count':0,'output_hash':None,'sensitive_headers_removed':False,'removed_count':0,'post_filter_count':0,'codex_stdout_bytes':0,'codex_stdout_sha256':None,'codex_stdout_terminal_newline':False,'eof_stdout_drained':False,'eof_stderr_drained':False,'readers_joined':False,'usage':None,'child_schema_diagnostic':None,'event_types':[],'event_counts':{},'event_sequence_hash':hashlib.sha256(b'{\"event_counts\":{},\"event_types\":[]}').hexdigest(),'tool_event_count':0,'agent_message_count':0,'output_byte_count':0,'output_sha256':None,'last_message_exists':False,'last_message_regular':False,'last_message_size':0,'last_message_sha256':None,'last_message_match':False,'last_message_marker_match':False,'marker_match':False,'connection_delay_ms':0,'connection_delay_warning':False,'stderr_byte_count':0,'stderr_sha256':hashlib.sha256(b'').hexdigest(),'stderr_category':None,'prompt_mode':'STDIN_FORCED','config_loaded_expected':True,'argc':" + str(len(FIXED_CODEX_ARGV)) + ",'codex_exit_code':None,'strict_http_reject_reason':None,'request_header_count':0,'request_body_bytes':0,'request_body_sha256':hashlib.sha256(b'').hexdigest(),'request_json_keyset_hash':None,'input_shape':None}; emitted=False; implementation=sys.argv[2] if len(sys.argv)==4 else ''; spec_arg=sys.argv[3] if len(sys.argv)==4 else ''",
    "def cj(v): return json.dumps(v,ensure_ascii=False,sort_keys=True,separators=(',',':'))",
    CODEX_CHILD_CONTROL_GENERATED_VALIDATOR,
    "def build_frame(status,stage,error=None,cleanup_ok=False,substage=None):",
    " payload=dict(FRAME_DEFAULTS); payload.update({'status':status,'stage':stage,'substage':substage,'error_code':error,'cleanup_ok':bool(cleanup_ok)}); payload['process_counts']=dict(COUNTS); payload['implementation_hash']=implementation; payload['schema_version']=FRAME_SCHEMA_VERSION; payload.update(PROOF); return payload",
    "def emit(status,stage,error=None,cleanup_ok=False,substage=None):",
    " global emitted",
    " if emitted: return",
    " emitted=True; payload=build_frame(status,stage,error,cleanup_ok,substage)",
    " os.write(1,(P+base64.urlsafe_b64encode(cj(payload).encode('utf-8')).rstrip(b'=').decode('ascii')+'\\n').encode('ascii'))",
    "def materialize(t,v): return [v.get(x,x) for x in t]",
    "def hash_file(path):",
    " h=hashlib.sha256()",
    " with open(path,'rb') as fp:",
    "  while True:",
    "   chunk=fp.read(65536)",
    "   if not chunk: break",
    "   h.update(chunk)",
    " return h.hexdigest()",
    "def argv_diag(actual, expected):",
    " if not isinstance(actual, list): return {'argc':0,'mismatch_index':0,'reason_code':'argv_type_invalid'}",
    " if any(not isinstance(token, str) for token in actual):",
    "  bad=next(index for index, token in enumerate(actual) if not isinstance(token, str))",
    "  return {'argc':len(actual),'mismatch_index':bad,'reason_code':'argv_token_type_invalid'}",
    " if len(actual)!=len(expected): return {'argc':len(actual),'mismatch_index':min(len(actual),len(expected)),'reason_code':'argc_mismatch'}",
    " for index,(token, sealed) in enumerate(zip(actual, expected)):",
    "  if token!=sealed: return {'argc':len(actual),'mismatch_index':index,'reason_code':'token_mismatch'}",
    " return None",
    "def classify_child_lifecycle(payload,expected_response_hash,expected_output_hash):",
    " events=payload['event_types']; counts=payload['event_counts']; observed={}",
    " for kind in events: observed[kind]=observed.get(kind,0)+1",
    " expected_hash=hashlib.sha256(cj({'event_types':events,'event_counts':counts}).encode('utf-8')).hexdigest()",
    " if observed!=counts or payload['event_sequence_hash']!=expected_hash: return 'response_proof_invalid'",
    " if payload['accepted_post']!=payload['request_validated'] or payload['response_sent']>payload['accepted_post'] or payload['request_validated']>payload['request_seen']: return 'response_proof_invalid'",
    " if not payload['spawn_confirmed']: return payload.get('error_code') or 'codex_spawn_os_error'",
    " if payload.get('codex_exit_code') is None: return 'response_proof_invalid'",
    " if not payload.get('eof_stdout_drained') or not payload.get('eof_stderr_drained') or not payload.get('readers_joined'): return 'response_proof_invalid'",
    " if payload['tool_event_count']>0: return 'tool_event_policy_violation'",
    " if not events and payload['codex_exit_code']==0 and payload['request_seen']==0: return 'cli_no_event_exit'",
    " if counts.get('thread.started',0)==1 and counts.get('turn.started',0)==0: return 'cli_no_turn'",
    " if counts.get('turn.started',0)>=1 and payload['request_seen']==0: return 'provider_endpoint_not_reached'",
    " if payload['request_seen']==1 and payload['request_validated']==0: return 'strict_http_rejected' if payload.get('strict_http_reject_reason') in CHILD_SCHEMA['strict_http_reject_reasons'] else 'request_proof_invalid'",
    " if payload['request_validated']==1 and payload['response_sent']==0: return 'fake_response_not_sent'",
    " if payload['response_sent']==1 and counts.get('turn.completed',0)==0:",
    "  if payload['accepted_post']==1 and payload.get('response_sha256')==expected_response_hash and payload.get('response_byte_count',0)>0 and payload.get('eof_stdout_drained') and payload.get('eof_stderr_drained') and payload.get('readers_joined'): return 'response_not_consumed'",
    "  return 'response_proof_invalid'",
    " if counts.get('turn.failed',0)>0: return 'codex_turn_failed'",
    " if counts.get('error',0)>0: return 'codex_error_event'",
    " if payload['codex_exit_code']!=0:",
    "  return {'CLI_USAGE_ERROR':'cli_usage_error','STRICT_CONFIG_ERROR':'strict_config_error','CONFIG_INVALID':'config_invalid','PROVIDER_MISSING':'provider_missing','AUTH_ENV_MISSING':'auth_env_missing'}.get(payload.get('stderr_category'),'child_exit_other')",
    " if counts.get('turn.completed',0)==1 and (payload.get('agent_message_count')!=1 or payload.get('output_byte_count',0)<=0 or payload.get('output_sha256') is None or payload.get('last_message_sha256') is None): return 'output_proof_field_missing'",
    " if payload.get('agent_message_count')==0: return 'jsonl_agent_message_missing'",
    " if payload.get('agent_message_count')!=1: return 'jsonl_agent_message_duplicate'",
    " if payload.get('output_sha256')!=expected_output_hash: return 'jsonl_output_mismatch'",
    " if not payload['last_message_exists']: return 'codex_final_message_missing'",
    " if not payload['last_message_regular'] or not payload['last_message_match'] or not payload['last_message_marker_match']: return 'codex_final_message_mismatch'",
    " if payload.get('last_message_sha256')!=expected_output_hash or payload.get('last_message_sha256')!=payload.get('output_sha256') or not payload.get('marker_match'): return 'jsonl_output_mismatch'",
    " if counts.get('thread.started',0)!=1 or counts.get('turn.started',0)!=1 or counts.get('turn.completed',0)!=1 or events[0]!='thread.started' or events[-1]!='turn.completed': return 'response_proof_invalid'",
    " return payload.get('error_code')",
    "def stop(p):",
    " if p is None: return True",
    " if p.poll() is None:",
    "  p.terminate()",
    "  try: p.wait(timeout=3)",
    "  except Exception:",
    "   p.kill()",
    "   try: p.wait(timeout=3)",
    "   except Exception: return False",
    " return p.poll() is not None",
    "def parse_relay_boot(raw):",
    " try: decoded=raw.decode('utf-8','strict').replace('\\r\\n','\\n'); all_lines=[line for line in decoded.split('\\n') if line]",
    " except Exception: raise ValueError('relay_boot_invalid')",
    " lines=[line for line in all_lines if line.startswith(BOOT)]",
    " if not lines: raise ValueError('relay_boot_missing')",
    " if len(lines)!=1: raise ValueError('relay_boot_duplicate')",
    " if any(not (line.startswith(BOOT) or line.startswith('CODEXGATE_CODEX_RELAY_V1:')) for line in all_lines): raise ValueError('relay_boot_invalid')",
    " encoded=lines[0][len(BOOT):]",
    " if not encoded or '=' in encoded or not re.fullmatch(r'[A-Za-z0-9_-]+',encoded): raise ValueError('relay_boot_invalid')",
    " try: raw_payload=base64.urlsafe_b64decode(encoded+'='*((4-len(encoded)%4)%4)); payload=json.loads(raw_payload.decode('utf-8','strict'))",
    " except Exception: raise ValueError('relay_boot_invalid')",
    " if not isinstance(payload,dict) or set(payload)!=BOOT_FIELDS: raise ValueError('relay_boot_invalid')",
    " if json.dumps(payload,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode('utf-8')!=raw_payload: raise ValueError('relay_boot_invalid')",
    " if payload.get('stage')!='CHILD_START' or not isinstance(payload.get('implementation_hash'),str) or not re.fullmatch(r'[0-9a-f]{64}',payload['implementation_hash']) or payload.get('implementation_hash')!=implementation: raise ValueError('relay_boot_invalid')",
    " return payload",
    "def parse_child_control(raw):",
    " global PROOF",
    " def invalid(diagnostic): PROOF['child_schema_diagnostic']=diagnostic; raise_error=ValueError('codex_child_control_invalid'); return raise_error",
    " try: decoded=raw.decode('utf-8','strict').replace('\\r\\n','\\n'); all_lines=[line for line in decoded.split('\\n') if line]",
    " except Exception: raise invalid('bad_type_fields')",
    " lines=[line for line in all_lines if line.startswith(CHILD)]",
    " if not lines: raise ValueError('codex_child_control_missing')",
    " if len(lines)!=1: raise ValueError('codex_child_control_duplicate')",
    " if any(not line.startswith(CHILD) for line in all_lines): raise invalid('extra_fields')",
    " encoded=lines[0][len(CHILD):]",
    " if not encoded or '=' in encoded or not re.fullmatch(r'[A-Za-z0-9_-]+',encoded): raise invalid('bad_type_fields')",
    " try: raw_payload=base64.urlsafe_b64decode(encoded+'='*((4-len(encoded)%4)%4)); payload=json.loads(raw_payload.decode('utf-8','strict'))",
    " except Exception: raise invalid('bad_type_fields')",
    " if json.dumps(payload,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode('utf-8')!=raw_payload: raise invalid('bad_type_fields')",
    " diagnostic=child_schema_diagnostic(payload,implementation)",
    " if diagnostic is not None: raise invalid(diagnostic)",
    " return payload",
    f"def parse_relay_frame(raw,prefix={RELAY_FRAME_PREFIX!r}.encode('ascii')):",
    " try: lines=raw.decode('utf-8','strict').replace('\\r\\n','\\n').split('\\n')",
    " except Exception: raise ValueError('relay_proof_invalid')",
    " lines=[line for line in lines if line]",
    " if any(not (line.startswith(prefix.decode('ascii')) or line.startswith(BOOT)) for line in lines): raise ValueError('relay_proof_invalid')",
    " lines=[line for line in lines if line.startswith(prefix.decode('ascii'))]",
    " if not lines: raise ValueError('relay_proof_missing')",
    " if len(lines)>2: raise ValueError('relay_proof_duplicate')",
    " payloads=[]",
    " for line in lines:",
    "  if not line.startswith(prefix.decode('ascii')): raise ValueError('relay_proof_invalid')",
    "  encoded=line[len(prefix):]",
    "  if not encoded or '=' in encoded or not re.fullmatch(r'[A-Za-z0-9_-]+',encoded): raise ValueError('relay_proof_invalid')",
    "  try: raw_payload=base64.urlsafe_b64decode(encoded+'='*((4-len(encoded)%4)%4)); payload=json.loads(raw_payload.decode('utf-8','strict'))",
    "  except Exception: raise ValueError('relay_proof_invalid')",
     "  if not isinstance(payload,dict) or set(payload)!=RELAY_FIELDS or json.dumps(payload,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode('utf-8')!=raw_payload: raise ValueError('relay_proof_invalid')",
    "  if payload.get('status') not in {'READY','PASSED','ERROR','BLOCKED','POLICY_VIOLATION'} or payload.get('substage') not in FRAME_SUBSTAGES: raise ValueError('relay_proof_invalid')",
     "  if any(isinstance(payload.get(name),bool) or not isinstance(payload.get(name),int) or payload.get(name)<0 for name in ('codex_cli','request_seen','request_validated','response_sent','accepted_post','response_byte_count','codex_stdout_bytes','connection_delay_ms','stderr_byte_count','tool_event_count','agent_message_count','output_byte_count','last_message_size')) or any(payload.get(name) not in {0,1} for name in ('codex_cli','request_seen','request_validated','response_sent','accepted_post')) or not isinstance(payload.get('codex_stdout_terminal_newline'),bool) or not isinstance(payload.get('connection_delay_warning'),bool) or any(not isinstance(payload.get(name),bool) for name in ('last_message_exists','last_message_regular','last_message_match','last_message_marker_match','marker_match','eof_stdout_drained','eof_stderr_drained','readers_joined')): raise ValueError('relay_proof_invalid')",
    "  if any(payload.get(name) is not None and (not isinstance(payload.get(name),str) or not re.fullmatch(r'[0-9a-f]{64}',payload.get(name))) for name in ('codex_stdout_sha256','output_sha256','last_message_sha256')): raise ValueError('relay_proof_invalid')",
     "  if not isinstance(payload.get('stderr_sha256'),str) or not re.fullmatch(r'[0-9a-f]{64}',payload.get('stderr_sha256')): raise ValueError('relay_proof_invalid')",
     "  if payload.get('stderr_category') not in {None,'CODEX_HOME_WRITE_FAILED','ARG0_INIT_FAILED','CONFIG_LOAD_FAILED','AUTH_REQUIRED','CLI_USAGE_ERROR','STRICT_CONFIG_ERROR','CONFIG_INVALID','PROVIDER_MISSING','AUTH_ENV_MISSING','CHILD_EXIT_OTHER'}: raise ValueError('relay_proof_invalid')",
     "  ishape=payload.get('input_shape')",
     "  if ishape is not None and (not isinstance(ishape,dict) or set(ishape) != {'item_count','item_type_ids','item_key_presence_masks','role_ids','content_type_ids','content_counts','text_byte_counts','text_sha256s','shape_hash'} or not isinstance(ishape.get('shape_hash'),str) or not re.fullmatch(r'[0-9a-f]{64}',ishape.get('shape_hash'))): raise ValueError('relay_proof_invalid')",
     "  if not isinstance(payload.get('event_types'),list) or any(kind not in FRAME_TYPES for kind in payload.get('event_types')): raise ValueError('relay_proof_invalid')",
     "  if not isinstance(payload.get('event_counts'),dict) or any(kind not in FRAME_TYPES or isinstance(count,bool) or not isinstance(count,int) or count<0 for kind,count in payload.get('event_counts').items()): raise ValueError('relay_proof_invalid')",
    "  if not isinstance(payload.get('event_sequence_hash'),str) or not re.fullmatch(r'[0-9a-f]{64}',payload.get('event_sequence_hash')): raise ValueError('relay_proof_invalid')",
    "  if payload.get('strict_http_reject_reason') is not None and payload.get('strict_http_reject_reason') not in CHILD_SCHEMA['strict_http_reject_reasons']: raise ValueError('relay_proof_invalid')",
     "  if payload.get('request_hash') is not None and (not isinstance(payload.get('request_hash'),str) or not re.fullmatch(r'[0-9a-f]{64}',payload.get('request_hash'))) or not isinstance(payload.get('sensitive_headers_removed'),bool) or isinstance(payload.get('removed_count'),bool) or not isinstance(payload.get('removed_count'),int) or payload.get('removed_count')<0 or isinstance(payload.get('post_filter_count'),bool) or not isinstance(payload.get('post_filter_count'),int) or payload.get('post_filter_count')<0 or payload.get('sensitive_headers_removed') is not True and payload.get('status')=='PASSED' or payload.get('post_filter_count')!=0 and payload.get('status')=='PASSED': raise ValueError('relay_proof_invalid')",
     "  if isinstance(payload.get('request_header_count'),bool) or not isinstance(payload.get('request_header_count'),int) or payload.get('request_header_count')<0 or isinstance(payload.get('request_body_bytes'),bool) or not isinstance(payload.get('request_body_bytes'),int) or payload.get('request_body_bytes')<0 or not isinstance(payload.get('request_body_sha256'),str) or not re.fullmatch(r'[0-9a-f]{64}',payload.get('request_body_sha256')) or (payload.get('request_json_keyset_hash') is not None and (not isinstance(payload.get('request_json_keyset_hash'),str) or not re.fullmatch(r'[0-9a-f]{64}',payload.get('request_json_keyset_hash')))): raise ValueError('relay_proof_invalid')",
     "  if payload.get('codex_exit_code') is not None and (isinstance(payload.get('codex_exit_code'),bool) or not isinstance(payload.get('codex_exit_code'),int) or payload.get('codex_exit_code')<0): raise ValueError('relay_proof_invalid')",
     "  usage=payload.get('usage')",
     "  if usage is not None and (not isinstance(usage,dict) or set(usage)!=set(CHILD_SCHEMA['usage_fields']) or any(isinstance(value,bool) or not isinstance(value,int) or value<0 for value in usage.values())): raise ValueError('relay_proof_invalid')",
    "  if payload.get('prompt_mode')!='STDIN_FORCED' or payload.get('config_loaded_expected') is not True or isinstance(payload.get('argc'),bool) or not isinstance(payload.get('argc'),int) or payload.get('argc')<1: raise ValueError('relay_proof_invalid')",
    "  if payload.get('last_message_match')!=payload.get('last_message_marker_match') or payload.get('last_message_match') and (not payload.get('last_message_exists') or not payload.get('last_message_regular') or payload.get('last_message_sha256') is None) or payload.get('agent_message_count')==0 and (payload.get('output_byte_count')!=0 or payload.get('output_sha256') is not None) or payload.get('agent_message_count')>0 and (payload.get('output_byte_count',0)<=0 or payload.get('output_sha256') is None) or payload.get('marker_match') and (payload.get('agent_message_count')!=1 or payload.get('output_sha256') is None or payload.get('last_message_sha256') is None or not payload.get('last_message_match') or payload.get('output_sha256')!=payload.get('last_message_sha256')): raise ValueError('relay_proof_invalid')",
    "  if payload.get('status')=='READY' and (payload.get('substage')!='READY_EMIT' or payload.get('error_code') is not None or payload.get('codex_cli')!=0 or any(payload.get(name)!=0 for name in ('request_seen','request_validated','response_sent','accepted_post','response_byte_count','agent_message_count','output_byte_count'))): raise ValueError('relay_proof_invalid')",
    "  payloads.append(payload)",
    " if len(payloads)==2:",
    "  if payloads[0].get('status')!='READY' or payloads[1].get('status')=='READY': raise ValueError('relay_proof_invalid')",
    " elif payloads[0].get('status') in {'READY','PASSED'} or payloads[0].get('substage') not in {'LOOPBACK_BIND','LOOPBACK_LISTEN','CODEX_HOME_PREPARE','CONFIG_VALIDATE','SOCKET_VALIDATE'}: raise ValueError('relay_proof_invalid')",
    " return payloads[-1]",
    "root=None; broker=None; relay=None; stage='BOOT'; failed=None; substage=None; cleaned=False",
    "try:",
    " if len(sys.argv)!=4: stage='CLAIM_VALIDATE'; raise ValueError('claim_invalid')",
    " try: uuid.UUID(sys.argv[1])",
    " except Exception: stage='CLAIM_VALIDATE'; raise ValueError('claim_invalid')",
    " if len(implementation)!=64: stage='SPEC_VALIDATE'; raise ValueError('implementation_invalid')",
    " if not WIRE_PROVEN: stage='RUNTIME_VALIDATE'; raise ValueError('codex_wire_contract_unproven')",
    " try: spec=json.loads(base64.urlsafe_b64decode(spec_arg+'='*((4-len(spec_arg)%4)%4)).decode('utf-8','strict'))",
    " except Exception: stage='SPEC_VALIDATE'; raise ValueError('supervisor_spec_invalid')",
    " if not isinstance(spec,dict): stage='SPEC_VALIDATE'; raise ValueError('supervisor_spec_invalid')",
    " root=tempfile.mkdtemp(prefix='cg-codex-'); os.chmod(root,0o700); work=os.path.join(root,'work'); sock=os.path.join(root,'socket'); sealed=os.path.join(root,'sealed'); os.mkdir(work,0o700); os.mkdir(sock,0o700); os.mkdir(sealed,0o700)",
    " fixture=os.path.join(work,'fixture.json'); fp=open(fixture,'wb'); fp.write(b'{\\\"kind\\\":\\\"offline-canary\\\"}\\n'); fp.flush(); os.fsync(fp.fileno()); fp.close(); os.chmod(fixture,0o444)",
    " config=os.path.join(sealed,'config.toml'); fp=open(config,'wb'); fp.write(CONFIG); fp.flush(); os.fsync(fp.fileno()); fp.close(); os.chmod(config,0o400); dirfd=os.open(sealed,os.O_RDONLY|os.O_DIRECTORY); os.fsync(dirfd); os.close(dirfd)",
    " stage='BROKER_SPAWN'; ba=materialize(BT,{'{EXECUTION_SOCKET_DIR}':sock,'{BROKER_CHILD_CODE}':BROKER.decode('utf-8')}); broker=subprocess.Popen(ba,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={}); COUNTS['broker_bwrap']=1",
    " stage='BROKER_READY'; deadline=time.monotonic()+10",
    " while not os.path.exists(os.path.join(sock,'broker.sock')):",
    "  if broker.poll() is not None or time.monotonic()>=deadline: raise TimeoutError('broker_not_ready')",
    "  time.sleep(.02)",
    " stage='RELAY_CODEX_SPAWN'; substage='RUNTIME_BIND_VALIDATE'; binary=spec.get('runtime_binary'); expected_binary_sha=spec.get('runtime_binary_sha256'); expected_config_hash=spec.get('provider_config_hash'); expected_prompt_hash=spec.get('prompt_hash'); expected_request_hash=spec.get('request_hash'); expected_response_hash=spec.get('response_hash'); expected_output_hash=spec.get('output_hash')",
    " if not isinstance(binary,str) or not binary.startswith('/'): raise ValueError('runtime_bind_invalid')",
    " if not all(isinstance(v,str) and len(v)==64 for v in (expected_binary_sha,expected_config_hash,expected_prompt_hash,expected_request_hash,expected_response_hash,expected_output_hash)): raise ValueError('supervisor_spec_invalid')",
    " if not os.path.exists(binary): raise ValueError('runtime_bind_missing')",
    " st=os.lstat(binary)",
    " if not stat.S_ISREG(st.st_mode): raise ValueError('runtime_binary_not_regular')",
    " if stat.S_ISLNK(st.st_mode): raise ValueError('runtime_binary_symlink')",
    " if os.access(binary,os.X_OK) is False: raise ValueError('runtime_binary_not_executable')",
    " substage='WORK_FIXTURE_VALIDATE'",
    " if not os.path.isfile(fixture): raise ValueError('work_fixture_missing')",
    " if bool(os.stat(fixture).st_mode & 0o222): raise ValueError('work_fixture_not_read_only')",
    " substage='CONFIG_VALIDATE'",
    " if not os.path.isfile(config): raise ValueError('codex_config_missing')",
    " if hash_file(config)!=expected_config_hash: raise ValueError('codex_config_hash_mismatch')",
    " substage='CODEX_BINARY_VALIDATE'",
    " if hash_file(binary)!=expected_binary_sha: raise ValueError('runtime_binary_sha_mismatch')",
    " substage='CODEX_ARGV_VALIDATE'; sealed_argv=" + repr(list(build_sealed_codex_argv())),
    " relay_spec=spec.get('relay_codex') if isinstance(spec.get('relay_codex'),dict) else None",
    " argv_reason=argv_diag(spec.get('codex_argv'), sealed_argv) or argv_diag(None if relay_spec is None else relay_spec.get('argv'), sealed_argv)",
    " if argv_reason is not None: raise ValueError('codex_argv_invalid')",
    f" if spec.get('provider_model')!={CUSTOM_PROVIDER_ID!r}: raise ValueError('codex_model_invalid')",
    f" if expected_prompt_hash!={EXPECTED_PROMPT_HASH!r}: raise ValueError('codex_prompt_invalid')",
    " substage='CODEX_SPAWN'; ra=materialize(RT,{'{EXECUTION_SOCKET_DIR}':sock,'{FIXTURE_SOURCE}':fixture,'{SEALED_CONFIG_SOURCE}':config,'{CODEX_BINARY}':binary,'{RELAY_CODEX_CHILD_CODE}':RELAY.decode('utf-8'),'{EXECUTOR_IMPLEMENTATION_HASH}':implementation}); relay=subprocess.Popen(ra,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={}); COUNTS['relay_codex_bwrap']=1",
    " out,err=relay.communicate(timeout=30)",
    " if len(out)+len(err)>16384: raise ValueError('output_limit')",
    " boot=parse_relay_boot(err)",
    " try: control=parse_child_control(out)",
    " except ValueError as exc:",
    "  if relay.returncode!=0 and str(exc)=='codex_child_control_missing': raise ValueError('relay_child_transport_error')",
    "  raise",
    " proof=parse_relay_frame(err)",
    " if relay.returncode!=0 and not control.get('error_code') and not control.get('spawn_confirmed'): raise ValueError('relay_child_transport_error')",
    " substage=control.get('stage')",
     " PROOF.update({'request_seen':control['request_seen'],'request_validated':control['request_validated'],'request_hash':control.get('request_hash'),'sensitive_headers_removed':control.get('sensitive_headers_removed',False),'removed_count':control.get('removed_count',0),'post_filter_count':control.get('post_filter_count',0),'response_hash':control['response_sha256'] if control['response_sent'] else None,'response_sent':control['response_sent'],'accepted_post':control['accepted_post'],'response_byte_count':control['response_byte_count'],'output_hash':control['output_sha256'] if control['marker_match'] else None,'event_types':control['event_types'],'event_counts':control['event_counts'],'event_sequence_hash':control['event_sequence_hash'],'tool_event_count':control['tool_event_count'],'agent_message_count':control['agent_message_count'],'output_byte_count':control['output_byte_count'],'output_sha256':control['output_sha256'],'usage':control['usage'],'last_message_exists':control['last_message_exists'],'last_message_regular':control['last_message_regular'],'last_message_size':control['last_message_size'],'last_message_sha256':control['last_message_sha256'],'last_message_match':control['last_message_match'],'last_message_marker_match':control['last_message_marker_match'],'marker_match':control['marker_match'],'eof_stdout_drained':control['eof_stdout_drained'],'eof_stderr_drained':control['eof_stderr_drained'],'readers_joined':control['readers_joined'],'stderr_byte_count':control['stderr_byte_count'],'stderr_sha256':control['stderr_sha256'],'stderr_category':control['stderr_category'],'codex_exit_code':control['codex_exit_code'],'codex_stdout_bytes':proof.get('codex_stdout_bytes',0),'codex_stdout_sha256':control['stdout_sha256'],'codex_stdout_terminal_newline':proof.get('codex_stdout_terminal_newline',False),'connection_delay_ms':proof.get('connection_delay_ms'),'connection_delay_warning':proof.get('connection_delay_warning'),'prompt_mode':proof.get('prompt_mode'),'config_loaded_expected':proof.get('config_loaded_expected'),'argc':proof.get('argc'),'strict_http_reject_reason':control['strict_http_reject_reason'],'request_header_count':control['request_header_count'],'request_body_bytes':control['request_body_bytes'],'request_body_sha256':control['request_body_sha256'],'request_json_keyset_hash':control['request_json_keyset_hash'],'input_shape':control.get('input_shape')})",
    " if control.get('spawn_confirmed'): COUNTS['codex_cli']=1",
    " if not control.get('cleanup_ok'): raise ValueError('cleanup_failed')",
    " lifecycle_error=classify_child_lifecycle(control,expected_response_hash,expected_output_hash)",
    " if lifecycle_error is not None: raise ValueError(lifecycle_error)",
    " if proof.get('status')!='PASSED': raise ValueError(proof.get('error_code') or 'relay_codex_failed')",
    " if proof.get('codex_cli')!=1 or any(control.get(name)!=1 for name in ('request_seen','request_validated','response_sent','accepted_post')): raise ValueError('response_proof_invalid')",
    " if proof.get('request_hash') is None or control.get('request_hash')!=proof.get('request_hash') or proof.get('response_hash')!=control.get('response_sha256') or control.get('response_sha256')!=expected_response_hash or proof.get('response_byte_count')!=control.get('response_byte_count') or control.get('response_byte_count')<=0 or proof.get('output_hash')!=control.get('output_sha256') or control.get('output_sha256')!=expected_output_hash or proof.get('agent_message_count')!=control.get('agent_message_count') or proof.get('output_byte_count')!=control.get('output_byte_count') or proof.get('output_sha256')!=control.get('output_sha256') or proof.get('last_message_sha256')!=control.get('last_message_sha256') or proof.get('marker_match') is not True or proof.get('sensitive_headers_removed') is not True or control.get('sensitive_headers_removed') is not True or proof.get('post_filter_count')!=0 or control.get('post_filter_count')!=0: raise ValueError('response_proof_invalid')",
    " COUNTS['codex_cli']=1; PROOF.update({'request_hash':proof['request_hash'],'response_hash':control['response_sha256'],'response_byte_count':control['response_byte_count'],'output_hash':control['output_sha256'],'sensitive_headers_removed':proof['sensitive_headers_removed']}); stage='RESPONSE_VALIDATE'; substage='CODEX_SPAWN'",
    " stage='CLEANUP'",
    "except TimeoutError as exc: failed='supervisor_timeout'",
    "except subprocess.TimeoutExpired as exc: failed='supervisor_timeout'",
     "except ValueError as exc: failed=str(exc) if str(exc) in FRAME_ERROR_CODES else 'supervisor_error'",
    "except Exception: failed='supervisor_error'",
    "finally:",
    " stage='CLEANUP' if failed is None else stage; relay_stopped=stop(relay); broker_stopped=stop(broker); shutil.rmtree(root,ignore_errors=True) if root else None; cleaned=bool(relay_stopped and broker_stopped and (root is None or not os.path.exists(root)))",
    " if failed is not None: emit('POLICY_VIOLATION' if failed=='tool_event_policy_violation' else 'ERROR',stage,failed,cleaned,substage)",
    " elif not cleaned: emit('ERROR','CLEANUP','cleanup_failed',False)",
    " else: emit('PASSED','CLEANUP',None,True)",
    "",
))
SUPERVISOR_CODE = _SUPERVISOR_SOURCE.encode("utf-8")


# This is the only Python source placed on the Windows command line.  It
# accepts one bounded canonical payload on stdin, validates it, then runs the
# sealed supervisor with the argv shape it already expects.  It never writes a
# payload, source, argv, or diagnostics verbatim to stdout/stderr.
_SUPERVISOR_BOOTSTRAP_LOGIC = """try:
 import base64 as b,builtins,hashlib as h,json as j,os,re,sys,uuid
 P=%r;Q=%r;M=%d;K=%r;F=re.fullmatch;D=b.urlsafe_b64decode;J=lambda a:j.dumps(a,sort_keys=1,separators=(',',':')).encode();G=j.loads(%r);S='STDIN_READ'
 def w(error,substage,implementation):
  payload=dict(G); payload.update({'status':'ERROR','stage':'BOOT','substage':substage,'error_code':error,'cleanup_ok':True}); payload['process_counts']={'supervisor':1,'broker_bwrap':0,'relay_codex_bwrap':0,'codex_cli':0}; payload['implementation_hash']=implementation; return payload
 def z(e):
  x=sys.argv[1] if len(sys.argv)==2 and F('[0-9a-f]{64}',sys.argv[1]) else '0'*64
  os.write(1,(P+b.urlsafe_b64encode(J(w(e,S,x))).rstrip(b'=').decode()+'\\n').encode())
 y=sys.stdin.buffer.read(M+1)
 if len(y)>M or y.count(b'\\n')!=1 or not y.endswith(b'\\n') or not y.startswith(Q.encode()):raise ValueError()
 S='PAYLOAD_DECODE';v=y[len(Q):-1]
 if not F(br'[A-Za-z0-9_-]+',v):raise ValueError()
 r=D(v+b'='*((4-len(v)%%4)%%4));x=j.loads(r.decode())
 S='PAYLOAD_SCHEMA'
 if J(x)!=r or set(x)!=set(K) or x.get('schema_version')!='1':raise ValueError()
 if x['implementation_hash']!=sys.argv[1]:raise ValueError()
 s=x['supervisor_code_b64'];q=x['supervisor_spec_b64']
 S='CODE_HASH_VALIDATE';c=__import__('zlib').decompress(D(s+'='*((4-len(s)%%4)%%4)))
 if h.sha256(c).hexdigest()!=x['supervisor_code_sha256']:E='bootstrap_code_hash_mismatch';raise ValueError()
 S='SPEC_DECODE';p=D(q+'='*((4-len(q)%%4)%%4));a=j.loads(p.decode())
 S='EXEC_PREPARE';sys.argv=['',x['claim_id'],x['implementation_hash'],q];g={'__name__':'__main__','__file__':'<sealed-supervisor>','__package__':None,'__builtins__':builtins}
 S='EXEC_CALL';exec(compile(c.decode(),'sealed-supervisor','exec'),g)
except BaseException:
 try:z('bootstrap_payload_invalid')
 except BaseException:pass
""" % (
    SUPERVISOR_FRAME_PREFIX,
    SUPERVISOR_BOOTSTRAP_PREFIX,
     SUPERVISOR_BOOTSTRAP_MAX_BYTES,
     sorted(SUPERVISOR_BOOTSTRAP_FIELDS),
    canonical_implementation_json(SUPERVISOR_FRAME_DEFAULTS),
)
_SUPERVISOR_BOOTSTRAP_SOURCE = "import base64,zlib;exec(zlib.decompress(base64.b85decode(%r)))" % (
    base64.b85encode(zlib.compress(_SUPERVISOR_BOOTSTRAP_LOGIC.encode("utf-8"), 9)),
)
SUPERVISOR_BOOTSTRAP_CODE = _SUPERVISOR_BOOTSTRAP_SOURCE.encode("utf-8")
if len(SUPERVISOR_BOOTSTRAP_CODE) > 4096:  # sealed review invariant
    raise RuntimeError("supervisor bootstrap exceeds command-line budget")


def _digest(value: bytes | str) -> str:
    return hashlib.sha256(value.encode("utf-8") if isinstance(value, str) else value).hexdigest()


def _encode_supervisor_spec(spec: Mapping[str, Any]) -> str:
    raw = canonical_json(dict(spec)).encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _decode_base64url(value: str) -> bytes:
    if not isinstance(value, str) or not value or "=" in value or not _BASE64URL.fullmatch(value):
        raise PolicyError("bootstrap_payload_invalid")
    try:
        return base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))
    except Exception as exc:
        raise PolicyError("bootstrap_payload_invalid") from exc


def parse_supervisor_bootstrap_payload(payload: bytes) -> dict[str, str]:
    """Strictly validate the one-line stdin transport without executing it."""
    if not isinstance(payload, bytes) or len(payload) > SUPERVISOR_BOOTSTRAP_MAX_BYTES:
        raise PolicyError("bootstrap_payload_invalid")
    prefix = SUPERVISOR_BOOTSTRAP_PREFIX.encode("ascii")
    if payload.count(b"\n") != 1 or not payload.endswith(b"\n") or not payload.startswith(prefix):
        raise PolicyError("bootstrap_payload_invalid")
    raw = _decode_base64url(payload[len(prefix):-1].decode("ascii", "strict"))
    try:
        decoded = json.loads(raw.decode("utf-8", "strict"))
    except Exception as exc:
        raise PolicyError("bootstrap_payload_invalid") from exc
    if not isinstance(decoded, dict) or set(decoded) != SUPERVISOR_BOOTSTRAP_FIELDS:
        raise PolicyError("bootstrap_payload_invalid")
    if canonical_json(decoded).encode("utf-8") != raw or decoded.get("schema_version") != SUPERVISOR_BOOTSTRAP_SCHEMA_VERSION:
        raise PolicyError("bootstrap_payload_invalid")
    try:
        uuid.UUID(decoded["claim_id"])
    except (TypeError, ValueError) as exc:
        raise PolicyError("bootstrap_payload_invalid") from exc
    for field in ("implementation_hash", "supervisor_code_sha256"):
        if not isinstance(decoded.get(field), str) or not _DIGEST.fullmatch(decoded[field]):
            raise PolicyError("bootstrap_payload_invalid")
    code = _decode_base64url(decoded.get("supervisor_code_b64"))
    try:
        code = zlib.decompress(code)
    except zlib.error as exc:
        raise PolicyError("bootstrap_payload_invalid") from exc
    if hashlib.sha256(code).hexdigest() != decoded["supervisor_code_sha256"]:
        raise PolicyError("bootstrap_code_hash_mismatch")
    _decode_base64url(decoded.get("supervisor_spec_b64"))
    return {field: decoded[field] for field in SUPERVISOR_BOOTSTRAP_FIELDS}


def build_supervisor_bootstrap_payload(execution_claim_id: str, supervisor_spec: Mapping[str, Any]) -> bytes:
    try:
        uuid.UUID(execution_claim_id)
    except (TypeError, ValueError) as exc:
        raise PolicyError("canary_execution_claim_invalid") from exc
    payload = {
        "schema_version": SUPERVISOR_BOOTSTRAP_SCHEMA_VERSION,
        "claim_id": execution_claim_id,
        "implementation_hash": EXECUTOR_IMPLEMENTATION_HASH,
        "supervisor_code_b64": base64.urlsafe_b64encode(zlib.compress(SUPERVISOR_CODE, 9)).rstrip(b"=").decode("ascii"),
        "supervisor_code_sha256": hashlib.sha256(SUPERVISOR_CODE).hexdigest(),
        "supervisor_spec_b64": _encode_supervisor_spec(supervisor_spec),
    }
    encoded = base64.urlsafe_b64encode(canonical_json(payload).encode("utf-8")).rstrip(b"=")
    result = SUPERVISOR_BOOTSTRAP_PREFIX.encode("ascii") + encoded + b"\n"
    parse_supervisor_bootstrap_payload(result)
    return result


def compute_executor_implementation(
    *,
    supervisor_code: bytes = SUPERVISOR_CODE,
    supervisor_bootstrap_code: bytes = SUPERVISOR_BOOTSTRAP_CODE,
    broker_child_code: bytes = BROKER_CHILD_CODE,
    relay_codex_child_code: bytes = RELAY_CODEX_CHILD_CODE,
    broker_argv: Sequence[str] = BROKER_CHILD_ARGV_TEMPLATE,
    relay_codex_argv: Sequence[str] = RELAY_CODEX_CHILD_ARGV_TEMPLATE,
    supervisor_argv: Sequence[str] = SUPERVISOR_ARGV_TEMPLATE,
    codex_argv: Sequence[str] | None = None,
    prompt: str = FIXED_PROMPT,
    fake_response: Mapping[str, Any] = FIXED_FAKE_RESPONSE,
    child_control_schema: Mapping[str, Any] = CODEX_CHILD_CONTROL_SCHEMA,
) -> tuple[str, dict[str, str]]:
    """Canonical seal for the review spec and the actual fixed argv source."""
    sealed_codex_argv = tuple(build_sealed_codex_argv() if codex_argv is None else codex_argv)
    components = {
        "supervisor_sha256": _digest(supervisor_code),
        "supervisor_bootstrap_sha256": _digest(supervisor_bootstrap_code),
        "supervisor_bootstrap_schema_sha256": implementation_json_hash(SUPERVISOR_BOOTSTRAP_FIELDS),
        "supervisor_frame_schema_sha256": implementation_json_hash(SUPERVISOR_FRAME_SCHEMA),
        "codex_child_control_schema_sha256": implementation_json_hash(child_control_schema),
        "broker_child_sha256": _digest(broker_child_code),
        "relay_codex_child_sha256": _digest(relay_codex_child_code),
        "argv_template_sha256": implementation_json_hash({
            "common": list(BWRAP_COMMON_ARGS), "broker": list(broker_argv),
            "relay_codex": list(relay_codex_argv), "supervisor": list(supervisor_argv), "codex": list(sealed_codex_argv),
        }),
        "prompt_sha256": _digest(prompt),
        "fake_response_sha256": implementation_json_hash(fake_response),
        "provider_config_sha256": provider_config_hash(canonical_provider_toml()),
        "loopback_endpoint_sha256": implementation_json_hash({"host": LOOPBACK_HOST, "port": LOOPBACK_PORT}),
        "wire_contract_sha256": WIRE_CONTRACT_HASH,
        "pinned_responses_top_level_keys_sha256": implementation_json_hash({
            "keys": PINNED_REQUEST_KEYS,
            "required": PINNED_REQUEST_REQUIRED_KEYS,
            "optional": PINNED_REQUEST_OPTIONAL_KEYS,
            "stream_options": {"reasoning_summary_delivery": "sequential_cutoff"},
            "client_metadata": "string_to_string_map",
        }),
        "pinned_include_contract_sha256": implementation_json_hash(PINNED_INCLUDE_SEQUENCE),
        "pinned_input_schema_sha256": implementation_json_hash(PINNED_INPUT_SCHEMA_V0145),
        "responses_parser_fixture_sha256": PARSER_FIXTURE_SHA256,
        "full_turn_fixture_sha256": SEALED_RESPONSE_BODY_SHA256,
        "full_turn_http_envelope_sha256": _digest(SEALED_HTTP_RESPONSE_BYTES),
        "relay_counter_schema_sha256": implementation_json_hash(RELAY_COUNTER_FIELDS),
    }
    return implementation_json_hash({
        "policy_version": EXECUTOR_POLICY_VERSION,
        "components": components,
    }), components


EXECUTOR_IMPLEMENTATION_HASH, EXECUTOR_COMPONENT_HASHES = compute_executor_implementation()
EXECUTOR_VERSION = f"sealed-offline-codex-{EXECUTOR_IMPLEMENTATION_HASH[:16]}"


def _materialize_argv(template: Sequence[str], replacements: Mapping[str, str]) -> list[str]:
    if set(replacements) - set(template):
        raise PolicyError("codex_executor_argv_invalid")
    result = [replacements.get(item, item) for item in template]
    if any(item.startswith("{") and item.endswith("}") for item in result):
        raise PolicyError("codex_executor_argv_invalid")
    return result


def windows_quoted_command_line_bytes(args: Sequence[str]) -> int:
    """Windows uses a quoted UTF-16 command line even when Python receives argv."""
    if any(not isinstance(arg, str) for arg in args):
        raise PolicyError("command_line_too_long")
    return len(subprocess.list2cmdline(list(args)).encode("utf-16-le"))


def build_codex_supervisor_argv(wsl_executable: str) -> list[str]:
    if not isinstance(wsl_executable, str) or not wsl_executable or any(ord(char) < 32 for char in wsl_executable):
        raise PolicyError("wsl_unavailable")
    argv = _materialize_argv(SUPERVISOR_ARGV_TEMPLATE, {
        "{WSL_EXECUTABLE}": wsl_executable,
        "{SUPERVISOR_BOOTSTRAP_CODE}": SUPERVISOR_BOOTSTRAP_CODE.decode("utf-8"),
        "{EXECUTOR_IMPLEMENTATION_HASH}": EXECUTOR_IMPLEMENTATION_HASH,
    })
    if windows_quoted_command_line_bytes(argv) > WINDOWS_QUOTED_COMMAND_LINE_MAX_BYTES:
        raise PolicyError("command_line_too_long")
    return argv


def build_codex_executor_launch_spec(
    binary_path: str, *, runtime_binary_sha256: str | None = None
) -> dict[str, Any]:
    """Private review spec generated only from shared, sealed templates."""
    binary_path = validate_wsl_codex_binary_path(binary_path)
    runtime_policy = sealed_runtime_execution_policy()
    environment = dict(runtime_policy["environment"])
    sealed_codex_argv = list(build_sealed_codex_argv())
    return {
        "backend": "WSL2_BWRAP",
        "supervisor_argv_template": list(SUPERVISOR_ARGV_TEMPLATE),
        "broker_argv_template": list(BROKER_CHILD_ARGV_TEMPLATE),
        "relay_codex_argv_template": list(RELAY_CODEX_CHILD_ARGV_TEMPLATE),
        "codex_argv": list(sealed_codex_argv),
        "broker": {"unshare_all": True, "clearenv": True, "socket": "single_af_unix_pathname", "tmpfs": ["/tmp", "/home", "/runtime-state"]},
        "relay_codex": {
            "unshare_all": True, "clearenv": True, "network": "sealed_loopback_only",
            "socket": "single_af_unix_and_loopback", "work_read_only": True,
            "fixture": "/work/fixture.json", "codex_home": "tmpfs", "runtime_state": "tmpfs",
            "sealed_config": "read_only_source_copy", "tmpfs": ["/tmp", "/home", "/runtime-state", "/runtime/codex-home"], "environment": environment,
            "endpoint": {"host": LOOPBACK_HOST, "port": LOOPBACK_PORT, "path": BROKER_REQUEST_PATH},
            "argv": list(sealed_codex_argv),
            "model": CUSTOM_PROVIDER_ID,
            "codex_home_config": "sealed_source_copy_to_tmpfs",
        },
        "forbidden_binds": ["/mnt", "WINDOWS", "SOURCE_ROOT", "DATA_ROOT", "USER_HOME"],
        "runtime_binary": binary_path,
        "runtime_binary_sha256": runtime_binary_sha256,
        "provider_config_hash": EXPECTED_CONFIG_HASH,
        "request_hash": EXPECTED_REQUEST_HASH,
        "response_hash": EXPECTED_RESPONSE_HASH,
        "prompt_hash": EXPECTED_PROMPT_HASH,
        "output_hash": EXPECTED_OUTPUT_HASH,
        "provider_model": CUSTOM_PROVIDER_ID,
        "wire_contract_hash": WIRE_CONTRACT_HASH,
        "executor_implementation_hash": EXECUTOR_IMPLEMENTATION_HASH,
    }


class CodexExecutorFailure(PolicyError):
    """A sanitized supervisor/transport error with observed provenance only."""

    def __init__(
        self, code: str, *, supervisor_processes: int = 0, bwrap_processes: int = 0,
        codex_processes: int = 0, stage: str | None = None, cleanup_ok: bool | None = None,
        stdout_bytes: int = 0, stderr_bytes: int = 0, exit_code: int | None = None,
        substage: str | None = None,
        connection_delay_ms: int = 0,
        child_exit_category: str | None = None,
        event_types: Sequence[str] = (),
        event_counts: Mapping[str, int] | None = None,
        event_sequence_hash: str | None = None,
        tool_event_count: int = 0,
        agent_message_count: int = 0,
        output_byte_count: int = 0,
        output_sha256: str | None = None,
        request_seen: int = 0,
        request_validated: int = 0,
        response_sent: int = 0,
        accepted_post: int = 0,
        request_hash: str | None = None,
        sensitive_headers_removed: bool = False,
        removed_count: int = 0,
        post_filter_count: int = 0,
        response_hash: str | None = None,
        response_byte_count: int = 0,
        last_message_exists: bool = False,
        last_message_regular: bool = False,
        last_message_size: int = 0,
        last_message_sha256: str | None = None,
        last_message_match: bool = False,
        last_message_marker_match: bool = False,
        marker_match: bool = False,
        output_hash: str | None = None,
        stdout_eof: bool = False,
        stderr_eof: bool = False,
        readers_joined: bool = False,
        codex_exit_code: int | None = None,
        stderr_sha256: str | None = None,
        strict_http_reject_reason: str | None = None,
        request_header_count: int = 0,
        request_body_bytes: int = 0,
        request_body_sha256: str | None = None,
        request_json_keyset_hash: str | None = None,
        input_shape: Mapping[str, Any] | None = None,
        schema_diagnostic: str | None = None,
        transport: bool = False,
    ):
        super().__init__(code)
        self.stage = stage
        self.substage = substage
        self.connection_delay_ms = max(0, int(connection_delay_ms))
        self.child_exit_category = child_exit_category
        self.event_types = tuple(event_types)
        self.event_counts = dict(event_counts or {})
        self.event_sequence_hash = event_sequence_hash
        self.tool_event_count = max(0, int(tool_event_count))
        self.agent_message_count = max(0, int(agent_message_count))
        self.output_byte_count = max(0, int(output_byte_count))
        self.output_sha256 = output_sha256 if _digest_or_none(output_sha256) else None
        self.request_seen = max(0, int(request_seen))
        self.request_validated = max(0, int(request_validated))
        self.response_sent = max(0, int(response_sent))
        self.accepted_post = max(0, int(accepted_post))
        self.request_hash = request_hash if _digest_or_none(request_hash) else None
        self.sensitive_headers_removed = bool(sensitive_headers_removed)
        self.removed_count = max(0, int(removed_count))
        self.post_filter_count = max(0, int(post_filter_count))
        self.response_hash = response_hash if _digest_or_none(response_hash) else None
        self.response_byte_count = max(0, int(response_byte_count))
        self.last_message_exists = bool(last_message_exists)
        self.last_message_regular = bool(last_message_regular)
        self.last_message_size = max(0, int(last_message_size))
        self.last_message_sha256 = last_message_sha256 if _digest_or_none(last_message_sha256) else None
        self.last_message_match = bool(last_message_match)
        self.last_message_marker_match = bool(last_message_marker_match)
        self.marker_match = bool(marker_match)
        self.output_hash = output_hash if _digest_or_none(output_hash) else None
        self.stdout_eof = bool(stdout_eof)
        self.stderr_eof = bool(stderr_eof)
        self.readers_joined = bool(readers_joined)
        self.codex_exit_code = codex_exit_code
        self.stderr_sha256 = stderr_sha256
        self.strict_http_reject_reason = strict_http_reject_reason if strict_http_reject_reason in STRICT_HTTP_REJECT_REASONS else None
        self.request_header_count = max(0, int(request_header_count))
        self.request_body_bytes = max(0, int(request_body_bytes))
        self.request_body_sha256 = request_body_sha256 if _digest_or_none(request_body_sha256) else None
        self.request_json_keyset_hash = request_json_keyset_hash if _digest_or_none(request_json_keyset_hash) else None
        self.input_shape = dict(input_shape) if _input_shape_valid(input_shape) and input_shape is not None else None
        self.schema_diagnostic = schema_diagnostic if schema_diagnostic in SUPERVISOR_SCHEMA_DIAGNOSTICS else None
        self.cleanup_ok = cleanup_ok
        self.stdout_bytes = max(0, int(stdout_bytes))
        self.stderr_bytes = max(0, int(stderr_bytes))
        self.exit_code = exit_code
        self.transport = bool(transport)
        self.supervisor_processes = max(0, int(supervisor_processes))
        self.bwrap_processes = max(0, int(bwrap_processes))
        self.codex_processes = max(0, int(codex_processes))
        self.local_processes = self.supervisor_processes + self.bwrap_processes + self.codex_processes


class SealedWSLSupervisorRunner:
    """Fixed-argv WSL runner with an immediate post-spawn callback.

    This is not instantiated until a claim is ``RUNNING``.  The callback is
    deliberately invoked after ``create_subprocess_exec`` succeeds so the
    database counter represents a real observed supervisor, including a
    later timeout or frame failure.
    """

    def find_wsl(self) -> str | None:
        return shutil.which("wsl.exe") or shutil.which("wsl")

    async def run(
        self, args: list[str], *, payload: bytes, timeout_seconds: float, on_started: Callable[[], None] | None = None,
    ) -> ProcessResult:
        parse_supervisor_bootstrap_payload(payload)
        try:
            process = await asyncio.create_subprocess_exec(
                *args, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
        except (FileNotFoundError, OSError) as exc:
            code = "command_line_too_long" if getattr(exc, "winerror", None) == 206 or getattr(exc, "errno", None) == errno.E2BIG else "supervisor_transport_error"
            raise CodexExecutorFailure(code, stage="BOOT", transport=True) from exc
        if on_started is not None:
            on_started()
        try:
            await self._write_bootstrap_payload(process, payload)
        except Exception as exc:
            await self._terminate_process_tree(process)
            raise CodexExecutorFailure("payload_write_failed", stage="BOOT", supervisor_processes=1, transport=True) from exc
        try:
            stdout, stderr = await self._collect_limited_output(process, timeout_seconds)
        except asyncio.TimeoutError:
            await self._terminate_process_tree(process)
            raise CodexExecutorFailure("supervisor_transport_timeout", stage="BOOT", supervisor_processes=1, transport=True)
        return ProcessResult(
            exit_code=process.returncode,
            stdout=stdout.decode("utf-8", errors="replace"), stderr=stderr.decode("utf-8", errors="replace"),
            stdout_bytes=stdout, stderr_bytes=stderr,
        )

    @staticmethod
    async def _write_bootstrap_payload(process: asyncio.subprocess.Process, payload: bytes) -> None:
        if process.stdin is None:
            raise RuntimeError("stdin unavailable")
        process.stdin.write(payload)
        await process.stdin.drain()
        process.stdin.close()
        wait_closed = getattr(process.stdin, "wait_closed", None)
        if wait_closed is not None:
            await wait_closed()

    @staticmethod
    async def _collect_limited_output(process: asyncio.subprocess.Process, timeout_seconds: float) -> tuple[bytes, bytes]:
        """Drain both streams while enforcing the cap before process exit."""
        if process.stdout is None or process.stderr is None:
            raise CodexExecutorFailure("supervisor_transport_error", stage="BOOT", supervisor_processes=1, transport=True)
        buffers = {"stdout": bytearray(), "stderr": bytearray()}
        readers = {"stdout": process.stdout, "stderr": process.stderr}
        pending: dict[asyncio.Task[bytes], str] = {
            asyncio.create_task(reader.read(4096)): name for name, reader in readers.items()
        }
        deadline = asyncio.get_running_loop().time() + timeout_seconds
        try:
            while pending:
                remaining = deadline - asyncio.get_running_loop().time()
                if remaining <= 0:
                    raise asyncio.TimeoutError
                done, _ = await asyncio.wait(pending, timeout=remaining, return_when=asyncio.FIRST_COMPLETED)
                if not done:
                    raise asyncio.TimeoutError
                for task in done:
                    name = pending.pop(task)
                    chunk = task.result()
                    if not chunk:
                        continue
                    buffers[name].extend(chunk)
                    if len(buffers["stdout"]) + len(buffers["stderr"]) > SUPERVISOR_OUTPUT_LIMIT_BYTES:
                        await SealedWSLSupervisorRunner._terminate_process_tree(process)
                        raise CodexExecutorFailure(
                            "supervisor_output_limit", stage="BOOT", supervisor_processes=1,
                            stdout_bytes=len(buffers["stdout"]), stderr_bytes=len(buffers["stderr"]),
                        )
                    pending[asyncio.create_task(readers[name].read(4096))] = name
            await process.wait()
            return bytes(buffers["stdout"]), bytes(buffers["stderr"])
        finally:
            for task in pending:
                task.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)

    @staticmethod
    async def _terminate_process_tree(process: asyncio.subprocess.Process) -> None:
        if sys.platform == "win32" and process.pid:
            try:
                killer = await asyncio.create_subprocess_exec(
                    "taskkill.exe", "/PID", str(process.pid), "/T", "/F",
                    stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
                )
                await killer.communicate()
            except (FileNotFoundError, OSError):
                pass
        try:
            process.kill()
        except ProcessLookupError:
            pass
        await process.communicate()


@dataclass(frozen=True)
class _SupervisorFrame:
    status: str
    stage: str
    substage: str | None
    error_code: str | None
    process_counts: dict[str, int]
    cleanup_ok: bool
    implementation_hash: str
    request_seen: int
    request_validated: int
    response_sent: int
    accepted_post: int
    request_hash: str | None
    response_hash: str | None
    response_byte_count: int
    output_hash: str | None
    sensitive_headers_removed: bool
    removed_count: int
    post_filter_count: int
    connection_delay_ms: int
    connection_delay_warning: bool
    stderr_byte_count: int
    stderr_sha256: str
    stderr_category: str | None
    codex_stdout_bytes: int
    codex_stdout_sha256: str | None
    codex_stdout_terminal_newline: bool
    eof_stdout_drained: bool
    eof_stderr_drained: bool
    readers_joined: bool
    usage: dict[str, int] | None
    child_schema_diagnostic: str | None
    event_types: tuple[str, ...]
    event_counts: dict[str, int]
    event_sequence_hash: str
    tool_event_count: int
    agent_message_count: int
    output_byte_count: int
    output_sha256: str | None
    last_message_exists: bool
    last_message_regular: bool
    last_message_size: int
    last_message_sha256: str | None
    last_message_match: bool
    last_message_marker_match: bool
    marker_match: bool
    codex_exit_code: int | None
    strict_http_reject_reason: str | None
    request_header_count: int
    request_body_bytes: int
    request_body_sha256: str
    request_json_keyset_hash: str | None
    input_shape: dict[str, Any] | None
    prompt_mode: str
    config_loaded_expected: bool
    argc: int

    @property
    def supervisor_processes(self) -> int:
        return self.process_counts["supervisor"]

    @property
    def bwrap_processes(self) -> int:
        return self.process_counts["broker_bwrap"] + self.process_counts["relay_codex_bwrap"]

    @property
    def codex_processes(self) -> int:
        return self.process_counts["codex_cli"]


def build_supervisor_frame_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Build the canonical supervisor frame payload shared by all emitters."""
    value = dict(SUPERVISOR_FRAME_DEFAULTS)
    value["process_counts"] = dict(SUPERVISOR_FRAME_DEFAULTS["process_counts"])
    value.update(dict(payload))
    if set(value) != SUPERVISOR_FRAME_FIELDS:
        raise ValueError("supervisor_frame_fields")
    return value


def encode_supervisor_frame(payload: Mapping[str, Any]) -> str:
    """Encode the one-line supervisor frame used by production and fakes."""
    value = build_supervisor_frame_payload(payload)
    raw = canonical_json(value).encode("utf-8")
    return SUPERVISOR_FRAME_PREFIX + base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") + "\n"


def _stream_size(value: bytes | str | None) -> int:
    if isinstance(value, bytes):
        return len(value)
    if isinstance(value, str):
        return len(value.encode("utf-8", "replace"))
    return 0


def _frame_failure(
    code: str,
    *,
    stage: str,
    result: ProcessResult,
    counts: Mapping[str, int] | None = None,
    cleanup_ok: bool | None = None,
    substage: str | None = None,
    schema_diagnostic: str | None = None,
    transport: bool = False,
) -> CodexExecutorFailure:
    observed = dict(counts or {"supervisor": 1, "broker_bwrap": 0, "relay_codex_bwrap": 0, "codex_cli": 0})
    return CodexExecutorFailure(
        code, supervisor_processes=observed.get("supervisor", 0),
        bwrap_processes=observed.get("broker_bwrap", 0) + observed.get("relay_codex_bwrap", 0),
        codex_processes=observed.get("codex_cli", 0), stage=stage, cleanup_ok=cleanup_ok,
        stdout_bytes=_stream_size(result.stdout_bytes if result.stdout_bytes is not None else result.stdout),
        stderr_bytes=_stream_size(result.stderr_bytes if result.stderr_bytes is not None else result.stderr),
        exit_code=result.exit_code, substage=substage, schema_diagnostic=schema_diagnostic, transport=transport,
    )


def _schema_frame_failure(
    diagnostic: str,
    *,
    stage: str,
    result: ProcessResult,
    counts: Mapping[str, int] | None = None,
    cleanup_ok: bool | None = None,
    substage: str | None = None,
) -> CodexExecutorFailure:
    diagnostic = {
        "missing_field": "missing_fields", "extra_field": "extra_fields",
        "bad_type": "bad_type_fields", "bad_enum": "bad_enum_fields",
    }.get(diagnostic, diagnostic)
    if diagnostic not in SUPERVISOR_SCHEMA_DIAGNOSTICS:
        diagnostic = "bad_type_fields"
    return _frame_failure(
        "supervisor_frame_schema_invalid", stage=stage, result=result, counts=counts,
        cleanup_ok=cleanup_ok, substage=substage, schema_diagnostic=diagnostic,
    )


def _strict_supervisor_frame(result: ProcessResult, expected: Mapping[str, str] | str) -> _SupervisorFrame:
    try:
        stdout = result.stdout_bytes if isinstance(result.stdout_bytes, bytes) else (
            result.stdout if isinstance(result.stdout, bytes) else result.stdout.encode("utf-8", "strict")
        )
        stderr = result.stderr_bytes if isinstance(result.stderr_bytes, bytes) else (
            result.stderr if isinstance(result.stderr, bytes) else result.stderr.encode("utf-8", "strict")
        )
    except UnicodeError as exc:
        raise _frame_failure("supervisor_frame_invalid_utf8", stage="BOOT", result=result) from exc
    if len(stdout) + len(stderr) > SUPERVISOR_OUTPUT_LIMIT_BYTES:
        raise _frame_failure("supervisor_output_limit", stage="BOOT", result=result)
    if result.exit_code != 0:
        raise _frame_failure("supervisor_transport_exit", stage="BOOT", result=result, transport=True)
    try:
        text = stdout.decode("utf-8", "strict").replace("\r\n", "\n")
    except UnicodeDecodeError as exc:
        raise _frame_failure("supervisor_frame_invalid_utf8", stage="BOOT", result=result) from exc
    lines = text.split("\n")
    while lines and lines[0] == "":
        lines.pop(0)
    while lines and lines[-1] == "":
        lines.pop()
    if not lines:
        raise _frame_failure("supervisor_frame_missing", stage="BOOT", result=result)
    if len(lines) > 1:
        code = "supervisor_frame_duplicate" if all(line.startswith(SUPERVISOR_FRAME_PREFIX) for line in lines) else "supervisor_frame_extra_output"
        raise _frame_failure(code, stage="BOOT", result=result)
    line = lines[0]
    if not line.startswith(SUPERVISOR_FRAME_PREFIX):
        raise _frame_failure("supervisor_frame_extra_output", stage="BOOT", result=result)
    encoded = line[len(SUPERVISOR_FRAME_PREFIX):]
    if not encoded or "=" in encoded or not _BASE64URL.fullmatch(encoded) or len(encoded) % 4 == 1:
        raise _frame_failure("supervisor_frame_invalid_base64", stage="BOOT", result=result)
    try:
        raw = base64.urlsafe_b64decode(encoded + "=" * ((4 - len(encoded) % 4) % 4))
        payload = json.loads(raw.decode("utf-8", "strict"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _frame_failure("supervisor_frame_invalid_json", stage="BOOT", result=result) from exc
    if not isinstance(payload, dict):
        raise _schema_frame_failure("bad_type", stage="BOOT", result=result)
    expected_fields = SUPERVISOR_FRAME_PASSED_FIELDS if payload.get("status") == "PASSED" else SUPERVISOR_FRAME_ERROR_FIELDS
    missing_fields = expected_fields - set(payload)
    extra_fields = set(payload) - expected_fields
    if missing_fields:
        raise _schema_frame_failure("missing_field", stage="BOOT", result=result)
    if extra_fields:
        raise _schema_frame_failure("extra_field", stage="BOOT", result=result)
    if canonical_json(payload).encode("utf-8") != raw:
        raise _schema_frame_failure("bad_type", stage="BOOT", result=result)
    if payload.get("schema_version") != SUPERVISOR_FRAME_SCHEMA_VERSION:
        raise _schema_frame_failure("bad_enum", stage="BOOT", result=result)
    stage = payload.get("stage")
    if payload.get("status") not in SUPERVISOR_STATUSES or stage not in SUPERVISOR_STAGES:
        raise _schema_frame_failure("bad_enum", stage="BOOT", result=result)
    substage = payload.get("substage")
    if substage is not None:
        valid_bootstrap_stage = isinstance(substage, str) and stage == "BOOT" and substage in BOOTSTRAP_SUBSTAGES
        valid_relay_stage = isinstance(substage, str) and stage == "RELAY_CODEX_SPAWN" and substage in SUPERVISOR_RELAY_SUBSTAGES
        if not (valid_bootstrap_stage or valid_relay_stage):
            raise _schema_frame_failure("bad_enum", stage=stage, result=result)
    elif stage == "RELAY_CODEX_SPAWN" and payload.get("status") != "PASSED":
        raise _schema_frame_failure("bad_enum", stage=stage, result=result)
    if not isinstance(payload.get("implementation_hash"), str) or not _DIGEST.fullmatch(payload["implementation_hash"]):
        raise _schema_frame_failure("bad_type", stage=stage, result=result)
    expected_hash = expected if isinstance(expected, str) else expected.get("implementation_hash", EXECUTOR_IMPLEMENTATION_HASH)
    if payload["implementation_hash"] != expected_hash:
        raise _frame_failure(
            "supervisor_implementation_mismatch", stage=stage, result=result,
            schema_diagnostic="hash_mismatch",
        )
    counts = payload.get("process_counts")
    if not isinstance(counts, dict) or set(counts) != set(SUPERVISOR_PROCESS_FIELDS) or any(
        isinstance(counts.get(name), bool) or not isinstance(counts.get(name), int) or counts[name] < 0 for name in SUPERVISOR_PROCESS_FIELDS
    ):
        raise _schema_frame_failure("bad_type", stage=stage, result=result)
    if (
        isinstance(payload.get("agent_message_count"), bool)
        or not isinstance(payload.get("agent_message_count"), int)
        or payload["agent_message_count"] < 0
        or isinstance(payload.get("output_byte_count"), bool)
        or not isinstance(payload.get("output_byte_count"), int)
        or payload["output_byte_count"] < 0
        or not _digest_or_none(payload.get("output_sha256"))
        or not _digest_or_none(payload.get("last_message_sha256"))
        or any(not isinstance(payload.get(name), bool) for name in (
            "last_message_match", "last_message_marker_match", "marker_match",
        ))
    ):
        raise _schema_frame_failure("bad_type", stage=stage, result=result)
    if not isinstance(payload.get("cleanup_ok"), bool):
        raise _schema_frame_failure("bad_type", stage=stage, result=result)
    reject_reason = payload.get("strict_http_reject_reason")
    if reject_reason is not None and reject_reason not in STRICT_HTTP_REJECT_REASONS:
        raise _schema_frame_failure("bad_enum", stage=stage, result=result)
    if (
        isinstance(payload.get("request_header_count"), bool)
        or not isinstance(payload.get("request_header_count"), int)
        or payload["request_header_count"] < 0
        or isinstance(payload.get("request_body_bytes"), bool)
        or not isinstance(payload.get("request_body_bytes"), int)
        or payload["request_body_bytes"] < 0
        or not isinstance(payload.get("request_body_sha256"), str)
        or not _DIGEST.fullmatch(payload["request_body_sha256"])
        or payload.get("request_json_keyset_hash") is not None
        and (not isinstance(payload.get("request_json_keyset_hash"), str) or not _DIGEST.fullmatch(payload["request_json_keyset_hash"]))
        or (payload.get("error_code") == "strict_http_rejected" and reject_reason is None)
        or not _input_shape_valid(payload.get("input_shape"))
    ):
        raise _schema_frame_failure("bad_type", stage=stage, result=result)
    counters = {name: payload.get(name) for name in RELAY_COUNTER_FIELDS}
    if any(isinstance(value, bool) or not isinstance(value, int) or value not in (0, 1) for value in counters.values()):
        raise _schema_frame_failure("bad_type", stage=stage, result=result)
    response_byte_count = payload.get("response_byte_count")
    if isinstance(response_byte_count, bool) or not isinstance(response_byte_count, int) or response_byte_count < 0:
        raise _schema_frame_failure("bad_type", stage=stage, result=result)
    if not all(_digest_or_none(payload.get(field)) for field in ("request_hash", "response_hash", "output_hash")):
        raise _schema_frame_failure("bad_type", stage=stage, result=result)
    if not isinstance(payload.get("sensitive_headers_removed"), bool):
        raise _schema_frame_failure("bad_type", stage=stage, result=result)
    if (
        isinstance(payload.get("removed_count"), bool)
        or not isinstance(payload.get("removed_count"), int)
        or payload["removed_count"] < 0
        or isinstance(payload.get("post_filter_count"), bool)
        or not isinstance(payload.get("post_filter_count"), int)
        or payload["post_filter_count"] < 0
        or payload["post_filter_count"] != 0
        or payload["sensitive_headers_removed"] is not True
        and payload["status"] == "PASSED"
    ):
        raise _frame_failure("sensitive_header_proof_invalid", stage=stage, result=result)
    if (
        isinstance(payload.get("connection_delay_ms"), bool)
        or not isinstance(payload.get("connection_delay_ms"), int)
        or payload["connection_delay_ms"] < 0
        or not isinstance(payload.get("connection_delay_warning"), bool)
            or isinstance(payload.get("stderr_byte_count"), bool)
            or not isinstance(payload.get("stderr_byte_count"), int)
            or payload["stderr_byte_count"] < 0
            or not isinstance(payload.get("stderr_sha256"), str)
            or not _DIGEST.fullmatch(payload["stderr_sha256"])
            or isinstance(payload.get("codex_stdout_bytes"), bool)
            or not isinstance(payload.get("codex_stdout_bytes"), int)
            or payload["codex_stdout_bytes"] < 0
            or not _digest_or_none(payload.get("codex_stdout_sha256"))
            or not isinstance(payload.get("codex_stdout_terminal_newline"), bool)
            or not isinstance(payload.get("eof_stdout_drained"), bool)
            or not isinstance(payload.get("eof_stderr_drained"), bool)
            or not isinstance(payload.get("readers_joined"), bool)
            or payload.get("child_schema_diagnostic") not in {None, *SUPERVISOR_SCHEMA_DIAGNOSTICS}
        or payload.get("stderr_category") not in {
            None, "CODEX_HOME_WRITE_FAILED", "ARG0_INIT_FAILED", "CONFIG_LOAD_FAILED", "AUTH_REQUIRED",
            "CLI_USAGE_ERROR", "STRICT_CONFIG_ERROR", "CONFIG_INVALID", "PROVIDER_MISSING",
            "AUTH_ENV_MISSING", "CHILD_EXIT_OTHER",
        }
        or payload.get("prompt_mode") != "STDIN_FORCED"
        or payload.get("config_loaded_expected") is not True
        or isinstance(payload.get("argc"), bool)
        or not isinstance(payload.get("argc"), int)
            or payload.get("argc") != len(FIXED_CODEX_ARGV)
            or not isinstance(payload.get("event_types"), list)
            or any(not isinstance(item, str) or item not in CODEX_JSONL_EVENT_TYPES for item in payload["event_types"])
            or not isinstance(payload.get("event_counts"), dict)
                or any(not isinstance(key, str) or key not in CODEX_JSONL_EVENT_TYPES or isinstance(value, bool) or not isinstance(value, int) or value < 0
                       for key, value in payload["event_counts"].items())
            or not isinstance(payload.get("event_sequence_hash"), str)
            or not _DIGEST.fullmatch(payload["event_sequence_hash"])
            or isinstance(payload.get("tool_event_count"), bool)
            or not isinstance(payload.get("tool_event_count"), int)
            or payload["tool_event_count"] < 0
            or any(not isinstance(payload.get(name), bool) for name in (
                "last_message_exists", "last_message_regular", "last_message_marker_match",
            ))
            or isinstance(payload.get("last_message_size"), bool)
            or not isinstance(payload.get("last_message_size"), int)
            or payload["last_message_size"] < 0
            or payload.get("codex_exit_code") is not None and (isinstance(payload.get("codex_exit_code"), bool) or not isinstance(payload.get("codex_exit_code"), int))
        ):
        raise _schema_frame_failure("bad_type", stage=stage, result=result)
    usage = payload.get("usage")
    if usage is not None and (
        not isinstance(usage, dict)
        or set(usage) != CODEX_TURN_COMPLETED_USAGE_FIELDS
        or any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in usage.values()
        )
    ):
        raise _schema_frame_failure("bad_type", stage=stage, result=result)
    observed_event_counts: dict[str, int] = {}
    for kind in payload["event_types"]:
        observed_event_counts[kind] = observed_event_counts.get(kind, 0) + 1
    expected_event_sequence_hash = hashlib.sha256(
        canonical_json({
            "event_types": payload["event_types"],
            "event_counts": payload["event_counts"],
        }).encode("utf-8")
    ).hexdigest()
    if (
        observed_event_counts != payload["event_counts"]
        or payload["event_sequence_hash"] != expected_event_sequence_hash
        or counters["accepted_post"] != counters["request_validated"]
        or counters["response_sent"] > counters["accepted_post"]
        or counters["request_validated"] > counters["request_seen"]
        or counters["response_sent"] == 0 and response_byte_count != 0
        or counters["response_sent"] == 1 and response_byte_count <= 0
        or payload["last_message_regular"] and not payload["last_message_exists"]
        or payload["last_message_match"] != payload["last_message_marker_match"]
        or payload["last_message_match"] and (
            not payload["last_message_exists"]
            or not payload["last_message_regular"]
            or payload["last_message_sha256"] is None
        )
        or payload["last_message_marker_match"] and (
            not payload["last_message_exists"] or not payload["last_message_regular"]
        )
        or payload["agent_message_count"] == 0 and (
            payload["output_byte_count"] != 0 or payload["output_sha256"] is not None
        )
        or payload["agent_message_count"] > 0 and (
            payload["output_byte_count"] <= 0 or payload["output_sha256"] is None
        )
        or payload["marker_match"] and (
            payload["agent_message_count"] != 1
            or payload["output_sha256"] is None
            or payload["last_message_sha256"] is None
            or not payload["last_message_match"]
            or payload["output_sha256"] != payload["last_message_sha256"]
        )
    ):
        raise _frame_failure(
            "response_proof_invalid", stage=stage, result=result, counts=counts,
            cleanup_ok=payload["cleanup_ok"], substage=substage,
        )
    if counts["supervisor"] != 1:
        raise _frame_failure("supervisor_process_count_invalid", stage=stage, result=result)
    if stage in {"BOOT", "CLAIM_VALIDATE", "SPEC_VALIDATE", "RUNTIME_VALIDATE"} and any(
        counts[name] for name in ("broker_bwrap", "relay_codex_bwrap", "codex_cli")
    ):
        raise _frame_failure("supervisor_process_count_invalid", stage=stage, result=result)
    error = payload.get("error_code")
    if error is not None and (not isinstance(error, str) or error not in SUPERVISOR_FRAME_ERROR_CODES):
        raise _schema_frame_failure("bad_enum", stage=stage, result=result)
    if error == "response_not_consumed" and not (
        counters == {
            "request_seen": 1, "request_validated": 1,
            "response_sent": 1, "accepted_post": 1,
        }
        and payload.get("response_hash") == EXPECTED_RESPONSE_HASH
        and response_byte_count == len(SEALED_RESPONSE_BODY_BYTES)
        and payload["eof_stdout_drained"]
        and payload["eof_stderr_drained"]
        and payload["readers_joined"]
        and payload["event_counts"].get("turn.completed", 0) == 0
    ):
        raise _frame_failure(
            "response_proof_invalid", stage=stage, result=result, counts=counts,
            cleanup_ok=payload["cleanup_ok"], substage=substage,
        )
    if payload["status"] == "PASSED":
        if (
            error is not None or stage != "CLEANUP" or not payload["cleanup_ok"]
            or counts != {"supervisor": 1, "broker_bwrap": 1, "relay_codex_bwrap": 1, "codex_cli": 1}
            or counters != {
                "request_seen": 1, "request_validated": 1, "response_sent": 1, "accepted_post": 1,
            }
            or not all(_DIGEST.fullmatch(str(payload.get(field) or "")) for field in ("request_hash", "response_hash", "output_hash"))
            or payload["response_hash"] != EXPECTED_RESPONSE_HASH
            or payload["output_hash"] != EXPECTED_OUTPUT_HASH
            or payload["output_hash"] != payload["output_sha256"]
            or response_byte_count != len(SEALED_RESPONSE_BODY_BYTES)
            or not payload["sensitive_headers_removed"] or substage is not None
            or payload["event_counts"].get("thread.started") != 1
            or payload["event_counts"].get("turn.started") != 1
            or payload["event_counts"].get("item.completed", 0) < 1
            or payload["event_counts"].get("turn.completed") != 1
            or payload["event_types"][0] != "thread.started"
            or payload["event_types"][-1] != "turn.completed"
            or payload["tool_event_count"] != 0
            or payload["agent_message_count"] != 1
            or payload["output_byte_count"] != len(SUCCESS_MARKER.encode("utf-8"))
            or payload["output_sha256"] != EXPECTED_OUTPUT_HASH
            or not payload["eof_stdout_drained"] or not payload["eof_stderr_drained"]
            or not payload["readers_joined"]
            or usage is None
            or not payload["last_message_exists"] or not payload["last_message_regular"]
            or payload["last_message_sha256"] != EXPECTED_OUTPUT_HASH
            or not payload["last_message_match"]
            or not payload["last_message_marker_match"]
            or not payload["marker_match"]
            or payload.get("codex_exit_code") != 0
        ):
            raise _frame_failure(
                "supervisor_success_proof_invalid",
                stage=stage,
                result=result,
                counts=counts,
                cleanup_ok=payload["cleanup_ok"],
                substage=substage,
            )
    if payload["status"] != "PASSED" and error is None:
        raise _schema_frame_failure("bad_enum", stage=stage, result=result)
    return _SupervisorFrame(
        payload["status"], stage, substage, error, dict(counts), payload["cleanup_ok"], payload["implementation_hash"],
        counters["request_seen"], counters["request_validated"], counters["response_sent"], counters["accepted_post"],
        payload["request_hash"], payload["response_hash"], response_byte_count, payload["output_hash"], payload["sensitive_headers_removed"], payload["removed_count"], payload["post_filter_count"],
        payload["connection_delay_ms"], payload["connection_delay_warning"], payload["stderr_byte_count"],
        payload["stderr_sha256"], payload["stderr_category"], payload["codex_stdout_bytes"], payload["codex_stdout_sha256"], payload["codex_stdout_terminal_newline"],
        payload["eof_stdout_drained"], payload["eof_stderr_drained"],
        payload["readers_joined"], dict(usage) if usage is not None else None,
        payload["child_schema_diagnostic"],
        tuple(payload["event_types"]), dict(payload["event_counts"]), payload["event_sequence_hash"],
        payload["tool_event_count"], payload["agent_message_count"], payload["output_byte_count"], payload["output_sha256"],
        payload["last_message_exists"], payload["last_message_regular"], payload["last_message_size"],
        payload["last_message_sha256"], payload["last_message_match"], payload["last_message_marker_match"], payload["marker_match"],
        payload["codex_exit_code"], payload["strict_http_reject_reason"], payload["request_header_count"], payload["request_body_bytes"],
        payload["request_body_sha256"], payload["request_json_keyset_hash"], payload.get("input_shape"), payload["prompt_mode"],
        payload["config_loaded_expected"], payload["argc"],
    )


def parse_supervisor_frame(result: ProcessResult, expected_implementation_hash: str = EXECUTOR_IMPLEMENTATION_HASH) -> _SupervisorFrame:
    """Public read-only parser seam used by the fake-supervisor tests."""
    return _strict_supervisor_frame(result, expected_implementation_hash)


class WSLCodexProcessCanaryExecutor:
    """One fresh sealed supervisor executor for one ``RUNNING`` claim only."""

    is_production_executor = True

    def __init__(self, store, execution_claim_id: str, runner: Any | None = None):
        try:
            uuid.UUID(execution_claim_id)
        except (TypeError, ValueError) as exc:
            raise PolicyError("canary_execution_claim_invalid") from exc
        claim = store.codex_canary_execution_claim_by_id(execution_claim_id)
        if claim.get("status") != "RUNNING" or int(claim.get("spawn_count") or 0) != 0:
            raise PolicyError("canary_execution_claim_not_runnable")
        self.store = store
        self.execution_claim_id = execution_claim_id
        self.runner = runner or SealedWSLSupervisorRunner()
        self.calls = 0

    async def run(self, binding: Mapping[str, str], canary_launch_spec: Mapping[str, Any]):
        claim = self.store.validate_running_codex_canary_execution_claim(self.execution_claim_id, binding)
        if claim.get("runner_implementation_hash") != EXECUTOR_IMPLEMENTATION_HASH:
            raise PolicyError("canary_implementation_mismatch")
        runtime = self.store.wsl_codex_runtime_result()
        config = self.store.wsl_codex_runtime_config_private()
        if not isinstance(runtime, Mapping) or not isinstance(config, Mapping):
            raise PolicyError("runtime_identity_missing")
        if any(runtime.get(field) != binding.get(field) for field in ("runtime_fingerprint", "launch_spec_hash", "binary_sha256", "isolation_cache_key")):
            raise PolicyError("execution_binding_changed")
        binary_path = config.get("binary_path")
        if not isinstance(binary_path, str):
            raise PolicyError("runtime_identity_missing")
        spec = build_codex_executor_launch_spec(
            binary_path, runtime_binary_sha256=binding.get("binary_sha256")
        )
        if spec["executor_implementation_hash"] != binding.get("implementation_hash"):
            raise PolicyError("canary_implementation_mismatch")
        if spec.get("wire_contract_hash") != WIRE_CONTRACT_HASH or canary_launch_spec.get("wire_contract_hash") != WIRE_CONTRACT_HASH:
            raise PolicyError("codex_wire_contract_mismatch")
        if WIRE_CONTRACT_STATUS != "PARSER_PROVEN" and isinstance(self.runner, SealedWSLSupervisorRunner):
            raise PolicyError("codex_wire_contract_unproven")
        if canary_launch_spec.get("contract_hash") != binding.get("contract_hash") or provider_config_hash(canonical_provider_toml()) != binding.get("config_hash"):
            raise PolicyError("execution_binding_changed")
        if validate_wsl_distro(self.store.wsl_isolation_config().get("distro")) != "Ubuntu":
            raise PolicyError("distro_not_ubuntu")
        wsl_executable = self.runner.find_wsl()
        if not wsl_executable:
            raise PolicyError("wsl_unavailable")
        argv = build_codex_supervisor_argv(wsl_executable)
        payload = build_supervisor_bootstrap_payload(self.execution_claim_id, spec)
        self.store.reserve_codex_canary_supervisor_spawn(self.execution_claim_id, binding)
        self.calls += 1
        try:
            process = await self.runner.run(
                argv, payload=payload, timeout_seconds=SUPERVISOR_TIMEOUT_SECONDS,
                on_started=lambda: self.store.mark_codex_canary_supervisor_spawned(self.execution_claim_id, binding),
            )
        except CodexExecutorFailure:
            raise
        except TimeoutError as exc:
            raise CodexExecutorFailure("supervisor_transport_timeout", stage="BOOT", supervisor_processes=1, transport=True) from exc
        except Exception as exc:
            raise CodexExecutorFailure("supervisor_transport_error", stage="BOOT", supervisor_processes=1, transport=True) from exc
        frame = _strict_supervisor_frame(process, EXECUTOR_IMPLEMENTATION_HASH)
        if frame.status != "PASSED":
            raise CodexExecutorFailure(
                frame.error_code or "supervisor_workload_error", stage=frame.stage,
                supervisor_processes=frame.supervisor_processes, bwrap_processes=frame.bwrap_processes,
                codex_processes=frame.codex_processes, cleanup_ok=frame.cleanup_ok, substage=frame.substage,
                connection_delay_ms=frame.connection_delay_ms, child_exit_category=frame.stderr_category,
                event_types=frame.event_types, event_counts=frame.event_counts,
                event_sequence_hash=frame.event_sequence_hash, tool_event_count=frame.tool_event_count,
                agent_message_count=frame.agent_message_count,
                output_byte_count=frame.output_byte_count, output_sha256=frame.output_sha256,
                request_seen=frame.request_seen, request_validated=frame.request_validated,
                response_sent=frame.response_sent, accepted_post=frame.accepted_post,
                request_hash=frame.request_hash, sensitive_headers_removed=frame.sensitive_headers_removed,
                removed_count=frame.removed_count, post_filter_count=frame.post_filter_count,
                response_hash=frame.response_hash,
                response_byte_count=frame.response_byte_count,
                last_message_exists=frame.last_message_exists, last_message_regular=frame.last_message_regular,
                last_message_size=frame.last_message_size,
                last_message_sha256=frame.last_message_sha256, last_message_match=frame.last_message_match,
                last_message_marker_match=frame.last_message_marker_match,
                marker_match=frame.marker_match, output_hash=frame.output_hash,
                stdout_eof=frame.eof_stdout_drained, stderr_eof=frame.eof_stderr_drained,
                readers_joined=frame.readers_joined,
                codex_exit_code=frame.codex_exit_code, stderr_sha256=frame.stderr_sha256,
                strict_http_reject_reason=frame.strict_http_reject_reason,
                request_header_count=frame.request_header_count, request_body_bytes=frame.request_body_bytes,
                request_body_sha256=frame.request_body_sha256, request_json_keyset_hash=frame.request_json_keyset_hash,
                input_shape=frame.input_shape,
                schema_diagnostic=frame.child_schema_diagnostic,
                stdout_bytes=_stream_size(process.stdout_bytes if process.stdout_bytes is not None else process.stdout),
                stderr_bytes=_stream_size(process.stderr_bytes if process.stderr_bytes is not None else process.stderr),
                exit_code=frame.codex_exit_code if frame.codex_exit_code is not None else process.exit_code,
            )
        # Import only after construction to keep this module free of a cycle.
        from .codex_process_canary import CanaryExecution

        # The frame contains only relay-observed digests.  Do not manufacture
        # request, response, or marker proof from expectations on the host.
        separate_stream_byte_count(process)
        return CanaryExecution(
            request_count=frame.accepted_post, request_seen=frame.request_seen, request_validated=frame.request_validated,
            response_sent=frame.response_sent, accepted_post=frame.accepted_post,
            response_byte_count=frame.response_byte_count,
            event_types=frame.event_types, event_counts=frame.event_counts,
            event_sequence_hash=frame.event_sequence_hash, tool_event_count=frame.tool_event_count,
            agent_message_count=frame.agent_message_count,
            output_byte_count=frame.output_byte_count, output_sha256=frame.output_sha256,
            last_message_exists=frame.last_message_exists, last_message_regular=frame.last_message_regular,
            last_message_size=frame.last_message_size, last_message_marker_match=frame.last_message_marker_match,
            last_message_sha256=frame.last_message_sha256, last_message_match=frame.last_message_match,
            marker_match=frame.marker_match,
            stdout_eof=frame.eof_stdout_drained, stderr_eof=frame.eof_stderr_drained,
            readers_joined=frame.readers_joined,
            codex_exit_code=frame.codex_exit_code, stderr_sha256=frame.stderr_sha256,
            strict_http_reject_reason=frame.strict_http_reject_reason,
            request_header_count=frame.request_header_count, request_body_bytes=frame.request_body_bytes,
            request_body_sha256=frame.request_body_sha256, request_json_keyset_hash=frame.request_json_keyset_hash,
            input_shape=frame.input_shape,
            stderr_category=frame.stderr_category,
            request_hash=frame.request_hash or "", response_hash=frame.response_hash or "",
            config_hash=EXPECTED_CONFIG_HASH, prompt_hash=EXPECTED_PROMPT_HASH, expected_output_hash=EXPECTED_OUTPUT_HASH,
            exit_code=process.exit_code or 0,
            stdout_bytes=_stream_size(process.stdout_bytes if process.stdout_bytes is not None else process.stdout),
            stderr_bytes=_stream_size(process.stderr_bytes if process.stderr_bytes is not None else process.stderr),
            local_processes=frame.supervisor_processes + frame.bwrap_processes + frame.codex_processes,
            marker=None, output_hash=frame.output_hash, marker_verified=frame.output_hash == EXPECTED_OUTPUT_HASH,
            sensitive_headers_removed=frame.sensitive_headers_removed,
            removed_count=frame.removed_count, post_filter_count=frame.post_filter_count,
            process_terminated=True, resources_cleaned=frame.cleanup_ok,
            runner_kind="WSL_CODEX_CANARY", runner_version=EXECUTOR_VERSION,
            runner_implementation_hash=EXECUTOR_IMPLEMENTATION_HASH,
            supervisor_processes=frame.supervisor_processes, bwrap_processes=frame.bwrap_processes,
            codex_processes=frame.codex_processes,
            supervisor_stage=frame.stage, cleanup_ok=frame.cleanup_ok,
        )


def production_executor_factory(store) -> Callable[[str], WSLCodexProcessCanaryExecutor]:
    """Return a per-claim factory; it does not construct an executor yet."""
    return lambda execution_claim_id: WSLCodexProcessCanaryExecutor(store, execution_claim_id)
