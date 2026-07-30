"""Immutable, local-only contract for a future sealed Codex egress path.

Phase 1 describes the only acceptable custom-provider, relay, and broker
boundary.  It deliberately opens no socket, launches no Codex process, and
does not materialize an authentication value.
"""
from __future__ import annotations

import hashlib
import re
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping
from urllib.parse import urlsplit

from .isolation_repro import REPRO_RUNS, REPRO_VERSION, SAFE_REPRODUCIBLE
from .policy import PolicyError, canonical_json, sha256_json, validate_sealed_loopback_base_url
from .storage import RUNTIME_IDENTITY_VERSION


UNCONFIGURED = "UNCONFIGURED"
CONTRACT_READY = "CONTRACT_READY"
RELAY_MISSING = "RELAY_MISSING"
BROKER_MISSING = "BROKER_MISSING"
AUTH_UNCONFIGURED = "AUTH_UNCONFIGURED"
READY_CANDIDATE = "READY_CANDIDATE"
BLOCKED = "BLOCKED"
ERROR = "ERROR"

EGRESS_CONTRACT_POLICY_VERSION = "sealed-egress-contract-v1"
CUSTOM_PROVIDER_ID = "codexgate-sealed"
LOOPBACK_HOST = "127.0.0.1"
LOOPBACK_PORT = 8788
# The sealed endpoint is the single source of truth for every local provider,
# relay, and broker authority.  Consumers must import this contract rather
# than carrying a second loopback port or authority literal.
SEALED_LOOPBACK_ENDPOINT = (LOOPBACK_HOST, LOOPBACK_PORT)
SEALED_LOOPBACK_AUTHORITY = f"{LOOPBACK_HOST}:{LOOPBACK_PORT}"
SEALED_BASE_URL = f"http://{SEALED_LOOPBACK_AUTHORITY}/v1"
EPHEMERAL_TOKEN_ENV = "CODEXGATE_EPHEMERAL_TOKEN"
BROKER_SOCKET_PATH = "/runtime-state/codexgate-broker.sock"
BROKER_REQUEST_PATH = "/v1/responses"
MAX_REQUEST_BYTES = 256 * 1024
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
BROKER_TIMEOUT_SECONDS = 120
HARNESS_EXPECTED_SECONDS = 30
MIN_CANARY_RESERVE_SECONDS = 5 * 60
CANARY_REQUIRED_REMAINING_SECONDS = HARNESS_EXPECTED_SECONDS + MIN_CANARY_RESERVE_SECONDS
_EMPTY_PROOF_HASH = "0" * 64

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_HEADER = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}$")
_STRIPPED_HEADERS = frozenset({"authorization", "cookie", "proxy-authorization", "proxy-connection"})


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def provider_config(base_url: str = SEALED_BASE_URL) -> dict[str, Any]:
    """Return the complete, closed custom-provider configuration."""
    base_url = validate_sealed_loopback_base_url(base_url)
    return {
        "name": "CodexGate sealed broker",
        "base_url": base_url,
        "wire_api": "responses",
        "requires_openai_auth": False,
        "env_key": EPHEMERAL_TOKEN_ENV,
        "supports_websockets": False,
        "request_max_retries": 0,
        "stream_max_retries": 0,
    }


def expected_repro_key(config_hash: str, tool_fingerprint: str) -> str:
    """Derive the Repro identity without reusing the Isolation cache key."""
    for name, value in (("config_hash", config_hash), ("tool_fingerprint", tool_fingerprint)):
        if not isinstance(value, str) or not _DIGEST.fullmatch(value):
            raise PolicyError(f"{name} is invalid")
    return sha256_json({
        "config_hash": config_hash,
        "tool_fingerprint": tool_fingerprint,
        "repro_version": REPRO_VERSION,
    })


def validate_sealed_execution_proof(store, *, now: datetime | None = None) -> tuple[dict[str, str] | None, str | None]:
    """Validate a fresh Canary and its exact current-environment Repro record."""
    isolation = store.wsl_isolation_result()
    if not isinstance(isolation, Mapping) or isolation.get("status") != "SAFE_CANDIDATE":
        return None, "isolation_not_safe"
    current = now or datetime.now(timezone.utc)
    try:
        expires_at = datetime.fromisoformat(str(isolation.get("expires_at")))
        if expires_at.tzinfo is None:
            raise ValueError
    except (TypeError, ValueError):
        return None, "isolation_expiry_invalid"
    if expires_at < current + timedelta(seconds=CANARY_REQUIRED_REMAINING_SECONDS):
        return None, "isolation_expiring"
    config_hash = isolation.get("config_hash")
    tool_fingerprint = isolation.get("tool_fingerprint")
    try:
        repro_key = expected_repro_key(config_hash, tool_fingerprint)
    except PolicyError:
        return None, "isolation_identity_missing"
    repro = store.wsl_isolation_repro(repro_key)
    if not isinstance(repro, Mapping):
        return None, "repro_missing"
    if repro.get("status") != SAFE_REPRODUCIBLE:
        return None, "repro_not_safe"
    if (
        repro.get("requested_runs") != REPRO_RUNS
        or repro.get("completed_runs") != REPRO_RUNS
        or repro.get("success_count") != REPRO_RUNS
    ):
        return None, "repro_incomplete"
    if repro.get("config_hash") != config_hash or repro.get("tool_fingerprint") != tool_fingerprint:
        return None, "repro_binding_changed"
    result_hash = repro.get("result_hash")
    if not isinstance(result_hash, str) or not _DIGEST.fullmatch(result_hash):
        return None, "repro_result_invalid"
    if repro.get("cache_key") != repro_key:
        return None, "repro_key_invalid"
    return {
        "repro_version": REPRO_VERSION,
        "repro_key": repro_key,
        "repro_result_hash": result_hash,
    }, None


def canonical_provider_toml(base_url: str = SEALED_BASE_URL) -> bytes:
    """Build the fixed config.toml bytes for an ephemeral CODEX_HOME.

    The return value is private process-input material.  Callers persist only
    its digest and the redacted provider snapshot below.
    """
    config = provider_config(base_url)
    lines = [
        f'model_provider = "{CUSTOM_PROVIDER_ID}"',
        "",
        f"[model_providers.{CUSTOM_PROVIDER_ID}]",
    ]
    for key in (
        "name", "base_url", "wire_api", "requires_openai_auth", "env_key",
        "supports_websockets", "request_max_retries", "stream_max_retries",
    ):
        value = config[key]
        if isinstance(value, str):
            lines.append(f'{key} = {canonical_json(value)}')
        elif isinstance(value, bool):
            lines.append(f"{key} = {'true' if value else 'false'}")
        else:
            lines.append(f"{key} = {value}")
    return ("\n".join(lines) + "\n").encode("utf-8")


def provider_config_hash(config_bytes: bytes) -> str:
    if not isinstance(config_bytes, bytes) or not config_bytes:
        raise PolicyError("sealed provider config must be non-empty bytes")
    return hashlib.sha256(config_bytes).hexdigest()


def provider_snapshot(base_url: str = SEALED_BASE_URL) -> dict[str, Any]:
    """Return only fields safe for SQLite, API, and UI presentation."""
    config = provider_config(base_url)
    return {
        "provider_id": CUSTOM_PROVIDER_ID,
        "endpoint_type": "LOOPBACK_HTTP_V1",
        "wire_api": config["wire_api"],
        "requires_openai_auth": config["requires_openai_auth"],
        "env_key_name": config["env_key"],
        "supports_websockets": config["supports_websockets"],
        "request_max_retries": config["request_max_retries"],
        "stream_max_retries": config["stream_max_retries"],
    }


def relay_contract(base_url: str = SEALED_BASE_URL, unix_socket: str = BROKER_SOCKET_PATH) -> dict[str, Any]:
    """Describe the relay without opening any listener or Unix socket."""
    base_url = validate_sealed_loopback_base_url(base_url)
    validate_broker_socket(unix_socket)
    parsed = urlsplit(base_url)
    return {
        "listen": {
            "scheme": parsed.scheme,
            "host": LOOPBACK_HOST,
            "port": LOOPBACK_PORT,
            "path_prefix": "/v1",
        },
        "external_outputs": [{"transport": "unix_socket", "path": unix_socket}],
        "dns_allowed": False,
        "internet_allowed": False,
        "other_unix_sockets_allowed": False,
    }


def validate_broker_socket(value: str) -> str:
    if value != BROKER_SOCKET_PATH:
        raise PolicyError("sealed relay permits exactly one fixed Unix socket")
    return value


def broker_contract(unix_socket: str = BROKER_SOCKET_PATH) -> dict[str, Any]:
    validate_broker_socket(unix_socket)
    return {
        "listen": {"transport": "unix_socket", "path": unix_socket},
        "allowed_methods": ["POST"],
        "allowed_paths": [BROKER_REQUEST_PATH],
        "required_host": SEALED_LOOPBACK_AUTHORITY,
        "reject_connect": True,
        "reject_redirects": True,
        "reject_absolute_form": True,
        "request_max_bytes": MAX_REQUEST_BYTES,
        "response_max_bytes": MAX_RESPONSE_BYTES,
        "timeout_seconds": BROKER_TIMEOUT_SECONDS,
        "strip_headers": ["Authorization", "Cookie", "Proxy-*"],
        "authentication": "future_broker_injection_only",
        "store_raw_bodies": False,
    }


def sanitize_broker_headers(headers: Mapping[str, str]) -> dict[str, str]:
    """Remove caller supplied credentials and proxy headers before forwarding."""
    if not isinstance(headers, Mapping):
        raise PolicyError("broker headers must be a mapping")
    clean: dict[str, str] = {}
    for name, value in headers.items():
        if not isinstance(name, str) or not _HEADER.fullmatch(name) or not isinstance(value, str):
            raise PolicyError("broker header is invalid")
        lowered = name.casefold()
        if lowered in _STRIPPED_HEADERS or lowered.startswith("proxy-"):
            continue
        clean[name] = value
    return clean


def validate_broker_request(method: str, path: str, headers: Mapping[str, str], body_bytes: int) -> dict[str, str]:
    """Validate a future broker request without performing any I/O."""
    if method != "POST":
        raise PolicyError("sealed broker permits POST only")
    if not isinstance(path, str) or path != BROKER_REQUEST_PATH:
        raise PolicyError("sealed broker permits /v1/responses only")
    if path.startswith(("http://", "https://")) or "://" in path:
        raise PolicyError("absolute-form request targets are forbidden")
    if not isinstance(body_bytes, int) or isinstance(body_bytes, bool) or not 0 <= body_bytes <= MAX_REQUEST_BYTES:
        raise PolicyError("sealed broker request body exceeds its limit")
    clean = sanitize_broker_headers(headers)
    host_values = [value for name, value in clean.items() if name.casefold() == "host"]
    if len(host_values) != 1 or host_values[0].casefold() != SEALED_LOOPBACK_AUTHORITY:
        raise PolicyError("sealed broker host is invalid")
    return clean


def validate_broker_response(status_code: int, body_bytes: int) -> None:
    if not isinstance(status_code, int) or isinstance(status_code, bool) or not 100 <= status_code <= 599:
        raise PolicyError("broker response status is invalid")
    if 300 <= status_code < 400:
        raise PolicyError("broker redirects are forbidden")
    if not isinstance(body_bytes, int) or isinstance(body_bytes, bool) or not 0 <= body_bytes <= MAX_RESPONSE_BYTES:
        raise PolicyError("sealed broker response body exceeds its limit")


def build_private_contract(
    *,
    runtime_fingerprint: str,
    isolation_cache_key: str,
    binary_sha256: str,
    runtime_identity_version: str = RUNTIME_IDENTITY_VERSION,
    launch_spec_hash: str = _EMPTY_PROOF_HASH,
    isolation_config_hash: str = _EMPTY_PROOF_HASH,
    isolation_tool_fingerprint: str = _EMPTY_PROOF_HASH,
    repro_version: str = REPRO_VERSION,
    repro_key: str = _EMPTY_PROOF_HASH,
    repro_result_hash: str = _EMPTY_PROOF_HASH,
    base_url: str = SEALED_BASE_URL,
) -> dict[str, Any]:
    """Construct a deterministic private contract from sealed runtime inputs."""
    for name, value in {
        "runtime fingerprint": runtime_fingerprint,
        "isolation cache key": isolation_cache_key,
        "binary SHA-256": binary_sha256,
        "launch-spec hash": launch_spec_hash,
        "isolation config hash": isolation_config_hash,
        "isolation tool fingerprint": isolation_tool_fingerprint,
        "Repro key": repro_key,
        "Repro result SHA-256": repro_result_hash,
    }.items():
        if not isinstance(value, str) or not _DIGEST.fullmatch(value):
            raise PolicyError(f"{name} is invalid")
    if runtime_identity_version != RUNTIME_IDENTITY_VERSION:
        raise PolicyError("runtime identity version is invalid")
    if repro_version != REPRO_VERSION:
        raise PolicyError("Repro version is invalid")
    config_bytes = canonical_provider_toml(base_url)
    config_hash = provider_config_hash(config_bytes)
    relay = relay_contract(base_url)
    broker = broker_contract()
    binding = {
        "policy_version": EGRESS_CONTRACT_POLICY_VERSION,
        "runtime_identity_version": runtime_identity_version,
        "runtime_fingerprint": runtime_fingerprint,
        "launch_spec_hash": launch_spec_hash,
        "isolation_cache_key": isolation_cache_key,
        "isolation_config_hash": isolation_config_hash,
        "isolation_tool_fingerprint": isolation_tool_fingerprint,
        "binary_sha256": binary_sha256,
        "repro_version": repro_version,
        "repro_key": repro_key,
        "repro_result_hash": repro_result_hash,
        "provider_config_hash": config_hash,
    }
    identity = {
        **binding,
        "provider": provider_snapshot(base_url),
        "relay": relay,
        "broker": broker,
    }
    return {
        "identity": identity,
        "current_binding_hash": sha256_json(binding),
        "contract_hash": sha256_json(identity),
        "config_toml_bytes": config_bytes,
    }


def public_contract_result(result: Mapping[str, Any] | None) -> dict[str, Any]:
    if not isinstance(result, Mapping):
        return {"status": UNCONFIGURED, "start_allowed": False, "endpoint_type": "UNCONFIGURED", "created": False, "reused": False}
    fields = (
        "contract_id", "preview_hash", "status", "checked_at", "contract_hash", "endpoint_type", "relay_status",
        "broker_status", "auth_status", "start_allowed", "error_code", "created", "reused",
    )
    value = {field: result.get(field) for field in fields if field in result}
    value.setdefault("created", False)
    value.setdefault("reused", False)
    return value


def public_contract_preview(result: Mapping[str, Any] | None) -> dict[str, Any]:
    """Expose a redacted, read-only preview without making it executable."""
    if not isinstance(result, Mapping):
        return {
            "status": UNCONFIGURED,
            "preview_hash": None,
            "current_binding_hash": None,
            "instance_stored": False,
            "start_allowed": False,
            "endpoint_type": UNCONFIGURED,
        }
    fields = (
        "status", "preview_hash", "current_binding_hash", "instance_stored", "checked_at",
        "endpoint_type", "relay_status", "broker_status", "auth_status", "start_allowed", "error_code",
    )
    return {field: result.get(field) for field in fields if field in result}


class SealedEgressContractService:
    """Creates and revalidates the no-I/O egress contract."""

    def __init__(self, store, *, proof_required: bool = False):
        self.store = store
        self.proof_required = proof_required

    def _inputs(self) -> tuple[Mapping[str, Any] | None, Mapping[str, Any] | None, dict[str, str] | None, str | None]:
        runtime = self.store.wsl_codex_runtime_result()
        isolation = self.store.wsl_isolation_result()
        problem = self._binding_problem(runtime, isolation)
        if problem:
            return runtime, isolation, None, problem
        proof, proof_error = validate_sealed_execution_proof(self.store)
        if self.proof_required and proof is None:
            return runtime, isolation, None, proof_error or "repro_missing"
        return runtime, isolation, proof or {
            "repro_version": REPRO_VERSION,
            "repro_key": _EMPTY_PROOF_HASH,
            "repro_result_hash": _EMPTY_PROOF_HASH,
        }, None

    @staticmethod
    def _blocked_preview(error_code: str) -> dict[str, Any]:
        return {
            "status": BLOCKED,
            "preview_only": True,
            "instance_stored": False,
            "preview_hash": None,
            "current_binding_hash": None,
            "contract_hash": None,
            "checked_at": _now(),
            "endpoint_type": UNCONFIGURED,
            "relay_status": RELAY_MISSING,
            "broker_status": BROKER_MISSING,
            "auth_status": AUTH_UNCONFIGURED,
            "start_allowed": False,
            "error_code": error_code,
        }

    def preview(self) -> dict[str, Any]:
        """Purely calculate the current preview; this method never writes SQLite."""
        runtime, isolation, proof, problem = self._inputs()
        if problem:
            return self._blocked_preview(problem)
        assert isinstance(runtime, Mapping) and isinstance(isolation, Mapping) and proof is not None
        private = build_private_contract(
            runtime_fingerprint=runtime["runtime_fingerprint"],
            isolation_cache_key=isolation["cache_key"],
            binary_sha256=runtime["binary_sha256"],
            runtime_identity_version=runtime["identity_version"],
            launch_spec_hash=runtime["launch_spec_hash"],
            isolation_config_hash=isolation["config_hash"],
            isolation_tool_fingerprint=isolation["tool_fingerprint"],
            **proof,
        )
        snapshot = provider_snapshot()
        return {
            "status": CONTRACT_READY,
            "preview_only": True,
            "instance_stored": False,
            "preview_hash": private["contract_hash"],
            "current_binding_hash": private["current_binding_hash"],
            "contract_hash": None,
            "checked_at": _now(),
            "runtime_identity_version": runtime["identity_version"],
            "runtime_fingerprint": runtime["runtime_fingerprint"],
            "launch_spec_hash": runtime["launch_spec_hash"],
            "isolation_config_hash": isolation["config_hash"],
            "isolation_tool_fingerprint": isolation["tool_fingerprint"],
            "isolation_cache_key": isolation["cache_key"],
            "binary_sha256": runtime["binary_sha256"],
            **proof,
            "provider_config_hash": provider_config_hash(private["config_toml_bytes"]),
            "contract_policy_version": EGRESS_CONTRACT_POLICY_VERSION,
            "endpoint_type": snapshot["endpoint_type"],
            "provider_snapshot": snapshot,
            "relay_status": RELAY_MISSING,
            "broker_status": BROKER_MISSING,
            "auth_status": AUTH_UNCONFIGURED,
            "start_allowed": False,
            "error_code": "auth_unconfigured",
        }

    def create(self, expected_preview_hash: str | None = None) -> dict[str, Any]:
        """Create an immutable instance only from a fresh, matching preview.

        The optional argument preserves the local service API used by older
        callers; the HTTP API requires it explicitly.
        """
        started = time.monotonic()
        compatibility_call = expected_preview_hash is None
        first = self.preview()
        preview_hash = first.get("preview_hash")
        if first.get("status") != CONTRACT_READY or not isinstance(preview_hash, str):
            return self._save_failure(first.get("error_code") or "runtime_not_ready", started)
        if expected_preview_hash is None:
            expected_preview_hash = preview_hash
        if not isinstance(expected_preview_hash, str) or not _DIGEST.fullmatch(expected_preview_hash) or expected_preview_hash != preview_hash:
            return self._save_failure("preview_stale", started)
        second = self.preview()
        if second.get("status") != CONTRACT_READY or second.get("preview_hash") != expected_preview_hash:
            return self._save_failure("preview_hash_mismatch" if compatibility_call else "preview_stale", started)
        runtime, isolation, proof, problem = self._inputs()
        if problem or not isinstance(runtime, Mapping) or not isinstance(isolation, Mapping) or proof is None:
            return self._save_failure("preview_stale", started)
        private = build_private_contract(
            runtime_fingerprint=runtime["runtime_fingerprint"],
            isolation_cache_key=isolation["cache_key"],
            binary_sha256=runtime["binary_sha256"],
            runtime_identity_version=runtime["identity_version"],
            launch_spec_hash=runtime["launch_spec_hash"],
            isolation_config_hash=isolation["config_hash"],
            isolation_tool_fingerprint=isolation["tool_fingerprint"],
            **proof,
        )
        if private["contract_hash"] != expected_preview_hash:
            return self._save_failure("preview_stale", started)
        snapshot = provider_snapshot()
        checked_at = _now()
        result = {
            "contract_id": str(uuid.uuid4()),
            "preview_hash": expected_preview_hash,
            "current_binding_hash": private["current_binding_hash"],
            "created_at": checked_at,
            "status": AUTH_UNCONFIGURED,
            "checked_at": checked_at,
            "contract_hash": private["contract_hash"],
            "runtime_identity_version": runtime["identity_version"],
            "runtime_fingerprint": runtime["runtime_fingerprint"],
            "launch_spec_hash": runtime["launch_spec_hash"],
            "isolation_cache_key": isolation["cache_key"],
            "isolation_config_hash": isolation["config_hash"],
            "isolation_tool_fingerprint": isolation["tool_fingerprint"],
            "binary_sha256": runtime["binary_sha256"],
            **proof,
            "provider_config_hash": provider_config_hash(private["config_toml_bytes"]),
            "contract_policy_version": EGRESS_CONTRACT_POLICY_VERSION,
            "endpoint_type": snapshot["endpoint_type"],
            "provider_snapshot": snapshot,
            "relay_status": RELAY_MISSING,
            "broker_status": BROKER_MISSING,
            "auth_status": AUTH_UNCONFIGURED,
            "start_allowed": False,
            "error_code": "auth_unconfigured",
            "local_duration_ms": max(0, round((time.monotonic() - started) * 1000)),
        }
        saved = self.store.create_sealed_egress_contract_instance(result)
        reused = bool(saved.get("reused"))
        if not reused:
            self.store.record_sealed_egress_contract_ledger(saved)
        return {**saved, "created": not reused, "reused": reused}

    def current(self) -> dict[str, Any] | None:
        result = self.store.latest_sealed_egress_contract_instance()
        if result is None:
            return self.preview()
        problem = self._binding_problem(self.store.wsl_codex_runtime_result(), self.store.wsl_isolation_result(), result)
        if problem:
            return {
                **result,
                "status": BLOCKED,
                "start_allowed": False,
                "error_code": problem,
            }
        if self.proof_required:
            proof, proof_error = validate_sealed_execution_proof(self.store)
            if proof is None or any(result.get(field) != value for field, value in proof.items()):
                return {
                    **result,
                    "status": BLOCKED,
                    "start_allowed": False,
                    "error_code": proof_error or "repro_binding_changed",
                }
        return result

    def immutable_execution_contract(self) -> tuple[dict[str, Any] | None, str | None]:
        """Return only a stored immutable instance that still binds to runtime.

        A preview is intentionally never enough to cross the harness boundary.
        This is read-only validation; it neither upgrades authentication nor
        changes the contract state.
        """
        result = self.store.latest_sealed_egress_contract_instance()
        if not isinstance(result, Mapping):
            return None, "stored_contract_required"
        contract_hash = result.get("contract_hash")
        if not isinstance(contract_hash, str) or result.get("preview_hash") != contract_hash:
            return None, "stored_contract_required"
        stored = self.store.egress_contract_instance(contract_hash)
        if not isinstance(stored, Mapping) or stored.get("contract_id") != result.get("contract_id"):
            return None, "stored_contract_required"
        if stored.get("status") != AUTH_UNCONFIGURED:
            return None, "stored_contract_invalid"
        if self.proof_required:
            proof, proof_error = validate_sealed_execution_proof(self.store)
            if proof is None or any(stored.get(field) != value for field, value in proof.items()):
                return None, proof_error or "repro_binding_changed"
        return dict(stored), None

    @staticmethod
    def _binding_problem(runtime: Mapping[str, Any] | None, isolation: Mapping[str, Any] | None,
                         result: Mapping[str, Any] | None = None) -> str | None:
        if isinstance(runtime, Mapping) and runtime.get("error_code") == "runtime_identity_incomplete":
            return "runtime_identity_incomplete"
        if not isinstance(runtime, Mapping) or runtime.get("status") != "EGRESS_UNCONFIGURED":
            return "runtime_not_ready"
        if runtime.get("egress_blocked") is not True or runtime.get("start_allowed") is not False:
            return "runtime_not_sealed"
        if not isinstance(isolation, Mapping) or isolation.get("status") != "SAFE_CANDIDATE":
            return "isolation_not_safe"
        if runtime.get("identity_version") != RUNTIME_IDENTITY_VERSION or runtime.get("identity_complete") is not True:
            return "runtime_identity_missing"
        fields = ("runtime_fingerprint", "launch_spec_hash", "binary_sha256")
        if any(not isinstance(runtime.get(field), str) or not _DIGEST.fullmatch(runtime[field]) for field in fields):
            return "runtime_identity_missing"
        cache_key = isolation.get("cache_key")
        if any(not isinstance(isolation.get(field), str) or not _DIGEST.fullmatch(isolation[field]) for field in ("config_hash", "tool_fingerprint", "cache_key")):
            return "isolation_identity_missing"
        if runtime.get("isolation_cache_key") != cache_key:
            return "contract_binding_changed" if result is not None else "isolation_binding_changed"
        if result is not None:
            expected = {
                "runtime_identity_version": RUNTIME_IDENTITY_VERSION,
                "runtime_fingerprint": runtime["runtime_fingerprint"],
                "isolation_cache_key": cache_key,
                "binary_sha256": runtime["binary_sha256"],
                "launch_spec_hash": runtime["launch_spec_hash"],
                "isolation_config_hash": isolation["config_hash"],
                "isolation_tool_fingerprint": isolation["tool_fingerprint"],
            }
            if any(result.get(field) != value for field, value in expected.items()):
                return "contract_binding_changed"
        return None

    def _save_failure(self, error_code: str, started: float) -> dict[str, Any]:
        result = {
            "status": BLOCKED,
            "checked_at": _now(),
            "contract_hash": None,
            "runtime_fingerprint": None,
            "isolation_cache_key": None,
            "binary_sha256": None,
            "provider_config_hash": None,
            "contract_policy_version": EGRESS_CONTRACT_POLICY_VERSION,
            "endpoint_type": "UNCONFIGURED",
            "provider_snapshot": None,
            "relay_status": RELAY_MISSING,
            "broker_status": BROKER_MISSING,
            "auth_status": AUTH_UNCONFIGURED,
            "start_allowed": False,
            "error_code": error_code,
            "local_duration_ms": max(0, round((time.monotonic() - started) * 1000)),
        }
        saved = self.store.save_sealed_egress_contract(result)
        self.store.record_sealed_egress_contract_ledger(saved)
        return saved
