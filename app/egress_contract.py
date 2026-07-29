"""Immutable, local-only contract for a future sealed Codex egress path.

Phase 1 describes the only acceptable custom-provider, relay, and broker
boundary.  It deliberately opens no socket, launches no Codex process, and
does not materialize an authentication value.
"""
from __future__ import annotations

import hashlib
import re
import time
from datetime import datetime, timezone
from typing import Any, Mapping
from urllib.parse import urlsplit

from .policy import PolicyError, canonical_json, sha256_json, validate_sealed_loopback_base_url


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
SEALED_BASE_URL = f"http://{LOOPBACK_HOST}:{LOOPBACK_PORT}/v1"
EPHEMERAL_TOKEN_ENV = "CODEXGATE_EPHEMERAL_TOKEN"
BROKER_SOCKET_PATH = "/runtime-state/codexgate-broker.sock"
BROKER_REQUEST_PATH = "/v1/responses"
MAX_REQUEST_BYTES = 256 * 1024
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
BROKER_TIMEOUT_SECONDS = 120

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
        "required_host": f"{LOOPBACK_HOST}:{LOOPBACK_PORT}",
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
    if len(host_values) != 1 or host_values[0].casefold() != f"{LOOPBACK_HOST}:{LOOPBACK_PORT}":
        raise PolicyError("sealed broker host is invalid")
    return clean


def validate_broker_response(status_code: int, body_bytes: int) -> None:
    if not isinstance(status_code, int) or isinstance(status_code, bool) or not 100 <= status_code <= 599:
        raise PolicyError("broker response status is invalid")
    if 300 <= status_code < 400:
        raise PolicyError("broker redirects are forbidden")
    if not isinstance(body_bytes, int) or isinstance(body_bytes, bool) or not 0 <= body_bytes <= MAX_RESPONSE_BYTES:
        raise PolicyError("sealed broker response body exceeds its limit")


def build_private_contract(*, runtime_fingerprint: str, isolation_cache_key: str, binary_sha256: str,
                           base_url: str = SEALED_BASE_URL) -> dict[str, Any]:
    """Construct a deterministic private contract from sealed runtime inputs."""
    for name, value in {
        "runtime fingerprint": runtime_fingerprint,
        "isolation cache key": isolation_cache_key,
        "binary SHA-256": binary_sha256,
    }.items():
        if not isinstance(value, str) or not _DIGEST.fullmatch(value):
            raise PolicyError(f"{name} is invalid")
    config_bytes = canonical_provider_toml(base_url)
    config_hash = provider_config_hash(config_bytes)
    relay = relay_contract(base_url)
    broker = broker_contract()
    identity = {
        "policy_version": EGRESS_CONTRACT_POLICY_VERSION,
        "runtime_fingerprint": runtime_fingerprint,
        "isolation_cache_key": isolation_cache_key,
        "binary_sha256": binary_sha256,
        "provider_config_hash": config_hash,
        "provider": provider_snapshot(base_url),
        "relay": relay,
        "broker": broker,
    }
    return {
        "identity": identity,
        "contract_hash": sha256_json(identity),
        "config_toml_bytes": config_bytes,
    }


def public_contract_result(result: Mapping[str, Any] | None) -> dict[str, Any]:
    if not isinstance(result, Mapping):
        return {"status": UNCONFIGURED, "start_allowed": False, "endpoint_type": "UNCONFIGURED"}
    fields = (
        "status", "checked_at", "contract_hash", "endpoint_type", "relay_status",
        "broker_status", "auth_status", "start_allowed", "error_code",
    )
    return {field: result.get(field) for field in fields if field in result}


class SealedEgressContractService:
    """Creates and revalidates the no-I/O egress contract."""

    def __init__(self, store):
        self.store = store

    def create(self) -> dict[str, Any]:
        started = time.monotonic()
        runtime = self.store.wsl_codex_runtime_result()
        isolation = self.store.wsl_isolation_result()
        problem = self._binding_problem(runtime, isolation)
        if problem:
            return self._save_failure(problem, started)
        assert runtime is not None and isolation is not None
        private = build_private_contract(
            runtime_fingerprint=runtime["runtime_fingerprint"],
            isolation_cache_key=isolation["cache_key"],
            binary_sha256=runtime["binary_sha256"],
        )
        snapshot = provider_snapshot()
        result = {
            "status": AUTH_UNCONFIGURED,
            "checked_at": _now(),
            "contract_hash": private["contract_hash"],
            "runtime_fingerprint": runtime["runtime_fingerprint"],
            "isolation_cache_key": isolation["cache_key"],
            "binary_sha256": runtime["binary_sha256"],
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
        saved = self.store.save_sealed_egress_contract(result)
        self.store.record_sealed_egress_contract_ledger(saved)
        return saved

    def current(self) -> dict[str, Any] | None:
        result = self.store.sealed_egress_contract()
        if result is None:
            return None
        problem = self._binding_problem(self.store.wsl_codex_runtime_result(), self.store.wsl_isolation_result(), result)
        if problem:
            return {
                **result,
                "status": BLOCKED,
                "start_allowed": False,
                "error_code": problem,
            }
        return result

    @staticmethod
    def _binding_problem(runtime: Mapping[str, Any] | None, isolation: Mapping[str, Any] | None,
                         result: Mapping[str, Any] | None = None) -> str | None:
        if not isinstance(runtime, Mapping) or runtime.get("status") != "EGRESS_UNCONFIGURED":
            return "runtime_not_ready"
        if runtime.get("egress_blocked") is not True or runtime.get("start_allowed") is not False:
            return "runtime_not_sealed"
        if not isinstance(isolation, Mapping) or isolation.get("status") != "SAFE_CANDIDATE":
            return "isolation_not_safe"
        fields = ("runtime_fingerprint", "binary_sha256")
        if any(not isinstance(runtime.get(field), str) or not _DIGEST.fullmatch(runtime[field]) for field in fields):
            return "runtime_identity_missing"
        cache_key = isolation.get("cache_key")
        if not isinstance(cache_key, str) or not _DIGEST.fullmatch(cache_key):
            return "isolation_identity_missing"
        if result is not None:
            expected = {
                "runtime_fingerprint": runtime["runtime_fingerprint"],
                "isolation_cache_key": cache_key,
                "binary_sha256": runtime["binary_sha256"],
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
