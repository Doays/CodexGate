from __future__ import annotations

import asyncio
import json
import tomllib
from datetime import datetime, timedelta, timezone

import pytest

import app.egress_contract as egress_contract

from app.egress_contract import (
    AUTH_UNCONFIGURED,
    BLOCKED,
    BROKER_SOCKET_PATH,
    BROKER_TIMEOUT_SECONDS,
    CUSTOM_PROVIDER_ID,
    EGRESS_CONTRACT_POLICY_VERSION,
    EPHEMERAL_TOKEN_ENV,
    LOOPBACK_PORT,
    MAX_REQUEST_BYTES,
    MAX_RESPONSE_BYTES,
    SealedEgressContractService,
    build_private_contract,
    canonical_provider_toml,
    provider_config_hash,
    public_contract_result,
    relay_contract,
    sanitize_broker_headers,
    validate_broker_request,
    validate_broker_response,
)
from app.isolation_wsl import ProcessResult, SAFE_CANDIDATE
from app.policy import PolicyError, validate_sealed_loopback_base_url
from app.storage import Store
from app.wsl_codex_runtime import EGRESS_UNCONFIGURED, EXPECTED_CODEX_VERSION, WSLCodexRuntime


class FakeRuntimeRunner:
    def __init__(self, sha256: str = "a" * 64):
        self.sha256 = sha256
        self.calls: list[list[str]] = []

    def find_wsl(self) -> str:
        return "wsl.exe"

    async def run(self, args: list[str], *, timeout_seconds: float) -> ProcessResult:
        self.calls.append(args)
        return ProcessResult(
            exit_code=0,
            stdout=json.dumps({
                "status": "OK", "sha256": self.sha256, "version": EXPECTED_CODEX_VERSION,
                "size": 42, "mtime_ns": 7, "error": None,
            }, sort_keys=True, separators=(",", ":")) + "\n",
            stderr="",
        )


def _safe_isolation(store: Store, cache_key: str = "c" * 64) -> None:
    now = datetime.now(timezone.utc)
    store.save_wsl_isolation_config("Ubuntu")
    store.save_wsl_isolation_result({
        "backend": "WSL2_BWRAP", "distro": "Ubuntu", "status": SAFE_CANDIDATE,
        "checked_at": now.isoformat(), "expires_at": (now + timedelta(minutes=30)).isoformat(),
        "config_hash": "f" * 64, "tool_fingerprint": "b" * 64, "cache_key": cache_key,
        "probe_version": "wsl2-bwrap-v1", "tool_versions": {"wsl2": True, "bwrap_present": True},
    })


def _ready(tmp_path, *, sha256: str = "a" * 64, cache_key: str = "c" * 64):
    store = Store(tmp_path / "data")
    _safe_isolation(store, cache_key)
    store.save_wsl_codex_runtime_config("/usr/local/bin/codex")
    runner = FakeRuntimeRunner(sha256)
    runtime = WSLCodexRuntime(store, runner)
    result = asyncio.run(runtime.preflight())
    assert result["status"] == EGRESS_UNCONFIGURED
    return store, runtime, runner


def test_canonical_provider_toml_is_closed_and_uses_only_the_custom_responses_provider():
    raw = canonical_provider_toml()
    parsed = tomllib.loads(raw.decode("utf-8"))
    assert raw.endswith(b"\n")
    assert set(parsed) == {"model_provider", "model_providers"}
    assert parsed["model_provider"] == CUSTOM_PROVIDER_ID
    providers = parsed["model_providers"]
    assert set(providers) == {CUSTOM_PROVIDER_ID}
    provider = providers[CUSTOM_PROVIDER_ID]
    assert set(provider) == {
        "name", "base_url", "wire_api", "requires_openai_auth", "env_key",
        "supports_websockets", "request_max_retries", "stream_max_retries",
    }
    assert provider["wire_api"] == "responses"
    assert provider["requires_openai_auth"] is False
    assert provider["env_key"] == EPHEMERAL_TOKEN_ENV
    assert provider["supports_websockets"] is False
    assert provider["request_max_retries"] == provider["stream_max_retries"] == 0
    assert "openai_base_url" not in raw.decode("utf-8")
    assert 'model_provider = "openai"' not in raw.decode("utf-8")


@pytest.mark.parametrize("value", [
    "https://127.0.0.1:8788/v1", "http://localhost:8788/v1", "http://127.0.0.1:8789/v1",
    "http://127.0.0.1:8788/v1/", "http://127.0.0.1:8788/v1?x=1", "http://127.0.0.1/v1",
])
def test_only_the_fixed_loopback_base_url_is_accepted(value):
    with pytest.raises(PolicyError):
        validate_sealed_loopback_base_url(value)


def test_relay_allows_exactly_one_fixed_unix_socket_and_no_network():
    relay = relay_contract()
    assert relay["listen"] == {"scheme": "http", "host": "127.0.0.1", "port": LOOPBACK_PORT, "path_prefix": "/v1"}
    assert relay["external_outputs"] == [{"transport": "unix_socket", "path": BROKER_SOCKET_PATH}]
    assert relay["dns_allowed"] is relay["internet_allowed"] is relay["other_unix_sockets_allowed"] is False
    with pytest.raises(PolicyError):
        relay_contract(unix_socket="/runtime-state/other.sock")


def test_broker_contract_rejects_all_other_targets_and_strips_caller_credentials():
    headers = validate_broker_request(
        "POST", "/v1/responses",
        {"Host": "127.0.0.1:8788", "Authorization": "should-not-forward", "Cookie": "no", "Proxy-Test": "no", "Content-Type": "application/json"},
        MAX_REQUEST_BYTES,
    )
    assert headers == {"Host": "127.0.0.1:8788", "Content-Type": "application/json"}
    assert sanitize_broker_headers({"Authorization": "x", "Proxy-Thing": "y", "Accept": "application/json"}) == {"Accept": "application/json"}
    for method, path, host, size in (
        ("CONNECT", "/v1/responses", "127.0.0.1:8788", 0),
        ("GET", "/v1/responses", "127.0.0.1:8788", 0),
        ("POST", "/v1/chat/completions", "127.0.0.1:8788", 0),
        ("POST", "http://example.invalid/v1/responses", "127.0.0.1:8788", 0),
        ("POST", "/v1/responses", "example.invalid", 0),
        ("POST", "/v1/responses", "127.0.0.1:8788", MAX_REQUEST_BYTES + 1),
    ):
        with pytest.raises(PolicyError):
            validate_broker_request(method, path, {"Host": host}, size)
    validate_broker_response(200, MAX_RESPONSE_BYTES)
    for status, size in ((302, 0), (200, MAX_RESPONSE_BYTES + 1)):
        with pytest.raises(PolicyError):
            validate_broker_response(status, size)
    assert BROKER_TIMEOUT_SECONDS == 120


def test_contract_hash_binds_runtime_isolation_binary_provider_and_policy_identity():
    first = build_private_contract(runtime_fingerprint="a" * 64, isolation_cache_key="b" * 64, binary_sha256="c" * 64)
    assert first["contract_hash"] == build_private_contract(
        runtime_fingerprint="a" * 64, isolation_cache_key="b" * 64, binary_sha256="c" * 64
    )["contract_hash"]
    assert first["contract_hash"] != build_private_contract(
        runtime_fingerprint="d" * 64, isolation_cache_key="b" * 64, binary_sha256="c" * 64
    )["contract_hash"]
    assert first["contract_hash"] != build_private_contract(
        runtime_fingerprint="a" * 64, isolation_cache_key="e" * 64, binary_sha256="c" * 64
    )["contract_hash"]
    assert first["contract_hash"] != build_private_contract(
        runtime_fingerprint="a" * 64, isolation_cache_key="b" * 64, binary_sha256="f" * 64
    )["contract_hash"]
    assert first["identity"]["policy_version"] == EGRESS_CONTRACT_POLICY_VERSION
    assert first["identity"]["provider_config_hash"] == provider_config_hash(first["config_toml_bytes"])


def test_contract_is_auth_unconfigured_start_blocked_and_ledger_is_local_only(tmp_path):
    store, runtime, runner = _ready(tmp_path)
    service = SealedEgressContractService(store)
    result = service.create()
    assert result["status"] == AUTH_UNCONFIGURED
    assert result["relay_status"] == "RELAY_MISSING"
    assert result["broker_status"] == "BROKER_MISSING"
    assert result["auth_status"] == AUTH_UNCONFIGURED
    assert result["start_allowed"] is False
    assert len(runner.calls) == 1
    with pytest.raises(PolicyError, match="egress"):
        runtime.start()
    ledger = store.token_ledger_report()["sealed_egress_contract"]
    assert ledger["executions"] == 1
    assert ledger["tokens"] == ledger["app_server_rpc_calls"] == 0


def test_runtime_isolation_or_binary_change_invalidates_an_existing_contract(tmp_path):
    store, runtime, runner = _ready(tmp_path)
    service = SealedEgressContractService(store)
    first = service.create()
    assert service.current()["status"] == AUTH_UNCONFIGURED
    runner.sha256 = "d" * 64
    asyncio.run(runtime.preflight())
    assert service.current()["status"] == BLOCKED
    assert service.current()["error_code"] == "contract_binding_changed"
    _safe_isolation(store, "e" * 64)
    assert service.current()["status"] == BLOCKED
    assert first["contract_hash"] != build_private_contract(
        runtime_fingerprint=store.wsl_codex_runtime_result()["runtime_fingerprint"],
        isolation_cache_key="e" * 64,
        binary_sha256=store.wsl_codex_runtime_result()["binary_sha256"],
    )["contract_hash"]


def test_saved_and_public_contracts_never_include_toml_token_credentials_or_user_paths(tmp_path):
    store, _, _ = _ready(tmp_path)
    saved = SealedEgressContractService(store).create()
    public = public_contract_result(saved)
    serialized = json.dumps({"saved": saved, "public": public, "ledger": store.token_ledger_report()})
    assert "config_toml" not in serialized
    assert "Authorization" not in serialized
    assert "Cookie" not in serialized
    assert "/home/" not in serialized and "C:\\Users" not in serialized
    assert "CODEXGATE_EPHEMERAL_TOKEN" in serialized
    assert "not-a-real-token" not in serialized
    assert set(public) == {
        "contract_id", "preview_hash", "status", "checked_at", "contract_hash", "endpoint_type", "relay_status",
        "broker_status", "auth_status", "start_allowed", "error_code",
    }


def test_contract_cannot_be_created_without_a_current_sealed_runtime(tmp_path):
    store = Store(tmp_path / "data")
    result = SealedEgressContractService(store).create()
    assert result["status"] == BLOCKED
    assert result["error_code"] == "runtime_not_ready"
    assert result["start_allowed"] is False


def test_preview_and_generated_instance_hash_mismatch_holds_before_immutable_save(tmp_path, monkeypatch):
    store, _, _ = _ready(tmp_path)
    original = egress_contract.build_private_contract
    calls = 0

    def mismatching_instance(**kwargs):
        nonlocal calls
        calls += 1
        result = original(**kwargs)
        if calls == 2:
            result = {**result, "contract_hash": "d" * 64}
        return result

    monkeypatch.setattr(egress_contract, "build_private_contract", mismatching_instance)
    result = SealedEgressContractService(store).create()
    assert result["status"] == BLOCKED
    assert result["error_code"] == "preview_hash_mismatch"
    assert store.egress_contract_instance("d" * 64) is None
