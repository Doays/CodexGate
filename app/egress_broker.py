"""Pure broker policy and deterministic fake Responses API for harness tests.

This module deliberately creates no sockets.  A future broker implementation
must satisfy these rules before it is permitted to open the single AF_UNIX
listener described by the sealed contract.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Mapping

from .egress_contract import (
    BROKER_REQUEST_PATH,
    LOOPBACK_HOST,
    LOOPBACK_PORT,
    MAX_RESPONSE_BYTES,
    validate_broker_request,
    validate_broker_response,
)
from .policy import PolicyError, canonical_json


BROKER_SOCKET_FAMILY = "AF_UNIX"


def build_broker_launch_spec(contract: Mapping[str, Any]) -> dict[str, Any]:
    """Return a private, fixed-argv broker description without opening it."""
    if not isinstance(contract, Mapping) or not isinstance(contract.get("contract_hash"), str):
        raise PolicyError("sealed egress contract is invalid")
    return {
        "transport": BROKER_SOCKET_FAMILY,
        "listener_count": 1,
        "socket": "CONTRACT_SOCKET_ONLY",
        "network_socket_counts": {"tcp": 0, "udp": 0, "dns": 0},
        "clearenv": True,
        "environment": {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
        "argv": ["/usr/bin/python3", "-I", "-S", "-u", "-m", "app.egress_broker"],
    }


def deterministic_fake_response() -> bytes:
    """A closed Responses-shaped result; no request data influences its body."""
    payload = {
        "id": "resp_codexgate_fake_v1",
        "object": "response",
        "output": [{
            "id": "msg_codexgate_fake_v1",
            "type": "message",
            "role": "assistant",
            "content": [{"type": "output_text", "text": "codexgate sealed harness"}],
        }],
        "status": "completed",
    }
    return canonical_json(payload).encode("utf-8")


def deterministic_response_metadata() -> dict[str, Any]:
    body = deterministic_fake_response()
    validate_broker_response(200, len(body))
    return {
        "status_code": 200,
        "response_bytes": len(body),
        "response_hash": hashlib.sha256(body).hexdigest(),
    }


@dataclass
class BrokerResult:
    status_code: int
    response_bytes: int
    response_hash: str
    sanitized_headers: Mapping[str, str]


class FakeUnixBroker:
    """In-memory model of the one-listener/one-request broker boundary."""

    def __init__(self, contract: Mapping[str, Any], *, socket_counts: Mapping[str, int] | None = None):
        self.contract = contract
        self.socket_counts = dict(socket_counts or {"af_unix": 1, "tcp": 0, "udp": 0, "dns": 0})
        self.connections = 0
        self.requests = 0

    def accept_connection(self) -> None:
        if self.connections:
            raise PolicyError("sealed broker rejects a second connection")
        self.connections += 1
        if self.socket_counts.get("af_unix") != 1 or any(self.socket_counts.get(kind, 0) != 0 for kind in ("tcp", "udp", "dns")):
            raise PolicyError("sealed broker socket policy was violated")

    def handle_request(self, method: str, path: str, headers: Mapping[str, str], body: bytes) -> BrokerResult:
        if self.connections != 1:
            raise PolicyError("sealed broker requires its single connection")
        if self.requests:
            raise PolicyError("sealed broker rejects a second request")
        if not isinstance(body, bytes):
            raise PolicyError("sealed broker request body is invalid")
        clean = validate_broker_request(method, path, headers, len(body))
        self.requests += 1
        response = deterministic_response_metadata()
        if response["response_bytes"] > MAX_RESPONSE_BYTES:
            raise PolicyError("sealed broker response body exceeds its limit")
        return BrokerResult(sanitized_headers=clean, **response)


def fixed_client_request() -> tuple[str, str, dict[str, str], bytes]:
    """Return the sole immutable synthetic request used by the fake harness."""
    return (
        "POST",
        BROKER_REQUEST_PATH,
        {
            "Host": f"{LOOPBACK_HOST}:{LOOPBACK_PORT}",
            "Content-Type": "application/json",
            "Authorization": "removed-before-broker",
            "Cookie": "removed-before-broker",
            "Proxy-Authorization": "removed-before-broker",
        },
        b'{"model":"sealed-harness"}',
    )
