"""Pure relay policy for the sealed local egress harness.

The Phase 2 implementation uses this in-memory model only.  It neither starts
bubblewrap nor binds a loopback listener; the launch spec is a reviewable
description for a later, separately authorized implementation.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .egress_broker import BrokerResult, FakeUnixBroker
from .egress_contract import LOOPBACK_HOST, LOOPBACK_PORT, sanitize_broker_headers
from .policy import PolicyError


RELAY_START_TIMEOUT_SECONDS = 10
RELAY_REQUEST_TIMEOUT_SECONDS = 15
HARNESS_TOTAL_TIMEOUT_SECONDS = 30
PROCESS_OUTPUT_LIMIT_BYTES = 8 * 1024


def build_relay_launch_spec(contract: Mapping[str, Any]) -> dict[str, Any]:
    """Describe the later bwrap relay without disclosing a host socket path."""
    if not isinstance(contract, Mapping) or not isinstance(contract.get("contract_hash"), str):
        raise PolicyError("sealed egress contract is invalid")
    environment = {"PATH": "/usr/bin:/bin", "HOME": "/home/relay", "TMPDIR": "/tmp", "LANG": "C.UTF-8"}
    return {
        "backend": "WSL2_BWRAP",
        "listen": {"host": LOOPBACK_HOST, "port": LOOPBACK_PORT},
        "network": "sandbox_loopback_only",
        "socket_directory_bind": {"source": "SOCKET_DIR_ONLY", "target": "/runtime/broker", "mode": "rw"},
        "broker_socket": "CONTRACT_SOCKET_ONLY",
        "timeouts": {
            "start_seconds": RELAY_START_TIMEOUT_SECONDS,
            "request_seconds": RELAY_REQUEST_TIMEOUT_SECONDS,
            "total_seconds": HARNESS_TOTAL_TIMEOUT_SECONDS,
        },
        "output_limit_bytes": PROCESS_OUTPUT_LIMIT_BYTES,
        "clearenv": True,
        "environment": environment,
        "argv": [
            "/usr/bin/bwrap", "--unshare-all", "--new-session", "--die-with-parent", "--clearenv",
            "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--tmpfs", "/home",
            "--dir", "/home/relay", "--dir", "/runtime", "--dir", "/runtime/broker",
            "--bind", "SOCKET_DIR_ONLY", "/runtime/broker", "--setenv", "PATH", environment["PATH"],
            "--setenv", "HOME", environment["HOME"], "--setenv", "TMPDIR", environment["TMPDIR"],
            "--setenv", "LANG", environment["LANG"], "/usr/bin/python3", "-I", "-S", "-u",
            "-m", "app.egress_relay",
        ],
    }


def validate_relay_loopback_boundary(spec: Mapping[str, Any]) -> None:
    """Reject a relay description that expands the sealed local boundary."""
    if not isinstance(spec, Mapping):
        raise PolicyError("sealed relay launch spec is invalid")
    if spec.get("listen") != {"host": LOOPBACK_HOST, "port": LOOPBACK_PORT}:
        raise PolicyError("sealed relay loopback boundary is invalid")
    if spec.get("broker_socket") != "CONTRACT_SOCKET_ONLY":
        raise PolicyError("sealed relay socket boundary is invalid")
    if spec.get("network") not in {"sandbox_loopback_only", "unshare_all_loopback_only"}:
        raise PolicyError("sealed relay network boundary is invalid")


@dataclass
class RelayResult:
    status_code: int
    response_bytes: int
    response_hash: str
    request_bytes: int
    sensitive_headers_removed: bool


class FakeLoopbackRelay:
    """In-memory relay that permits exactly one client and one HTTP request."""

    def __init__(self, broker: FakeUnixBroker):
        self.broker = broker
        self.connections = 0
        self.requests = 0

    def accept_connection(self) -> None:
        if self.connections:
            raise PolicyError("sealed relay rejects a second connection")
        self.connections += 1
        self.broker.accept_connection()

    def forward(self, method: str, path: str, headers: Mapping[str, str], body: bytes) -> RelayResult:
        if self.connections != 1:
            raise PolicyError("sealed relay requires its single connection")
        if self.requests:
            raise PolicyError("sealed relay rejects a second request")
        # Credentials and proxy controls never cross the relay→broker boundary.
        clean_headers = sanitize_broker_headers(headers)
        result: BrokerResult = self.broker.handle_request(method, path, clean_headers, body)
        self.requests += 1
        sensitive_removed = all(name.casefold() not in {"authorization", "cookie", "proxy-authorization"}
                                and not name.casefold().startswith("proxy-")
                                for name in clean_headers)
        return RelayResult(
            status_code=result.status_code,
            response_bytes=result.response_bytes,
            response_hash=result.response_hash,
            request_bytes=len(body),
            sensitive_headers_removed=sensitive_removed,
        )
