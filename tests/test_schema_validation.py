from pathlib import Path

import pytest

from app.protocol import ProtocolSchema, ProtocolValidationError


def test_generated_schema_validates_thread_and_turn_start_payloads():
    protocol = ProtocolSchema.load(Path("schemas"))
    protocol.validate("thread_start", {"cwd": "C:/work", "sandbox": "read-only", "approvalPolicy": "on-request", "approvalsReviewer": "user"})
    protocol.validate("turn_start", {
        "threadId": "thread", "input": [{"type": "text", "text": "hello"}], "cwd": "C:/work",
        "approvalPolicy": "on-request", "approvalsReviewer": "user", "sandboxPolicy": {"type": "readOnly", "networkAccess": False},
    })


def test_generated_schema_rejects_invalid_thread_and_turn_start_payloads():
    protocol = ProtocolSchema.load(Path("schemas"))
    with pytest.raises(ProtocolValidationError):
        protocol.validate("thread_start", {"sandbox": "not-a-sandbox", "approvalPolicy": "on-request", "approvalsReviewer": "user"})
    with pytest.raises(ProtocolValidationError):
        protocol.validate("turn_start", {"threadId": "thread", "input": [], "approvalPolicy": "never-a-policy"})
