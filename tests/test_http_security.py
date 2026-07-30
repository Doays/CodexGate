from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import app.indexer as app_indexer
import app.main as app_main


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(app_main, "DATA_ROOT", tmp_path / "data")
    with TestClient(app_main.app, base_url="http://127.0.0.1:8787") as test_client:
        yield test_client


def test_local_host_and_origin_are_allowed(client):
    response = client.get("/api/status", headers={"origin": "http://127.0.0.1:8787"})
    assert response.status_code == 200


def test_foreign_host_is_rejected(client):
    response = client.get("/api/status", headers={"host": "evil.example:8787"})
    assert response.status_code == 403


def test_testserver_stays_forbidden_and_local_actual_route_is_fail_closed(tmp_path, monkeypatch):
    monkeypatch.setattr(app_main, "DATA_ROOT", tmp_path / "host-policy")
    with TestClient(app_main.app) as default_client:
        assert default_client.get("/api/status").status_code == 403
    with TestClient(app_main.app, base_url="http://127.0.0.1:8787") as local_client:
        response = local_client.post(
            "/api/isolation/wsl/egress-harness/actual",
            json={},
        )
        assert response.status_code == 409
        permitless = local_client.post("/api/isolation/wsl/codex-process-canary/arm", json={})
        assert permitless.status_code == 403
        permitless = local_client.post(
            "/api/isolation/wsl/codex-process-canary/arm",
            headers={"Origin": "http://127.0.0.1:8787"}, json={},
        )
        assert permitless.status_code == 409
    with TestClient(app_main.app) as default_client:
        assert default_client.post("/api/isolation/wsl/codex-process-canary/permit", json={}).status_code == 403


def test_foreign_origin_is_rejected(client):
    response = client.get("/api/status", headers={"origin": "http://evil.example:8787"})
    assert response.status_code == 403


def test_malicious_project_id_is_rejected_before_run_starts(client):
    payload = {
        "project_name": "Demo",
        "project_id": "../escape",
        "root": str(Path.cwd()),
        "task": "small patch",
        "decision": {
            "decision": "execute",
            "task_class": "patch",
            "recommended_model": "model",
            "recommended_effort": "high",
            "allowed_files": ["decision.json"],
            "forbidden_files": [],
            "validation_commands": [],
            "stop_conditions": [],
        },
        "model": "model",
        "effort": "high",
        "permission": "read-only",
        "budget_level": "tiny",
    }
    response = client.post("/api/run", json=payload)
    assert response.status_code == 422


def test_forbidden_root_blocks_preflight_without_scanning(client, monkeypatch):
    def fail_if_called(_root):
        raise AssertionError("collect_metadata should not run for forbidden roots")

    monkeypatch.setattr(app_indexer, "collect_metadata", fail_if_called)
    response = client.post(
        "/api/preflight",
        json={"project_name": "Demo", "root": r"E:\.codex", "task": "Inspect the workspace"},
    )
    assert response.status_code == 400
    assert "blocked" in response.json()["detail"]


@pytest.mark.parametrize("root", [r"E:\\", r"E:\.codex"])
def test_bridge_creation_rejects_forbidden_windows_roots_immediately(client, root):
    response = client.post(
        "/api/bridge/tasks",
        json={
            "project_name": "Demo",
            "project_id": "demo",
            "root": root,
            "task": "Inspect a bounded local scope",
            "permission": "read-only",
            "chat_url": "https://chatgpt.com/",
        },
    )
    assert response.status_code == 400
    assert "blocked" in response.json()["detail"]


@pytest.mark.parametrize("root", [r"E:\\", r"E:\.codex", r"E:\.codex\assets"])
def test_catalog_registration_rejects_forbidden_windows_roots(client, root):
    response = client.post("/api/catalog/sources", json={"alias": "blocked", "root": root})
    assert response.status_code == 400
    assert "blocked" in response.json()["detail"]
