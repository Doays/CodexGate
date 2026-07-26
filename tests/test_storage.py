from __future__ import annotations

import uuid

import pytest

from app.policy import PolicyError
from app.storage import Store


def test_task_and_artifacts_are_persisted(tmp_path):
    store = Store(tmp_path)
    task_id = str(uuid.uuid4())
    store.save_task(task_id, "demo-project", "starting", {"name": "test"})
    artifact = store.write_artifact("demo-project", task_id, "decision.json", {"decision": "execute"})
    assert artifact.exists()
    assert '"decision": "execute"' in artifact.read_text(encoding="utf-8")


@pytest.mark.parametrize("project_id", ["../escape", "/abs/path", "C:/escape"])
def test_storage_rejects_bad_project_ids_before_creating_paths(tmp_path, project_id):
    store = Store(tmp_path)
    with pytest.raises(PolicyError):
        store.write_artifact(project_id, str(uuid.uuid4()), "decision.json", {})
    assert not (tmp_path / "projects").exists()


def test_storage_rejects_bad_task_ids_and_artifact_names(tmp_path):
    store = Store(tmp_path)
    with pytest.raises(PolicyError):
        store.save_task("../task", "demo-project", "starting", {})
    with pytest.raises(PolicyError):
        store.write_artifact("demo-project", "../task", "decision.json", {})
    with pytest.raises(PolicyError):
        store.write_artifact("demo-project", str(uuid.uuid4()), "../decision.json", {})
    assert not (tmp_path / "projects").exists()
