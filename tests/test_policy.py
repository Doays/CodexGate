import pytest

from app.policy import (
    Decision,
    PolicyError,
    model_choices,
    validate_allowed_file_scope,
    validate_selection,
    validate_workspace,
    validation_evidence,
)


MODELS = [{
    "id": "gpt-5.6-terra",
    "model": "gpt-5.6-terra",
    "displayName": "5.6 Terra",
    "hidden": False,
    "defaultReasoningEffort": "high",
    "supportedReasoningEfforts": [{"reasoningEffort": "medium"}, {"reasoningEffort": "high"}, {"reasoningEffort": "ultra"}],
}]


def test_keeps_server_effort_order():
    assert model_choices(MODELS)[0]["efforts"] == ["medium", "high", "ultra"]


def test_ultra_is_locked():
    with pytest.raises(PolicyError, match="Ultra"):
        validate_selection(MODELS, "gpt-5.6-terra", "ultra")


def test_workspace_write_rejects_high_risk_work(tmp_path):
    with pytest.raises(PolicyError, match="high-risk"):
        validate_workspace(str(tmp_path), "workspace-write", "nginx 설정을 변경해줘")


def test_decision_requires_structured_lists():
    with pytest.raises(PolicyError, match="allowed_files"):
        Decision.from_json({"decision": "execute", "task_class": "patch", "recommended_model": "m", "recommended_effort": "high", "allowed_files": "a.py"})


def test_decision_route_fields_and_validation_evidence_are_structured(tmp_path):
    (tmp_path / "tests").mkdir()
    value = Decision.from_json({
        "decision": "execute",
        "task_class": "T3",
        "recommended_model": "m",
        "recommended_effort": "high",
        "allowed_files": ["a.py", "./a.py"],
        "validation_commands": ["pytest -q"],
        "risk": "high",
        "parallel_audit": True,
        "independent_axes": 3,
    })
    files, reasons = validate_allowed_file_scope(tmp_path, value.allowed_files)
    evidence = validation_evidence(tmp_path, value.validation_commands)
    assert (value.risk, value.parallel_audit, value.independent_axes) == ("high", True, 3)
    assert files == ["a.py"] and reasons == []
    assert evidence["validation_commands_present"] is True
    assert evidence["local_test_target_exists"] is True
    assert evidence["has_tests"] is True
