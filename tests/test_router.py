from __future__ import annotations

from fastapi.testclient import TestClient

import app.main as app_main
from app.router import route_preview


def model(model_id: str, efforts: list[str] | None = None):
    values = efforts or ["low", "medium", "high", "xhigh", "max"]
    return {
        "id": model_id,
        "model": model_id,
        "displayName": model_id,
        "hidden": False,
        "supportedReasoningEfforts": [{"reasoningEffort": value} for value in values],
    }


MODELS = [
    model("gpt-spark"),
    model("gpt-mini"),
    model("gpt-luna"),
    model("gpt-5.4"),
    model("gpt-terra", ["low", "medium", "high", "xhigh", "max", "ultra"]),
    model("gpt-5.5"),
    model("gpt-sol", ["low", "medium", "high", "xhigh", "max", "ultra"]),
]


def usage(state: str, percent: int | None = None):
    return {
        "account_state_evidence": {
            "status": state,
            "maximum_used_percent": percent,
            "maximum_window": {"source": "rateLimits", "window": "primary", "used_percent": percent} if percent is not None else None,
            "windows": [],
            "blocking_reason": None,
        }
    }


def preview(**overrides):
    payload = {
        "task_class": "T3",
        "risk": "low",
        "read_only": True,
        "file_count": 2,
        "has_tests": True,
        "web_recommendation": {"model": "gpt-terra", "effort": "high"},
        "account_state": "NORMAL",
        "account_usage": usage("NORMAL", 12),
    }
    payload.update(overrides)
    return route_preview(MODELS, **payload)


def test_safe_one_and_two_step_downgrades_follow_the_policy_ladder():
    one_step = preview()
    assert one_step["status"] == "PREVIEW"
    assert one_step["final"]["model"] == "gpt-5.4"
    assert one_step["final"]["effort"] == "high"

    two_step = preview(
        task_class="T4",
        web_recommendation={"model": "gpt-sol", "effort": "max"},
    )
    assert two_step["status"] == "PREVIEW"
    assert two_step["final"]["model"] == "gpt-terra"
    assert two_step["final"]["effort"] == "xhigh"


def test_t5_sol_max_is_never_reduced_to_sol_medium():
    result = preview(
        task_class="T5",
        risk="medium",
        web_recommendation={"model": "gpt-sol", "effort": "max"},
    )
    assert result["status"] == "PREVIEW"
    assert result["final"]["model"] == "gpt-sol"
    assert result["final"]["effort"] == "max"


def test_t4_medium_recommendation_holds_instead_of_lowering_effort():
    result = preview(
        task_class="T4",
        risk="medium",
        web_recommendation={"model": "gpt-terra", "effort": "medium"},
    )
    assert result["status"] == "HOLD"
    assert result["final"] is None
    assert "below the local minimum" in result["hold_reasons"][0]


def test_medium_t4_sol_max_and_medium_t3_terra_xhigh_preserve_recommendation_stage():
    t4 = preview(
        task_class="T4",
        risk="medium",
        web_recommendation={"model": "gpt-sol", "effort": "max"},
    )
    t3 = preview(
        task_class="T3",
        risk="high",
        web_recommendation={"model": "gpt-terra", "effort": "xhigh"},
    )
    assert (t4["final"]["model"], t4["final"]["effort"]) == ("gpt-sol", "max")
    assert (t3["final"]["model"], t3["final"]["effort"]) == ("gpt-terra", "xhigh")


def test_low_read_only_can_map_terra_max_to_5_4_xhigh_at_four_files():
    result = preview(
        file_count=4,
        web_recommendation={"model": "gpt-terra", "effort": "max"},
    )
    assert (result["final"]["model"], result["final"]["effort"]) == ("gpt-5.4", "xhigh")
    assert any("Model downgrade" in reason for reason in result["downgrade_reasons"])
    assert any("Effort downgrade" in reason for reason in result["downgrade_reasons"])


def test_effort_aliases_map_to_the_target_models_server_literal():
    for alias in ("very-high", "very high", "매우 높음"):
        result = preview(
            risk="medium",
            web_recommendation={"model": "gpt-terra", "effort": alias},
        )
        assert result["status"] == "PREVIEW"
        assert result["final"]["effort"] == "xhigh"
        assert any("Effort literal mapping" in reason for reason in result["downgrade_reasons"])


def test_same_stage_without_a_server_literal_holds():
    terra_without_xhigh = [entry if entry["id"] != "gpt-terra" else model("gpt-terra", ["low", "medium", "high", "max"]) for entry in MODELS]
    result = route_preview(
        terra_without_xhigh,
        task_class="T3", risk="medium", read_only=True, file_count=2, has_tests=True,
        web_recommendation={"model": "gpt-terra", "effort": "very-high"}, account_state="NORMAL",
    )
    assert result["status"] == "HOLD"
    assert "server-advertised literal" in result["hold_reasons"][0]


def test_t5_5_5_uses_its_highest_advertised_non_ultra_effort():
    five5_xhigh = [entry if entry["id"] != "gpt-5.5" else model("gpt-5.5", ["low", "medium", "high", "xhigh"]) for entry in MODELS]
    result = route_preview(
        five5_xhigh,
        task_class="T5", risk="high", read_only=True, file_count=1, has_tests=True,
        web_recommendation={"model": "gpt-5.5", "effort": "xhigh"}, account_state="NORMAL",
    )
    assert result["status"] == "PREVIEW"
    assert (result["final"]["model"], result["final"]["effort"]) == ("gpt-5.5", "xhigh")


def test_file_count_requires_reclassification_for_oversized_tasks():
    small = preview(task_class="T1", file_count=1, risk="medium")
    oversized = preview(task_class="T1", file_count=100, risk="medium")
    assert small["status"] == "PREVIEW"
    assert oversized["status"] == "HOLD"
    assert "reclassify" in oversized["hold_reasons"][0]
    assert small["policy_input"]["file_count"] != oversized["policy_input"]["file_count"]


def test_write_downgrade_requires_tests_and_is_limited_to_two_grades():
    without_tests = preview(read_only=False, has_tests=False)
    with_tests = preview(read_only=False, has_tests=True)
    assert without_tests["status"] == "PREVIEW"
    assert without_tests["final"]["model"] == "gpt-terra"
    assert with_tests["status"] == "PREVIEW"
    assert with_tests["final"]["model"] == "gpt-5.4"
    assert any("two model grades" in reason for reason in with_tests["downgrade_reasons"])


def test_unknown_task_class_holds_instead_of_defaulting_to_t1():
    result = preview(task_class="unclassified-work")
    assert result["status"] == "HOLD"
    assert result["task_class"] is None
    assert "Unknown task_class" in result["hold_reasons"][0]


def test_high_risk_depleted_model_holds_instead_of_forcing_a_lower_model():
    result = preview(model_statuses={"gpt-terra": "DEPLETED"}, risk="high")
    assert result["status"] == "HOLD"
    assert result["final"] is None
    assert "medium- and high-risk" in result["hold_reasons"][0]


def test_recommendation_below_local_minimum_holds_without_auto_promotion():
    result = preview(
        task_class="T3",
        web_recommendation={"model": "gpt-mini", "effort": "high"},
    )
    assert result["status"] == "HOLD"
    assert "automatic promotion" in result["hold_reasons"][0]


def test_unadvertised_effort_and_manual_limited_models_are_reported():
    unsupported = preview(web_recommendation={"model": "gpt-terra", "effort": "maximum"})
    assert unsupported["status"] == "HOLD"
    assert unsupported["final"] is None

    limited = preview(model_statuses={"gpt-terra": "LIMITED"}, risk="high")
    assert limited["status"] == "PREVIEW"
    assert limited["final"]["effort"] == "high"
    assert limited["final"]["status"] == "LIMITED"
    assert any("LIMITED" in warning for warning in limited["warnings"])


def test_account_states_control_preview_and_record_usage_evidence():
    normal = preview(account_state="NORMAL", account_usage=usage("NORMAL", 20))
    conserve = preview(account_state="CONSERVE", account_usage=usage("CONSERVE", 75), risk="medium")
    critical = preview(account_state="CRITICAL", account_usage=usage("CRITICAL", 95))
    blocked = preview(account_state="BLOCKED", account_usage=usage("BLOCKED", 100))
    unknown = preview(account_state="UNKNOWN", account_usage=usage("UNKNOWN"), risk="medium")
    assert normal["final"]["model"] == "gpt-5.4"
    assert conserve["status"] == "PREVIEW" and conserve["final"]["model"] == "gpt-terra"
    assert critical["status"] == "HOLD"
    assert blocked["status"] == "HOLD"
    assert unknown["status"] == "PREVIEW"
    assert "UNKNOWN" in unknown["warnings"][0]
    assert critical["account_usage_evidence"]["maximum_used_percent"] == 95


def test_ultra_is_previewed_only_when_all_four_conditions_and_account_allow_it():
    blocked = preview(web_recommendation={"model": "gpt-terra", "effort": "ultra"})
    assert blocked["status"] == "PREVIEW"
    assert blocked["final"]["effort"] == "max"

    conserve = preview(
        account_state="CONSERVE",
        account_usage=usage("CONSERVE", 70),
        web_recommendation={"model": "gpt-terra", "effort": "ultra"},
        parallel_audit=True,
        independent_axes=3,
        explicit_ultra_approval=True,
    )
    assert conserve["final"]["effort"] == "max"

    allowed = preview(
        web_recommendation={"model": "gpt-terra", "effort": "ultra"},
        parallel_audit=True,
        independent_axes=3,
        explicit_ultra_approval=True,
    )
    assert allowed["status"] == "PREVIEW"
    assert allowed["final"]["effort"] == "ultra"
    assert allowed["ultra_conditions"]["account_allows_ultra"] is True


def test_router_preview_is_pure_and_never_reports_an_execution_rpc():
    result = preview()
    assert result["execution_rpc_called"] is False
    assert result["preview_only"] is True
    assert all("selection_reason" in candidate for candidate in result["candidate_ladder"])


def test_preview_endpoint_does_not_touch_the_app_server_execution_client(tmp_path, monkeypatch):
    class ExecutionMustNotRun:
        async def request(self, method, params):  # pragma: no cover - assertion is the contract
            raise AssertionError(f"preview attempted execution RPC: {method}")

        async def close(self):
            return None

    monkeypatch.setattr(app_main, "DATA_ROOT", tmp_path / "data")
    with TestClient(app_main.app, base_url="http://127.0.0.1:8787") as client:
        client.app.state.gate.store.save_model_catalog(MODELS)
        client.app.state.gate.client = ExecutionMustNotRun()
        response = client.post("/api/router/preview", json={
            "task_class": "T3",
            "risk": "low",
            "read_only": True,
            "file_count": 1,
            "has_tests": True,
            "web_recommendation": {"model": "gpt-terra", "effort": "high"},
        })
    assert response.status_code == 200
    assert response.json()["execution_rpc_called"] is False
