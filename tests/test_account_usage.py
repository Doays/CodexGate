from __future__ import annotations

import asyncio
import sqlite3

from app.gateway import Gate
from app.storage import Store, account_state_details_from_snapshot


MODELS = [
    {
        "id": "gpt-5.6-terra",
        "model": "gpt-5.6-terra",
        "displayName": "5.6 Terra",
        "hidden": False,
        "defaultReasoningEffort": "high",
        "supportedReasoningEfforts": [
            {"reasoningEffort": "medium"},
            {"reasoningEffort": "high"},
            {"reasoningEffort": "ultra"},
        ],
        "serviceTiers": [{"id": "fast", "name": "Fast", "description": "Fast tier"}],
    }
]


class AccountClient:
    connected = True
    models = MODELS
    stderr_lines: list[str] = []
    command = "codex"
    version = "0.145.0"
    protocol = None
    schema_error = None
    workspace_write_schema_ready = False

    async def connect(self):
        return MODELS

    async def read_account(self):
        return {
            "requiresOpenaiAuth": False,
            "account": {"type": "chatgpt", "planType": "plus", "email": "person@example.com"},
        }

    async def read_rate_limits(self):
        return {
            "rateLimits": {
                "limitId": "codex",
                "primary": {"usedPercent": 72, "resetsAt": 1_800_000_000, "windowDurationMins": 300},
            }
        }

    async def read_usage(self):
        return {
            "summary": {},
            "dailyUsageBuckets": [{"startDate": "2026-07-26", "tokens": 1234}],
        }


def test_account_snapshot_masks_email_and_preserves_server_effort_order(tmp_path):
    async def scenario():
        store = Store(tmp_path)
        gate = Gate(store)
        gate.client = AccountClient()
        await gate.connect()
        overview = store.account_overview()
        assert overview["account"] == {
            "status": "AVAILABLE",
            "captured_at": overview["account"]["captured_at"],
            "auth_mode": "chatgpt",
            "plan_type": "plus",
            "email_masked": "p***@example.com",
            "requires_openai_auth": False,
        }
        catalog = store.model_catalog()
        assert catalog[0]["efforts"] == ["medium", "high", "ultra"]
        assert catalog[0]["speed_tiers"] == [{"id": "fast", "name": "Fast"}]
        with sqlite3.connect(store.db_path) as conn:
            saved_payloads = " ".join(row[0] for row in conn.execute("SELECT payload FROM account_snapshots"))
        assert "person@example.com" not in saved_payloads
    asyncio.run(scenario())


def test_rate_limit_sparse_update_merges_without_creating_model_balances(tmp_path):
    async def scenario():
        store = Store(tmp_path)
        store.save_rate_limits({
            "rateLimits": {
                "limitId": "codex",
                "primary": {"usedPercent": 40, "resetsAt": 100, "windowDurationMins": 60},
                "secondary": {"usedPercent": 10, "resetsAt": 200, "windowDurationMins": 1440},
            },
            "rateLimitsByLimitId": {"other": {"secondary": {"usedPercent": 95}}},
        })
        gate = Gate(store)
        await gate.handle_event({"method": "account/rateLimits/updated", "params": {"rateLimits": {"primary": {"usedPercent": 91, "resetsAt": None}}}})
        overview = store.account_overview()
        primary = overview["rate_limits"]["rateLimits"]["primary"]
        assert primary == {"usedPercent": 91, "resetsAt": 100, "windowDurationMins": 60}
        assert overview["rate_limits"]["rateLimitsByLimitId"]["other"]["secondary"]["usedPercent"] == 95
        assert overview["account_state"] == "CRITICAL"
        assert "models" not in overview["rate_limits"]
        assert store.model_catalog() == []
    asyncio.run(scenario())


def test_missing_account_fields_are_unknown_and_thresholds_are_configurable(tmp_path):
    store = Store(tmp_path)
    store.save_account({"requiresOpenaiAuth": False, "account": None})
    store.save_rate_limits({})
    store.save_usage({"summary": {}})
    overview = store.account_overview()
    assert overview["account"]["status"] == "UNKNOWN"
    assert overview["rate_limits"]["status"] == "UNKNOWN"
    assert overview["usage"]["status"] == "UNKNOWN"
    assert overview["account_state"] == "UNKNOWN"
    assert store.set_usage_thresholds({"conserve": 60, "critical": 80, "blocked": 100}) == {
        "conserve": 60,
        "critical": 80,
        "blocked": 100,
    }


def test_manual_model_states_are_separate_from_account_limits(tmp_path):
    store = Store(tmp_path)
    store.save_model_catalog(MODELS)
    assert store.model_catalog()[0]["status"] == "AVAILABLE"
    store.set_model_status("gpt-5.6-terra", "LIMITED")
    assert store.model_catalog()[0]["status"] == "LIMITED"
    store.set_model_status("gpt-5.6-terra", "DEPLETED")
    assert store.model_catalog()[0]["status"] == "DEPLETED"
    store.save_rate_limits({"rateLimits": {"primary": {"usedPercent": 20}}})
    assert store.account_overview()["account_state"] == "NORMAL"
    assert store.model_catalog()[0]["status"] == "DEPLETED"


def test_secondary_and_per_limit_windows_use_the_highest_used_percent(tmp_path):
    store = Store(tmp_path)
    store.save_rate_limits({
        "rateLimits": {
            "primary": {"usedPercent": 10},
            "secondary": {"usedPercent": 95},
        },
        "rateLimitsByLimitId": {
            "other": {
                "primary": {"usedPercent": 80},
                "secondary": {"usedPercent": 15},
            }
        },
    })
    overview = store.account_overview()
    assert overview["account_state"] == "CRITICAL"
    assert overview["account_state_evidence"] == {
        "status": "CRITICAL",
        "maximum_used_percent": 95,
        "maximum_window": {"source": "rateLimits", "window": "secondary", "used_percent": 95},
        "windows": [
            {"source": "rateLimits", "window": "primary", "used_percent": 10},
            {"source": "rateLimits", "window": "secondary", "used_percent": 95},
            {"source": "rateLimitsByLimitId.other", "window": "primary", "used_percent": 80},
            {"source": "rateLimitsByLimitId.other", "window": "secondary", "used_percent": 15},
        ],
        "blocking_reason": None,
    }


def test_spend_control_and_rate_limit_reached_are_blocked_even_below_thresholds():
    thresholds = {"conserve": 70, "critical": 90, "blocked": 100}
    spend_control = account_state_details_from_snapshot(
        {"rateLimits": {"primary": {"usedPercent": 1}, "spendControlReached": True}}, thresholds
    )
    rate_limit = account_state_details_from_snapshot(
        {"rateLimits": {"primary": {"usedPercent": 1}, "rateLimitReachedType": "rate_limit_reached"}}, thresholds
    )
    assert spend_control["status"] == "BLOCKED"
    assert spend_control["blocking_reason"] == "rateLimits.spendControlReached"
    assert rate_limit["status"] == "BLOCKED"
    assert rate_limit["blocking_reason"] == "rateLimits.rateLimitReachedType=rate_limit_reached"
