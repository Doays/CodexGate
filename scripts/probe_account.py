from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.app_server import AppServerClient  # noqa: E402


async def _ignore(_: Any) -> None:
    return None


def _mask_email(value: Any) -> str | None:
    if not isinstance(value, str) or "@" not in value:
        return None
    local, domain = value.split("@", 1)
    return f"{local[:1] or '*'}***@{domain}"


def _rate_summary(response: dict[str, Any]) -> dict[str, Any]:
    snapshot = response.get("rateLimits") if isinstance(response.get("rateLimits"), dict) else {}
    primary = snapshot.get("primary") if isinstance(snapshot.get("primary"), dict) else {}
    secondary = snapshot.get("secondary") if isinstance(snapshot.get("secondary"), dict) else {}
    return {
        "status": "AVAILABLE" if primary else "UNKNOWN",
        "primary": {key: primary.get(key) for key in ("usedPercent", "resetsAt", "windowDurationMins")},
        "secondary": {key: secondary.get(key) for key in ("usedPercent", "resetsAt", "windowDurationMins")},
        "note": "This is an account-wide rate-limit snapshot, not per-model remaining capacity.",
    }


async def probe() -> dict[str, Any]:
    client = AppServerClient(_ignore)
    try:
        models = await client.connect()
        result: dict[str, Any] = {
            "codex_path": client.command,
            "codex_version": client.version,
            "models": [
                {
                    "id": item.get("id"),
                    "name": item.get("displayName"),
                    "efforts": [
                        option.get("reasoningEffort")
                        for option in item.get("supportedReasoningEfforts", [])
                        if isinstance(option, dict)
                    ],
                    "speed_tiers": [
                        tier.get("name")
                        for tier in item.get("serviceTiers", [])
                        if isinstance(tier, dict)
                    ],
                }
                for item in models
            ],
        }
        try:
            account = await client.read_account()
            account_data = account.get("account") if isinstance(account.get("account"), dict) else {}
            result["account"] = {
                "status": "AVAILABLE" if account_data else "UNKNOWN",
                "auth_mode": account_data.get("type", "UNKNOWN"),
                "plan_type": account_data.get("planType", "UNKNOWN"),
                "email_masked": _mask_email(account_data.get("email")),
            }
        except Exception:
            result["account"] = {"status": "UNKNOWN"}
        try:
            result["rate_limits"] = _rate_summary(await client.read_rate_limits())
        except Exception:
            result["rate_limits"] = {"status": "UNKNOWN"}
        try:
            usage = await client.read_usage()
            buckets = usage.get("dailyUsageBuckets")
            result["usage"] = {
                "status": "AVAILABLE" if isinstance(buckets, list) else "UNKNOWN",
                "daily": [
                    {"startDate": item.get("startDate"), "tokens": item.get("tokens")}
                    for item in buckets
                    if isinstance(item, dict)
                ] if isinstance(buckets, list) else [],
            }
        except Exception:
            result["usage"] = {"status": "UNKNOWN"}
        return result
    finally:
        await client.close()


if __name__ == "__main__":
    print(json.dumps(asyncio.run(probe()), ensure_ascii=False, indent=2))
