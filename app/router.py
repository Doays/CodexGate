from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any


MODEL_STATES = frozenset({"AVAILABLE", "LIMITED", "DEPLETED", "UNKNOWN", "DISABLED"})
ACCOUNT_STATES = frozenset({"NORMAL", "CONSERVE", "CRITICAL", "BLOCKED", "UNKNOWN"})

# These are policy families, not a lexical ordering of app-server model names.
TASK_FAMILIES = {
    "T0": ("spark",),
    "T1": ("spark", "mini"),
    "T2": ("mini", "luna"),
    "T3": ("5.4", "terra"),
    "T4": ("terra", "5.4"),
    "T5": ("sol", "5.5"),
}
TASK_MIN_GRADE = {"T0": 0, "T1": 0, "T2": 1, "T3": 3, "T4": 3, "T5": 5}
TASK_MIN_EFFORT_STAGE = {"T0": 1, "T1": 2, "T2": 2, "T3": 2, "T4": 3, "T5": 4}
FAMILY_GRADE = {"spark": 0, "mini": 1, "luna": 2, "5.4": 3, "terra": 4, "5.5": 5, "sol": 6}
LOW_RISK = frozenset({"low", "safe", "minimal"})

# The comparison is semantic; the selected value still comes from model/list order.
EFFORT_STAGE = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "xhigh": 3,
    "x-high": 3,
    "veryhigh": 3,
    "very-high": 3,
    "매우높음": 3,
    "매우-높음": 3,
    "max": 4,
    "ultra": 5,
}
EFFORT_LABEL = {1: "Medium", 2: "High", 3: "Very High", 4: "Max"}


@dataclass(frozen=True)
class CatalogModel:
    id: str
    name: str
    family: str | None
    grade: int | None
    efforts: tuple[str, ...]
    status: str


def _normalized_task_class(value: str) -> str | None:
    candidate = value.strip().upper()
    if candidate in TASK_FAMILIES:
        return candidate
    aliases = {
        "INSPECT": "T0", "READ": "T0", "DOCS": "T0", "PATCH": "T1", "TEST": "T2",
        "REFACTOR": "T3", "ARCHITECTURE": "T4", "CRITICAL": "T5",
    }
    return aliases.get(candidate)


def _family_for(model: Mapping[str, Any]) -> str | None:
    text = " ".join(
        str(model.get(key, "")) for key in ("id", "model", "displayName", "display_name")
    ).casefold()
    for family in ("spark", "mini", "luna", "terra", "sol", "5.5", "5.4"):
        if family in text:
            return family
    return None


def _effort_stage(value: str) -> int | None:
    normalized = value.strip().casefold().replace("_", "-").replace(" ", "-")
    return EFFORT_STAGE.get(normalized)


def _catalog(models: Sequence[Mapping[str, Any]], statuses: Mapping[str, str] | None) -> list[CatalogModel]:
    result: list[CatalogModel] = []
    for entry in models:
        model_id = entry.get("id")
        if not isinstance(model_id, str) or not model_id or entry.get("hidden"):
            continue
        efforts = tuple(
            option["reasoningEffort"]
            for option in entry.get("supportedReasoningEfforts", [])
            if isinstance(option, Mapping) and isinstance(option.get("reasoningEffort"), str)
        )
        if not efforts:
            continue
        raw_status = (statuses or {}).get(model_id, entry.get("manual_status", "AVAILABLE"))
        status = raw_status.upper() if isinstance(raw_status, str) else "UNKNOWN"
        if status not in MODEL_STATES:
            status = "UNKNOWN"
        family = _family_for(entry)
        result.append(CatalogModel(
            id=model_id,
            name=str(entry.get("displayName", entry.get("display_name", model_id))),
            family=family,
            grade=FAMILY_GRADE.get(family) if family else None,
            efforts=efforts,
            status=status,
        ))
    return result


def _recommendation(value: Mapping[str, Any] | None) -> tuple[str | None, str | None]:
    if not isinstance(value, Mapping):
        return None, None
    model = value.get("model") or value.get("model_id")
    effort = value.get("effort") or value.get("reasoning_effort")
    return (model if isinstance(model, str) else None, effort if isinstance(effort, str) else None)


def _is_ultra(model: CatalogModel, effort: str | None) -> bool:
    return effort is not None and effort.casefold() == "ultra" and model.family in {"sol", "terra", "luna"}


def _minimum_effort_stage(task_class: str, file_count: int, model: CatalogModel | None = None) -> int:
    if task_class == "T5" and model is not None and model.family == "5.5":
        advertised = [_effort_stage(effort) for effort in model.efforts if _effort_stage(effort) is not None and _effort_stage(effort) < EFFORT_STAGE["ultra"]]
        if advertised:
            return max(advertised)
    if task_class == "T3" and file_count >= 4:
        return 3
    return TASK_MIN_EFFORT_STAGE[task_class]


def _literal_at_stage(model: CatalogModel, stage: int) -> str | None:
    for effort in model.efforts:
        if _effort_stage(effort) == stage:
            return effort
    return None


def _select_effort(model: CatalogModel, minimum_stage: int, ceiling_stage: int | None) -> str | None:
    """Select the first suitable server literal without sorting the model/list array."""
    if ceiling_stage is None or ceiling_stage < minimum_stage:
        return None
    for effort in model.efforts:
        stage = _effort_stage(effort)
        if stage is not None and minimum_stage <= stage <= ceiling_stage and stage < EFFORT_STAGE["ultra"]:
            return effort
    return None


def _highest_non_ultra_effort(model: CatalogModel) -> str | None:
    for effort in reversed(model.efforts):
        stage = _effort_stage(effort)
        if stage is not None and stage < EFFORT_STAGE["ultra"]:
            return effort
    return None


def _ladder(catalog: Sequence[CatalogModel], task_class: str, maximum_grade: int) -> list[CatalogModel]:
    """Apply the task-family ladder while retaining server order inside each family."""
    families: list[str] = list(TASK_FAMILIES[task_class])
    for family in ("sol", "5.5", "terra", "5.4", "luna", "mini", "spark"):
        if family not in families:
            families.append(family)
    result: list[CatalogModel] = []
    for family in families:
        for model in catalog:
            if (
                model.family == family
                and model.grade is not None
                and TASK_MIN_GRADE[task_class] <= model.grade <= maximum_grade
                and model not in result
            ):
                result.append(model)
    return result


def _account_evidence(account_usage: Mapping[str, Any] | None) -> dict[str, Any]:
    if not isinstance(account_usage, Mapping):
        return {"status": "UNKNOWN", "maximum_window": None, "maximum_used_percent": None, "windows": []}
    evidence = account_usage.get("account_state_evidence")
    if not isinstance(evidence, Mapping):
        return {"status": "UNKNOWN", "maximum_window": None, "maximum_used_percent": None, "windows": []}
    return {
        "status": evidence.get("status", "UNKNOWN"),
        "maximum_window": evidence.get("maximum_window"),
        "maximum_used_percent": evidence.get("maximum_used_percent"),
        "windows": evidence.get("windows", []),
        "blocking_reason": evidence.get("blocking_reason"),
    }


def _policy_input(task_class: str | None, file_count: int, has_tests: bool, read_only: bool, risk: str, minimum_stage: int | None) -> dict[str, Any]:
    return {
        "task_class": task_class,
        "file_count": file_count,
        "has_tests": has_tests,
        "read_only": read_only,
        "risk": risk,
        "minimum_effort": EFFORT_LABEL.get(minimum_stage) if minimum_stage is not None else None,
    }


def _candidate(model: CatalogModel, effort: str | None, selected: bool = False) -> dict[str, Any]:
    if selected:
        reason = "selected by the preview policy"
    elif model.status in {"DISABLED", "DEPLETED", "UNKNOWN"}:
        reason = f"excluded: manual model status is {model.status}"
    elif model.status == "LIMITED":
        reason = "eligible only after AVAILABLE candidates; manual status warning"
    elif effort is None:
        reason = "excluded: no advertised non-Ultra effort meets the local minimum within the Web GPT ceiling"
    else:
        reason = "eligible: advertised effort satisfies the local minimum"
    return {
        "model": model.id,
        "name": model.name,
        "family": model.family,
        "effort": effort,
        "status": model.status,
        "selection_reason": reason,
    }


def _result(
    *,
    status: str,
    task_class: str | None,
    recommendation: dict[str, str | None],
    ladder: Sequence[CatalogModel],
    minimum_effort: int | None,
    account_state: str,
    account_usage: Mapping[str, Any] | None,
    file_count: int,
    has_tests: bool,
    read_only: bool,
    risk: str,
    recommendation_stage: int | None = None,
    final: tuple[CatalogModel, str] | None = None,
    downgrade_reasons: Sequence[str] = (),
    hold_reasons: Sequence[str] = (),
    warnings: Sequence[str] = (),
    ultra_conditions: Mapping[str, bool] | None = None,
) -> dict[str, Any]:
    if recommendation_stage is None:
        recommendation_stage = _effort_stage(recommendation.get("effort")) if recommendation.get("effort") else None
    selected_id = final[0].id if final else None
    reasons = list(downgrade_reasons)
    if final and recommendation.get("model") and final[0].id != recommendation["model"]:
        reasons.append(f"Model downgrade: {recommendation['model']} -> {final[0].id}.")
    if final and recommendation.get("effort") and final[1] != recommendation["effort"]:
        final_stage = _effort_stage(final[1])
        if final_stage is not None and recommendation_stage is not None and final_stage < recommendation_stage:
            reasons.append(f"Effort downgrade: stage {recommendation_stage} -> {final_stage} ({recommendation['effort']} -> {final[1]}).")
        else:
            reasons.append(f"Effort literal mapping: {recommendation['effort']} -> {final[1]} at semantic stage {recommendation_stage}.")
    return {
        "status": status,
        "task_class": task_class,
        "recommendation": recommendation,
        "final": _candidate(final[0], final[1], selected=True) if final else None,
        "candidate_ladder": [
            _candidate(
                model,
                final[1] if final and model.id == selected_id else (
                    _select_effort(model, _minimum_effort_stage(task_class, file_count, model), recommendation_stage) if recommendation_stage is not None else None
                ),
                model.id == selected_id,
            )
            for model in ladder
        ],
        "downgrade_reasons": reasons,
        "hold_reasons": list(hold_reasons),
        "warnings": list(warnings),
        "account_state": account_state,
        "account_usage_evidence": _account_evidence(account_usage),
        "policy_input": _policy_input(task_class, file_count, has_tests, read_only, risk, minimum_effort),
        "ultra_conditions": dict(ultra_conditions or {}),
        "preview_only": True,
        "execution_rpc_called": False,
    }


def _scale_hold_reason(task_class: str, file_count: int) -> str | None:
    limits = {"T1": (2, "T2"), "T2": (5, "T3"), "T3": (10, "T4")}
    limit = limits.get(task_class)
    if limit and file_count > limit[0]:
        return f"{task_class} covers at most {limit[0]} files; reclassify this {file_count}-file task as {limit[1]} or split it."
    return None


def _downgrade_policy(
    *, task_class: str, risk: str, read_only: bool, has_tests: bool, account_state: str,
) -> tuple[bool, int | None, str | None]:
    if risk.strip().casefold() not in LOW_RISK:
        return False, None, "medium- and high-risk work is not automatically downgraded"
    if account_state == "CONSERVE" and risk.strip().casefold() not in LOW_RISK:
        return False, None, "CONSERVE permits downgrade previews only for low-risk work"
    if read_only:
        return True, None, None
    if not has_tests:
        return False, None, "low-risk Write work requires tests before any automatic downgrade"
    if task_class in {"T2", "T3", "T4", "T5"} and not has_tests:
        return False, None, "non-Read Only T2+ work without tests cannot be automatically downgraded"
    return True, 2, "low-risk Write downgrade is limited to two model grades"


def route_preview(
    models: Sequence[Mapping[str, Any]],
    model_statuses: Mapping[str, str] | None = None,
    *,
    task_class: str,
    risk: str,
    read_only: bool,
    file_count: int,
    has_tests: bool,
    web_recommendation: Mapping[str, Any] | None,
    account_state: str = "UNKNOWN",
    account_usage: Mapping[str, Any] | None = None,
    parallel_audit: bool = False,
    independent_axes: int = 0,
    explicit_ultra_approval: bool = False,
) -> dict[str, Any]:
    """Return a side-effect-free route preview; it never starts a Codex turn."""
    normalized_class = _normalized_task_class(task_class)
    recommendation_model, recommendation_effort = _recommendation(web_recommendation)
    recommendation = {"model": recommendation_model, "effort": recommendation_effort}
    normalized_account = account_state.strip().upper() if isinstance(account_state, str) else "UNKNOWN"
    if normalized_account not in ACCOUNT_STATES:
        normalized_account = "UNKNOWN"
    warnings = ["Account state is UNKNOWN; no usage-based downgrade decision was made."] if normalized_account == "UNKNOWN" else []

    if normalized_class is None:
        return _result(
            status="HOLD", task_class=None, recommendation=recommendation, ladder=(), minimum_effort=None,
            account_state=normalized_account, account_usage=account_usage, file_count=file_count, has_tests=has_tests,
            read_only=read_only, risk=risk, hold_reasons=[f"Unknown task_class: {task_class!r}. Reclassify before routing."], warnings=warnings,
        )

    catalog = _catalog(models, model_statuses)
    if not recommendation_model or not recommendation_effort:
        return _result(
            status="HOLD", task_class=normalized_class, recommendation=recommendation, ladder=(),
            minimum_effort=_minimum_effort_stage(normalized_class, file_count), account_state=normalized_account,
            account_usage=account_usage, file_count=file_count, has_tests=has_tests, read_only=read_only, risk=risk,
            hold_reasons=["Web GPT model and effort recommendation are required for a route preview."], warnings=warnings,
        )
    recommended = next((model for model in catalog if model.id == recommendation_model), None)
    if not recommended or recommended.grade is None:
        return _result(
            status="HOLD", task_class=normalized_class, recommendation=recommendation, ladder=(),
            minimum_effort=_minimum_effort_stage(normalized_class, file_count), account_state=normalized_account,
            account_usage=account_usage, file_count=file_count, has_tests=has_tests, read_only=read_only, risk=risk,
            hold_reasons=["Recommended model is not present in the current model/list catalog."], warnings=warnings,
        )

    ladder = _ladder(catalog, normalized_class, recommended.grade)
    display_ladder = [recommended, *[model for model in ladder if model.id != recommended.id]]
    minimum_effort = _minimum_effort_stage(normalized_class, file_count, recommended)
    if normalized_account == "BLOCKED":
        return _result(
            status="HOLD", task_class=normalized_class, recommendation=recommendation, ladder=display_ladder,
            minimum_effort=minimum_effort, account_state=normalized_account, account_usage=account_usage,
            file_count=file_count, has_tests=has_tests, read_only=read_only, risk=risk,
            hold_reasons=["Account state is BLOCKED; all Codex routing previews are held."], warnings=warnings,
        )
    if normalized_account == "CRITICAL" and normalized_class in {"T3", "T4", "T5"}:
        return _result(
            status="HOLD", task_class=normalized_class, recommendation=recommendation, ladder=display_ladder,
            minimum_effort=minimum_effort, account_state=normalized_account, account_usage=account_usage,
            file_count=file_count, has_tests=has_tests, read_only=read_only, risk=risk,
            hold_reasons=["Account state is CRITICAL; T3 through T5 previews are held."], warnings=warnings,
        )
    scale_reason = _scale_hold_reason(normalized_class, file_count)
    if scale_reason:
        return _result(
            status="HOLD", task_class=normalized_class, recommendation=recommendation, ladder=display_ladder,
            minimum_effort=minimum_effort, account_state=normalized_account, account_usage=account_usage,
            file_count=file_count, has_tests=has_tests, read_only=read_only, risk=risk,
            hold_reasons=[scale_reason], warnings=warnings,
        )
    if recommended.grade < TASK_MIN_GRADE[normalized_class]:
        return _result(
            status="HOLD", task_class=normalized_class, recommendation=recommendation, ladder=display_ladder,
            minimum_effort=minimum_effort, account_state=normalized_account, account_usage=account_usage,
            file_count=file_count, has_tests=has_tests, read_only=read_only, risk=risk,
            hold_reasons=["Web GPT recommendation is below the local minimum grade; automatic promotion is forbidden."], warnings=warnings,
        )
    recommendation_stage = _effort_stage(recommendation_effort)
    if recommendation_stage is None:
        return _result(
            status="HOLD", task_class=normalized_class, recommendation=recommendation, ladder=display_ladder,
            minimum_effort=minimum_effort, account_state=normalized_account, account_usage=account_usage,
            file_count=file_count, has_tests=has_tests, read_only=read_only, risk=risk,
            hold_reasons=["Recommended effort is not advertised by model/list."], warnings=warnings,
        )
    if _literal_at_stage(recommended, recommendation_stage) is None:
        return _result(
            status="HOLD", task_class=normalized_class, recommendation=recommendation, ladder=display_ladder,
            minimum_effort=minimum_effort, account_state=normalized_account, account_usage=account_usage,
            file_count=file_count, has_tests=has_tests, read_only=read_only, risk=risk,
            hold_reasons=["Recommended effort stage has no server-advertised literal on the recommended model."], warnings=warnings,
        )
    if recommendation_stage < minimum_effort:
        return _result(
            status="HOLD", task_class=normalized_class, recommendation=recommendation, ladder=display_ladder,
            minimum_effort=minimum_effort, account_state=normalized_account, account_usage=account_usage,
            file_count=file_count, has_tests=has_tests, read_only=read_only, risk=risk,
            hold_reasons=["Web GPT recommended effort is below the local minimum; automatic effort promotion is forbidden."], warnings=warnings,
        )

    is_ultra_request = _is_ultra(recommended, recommendation_effort)
    ultra_conditions = {
        "read_only": read_only,
        "parallel_audit": parallel_audit,
        "independent_axes": independent_axes >= 3,
        "explicit_ultra_approval": explicit_ultra_approval,
        "account_allows_ultra": normalized_account not in {"CONSERVE", "CRITICAL"},
    }
    if is_ultra_request:
        if all(ultra_conditions.values()) and recommended.status in {"AVAILABLE", "LIMITED"}:
            ultra_literal = _literal_at_stage(recommended, recommendation_stage)
            return _result(
                status="PREVIEW", task_class=normalized_class, recommendation=recommendation, ladder=display_ladder,
                minimum_effort=minimum_effort, account_state=normalized_account, account_usage=account_usage,
                file_count=file_count, has_tests=has_tests, read_only=read_only, risk=risk,
                final=(recommended, ultra_literal), warnings=warnings,
                ultra_conditions=ultra_conditions,
            )
        fallback = _highest_non_ultra_effort(recommended)
        if fallback and _effort_stage(fallback) is not None and _effort_stage(fallback) >= minimum_effort and recommended.status in {"AVAILABLE", "LIMITED"}:
            return _result(
                status="PREVIEW", task_class=normalized_class, recommendation=recommendation, ladder=display_ladder,
                minimum_effort=minimum_effort, account_state=normalized_account, account_usage=account_usage,
                file_count=file_count, has_tests=has_tests, read_only=read_only, risk=risk, final=(recommended, fallback),
                downgrade_reasons=["Ultra is unavailable for this preview; highest advertised non-Ultra effort was selected."],
                warnings=warnings, ultra_conditions=ultra_conditions,
            )
        return _result(
            status="HOLD", task_class=normalized_class, recommendation=recommendation, ladder=display_ladder,
            minimum_effort=minimum_effort, account_state=normalized_account, account_usage=account_usage,
            file_count=file_count, has_tests=has_tests, read_only=read_only, risk=risk,
            hold_reasons=["Ultra is unavailable and the recommended model has no safe non-Ultra effort."], warnings=warnings,
            ultra_conditions=ultra_conditions,
        )

    automatic, write_limit, automatic_reason = _downgrade_policy(
        task_class=normalized_class, risk=risk, read_only=read_only, has_tests=has_tests, account_state=normalized_account,
    )
    lower_candidates = [
        model for model in ladder
        if model.id != recommended.id
        and model.grade is not None
        and model.grade < recommended.grade
        and (write_limit is None or recommended.grade - model.grade <= write_limit)
    ]
    if automatic:
        for states in (("AVAILABLE",), ("LIMITED",)):
            selected = next(
                (
                    model for model in lower_candidates
                    if model.status in states and _select_effort(model, _minimum_effort_stage(normalized_class, file_count, model), recommendation_stage)
                ),
                None,
            )
            if selected:
                selected_effort = _select_effort(selected, _minimum_effort_stage(normalized_class, file_count, selected), recommendation_stage)
                candidate_warning = ["Selected model is LIMITED because no AVAILABLE lower candidate was eligible."] if selected.status == "LIMITED" else []
                return _result(
                    status="PREVIEW", task_class=normalized_class, recommendation=recommendation, ladder=display_ladder,
                    minimum_effort=minimum_effort, account_state=normalized_account, account_usage=account_usage,
                    file_count=file_count, has_tests=has_tests, read_only=read_only, risk=risk, final=(selected, selected_effort),
                    downgrade_reasons=["Low-risk policy selected a lower model within the Web GPT recommendation ceiling."] + ([automatic_reason] if automatic_reason else []),
                    warnings=warnings + candidate_warning,
                )

    recommended_effort_value = (
        _select_effort(recommended, minimum_effort, recommendation_stage)
        if automatic else _literal_at_stage(recommended, recommendation_stage)
    )
    if recommended.status in {"AVAILABLE", "LIMITED"} and recommended_effort_value:
        limited_warning = ["Recommended model is LIMITED; AVAILABLE candidates would take priority for an allowed automatic downgrade."] if recommended.status == "LIMITED" else []
        return _result(
            status="PREVIEW", task_class=normalized_class, recommendation=recommendation, ladder=display_ladder,
            minimum_effort=minimum_effort, account_state=normalized_account, account_usage=account_usage,
            file_count=file_count, has_tests=has_tests, read_only=read_only, risk=risk, final=(recommended, recommended_effort_value),
            warnings=warnings + limited_warning,
        )

    reason = automatic_reason or f"Recommended model is {recommended.status} or cannot meet the local effort minimum."
    return _result(
        status="HOLD", task_class=normalized_class, recommendation=recommendation, ladder=display_ladder,
        minimum_effort=minimum_effort, account_state=normalized_account, account_usage=account_usage,
        file_count=file_count, has_tests=has_tests, read_only=read_only, risk=risk, hold_reasons=[reason], warnings=warnings,
    )
