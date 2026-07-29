from __future__ import annotations

import asyncio
import json
import os
from contextlib import asynccontextmanager
from urllib.parse import urlsplit
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, ConfigDict, Field, field_validator

from .capsule import create_evidence_capsule
from .catalog import CatalogService
from .bridge import BridgeService
from .gateway import Gate
from .isolation_wsl import LocalWSLCommandRunner, WSLBubblewrapIsolation, public_result as public_wsl_isolation_result
from .isolation_repro import IsolationReproService, public_repro_result
from .wsl_codex_runtime import WSLCodexRuntime, public_runtime_result
from .egress_contract import SealedEgressContractService, public_contract_preview, public_contract_result
from .egress_harness import (
    ActualWSLHarnessGate,
    FAKE_RUNNER_IMPLEMENTATION_HASH,
    FAKE_RUNNER_KIND,
    FAKE_RUNNER_VERSION,
    FakeHarnessRunner,
    SealedEgressHarnessService,
    public_harness_result,
)
from .egress_harness_wsl import (
    RUNNER_IMPLEMENTATION_HASH,
    WSLEgressHarnessRunner,
    WSL_EGRESS_RUNNER_VERSION,
)
from .codex_process_canary import (
    CANARY_RUNNER_KIND,
    RUNNER_IMPLEMENTATION_HASH as CODEX_CANARY_IMPLEMENTATION_HASH,
    RUNNER_VERSION as CODEX_CANARY_RUNNER_VERSION,
    SealedOfflineCodexProcessCanary,
    WSLCodexProcessCanaryRunner,
    public_canary_result,
)
from .format_probe import FormatProbeService
from .indexer import preflight
from .policy import PolicyError, model_choices, validate_project_id, validate_workspace_root
from .router import route_preview
from .storage import Store


ROOT = Path(__file__).resolve().parent
DATA_ROOT = Path(os.environ.get("CODEX_GATE_HOME", str(Path.home() / "CodexGate")))
ALLOWED_LOCAL_HOSTS = {"127.0.0.1", "localhost"}


class PreflightRequest(BaseModel):
    project_name: str = Field(min_length=1, max_length=120)
    root: str = Field(min_length=1)
    task: str = Field(min_length=3, max_length=12_000)


class RunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    route_plan_id: str = Field(min_length=36, max_length=36)


class RoutePlanRequest(PreflightRequest):
    model_config = ConfigDict(extra="forbid")

    project_id: str = Field(min_length=1, max_length=80)
    decision: dict[str, Any]
    permission: str
    explicit_ultra_approval: bool = False

    @field_validator("project_id")
    @classmethod
    def validate_project_id_field(cls, value: str) -> str:
        return validate_project_id(value)


class ApprovalResponseRequest(BaseModel):
    decision: str = Field(pattern="^(accept|acceptForSession|decline|cancel)$")
    permissions: dict[str, Any] | None = None


class RouterPreviewRequest(BaseModel):
    task_class: str = Field(min_length=1, max_length=40)
    risk: str = Field(min_length=1, max_length=40)
    read_only: bool
    file_count: int = Field(ge=0, le=100_000)
    has_tests: bool
    web_recommendation: dict[str, Any]
    parallel_audit: bool = False
    independent_axes: int = Field(default=0, ge=0, le=20)
    explicit_ultra_approval: bool = False


class ModelStatusRequest(BaseModel):
    status: str = Field(pattern="^(AVAILABLE|LIMITED|DEPLETED|UNKNOWN|DISABLED)$")


class UsageThresholdRequest(BaseModel):
    conserve: int = Field(ge=0, le=100)
    critical: int = Field(ge=0, le=100)
    blocked: int = Field(ge=0, le=100)


class BridgeStartRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    project_name: str = Field(min_length=1, max_length=120)
    project_id: str = Field(min_length=1, max_length=80)
    root: str = Field(min_length=1)
    task: str = Field(min_length=3, max_length=12_000)
    permission: str = Field(pattern="^(read-only|workspace-write)$")
    chat_url: str | None = Field(default=None, max_length=2048)

    @field_validator("project_id")
    @classmethod
    def validate_bridge_project_id(cls, value: str) -> str:
        return validate_project_id(value)


class BridgeImportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    packet: str = Field(min_length=1, max_length=70_000)


class BridgeReviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    result: dict[str, Any]
    validation: dict[str, Any]


class EvidenceMapRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str = Field(min_length=1, max_length=1024)
    start_line: int | None = Field(default=None, ge=1)
    end_line: int | None = Field(default=None, ge=1)
    line: int | None = Field(default=None, ge=1)
    context_before: int | None = Field(default=None, ge=0)
    context_after: int | None = Field(default=None, ge=0)


class CatalogSourceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    alias: str = Field(min_length=1, max_length=120)
    root: str = Field(min_length=1, max_length=4096)


class CatalogScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_files: int | None = Field(default=None, ge=1, le=10_000_000)


class FormatProbeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    catalog_entry_ids: list[str] = Field(min_length=1, max_length=50)


class WSLIsolationConfigRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    distro: str = Field(min_length=1, max_length=128)


class WSLCodexRuntimeConfigRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    binary_path: str = Field(min_length=1, max_length=512)


class EgressContractCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_preview_hash: str = Field(pattern=r"^[0-9a-f]{64}$")


class ActualWSLHarnessRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    window_nonce: str | None = Field(default=None, min_length=32, max_length=128)
    arm_nonce: str | None = Field(default=None, min_length=32, max_length=128)


class CodexProcessCanaryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    canary_nonce: str | None = Field(default=None, min_length=32, max_length=128)


def _local_host(value: str | None) -> str | None:
    if not value:
        return None
    return value.split(":", 1)[0].strip().casefold()


def _port_or_default(url) -> int | None:
    if url.port is not None:
        return url.port
    return 443 if url.scheme == "https" else 80 if url.scheme == "http" else None


def _same_local_origin(request: Request, origin: str) -> bool:
    parsed = urlsplit(origin)
    if parsed.scheme != request.url.scheme:
        return False
    origin_host = _local_host(parsed.hostname)
    request_host = _local_host(request.url.hostname)
    if origin_host not in ALLOWED_LOCAL_HOSTS or request_host not in ALLOWED_LOCAL_HOSTS:
        return False
    if origin_host != request_host:
        return False
    return _port_or_default(parsed) == _port_or_default(request.url)


def _reject_local_request(detail: str) -> JSONResponse:
    return JSONResponse(status_code=403, content={"detail": detail})


def _enforce_local_request(request: Request) -> JSONResponse | None:
    host = _local_host(request.headers.get("host"))
    if host not in ALLOWED_LOCAL_HOSTS:
        return _reject_local_request("Host must be 127.0.0.1 or localhost.")
    origin = request.headers.get("origin")
    if origin and not _same_local_origin(request, origin):
        return _reject_local_request("Origin must match the local app origin.")
    return None


def _enforce_execution_window_arm_request(request: Request) -> JSONResponse | None:
    """Arming is stricter than ordinary local API access: IPv4 loopback + Origin."""
    if _local_host(request.headers.get("host")) != "127.0.0.1":
        return _reject_local_request("Execution window arming requires Host 127.0.0.1.")
    origin = request.headers.get("origin")
    if not origin or not _same_local_origin(request, origin):
        return _reject_local_request("Execution window arming requires the matching local Origin.")
    return None


@asynccontextmanager
async def lifespan(app: FastAPI):
    store = Store(DATA_ROOT)
    store.recover_interrupted_format_probes()
    store.recover_interrupted_wsl_isolation_probes()
    store.recover_interrupted_wsl_isolation_repros()
    store.recover_interrupted_egress_harnesses()
    store.recover_armed_egress_execution_windows()
    store.recover_interrupted_codex_process_canaries()
    store.recover_armed_codex_process_canary_windows()
    gate_instance = Gate(store)
    app.state.wsl_isolation_service = WSLBubblewrapIsolation(store)
    app.state.wsl_repro_service = IsolationReproService(store, app.state.wsl_isolation_service)
    app.state.wsl_codex_runtime_service = WSLCodexRuntime(store)
    app.state.sealed_egress_contract_service = SealedEgressContractService(store, proof_required=True)
    app.state.sealed_egress_harness_service = SealedEgressHarnessService(
        store, app.state.sealed_egress_contract_service, FakeHarnessRunner()
    )
    actual_runner = WSLEgressHarnessRunner(store, LocalWSLCommandRunner())
    app.state.actual_wsl_egress_harness_service = SealedEgressHarnessService(
        store, app.state.sealed_egress_contract_service, actual_runner,
    )
    # Constructing the runner starts no WSL or other process.  Phase 3.3 only
    # permits it behind an explicit, non-persistent execution window.
    app.state.actual_wsl_egress_harness_gate = ActualWSLHarnessGate(
        store, app.state.actual_wsl_egress_harness_service,
    )
    # Phase 4.0 deliberately exposes no runnable WSL/Codex executor.  The
    # service still publishes its sealed requirements and can only be armed by
    # a future explicit release after a separate implementation review.
    app.state.codex_process_canary_service = SealedOfflineCodexProcessCanary(
        store, app.state.sealed_egress_contract_service, WSLCodexProcessCanaryRunner(),
    )
    app.state.sealed_egress_harness_runner_version = WSL_EGRESS_RUNNER_VERSION
    BridgeService(store, gate_instance.create_route_plan).recover_processing_on_startup()
    app.state.gate = gate_instance
    yield
    await app.state.gate.client.close()


app = FastAPI(title="Codex Gate", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")
templates = Jinja2Templates(directory=ROOT / "templates")


@app.middleware("http")
async def local_request_guard(request: Request, call_next):
    rejection = _enforce_local_request(request)
    if rejection is not None:
        return rejection
    return await call_next(request)


def gate(request: Request) -> Gate:
    return request.app.state.gate


def bridge(request: Request) -> BridgeService:
    current_gate = gate(request)
    return BridgeService(current_gate.store, current_gate.create_route_plan)


def catalog(request: Request) -> CatalogService:
    return CatalogService(gate(request).store)


def format_probe(request: Request) -> FormatProbeService:
    return FormatProbeService(gate(request).store)


def wsl_isolation(request: Request) -> WSLBubblewrapIsolation:
    return request.app.state.wsl_isolation_service


def wsl_repro(request: Request) -> IsolationReproService:
    return request.app.state.wsl_repro_service


def wsl_codex_runtime(request: Request) -> WSLCodexRuntime:
    return request.app.state.wsl_codex_runtime_service


def sealed_egress_contract(request: Request) -> SealedEgressContractService:
    return request.app.state.sealed_egress_contract_service


def sealed_egress_harness(request: Request) -> SealedEgressHarnessService:
    return request.app.state.sealed_egress_harness_service


def actual_wsl_egress_harness(request: Request) -> SealedEgressHarnessService:
    return request.app.state.actual_wsl_egress_harness_service


def actual_wsl_egress_harness_gate(request: Request) -> ActualWSLHarnessGate:
    return request.app.state.actual_wsl_egress_harness_gate


def codex_process_canary(request: Request) -> SealedOfflineCodexProcessCanary:
    return request.app.state.codex_process_canary_service


def codex_process_canary_snapshot(request: Request) -> dict[str, Any]:
    service = codex_process_canary(request)
    readiness = service.ready()
    if readiness.get("status") == "READY":
        current = gate(request).store.codex_process_canary_result(
            readiness["contract_hash"], CANARY_RUNNER_KIND, CODEX_CANARY_RUNNER_VERSION,
            CODEX_CANARY_IMPLEMENTATION_HASH,
        )
        result = public_canary_result(current) if current else readiness
    else:
        result = readiness
    result["execution_window"] = service.window_status()
    result["execution_enabled"] = result["execution_window"].get("status") == "ARMED"
    return result


def as_http_error(error: Exception) -> HTTPException:
    return HTTPException(status_code=400, detail=str(error))


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse(request, "index.html", {"data_root": str(DATA_ROOT)})


@app.get("/api/status")
async def status(request: Request):
    state = gate(request).status()
    state["wsl_isolation"] = public_wsl_isolation_result(gate(request).store.wsl_isolation_result())
    state["wsl_codex_runtime"] = public_runtime_result(gate(request).store.wsl_codex_runtime_result())
    state["sealed_egress_contract"] = public_contract_result(sealed_egress_contract(request).current())
    contract_hash = state["sealed_egress_contract"].get("contract_hash", "")
    current_harness = gate(request).store.egress_harness_result(
        contract_hash, FAKE_RUNNER_KIND, FAKE_RUNNER_VERSION, FAKE_RUNNER_IMPLEMENTATION_HASH,
    ) if contract_hash else None
    state["sealed_egress_harness"] = public_harness_result(current_harness) if current_harness else sealed_egress_harness(request).ready()
    current_actual = gate(request).store.egress_harness_result(
        contract_hash, "WSL_SUPERVISOR", WSL_EGRESS_RUNNER_VERSION, RUNNER_IMPLEMENTATION_HASH,
    ) if contract_hash else None
    state["actual_wsl_egress_harness"] = (
        public_harness_result(current_actual) if current_actual else actual_wsl_egress_harness(request).ready()
    )
    state["actual_wsl_egress_harness"]["execution_window"] = actual_wsl_egress_harness_gate(request).window_status()
    state["actual_wsl_egress_harness"]["execution_enabled"] = (
        state["actual_wsl_egress_harness"]["execution_window"].get("status") == "ARMED"
    )
    state["codex_process_canary"] = codex_process_canary_snapshot(request)
    state["choices"] = model_choices(state["models"])
    return state


@app.post("/api/connect")
async def connect(request: Request):
    try:
        models = await gate(request).connect()
        state = gate(request).status()
        state["wsl_isolation"] = public_wsl_isolation_result(gate(request).store.wsl_isolation_result())
        state["wsl_codex_runtime"] = public_runtime_result(gate(request).store.wsl_codex_runtime_result())
        state["sealed_egress_contract"] = public_contract_result(sealed_egress_contract(request).current())
        contract_hash = state["sealed_egress_contract"].get("contract_hash", "")
        current_harness = gate(request).store.egress_harness_result(
            contract_hash, FAKE_RUNNER_KIND, FAKE_RUNNER_VERSION, FAKE_RUNNER_IMPLEMENTATION_HASH,
        ) if contract_hash else None
        state["sealed_egress_harness"] = public_harness_result(current_harness) if current_harness else sealed_egress_harness(request).ready()
        current_actual = gate(request).store.egress_harness_result(
            contract_hash, "WSL_SUPERVISOR", WSL_EGRESS_RUNNER_VERSION, RUNNER_IMPLEMENTATION_HASH,
        ) if contract_hash else None
        state["actual_wsl_egress_harness"] = (
            public_harness_result(current_actual) if current_actual else actual_wsl_egress_harness(request).ready()
        )
        state["actual_wsl_egress_harness"]["execution_window"] = actual_wsl_egress_harness_gate(request).window_status()
        state["actual_wsl_egress_harness"]["execution_enabled"] = (
            state["actual_wsl_egress_harness"]["execution_window"].get("status") == "ARMED"
        )
        state["codex_process_canary"] = codex_process_canary_snapshot(request)
        return {
            "models": models,
            "choices": model_choices(models),
            **{
                key: state[key]
                for key in (
                    "codex_path",
                    "codex_version",
                    "schema_path",
                    "schema_error",
                    "workspace_write_available",
                    "workspace_write_schema_ready",
                    "account_usage",
                    "model_catalog",
                    "isolation",
                    "wsl_isolation",
                    "wsl_codex_runtime",
                    "sealed_egress_contract",
                    "sealed_egress_harness",
                    "actual_wsl_egress_harness",
                    "codex_process_canary",
                    "token_ledger",
                )
            },
        }
    except Exception as exc:
        raise as_http_error(exc) from exc


@app.post("/api/isolation/probe")
async def isolation_probe(request: Request):
    try:
        # This endpoint opens a throwaway command/exec-only transport; it never starts a turn.
        return await gate(request).run_isolation_probe()
    except Exception as exc:
        raise as_http_error(exc) from exc


@app.post("/api/isolation/wsl/config")
async def configure_wsl_isolation(payload: WSLIsolationConfigRequest, request: Request):
    try:
        return gate(request).store.save_wsl_isolation_config(payload.distro)
    except Exception as exc:
        raise as_http_error(exc) from exc


@app.get("/api/isolation/wsl/runtime")
async def wsl_codex_runtime_status(request: Request):
    try:
        return public_runtime_result(gate(request).store.wsl_codex_runtime_result())
    except Exception as exc:
        raise as_http_error(exc) from exc


@app.post("/api/isolation/wsl/runtime/config")
async def configure_wsl_codex_runtime(payload: WSLCodexRuntimeConfigRequest, request: Request):
    try:
        return gate(request).store.save_wsl_codex_runtime_config(payload.binary_path)
    except Exception as exc:
        raise as_http_error(exc) from exc


@app.post("/api/isolation/wsl/runtime/preflight")
async def wsl_codex_runtime_preflight(request: Request):
    try:
        # Fixed WSL argv performs binary metadata and --version only; it does not start Codex.
        return public_runtime_result(await wsl_codex_runtime(request).preflight())
    except Exception as exc:
        raise as_http_error(exc) from exc


@app.get("/api/isolation/wsl/egress-contract")
async def sealed_egress_contract_status(request: Request):
    try:
        current = sealed_egress_contract(request).current()
        return public_contract_preview(current) if isinstance(current, dict) and current.get("preview_only") else public_contract_result(current)
    except Exception as exc:
        raise as_http_error(exc) from exc


@app.get("/api/isolation/wsl/egress-contract/preview")
async def sealed_egress_contract_preview(request: Request):
    try:
        return public_contract_preview(sealed_egress_contract(request).preview())
    except Exception as exc:
        raise as_http_error(exc) from exc


@app.post("/api/isolation/wsl/egress-contract")
async def create_sealed_egress_contract(payload: EgressContractCreateRequest, request: Request):
    try:
        # Contract construction is pure local serialization and SQLite storage;
        # it starts neither a relay nor a Codex process.
        return public_contract_result(sealed_egress_contract(request).create(payload.expected_preview_hash))
    except Exception as exc:
        raise as_http_error(exc) from exc


@app.get("/api/isolation/wsl/egress-harness")
async def sealed_egress_harness_status(request: Request):
    try:
        readiness = sealed_egress_harness(request).ready()
        if readiness.get("status") == "READY":
            current = gate(request).store.egress_harness_result(
                readiness["contract_hash"], FAKE_RUNNER_KIND, FAKE_RUNNER_VERSION,
                FAKE_RUNNER_IMPLEMENTATION_HASH,
            )
            return public_harness_result(current) if current else readiness
        return readiness
    except Exception as exc:
        raise as_http_error(exc) from exc


@app.post("/api/isolation/wsl/egress-harness")
async def run_sealed_egress_harness(request: Request):
    try:
        # This legacy endpoint remains the deterministic fake identity only.
        return await sealed_egress_harness(request).run()
    except Exception as exc:
        raise as_http_error(exc) from exc


@app.get("/api/isolation/wsl/egress-harness/actual")
async def actual_wsl_egress_harness_status(request: Request):
    try:
        readiness = actual_wsl_egress_harness(request).ready()
        if readiness.get("status") == "READY":
            current = gate(request).store.egress_harness_result(
                readiness["contract_hash"], "WSL_SUPERVISOR", WSL_EGRESS_RUNNER_VERSION,
                RUNNER_IMPLEMENTATION_HASH,
            )
            result = public_harness_result(current) if current else readiness
        else:
            result = readiness
        window = actual_wsl_egress_harness_gate(request).window_status()
        return {
            **result,
            "execution_window": window,
            "execution_enabled": window.get("status") == "ARMED",
        }
    except Exception as exc:
        raise as_http_error(exc) from exc


@app.post("/api/isolation/wsl/egress-harness/actual/arm")
async def arm_actual_wsl_egress_harness(request: Request):
    rejection = _enforce_execution_window_arm_request(request)
    if rejection is not None:
        return rejection
    try:
        # A local click creates both one-time nonces; neither is stored in
        # plaintext and an app restart expires the window.
        return actual_wsl_egress_harness_gate(request).arm()
    except PolicyError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.post("/api/isolation/wsl/egress-harness/actual")
async def run_actual_wsl_egress_harness(payload: ActualWSLHarnessRequest, request: Request):
    try:
        return await actual_wsl_egress_harness_gate(request).run(payload.window_nonce, payload.arm_nonce)
    except PolicyError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.get("/api/isolation/wsl/codex-process-canary")
async def codex_process_canary_status(request: Request):
    try:
        return codex_process_canary_snapshot(request)
    except Exception as exc:
        raise as_http_error(exc) from exc


@app.post("/api/isolation/wsl/codex-process-canary/arm")
async def arm_codex_process_canary(request: Request):
    rejection = _enforce_execution_window_arm_request(request)
    if rejection is not None:
        return rejection
    try:
        # The production runner is disabled in Phase 4.0, so this endpoint
        # remains fail-closed without starting WSL, Codex, or a network path.
        return await codex_process_canary(request).arm()
    except PolicyError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.post("/api/isolation/wsl/codex-process-canary")
async def run_codex_process_canary(payload: CodexProcessCanaryRequest, request: Request):
    try:
        return await codex_process_canary(request).run(payload.canary_nonce)
    except PolicyError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.post("/api/isolation/wsl/probe")
async def wsl_isolation_probe(request: Request):
    try:
        # This local probe uses only fixed direct WSL/bwrap argv; it never opens app-server.
        return public_wsl_isolation_result(await wsl_isolation(request).probe())
    except Exception as exc:
        raise as_http_error(exc) from exc


@app.get("/api/isolation/wsl/repro")
async def wsl_isolation_repro_status(request: Request):
    try:
        result = gate(request).store.wsl_isolation_repro(
            request.query_params.get("cache_key", "")
        ) if request.query_params.get("cache_key") else None
        return public_repro_result(result)
    except Exception as exc:
        raise as_http_error(exc) from exc


@app.post("/api/isolation/wsl/repro")
async def wsl_isolation_repro(request: Request):
    try:
        # Identity is taken from the sanitized SAFE_CANDIDATE snapshot; the
        # optional body is intentionally ignored to prevent policy overrides.
        result = await wsl_repro(request).run()
        return public_repro_result(result)
    except Exception as exc:
        raise as_http_error(exc) from exc


@app.post("/api/preflight")
async def run_preflight(payload: PreflightRequest, request: Request):
    try:
        root = validate_workspace_root(payload.root)
        models = gate(request).status()["models"]
        return preflight(payload.project_name, root, payload.task, models)
    except Exception as exc:
        raise as_http_error(exc) from exc


@app.post("/api/run")
async def start_run(payload: RunRequest, request: Request):
    try:
        run = await gate(request).start_run(payload.model_dump())
        return run.snapshot()
    except Exception as exc:
        raise as_http_error(exc) from exc


@app.post("/api/route-plans")
async def create_route_plan(payload: RoutePlanRequest, request: Request):
    try:
        return gate(request).create_route_plan(payload.model_dump())
    except Exception as exc:
        raise as_http_error(exc) from exc


@app.post("/api/route-plans/{route_plan_id}/capsule")
async def create_capsule(route_plan_id: str, request: Request):
    try:
        # Capsule creation reads only the Route Plan's sealed evidence scope; it never connects to app-server.
        result = create_evidence_capsule(gate(request).store, route_plan_id)
        return {
            "status": result["status"],
            "total_bytes": result["total_bytes"],
            "file_count": result["file_count"],
            "evidence_fingerprint": result["evidence_fingerprint"],
            "hold_reasons": result["hold_reasons"],
        }
    except Exception as exc:
        raise as_http_error(exc) from exc


@app.post("/api/bridge/tasks")
async def create_bridge_task(payload: BridgeStartRequest, request: Request):
    try:
        # Manual bridge setup is local storage and packet construction only; no app-server request is made.
        return bridge(request).create(payload.model_dump())
    except Exception as exc:
        raise as_http_error(exc) from exc


@app.get("/api/bridge/tasks/recent")
async def recent_bridge_tasks(request: Request):
    try:
        return {"tasks": bridge(request).recent(), "latest": bridge(request).latest()}
    except Exception as exc:
        raise as_http_error(exc) from exc


@app.get("/api/bridge/tasks/{task_id}")
async def read_bridge_task(task_id: str, request: Request):
    try:
        return bridge(request).get(task_id)
    except Exception as exc:
        raise as_http_error(exc) from exc


@app.get("/api/bridge/tasks/{task_id}/packet")
async def bridge_packet(task_id: str, request: Request):
    try:
        return {"packet": bridge(request).packet(task_id)}
    except Exception as exc:
        raise as_http_error(exc) from exc


@app.post("/api/bridge/tasks/{task_id}/copied")
async def bridge_copied(task_id: str, request: Request):
    try:
        return bridge(request).copied(task_id)
    except Exception as exc:
        raise as_http_error(exc) from exc


@app.post("/api/bridge/tasks/{task_id}/import")
async def bridge_import(task_id: str, payload: BridgeImportRequest, request: Request):
    try:
        return bridge(request).import_response(task_id, payload.packet)
    except Exception as exc:
        raise as_http_error(exc) from exc


@app.post("/api/bridge/tasks/{task_id}/review")
async def bridge_review(task_id: str, payload: BridgeReviewRequest, request: Request):
    try:
        return bridge(request).prepare_review(task_id, payload.result, payload.validation)
    except Exception as exc:
        raise as_http_error(exc) from exc


@app.post("/api/bridge/tasks/{task_id}/restart")
async def bridge_restart(task_id: str, request: Request):
    try:
        return bridge(request).restart(task_id)
    except Exception as exc:
        raise as_http_error(exc) from exc


@app.post("/api/bridge/tasks/{task_id}/evidence/{request_id}/map")
async def map_bridge_evidence(task_id: str, request_id: str, payload: EvidenceMapRequest, request: Request):
    try:
        options = {key: value for key, value in payload.model_dump().items() if key != "path" and value is not None}
        return bridge(request).map_evidence(task_id, request_id, payload.path, options)
    except Exception as exc:
        raise as_http_error(exc) from exc


@app.post("/api/bridge/tasks/{task_id}/evidence/{request_id}/collect")
async def collect_bridge_evidence(task_id: str, request_id: str, request: Request):
    try:
        # Local bounded collector only: no shell command or app-server RPC is reachable here.
        return bridge(request).collect_evidence(task_id, request_id)
    except Exception as exc:
        raise as_http_error(exc) from exc


@app.get("/api/catalog/sources")
async def list_catalog_sources(request: Request):
    try:
        return {"sources": catalog(request).sources()}
    except Exception as exc:
        raise as_http_error(exc) from exc


@app.post("/api/catalog/sources")
async def register_catalog_source(payload: CatalogSourceRequest, request: Request):
    try:
        # Registration records a local root only in SQLite; public responses use its alias.
        return catalog(request).register_source(payload.alias, payload.root)
    except Exception as exc:
        raise as_http_error(exc) from exc


@app.post("/api/catalog/sources/{source_id}/scan")
async def scan_catalog_source(source_id: str, payload: CatalogScanRequest, request: Request):
    try:
        # scandir/stat metadata only; this path cannot reach app-server or a model turn.
        scan = await asyncio.to_thread(catalog(request).scan, source_id, max_files=payload.max_files)
        try:
            gate(request).store.record_ledger_usage_event({
                "source_event_id": f"catalog:{source_id}:{scan.get('scan_id')}:{scan.get('generation')}",
                "source": "LOCAL_ESTIMATE",
                "quality": "OBSERVED",
                "event_type": "catalog_scan",
                "task_id": source_id,
                "comparison_key": f"catalog:{source_id}",
                "source_bytes": int(scan.get("metrics", {}).get("bytes_indexed", 0)),
                "catalog_source_bytes": int(scan.get("metrics", {}).get("bytes_indexed", 0)),
                "occurred_at": scan.get("finished_at") or None,
            })
        except Exception:
            pass
        return scan
    except Exception as exc:
        raise as_http_error(exc) from exc


@app.post("/api/catalog/sources/{source_id}/resume")
async def resume_catalog_source(source_id: str, payload: CatalogScanRequest, request: Request):
    try:
        scan = await asyncio.to_thread(catalog(request).scan, source_id, resume=True, max_files=payload.max_files)
        try:
            gate(request).store.record_ledger_usage_event({
                "source_event_id": f"catalog:{source_id}:{scan.get('scan_id')}:{scan.get('generation')}:resume",
                "source": "LOCAL_ESTIMATE",
                "quality": "OBSERVED",
                "event_type": "catalog_scan",
                "task_id": source_id,
                "comparison_key": f"catalog:{source_id}",
                "source_bytes": int(scan.get("metrics", {}).get("bytes_indexed", 0)),
                "catalog_source_bytes": int(scan.get("metrics", {}).get("bytes_indexed", 0)),
                "occurred_at": scan.get("finished_at") or None,
            })
        except Exception:
            pass
        return scan
    except Exception as exc:
        raise as_http_error(exc) from exc


@app.post("/api/catalog/sources/{source_id}/cancel")
async def cancel_catalog_source(source_id: str, request: Request):
    try:
        return catalog(request).cancel(source_id)
    except Exception as exc:
        raise as_http_error(exc) from exc


@app.get("/api/catalog/sources/{source_id}/entries")
async def list_catalog_entries(
    source_id: str,
    request: Request,
    status: str | None = None,
    asset_kind: str | None = None,
    extension: str | None = None,
    min_size: int | None = Query(default=None, ge=0),
    max_size: int | None = Query(default=None, ge=0),
):
    try:
        if min_size is not None and max_size is not None and min_size > max_size:
            raise PolicyError("min_size cannot exceed max_size")
        return {"entries": catalog(request).entries(source_id, status=status, asset_kind=asset_kind, extension=extension, min_size=min_size, max_size=max_size)}
    except Exception as exc:
        raise as_http_error(exc) from exc


@app.post("/api/format-probes")
async def run_format_probe(payload: FormatProbeRequest, request: Request):
    try:
        # Targeted header sampling only: no app-server RPC, no model turn, and no whole-file parsing.
        results = await asyncio.to_thread(format_probe(request).probe, payload.catalog_entry_ids)
        store = gate(request).store
        if results:
            try:
                store.record_ledger_usage_event({
                    "source_event_id": f"probe:{results[0].get('probe_id') or '-'}:{len(results)}",
                    "source": "LOCAL_ESTIMATE",
                    "quality": "OBSERVED",
                    "event_type": "format_probe",
                    "comparison_key": f"probe:{results[0].get('alias') or 'catalog'}",
                    "probe_bytes": sum(int(item.get("bytes_read", 0)) for item in results),
                    "occurred_at": results[0].get("updated_at") or results[0].get("created_at") or None,
                })
            except Exception:
                pass
        return {"results": results}
    except Exception as exc:
        raise as_http_error(exc) from exc


@app.post("/api/router/preview")
async def router_preview(payload: RouterPreviewRequest, request: Request):
    try:
        store = gate(request).store
        account_usage = store.account_overview()
        return route_preview(
            store.router_models(),
            task_class=payload.task_class,
            risk=payload.risk,
            read_only=payload.read_only,
            file_count=payload.file_count,
            has_tests=payload.has_tests,
            web_recommendation=payload.web_recommendation,
            account_state=account_usage["account_state"],
            account_usage=account_usage,
            parallel_audit=payload.parallel_audit,
            independent_axes=payload.independent_axes,
            explicit_ultra_approval=payload.explicit_ultra_approval,
        )
    except Exception as exc:
        raise as_http_error(exc) from exc


@app.get("/api/token-ledger/report")
async def token_ledger_report(request: Request):
    try:
        return gate(request).store.token_ledger_report()
    except Exception as exc:
        raise as_http_error(exc) from exc


@app.post("/api/token-ledger/baselines")
async def import_token_ledger_baseline(request: Request):
    try:
        body = await request.body()
        if len(body) > 64 * 1024:
            raise PolicyError("Token ledger baseline import exceeds 64KB")
        payload = json.loads(body.decode("utf-8"))
        store = gate(request).store
        baseline = store.record_ledger_baseline(payload)
        return {"baseline": baseline, "token_ledger": store.token_ledger_report()}
    except Exception as exc:
        raise as_http_error(exc) from exc


@app.get("/api/token-ledger/export")
async def export_token_ledger(request: Request, format: str = "json"):
    try:
        store = gate(request).store
        data = store.export_token_ledger_report(format)
        if format == "markdown":
            return PlainTextResponse(data)
        return JSONResponse(content=json.loads(data))
    except Exception as exc:
        raise as_http_error(exc) from exc


@app.post("/api/models/{model_id}/status")
async def set_model_status(model_id: str, payload: ModelStatusRequest, request: Request):
    try:
        store = gate(request).store
        store.set_model_status(model_id, payload.status)
        return {"model_catalog": store.model_catalog()}
    except Exception as exc:
        raise as_http_error(exc) from exc


@app.post("/api/account/thresholds")
async def set_usage_thresholds(payload: UsageThresholdRequest, request: Request):
    try:
        store = gate(request).store
        thresholds = store.set_usage_thresholds(payload.model_dump())
        return {"thresholds": thresholds, "account_usage": store.account_overview()}
    except Exception as exc:
        raise as_http_error(exc) from exc


@app.get("/api/runs/{run_id}")
async def read_run(run_id: str, request: Request):
    try:
        return gate(request).snapshot(run_id)
    except Exception as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/api/runs/{run_id}/interrupt")
async def interrupt(run_id: str, request: Request):
    try:
        await gate(request).interrupt(run_id)
        return gate(request).snapshot(run_id)
    except Exception as exc:
        raise as_http_error(exc) from exc


@app.post("/api/runs/{run_id}/approvals/{request_id}")
async def resolve_approval(run_id: str, request_id: str, payload: ApprovalResponseRequest, request: Request):
    try:
        return await gate(request).resolve_approval(run_id, request_id, payload.decision, payload.permissions)
    except Exception as exc:
        raise as_http_error(exc) from exc


@app.get("/api/events/{run_id}")
async def events(run_id: str, request: Request):
    try:
        run = gate(request)._run(run_id)
    except Exception as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    async def stream():
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        run.subscribers.add(queue)
        try:
            yield f"event: run\ndata: {json.dumps(run.snapshot(), ensure_ascii=False)}\n\n"
            while True:
                event = await queue.get()
                yield f"event: {event['event']}\ndata: {json.dumps(event['data'], ensure_ascii=False)}\n\n"
        finally:
            run.subscribers.discard(queue)

    return StreamingResponse(stream(), media_type="text/event-stream")
