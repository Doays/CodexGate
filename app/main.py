from __future__ import annotations

import asyncio
import json
import os
from contextlib import asynccontextmanager
from urllib.parse import urlsplit
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field, field_validator

from .gateway import Gate
from .indexer import preflight
from .policy import PolicyError, model_choices, validate_project_id, validate_workspace_root
from .storage import Store


ROOT = Path(__file__).resolve().parent
DATA_ROOT = Path(os.environ.get("CODEX_GATE_HOME", str(Path.home() / "CodexGate")))
ALLOWED_LOCAL_HOSTS = {"127.0.0.1", "localhost"}


class PreflightRequest(BaseModel):
    project_name: str = Field(min_length=1, max_length=120)
    root: str = Field(min_length=1)
    task: str = Field(min_length=3, max_length=12_000)


class RunRequest(PreflightRequest):
    project_id: str = Field(min_length=1, max_length=80)
    decision: dict[str, Any]
    model: str = Field(min_length=1)
    effort: str = Field(min_length=1)
    permission: str
    budget_level: str

    @field_validator("project_id")
    @classmethod
    def validate_project_id_field(cls, value: str) -> str:
        return validate_project_id(value)


class ApprovalResponseRequest(BaseModel):
    decision: str = Field(pattern="^(accept|acceptForSession|decline|cancel)$")
    permissions: dict[str, Any] | None = None


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


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.gate = Gate(Store(DATA_ROOT))
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


def as_http_error(error: Exception) -> HTTPException:
    return HTTPException(status_code=400, detail=str(error))


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse(request, "index.html", {"data_root": str(DATA_ROOT)})


@app.get("/api/status")
async def status(request: Request):
    state = gate(request).status()
    state["choices"] = model_choices(state["models"])
    return state


@app.post("/api/connect")
async def connect(request: Request):
    try:
        models = await gate(request).connect()
        state = gate(request).status()
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
                )
            },
        }
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
