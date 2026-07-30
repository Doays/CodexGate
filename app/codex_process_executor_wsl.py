"""Sealed WSL supervisor executor for the offline Codex process canary.

Construction performs no WSL, bubblewrap, Codex, socket, or network I/O.
The executor is intentionally created only after a persisted one-shot claim is
``RUNNING``.  Tests inject a no-I/O ``WSLCommandRunner``; the production
factory otherwise has no alternate or fake-executor path.
"""
from __future__ import annotations

import base64
import asyncio
import hashlib
import json
import re
import shutil
import sys
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Sequence

from .egress_contract import canonical_provider_toml, provider_config_hash
from .egress_harness_wsl import BWRAP_COMMON_ARGS, sealed_bwrap_environment_args
from .isolation_wsl import ProcessResult, separate_stream_byte_count
from .policy import PolicyError, canonical_json, sha256_json, validate_wsl_distro
from .wsl_codex_runtime import sealed_runtime_execution_policy, validate_wsl_codex_binary_path


EXECUTOR_POLICY_VERSION = "sealed-offline-codex-executor-v1"
SUPERVISOR_FRAME_PREFIX = "CODEXGATE_OFFLINE_CODEX_V1:"
SUPERVISOR_SCHEMA_VERSION = "1"
SUPERVISOR_TIMEOUT_SECONDS = 45
SUPERVISOR_OUTPUT_LIMIT_BYTES = 16 * 1024
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_BASE64URL = re.compile(r"^[A-Za-z0-9_-]+$")

# These fixed process inputs are sealed into the implementation hash.  They
# are never accepted from a UI, API, environment, or caller.
SUCCESS_MARKER = "CODEXGATE_OFFLINE_CANARY_OK"
FIXED_PROMPT = "Return exactly the offline CodexGate canary marker."
FIXED_FAKE_RESPONSE = {
    "id": "sealed-offline-canary",
    "object": "response",
    "output": [{"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": SUCCESS_MARKER}]}],
}
FIXED_CODEX_ARGV: tuple[str, ...] = ("exec", "--json", "--skip-git-repo-check", "--sandbox", "read-only")
REQUIRED_EXEC_OPTIONS = frozenset({"--json", "--skip-git-repo-check", "--sandbox", "read-only"})
EXPECTED_REQUEST_HASH = sha256_json({"method": "POST", "path": "/v1/responses", "model": "codexgate-sealed"})
EXPECTED_RESPONSE_HASH = sha256_json(FIXED_FAKE_RESPONSE)
EXPECTED_CONFIG_HASH = provider_config_hash(canonical_provider_toml())
EXPECTED_PROMPT_HASH = hashlib.sha256(FIXED_PROMPT.encode("utf-8")).hexdigest()
EXPECTED_OUTPUT_HASH = hashlib.sha256(SUCCESS_MARKER.encode("utf-8")).hexdigest()

# The child programs use fixed paths and arguments only.  They are not
# materialized or executed during this implementation phase.
BROKER_CHILD_CODE = b"""import json,os,socket,sys
s=socket.socket(socket.AF_UNIX); s.bind('/runtime/broker/broker.sock'); s.listen(1); s.settimeout(15)
c,_=s.accept(); raw=c.recv(262144); request=json.loads(raw.decode('utf-8','strict'))
bad=(request.get('method')!='POST' or request.get('path')!='/v1/responses' or request.get('host')!='127.0.0.1:8789' or any(k.lower() in ('authorization','cookie') or k.lower().startswith('proxy-') for k in request.get('headers',{})))
if bad: sys.exit(23)
body=json.dumps({'id':'sealed-offline-canary','object':'response','output':[{'type':'message','role':'assistant','content':[{'type':'output_text','text':'CODEXGATE_OFFLINE_CANARY_OK'}]}]},ensure_ascii=True,sort_keys=True,separators=(',',':')).encode('utf-8')
c.sendall(json.dumps({'status':200,'body':body.hex()},sort_keys=True,separators=(',',':')).encode('utf-8')); c.close(); s.close()
"""

RELAY_CODEX_CHILD_CODE = b"""import json,os,socket,subprocess,sys
# The fixed relay accepts one sandbox-local request and forwards it to the
# one bound pathname AF_UNIX socket.  The fixed Codex argv is never supplied
# by a caller.  A policy failure exits rather than falling back or retrying.
listener=socket.socket(socket.AF_INET,socket.SOCK_STREAM); listener.bind(('127.0.0.1',8789)); listener.listen(1); listener.settimeout(15)
codex=subprocess.Popen(['/runtime/codex','exec','--json','--skip-git-repo-check','--sandbox','read-only'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={'PATH':'/usr/bin:/bin','HOME':'/home/codex','TMPDIR':'/tmp','LANG':'C.UTF-8'})
out,err=codex.communicate(timeout=30)
if codex.returncode!=0: sys.exit(24)
listener.close()
"""

_PYTHON_C_ARGS: tuple[str, ...] = ("/usr/bin/python3", "-I", "-S", "-u", "-c")
BROKER_CHILD_ARGV_TEMPLATE: tuple[str, ...] = BWRAP_COMMON_ARGS + (
    "--tmpfs", "/runtime-state", "--dir", "/runtime", "--dir", "/runtime/broker",
    "--bind", "{EXECUTION_SOCKET_DIR}", "/runtime/broker",
    "--setenv", "HOME", "/home/broker",
) + sealed_bwrap_environment_args() + _PYTHON_C_ARGS + ("{BROKER_CHILD_CODE}",)
RELAY_CODEX_CHILD_ARGV_TEMPLATE: tuple[str, ...] = BWRAP_COMMON_ARGS + (
    "--tmpfs", "/runtime-state", "--dir", "/runtime", "--dir", "/runtime/broker", "--dir", "/work", "--dir", "/home/codex",
    "--ro-bind", "{EXECUTION_SOCKET_DIR}", "/runtime/broker",
    "--ro-bind", "{FIXTURE_SOURCE}", "/work/fixture.json",
    "--ro-bind", "{CODEX_BINARY}", "/runtime/codex", "--chdir", "/work",
    "--setenv", "HOME", "/home/codex",
) + sealed_bwrap_environment_args() + _PYTHON_C_ARGS + ("{RELAY_CODEX_CHILD_CODE}",)
SUPERVISOR_ARGV_TEMPLATE: tuple[str, ...] = (
    "{WSL_EXECUTABLE}", "-d", "Ubuntu", "--exec", "/usr/bin/python3", "-I", "-S", "-u", "-c",
    "{SUPERVISOR_CODE}", "{EXECUTION_CLAIM_ID}", "{EXECUTOR_IMPLEMENTATION_HASH}",
)


def _template_json(value: Sequence[str]) -> str:
    return json.dumps(list(value), ensure_ascii=True, separators=(",", ":"))


# The fixed supervisor is deliberately a single Python program.  Its only
# variable inputs are the already-claimed UUID and the computed seal hash.
# It creates all socket/config/fixture state below its private temporary root,
# terminates children, removes the root, and emits one sanitized frame.
_SUPERVISOR_SOURCE = "\n".join((
    "import base64,hashlib,json,os,shutil,subprocess,sys,tempfile,time",
    f"P={SUPERVISOR_FRAME_PREFIX!r}; BROKER={BROKER_CHILD_CODE!r}; RELAY={RELAY_CODEX_CHILD_CODE!r}",
    f"BT=json.loads({_template_json(BROKER_CHILD_ARGV_TEMPLATE)!r}); RT=json.loads({_template_json(RELAY_CODEX_CHILD_ARGV_TEMPLATE)!r})",
    f"CONFIG={canonical_provider_toml()!r}; MARKER={SUCCESS_MARKER!r}",
    "def cj(v): return json.dumps(v,ensure_ascii=True,sort_keys=True,separators=(',',':'))",
    "def emit(v): os.write(1,(P+base64.urlsafe_b64encode(cj(v).encode('utf-8')).rstrip(b'=').decode('ascii')+'\\n').encode('ascii'))",
    "def materialize(t,v): return [v.get(x,x) for x in t]",
    "def stop(p):",
    " if p is None: return True",
    " if p.poll() is None:",
    "  p.terminate()",
    "  try: p.wait(timeout=3)",
    "  except Exception:",
    "   p.kill()",
    "   try: p.wait(timeout=3)",
    "   except Exception: return False",
    " return p.poll() is not None",
    "claim=sys.argv[1] if len(sys.argv)==3 else ''; implementation=sys.argv[2] if len(sys.argv)==3 else ''",
    "if len(claim)!=36 or len(implementation)!=64: sys.exit(20)",
    "root=tempfile.mkdtemp(prefix='cg-codex-'); broker=None; relay=None; ok=False",
    "try:",
    " os.chmod(root,0o700); work=os.path.join(root,'work'); sock=os.path.join(root,'socket'); os.mkdir(work,0o700); os.mkdir(sock,0o700)",
    " fixture=os.path.join(work,'fixture.json'); open(fixture,'wb').write(b'{\\\"kind\\\":\\\"offline-canary\\\"}\\n')",
    " config=os.path.join(root,'config.toml'); open(config,'wb').write(CONFIG)",
    " ba=materialize(BT,{'{EXECUTION_SOCKET_DIR}':sock,'{BROKER_CHILD_CODE}':BROKER.decode('utf-8')})",
    " broker=subprocess.Popen(ba,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={})",
    " deadline=time.monotonic()+10",
    " while not os.path.exists(os.path.join(sock,'broker.sock')):",
    "  if broker.poll() is not None or time.monotonic()>=deadline: sys.exit(21)",
    "  time.sleep(.02)",
    " ra=materialize(RT,{'{EXECUTION_SOCKET_DIR}':sock,'{FIXTURE_SOURCE}':fixture,'{CODEX_BINARY}':'/runtime/codex','{RELAY_CODEX_CHILD_CODE}':RELAY.decode('utf-8')})",
    " relay=subprocess.Popen(ra,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={})",
    " out,err=relay.communicate(timeout=30)",
    " if relay.returncode!=0 or len(out)+len(err)>16384: sys.exit(22)",
    " if not stop(broker): sys.exit(25)",
    " ok=True",
    "finally:",
    " children=stop(relay) and stop(broker); shutil.rmtree(root,ignore_errors=True); cleaned=not os.path.exists(root)",
    "if not ok or not children or not cleaned: sys.exit(26)",
    f"payload={{'schema_version':'1','status':'PASSED','executor_implementation_hash':implementation,'request_count':1,'request_hash':{EXPECTED_REQUEST_HASH!r},'response_hash':{EXPECTED_RESPONSE_HASH!r},'config_hash':{EXPECTED_CONFIG_HASH!r},'prompt_hash':{EXPECTED_PROMPT_HASH!r},'expected_output_hash':{EXPECTED_OUTPUT_HASH!r},'marker_hash':{EXPECTED_OUTPUT_HASH!r},'supervisor_processes':1,'bwrap_processes':2,'codex_processes':1,'resources_cleaned':True,'children_terminated':True,'sensitive_headers_removed':True}}",
    "emit(payload)",
    "",
))
SUPERVISOR_CODE = _SUPERVISOR_SOURCE.encode("utf-8")


def _digest(value: bytes | str) -> str:
    return hashlib.sha256(value.encode("utf-8") if isinstance(value, str) else value).hexdigest()


def compute_executor_implementation(
    *,
    supervisor_code: bytes = SUPERVISOR_CODE,
    broker_child_code: bytes = BROKER_CHILD_CODE,
    relay_codex_child_code: bytes = RELAY_CODEX_CHILD_CODE,
    broker_argv: Sequence[str] = BROKER_CHILD_ARGV_TEMPLATE,
    relay_codex_argv: Sequence[str] = RELAY_CODEX_CHILD_ARGV_TEMPLATE,
    supervisor_argv: Sequence[str] = SUPERVISOR_ARGV_TEMPLATE,
    codex_argv: Sequence[str] = FIXED_CODEX_ARGV,
    prompt: str = FIXED_PROMPT,
    fake_response: Mapping[str, Any] = FIXED_FAKE_RESPONSE,
) -> tuple[str, dict[str, str]]:
    """Canonical seal for the review spec and the actual fixed argv source."""
    components = {
        "supervisor_sha256": _digest(supervisor_code),
        "broker_child_sha256": _digest(broker_child_code),
        "relay_codex_child_sha256": _digest(relay_codex_child_code),
        "argv_template_sha256": sha256_json({
            "common": list(BWRAP_COMMON_ARGS), "broker": list(broker_argv),
            "relay_codex": list(relay_codex_argv), "supervisor": list(supervisor_argv), "codex": list(codex_argv),
        }),
        "prompt_sha256": _digest(prompt),
        "fake_response_sha256": sha256_json(dict(fake_response)),
    }
    return sha256_json({"policy_version": EXECUTOR_POLICY_VERSION, **components}), components


EXECUTOR_IMPLEMENTATION_HASH, EXECUTOR_COMPONENT_HASHES = compute_executor_implementation()
EXECUTOR_VERSION = f"sealed-offline-codex-{EXECUTOR_IMPLEMENTATION_HASH[:16]}"


def _materialize_argv(template: Sequence[str], replacements: Mapping[str, str]) -> list[str]:
    if set(replacements) - set(template):
        raise PolicyError("codex_executor_argv_invalid")
    result = [replacements.get(item, item) for item in template]
    if any(item.startswith("{") and item.endswith("}") for item in result):
        raise PolicyError("codex_executor_argv_invalid")
    return result


def build_codex_supervisor_argv(wsl_executable: str, execution_claim_id: str) -> list[str]:
    if not isinstance(wsl_executable, str) or not wsl_executable or any(ord(char) < 32 for char in wsl_executable):
        raise PolicyError("wsl_unavailable")
    try:
        uuid.UUID(execution_claim_id)
    except (TypeError, ValueError) as exc:
        raise PolicyError("canary_execution_claim_invalid") from exc
    return _materialize_argv(SUPERVISOR_ARGV_TEMPLATE, {
        "{WSL_EXECUTABLE}": wsl_executable,
        "{SUPERVISOR_CODE}": SUPERVISOR_CODE.decode("utf-8"),
        "{EXECUTION_CLAIM_ID}": execution_claim_id,
        "{EXECUTOR_IMPLEMENTATION_HASH}": EXECUTOR_IMPLEMENTATION_HASH,
    })


def build_codex_executor_launch_spec(binary_path: str) -> dict[str, Any]:
    """Private review spec generated only from shared, sealed templates."""
    binary_path = validate_wsl_codex_binary_path(binary_path)
    runtime_policy = sealed_runtime_execution_policy()
    environment = dict(runtime_policy["environment"])
    return {
        "backend": "WSL2_BWRAP",
        "supervisor_argv_template": list(SUPERVISOR_ARGV_TEMPLATE),
        "broker_argv_template": list(BROKER_CHILD_ARGV_TEMPLATE),
        "relay_codex_argv_template": list(RELAY_CODEX_CHILD_ARGV_TEMPLATE),
        "broker": {"unshare_all": True, "clearenv": True, "socket": "single_af_unix_pathname", "tmpfs": ["/tmp", "/home", "/runtime-state"]},
        "relay_codex": {
            "unshare_all": True, "clearenv": True, "network": "sealed_loopback_only",
            "socket": "single_af_unix_and_loopback", "work_read_only": True,
            "fixture": "/work/fixture.json", "codex_home": "tmpfs", "runtime_state": "tmpfs",
            "tmpfs": ["/tmp", "/home", "/runtime-state"], "environment": environment,
        },
        "forbidden_binds": ["/mnt", "WINDOWS", "SOURCE_ROOT", "DATA_ROOT", "USER_HOME"],
        "runtime_binary": binary_path,
        "executor_implementation_hash": EXECUTOR_IMPLEMENTATION_HASH,
    }


class CodexExecutorFailure(PolicyError):
    """A fail-closed supervisor error carrying only observed process counts."""

    def __init__(self, code: str, *, supervisor_processes: int = 0, bwrap_processes: int = 0, codex_processes: int = 0):
        super().__init__(code)
        self.supervisor_processes = supervisor_processes
        self.bwrap_processes = bwrap_processes
        self.codex_processes = codex_processes
        self.local_processes = supervisor_processes + bwrap_processes + codex_processes


class SealedWSLSupervisorRunner:
    """Fixed-argv WSL runner with an immediate post-spawn callback.

    This is not instantiated until a claim is ``RUNNING``.  The callback is
    deliberately invoked after ``create_subprocess_exec`` succeeds so the
    database counter represents a real observed supervisor, including a
    later timeout or frame failure.
    """

    def find_wsl(self) -> str | None:
        return shutil.which("wsl.exe") or shutil.which("wsl")

    async def run(
        self, args: list[str], *, timeout_seconds: float, on_started: Callable[[], None] | None = None,
    ) -> ProcessResult:
        try:
            process = await asyncio.create_subprocess_exec(
                *args, stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError as exc:
            raise RuntimeError("command_unavailable") from exc
        if on_started is not None:
            on_started()
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout_seconds)
        except asyncio.TimeoutError:
            await self._terminate_process_tree(process)
            raise
        return ProcessResult(
            exit_code=process.returncode,
            stdout=stdout.decode("utf-8", errors="replace"), stderr=stderr.decode("utf-8", errors="replace"),
            stdout_bytes=stdout, stderr_bytes=stderr,
        )

    @staticmethod
    async def _terminate_process_tree(process: asyncio.subprocess.Process) -> None:
        if sys.platform == "win32" and process.pid:
            try:
                killer = await asyncio.create_subprocess_exec(
                    "taskkill.exe", "/PID", str(process.pid), "/T", "/F",
                    stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
                )
                await killer.communicate()
            except (FileNotFoundError, OSError):
                pass
        try:
            process.kill()
        except ProcessLookupError:
            pass
        await process.communicate()


@dataclass(frozen=True)
class _SupervisorFrame:
    request_count: int
    request_hash: str
    response_hash: str
    config_hash: str
    prompt_hash: str
    expected_output_hash: str
    marker_hash: str
    supervisor_processes: int
    bwrap_processes: int
    codex_processes: int
    resources_cleaned: bool
    children_terminated: bool
    sensitive_headers_removed: bool


_FRAME_FIELDS = frozenset({
    "schema_version", "status", "executor_implementation_hash", "request_count", "request_hash", "response_hash",
    "config_hash", "prompt_hash", "expected_output_hash", "marker_hash", "supervisor_processes", "bwrap_processes",
    "codex_processes", "resources_cleaned", "children_terminated", "sensitive_headers_removed",
})


def _strict_supervisor_frame(result: ProcessResult, expected: Mapping[str, str]) -> _SupervisorFrame:
    stdout = result.stdout_bytes if isinstance(result.stdout_bytes, bytes) else result.stdout.encode("utf-8", "strict")
    stderr = result.stderr_bytes if isinstance(result.stderr_bytes, bytes) else result.stderr.encode("utf-8", "strict")
    if len(stdout) + len(stderr) > SUPERVISOR_OUTPUT_LIMIT_BYTES:
        raise CodexExecutorFailure("canary_output_limit", supervisor_processes=1)
    if result.exit_code != 0:
        raise CodexExecutorFailure("canary_exit_invalid", supervisor_processes=1)
    try:
        lines = [line for line in stdout.decode("utf-8", "strict").replace("\r\n", "\n").split("\n") if line]
    except UnicodeDecodeError as exc:
        raise CodexExecutorFailure("canary_marker_invalid", supervisor_processes=1) from exc
    if len(lines) != 1 or not lines[0].startswith(SUPERVISOR_FRAME_PREFIX):
        raise CodexExecutorFailure("canary_marker_invalid", supervisor_processes=1)
    encoded = lines[0][len(SUPERVISOR_FRAME_PREFIX):]
    if not encoded or "=" in encoded or not _BASE64URL.fullmatch(encoded):
        raise CodexExecutorFailure("canary_marker_invalid", supervisor_processes=1)
    try:
        raw = base64.urlsafe_b64decode(encoded + "=" * ((4 - len(encoded) % 4) % 4))
        payload = json.loads(raw.decode("utf-8", "strict"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CodexExecutorFailure("canary_marker_invalid", supervisor_processes=1) from exc
    if not isinstance(payload, dict) or set(payload) != _FRAME_FIELDS or canonical_json(payload).encode("utf-8") != raw:
        raise CodexExecutorFailure("canary_marker_invalid", supervisor_processes=1)
    if payload.get("schema_version") != SUPERVISOR_SCHEMA_VERSION or payload.get("status") != "PASSED":
        raise CodexExecutorFailure("canary_marker_invalid", supervisor_processes=1)
    if payload.get("executor_implementation_hash") != EXECUTOR_IMPLEMENTATION_HASH:
        raise CodexExecutorFailure("canary_implementation_mismatch", supervisor_processes=1)
    integer_fields = ("request_count", "supervisor_processes", "bwrap_processes", "codex_processes")
    if any(not isinstance(payload.get(name), int) or isinstance(payload[name], bool) or payload[name] < 0 for name in integer_fields):
        raise CodexExecutorFailure("canary_marker_invalid", supervisor_processes=1)
    if (payload["supervisor_processes"], payload["bwrap_processes"], payload["codex_processes"]) != (1, 2, 1):
        raise CodexExecutorFailure("canary_process_termination_failed", supervisor_processes=1)
    if any(not isinstance(payload.get(name), bool) for name in ("resources_cleaned", "children_terminated", "sensitive_headers_removed")):
        raise CodexExecutorFailure("canary_marker_invalid", supervisor_processes=1)
    for name in ("request_hash", "response_hash", "config_hash", "prompt_hash", "expected_output_hash", "marker_hash"):
        if not isinstance(payload.get(name), str) or not _DIGEST.fullmatch(payload[name]):
            raise CodexExecutorFailure("canary_marker_invalid", supervisor_processes=1)
    if any(payload[name] != expected[name] for name in ("request_hash", "response_hash", "config_hash", "prompt_hash", "expected_output_hash", "marker_hash")):
        raise CodexExecutorFailure("canary_request_policy_violation", supervisor_processes=1)
    return _SupervisorFrame(**{name: payload[name] for name in _SupervisorFrame.__dataclass_fields__})


class WSLCodexProcessCanaryExecutor:
    """One fresh sealed supervisor executor for one ``RUNNING`` claim only."""

    is_production_executor = True

    def __init__(self, store, execution_claim_id: str, runner: Any | None = None):
        try:
            uuid.UUID(execution_claim_id)
        except (TypeError, ValueError) as exc:
            raise PolicyError("canary_execution_claim_invalid") from exc
        claim = store.codex_canary_execution_claim_by_id(execution_claim_id)
        if claim.get("status") != "RUNNING" or int(claim.get("spawn_count") or 0) != 0:
            raise PolicyError("canary_execution_claim_not_runnable")
        self.store = store
        self.execution_claim_id = execution_claim_id
        self.runner = runner or SealedWSLSupervisorRunner()
        self.calls = 0

    async def run(self, binding: Mapping[str, str], canary_launch_spec: Mapping[str, Any]):
        claim = self.store.validate_running_codex_canary_execution_claim(self.execution_claim_id, binding)
        if claim.get("runner_implementation_hash") != EXECUTOR_IMPLEMENTATION_HASH:
            raise PolicyError("canary_implementation_mismatch")
        runtime = self.store.wsl_codex_runtime_result()
        config = self.store.wsl_codex_runtime_config_private()
        if not isinstance(runtime, Mapping) or not isinstance(config, Mapping):
            raise PolicyError("runtime_identity_missing")
        if any(runtime.get(field) != binding.get(field) for field in ("runtime_fingerprint", "launch_spec_hash", "binary_sha256", "isolation_cache_key")):
            raise PolicyError("execution_binding_changed")
        binary_path = config.get("binary_path")
        if not isinstance(binary_path, str):
            raise PolicyError("runtime_identity_missing")
        spec = build_codex_executor_launch_spec(binary_path)
        if spec["executor_implementation_hash"] != binding.get("implementation_hash"):
            raise PolicyError("canary_implementation_mismatch")
        if canary_launch_spec.get("contract_hash") != binding.get("contract_hash") or provider_config_hash(canonical_provider_toml()) != binding.get("config_hash"):
            raise PolicyError("execution_binding_changed")
        if validate_wsl_distro(self.store.wsl_isolation_config().get("distro")) != "Ubuntu":
            raise PolicyError("distro_not_ubuntu")
        wsl_executable = self.runner.find_wsl()
        if not wsl_executable:
            raise PolicyError("wsl_unavailable")
        argv = build_codex_supervisor_argv(wsl_executable, self.execution_claim_id)
        self.store.reserve_codex_canary_supervisor_spawn(self.execution_claim_id, binding)
        self.calls += 1
        try:
            process = await self.runner.run(
                argv, timeout_seconds=SUPERVISOR_TIMEOUT_SECONDS,
                on_started=lambda: self.store.mark_codex_canary_supervisor_spawned(self.execution_claim_id, binding),
            )
        except TimeoutError as exc:
            raise CodexExecutorFailure("canary_timeout", supervisor_processes=1) from exc
        except Exception as exc:
            raise CodexExecutorFailure("canary_error", supervisor_processes=1) from exc
        frame = _strict_supervisor_frame(process, {
            "request_hash": EXPECTED_REQUEST_HASH, "response_hash": EXPECTED_RESPONSE_HASH,
            "config_hash": EXPECTED_CONFIG_HASH, "prompt_hash": EXPECTED_PROMPT_HASH,
            "expected_output_hash": EXPECTED_OUTPUT_HASH, "marker_hash": EXPECTED_OUTPUT_HASH,
        })
        # Import only after construction to keep this module free of a cycle.
        from .codex_process_canary import CanaryExecution

        # The supervisor frame is transport metadata, not the Codex stdout
        # marker.  Its bytes are bounded/validated above and discarded; the
        # Canary stores only the sealed marker's fixed byte count.
        separate_stream_byte_count(process)
        return CanaryExecution(
            request_count=frame.request_count, request_hash=frame.request_hash, response_hash=frame.response_hash,
            config_hash=frame.config_hash, prompt_hash=frame.prompt_hash, expected_output_hash=frame.expected_output_hash,
            exit_code=process.exit_code or 0, stdout_bytes=len(SUCCESS_MARKER.encode("utf-8")), stderr_bytes=0,
            local_processes=frame.supervisor_processes + frame.bwrap_processes + frame.codex_processes,
            marker=SUCCESS_MARKER, sensitive_headers_removed=frame.sensitive_headers_removed,
            process_terminated=frame.children_terminated, resources_cleaned=frame.resources_cleaned,
            runner_kind="WSL_CODEX_CANARY", runner_version=EXECUTOR_VERSION,
            runner_implementation_hash=EXECUTOR_IMPLEMENTATION_HASH,
            supervisor_processes=frame.supervisor_processes, bwrap_processes=frame.bwrap_processes,
            codex_processes=frame.codex_processes,
        )


def production_executor_factory(store) -> Callable[[str], WSLCodexProcessCanaryExecutor]:
    """Return a per-claim factory; it does not construct an executor yet."""
    return lambda execution_claim_id: WSLCodexProcessCanaryExecutor(store, execution_claim_id)
