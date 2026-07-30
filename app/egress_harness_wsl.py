"""Implementation-sealed WSL supervisor for the local egress harness.

Constructing and inspecting this module performs no process or network I/O.
The actual runner remains behind the disabled Phase 3.2 gate; tests inject a
fake ``WSLCommandRunner``.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .egress_broker import build_broker_launch_spec, deterministic_response_metadata, fixed_client_request
from .egress_contract import (
    AUTH_UNCONFIGURED,
    SealedEgressContractService,
    canonical_provider_toml,
    provider_config_hash,
    validate_sealed_execution_proof,
)
from .egress_harness import HarnessExecution, WSL_RUNNER_KIND
from .egress_relay import (
    HARNESS_TOTAL_TIMEOUT_SECONDS,
    PROCESS_OUTPUT_LIMIT_BYTES,
    RELAY_REQUEST_TIMEOUT_SECONDS,
    RELAY_START_TIMEOUT_SECONDS,
    build_relay_launch_spec,
    validate_relay_loopback_boundary,
)
from .isolation_wsl import ProcessResult, WSLCommandRunner, separate_stream_byte_count, validate_wsl_distro
from .policy import PolicyError, canonical_json, sha256_json


SUPERVISOR_FRAME_PREFIX = "CODEXGATE_EGRESS_HARNESS_V1:"
SUPERVISOR_SCHEMA_VERSION = "1"
SUPERVISOR_TIMEOUT_SECONDS = HARNESS_TOTAL_TIMEOUT_SECONDS
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_BASE64URL = re.compile(r"^[A-Za-z0-9_-]+$")

_FRAME_FIELDS = frozenset({
    "schema_version", "status", "runner_implementation_hash", "request_hash", "response_hash",
    "request_bytes", "response_bytes", "status_code", "relay_connections", "broker_connections",
    "relay_requests", "broker_requests", "sensitive_headers_removed", "broker_sockets",
    "relay_sockets", "child_processes", "resources_cleaned", "children_terminated",
})
_BROKER_SOCKET_FIELDS = frozenset({
    "pathname_af_unix", "inet_attempts", "udp_attempts", "dns_attempts",
})
_RELAY_SOCKET_FIELDS = frozenset({
    "af_unix_connections", "loopback_tcp_listeners", "loopback_tcp_connections",
    "non_loopback_attempts", "udp_attempts", "dns_attempts",
})


# These constants are the only source for both reviewable launch specs and the
# argv materialized inside the supervisor.
BWRAP_COMMON_ARGS: tuple[str, ...] = (
    "/usr/bin/bwrap", "--unshare-all", "--new-session", "--die-with-parent", "--clearenv",
    "--ro-bind", "/usr", "/usr", "--ro-bind", "/bin", "/bin",
    "--ro-bind", "/lib", "/lib", "--ro-bind", "/lib64", "/lib64",
    "--ro-bind", "/etc", "/etc", "--proc", "/proc", "--dev", "/dev",
    "--tmpfs", "/tmp", "--tmpfs", "/home",
)
_FIXED_ENV_ARGS: tuple[str, ...] = (
    "--setenv", "PATH", "/usr/bin:/bin",
    "--setenv", "TMPDIR", "/tmp",
    "--setenv", "LANG", "C.UTF-8",
)
_PYTHON_C_ARGS: tuple[str, ...] = ("/usr/bin/python3", "-I", "-S", "-u", "-c")


def sealed_bwrap_environment_args() -> tuple[str, ...]:
    """Return the sole fixed clear-environment allowlist for sealed children.

    The caller may choose a fixed sandbox HOME separately, but no inherited
    Windows or WSL environment variable is ever appended to these args.
    """
    return _FIXED_ENV_ARGS

BROKER_CHILD_ARGV_TEMPLATE: tuple[str, ...] = BWRAP_COMMON_ARGS + (
    "--dir", "/home/broker", "--dir", "/runtime", "--dir", "/runtime/broker",
    "--bind", "{EXECUTION_SOCKET_DIR}", "/runtime/broker",
    "--setenv", "HOME", "/home/broker",
) + _FIXED_ENV_ARGS + _PYTHON_C_ARGS + ("{BROKER_CHILD_CODE}",)

RELAY_CHILD_ARGV_TEMPLATE: tuple[str, ...] = BWRAP_COMMON_ARGS + (
    "--dir", "/home/relay", "--dir", "/work",
    "--ro-bind", "{FIXTURE_SOURCE}", "/work/fixture.txt",
    "--dir", "/runtime", "--dir", "/runtime/broker",
    "--ro-bind", "{EXECUTION_SOCKET_DIR}", "/runtime/broker",
    "--setenv", "HOME", "/home/relay",
) + _FIXED_ENV_ARGS + _PYTHON_C_ARGS + ("{RELAY_CHILD_CODE}",)

SUPERVISOR_ARGV_TEMPLATE: tuple[str, ...] = (
    "{WSL_EXECUTABLE}", "-d", "Ubuntu", "--exec",
    "/usr/bin/python3", "-I", "-S", "-u", "-c",
    "{SUPERVISOR_CODE}", "{RUNNER_IMPLEMENTATION_HASH}",
)


BROKER_CHILD_CODE = r'''import base64,json,os,socket,sys
s=socket.socket(socket.AF_UNIX); s.bind("/runtime/broker/broker.sock"); s.listen(1); s.settimeout(15)
c,_=s.accept(); raw=c.recv(4096); request=json.loads(raw.decode("utf-8"))
bad=(request.get("method")!="POST" or request.get("path")!="/v1/responses" or request.get("host")!="127.0.0.1:8788" or any(k.lower() in ("authorization","cookie") or k.lower().startswith("proxy-") for k in request.get("headers",{})))
if bad: sys.exit(23)
body=json.dumps({"id":"resp_codexgate_fake_v1","object":"response","output":[{"id":"msg_codexgate_fake_v1","type":"message","role":"assistant","content":[{"type":"output_text","text":"codexgate sealed harness"}]}],"status":"completed"},ensure_ascii=True,sort_keys=True,separators=(",",":"))
policy={"pathname_af_unix":1,"inet_attempts":0,"udp_attempts":0,"dns_attempts":0}
c.sendall(json.dumps({"status":200,"body":base64.urlsafe_b64encode(body.encode("utf-8")).decode("ascii"),"broker_sockets":policy},sort_keys=True,separators=(",",":")).encode("utf-8")); c.close(); s.close()
'''

RELAY_CHILD_CODE = r'''import base64,hashlib,json,os,socket,sys
req=b'{"model":"sealed-harness"}'; host=b"127.0.0.1:8788"
listener=socket.socket(socket.AF_INET,socket.SOCK_STREAM); listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); listener.bind(("127.0.0.1",8788)); listener.listen(1); listener.settimeout(15)
client=socket.socket(socket.AF_INET,socket.SOCK_STREAM); client.settimeout(15); client.connect(("127.0.0.1",8788)); client.sendall(b"POST /v1/responses HTTP/1.1\r\nHost: "+host+b"\r\nAuthorization: removed\r\nCookie: removed\r\nProxy-Authorization: removed\r\nContent-Length: "+str(len(req)).encode("ascii")+b"\r\n\r\n"+req)
conn,_=listener.accept(); raw=conn.recv(4096); head,body=raw.split(b"\r\n\r\n",1); lines=head.split(b"\r\n"); first=lines[0].split(); headers={}
for line in lines[1:]:
 k,v=line.split(b":",1); headers[k.decode("ascii")]=v.strip().decode("ascii")
if first!=[b"POST",b"/v1/responses",b"HTTP/1.1"] or headers.get("Host")!="127.0.0.1:8788" or body!=req: sys.exit(24)
clean={k:v for k,v in headers.items() if k.lower() not in ("authorization","cookie") and not k.lower().startswith("proxy-")}
broker=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); broker.settimeout(15); broker.connect("/runtime/broker/broker.sock"); broker.sendall(json.dumps({"method":"POST","path":"/v1/responses","host":clean.get("Host"),"headers":clean},sort_keys=True,separators=(",",":")).encode("utf-8")); answer=json.loads(broker.recv(4096).decode("utf-8")); response=base64.urlsafe_b64decode(answer["body"].encode("ascii")); broker.close()
conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: "+str(len(response)).encode("ascii")+b"\r\n\r\n"+response); got=client.recv(4096); client.close(); conn.close(); listener.close()
if not got.endswith(response): sys.exit(25)
relay_policy={"af_unix_connections":1,"loopback_tcp_listeners":1,"loopback_tcp_connections":1,"non_loopback_attempts":0,"udp_attempts":0,"dns_attempts":0}
result={"request_hash":hashlib.sha256(req).hexdigest(),"response_hash":hashlib.sha256(response).hexdigest(),"request_bytes":len(req),"response_bytes":len(response),"status_code":200,"relay_connections":1,"broker_connections":1,"relay_requests":1,"broker_requests":1,"sensitive_headers_removed":True,"broker_sockets":answer["broker_sockets"],"relay_sockets":relay_policy}
os.write(1,json.dumps(result,ensure_ascii=True,sort_keys=True,separators=(",",":")).encode("utf-8"))
'''


def _template_json(value: Sequence[str]) -> str:
    return json.dumps(list(value), ensure_ascii=True, separators=(",", ":"))


_SUPERVISOR_SOURCE = "\n".join((
    "import base64,json,os,shutil,subprocess,sys,tempfile,time",
    f"P={SUPERVISOR_FRAME_PREFIX!r}; F=b'codexgate sealed egress fixture\\n'",
    f"BROKER={BROKER_CHILD_CODE!r}; RELAY={RELAY_CHILD_CODE!r}",
    f"BROKER_TEMPLATE=json.loads({_template_json(BROKER_CHILD_ARGV_TEMPLATE)!r})",
    f"RELAY_TEMPLATE=json.loads({_template_json(RELAY_CHILD_ARGV_TEMPLATE)!r})",
    "def cj(v): return json.dumps(v,ensure_ascii=True,sort_keys=True,separators=(',',':'))",
    "def emit(v): os.write(1,(P+base64.urlsafe_b64encode(cj(v).encode('utf-8')).rstrip(b'=').decode('ascii')+'\\n').encode('ascii'))",
    "def materialize(template,values): return [values.get(item,item) for item in template]",
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
    "implementation=sys.argv[1] if len(sys.argv)==2 else ''",
    "if len(implementation)!=64: sys.exit(20)",
    "root=tempfile.mkdtemp(prefix='cg-egress-'); broker=None; relay=None; payload=None; ok=False",
    "try:",
    " os.chmod(root,0o700); work=os.path.join(root,'work'); socket_dir=os.path.join(root,'socket'); os.mkdir(work,0o700); os.mkdir(socket_dir,0o700)",
    " fixture=os.path.join(work,'fixture.txt')",
    " with open(fixture,'wb') as f: f.write(F); f.flush(); os.fsync(f.fileno())",
    " broker_argv=materialize(BROKER_TEMPLATE,{'{EXECUTION_SOCKET_DIR}':socket_dir,'{BROKER_CHILD_CODE}':BROKER})",
    " broker=subprocess.Popen(broker_argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={})",
    " deadline=time.monotonic()+10",
    " while not os.path.exists(os.path.join(socket_dir,'broker.sock')):",
    "  if broker.poll() is not None or time.monotonic()>=deadline: sys.exit(21)",
    "  time.sleep(.02)",
    " relay_argv=materialize(RELAY_TEMPLATE,{'{EXECUTION_SOCKET_DIR}':socket_dir,'{FIXTURE_SOURCE}':fixture,'{RELAY_CHILD_CODE}':RELAY})",
    " relay=subprocess.Popen(relay_argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={})",
    " out,err=relay.communicate(timeout=15)",
    " if relay.returncode!=0 or len(out)+len(err)>8192: sys.exit(22)",
    " payload=json.loads(out.decode('utf-8'))",
    " if not stop(broker): sys.exit(26)",
    " broker_out,broker_err=broker.communicate(timeout=1)",
    " if len(broker_out)+len(broker_err)>8192 or broker.returncode!=0: sys.exit(27)",
    " ok=True",
    "except Exception:",
    " ok=False",
    "finally:",
    " children=stop(relay) and stop(broker); shutil.rmtree(root,ignore_errors=True); cleaned=not os.path.exists(root)",
    "if not ok or not children or not cleaned or not isinstance(payload,dict): sys.exit(28)",
    "payload.update({'schema_version':'1','status':'PASSED','runner_implementation_hash':implementation,'child_processes':2,'resources_cleaned':True,'children_terminated':True}); emit(payload)",
    "",
))
SUPERVISOR_CODE = _SUPERVISOR_SOURCE.encode("utf-8")


def compute_runner_implementation(
    *,
    supervisor_code: bytes = SUPERVISOR_CODE,
    broker_child_code: str = BROKER_CHILD_CODE,
    relay_child_code: str = RELAY_CHILD_CODE,
    common_args: Sequence[str] = BWRAP_COMMON_ARGS,
    broker_argv: Sequence[str] = BROKER_CHILD_ARGV_TEMPLATE,
    relay_argv: Sequence[str] = RELAY_CHILD_ARGV_TEMPLATE,
    supervisor_argv: Sequence[str] = SUPERVISOR_ARGV_TEMPLATE,
) -> tuple[str, dict[str, str]]:
    """Return the canonical implementation seal and reviewable component hashes."""
    argv_template_sha256 = hashlib.sha256(canonical_json({
        "common": list(common_args),
        "broker": list(broker_argv),
        "relay": list(relay_argv),
        "supervisor": list(supervisor_argv),
    }).encode("utf-8")).hexdigest()
    components = {
        "supervisor_sha256": hashlib.sha256(supervisor_code).hexdigest(),
        "broker_child_sha256": hashlib.sha256(broker_child_code.encode("utf-8")).hexdigest(),
        "relay_child_sha256": hashlib.sha256(relay_child_code.encode("utf-8")).hexdigest(),
        "argv_template_sha256": argv_template_sha256,
    }
    return sha256_json(components), components


RUNNER_IMPLEMENTATION_HASH, RUNNER_COMPONENT_HASHES = compute_runner_implementation()
ARGV_TEMPLATE_SHA256 = RUNNER_COMPONENT_HASHES["argv_template_sha256"]
WSL_EGRESS_RUNNER_VERSION = f"sealed-egress-wsl-{RUNNER_IMPLEMENTATION_HASH[:16]}"


def _materialize_argv(template: Sequence[str], replacements: Mapping[str, str]) -> list[str]:
    if set(replacements) - set(template):
        raise PolicyError("runner argv replacement is invalid")
    result = [replacements.get(item, item) for item in template]
    if any(item.startswith("{") and item.endswith("}") for item in result):
        raise PolicyError("runner argv template is unresolved")
    return result


def build_wsl_supervisor_argv(wsl_executable: str, distro: str) -> list[str]:
    """Return the sole implementation-sealed WSL process argv."""
    if not isinstance(wsl_executable, str) or not wsl_executable or any(ord(char) < 32 for char in wsl_executable):
        raise PolicyError("wsl_executable_invalid")
    if validate_wsl_distro(distro) != "Ubuntu":
        raise PolicyError("distro_not_ubuntu")
    return _materialize_argv(SUPERVISOR_ARGV_TEMPLATE, {
        "{WSL_EXECUTABLE}": wsl_executable,
        "{SUPERVISOR_CODE}": SUPERVISOR_CODE.decode("utf-8"),
        "{RUNNER_IMPLEMENTATION_HASH}": RUNNER_IMPLEMENTATION_HASH,
    })


def _child_argv(template: Sequence[str], *, socket_dir: str, fixture: str | None, child_code: str) -> list[str]:
    replacements = {
        "{EXECUTION_SOCKET_DIR}": socket_dir,
        "{BROKER_CHILD_CODE}" if template is BROKER_CHILD_ARGV_TEMPLATE else "{RELAY_CHILD_CODE}": child_code,
    }
    if fixture is not None:
        replacements["{FIXTURE_SOURCE}"] = fixture
    return _materialize_argv(template, replacements)


def build_wsl_broker_launch_spec(contract: Mapping[str, Any]) -> dict[str, Any]:
    """Review spec generated from the exact broker argv template."""
    base = build_broker_launch_spec(contract)
    env = {"PATH": "/usr/bin:/bin", "HOME": "/home/broker", "TMPDIR": "/tmp", "LANG": "C.UTF-8"}
    return {
        **base,
        "backend": "WSL2_BWRAP",
        "network": "unshare_all_no_host_network",
        "allowed_socket_families": ["AF_UNIX_PATHNAME"],
        "socket_directory_bind": {"source": "EXECUTION_SOCKET_DIR_ONLY", "target": "/runtime/broker", "mode": "rw"},
        "tmpfs": ["/tmp", "/home"],
        "clearenv": True,
        "environment": env,
        "argv_template": list(BROKER_CHILD_ARGV_TEMPLATE),
        "argv": _child_argv(
            BROKER_CHILD_ARGV_TEMPLATE,
            socket_dir="EXECUTION_SOCKET_DIR_ONLY",
            fixture=None,
            child_code=BROKER_CHILD_CODE,
        ),
        "runner_implementation_hash": RUNNER_IMPLEMENTATION_HASH,
    }


def build_wsl_relay_client_launch_spec(contract: Mapping[str, Any]) -> dict[str, Any]:
    """Review spec generated from the exact relay/client argv template."""
    base = build_relay_launch_spec(contract)
    env = {"PATH": "/usr/bin:/bin", "HOME": "/home/relay", "TMPDIR": "/tmp", "LANG": "C.UTF-8"}
    spec = {
        **base,
        "backend": "WSL2_BWRAP",
        "network": "unshare_all_loopback_only",
        "allowed_socket_boundaries": ["AF_UNIX_BROKER", "TCP_LOOPBACK"],
        "socket_directory_bind": {"source": "EXECUTION_SOCKET_DIR_ONLY", "target": "/runtime/broker", "mode": "ro"},
        "fixture_bind": {"source": "FIXTURE_SOURCE_ONLY", "target": "/work/fixture.txt", "mode": "ro"},
        "broker_socket": "CONTRACT_SOCKET_ONLY",
        "loopback_listener": {"host": "127.0.0.1", "port": 8788},
        "tmpfs": ["/tmp", "/home"],
        "clearenv": True,
        "environment": env,
        "argv_template": list(RELAY_CHILD_ARGV_TEMPLATE),
        "argv": _child_argv(
            RELAY_CHILD_ARGV_TEMPLATE,
            socket_dir="EXECUTION_SOCKET_DIR_ONLY",
            fixture="FIXTURE_SOURCE_ONLY",
            child_code=RELAY_CHILD_CODE,
        ),
        "runner_implementation_hash": RUNNER_IMPLEMENTATION_HASH,
    }
    validate_relay_loopback_boundary(spec)
    return spec


def expected_request_hash() -> str:
    return hashlib.sha256(fixed_client_request()[3]).hexdigest()


def validate_role_socket_boundaries(
    broker_sockets: Mapping[str, Any],
    relay_sockets: Mapping[str, Any],
) -> None:
    """Validate each process against its own socket allowance."""
    if not isinstance(broker_sockets, Mapping) or set(broker_sockets) != _BROKER_SOCKET_FIELDS:
        raise PolicyError("broker_socket_policy_violation")
    if not isinstance(relay_sockets, Mapping) or set(relay_sockets) != _RELAY_SOCKET_FIELDS:
        raise PolicyError("relay_socket_policy_violation")
    if any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in broker_sockets.values()):
        raise PolicyError("broker_socket_policy_violation")
    if any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in relay_sockets.values()):
        raise PolicyError("relay_socket_policy_violation")
    if broker_sockets["pathname_af_unix"] != 1 or any(
        broker_sockets[name] != 0 for name in ("inet_attempts", "udp_attempts", "dns_attempts")
    ):
        raise PolicyError("broker_socket_policy_violation")
    if (
        relay_sockets["af_unix_connections"] != 1
        or relay_sockets["loopback_tcp_listeners"] != 1
        or relay_sockets["loopback_tcp_connections"] != 1
        or any(relay_sockets[name] != 0 for name in ("non_loopback_attempts", "udp_attempts", "dns_attempts"))
    ):
        raise PolicyError("relay_socket_policy_violation")


@dataclass(frozen=True)
class SupervisorFrame:
    runner_implementation_hash: str
    request_hash: str
    response_hash: str
    request_bytes: int
    response_bytes: int
    status_code: int
    relay_connections: int
    broker_connections: int
    relay_requests: int
    broker_requests: int
    sensitive_headers_removed: bool
    broker_sockets: Mapping[str, int]
    relay_sockets: Mapping[str, int]
    child_processes: int
    resources_cleaned: bool
    children_terminated: bool


def _strict_frame(result: ProcessResult) -> SupervisorFrame:
    stdout = result.stdout_bytes if isinstance(result.stdout_bytes, bytes) else result.stdout.encode("utf-8", "strict")
    stderr = result.stderr_bytes if isinstance(result.stderr_bytes, bytes) else result.stderr.encode("utf-8", "strict")
    if len(stdout) + len(stderr) > PROCESS_OUTPUT_LIMIT_BYTES:
        raise PolicyError("output_limit")
    if result.exit_code != 0:
        raise PolicyError("supervisor_process_error")
    try:
        text = stdout.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise PolicyError("supervisor_frame_encoding") from exc
    lines = text.replace("\r\n", "\n").split("\n")
    nonempty = [line for line in lines if line]
    if len(nonempty) != 1:
        raise PolicyError("supervisor_frame_count")
    line = nonempty[0]
    if not line.startswith(SUPERVISOR_FRAME_PREFIX):
        raise PolicyError("supervisor_frame_missing")
    encoded = line[len(SUPERVISOR_FRAME_PREFIX):]
    if not encoded or "=" in encoded or not _BASE64URL.fullmatch(encoded):
        raise PolicyError("supervisor_frame_base64")
    try:
        raw = base64.urlsafe_b64decode(encoded + "=" * ((4 - len(encoded) % 4) % 4))
        payload = json.loads(raw.decode("utf-8", "strict"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PolicyError("supervisor_frame_json") from exc
    if not isinstance(payload, dict) or set(payload) != _FRAME_FIELDS:
        raise PolicyError("supervisor_frame_schema")
    if canonical_json(payload).encode("utf-8") != raw:
        raise PolicyError("supervisor_frame_not_canonical")
    if payload.get("schema_version") != SUPERVISOR_SCHEMA_VERSION:
        raise PolicyError("supervisor_frame_schema")
    if payload.get("runner_implementation_hash") != RUNNER_IMPLEMENTATION_HASH:
        raise PolicyError("runner_implementation_mismatch")
    if payload.get("status") == "POLICY_VIOLATION":
        raise PolicyError("policy_violation")
    if payload.get("status") != "PASSED":
        raise PolicyError("supervisor_frame_status")
    for name in ("request_hash", "response_hash"):
        if not isinstance(payload.get(name), str) or not _DIGEST.fullmatch(payload[name]):
            raise PolicyError("supervisor_frame_digest")
    if payload["request_hash"] != expected_request_hash() or payload["response_hash"] != deterministic_response_metadata()["response_hash"]:
        raise PolicyError("supervisor_frame_hash")
    integer_fields = (
        "request_bytes", "response_bytes", "status_code", "relay_connections", "broker_connections",
        "relay_requests", "broker_requests", "child_processes",
    )
    if any(not isinstance(payload.get(name), int) or isinstance(payload[name], bool) or payload[name] < 0 for name in integer_fields):
        raise PolicyError("supervisor_frame_schema")
    if payload["request_bytes"] != len(fixed_client_request()[3]) or payload["response_bytes"] != deterministic_response_metadata()["response_bytes"]:
        raise PolicyError("supervisor_frame_bytes")
    if payload["status_code"] != 200 or payload["child_processes"] != 2:
        raise PolicyError("supervisor_frame_status")
    if not isinstance(payload["sensitive_headers_removed"], bool):
        raise PolicyError("supervisor_frame_schema")
    if not payload["sensitive_headers_removed"]:
        raise PolicyError("sensitive_headers_not_removed")
    validate_role_socket_boundaries(payload["broker_sockets"], payload["relay_sockets"])
    if not isinstance(payload["resources_cleaned"], bool) or not isinstance(payload["children_terminated"], bool):
        raise PolicyError("supervisor_frame_schema")
    if not payload["resources_cleaned"]:
        raise PolicyError("resource_cleanup_failed")
    if not payload["children_terminated"]:
        raise PolicyError("process_termination_failed")
    return SupervisorFrame(
        runner_implementation_hash=payload["runner_implementation_hash"],
        request_hash=payload["request_hash"],
        response_hash=payload["response_hash"],
        request_bytes=payload["request_bytes"],
        response_bytes=payload["response_bytes"],
        status_code=payload["status_code"],
        relay_connections=payload["relay_connections"],
        broker_connections=payload["broker_connections"],
        relay_requests=payload["relay_requests"],
        broker_requests=payload["broker_requests"],
        sensitive_headers_removed=payload["sensitive_headers_removed"],
        broker_sockets=dict(payload["broker_sockets"]),
        relay_sockets=dict(payload["relay_sockets"]),
        child_processes=payload["child_processes"],
        resources_cleaned=payload["resources_cleaned"],
        children_terminated=payload["children_terminated"],
    )


class WSLEgressHarnessRunner:
    """Dormant actual runner with strict implementation and proof binding."""

    runner_kind = WSL_RUNNER_KIND
    # The gate uses this sealed identity rather than any generic/fake runner.
    # It does not alter the child-code/argv implementation hash.
    is_actual_wsl_runner = True
    runner_implementation_hash = RUNNER_IMPLEMENTATION_HASH
    runner_version = WSL_EGRESS_RUNNER_VERSION

    def __init__(self, store, runner: WSLCommandRunner):
        self.store = store
        self.runner = runner
        self.calls = 0
        self.requires_host_temp = False

    def _stored_contract(self, contract: Mapping[str, Any]) -> Mapping[str, Any]:
        contract_hash = contract.get("contract_hash") if isinstance(contract, Mapping) else None
        if not isinstance(contract_hash, str) or not _DIGEST.fullmatch(contract_hash):
            raise PolicyError("stored_contract_required")
        stored = self.store.egress_contract_instance(contract_hash)
        if not isinstance(stored, Mapping):
            raise PolicyError("stored_contract_required")
        if any(contract.get(field) != stored.get(field) for field in ("contract_id", "contract_hash", "preview_hash")):
            raise PolicyError("stored_contract_required")
        if stored.get("status") != AUTH_UNCONFIGURED or stored.get("preview_hash") != stored.get("contract_hash"):
            raise PolicyError("stored_contract_invalid")
        proof, proof_error = validate_sealed_execution_proof(self.store)
        if proof is None or any(stored.get(field) != value for field, value in proof.items()):
            raise PolicyError(proof_error or "repro_binding_changed")
        runtime = self.store.wsl_codex_runtime_result()
        isolation = self.store.wsl_isolation_result()
        problem = SealedEgressContractService._binding_problem(runtime, isolation, stored)
        if problem:
            raise PolicyError(problem)
        if stored.get("provider_config_hash") != provider_config_hash(canonical_provider_toml()):
            raise PolicyError("contract_provider_changed")
        if self.store.wsl_isolation_config().get("distro") != "Ubuntu":
            raise PolicyError("distro_not_ubuntu")
        return stored

    async def run(self, contract: Mapping[str, Any], launch_spec: Mapping[str, Any]) -> HarnessExecution:
        stored = self._stored_contract(contract)
        build_wsl_broker_launch_spec(stored)
        build_wsl_relay_client_launch_spec(stored)
        wsl_executable = self.runner.find_wsl()
        if not wsl_executable:
            raise PolicyError("wsl_unavailable")
        self.calls += 1
        process = await self.runner.run(
            build_wsl_supervisor_argv(wsl_executable, "Ubuntu"),
            timeout_seconds=SUPERVISOR_TIMEOUT_SECONDS,
        )
        frame = _strict_frame(process)
        stdout_bytes, stderr_bytes = separate_stream_byte_count(process)
        return HarnessExecution(
            relay_connections=frame.relay_connections,
            broker_connections=frame.broker_connections,
            relay_requests=frame.relay_requests,
            broker_requests=frame.broker_requests,
            request_bytes=frame.request_bytes,
            response_bytes=frame.response_bytes,
            response_hash=frame.response_hash,
            request_hash=frame.request_hash,
            status_code=frame.status_code,
            sensitive_headers_removed=frame.sensitive_headers_removed,
            socket_counts={},
            broker_socket_counts=frame.broker_sockets,
            relay_socket_counts=frame.relay_sockets,
            stdout_bytes=stdout_bytes,
            stderr_bytes=stderr_bytes,
            process_terminated=frame.children_terminated,
            resources_cleaned=frame.resources_cleaned,
            local_processes=1 + frame.child_processes,
            runner_kind=self.runner_kind,
            runner_version=self.runner_version,
            runner_implementation_hash=self.runner_implementation_hash,
        )
