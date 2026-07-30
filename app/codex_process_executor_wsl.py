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

from .egress_contract import (
    BROKER_REQUEST_PATH,
    CUSTOM_PROVIDER_ID,
    EPHEMERAL_TOKEN_ENV,
    LOOPBACK_HOST,
    LOOPBACK_PORT,
    SEALED_LOOPBACK_AUTHORITY,
    canonical_provider_toml,
    provider_config_hash,
    sanitize_broker_headers,
    validate_broker_request,
)
from .egress_harness_wsl import BWRAP_COMMON_ARGS, sealed_bwrap_environment_args
from .isolation_wsl import ProcessResult, separate_stream_byte_count
from .policy import PolicyError, canonical_json, sha256_json, validate_wsl_distro
from .wsl_codex_runtime import sealed_runtime_execution_policy, validate_wsl_codex_binary_path


EXECUTOR_POLICY_VERSION = "sealed-offline-codex-executor-v3"
SUPERVISOR_FRAME_PREFIX = "CODEXGATE_CODEX_SUPERVISOR_V1:"
SUPERVISOR_SCHEMA_VERSION = "1"
SUPERVISOR_TIMEOUT_SECONDS = 45
SUPERVISOR_OUTPUT_LIMIT_BYTES = 16 * 1024
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_BASE64URL = re.compile(r"^[A-Za-z0-9_-]+$")

SUPERVISOR_STAGES = frozenset({
    "BOOT", "CLAIM_VALIDATE", "SPEC_VALIDATE", "RUNTIME_VALIDATE", "BROKER_SPAWN",
    "BROKER_READY", "RELAY_CODEX_SPAWN", "RESPONSE_VALIDATE", "CLEANUP",
})
SUPERVISOR_FRAME_FIELDS = frozenset({
    "status", "stage", "error_code", "process_counts", "cleanup_ok", "implementation_hash",
    "request_count", "request_hash", "response_hash", "output_hash", "sensitive_headers_removed",
})
SUPERVISOR_PROCESS_FIELDS = ("supervisor", "broker_bwrap", "relay_codex_bwrap", "codex_cli")
SUPERVISOR_STATUSES = frozenset({"PASSED", "ERROR", "BLOCKED", "POLICY_VIOLATION"})

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
FIXED_REQUEST_BODY = {"model": CUSTOM_PROVIDER_ID, "input": FIXED_PROMPT}
FIXED_REQUEST_BODY_BYTES = canonical_json(FIXED_REQUEST_BODY).encode("utf-8")
EXPECTED_REQUEST_HASH = sha256_json({
    "method": "POST", "path": BROKER_REQUEST_PATH, "host": SEALED_LOOPBACK_AUTHORITY,
    "model": CUSTOM_PROVIDER_ID, "body_sha256": hashlib.sha256(FIXED_REQUEST_BODY_BYTES).hexdigest(),
})
EXPECTED_RESPONSE_HASH = sha256_json(FIXED_FAKE_RESPONSE)
EXPECTED_CONFIG_HASH = provider_config_hash(canonical_provider_toml())
EXPECTED_PROMPT_HASH = hashlib.sha256(FIXED_PROMPT.encode("utf-8")).hexdigest()
EXPECTED_OUTPUT_HASH = hashlib.sha256(SUCCESS_MARKER.encode("utf-8")).hexdigest()
# The help audit did not prove that the pinned CLI serialises ``exec --json``
# into this exact Responses request.  A real supervisor therefore blocks
# before any child spawn until a separately reviewed wire-contract seal flips
# this sealed constant.  Tests exercise only the pure byte-level relay path.
PINNED_CODEX_WIRE_CONTRACT_PROVEN = False


def _digest_or_none(value: Any) -> bool:
    return value is None or (isinstance(value, str) and _DIGEST.fullmatch(value) is not None)


def _fixed_http_request_bytes(headers: Mapping[str, str] | None = None) -> bytes:
    """Construct the one sealed synthetic request for byte-level tests only."""
    merged = {"Host": SEALED_LOOPBACK_AUTHORITY, "Content-Type": "application/json"}
    if headers:
        merged.update(headers)
    lines = [f"POST {BROKER_REQUEST_PATH} HTTP/1.1", *[f"{key}: {value}" for key, value in merged.items()],
             f"Content-Length: {len(FIXED_REQUEST_BODY_BYTES)}", "", ""]
    return "\r\n".join(lines).encode("ascii") + FIXED_REQUEST_BODY_BYTES


def parse_sealed_loopback_request(raw: bytes) -> dict[str, Any]:
    """Bounded, pure HTTP parser used by the relay review and no-I/O tests.

    It returns only metadata and digests: neither the request body nor any
    header value is persisted or returned to an API caller.
    """
    if not isinstance(raw, bytes) or len(raw) > 256 * 1024:
        raise PolicyError("canary_request_policy_violation")
    head, sep, body = raw.partition(b"\r\n\r\n")
    if not sep or len(head) > 8192:
        raise PolicyError("canary_request_policy_violation")
    try:
        lines = head.decode("ascii", "strict").split("\r\n")
        method, target, version = lines[0].split(" ")
    except (UnicodeDecodeError, ValueError, IndexError) as exc:
        raise PolicyError("canary_request_policy_violation") from exc
    if version != "HTTP/1.1" or method != "POST" or target != BROKER_REQUEST_PATH or "://" in target:
        raise PolicyError("canary_request_policy_violation")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line or ":" not in line:
            raise PolicyError("canary_request_policy_violation")
        name, value = line.split(":", 1)
        if name in headers:
            raise PolicyError("canary_request_policy_violation")
        headers[name] = value.strip()
    try:
        content_length = int(headers.get("Content-Length", "-1"))
    except ValueError as exc:
        raise PolicyError("canary_request_policy_violation") from exc
    if content_length != len(body) or content_length < 0 or content_length > 256 * 1024:
        raise PolicyError("canary_request_policy_violation")
    try:
        request = json.loads(body.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PolicyError("canary_request_policy_violation") from exc
    if not isinstance(request, dict) or request.get("model") != CUSTOM_PROVIDER_ID:
        raise PolicyError("canary_model_policy_violation")
    sensitive = any(name.casefold() in {"authorization", "cookie"} or name.casefold().startswith("proxy-") for name in headers)
    clean = sanitize_broker_headers(headers)
    validate_broker_request(method, target, clean, len(body))
    body_hash = hashlib.sha256(body).hexdigest()
    return {
        "request_count": 1,
        "request_hash": sha256_json({"method": method, "path": target, "host": SEALED_LOOPBACK_AUTHORITY,
                                       "model": CUSTOM_PROVIDER_ID, "body_sha256": body_hash}),
        "body_sha256": body_hash,
        "sensitive_headers_removed": sensitive or clean == headers,
        "clean_headers": clean,
    }


def synthetic_relay_broker_roundtrip(raw: bytes | None = None, *, second_request: bool = False) -> dict[str, Any]:
    """No-I/O model of the sole relay→broker exchange used by tests."""
    if second_request:
        raise PolicyError("canary_request_policy_violation")
    request = parse_sealed_loopback_request(raw if raw is not None else _fixed_http_request_bytes())
    response_bytes = canonical_json(FIXED_FAKE_RESPONSE).encode("utf-8")
    return {
        "request_count": request["request_count"], "request_hash": request["request_hash"],
        "response_hash": hashlib.sha256(response_bytes).hexdigest(),
        "output_hash": EXPECTED_OUTPUT_HASH,
        "sensitive_headers_removed": request["sensitive_headers_removed"],
    }

# The child programs use fixed paths and arguments only.  They are not
# materialized or executed during this implementation phase.
BROKER_CHILD_CODE = ("""import json,socket
HOST=%r; PATH=%r; MODEL=%r; RESPONSE=%r
s=socket.socket(socket.AF_UNIX); s.bind('/runtime/broker/broker.sock'); s.listen(1); s.settimeout(15)
c,_=s.accept(); raw=c.recv(262145)
if len(raw)>262144: raise ValueError('request_limit')
request=json.loads(raw.decode('utf-8','strict'))
if set(request)!={'method','path','host','headers','body_hex'}: raise ValueError('request_schema')
if request['method']!='POST' or request['path']!=PATH or request['host']!=HOST: raise ValueError('request_target')
if request['headers'].get('Host')!=HOST or any(k.casefold() in ('authorization','cookie') or k.casefold().startswith('proxy-') for k in request['headers']): raise ValueError('sensitive_header')
body=bytes.fromhex(request['body_hex']); parsed=json.loads(body.decode('utf-8','strict'))
if not isinstance(parsed,dict) or parsed.get('model')!=MODEL: raise ValueError('request_model')
c.sendall(json.dumps({'status':200,'body_hex':RESPONSE.hex()},sort_keys=True,separators=(',',':')).encode('utf-8')); c.close(); s.close()
""" % (SEALED_LOOPBACK_AUTHORITY, BROKER_REQUEST_PATH, CUSTOM_PROVIDER_ID, canonical_json(FIXED_FAKE_RESPONSE).encode('utf-8'))).encode("utf-8")

RELAY_CODEX_CHILD_CODE = ("""import base64,hashlib,json,os,socket,subprocess
HOST=%r; PORT=%d; AUTHORITY=%r; PATH=%r; MODEL=%r; PROMPT=%r; MARKER=%r; ARGV=%r; TOKEN_ENV=%r
def canon(v): return json.dumps(v,ensure_ascii=True,sort_keys=True,separators=(',',':')).encode('utf-8')
listener=socket.socket(socket.AF_INET,socket.SOCK_STREAM); listener.bind((HOST,PORT)); listener.listen(1); listener.settimeout(15)
token=os.urandom(32).hex(); env={'PATH':'/usr/bin:/bin','HOME':'/home/codex','TMPDIR':'/tmp','LANG':'C.UTF-8','CODEX_HOME':os.environ['CODEX_HOME'],TOKEN_ENV:token}
codex=subprocess.Popen(['/runtime/codex',*ARGV],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env)
conn,_=listener.accept(); raw=conn.recv(262145)
if len(raw)>262144 or b'\\r\\n\\r\\n' not in raw: raise ValueError('request_limit')
head,body=raw.split(b'\\r\\n\\r\\n',1); lines=head.decode('ascii','strict').split('\\r\\n')
if not lines or lines[0]!=('POST '+PATH+' HTTP/1.1'): raise ValueError('request_target')
headers={}
for line in lines[1:]:
 if ':' not in line: raise ValueError('request_header')
 name,value=line.split(':',1); headers[name]=value.strip()
if headers.get('Host')!=AUTHORITY or int(headers.get('Content-Length','-1'))!=len(body): raise ValueError('request_host')
parsed=json.loads(body.decode('utf-8','strict'))
if not isinstance(parsed,dict) or parsed.get('model')!=MODEL: raise ValueError('request_model')
sensitive=any(k.casefold() in ('authorization','cookie') or k.casefold().startswith('proxy-') for k in headers); clean={k:v for k,v in headers.items() if k.casefold() not in ('authorization','cookie') and not k.casefold().startswith('proxy-')}
upstream=socket.socket(socket.AF_UNIX); upstream.connect('/runtime/broker/broker.sock'); upstream.sendall(canon({'method':'POST','path':PATH,'host':AUTHORITY,'headers':clean,'body_hex':body.hex()})); reply=upstream.recv(2097153); upstream.close()
if len(reply)>2097152: raise ValueError('response_limit')
response=bytes.fromhex(json.loads(reply.decode('utf-8','strict'))['body_hex']); conn.sendall(b'HTTP/1.1 200 OK\\r\\nContent-Length: '+str(len(response)).encode('ascii')+b'\\r\\n\\r\\n'+response); conn.close(); listener.close()
out,err=codex.communicate(PROMPT,timeout=30)
if codex.returncode!=0 or out!=MARKER: raise ValueError('codex_marker')
proof={'codex_cli':1,'request_hash':hashlib.sha256(canon({'method':'POST','path':PATH,'host':AUTHORITY,'model':MODEL,'body_sha256':hashlib.sha256(body).hexdigest()})).hexdigest(),'response_hash':hashlib.sha256(response).hexdigest(),'output_hash':hashlib.sha256(out).hexdigest(),'sensitive_headers_removed':bool(sensitive)}
os.write(1,b'CODEXGATE_CODEX_RELAY_V1:'+base64.urlsafe_b64encode(canon(proof)).rstrip(b'=')+b'\\n')
""" % (LOOPBACK_HOST, LOOPBACK_PORT, SEALED_LOOPBACK_AUTHORITY, BROKER_REQUEST_PATH, CUSTOM_PROVIDER_ID, FIXED_PROMPT.encode('utf-8'), SUCCESS_MARKER.encode('utf-8'), list(FIXED_CODEX_ARGV), EPHEMERAL_TOKEN_ENV)).encode("utf-8")

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
    "--ro-bind", "{CODEX_HOME_SOURCE}", "/runtime/codex-home",
    "--ro-bind", "{CODEX_BINARY}", "/runtime/codex", "--chdir", "/work",
    "--setenv", "HOME", "/home/codex",
    "--setenv", "CODEX_HOME", "/runtime/codex-home",
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
    "import base64,json,os,shutil,subprocess,sys,tempfile,time,uuid",
    f"P={SUPERVISOR_FRAME_PREFIX!r}; BROKER={BROKER_CHILD_CODE!r}; RELAY={RELAY_CODEX_CHILD_CODE!r}",
    f"BT=json.loads({_template_json(BROKER_CHILD_ARGV_TEMPLATE)!r}); RT=json.loads({_template_json(RELAY_CODEX_CHILD_ARGV_TEMPLATE)!r})",
    f"CONFIG={canonical_provider_toml()!r}; WIRE_PROVEN={PINNED_CODEX_WIRE_CONTRACT_PROVEN!r}",
    "STAGES={'BOOT','CLAIM_VALIDATE','SPEC_VALIDATE','RUNTIME_VALIDATE','BROKER_SPAWN','BROKER_READY','RELAY_CODEX_SPAWN','RESPONSE_VALIDATE','CLEANUP'}",
    "COUNTS={'supervisor':1,'broker_bwrap':0,'relay_codex_bwrap':0,'codex_cli':0}; PROOF={'request_count':0,'request_hash':None,'response_hash':None,'output_hash':None,'sensitive_headers_removed':False}; emitted=False; implementation=sys.argv[2] if len(sys.argv)==3 else ''",
    "def cj(v): return json.dumps(v,ensure_ascii=False,sort_keys=True,separators=(',',':'))",
    "def emit(status,stage,error=None,cleanup_ok=False):",
    " global emitted",
    " if emitted: return",
    " emitted=True; payload={'status':status,'stage':stage,'error_code':error,'process_counts':dict(COUNTS),'cleanup_ok':bool(cleanup_ok),'implementation_hash':implementation,**PROOF}",
    " os.write(1,(P+base64.urlsafe_b64encode(cj(payload).encode('utf-8')).rstrip(b'=').decode('ascii')+'\\n').encode('ascii'))",
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
    "root=None; broker=None; relay=None; stage='BOOT'; failed=None; cleaned=False",
    "try:",
    " if len(sys.argv)!=3: stage='CLAIM_VALIDATE'; raise ValueError('claim_invalid')",
    " try: uuid.UUID(sys.argv[1])",
    " except Exception: stage='CLAIM_VALIDATE'; raise ValueError('claim_invalid')",
    " if len(implementation)!=64: stage='SPEC_VALIDATE'; raise ValueError('implementation_invalid')",
    " if not WIRE_PROVEN: stage='RUNTIME_VALIDATE'; raise ValueError('codex_wire_contract_unproven')",
    " root=tempfile.mkdtemp(prefix='cg-codex-'); os.chmod(root,0o700); work=os.path.join(root,'work'); sock=os.path.join(root,'socket'); home=os.path.join(root,'codex-home'); os.mkdir(work,0o700); os.mkdir(sock,0o700); os.mkdir(home,0o700)",
    " fixture=os.path.join(work,'fixture.json'); open(fixture,'wb').write(b'{\\\"kind\\\":\\\"offline-canary\\\"}\\n')",
    " config=os.path.join(home,'config.toml'); fp=open(config,'wb'); fp.write(CONFIG); fp.flush(); os.fsync(fp.fileno()); fp.close()",
    " stage='BROKER_SPAWN'; ba=materialize(BT,{'{EXECUTION_SOCKET_DIR}':sock,'{BROKER_CHILD_CODE}':BROKER.decode('utf-8')}); broker=subprocess.Popen(ba,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={}); COUNTS['broker_bwrap']=1",
    " stage='BROKER_READY'; deadline=time.monotonic()+10",
    " while not os.path.exists(os.path.join(sock,'broker.sock')):",
    "  if broker.poll() is not None or time.monotonic()>=deadline: raise TimeoutError('broker_not_ready')",
    "  time.sleep(.02)",
    " stage='RELAY_CODEX_SPAWN'; ra=materialize(RT,{'{EXECUTION_SOCKET_DIR}':sock,'{FIXTURE_SOURCE}':fixture,'{CODEX_HOME_SOURCE}':home,'{CODEX_BINARY}':'/runtime/codex','{RELAY_CODEX_CHILD_CODE}':RELAY.decode('utf-8')}); relay=subprocess.Popen(ra,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={}); COUNTS['relay_codex_bwrap']=1",
    " out,err=relay.communicate(timeout=30)",
    " if len(out)+len(err)>16384: raise ValueError('output_limit')",
    " if relay.returncode!=0: raise ValueError('relay_codex_failed')",
    " prefix=b'CODEXGATE_CODEX_RELAY_V1:'",
    " if not out.startswith(prefix): raise ValueError('codex_spawn_not_proven')",
    " encoded=out[len(prefix):].strip(); proof=json.loads(base64.urlsafe_b64decode(encoded+b'='*((4-len(encoded)%4)%4)).decode('utf-8','strict'))",
    " if set(proof)!={'codex_cli','request_hash','response_hash','output_hash','sensitive_headers_removed'} or proof.get('codex_cli')!=1: raise ValueError('codex_spawn_not_proven')",
    " COUNTS['codex_cli']=1; PROOF.update({'request_count':1,'request_hash':proof['request_hash'],'response_hash':proof['response_hash'],'output_hash':proof['output_hash'],'sensitive_headers_removed':proof['sensitive_headers_removed']}); stage='RESPONSE_VALIDATE'",
    " stage='CLEANUP'",
    "except TimeoutError as exc: failed='supervisor_timeout'",
    "except subprocess.TimeoutExpired as exc: failed='supervisor_timeout'",
    "except ValueError as exc: failed={'claim_invalid':'claim_invalid','implementation_invalid':'implementation_invalid','codex_wire_contract_unproven':'codex_wire_contract_unproven','broker_not_ready':'broker_not_ready','relay_codex_failed':'relay_codex_failed','output_limit':'output_limit','codex_spawn_not_proven':'codex_spawn_not_proven'}.get(str(exc),'supervisor_error')",
    "except Exception: failed='supervisor_error'",
    "finally:",
    " stage='CLEANUP' if failed is None else stage; relay_stopped=stop(relay); broker_stopped=stop(broker); shutil.rmtree(root,ignore_errors=True) if root else None; cleaned=bool(relay_stopped and broker_stopped and (root is None or not os.path.exists(root)))",
    " if failed is not None: emit('ERROR',stage,failed,cleaned)",
    " elif not cleaned: emit('ERROR','CLEANUP','cleanup_failed',False)",
    " else: emit('PASSED','CLEANUP',None,True)",
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
        "provider_config_sha256": provider_config_hash(canonical_provider_toml()),
        "loopback_endpoint_sha256": sha256_json({"host": LOOPBACK_HOST, "port": LOOPBACK_PORT}),
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
            "endpoint": {"host": LOOPBACK_HOST, "port": LOOPBACK_PORT, "path": BROKER_REQUEST_PATH},
            "codex_home_config": "execution_ephemeral_read_only_bind",
        },
        "forbidden_binds": ["/mnt", "WINDOWS", "SOURCE_ROOT", "DATA_ROOT", "USER_HOME"],
        "runtime_binary": binary_path,
        "executor_implementation_hash": EXECUTOR_IMPLEMENTATION_HASH,
    }


class CodexExecutorFailure(PolicyError):
    """A sanitized supervisor/transport error with observed provenance only."""

    def __init__(
        self, code: str, *, supervisor_processes: int = 0, bwrap_processes: int = 0,
        codex_processes: int = 0, stage: str | None = None, cleanup_ok: bool | None = None,
        stdout_bytes: int = 0, stderr_bytes: int = 0, exit_code: int | None = None,
        transport: bool = False,
    ):
        super().__init__(code)
        self.stage = stage
        self.cleanup_ok = cleanup_ok
        self.stdout_bytes = max(0, int(stdout_bytes))
        self.stderr_bytes = max(0, int(stderr_bytes))
        self.exit_code = exit_code
        self.transport = bool(transport)
        self.supervisor_processes = max(0, int(supervisor_processes))
        self.bwrap_processes = max(0, int(bwrap_processes))
        self.codex_processes = max(0, int(codex_processes))
        self.local_processes = self.supervisor_processes + self.bwrap_processes + self.codex_processes


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
        except (FileNotFoundError, OSError) as exc:
            raise CodexExecutorFailure("supervisor_transport_error", stage="BOOT", transport=True) from exc
        if on_started is not None:
            on_started()
        try:
            stdout, stderr = await self._collect_limited_output(process, timeout_seconds)
        except asyncio.TimeoutError:
            await self._terminate_process_tree(process)
            raise CodexExecutorFailure("supervisor_transport_timeout", stage="BOOT", supervisor_processes=1, transport=True)
        return ProcessResult(
            exit_code=process.returncode,
            stdout=stdout.decode("utf-8", errors="replace"), stderr=stderr.decode("utf-8", errors="replace"),
            stdout_bytes=stdout, stderr_bytes=stderr,
        )

    @staticmethod
    async def _collect_limited_output(process: asyncio.subprocess.Process, timeout_seconds: float) -> tuple[bytes, bytes]:
        """Drain both streams while enforcing the cap before process exit."""
        if process.stdout is None or process.stderr is None:
            raise CodexExecutorFailure("supervisor_transport_error", stage="BOOT", supervisor_processes=1, transport=True)
        buffers = {"stdout": bytearray(), "stderr": bytearray()}
        readers = {"stdout": process.stdout, "stderr": process.stderr}
        pending: dict[asyncio.Task[bytes], str] = {
            asyncio.create_task(reader.read(4096)): name for name, reader in readers.items()
        }
        deadline = asyncio.get_running_loop().time() + timeout_seconds
        try:
            while pending:
                remaining = deadline - asyncio.get_running_loop().time()
                if remaining <= 0:
                    raise asyncio.TimeoutError
                done, _ = await asyncio.wait(pending, timeout=remaining, return_when=asyncio.FIRST_COMPLETED)
                if not done:
                    raise asyncio.TimeoutError
                for task in done:
                    name = pending.pop(task)
                    chunk = task.result()
                    if not chunk:
                        continue
                    buffers[name].extend(chunk)
                    if len(buffers["stdout"]) + len(buffers["stderr"]) > SUPERVISOR_OUTPUT_LIMIT_BYTES:
                        await SealedWSLSupervisorRunner._terminate_process_tree(process)
                        raise CodexExecutorFailure(
                            "supervisor_output_limit", stage="BOOT", supervisor_processes=1,
                            stdout_bytes=len(buffers["stdout"]), stderr_bytes=len(buffers["stderr"]),
                        )
                    pending[asyncio.create_task(readers[name].read(4096))] = name
            await process.wait()
            return bytes(buffers["stdout"]), bytes(buffers["stderr"])
        finally:
            for task in pending:
                task.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)

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
    status: str
    stage: str
    error_code: str | None
    process_counts: dict[str, int]
    cleanup_ok: bool
    implementation_hash: str
    request_count: int
    request_hash: str | None
    response_hash: str | None
    output_hash: str | None
    sensitive_headers_removed: bool

    @property
    def supervisor_processes(self) -> int:
        return self.process_counts["supervisor"]

    @property
    def bwrap_processes(self) -> int:
        return self.process_counts["broker_bwrap"] + self.process_counts["relay_codex_bwrap"]

    @property
    def codex_processes(self) -> int:
        return self.process_counts["codex_cli"]


def encode_supervisor_frame(payload: Mapping[str, Any]) -> str:
    """Encode the one-line supervisor frame used by production and fakes."""
    if set(payload) != SUPERVISOR_FRAME_FIELDS:
        raise ValueError("supervisor_frame_fields")
    raw = canonical_json(dict(payload)).encode("utf-8")
    return SUPERVISOR_FRAME_PREFIX + base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") + "\n"


def _stream_size(value: bytes | str | None) -> int:
    if isinstance(value, bytes):
        return len(value)
    if isinstance(value, str):
        return len(value.encode("utf-8", "replace"))
    return 0


def _frame_failure(code: str, *, stage: str, result: ProcessResult, counts: Mapping[str, int] | None = None, cleanup_ok: bool | None = None, transport: bool = False) -> CodexExecutorFailure:
    observed = dict(counts or {"supervisor": 1, "broker_bwrap": 0, "relay_codex_bwrap": 0, "codex_cli": 0})
    return CodexExecutorFailure(
        code, supervisor_processes=observed.get("supervisor", 0),
        bwrap_processes=observed.get("broker_bwrap", 0) + observed.get("relay_codex_bwrap", 0),
        codex_processes=observed.get("codex_cli", 0), stage=stage, cleanup_ok=cleanup_ok,
        stdout_bytes=_stream_size(result.stdout_bytes if result.stdout_bytes is not None else result.stdout),
        stderr_bytes=_stream_size(result.stderr_bytes if result.stderr_bytes is not None else result.stderr),
        exit_code=result.exit_code, transport=transport,
    )


def _strict_supervisor_frame(result: ProcessResult, expected: Mapping[str, str] | str) -> _SupervisorFrame:
    try:
        stdout = result.stdout_bytes if isinstance(result.stdout_bytes, bytes) else (
            result.stdout if isinstance(result.stdout, bytes) else result.stdout.encode("utf-8", "strict")
        )
        stderr = result.stderr_bytes if isinstance(result.stderr_bytes, bytes) else (
            result.stderr if isinstance(result.stderr, bytes) else result.stderr.encode("utf-8", "strict")
        )
    except UnicodeError as exc:
        raise _frame_failure("supervisor_frame_invalid_utf8", stage="BOOT", result=result) from exc
    if len(stdout) + len(stderr) > SUPERVISOR_OUTPUT_LIMIT_BYTES:
        raise _frame_failure("supervisor_output_limit", stage="BOOT", result=result)
    if result.exit_code != 0:
        raise _frame_failure("supervisor_transport_exit", stage="BOOT", result=result, transport=True)
    try:
        text = stdout.decode("utf-8", "strict").replace("\r\n", "\n")
    except UnicodeDecodeError as exc:
        raise _frame_failure("supervisor_frame_invalid_utf8", stage="BOOT", result=result) from exc
    lines = text.split("\n")
    while lines and lines[0] == "":
        lines.pop(0)
    while lines and lines[-1] == "":
        lines.pop()
    if not lines:
        raise _frame_failure("supervisor_frame_missing", stage="BOOT", result=result)
    if len(lines) > 1:
        code = "supervisor_frame_duplicate" if all(line.startswith(SUPERVISOR_FRAME_PREFIX) for line in lines) else "supervisor_frame_extra_output"
        raise _frame_failure(code, stage="BOOT", result=result)
    line = lines[0]
    if not line.startswith(SUPERVISOR_FRAME_PREFIX):
        raise _frame_failure("supervisor_frame_extra_output", stage="BOOT", result=result)
    encoded = line[len(SUPERVISOR_FRAME_PREFIX):]
    if not encoded or "=" in encoded or not _BASE64URL.fullmatch(encoded) or len(encoded) % 4 == 1:
        raise _frame_failure("supervisor_frame_invalid_base64", stage="BOOT", result=result)
    try:
        raw = base64.urlsafe_b64decode(encoded + "=" * ((4 - len(encoded) % 4) % 4))
        payload = json.loads(raw.decode("utf-8", "strict"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _frame_failure("supervisor_frame_invalid_json", stage="BOOT", result=result) from exc
    if not isinstance(payload, dict) or set(payload) != SUPERVISOR_FRAME_FIELDS or canonical_json(payload).encode("utf-8") != raw:
        raise _frame_failure("supervisor_frame_schema_invalid", stage="BOOT", result=result)
    stage = payload.get("stage")
    if payload.get("status") not in SUPERVISOR_STATUSES or stage not in SUPERVISOR_STAGES:
        raise _frame_failure("supervisor_frame_schema_invalid", stage="BOOT", result=result)
    if not isinstance(payload.get("implementation_hash"), str) or not _DIGEST.fullmatch(payload["implementation_hash"]):
        raise _frame_failure("supervisor_frame_schema_invalid", stage=stage, result=result)
    expected_hash = expected if isinstance(expected, str) else expected.get("implementation_hash", EXECUTOR_IMPLEMENTATION_HASH)
    if payload["implementation_hash"] != expected_hash:
        raise _frame_failure("supervisor_implementation_mismatch", stage=stage, result=result)
    counts = payload.get("process_counts")
    if not isinstance(counts, dict) or set(counts) != set(SUPERVISOR_PROCESS_FIELDS) or any(
        isinstance(counts.get(name), bool) or not isinstance(counts.get(name), int) or counts[name] < 0 for name in SUPERVISOR_PROCESS_FIELDS
    ):
        raise _frame_failure("supervisor_frame_schema_invalid", stage=stage, result=result)
    if not isinstance(payload.get("cleanup_ok"), bool):
        raise _frame_failure("supervisor_frame_schema_invalid", stage=stage, result=result)
    request_count = payload.get("request_count")
    if isinstance(request_count, bool) or not isinstance(request_count, int) or request_count < 0 or request_count > 1:
        raise _frame_failure("supervisor_frame_schema_invalid", stage=stage, result=result)
    if not all(_digest_or_none(payload.get(field)) for field in ("request_hash", "response_hash", "output_hash")):
        raise _frame_failure("supervisor_frame_schema_invalid", stage=stage, result=result)
    if not isinstance(payload.get("sensitive_headers_removed"), bool):
        raise _frame_failure("supervisor_frame_schema_invalid", stage=stage, result=result)
    if counts["supervisor"] != 1:
        raise _frame_failure("supervisor_process_count_invalid", stage=stage, result=result)
    if stage in {"BOOT", "CLAIM_VALIDATE", "SPEC_VALIDATE", "RUNTIME_VALIDATE"} and any(
        counts[name] for name in ("broker_bwrap", "relay_codex_bwrap", "codex_cli")
    ):
        raise _frame_failure("supervisor_process_count_invalid", stage=stage, result=result)
    error = payload.get("error_code")
    if error is not None and (not isinstance(error, str) or not re.fullmatch(r"[a-z0-9_]{1,80}", error)):
        raise _frame_failure("supervisor_frame_schema_invalid", stage=stage, result=result)
    if payload["status"] == "PASSED":
        if (
            error is not None or stage != "CLEANUP" or not payload["cleanup_ok"]
            or counts != {"supervisor": 1, "broker_bwrap": 1, "relay_codex_bwrap": 1, "codex_cli": 1}
            or request_count != 1 or not all(_DIGEST.fullmatch(str(payload.get(field) or "")) for field in ("request_hash", "response_hash", "output_hash"))
            or not payload["sensitive_headers_removed"]
        ):
            raise _frame_failure("supervisor_success_proof_invalid", stage=stage, result=result, counts=counts, cleanup_ok=payload["cleanup_ok"])
    if payload["status"] != "PASSED" and error is None:
        raise _frame_failure("supervisor_frame_schema_invalid", stage=stage, result=result)
    return _SupervisorFrame(
        payload["status"], stage, error, dict(counts), payload["cleanup_ok"], payload["implementation_hash"],
        request_count, payload["request_hash"], payload["response_hash"], payload["output_hash"], payload["sensitive_headers_removed"],
    )


def parse_supervisor_frame(result: ProcessResult, expected_implementation_hash: str = EXECUTOR_IMPLEMENTATION_HASH) -> _SupervisorFrame:
    """Public read-only parser seam used by the fake-supervisor tests."""
    return _strict_supervisor_frame(result, expected_implementation_hash)


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
        except CodexExecutorFailure:
            raise
        except TimeoutError as exc:
            raise CodexExecutorFailure("supervisor_transport_timeout", stage="BOOT", supervisor_processes=1, transport=True) from exc
        except Exception as exc:
            raise CodexExecutorFailure("supervisor_transport_error", stage="BOOT", supervisor_processes=1, transport=True) from exc
        frame = _strict_supervisor_frame(process, EXECUTOR_IMPLEMENTATION_HASH)
        if frame.status != "PASSED":
            raise CodexExecutorFailure(
                frame.error_code or "supervisor_workload_error", stage=frame.stage,
                supervisor_processes=frame.supervisor_processes, bwrap_processes=frame.bwrap_processes,
                codex_processes=frame.codex_processes, cleanup_ok=frame.cleanup_ok,
                stdout_bytes=_stream_size(process.stdout_bytes if process.stdout_bytes is not None else process.stdout),
                stderr_bytes=_stream_size(process.stderr_bytes if process.stderr_bytes is not None else process.stderr),
                exit_code=process.exit_code,
            )
        # Import only after construction to keep this module free of a cycle.
        from .codex_process_canary import CanaryExecution

        # The frame contains only relay-observed digests.  Do not manufacture
        # request, response, or marker proof from expectations on the host.
        separate_stream_byte_count(process)
        return CanaryExecution(
            request_count=frame.request_count, request_hash=frame.request_hash or "", response_hash=frame.response_hash or "",
            config_hash=EXPECTED_CONFIG_HASH, prompt_hash=EXPECTED_PROMPT_HASH, expected_output_hash=EXPECTED_OUTPUT_HASH,
            exit_code=process.exit_code or 0,
            stdout_bytes=_stream_size(process.stdout_bytes if process.stdout_bytes is not None else process.stdout),
            stderr_bytes=_stream_size(process.stderr_bytes if process.stderr_bytes is not None else process.stderr),
            local_processes=frame.supervisor_processes + frame.bwrap_processes + frame.codex_processes,
            marker=None, output_hash=frame.output_hash, marker_verified=frame.output_hash == EXPECTED_OUTPUT_HASH,
            sensitive_headers_removed=frame.sensitive_headers_removed,
            process_terminated=True, resources_cleaned=frame.cleanup_ok,
            runner_kind="WSL_CODEX_CANARY", runner_version=EXECUTOR_VERSION,
            runner_implementation_hash=EXECUTOR_IMPLEMENTATION_HASH,
            supervisor_processes=frame.supervisor_processes, bwrap_processes=frame.bwrap_processes,
            codex_processes=frame.codex_processes,
            supervisor_stage=frame.stage, cleanup_ok=frame.cleanup_ok,
        )


def production_executor_factory(store) -> Callable[[str], WSLCodexProcessCanaryExecutor]:
    """Return a per-claim factory; it does not construct an executor yet."""
    return lambda execution_claim_id: WSLCodexProcessCanaryExecutor(store, execution_claim_id)
