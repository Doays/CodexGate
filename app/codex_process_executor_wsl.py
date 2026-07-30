"""Sealed WSL supervisor executor for the offline Codex process canary.

Construction performs no WSL, bubblewrap, Codex, socket, or network I/O.
The executor is intentionally created only after a persisted one-shot claim is
``RUNNING``.  Tests inject a no-I/O ``WSLCommandRunner``; the production
factory otherwise has no alternate or fake-executor path.
"""
from __future__ import annotations

import base64
import asyncio
import errno
import hashlib
import json
import re
import shutil
import subprocess
import sys
import uuid
import zlib
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
from .codex_wire_contract import (
    FIXED_PROMPT as WIRE_FIXED_PROMPT,
    SUCCESS_MARKER as WIRE_SUCCESS_MARKER,
    WIRE_CONTRACT_HASH,
    WIRE_CONTRACT_STATUS,
    build_fixed_request,
    canonical_request_hash,
    fixture_stream_bytes,
    fixture_stream_hash,
    fixed_prompt_hash,
    validate_request,
)
from .isolation_wsl import ProcessResult, separate_stream_byte_count
from .policy import PolicyError, canonical_json, sha256_json, validate_wsl_distro
from .wsl_codex_runtime import sealed_runtime_execution_policy, validate_wsl_codex_binary_path


EXECUTOR_POLICY_VERSION = "sealed-offline-codex-executor-v4"
SUPERVISOR_FRAME_PREFIX = "CODEXGATE_CODEX_SUPERVISOR_V1:"
SUPERVISOR_SCHEMA_VERSION = "1"
SUPERVISOR_BOOTSTRAP_PREFIX = "CODEXGATE_SUPERVISOR_BOOTSTRAP_V1:"
SUPERVISOR_BOOTSTRAP_SCHEMA_VERSION = "1"
SUPERVISOR_BOOTSTRAP_MAX_BYTES = 128 * 1024
WINDOWS_QUOTED_COMMAND_LINE_MAX_BYTES = 8 * 1024
SUPERVISOR_TIMEOUT_SECONDS = 45
SUPERVISOR_OUTPUT_LIMIT_BYTES = 16 * 1024
CODEX_ENDPOINT_DEADLINE_SECONDS = 45
CODEX_CONNECTION_WARNING_MILLISECONDS = 15_000
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_BASE64URL = re.compile(r"^[A-Za-z0-9_-]+$")

SUPERVISOR_STAGES = frozenset({
    "BOOT", "CLAIM_VALIDATE", "SPEC_VALIDATE", "RUNTIME_VALIDATE", "BROKER_SPAWN",
    "BROKER_READY", "RELAY_CODEX_SPAWN", "RESPONSE_VALIDATE", "CLEANUP",
})
RELAY_SPAWN_SUBSTAGES = frozenset({
    "RELAY_BOOT",
    "LOOPBACK_BIND",
    "LOOPBACK_LISTEN",
    "LOOPBACK_READY",
    "BROKER_SOCKET_CONNECT",
    "RUNTIME_BIND_VALIDATE",
    "WORK_FIXTURE_VALIDATE",
    "CODEX_HOME_PREPARE",
    "CONFIG_VALIDATE",
    "CODEX_BINARY_VALIDATE",
    "CODEX_ARGV_VALIDATE",
    "CODEX_SPAWN",
    "LOOPBACK_ACCEPT",
    "CHILD_START",
    "ENV_VALIDATE",
    "SOCKET_VALIDATE",
    "BROKER_CONNECT",
    "READY_EMIT",
})
BOOTSTRAP_SUBSTAGES = frozenset({
    "STDIN_READ", "PAYLOAD_DECODE", "PAYLOAD_SCHEMA", "CODE_HASH_VALIDATE",
    "SPEC_DECODE", "EXEC_PREPARE", "EXEC_CALL",
})
SUPERVISOR_FRAME_FIELDS = frozenset({
    "status", "stage", "substage", "error_code", "process_counts", "cleanup_ok", "implementation_hash",
    "request_count", "request_hash", "response_hash", "output_hash", "sensitive_headers_removed",
    "connection_delay_ms", "connection_delay_warning", "child_stderr_bytes", "child_stderr_sha256", "child_exit_category",
    "prompt_mode", "config_loaded_expected", "argc",
})
SUPERVISOR_PROCESS_FIELDS = ("supervisor", "broker_bwrap", "relay_codex_bwrap", "codex_cli")
SUPERVISOR_BOOTSTRAP_FIELDS = frozenset({
    "schema_version", "claim_id", "implementation_hash", "supervisor_code_b64",
    "supervisor_code_sha256", "supervisor_spec_b64",
})
SUPERVISOR_STATUSES = frozenset({"PASSED", "ERROR", "BLOCKED", "POLICY_VIOLATION"})
RELAY_FRAME_PREFIX = "CODEXGATE_CODEX_RELAY_V1:"
CODEX_CHILD_FRAME_PREFIX = "CODEXGATE_CODEX_CHILD_V1:"
CODEX_CHILD_STAGES = frozenset({
    "SPEC_VALIDATE", "BINARY_VALIDATE", "ENV_VALIDATE", "SPAWN_CALL",
    "SPAWN_CONFIRMED", "STDIN_WRITE", "STDIN_CLOSE", "ENDPOINT_WAIT", "CHILD_EXIT",
})
CODEX_CHILD_FRAME_FIELDS = frozenset({
    "stage", "error_code", "spawn_confirmed", "process_counts", "cleanup_ok", "implementation_hash",
})
RELAY_FRAME_FIELDS = frozenset({
    "status",
    "substage",
    "error_code",
    "codex_cli",
    "request_count",
    "request_hash",
    "response_hash",
    "output_hash",
    "sensitive_headers_removed",
    "connection_delay_ms",
    "connection_delay_warning",
    "child_stderr_bytes",
    "child_stderr_sha256",
    "child_exit_category",
    "prompt_mode",
    "config_loaded_expected",
    "argc",
})
RELAY_FRAME_STATUSES = frozenset({"READY", "PASSED", "ERROR", "BLOCKED", "POLICY_VIOLATION"})

# These fixed process inputs are sealed into the implementation hash.  They
# are never accepted from a UI, API, environment, or caller.
SUCCESS_MARKER = WIRE_SUCCESS_MARKER
FIXED_PROMPT = WIRE_FIXED_PROMPT
FIXED_FAKE_RESPONSE = {
    "id": "sealed-offline-canary",
    "object": "response",
    "output": [{"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": SUCCESS_MARKER}]}],
}
SEALED_CODEX_SUBCOMMAND = "exec"
SEALED_CODEX_MODEL = CUSTOM_PROVIDER_ID
SEALED_CODEX_CONFIG_TRANSPORT = "CODEX_HOME_TOML"
SEALED_CODEX_PROMPT_TRANSPORT = "STDIN"


def build_sealed_codex_argv() -> tuple[str, ...]:
    """Return the one sealed Codex argv token sequence.

    This function is the single canonical builder for:
    - the relay/Codex execution argv,
    - the supervisor validator's expected argv,
    - the launch spec snapshot, and
    - the executor implementation hash.
    """
    return (
        SEALED_CODEX_SUBCOMMAND,
        "--ephemeral",
        "--skip-git-repo-check",
        "--sandbox",
        "read-only",
        "--model",
        SEALED_CODEX_MODEL,
        "-",
    )


def _codex_argv_diagnostic(
    actual: Any, expected: Sequence[str] | None = None
) -> dict[str, int | str] | None:
    """Return only sanitized mismatch metadata for exact token validation."""
    sealed = tuple(build_sealed_codex_argv() if expected is None else expected)
    if not isinstance(actual, (list, tuple)):
        return {"argc": 0, "mismatch_index": 0, "reason_code": "argv_type_invalid"}
    tokens = tuple(actual)
    if any(not isinstance(token, str) for token in tokens):
        index = next(index for index, token in enumerate(tokens) if not isinstance(token, str))
        return {"argc": len(tokens), "mismatch_index": index, "reason_code": "argv_token_type_invalid"}
    if len(tokens) != len(sealed):
        return {"argc": len(tokens), "mismatch_index": min(len(tokens), len(sealed)), "reason_code": "argc_mismatch"}
    for index, (token, expected_token) in enumerate(zip(tokens, sealed)):
        if token != expected_token:
            return {"argc": len(tokens), "mismatch_index": index, "reason_code": "token_mismatch"}
    return None


FIXED_CODEX_ARGV: tuple[str, ...] = build_sealed_codex_argv()
REQUIRED_EXEC_OPTIONS = frozenset({"--ephemeral", "--skip-git-repo-check", "--sandbox", "read-only", "--model", SEALED_CODEX_MODEL, "-"})
FIXED_REQUEST_BODY = build_fixed_request(CUSTOM_PROVIDER_ID, FIXED_PROMPT)
FIXED_REQUEST_BODY_BYTES = canonical_json(FIXED_REQUEST_BODY).encode("utf-8")
EXPECTED_REQUEST_HASH = canonical_request_hash(FIXED_REQUEST_BODY)
EXPECTED_RESPONSE_HASH = fixture_stream_hash()
EXPECTED_CONFIG_HASH = provider_config_hash(canonical_provider_toml())
EXPECTED_PROMPT_HASH = fixed_prompt_hash()
EXPECTED_OUTPUT_HASH = hashlib.sha256(SUCCESS_MARKER.encode("utf-8")).hexdigest()
# The reviewed rust-v0.145.0 exec CLI accepts ``-`` as the forced-stdin
# positional prompt.  The sealed argv uses it with exactly one prompt write;
# both the config provider and selected model remain fixed constants.
PINNED_CODEX_WIRE_CONTRACT_PROVEN = WIRE_CONTRACT_STATUS == "PROVEN"


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
    try:
        request_meta = validate_request(request, expected_model=CUSTOM_PROVIDER_ID, expected_prompt_hash=EXPECTED_PROMPT_HASH)
    except PolicyError as exc:
        raise PolicyError(str(exc)) from exc
    sensitive = any(name.casefold() in {"authorization", "cookie"} or name.casefold().startswith("proxy-") for name in headers)
    clean = sanitize_broker_headers(headers)
    validate_broker_request(method, target, clean, len(body))
    body_hash = hashlib.sha256(body).hexdigest()
    return {
        "request_count": 1,
        "request_hash": request_meta["request_hash"],
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
        "response_hash": EXPECTED_RESPONSE_HASH,
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
""" % (SEALED_LOOPBACK_AUTHORITY, BROKER_REQUEST_PATH, CUSTOM_PROVIDER_ID, fixture_stream_bytes())).encode("utf-8")

RELAY_CODEX_CHILD_CODE = ("""import base64,hashlib,json,os,queue,socket,stat,subprocess,sys,threading,time
HOST=%r; PORT=%d; AUTHORITY=%r; PATH=%r; MODEL=%r; PROMPT=%r; MARKER=%r; ARGV=%r; TOKEN_ENV=%r; CONFIG=%r; CONFIG_HASH=%r; DEADLINE=%d; WARNING=%d; IMPL=sys.argv[1] if len(sys.argv)==2 else ''
def canon(v): return json.dumps(v,ensure_ascii=True,sort_keys=True,separators=(',',':')).encode('utf-8')
def category(exit_code,stderr): return 'CLI_USAGE_ERROR' if exit_code==2 else 'CHILD_EXIT_OTHER'
def emit(status,substage,error=None,request_count=0,request_hash=None,response_hash=None,output_hash=None,sensitive=False,codex_cli=0,delay=0,stderr=b'',exit_category=None):
 global control_error,control_stage
 control_error=error; control_stage={'CONFIG_VALIDATE':'SPEC_VALIDATE','CODEX_HOME_PREPARE':'ENV_VALIDATE','SOCKET_VALIDATE':'ENV_VALIDATE','LOOPBACK_BIND':'ENV_VALIDATE','LOOPBACK_LISTEN':'ENV_VALIDATE','READY_EMIT':'ENV_VALIDATE','CODEX_SPAWN':'CHILD_EXIT','LOOPBACK_ACCEPT':'ENDPOINT_WAIT','BROKER_SOCKET_CONNECT':'ENDPOINT_WAIT'}.get(substage,control_stage)
 payload={'status':status,'substage':substage,'error_code':error,'codex_cli':codex_cli,'request_count':request_count,'request_hash':request_hash,'response_hash':response_hash,'output_hash':output_hash,'sensitive_headers_removed':bool(sensitive),'connection_delay_ms':int(delay),'connection_delay_warning':bool(delay>=WARNING),'child_stderr_bytes':len(stderr),'child_stderr_sha256':hashlib.sha256(stderr).hexdigest() if stderr else None,'child_exit_category':exit_category,'prompt_mode':'STDIN_FORCED','config_loaded_expected':True,'argc':len(ARGV)}
 os.write(2,b'CODEXGATE_CODEX_RELAY_V1:'+base64.urlsafe_b64encode(canon(payload)).rstrip(b'=')+b'\\n')
def control():
 payload={'stage':control_stage,'error_code':control_error,'spawn_confirmed':bool(spawn_confirmed),'process_counts':{'codex_cli':int(bool(spawn_confirmed))},'cleanup_ok':bool(cleanup_ok),'implementation_hash':IMPL}
 os.write(1,b'CODEXGATE_CODEX_CHILD_V1:'+base64.urlsafe_b64encode(canon(payload)).rstrip(b'=')+b'\\n')
listener=None; codex=None; substage='CHILD_START'; control_stage='SPEC_VALIDATE'; control_error=None; spawn_confirmed=False; cleanup_ok=False
try:
 substage='LOOPBACK_BIND'
 listener=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
except Exception:
 emit('ERROR','LOOPBACK_BIND','loopback_bind_failed'); sys.exit(0)
try:
 substage='LOOPBACK_BIND'
 listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); listener.bind((HOST,PORT))
except Exception:
 emit('ERROR','LOOPBACK_BIND','loopback_bind_failed'); sys.exit(0)
try:
 substage='LOOPBACK_LISTEN'
 listener.listen(1); listener.settimeout(None)
except Exception:
 emit('ERROR','LOOPBACK_LISTEN','loopback_listen_failed'); sys.exit(0)
try:
 substage='ENV_VALIDATE'
 codex_home=os.environ.get('CODEX_HOME','')
 config_source='/runtime/sealed/config.toml'; config_path=os.path.join(codex_home,'config.toml')
 try:
  if not os.path.isdir(codex_home) or stat.S_IMODE(os.stat(codex_home).st_mode)!=0o700: raise ValueError('codex_home_mode_invalid')
 except Exception:
  emit('ERROR','CODEX_HOME_PREPARE','codex_home_mode_invalid',exit_category='CODEX_HOME_WRITE_FAILED'); sys.exit(0)
 try:
  with open(config_source,'rb') as fp: config_bytes=fp.read()
 except Exception:
  emit('ERROR','CONFIG_VALIDATE','codex_config_missing',exit_category='CONFIG_LOAD_FAILED'); sys.exit(0)
 if config_bytes!=CONFIG or hashlib.sha256(config_bytes).hexdigest()!=CONFIG_HASH:
  emit('ERROR','CONFIG_VALIDATE','codex_config_invalid',exit_category='CONFIG_LOAD_FAILED'); sys.exit(0)
 if b'model_provider = "'+MODEL.encode('ascii')+b'"\\n' not in config_bytes or b'base_url = "http://'+AUTHORITY.encode('ascii')+b'/v1"\\n' not in config_bytes:
  emit('ERROR','CONFIG_VALIDATE','codex_config_provider_invalid',exit_category='CONFIG_LOAD_FAILED'); sys.exit(0)
 substage='CODEX_HOME_PREPARE'
 try:
  fd=os.open(config_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600); fp=os.fdopen(fd,'wb'); fp.write(config_bytes); fp.flush(); os.fsync(fp.fileno()); fp.close(); os.chmod(config_path,0o600)
 except Exception:
  emit('ERROR','CODEX_HOME_PREPARE','config_copy_failed',exit_category='CODEX_HOME_WRITE_FAILED'); sys.exit(0)
 try:
  tmp_path=os.path.join(codex_home,'tmp'); os.mkdir(tmp_path,0o700); os.chmod(tmp_path,0o700)
  arg0_path=os.path.join(tmp_path,'arg0'); os.mkdir(arg0_path,0o700); os.chmod(arg0_path,0o700)
  if stat.S_IMODE(os.stat(tmp_path).st_mode)!=0o700 or stat.S_IMODE(os.stat(arg0_path).st_mode)!=0o700 or os.path.exists(os.path.join(codex_home,'arg0')): raise ValueError('arg0_init_failed')
 except Exception:
  emit('ERROR','CODEX_HOME_PREPARE','arg0_init_failed',exit_category='ARG0_INIT_FAILED'); sys.exit(0)
 try:
  probe=os.path.join(codex_home,'.codexgate-write-probe'); fd=os.open(probe,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600); os.write(fd,b'1'); os.fsync(fd); os.close(fd); os.unlink(probe)
  dirfd=os.open(codex_home,os.O_RDONLY|os.O_DIRECTORY); os.fsync(dirfd); os.close(dirfd)
  with open(config_path,'rb') as fp: copied_config=fp.read()
  if copied_config!=config_bytes or hashlib.sha256(copied_config).hexdigest()!=CONFIG_HASH or stat.S_IMODE(os.stat(config_path).st_mode)!=0o600: raise ValueError('config_copy_invalid')
 except Exception:
  emit('ERROR','CODEX_HOME_PREPARE','codex_home_write_probe_failed',exit_category='CODEX_HOME_WRITE_FAILED'); sys.exit(0)
 substage='SOCKET_VALIDATE'
 broker_socket='/runtime/broker/broker.sock'; broker_stat=os.lstat(broker_socket)
 if not stat.S_ISSOCK(broker_stat.st_mode) or not os.access(broker_socket,os.R_OK|os.W_OK):
  emit('ERROR','SOCKET_VALIDATE','broker_socket_invalid'); sys.exit(0)
 substage='READY_EMIT'; emit('READY','READY_EMIT')
 substage='CODEX_SPAWN'; control_stage='SPAWN_CALL'
 token=os.urandom(32).hex(); env={'PATH':'/usr/bin:/bin','HOME':'/home/codex','TMPDIR':'/tmp','LANG':'C.UTF-8','CODEX_HOME':os.environ['CODEX_HOME'],TOKEN_ENV:token}
 try:
  codex=subprocess.Popen(['/runtime/codex',*ARGV],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env)
 except FileNotFoundError:
  emit('ERROR','CODEX_SPAWN','codex_binary_missing'); sys.exit(0)
 except PermissionError:
  emit('ERROR','CODEX_SPAWN','codex_permission_denied'); sys.exit(0)
 except Exception:
  emit('ERROR','CODEX_SPAWN','codex_spawn_os_error'); sys.exit(0)
 spawn_confirmed=True; control_stage='SPAWN_CONFIRMED'
 try:
  control_stage='STDIN_WRITE'
  codex.stdin.write(PROMPT); codex.stdin.flush(); codex.stdin.close()
 except Exception:
  emit('ERROR','CODEX_SPAWN','codex_prompt_delivery_failed',codex_cli=1); sys.exit(0)
 control_stage='STDIN_CLOSE'; started=time.monotonic(); events=queue.Queue(); substage='LOOPBACK_ACCEPT'; control_stage='ENDPOINT_WAIT'
 def await_accept():
  try: events.put(('ACCEPT',listener.accept()))
  except Exception: events.put(('ACCEPT_ERROR',None))
 def await_exit():
  try: events.put(('EXIT',codex.wait()))
  except Exception: events.put(('EXIT_ERROR',None))
 threading.Thread(target=await_accept,daemon=True).start(); threading.Thread(target=await_exit,daemon=True).start()
 try: event,value=events.get(timeout=DEADLINE)
 except queue.Empty:
  emit('ERROR','LOOPBACK_ACCEPT','codex_endpoint_not_reached',codex_cli=1,delay=round((time.monotonic()-started)*1000)); sys.exit(0)
 delay=round((time.monotonic()-started)*1000)
 if event=='EXIT':
  out=codex.stdout.read(); err=codex.stderr.read(); error='cli_no_request_exit' if value==0 else 'codex_spawned_early_exit'; control_stage='CHILD_EXIT'; emit('ERROR','CODEX_SPAWN',error,codex_cli=1,delay=delay,stderr=err,exit_category=category(value,err)); sys.exit(0)
 if event!='ACCEPT':
  emit('ERROR','LOOPBACK_ACCEPT','loopback_accept_failed',codex_cli=1,delay=delay); sys.exit(0)
 conn,_=value; raw=conn.recv(262145)
 if len(raw)>262144 or b'\\r\\n\\r\\n' not in raw: emit('POLICY_VIOLATION','LOOPBACK_ACCEPT','request_limit',codex_cli=1); sys.exit(0)
 head,body=raw.split(b'\\r\\n\\r\\n',1); lines=head.decode('ascii','strict').split('\\r\\n')
 if not lines or lines[0]!=('POST '+PATH+' HTTP/1.1'): emit('POLICY_VIOLATION','LOOPBACK_ACCEPT','request_target',codex_cli=1); sys.exit(0)
 headers={}
 for line in lines[1:]:
  if ':' not in line: emit('POLICY_VIOLATION','LOOPBACK_ACCEPT','request_header',codex_cli=1); sys.exit(0)
  name,value=line.split(':',1); headers[name]=value.strip()
 if headers.get('Host')!=AUTHORITY or int(headers.get('Content-Length','-1'))!=len(body): emit('POLICY_VIOLATION','LOOPBACK_ACCEPT','request_host',codex_cli=1); sys.exit(0)
 parsed=json.loads(body.decode('utf-8','strict'))
 if not isinstance(parsed,dict) or parsed.get('model')!=MODEL: emit('POLICY_VIOLATION','LOOPBACK_ACCEPT','request_model',codex_cli=1); sys.exit(0)
 sensitive=any(k.casefold() in ('authorization','cookie') or k.casefold().startswith('proxy-') for k in headers); clean={k:v for k,v in headers.items() if k.casefold() not in ('authorization','cookie') and not k.casefold().startswith('proxy-')}
 try:
  upstream=socket.socket(socket.AF_UNIX); upstream.connect('/runtime/broker/broker.sock')
 except Exception:
  emit('ERROR','BROKER_SOCKET_CONNECT','broker_socket_connect_failed',codex_cli=1); sys.exit(0)
 upstream.sendall(canon({'method':'POST','path':PATH,'host':AUTHORITY,'headers':clean,'body_hex':body.hex()})); reply=upstream.recv(2097153); upstream.close()
 if len(reply)>2097152: emit('POLICY_VIOLATION','BROKER_SOCKET_CONNECT','response_limit',codex_cli=1); sys.exit(0)
 response=bytes.fromhex(json.loads(reply.decode('utf-8','strict'))['body_hex']); conn.sendall(b'HTTP/1.1 200 OK\\r\\nContent-Length: '+str(len(response)).encode('ascii')+b'\\r\\n\\r\\n'+response); conn.close(); listener.close()
 remaining=max(0.1,DEADLINE-(time.monotonic()-started))
 try: codex.wait(timeout=remaining)
 except subprocess.TimeoutExpired:
  emit('ERROR','CODEX_SPAWN','codex_completion_timeout',codex_cli=1,delay=delay); sys.exit(0)
 out=codex.stdout.read(); err=codex.stderr.read()
 if codex.returncode!=0 or out!=MARKER: emit('ERROR','CODEX_SPAWN','codex_marker',codex_cli=1); sys.exit(0)
 control_stage='CHILD_EXIT'; emit('PASSED','CODEX_SPAWN',None,request_count=1,request_hash=hashlib.sha256(body).hexdigest(),response_hash=hashlib.sha256(response).hexdigest(),output_hash=hashlib.sha256(out).hexdigest(),sensitive=bool(sensitive),codex_cli=1,delay=delay,stderr=err)
except Exception:
 emit('ERROR',substage,'relay_child_error',codex_cli=1 if codex is not None else 0); sys.exit(0)
finally:
 if listener is not None:
  try: listener.close()
  except Exception: pass
 if codex is not None and codex.poll() is None:
  try: codex.terminate(); codex.wait(timeout=3)
  except Exception: pass
 cleanup_ok=listener is None or getattr(listener,'fileno',lambda:-1)()==-1
 try: control()
 except Exception: pass
""" % (LOOPBACK_HOST, LOOPBACK_PORT, SEALED_LOOPBACK_AUTHORITY, BROKER_REQUEST_PATH, CUSTOM_PROVIDER_ID, FIXED_PROMPT.encode('utf-8'), SUCCESS_MARKER.encode('utf-8'), list(FIXED_CODEX_ARGV), EPHEMERAL_TOKEN_ENV, canonical_provider_toml(), EXPECTED_CONFIG_HASH, CODEX_ENDPOINT_DEADLINE_SECONDS, CODEX_CONNECTION_WARNING_MILLISECONDS)).encode("utf-8")

_PYTHON_C_ARGS: tuple[str, ...] = ("/usr/bin/python3", "-I", "-S", "-u", "-c")
BROKER_CHILD_ARGV_TEMPLATE: tuple[str, ...] = BWRAP_COMMON_ARGS + (
    "--tmpfs", "/runtime-state", "--dir", "/runtime", "--dir", "/runtime/broker",
    "--bind", "{EXECUTION_SOCKET_DIR}", "/runtime/broker",
    "--setenv", "HOME", "/home/broker",
) + sealed_bwrap_environment_args() + _PYTHON_C_ARGS + ("{BROKER_CHILD_CODE}",)
RELAY_CODEX_CHILD_ARGV_TEMPLATE: tuple[str, ...] = BWRAP_COMMON_ARGS + (
    "--tmpfs", "/runtime-state", "--dir", "/runtime", "--dir", "/runtime/broker", "--dir", "/runtime/sealed", "--perms", "0700", "--tmpfs", "/runtime/codex-home", "--dir", "/work", "--dir", "/home/codex",
    "--ro-bind", "{EXECUTION_SOCKET_DIR}", "/runtime/broker",
    "--ro-bind", "{FIXTURE_SOURCE}", "/work/fixture.json",
    "--ro-bind", "{SEALED_CONFIG_SOURCE}", "/runtime/sealed/config.toml",
    "--ro-bind", "{CODEX_BINARY}", "/runtime/codex", "--chdir", "/work",
    "--setenv", "HOME", "/home/codex",
    "--setenv", "CODEX_HOME", "/runtime/codex-home",
) + sealed_bwrap_environment_args() + _PYTHON_C_ARGS + ("{RELAY_CODEX_CHILD_CODE}", "{EXECUTOR_IMPLEMENTATION_HASH}")
SUPERVISOR_ARGV_TEMPLATE: tuple[str, ...] = (
    "{WSL_EXECUTABLE}", "-d", "Ubuntu", "--exec", "/usr/bin/python3", "-I", "-S", "-u", "-c",
    "{SUPERVISOR_BOOTSTRAP_CODE}", "{EXECUTOR_IMPLEMENTATION_HASH}",
)


def _template_json(value: Sequence[str]) -> str:
    return json.dumps(list(value), ensure_ascii=True, separators=(",", ":"))


# The fixed supervisor is deliberately a single Python program.  Its only
# variable inputs are the already-claimed UUID and the computed seal hash.
# It creates all socket/config/fixture state below its private temporary root,
# terminates children, removes the root, and emits one sanitized frame.
_SUPERVISOR_SOURCE = "\n".join((
    "import base64,hashlib,json,os,re,shutil,stat,subprocess,sys,tempfile,time,uuid",
    f"P={SUPERVISOR_FRAME_PREFIX!r}; CHILD={CODEX_CHILD_FRAME_PREFIX!r}; BROKER={BROKER_CHILD_CODE!r}; RELAY={RELAY_CODEX_CHILD_CODE!r}",
    f"BT=json.loads({_template_json(BROKER_CHILD_ARGV_TEMPLATE)!r}); RT=json.loads({_template_json(RELAY_CODEX_CHILD_ARGV_TEMPLATE)!r})",
    f"CONFIG={canonical_provider_toml()!r}; WIRE_PROVEN={PINNED_CODEX_WIRE_CONTRACT_PROVEN!r}",
    "STAGES={'BOOT','CLAIM_VALIDATE','SPEC_VALIDATE','RUNTIME_VALIDATE','BROKER_SPAWN','BROKER_READY','RELAY_CODEX_SPAWN','RESPONSE_VALIDATE','CLEANUP'}",
    "C_STAGES={'SPEC_VALIDATE','BINARY_VALIDATE','ENV_VALIDATE','SPAWN_CALL','SPAWN_CONFIRMED','STDIN_WRITE','STDIN_CLOSE','ENDPOINT_WAIT','CHILD_EXIT'}",
    "SUBSTAGES={'RELAY_BOOT','CHILD_START','ENV_VALIDATE','SOCKET_VALIDATE','BROKER_CONNECT','LOOPBACK_BIND','LOOPBACK_LISTEN','LOOPBACK_READY','READY_EMIT','BROKER_SOCKET_CONNECT','RUNTIME_BIND_VALIDATE','WORK_FIXTURE_VALIDATE','CODEX_HOME_PREPARE','CONFIG_VALIDATE','CODEX_BINARY_VALIDATE','CODEX_ARGV_VALIDATE','CODEX_SPAWN','LOOPBACK_ACCEPT'}",
    "COUNTS={'supervisor':1,'broker_bwrap':0,'relay_codex_bwrap':0,'codex_cli':0}; PROOF={'request_count':0,'request_hash':None,'response_hash':None,'output_hash':None,'sensitive_headers_removed':False,'connection_delay_ms':0,'connection_delay_warning':False,'child_stderr_bytes':0,'child_stderr_sha256':None,'child_exit_category':None,'prompt_mode':'STDIN_FORCED','config_loaded_expected':True,'argc':" + str(len(FIXED_CODEX_ARGV)) + "}; emitted=False; implementation=sys.argv[2] if len(sys.argv)==4 else ''; spec_arg=sys.argv[3] if len(sys.argv)==4 else ''",
    "def cj(v): return json.dumps(v,ensure_ascii=False,sort_keys=True,separators=(',',':'))",
    "def emit(status,stage,error=None,cleanup_ok=False,substage=None):",
    " global emitted",
    " if emitted: return",
    " emitted=True; payload={'status':status,'stage':stage,'substage':substage,'error_code':error,'process_counts':dict(COUNTS),'cleanup_ok':bool(cleanup_ok),'implementation_hash':implementation,**PROOF}",
    " os.write(1,(P+base64.urlsafe_b64encode(cj(payload).encode('utf-8')).rstrip(b'=').decode('ascii')+'\\n').encode('ascii'))",
    "def materialize(t,v): return [v.get(x,x) for x in t]",
    "def hash_file(path):",
    " h=hashlib.sha256()",
    " with open(path,'rb') as fp:",
    "  while True:",
    "   chunk=fp.read(65536)",
    "   if not chunk: break",
    "   h.update(chunk)",
    " return h.hexdigest()",
    "def argv_diag(actual, expected):",
    " if not isinstance(actual, list): return {'argc':0,'mismatch_index':0,'reason_code':'argv_type_invalid'}",
    " if any(not isinstance(token, str) for token in actual):",
    "  bad=next(index for index, token in enumerate(actual) if not isinstance(token, str))",
    "  return {'argc':len(actual),'mismatch_index':bad,'reason_code':'argv_token_type_invalid'}",
    " if len(actual)!=len(expected): return {'argc':len(actual),'mismatch_index':min(len(actual),len(expected)),'reason_code':'argc_mismatch'}",
    " for index,(token, sealed) in enumerate(zip(actual, expected)):",
    "  if token!=sealed: return {'argc':len(actual),'mismatch_index':index,'reason_code':'token_mismatch'}",
    " return None",
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
    "def parse_child_control(raw):",
    " try: decoded=raw.decode('utf-8','strict').replace('\\r\\n','\\n'); all_lines=[line for line in decoded.split('\\n') if line]",
    " except Exception: raise ValueError('codex_child_control_invalid')",
    " lines=[line for line in all_lines if line.startswith(CHILD)]",
    " if not lines: raise ValueError('codex_child_control_missing')",
    " if len(lines)!=1: raise ValueError('codex_child_control_duplicate')",
    " if any(not line.startswith(CHILD) for line in all_lines): raise ValueError('codex_child_control_invalid')",
    " encoded=lines[0][len(CHILD):]",
    " if not encoded or '=' in encoded or not re.fullmatch(r'[A-Za-z0-9_-]+',encoded): raise ValueError('codex_child_control_invalid')",
    " try: raw_payload=base64.urlsafe_b64decode(encoded+'='*((4-len(encoded)%4)%4)); payload=json.loads(raw_payload.decode('utf-8','strict'))",
    " except Exception: raise ValueError('codex_child_control_invalid')",
    " if not isinstance(payload,dict) or set(payload)!={'stage','error_code','spawn_confirmed','process_counts','cleanup_ok','implementation_hash'}: raise ValueError('codex_child_control_invalid')",
    " if json.dumps(payload,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode('utf-8')!=raw_payload: raise ValueError('codex_child_control_invalid')",
    " if payload.get('stage') not in C_STAGES or not isinstance(payload.get('spawn_confirmed'),bool) or not isinstance(payload.get('cleanup_ok'),bool): raise ValueError('codex_child_control_invalid')",
    " counts=payload.get('process_counts')",
    " if not isinstance(counts,dict) or set(counts)!={'codex_cli'} or counts.get('codex_cli') not in {0,1} or counts['codex_cli']!=int(payload['spawn_confirmed']): raise ValueError('codex_child_control_invalid')",
    " if payload.get('error_code') is not None and (not isinstance(payload.get('error_code'),str) or not re.fullmatch(r'[a-z0-9_]{1,80}',payload['error_code'])): raise ValueError('codex_child_control_invalid')",
    " if not isinstance(payload.get('implementation_hash'),str) or not re.fullmatch(r'[0-9a-f]{64}',payload['implementation_hash']) or payload.get('implementation_hash')!=implementation: raise ValueError('codex_child_control_invalid')",
    " return payload",
    f"def parse_relay_frame(raw,prefix={RELAY_FRAME_PREFIX!r}.encode('ascii')):",
    " try: lines=raw.decode('utf-8','strict').replace('\\r\\n','\\n').split('\\n')",
    " except Exception: raise ValueError('relay_proof_invalid')",
    " lines=[line for line in lines if line]",
    " if any(not line.startswith(prefix.decode('ascii')) for line in lines): raise ValueError('relay_proof_invalid')",
    " if not lines: raise ValueError('relay_proof_missing')",
    " if len(lines)>2: raise ValueError('relay_proof_duplicate')",
    " payloads=[]",
    " for line in lines:",
    "  if not line.startswith(prefix.decode('ascii')): raise ValueError('relay_proof_invalid')",
    "  encoded=line[len(prefix):]",
    "  if not encoded or '=' in encoded or not re.fullmatch(r'[A-Za-z0-9_-]+',encoded): raise ValueError('relay_proof_invalid')",
    "  try: raw_payload=base64.urlsafe_b64decode(encoded+'='*((4-len(encoded)%4)%4)); payload=json.loads(raw_payload.decode('utf-8','strict'))",
    "  except Exception: raise ValueError('relay_proof_invalid')",
    "  if not isinstance(payload,dict) or set(payload)!={'status','substage','error_code','codex_cli','request_count','request_hash','response_hash','output_hash','sensitive_headers_removed','connection_delay_ms','connection_delay_warning','child_stderr_bytes','child_stderr_sha256','child_exit_category','prompt_mode','config_loaded_expected','argc'} or json.dumps(payload,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode('utf-8')!=raw_payload: raise ValueError('relay_proof_invalid')",
    "  if payload.get('status') not in {'READY','PASSED','ERROR','BLOCKED','POLICY_VIOLATION'} or payload.get('substage') not in SUBSTAGES: raise ValueError('relay_proof_invalid')",
    "  if any(isinstance(payload.get(name),bool) or not isinstance(payload.get(name),int) or payload.get(name)<0 for name in ('codex_cli','request_count','connection_delay_ms','child_stderr_bytes')) or not isinstance(payload.get('connection_delay_warning'),bool): raise ValueError('relay_proof_invalid')",
    "  if payload.get('child_stderr_sha256') is not None and (not isinstance(payload.get('child_stderr_sha256'),str) or not re.fullmatch(r'[0-9a-f]{64}',payload.get('child_stderr_sha256'))): raise ValueError('relay_proof_invalid')",
    "  if payload.get('child_exit_category') is not None and payload.get('child_exit_category') not in {'CODEX_HOME_WRITE_FAILED','ARG0_INIT_FAILED','CONFIG_LOAD_FAILED','AUTH_REQUIRED','CLI_USAGE_ERROR','CHILD_EXIT_OTHER'}: raise ValueError('relay_proof_invalid')",
    "  if payload.get('prompt_mode')!='STDIN_FORCED' or payload.get('config_loaded_expected') is not True or isinstance(payload.get('argc'),bool) or not isinstance(payload.get('argc'),int) or payload.get('argc')<1: raise ValueError('relay_proof_invalid')",
    "  if payload.get('status')=='READY' and (payload.get('substage')!='READY_EMIT' or payload.get('error_code') is not None or payload.get('codex_cli')!=0 or payload.get('request_count')!=0): raise ValueError('relay_proof_invalid')",
    "  payloads.append(payload)",
    " if len(payloads)==2:",
    "  if payloads[0].get('status')!='READY' or payloads[1].get('status')=='READY': raise ValueError('relay_proof_invalid')",
    " elif payloads[0].get('status') in {'READY','PASSED'} or payloads[0].get('substage') not in {'LOOPBACK_BIND','LOOPBACK_LISTEN','CODEX_HOME_PREPARE','CONFIG_VALIDATE','SOCKET_VALIDATE'}: raise ValueError('relay_proof_invalid')",
    " return payloads[-1]",
    "root=None; broker=None; relay=None; stage='BOOT'; failed=None; substage=None; cleaned=False",
    "try:",
    " if len(sys.argv)!=4: stage='CLAIM_VALIDATE'; raise ValueError('claim_invalid')",
    " try: uuid.UUID(sys.argv[1])",
    " except Exception: stage='CLAIM_VALIDATE'; raise ValueError('claim_invalid')",
    " if len(implementation)!=64: stage='SPEC_VALIDATE'; raise ValueError('implementation_invalid')",
    " if not WIRE_PROVEN: stage='RUNTIME_VALIDATE'; raise ValueError('codex_wire_contract_unproven')",
    " try: spec=json.loads(base64.urlsafe_b64decode(spec_arg+'='*((4-len(spec_arg)%4)%4)).decode('utf-8','strict'))",
    " except Exception: stage='SPEC_VALIDATE'; raise ValueError('supervisor_spec_invalid')",
    " if not isinstance(spec,dict): stage='SPEC_VALIDATE'; raise ValueError('supervisor_spec_invalid')",
    " root=tempfile.mkdtemp(prefix='cg-codex-'); os.chmod(root,0o700); work=os.path.join(root,'work'); sock=os.path.join(root,'socket'); sealed=os.path.join(root,'sealed'); os.mkdir(work,0o700); os.mkdir(sock,0o700); os.mkdir(sealed,0o700)",
    " fixture=os.path.join(work,'fixture.json'); fp=open(fixture,'wb'); fp.write(b'{\\\"kind\\\":\\\"offline-canary\\\"}\\n'); fp.flush(); os.fsync(fp.fileno()); fp.close(); os.chmod(fixture,0o444)",
    " config=os.path.join(sealed,'config.toml'); fp=open(config,'wb'); fp.write(CONFIG); fp.flush(); os.fsync(fp.fileno()); fp.close(); os.chmod(config,0o400); dirfd=os.open(sealed,os.O_RDONLY|os.O_DIRECTORY); os.fsync(dirfd); os.close(dirfd)",
    " stage='BROKER_SPAWN'; ba=materialize(BT,{'{EXECUTION_SOCKET_DIR}':sock,'{BROKER_CHILD_CODE}':BROKER.decode('utf-8')}); broker=subprocess.Popen(ba,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={}); COUNTS['broker_bwrap']=1",
    " stage='BROKER_READY'; deadline=time.monotonic()+10",
    " while not os.path.exists(os.path.join(sock,'broker.sock')):",
    "  if broker.poll() is not None or time.monotonic()>=deadline: raise TimeoutError('broker_not_ready')",
    "  time.sleep(.02)",
    " stage='RELAY_CODEX_SPAWN'; substage='RUNTIME_BIND_VALIDATE'; binary=spec.get('runtime_binary'); expected_binary_sha=spec.get('runtime_binary_sha256'); expected_config_hash=spec.get('provider_config_hash'); expected_prompt_hash=spec.get('prompt_hash'); expected_request_hash=spec.get('request_hash'); expected_response_hash=spec.get('response_hash'); expected_output_hash=spec.get('output_hash')",
    " if not isinstance(binary,str) or not binary.startswith('/'): raise ValueError('runtime_bind_invalid')",
    " if not all(isinstance(v,str) and len(v)==64 for v in (expected_binary_sha,expected_config_hash,expected_prompt_hash,expected_request_hash,expected_response_hash,expected_output_hash)): raise ValueError('supervisor_spec_invalid')",
    " if not os.path.exists(binary): raise ValueError('runtime_bind_missing')",
    " st=os.lstat(binary)",
    " if not stat.S_ISREG(st.st_mode): raise ValueError('runtime_binary_not_regular')",
    " if stat.S_ISLNK(st.st_mode): raise ValueError('runtime_binary_symlink')",
    " if os.access(binary,os.X_OK) is False: raise ValueError('runtime_binary_not_executable')",
    " substage='WORK_FIXTURE_VALIDATE'",
    " if not os.path.isfile(fixture): raise ValueError('work_fixture_missing')",
    " if bool(os.stat(fixture).st_mode & 0o222): raise ValueError('work_fixture_not_read_only')",
    " substage='CONFIG_VALIDATE'",
    " if not os.path.isfile(config): raise ValueError('codex_config_missing')",
    " if hash_file(config)!=expected_config_hash: raise ValueError('codex_config_hash_mismatch')",
    " substage='CODEX_BINARY_VALIDATE'",
    " if hash_file(binary)!=expected_binary_sha: raise ValueError('runtime_binary_sha_mismatch')",
    " substage='CODEX_ARGV_VALIDATE'; sealed_argv=" + repr(list(build_sealed_codex_argv())),
    " relay_spec=spec.get('relay_codex') if isinstance(spec.get('relay_codex'),dict) else None",
    " argv_reason=argv_diag(spec.get('codex_argv'), sealed_argv) or argv_diag(None if relay_spec is None else relay_spec.get('argv'), sealed_argv)",
    " if argv_reason is not None: raise ValueError('codex_argv_invalid')",
    f" if spec.get('provider_model')!={CUSTOM_PROVIDER_ID!r}: raise ValueError('codex_model_invalid')",
    f" if expected_prompt_hash!={EXPECTED_PROMPT_HASH!r} or expected_request_hash!={EXPECTED_REQUEST_HASH!r}: raise ValueError('codex_prompt_invalid')",
    " substage='CODEX_SPAWN'; ra=materialize(RT,{'{EXECUTION_SOCKET_DIR}':sock,'{FIXTURE_SOURCE}':fixture,'{SEALED_CONFIG_SOURCE}':config,'{CODEX_BINARY}':binary,'{RELAY_CODEX_CHILD_CODE}':RELAY.decode('utf-8'),'{EXECUTOR_IMPLEMENTATION_HASH}':implementation}); relay=subprocess.Popen(ra,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={}); COUNTS['relay_codex_bwrap']=1",
    " out,err=relay.communicate(timeout=30)",
    " if len(out)+len(err)>16384: raise ValueError('output_limit')",
    " try: control=parse_child_control(out)",
    " except ValueError as exc:",
    "  if relay.returncode!=0 and str(exc)=='codex_child_control_missing': raise ValueError('relay_child_transport_error')",
    "  raise",
    " proof=parse_relay_frame(err)",
    " if relay.returncode!=0 and not control.get('error_code') and not control.get('spawn_confirmed'): raise ValueError('relay_child_transport_error')",
    " substage=control.get('stage')",
    " PROOF.update({'connection_delay_ms':proof.get('connection_delay_ms'),'connection_delay_warning':proof.get('connection_delay_warning'),'child_stderr_bytes':proof.get('child_stderr_bytes'),'child_stderr_sha256':proof.get('child_stderr_sha256'),'child_exit_category':proof.get('child_exit_category'),'prompt_mode':proof.get('prompt_mode'),'config_loaded_expected':proof.get('config_loaded_expected'),'argc':proof.get('argc')})",
    " if control.get('spawn_confirmed'): COUNTS['codex_cli']=1",
    " if not control.get('cleanup_ok'): raise ValueError('cleanup_failed')",
    " if not control.get('spawn_confirmed'): raise ValueError(control.get('error_code') or 'codex_spawn_os_error')",
    " if proof.get('status')!='PASSED': raise ValueError(proof.get('error_code') or 'relay_codex_failed')",
    " if proof.get('codex_cli')!=1 or proof.get('request_count')!=1: raise ValueError('codex_spawn_not_proven')",
    " if proof.get('request_hash')!=expected_request_hash or proof.get('response_hash')!=expected_response_hash or proof.get('output_hash')!=expected_output_hash or proof.get('sensitive_headers_removed') is not True: raise ValueError('response_proof_invalid')",
    " COUNTS['codex_cli']=1; PROOF.update({'request_count':1,'request_hash':proof['request_hash'],'response_hash':proof['response_hash'],'output_hash':proof['output_hash'],'sensitive_headers_removed':proof['sensitive_headers_removed']}); stage='RESPONSE_VALIDATE'; substage='CODEX_SPAWN'",
    " stage='CLEANUP'",
    "except TimeoutError as exc: failed='supervisor_timeout'",
    "except subprocess.TimeoutExpired as exc: failed='supervisor_timeout'",
    "except ValueError as exc: failed={'claim_invalid':'claim_invalid','implementation_invalid':'implementation_invalid','supervisor_spec_invalid':'supervisor_spec_invalid','codex_wire_contract_unproven':'codex_wire_contract_unproven','broker_not_ready':'broker_not_ready','runtime_bind_invalid':'runtime_bind_invalid','runtime_bind_missing':'runtime_bind_missing','runtime_binary_not_regular':'runtime_binary_not_regular','runtime_binary_symlink':'runtime_binary_symlink','runtime_binary_not_executable':'runtime_binary_not_executable','work_fixture_missing':'work_fixture_missing','work_fixture_not_read_only':'work_fixture_not_read_only','codex_config_missing':'codex_config_missing','codex_config_hash_mismatch':'codex_config_hash_mismatch','codex_config_invalid':'codex_config_invalid','codex_config_provider_invalid':'codex_config_provider_invalid','runtime_binary_sha_mismatch':'runtime_binary_sha_mismatch','codex_argv_invalid':'codex_argv_invalid','codex_model_invalid':'codex_model_invalid','codex_prompt_invalid':'codex_prompt_invalid','relay_codex_failed':'relay_codex_failed','relay_child_transport_error':'relay_child_transport_error','relay_child_frame_missing':'codex_child_control_missing','relay_child_frame_duplicate':'codex_child_control_duplicate','relay_child_frame_invalid':'codex_child_control_invalid','relay_child_frame_hash_mismatch':'codex_child_control_invalid','codex_child_control_missing':'codex_child_control_missing','codex_child_control_duplicate':'codex_child_control_duplicate','codex_child_control_invalid':'codex_child_control_invalid','codex_child_control_hash_mismatch':'codex_child_control_invalid','relay_proof_missing':'relay_proof_missing','relay_proof_duplicate':'relay_proof_duplicate','relay_proof_invalid':'relay_proof_invalid','codex_home_mode_invalid':'codex_home_mode_invalid','config_copy_failed':'config_copy_failed','codex_home_write_probe_failed':'codex_home_write_probe_failed','codex_home_write_failed':'codex_home_write_failed','arg0_init_failed':'arg0_init_failed','broker_socket_invalid':'broker_socket_invalid','loopback_bind_failed':'loopback_bind_failed','loopback_listen_failed':'loopback_listen_failed','loopback_ready_failed':'loopback_ready_failed','loopback_accept_failed':'loopback_accept_failed','loopback_accept_timeout':'loopback_accept_timeout','codex_endpoint_not_reached':'codex_endpoint_not_reached','broker_socket_connect_failed':'broker_socket_connect_failed','output_limit':'output_limit','codex_spawn_not_proven':'codex_spawn_not_proven','codex_spawn_os_error':'codex_spawn_os_error','codex_binary_missing':'codex_binary_missing','codex_permission_denied':'codex_permission_denied','codex_spawned_early_exit':'codex_spawned_early_exit','codex_prompt_delivery_failed':'codex_prompt_delivery_failed','codex_spawn_timeout':'codex_spawn_timeout','codex_early_exit':'codex_early_exit','cli_no_request_exit':'cli_no_request_exit','codex_marker':'codex_marker','request_limit':'request_limit','request_target':'request_target','request_header':'request_header','request_host':'request_host','request_model':'request_model','response_limit':'response_limit','response_proof_invalid':'response_proof_invalid','cleanup_failed':'cleanup_failed','relay_child_error':'relay_child_error'}.get(str(exc),'supervisor_error')",
    "except Exception: failed='supervisor_error'",
    "finally:",
    " stage='CLEANUP' if failed is None else stage; relay_stopped=stop(relay); broker_stopped=stop(broker); shutil.rmtree(root,ignore_errors=True) if root else None; cleaned=bool(relay_stopped and broker_stopped and (root is None or not os.path.exists(root)))",
    " if failed is not None: emit('ERROR',stage,failed,cleaned,substage)",
    " elif not cleaned: emit('ERROR','CLEANUP','cleanup_failed',False)",
    " else: emit('PASSED','CLEANUP',None,True)",
    "",
))
SUPERVISOR_CODE = _SUPERVISOR_SOURCE.encode("utf-8")


# This is the only Python source placed on the Windows command line.  It
# accepts one bounded canonical payload on stdin, validates it, then runs the
# sealed supervisor with the argv shape it already expects.  It never writes a
# payload, source, argv, or diagnostics verbatim to stdout/stderr.
_SUPERVISOR_BOOTSTRAP_LOGIC = """try:
 import base64 as b,builtins,hashlib as h,json as j,os,re,sys,uuid
 P=%r;Q=%r;M=%d;K=%r;F=re.fullmatch;D=b.urlsafe_b64decode;J=lambda a:j.dumps(a,sort_keys=1,separators=(',',':')).encode();S='STDIN_READ';E='bootstrap_payload_invalid'
 def z(e):
  x=sys.argv[1] if len(sys.argv)==2 and F('[0-9a-f]{64}',sys.argv[1]) else '0'*64
  k='status stage substage error_code process_counts cleanup_ok implementation_hash request_count request_hash response_hash output_hash sensitive_headers_removed connection_delay_ms connection_delay_warning child_stderr_bytes child_stderr_sha256 child_exit_category prompt_mode config_loaded_expected argc'.split();v=['ERROR','BOOT',S,e,{'supervisor':1,'broker_bwrap':0,'relay_codex_bwrap':0,'codex_cli':0},True,x,0,None,None,None,False,0,False,0,None,None,'STDIN_FORCED',True,%d]
  os.write(1,(P+b.urlsafe_b64encode(J(dict(zip(k,v)))).rstrip(b'=').decode()+'\\n').encode())
 y=sys.stdin.buffer.read(M+1)
 if len(y)>M or y.count(b'\\n')!=1 or not y.endswith(b'\\n') or not y.startswith(Q.encode()):raise ValueError()
 S='PAYLOAD_DECODE';v=y[len(Q):-1]
 if not F(br'[A-Za-z0-9_-]+',v):raise ValueError()
 r=D(v+b'='*((4-len(v)%%4)%%4));x=j.loads(r.decode())
 S='PAYLOAD_SCHEMA'
 if J(x)!=r or set(x)!=set(K) or x.get('schema_version')!='1':raise ValueError()
 uuid.UUID(x['claim_id'])
 if not F('[0-9a-f]{64}',x['implementation_hash']) or x['implementation_hash']!=sys.argv[1] or not F('[0-9a-f]{64}',x['supervisor_code_sha256']):raise ValueError()
 s=x['supervisor_code_b64'];q=x['supervisor_spec_b64']
 if not F('[A-Za-z0-9_-]+',s) or not F('[A-Za-z0-9_-]+',q):raise ValueError()
 S='CODE_HASH_VALIDATE';c=D(s+'='*((4-len(s)%%4)%%4))
 if h.sha256(c).hexdigest()!=x['supervisor_code_sha256']:E='bootstrap_code_hash_mismatch';raise ValueError()
 S='SPEC_DECODE';p=D(q+'='*((4-len(q)%%4)%%4));a=j.loads(p.decode())
 if not isinstance(a,dict) or J(a)!=p:raise ValueError()
 S='EXEC_PREPARE';sys.argv=['',x['claim_id'],x['implementation_hash'],q];g={'__name__':'__main__','__file__':'<sealed-supervisor>','__package__':None,'__builtins__':builtins}
 S='EXEC_CALL';exec(compile(c.decode(),'sealed-supervisor','exec'),g)
except BaseException:
 try:z(E)
 except BaseException:pass
""" % (
    SUPERVISOR_FRAME_PREFIX,
    SUPERVISOR_BOOTSTRAP_PREFIX,
    SUPERVISOR_BOOTSTRAP_MAX_BYTES,
    sorted(SUPERVISOR_BOOTSTRAP_FIELDS),
    len(FIXED_CODEX_ARGV),
)
_SUPERVISOR_BOOTSTRAP_SOURCE = "import base64,zlib;exec(zlib.decompress(base64.b85decode(%r)))" % (
    base64.b85encode(zlib.compress(_SUPERVISOR_BOOTSTRAP_LOGIC.encode("utf-8"), 9)),
)
SUPERVISOR_BOOTSTRAP_CODE = _SUPERVISOR_BOOTSTRAP_SOURCE.encode("utf-8")
if len(SUPERVISOR_BOOTSTRAP_CODE) > 2048:  # sealed review invariant
    raise RuntimeError("supervisor bootstrap exceeds command-line budget")


def _digest(value: bytes | str) -> str:
    return hashlib.sha256(value.encode("utf-8") if isinstance(value, str) else value).hexdigest()


def _encode_supervisor_spec(spec: Mapping[str, Any]) -> str:
    raw = canonical_json(dict(spec)).encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _decode_base64url(value: str) -> bytes:
    if not isinstance(value, str) or not value or "=" in value or not _BASE64URL.fullmatch(value):
        raise PolicyError("bootstrap_payload_invalid")
    try:
        return base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))
    except Exception as exc:
        raise PolicyError("bootstrap_payload_invalid") from exc


def parse_supervisor_bootstrap_payload(payload: bytes) -> dict[str, str]:
    """Strictly validate the one-line stdin transport without executing it."""
    if not isinstance(payload, bytes) or len(payload) > SUPERVISOR_BOOTSTRAP_MAX_BYTES:
        raise PolicyError("bootstrap_payload_invalid")
    prefix = SUPERVISOR_BOOTSTRAP_PREFIX.encode("ascii")
    if payload.count(b"\n") != 1 or not payload.endswith(b"\n") or not payload.startswith(prefix):
        raise PolicyError("bootstrap_payload_invalid")
    raw = _decode_base64url(payload[len(prefix):-1].decode("ascii", "strict"))
    try:
        decoded = json.loads(raw.decode("utf-8", "strict"))
    except Exception as exc:
        raise PolicyError("bootstrap_payload_invalid") from exc
    if not isinstance(decoded, dict) or set(decoded) != SUPERVISOR_BOOTSTRAP_FIELDS:
        raise PolicyError("bootstrap_payload_invalid")
    if canonical_json(decoded).encode("utf-8") != raw or decoded.get("schema_version") != SUPERVISOR_BOOTSTRAP_SCHEMA_VERSION:
        raise PolicyError("bootstrap_payload_invalid")
    try:
        uuid.UUID(decoded["claim_id"])
    except (TypeError, ValueError) as exc:
        raise PolicyError("bootstrap_payload_invalid") from exc
    for field in ("implementation_hash", "supervisor_code_sha256"):
        if not isinstance(decoded.get(field), str) or not _DIGEST.fullmatch(decoded[field]):
            raise PolicyError("bootstrap_payload_invalid")
    code = _decode_base64url(decoded.get("supervisor_code_b64"))
    if hashlib.sha256(code).hexdigest() != decoded["supervisor_code_sha256"]:
        raise PolicyError("bootstrap_code_hash_mismatch")
    _decode_base64url(decoded.get("supervisor_spec_b64"))
    return {field: decoded[field] for field in SUPERVISOR_BOOTSTRAP_FIELDS}


def build_supervisor_bootstrap_payload(execution_claim_id: str, supervisor_spec: Mapping[str, Any]) -> bytes:
    try:
        uuid.UUID(execution_claim_id)
    except (TypeError, ValueError) as exc:
        raise PolicyError("canary_execution_claim_invalid") from exc
    payload = {
        "schema_version": SUPERVISOR_BOOTSTRAP_SCHEMA_VERSION,
        "claim_id": execution_claim_id,
        "implementation_hash": EXECUTOR_IMPLEMENTATION_HASH,
        "supervisor_code_b64": base64.urlsafe_b64encode(SUPERVISOR_CODE).rstrip(b"=").decode("ascii"),
        "supervisor_code_sha256": hashlib.sha256(SUPERVISOR_CODE).hexdigest(),
        "supervisor_spec_b64": _encode_supervisor_spec(supervisor_spec),
    }
    encoded = base64.urlsafe_b64encode(canonical_json(payload).encode("utf-8")).rstrip(b"=")
    result = SUPERVISOR_BOOTSTRAP_PREFIX.encode("ascii") + encoded + b"\n"
    parse_supervisor_bootstrap_payload(result)
    return result


def compute_executor_implementation(
    *,
    supervisor_code: bytes = SUPERVISOR_CODE,
    supervisor_bootstrap_code: bytes = SUPERVISOR_BOOTSTRAP_CODE,
    broker_child_code: bytes = BROKER_CHILD_CODE,
    relay_codex_child_code: bytes = RELAY_CODEX_CHILD_CODE,
    broker_argv: Sequence[str] = BROKER_CHILD_ARGV_TEMPLATE,
    relay_codex_argv: Sequence[str] = RELAY_CODEX_CHILD_ARGV_TEMPLATE,
    supervisor_argv: Sequence[str] = SUPERVISOR_ARGV_TEMPLATE,
    codex_argv: Sequence[str] | None = None,
    prompt: str = FIXED_PROMPT,
    fake_response: Mapping[str, Any] = FIXED_FAKE_RESPONSE,
) -> tuple[str, dict[str, str]]:
    """Canonical seal for the review spec and the actual fixed argv source."""
    sealed_codex_argv = tuple(build_sealed_codex_argv() if codex_argv is None else codex_argv)
    components = {
        "supervisor_sha256": _digest(supervisor_code),
        "supervisor_bootstrap_sha256": _digest(supervisor_bootstrap_code),
        "supervisor_bootstrap_schema_sha256": sha256_json(sorted(SUPERVISOR_BOOTSTRAP_FIELDS)),
        "broker_child_sha256": _digest(broker_child_code),
        "relay_codex_child_sha256": _digest(relay_codex_child_code),
        "argv_template_sha256": sha256_json({
            "common": list(BWRAP_COMMON_ARGS), "broker": list(broker_argv),
            "relay_codex": list(relay_codex_argv), "supervisor": list(supervisor_argv), "codex": list(sealed_codex_argv),
        }),
        "prompt_sha256": _digest(prompt),
        "fake_response_sha256": sha256_json(dict(fake_response)),
        "provider_config_sha256": provider_config_hash(canonical_provider_toml()),
        "loopback_endpoint_sha256": sha256_json({"host": LOOPBACK_HOST, "port": LOOPBACK_PORT}),
        "wire_contract_sha256": WIRE_CONTRACT_HASH,
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


def windows_quoted_command_line_bytes(args: Sequence[str]) -> int:
    """Windows uses a quoted UTF-16 command line even when Python receives argv."""
    if any(not isinstance(arg, str) for arg in args):
        raise PolicyError("command_line_too_long")
    return len(subprocess.list2cmdline(list(args)).encode("utf-16-le"))


def build_codex_supervisor_argv(wsl_executable: str) -> list[str]:
    if not isinstance(wsl_executable, str) or not wsl_executable or any(ord(char) < 32 for char in wsl_executable):
        raise PolicyError("wsl_unavailable")
    argv = _materialize_argv(SUPERVISOR_ARGV_TEMPLATE, {
        "{WSL_EXECUTABLE}": wsl_executable,
        "{SUPERVISOR_BOOTSTRAP_CODE}": SUPERVISOR_BOOTSTRAP_CODE.decode("utf-8"),
        "{EXECUTOR_IMPLEMENTATION_HASH}": EXECUTOR_IMPLEMENTATION_HASH,
    })
    if windows_quoted_command_line_bytes(argv) > WINDOWS_QUOTED_COMMAND_LINE_MAX_BYTES:
        raise PolicyError("command_line_too_long")
    return argv


def build_codex_executor_launch_spec(
    binary_path: str, *, runtime_binary_sha256: str | None = None
) -> dict[str, Any]:
    """Private review spec generated only from shared, sealed templates."""
    binary_path = validate_wsl_codex_binary_path(binary_path)
    runtime_policy = sealed_runtime_execution_policy()
    environment = dict(runtime_policy["environment"])
    sealed_codex_argv = list(build_sealed_codex_argv())
    return {
        "backend": "WSL2_BWRAP",
        "supervisor_argv_template": list(SUPERVISOR_ARGV_TEMPLATE),
        "broker_argv_template": list(BROKER_CHILD_ARGV_TEMPLATE),
        "relay_codex_argv_template": list(RELAY_CODEX_CHILD_ARGV_TEMPLATE),
        "codex_argv": list(sealed_codex_argv),
        "broker": {"unshare_all": True, "clearenv": True, "socket": "single_af_unix_pathname", "tmpfs": ["/tmp", "/home", "/runtime-state"]},
        "relay_codex": {
            "unshare_all": True, "clearenv": True, "network": "sealed_loopback_only",
            "socket": "single_af_unix_and_loopback", "work_read_only": True,
            "fixture": "/work/fixture.json", "codex_home": "tmpfs", "runtime_state": "tmpfs",
            "sealed_config": "read_only_source_copy", "tmpfs": ["/tmp", "/home", "/runtime-state", "/runtime/codex-home"], "environment": environment,
            "endpoint": {"host": LOOPBACK_HOST, "port": LOOPBACK_PORT, "path": BROKER_REQUEST_PATH},
            "argv": list(sealed_codex_argv),
            "model": CUSTOM_PROVIDER_ID,
            "codex_home_config": "sealed_source_copy_to_tmpfs",
        },
        "forbidden_binds": ["/mnt", "WINDOWS", "SOURCE_ROOT", "DATA_ROOT", "USER_HOME"],
        "runtime_binary": binary_path,
        "runtime_binary_sha256": runtime_binary_sha256,
        "provider_config_hash": EXPECTED_CONFIG_HASH,
        "request_hash": EXPECTED_REQUEST_HASH,
        "response_hash": EXPECTED_RESPONSE_HASH,
        "prompt_hash": EXPECTED_PROMPT_HASH,
        "output_hash": EXPECTED_OUTPUT_HASH,
        "provider_model": CUSTOM_PROVIDER_ID,
        "wire_contract_hash": WIRE_CONTRACT_HASH,
        "executor_implementation_hash": EXECUTOR_IMPLEMENTATION_HASH,
    }


class CodexExecutorFailure(PolicyError):
    """A sanitized supervisor/transport error with observed provenance only."""

    def __init__(
        self, code: str, *, supervisor_processes: int = 0, bwrap_processes: int = 0,
        codex_processes: int = 0, stage: str | None = None, cleanup_ok: bool | None = None,
        stdout_bytes: int = 0, stderr_bytes: int = 0, exit_code: int | None = None,
        substage: str | None = None,
        connection_delay_ms: int = 0,
        child_exit_category: str | None = None,
        transport: bool = False,
    ):
        super().__init__(code)
        self.stage = stage
        self.substage = substage
        self.connection_delay_ms = max(0, int(connection_delay_ms))
        self.child_exit_category = child_exit_category
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
        self, args: list[str], *, payload: bytes, timeout_seconds: float, on_started: Callable[[], None] | None = None,
    ) -> ProcessResult:
        parse_supervisor_bootstrap_payload(payload)
        try:
            process = await asyncio.create_subprocess_exec(
                *args, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
        except (FileNotFoundError, OSError) as exc:
            code = "command_line_too_long" if getattr(exc, "winerror", None) == 206 or getattr(exc, "errno", None) == errno.E2BIG else "supervisor_transport_error"
            raise CodexExecutorFailure(code, stage="BOOT", transport=True) from exc
        if on_started is not None:
            on_started()
        try:
            await self._write_bootstrap_payload(process, payload)
        except Exception as exc:
            await self._terminate_process_tree(process)
            raise CodexExecutorFailure("payload_write_failed", stage="BOOT", supervisor_processes=1, transport=True) from exc
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
    async def _write_bootstrap_payload(process: asyncio.subprocess.Process, payload: bytes) -> None:
        if process.stdin is None:
            raise RuntimeError("stdin unavailable")
        process.stdin.write(payload)
        await process.stdin.drain()
        process.stdin.close()
        wait_closed = getattr(process.stdin, "wait_closed", None)
        if wait_closed is not None:
            await wait_closed()

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
    substage: str | None
    error_code: str | None
    process_counts: dict[str, int]
    cleanup_ok: bool
    implementation_hash: str
    request_count: int
    request_hash: str | None
    response_hash: str | None
    output_hash: str | None
    sensitive_headers_removed: bool
    connection_delay_ms: int
    connection_delay_warning: bool
    child_stderr_bytes: int
    child_stderr_sha256: str | None
    child_exit_category: str | None
    prompt_mode: str
    config_loaded_expected: bool
    argc: int

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
    value = dict(payload)
    value.setdefault("connection_delay_ms", 0)
    value.setdefault("connection_delay_warning", False)
    value.setdefault("child_stderr_bytes", 0)
    value.setdefault("child_stderr_sha256", None)
    value.setdefault("child_exit_category", None)
    value.setdefault("prompt_mode", "STDIN_FORCED")
    value.setdefault("config_loaded_expected", True)
    value.setdefault("argc", len(FIXED_CODEX_ARGV))
    if set(value) != SUPERVISOR_FRAME_FIELDS:
        raise ValueError("supervisor_frame_fields")
    raw = canonical_json(value).encode("utf-8")
    return SUPERVISOR_FRAME_PREFIX + base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") + "\n"


def _stream_size(value: bytes | str | None) -> int:
    if isinstance(value, bytes):
        return len(value)
    if isinstance(value, str):
        return len(value.encode("utf-8", "replace"))
    return 0


def _frame_failure(
    code: str,
    *,
    stage: str,
    result: ProcessResult,
    counts: Mapping[str, int] | None = None,
    cleanup_ok: bool | None = None,
    substage: str | None = None,
    transport: bool = False,
) -> CodexExecutorFailure:
    observed = dict(counts or {"supervisor": 1, "broker_bwrap": 0, "relay_codex_bwrap": 0, "codex_cli": 0})
    return CodexExecutorFailure(
        code, supervisor_processes=observed.get("supervisor", 0),
        bwrap_processes=observed.get("broker_bwrap", 0) + observed.get("relay_codex_bwrap", 0),
        codex_processes=observed.get("codex_cli", 0), stage=stage, cleanup_ok=cleanup_ok,
        stdout_bytes=_stream_size(result.stdout_bytes if result.stdout_bytes is not None else result.stdout),
        stderr_bytes=_stream_size(result.stderr_bytes if result.stderr_bytes is not None else result.stderr),
        exit_code=result.exit_code, substage=substage, transport=transport,
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
    substage = payload.get("substage")
    if substage is not None:
        valid_bootstrap_stage = stage == "BOOT" and substage in BOOTSTRAP_SUBSTAGES
        valid_relay_stage = stage == "RELAY_CODEX_SPAWN" and substage in RELAY_SPAWN_SUBSTAGES
        if not isinstance(substage, str) or not (valid_bootstrap_stage or valid_relay_stage):
            raise _frame_failure("supervisor_frame_schema_invalid", stage=stage, result=result)
    elif stage == "RELAY_CODEX_SPAWN" and payload.get("status") != "PASSED":
        raise _frame_failure("supervisor_frame_schema_invalid", stage=stage, result=result)
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
    if (
        isinstance(payload.get("connection_delay_ms"), bool)
        or not isinstance(payload.get("connection_delay_ms"), int)
        or payload["connection_delay_ms"] < 0
        or not isinstance(payload.get("connection_delay_warning"), bool)
        or isinstance(payload.get("child_stderr_bytes"), bool)
        or not isinstance(payload.get("child_stderr_bytes"), int)
        or payload["child_stderr_bytes"] < 0
        or not _digest_or_none(payload.get("child_stderr_sha256"))
        or payload.get("child_exit_category") not in {None, "CODEX_HOME_WRITE_FAILED", "ARG0_INIT_FAILED", "CONFIG_LOAD_FAILED", "AUTH_REQUIRED", "CLI_USAGE_ERROR", "CHILD_EXIT_OTHER"}
        or payload.get("prompt_mode") != "STDIN_FORCED"
        or payload.get("config_loaded_expected") is not True
        or isinstance(payload.get("argc"), bool)
        or not isinstance(payload.get("argc"), int)
        or payload.get("argc") != len(FIXED_CODEX_ARGV)
    ):
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
            or not payload["sensitive_headers_removed"] or substage is not None
        ):
            raise _frame_failure(
                "supervisor_success_proof_invalid",
                stage=stage,
                result=result,
                counts=counts,
                cleanup_ok=payload["cleanup_ok"],
                substage=substage,
            )
    if payload["status"] != "PASSED" and error is None:
        raise _frame_failure("supervisor_frame_schema_invalid", stage=stage, result=result)
    return _SupervisorFrame(
        payload["status"], stage, substage, error, dict(counts), payload["cleanup_ok"], payload["implementation_hash"],
        request_count, payload["request_hash"], payload["response_hash"], payload["output_hash"], payload["sensitive_headers_removed"],
        payload["connection_delay_ms"], payload["connection_delay_warning"], payload["child_stderr_bytes"],
        payload["child_stderr_sha256"], payload["child_exit_category"], payload["prompt_mode"],
        payload["config_loaded_expected"], payload["argc"],
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
        spec = build_codex_executor_launch_spec(
            binary_path, runtime_binary_sha256=binding.get("binary_sha256")
        )
        if spec["executor_implementation_hash"] != binding.get("implementation_hash"):
            raise PolicyError("canary_implementation_mismatch")
        if spec.get("wire_contract_hash") != WIRE_CONTRACT_HASH or canary_launch_spec.get("wire_contract_hash") != WIRE_CONTRACT_HASH:
            raise PolicyError("codex_wire_contract_mismatch")
        if WIRE_CONTRACT_STATUS != "PROVEN" and isinstance(self.runner, SealedWSLSupervisorRunner):
            raise PolicyError("codex_wire_contract_unproven")
        if canary_launch_spec.get("contract_hash") != binding.get("contract_hash") or provider_config_hash(canonical_provider_toml()) != binding.get("config_hash"):
            raise PolicyError("execution_binding_changed")
        if validate_wsl_distro(self.store.wsl_isolation_config().get("distro")) != "Ubuntu":
            raise PolicyError("distro_not_ubuntu")
        wsl_executable = self.runner.find_wsl()
        if not wsl_executable:
            raise PolicyError("wsl_unavailable")
        argv = build_codex_supervisor_argv(wsl_executable)
        payload = build_supervisor_bootstrap_payload(self.execution_claim_id, spec)
        self.store.reserve_codex_canary_supervisor_spawn(self.execution_claim_id, binding)
        self.calls += 1
        try:
            process = await self.runner.run(
                argv, payload=payload, timeout_seconds=SUPERVISOR_TIMEOUT_SECONDS,
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
                codex_processes=frame.codex_processes, cleanup_ok=frame.cleanup_ok, substage=frame.substage,
                connection_delay_ms=frame.connection_delay_ms, child_exit_category=frame.child_exit_category,
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
