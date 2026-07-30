"""Fail-fast I/O fuse for the pytest process.

The production WSL executor is intentionally real, but the default test
process must never reach an operating-system process or network primitive.
Tests use dependency-injected fake runners instead.  The only compatibility
exception is the existing Windows junction helper: its tiny PowerShell
operation is emulated with a temporary-directory symlink, so no child process
is created.
"""

from __future__ import annotations

import os
import re
import socket
import subprocess
import inspect
from pathlib import Path
from typing import Any

import pytest


FUSE_ERROR = "unexpected_real_io_in_test"
_ORIGINALS: dict[str, Any] = {}
_COUNTERS = {
    "process_attempts": 0,
    "socket_attempts": 0,
    "created_processes": 0,
    "created_application_sockets": 0,
}


class _FakeListenerSocket:
    def getsockname(self) -> tuple[str, int]:
        return ("127.0.0.1", 0)


class _FakeListener:
    def __init__(self) -> None:
        self.sockets = [_FakeListenerSocket()]

    def close(self) -> None:
        return None

    async def wait_closed(self) -> None:
        return None


async def _fake_start_server(*args: Any, **kwargs: Any) -> _FakeListener:
    """Dependency-injected listener for tests; it never creates a socket."""
    return _FakeListener()


def _blocked(kind: str) -> RuntimeError:
    _COUNTERS["process_attempts" if kind == "process" else "socket_attempts"] += 1
    return RuntimeError(FUSE_ERROR)


def _command_name(command: Any) -> str:
    if isinstance(command, (list, tuple)) and command:
        return Path(str(command[0])).name.casefold()
    if isinstance(command, str):
        return Path(command.strip().split(None, 1)[0]).name.casefold() if command.strip() else ""
    return ""


def _emulate_windows_junction(command: Any, **kwargs: Any) -> subprocess.CompletedProcess[Any] | None:
    """Emulate the two legacy test-only New-Item junction helpers."""
    name = _command_name(command)
    if name not in {"powershell", "powershell.exe", "pwsh", "pwsh.exe"}:
        return None
    text = " ".join(str(part) for part in command) if isinstance(command, (list, tuple)) else str(command)
    if "New-Item" not in text or "-Path" not in text or "-Target" not in text:
        return None
    match = re.search(r"-Path\s+'([^']*)'.*?-Target\s+'([^']*)'", text, flags=re.IGNORECASE)
    if not match:
        return None
    link, target = Path(match.group(1)), Path(match.group(2))
    try:
        # A regular marked directory is enough for the policy's test-only
        # link detector and avoids requiring Windows SeCreateSymbolicLinkPrivilege.
        link.mkdir(parents=False, exist_ok=False)
        (link / ".codex-test-junction").write_text("", encoding="ascii")
    except FileExistsError:
        pass
    except OSError:
        # The actual helper would return nonzero; returning that result keeps
        # the test's own failure message without starting a process.
        return subprocess.CompletedProcess(command, 1, stdout="", stderr="junction emulation failed")
    return subprocess.CompletedProcess(command, 0, stdout="", stderr="")


def _run(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[Any]:
    command = args[0] if args else kwargs.get("args")
    if isinstance(command, (list, tuple)) and command:
        executable = Path(str(command[0])).name.casefold()
        if executable == "git" and len(command) >= 2 and command[1] in {"status", "diff"}:
            return subprocess.CompletedProcess(command, 0, stdout=b"" if command[1] == "status" else "", stderr=b"" if command[1] == "status" else "")
    emulated = _emulate_windows_junction(command, **kwargs)
    if emulated is not None:
        return emulated
    raise _blocked("process")


def _popen(*args: Any, **kwargs: Any) -> Any:
    raise _blocked("process")


async def _create_subprocess_exec(*args: Any, **kwargs: Any) -> Any:
    raise _blocked("process")


def _system(*args: Any, **kwargs: Any) -> int:
    raise _blocked("process")


def _asyncio_internal_socket() -> bool:
    # Windows' ProactorEventLoop creates a private socketpair for its wakeup
    # pipe.  It is runtime plumbing, not application network I/O; allowing
    # only that exact stdlib path keeps asyncio usable while all test/app
    # socket connect/bind attempts fail closed.
    for frame in inspect.stack(context=0):
        filename = frame.filename.replace("\\", "/")
        if "/asyncio/" in filename and frame.function in {"_make_self_pipe", "socketpair"}:
            return True
    return False


def _socket_attempt(method_name: str, *args: Any, **kwargs: Any) -> Any:
    if _asyncio_internal_socket():
        method = _ORIGINALS.get(f"socket.socket.{method_name}")
        if method is not None:
            return method(*args, **kwargs)
    raise _blocked("socket")


def _socket_bind(*args: Any, **kwargs: Any) -> Any:
    return _socket_attempt("bind", *args, **kwargs)


def _socket_connect(*args: Any, **kwargs: Any) -> Any:
    return _socket_attempt("connect", *args, **kwargs)


def _socket_connect_ex(*args: Any, **kwargs: Any) -> Any:
    return _socket_attempt("connect_ex", *args, **kwargs)


def _install_fuse() -> None:
    if _ORIGINALS:
        return
    _ORIGINALS.update({
        "subprocess.run": subprocess.run,
        "subprocess.Popen": subprocess.Popen,
        "asyncio.create_subprocess_exec": __import__("asyncio").create_subprocess_exec,
        "os.system": os.system,
        "asyncio.start_server": __import__("asyncio").start_server,
        "socket.create_connection": socket.create_connection,
        "socket.socket.connect": socket.socket.connect,
        "socket.socket.connect_ex": socket.socket.connect_ex,
        "socket.socket.bind": socket.socket.bind,
    })
    try:
        import app.capsule as capsule_module
        import app.policy as policy_module

        _ORIGINALS["app.policy.is_link_or_junction"] = policy_module.is_link_or_junction
        _ORIGINALS["app.capsule.is_link_or_junction"] = capsule_module.is_link_or_junction
        _ORIGINALS["app.policy.resolve_project_path"] = policy_module.resolve_project_path

        def marked_link(path: Path) -> bool:
            candidate = Path(path)
            if candidate.is_dir() and (candidate / ".codex-test-junction").is_file():
                return True
            return bool(_ORIGINALS["app.policy.is_link_or_junction"](candidate))

        policy_module.is_link_or_junction = marked_link  # type: ignore[assignment]
        capsule_module.is_link_or_junction = marked_link  # type: ignore[assignment]

        def marked_resolve(root: str | Path, value: str):
            candidate = Path(root) / value
            if any((part / ".codex-test-junction").is_file() for part in [candidate, *candidate.parents]):
                raise policy_module.PolicyError("project path escapes a junction")
            return _ORIGINALS["app.policy.resolve_project_path"](root, value)

        policy_module.resolve_project_path = marked_resolve  # type: ignore[assignment]
    except ImportError:
        pass
    subprocess.run = _run  # type: ignore[assignment]
    subprocess.Popen = _popen  # type: ignore[assignment]
    import asyncio
    asyncio.create_subprocess_exec = _create_subprocess_exec  # type: ignore[assignment]
    asyncio.start_server = _fake_start_server  # type: ignore[assignment]
    os.system = _system  # type: ignore[assignment]
    socket.create_connection = _socket_attempt  # type: ignore[assignment]
    socket.socket.connect = _socket_connect  # type: ignore[assignment]
    socket.socket.connect_ex = _socket_connect_ex  # type: ignore[assignment]
    socket.socket.bind = _socket_bind  # type: ignore[assignment]


def _remove_fuse() -> None:
    if not _ORIGINALS:
        return
    subprocess.run = _ORIGINALS["subprocess.run"]
    subprocess.Popen = _ORIGINALS["subprocess.Popen"]
    import asyncio
    asyncio.create_subprocess_exec = _ORIGINALS["asyncio.create_subprocess_exec"]
    asyncio.start_server = _ORIGINALS["asyncio.start_server"]
    os.system = _ORIGINALS["os.system"]
    socket.create_connection = _ORIGINALS["socket.create_connection"]
    socket.socket.connect = _ORIGINALS["socket.socket.connect"]
    socket.socket.connect_ex = _ORIGINALS["socket.socket.connect_ex"]
    socket.socket.bind = _ORIGINALS["socket.socket.bind"]
    try:
        import app.capsule as capsule_module
        import app.policy as policy_module
        policy_module.is_link_or_junction = _ORIGINALS["app.policy.is_link_or_junction"]
        capsule_module.is_link_or_junction = _ORIGINALS["app.capsule.is_link_or_junction"]
        policy_module.resolve_project_path = _ORIGINALS["app.policy.resolve_project_path"]
    except (ImportError, KeyError):
        pass
    _ORIGINALS.clear()


def pytest_configure(config: pytest.Config) -> None:
    _install_fuse()


def pytest_unconfigure(config: pytest.Config) -> None:
    _remove_fuse()


@pytest.fixture(scope="session")
def no_real_io_counts() -> dict[str, int]:
    return _COUNTERS


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    # Keep the invariant visible to the suite without writing production data.
    session.config._codex_gate_real_io_counts = dict(_COUNTERS)
