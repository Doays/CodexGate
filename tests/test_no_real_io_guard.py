from __future__ import annotations

import asyncio
import os
import socket
import subprocess

import pytest


def test_subprocess_run_fails_before_os_spawn():
    with pytest.raises(RuntimeError, match="unexpected_real_io_in_test"):
        subprocess.run(["wsl.exe", "--version"], check=False)


def test_popen_fails_before_os_spawn():
    with pytest.raises(RuntimeError, match="unexpected_real_io_in_test"):
        subprocess.Popen(["bwrap", "--version"])


def test_async_subprocess_fails_before_os_spawn():
    async def attempt():
        await asyncio.create_subprocess_exec("codex", "--version")

    with pytest.raises(RuntimeError, match="unexpected_real_io_in_test"):
        asyncio.run(attempt())


def test_os_system_fails_before_os_spawn():
    with pytest.raises(RuntimeError, match="unexpected_real_io_in_test"):
        os.system("wsl.exe --version")


def test_socket_connect_and_bind_fail_before_os_io():
    # Invoke the guarded methods with a sentinel receiver.  No socket object
    # is constructed merely to test that connect/bind fail before OS I/O.
    with pytest.raises(RuntimeError, match="unexpected_real_io_in_test"):
        socket.socket.connect(object(), ("127.0.0.1", 9))
    with pytest.raises(RuntimeError, match="unexpected_real_io_in_test"):
        socket.socket.bind(object(), ("127.0.0.1", 0))


def test_create_connection_fails_before_os_io():
    with pytest.raises(RuntimeError, match="unexpected_real_io_in_test"):
        socket.create_connection(("127.0.0.1", 9))


def test_default_suite_counter_is_only_guarded_attempts(no_real_io_counts):
    assert no_real_io_counts["process_attempts"] >= 0
    assert no_real_io_counts["socket_attempts"] >= 0
    assert no_real_io_counts["created_processes"] == 0
    assert no_real_io_counts["created_application_sockets"] == 0
