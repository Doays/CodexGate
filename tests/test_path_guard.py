from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from app.policy import PolicyError, forbidden_workspace_reason, parse_git_porcelain_v2_z, resolve_project_path, validate_project_file, validate_workspace_root


def test_relative_and_absolute_paths_must_stay_inside_root(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    target = root / "src" / "api.py"
    target.parent.mkdir()
    target.write_text("x", encoding="utf-8")
    assert validate_project_file(root, "src/api.py", ["src/api.py"], []) == "src/api.py"
    assert validate_project_file(root, str(target), ["src/api.py"], []) == "src/api.py"
    with pytest.raises(PolicyError):
        resolve_project_path(root, "../outside.py")
    with pytest.raises(PolicyError):
        resolve_project_path(root, "C:/outside.py")


def test_forbidden_file_wins_over_allowed_and_case_is_normalized(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    with pytest.raises(PolicyError):
        validate_project_file(root, "SRC/Api.py", ["src/api.py"], ["src/api.py"])


def _quote_for_powershell(value):
    return str(value).replace("'", "''")


def _create_junction(link, target):
    if os.name != "nt":
        pytest.fail("Windows junction support is required for this test")
    script = (
        f"New-Item -ItemType Junction -Path '{_quote_for_powershell(link)}' "
        f"-Target '{_quote_for_powershell(target)}' | Out-Null"
    )
    result = subprocess.run(["powershell", "-NoProfile", "-Command", script], capture_output=True, text=True)
    if result.returncode != 0:
        pytest.fail(f"junction creation failed: {result.stderr or result.stdout}")


def test_windows_junction_escape_is_rejected(tmp_path):
    root = tmp_path / "project"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    link = root / "linked"
    _create_junction(link, outside)
    with pytest.raises(PolicyError):
        resolve_project_path(root, "linked/secret.txt")


def test_git_porcelain_v2_z_parser_handles_spaces_quotes_and_renames():
    payload = (
        b'1 .M N... 100644 100644 100644 aaaaaaa bbbbbbb folder/quoted "name".txt\0'
        b"2 R. N... 100644 100644 100644 aaaaaaa bbbbbbb 100 old path.txt\0new path.txt\0"
        b"? untracked file with spaces.txt\0"
    )
    paths = parse_git_porcelain_v2_z(payload)
    assert 'folder/quoted "name".txt' in paths
    assert "new path.txt" in paths
    assert "old path.txt" in paths
    assert "untracked file with spaces.txt" in paths


def test_forbidden_workspace_blocks_parent_same_and_child_paths_with_windows_semantics():
    forbidden = [Path(r"E:\.codex")]
    assert "blocked" in forbidden_workspace_reason(r"E:\\", forbidden)
    assert "blocked" in forbidden_workspace_reason(r"E:\.codex", forbidden)
    assert "blocked" in forbidden_workspace_reason(r"e:\.CODEX\cache", forbidden)
    assert forbidden_workspace_reason(r"E:\OtherProject", forbidden) is None


def test_windows_absolute_workspace_string_is_rejected_on_non_windows():
    if os.name == "nt":
        assert forbidden_workspace_reason(r"E:\OtherProject", [Path(r"E:\.codex")]) is None
    else:
        with pytest.raises(PolicyError, match="Windows absolute workspace paths"):
            validate_workspace_root(r"E:\OtherProject")
