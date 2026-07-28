from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import app.main as app_main
import app.capsule as capsule_module
from app.capsule import (
    CapsuleBuilder,
    MAX_CAPSULE_BYTES,
    MAX_FULL_FILE_BYTES,
    MAX_SINGLE_LINE_BYTES,
    create_evidence_capsule,
)
from app.gateway import Gate
from app.policy import PolicyError
from app.storage import Store


MODELS = [{
    "id": "gpt-terra",
    "model": "gpt-terra",
    "displayName": "Terra",
    "hidden": False,
    "defaultReasoningEffort": "high",
    "supportedReasoningEfforts": [
        {"reasoningEffort": "medium"},
        {"reasoningEffort": "high"},
        {"reasoningEffort": "xhigh"},
    ],
}]


class NoRpcClient:
    def __init__(self):
        self.requests: list[tuple[str, dict]] = []

    async def request(self, method, params):
        self.requests.append((method, params))
        raise AssertionError("Evidence Capsule creation must not call app-server")


def decision(**updates):
    value = {
        "decision": "execute",
        "task_class": "T3",
        "recommended_model": "gpt-terra",
        "recommended_effort": "high",
        "allowed_files": [],
        "forbidden_files": [],
        "validation_commands": [],
        "stop_conditions": [],
        "evidence_files": [],
        "evidence_ranges": [],
        "risk": "medium",
        "parallel_audit": False,
        "independent_axes": 0,
    }
    value.update(updates)
    return value


def make_gate(tmp_path: Path) -> Gate:
    store = Store(tmp_path / "data")
    store.save_model_catalog(MODELS)
    gate = Gate(store)
    gate.client = NoRpcClient()
    return gate


def make_plan(gate: Gate, root: Path, ttl_seconds: int = 600, **updates):
    payload = {
        "project_name": "Evidence Demo",
        "project_id": "evidence-demo",
        "root": str(root),
        "task": "Inspect only the sealed evidence.",
        "decision": decision(),
        "permission": "read-only",
        "explicit_ultra_approval": False,
    }
    payload.update(updates)
    return gate.create_route_plan(payload, ttl_seconds=ttl_seconds)


def capsule_dir(gate: Gate, plan: dict) -> Path:
    result = gate.store.load_evidence_capsule(plan["plan_id"])
    assert result is not None
    return gate.store.root / "capsules" / plan["plan_id"] / result["capsule_id"]


def test_exact_relative_evidence_is_hashed_and_captured_without_source_mutation(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    source = root / "src.py"
    source.write_text("answer = 42\n", encoding="utf-8")
    original_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    gate = make_gate(tmp_path)

    plan = make_plan(gate, root, decision=decision(evidence_files=["src.py"]))
    result = create_evidence_capsule(gate.store, plan["plan_id"])

    assert plan["status"] == "PREVIEW"
    assert plan["evidence_files"] == ["src.py"]
    assert plan["evidence_sources"] == [{"path": "src.py", "sha256": original_hash, "size": 13}]
    assert plan["evidence_sources"][0]["size"] == source.stat().st_size == len(source.read_bytes())
    assert result["status"] == "READY"
    assert source.read_text(encoding="utf-8") == "answer = 42\n"
    assert hashlib.sha256(source.read_bytes()).hexdigest() == original_hash
    manifest = json.loads((capsule_dir(gate, plan) / "EVIDENCE_MANIFEST.json").read_text(encoding="utf-8"))
    assert manifest["evidence"][0]["path"] == "src.py"
    assert manifest["evidence"][0]["mode"] == "full"
    assert (capsule_dir(gate, plan) / "files" / "src.py").read_text(encoding="utf-8") == "answer = 42\n"


@pytest.mark.parametrize("entry", ["*.py", "folder", "../outside.py"])
def test_glob_directory_and_escape_evidence_scopes_hold(tmp_path, entry):
    root = tmp_path / "project"
    root.mkdir()
    (root / "folder").mkdir()
    gate = make_gate(tmp_path)

    plan = make_plan(gate, root, decision=decision(evidence_files=[entry]))

    assert plan["status"] == "HOLD"
    assert any("evidence_files" in reason for reason in plan["hold_reasons"])


def test_absolute_and_forbidden_windows_evidence_scopes_hold_without_reading_them(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    local_absolute = root / "local.py"
    local_absolute.write_text("x\n", encoding="utf-8")
    gate = make_gate(tmp_path)
    for entry in (str(local_absolute), r"E:\\", r"E:\\.codex\\config.toml"):
        plan = make_plan(gate, root, decision=decision(evidence_files=[entry]))
        assert plan["status"] == "HOLD"
        assert plan["evidence_sources"] == []


def _create_link_or_junction(link: Path, target: Path) -> None:
    if os.name == "nt":
        quote = lambda value: str(value).replace("'", "''")
        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                f"New-Item -ItemType Junction -Path '{quote(link)}' -Target '{quote(target)}' | Out-Null",
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            pytest.fail(f"junction creation failed: {result.stderr or result.stdout}")
        return
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError as exc:
        pytest.fail(f"symlink creation failed: {exc}")


def test_symlink_or_junction_evidence_escape_is_held_without_following_target(tmp_path):
    root = tmp_path / "project"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (outside / "secret.txt").write_text("must not be read", encoding="utf-8")
    _create_link_or_junction(root / "linked", outside)
    gate = make_gate(tmp_path)

    plan = make_plan(gate, root, decision=decision(evidence_files=["linked/secret.txt"]))

    assert plan["status"] == "HOLD"
    assert any("symlink or junction" in reason for reason in plan["hold_reasons"])


def test_changed_source_sha_marks_capsule_invalid(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    source = root / "source.py"
    source.write_text("one\n", encoding="utf-8")
    gate = make_gate(tmp_path)
    plan = make_plan(gate, root, decision=decision(evidence_files=["source.py"]))
    source.write_text("two\n", encoding="utf-8")

    result = create_evidence_capsule(gate.store, plan["plan_id"])

    assert result["status"] == "INVALID"
    assert result["capsule_hash"] is None
    assert "SHA-256" in result["hold_reasons"][0]


def test_full_file_and_total_capsule_limits_hold_instead_of_truncating(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    oversized = root / "oversized.txt"
    oversized.write_bytes(b"a" * (MAX_FULL_FILE_BYTES + 1))
    gate = make_gate(tmp_path)
    plan = make_plan(gate, root, decision=decision(evidence_files=["oversized.txt"]))
    assert create_evidence_capsule(gate.store, plan["plan_id"])["status"] == "HOLD"

    names = []
    for index in range(9):
        name = f"source-{index}.txt"
        (root / name).write_bytes(b"b" * MAX_FULL_FILE_BYTES)
        names.append(name)
    total_plan = make_plan(gate, root, decision=decision(evidence_files=names))
    result = create_evidence_capsule(gate.store, total_plan["plan_id"])
    assert result["status"] == "HOLD"
    assert str(MAX_CAPSULE_BYTES) in result["hold_reasons"][0]


def test_total_file_limit_counts_metadata_and_never_creates_a_partial_capsule(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    names = []
    for index in range(13):
        name = f"evidence-{index}.txt"
        (root / name).write_text("x\n", encoding="utf-8")
        names.append(name)
    gate = make_gate(tmp_path)
    plan = make_plan(gate, root, decision=decision(evidence_files=names))

    result = create_evidence_capsule(gate.store, plan["plan_id"])

    assert result["status"] == "HOLD"
    assert "maximum is 15" in result["hold_reasons"][0]
    assert not (gate.store.root / "capsules" / plan["plan_id"]).exists()


def test_ranges_are_merged_deterministically_and_keep_original_line_numbers(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    source = root / "source.py"
    source.write_text("".join(f"line-{index}\n" for index in range(1, 9)), encoding="utf-8")
    gate = make_gate(tmp_path)
    plan = make_plan(gate, root, decision=decision(evidence_ranges=[
        {"path": "source.py", "start_line": 4, "end_line": 6},
        {"path": "source.py", "start_line": 1, "end_line": 4},
    ]))

    result = create_evidence_capsule(gate.store, plan["plan_id"])

    assert plan["evidence_ranges"] == [{"path": "source.py", "start_line": 1, "end_line": 6}]
    assert result["status"] == "READY"
    manifest = json.loads((capsule_dir(gate, plan) / "EVIDENCE_MANIFEST.json").read_text(encoding="utf-8"))
    entry = manifest["evidence"][0]
    assert entry["line_ranges"] == [{"start_line": 1, "end_line": 6}]
    snippet = (capsule_dir(gate, plan) / entry["capsule_path"]).read_text(encoding="utf-8")
    assert "1: line-1" in snippet and "6: line-6" in snippet


@pytest.mark.parametrize("name,payload", [("binary.bin", b"a\0b"), ("legacy.txt", b"\xff\xfe")])
def test_binary_and_unsupported_encoding_sources_hold_without_copying_raw_bytes(tmp_path, name, payload):
    root = tmp_path / "project"
    root.mkdir()
    (root / name).write_bytes(payload)
    gate = make_gate(tmp_path)
    plan = make_plan(gate, root, decision=decision(evidence_files=[name]))

    result = create_evidence_capsule(gate.store, plan["plan_id"])

    assert result["status"] == "HOLD"
    assert not (gate.store.root / "capsules" / plan["plan_id"]).exists()


def test_capsule_hash_is_deterministic_and_uses_no_app_server_rpc(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "source.py").write_text("x = 1\n", encoding="utf-8")
    gate = make_gate(tmp_path)
    plan = make_plan(gate, root, decision=decision(evidence_files=["source.py"]))

    first = create_evidence_capsule(gate.store, plan["plan_id"])
    second = create_evidence_capsule(gate.store, plan["plan_id"])

    assert first["status"] == second["status"] == "READY"
    assert (first["capsule_id"], first["capsule_hash"]) == (second["capsule_id"], second["capsule_hash"])
    assert gate.client.requests == []


def test_nested_capsule_files_revalidate_without_directory_false_positives(tmp_path):
    root = tmp_path / "project"
    source = root / "src" / "nested" / "source.py"
    source.parent.mkdir(parents=True)
    source.write_text("x = 1\n", encoding="utf-8")
    gate = make_gate(tmp_path)
    plan = make_plan(gate, root, decision=decision(evidence_files=["src/nested/source.py"]))

    first = create_evidence_capsule(gate.store, plan["plan_id"])
    second = create_evidence_capsule(gate.store, plan["plan_id"])

    assert first["status"] == second["status"] == "READY"


def test_capsule_api_uses_only_the_store_and_never_starts_app_server(tmp_path, monkeypatch):
    root = tmp_path / "project"
    root.mkdir()
    (root / "source.py").write_text("x = 1\n", encoding="utf-8")
    data_root = tmp_path / "data"
    setup_gate = Gate(Store(data_root))
    setup_gate.store.save_model_catalog(MODELS)
    plan = make_plan(setup_gate, root, decision=decision(evidence_files=["source.py"]))
    monkeypatch.setattr(app_main, "DATA_ROOT", data_root)

    with TestClient(app_main.app, base_url="http://127.0.0.1:8787") as client:
        response = client.post(f"/api/route-plans/{plan['plan_id']}/capsule")
        assert response.status_code == 200
        assert response.json()["status"] == "READY"
        assert set(response.json()) == {
            "status", "total_bytes", "file_count", "evidence_fingerprint", "hold_reasons",
        }
        assert client.app.state.gate.client.process is None


def _make_ready_capsule(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "source.py").write_text("value = 1\n", encoding="utf-8")
    gate = make_gate(tmp_path)
    plan = make_plan(gate, root, decision=decision(evidence_files=["source.py"]))
    result = create_evidence_capsule(gate.store, plan["plan_id"])
    assert result["status"] == "READY"
    return gate, plan, capsule_dir(gate, plan)


@pytest.mark.parametrize("mutation", ["content", "manifest", "missing", "extra"])
def test_ready_capsule_tampering_is_invalidated_on_recheck(tmp_path, mutation):
    gate, plan, directory = _make_ready_capsule(tmp_path)
    if mutation == "content":
        target = directory / "files" / "source.py"
        os.chmod(target, stat.S_IREAD | stat.S_IWRITE)
        target.write_text("forged\n", encoding="utf-8")
    elif mutation == "manifest":
        target = directory / "EVIDENCE_MANIFEST.json"
        os.chmod(target, stat.S_IREAD | stat.S_IWRITE)
        manifest = json.loads(target.read_text(encoding="utf-8"))
        manifest["manifest_canonical_hash"] = "0" * 64
        target.write_text(json.dumps(manifest), encoding="utf-8")
    elif mutation == "missing":
        target = directory / "TASK.md"
        os.chmod(target, stat.S_IREAD | stat.S_IWRITE)
        target.unlink()
    else:
        target = directory / "extra.txt"
        target.write_text("unexpected\n", encoding="utf-8")

    result = create_evidence_capsule(gate.store, plan["plan_id"])

    assert result["status"] == "INVALID"
    assert gate.store.load_evidence_capsule(plan["plan_id"])["status"] == "INVALID"
    with pytest.raises(PolicyError, match="invalid"):
        create_evidence_capsule(gate.store, plan["plan_id"])


def test_manifest_only_directory_is_not_reused_without_a_verified_record(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "source.py").write_text("value = 1\n", encoding="utf-8")
    gate = make_gate(tmp_path)
    plan = make_plan(gate, root, decision=decision(evidence_files=["source.py"]))
    builder = CapsuleBuilder(gate.store)
    directory = gate.store.root / "capsules" / plan["plan_id"] / builder._capsule_id(plan, plan["evidence_sources"])
    directory.mkdir(parents=True)
    (directory / "EVIDENCE_MANIFEST.json").write_text("{}", encoding="utf-8")

    result = create_evidence_capsule(gate.store, plan["plan_id"])

    assert result["status"] == "INVALID"
    assert "without a verified READY record" in result["hold_reasons"][0]


def test_hold_expired_and_claimed_route_plans_cannot_create_capsules(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "source.py").write_text("value = 1\n", encoding="utf-8")
    gate = make_gate(tmp_path)

    hold = make_plan(gate, root, decision=decision(evidence_files=["*.py"]))
    with pytest.raises(PolicyError, match="PREVIEW"):
        create_evidence_capsule(gate.store, hold["plan_id"])

    expired = make_plan(gate, root, ttl_seconds=1, decision=decision(evidence_files=["source.py"]))
    time.sleep(1.05)
    with pytest.raises(PolicyError, match="expired"):
        create_evidence_capsule(gate.store, expired["plan_id"])

    claimed = make_plan(gate, root, decision=decision(evidence_files=["source.py"]))
    gate.store.claim_route_plan(claimed["plan_id"], "00000000-0000-4000-8000-000000000000")
    with pytest.raises(PolicyError, match="claimed"):
        create_evidence_capsule(gate.store, claimed["plan_id"])


def test_full_and_range_selection_of_the_same_path_holds(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "source.py").write_text("value = 1\n", encoding="utf-8")
    gate = make_gate(tmp_path)
    plan = make_plan(gate, root, decision=decision(
        evidence_files=["source.py"],
        evidence_ranges=[{"path": "source.py", "start_line": 1, "end_line": 1}],
    ))

    result = create_evidence_capsule(gate.store, plan["plan_id"])

    assert result["status"] == "HOLD"
    assert "must not select the same path" in result["hold_reasons"][0]


def test_oversized_full_file_is_held_before_path_read_bytes(tmp_path, monkeypatch):
    root = tmp_path / "project"
    root.mkdir()
    (root / "oversized.txt").write_bytes(b"x" * (MAX_FULL_FILE_BYTES + 1))
    gate = make_gate(tmp_path)
    plan = make_plan(gate, root, decision=decision(evidence_files=["oversized.txt"]))

    def read_bytes_forbidden(_):
        raise AssertionError("Capsule must not call Path.read_bytes for an oversized whole file")

    monkeypatch.setattr(Path, "read_bytes", read_bytes_forbidden)
    result = create_evidence_capsule(gate.store, plan["plan_id"])

    assert result["status"] == "HOLD"


def test_large_range_source_is_streamed_and_excludes_unselected_lines(tmp_path, monkeypatch):
    root = tmp_path / "project"
    root.mkdir()
    source = root / "large.txt"
    with source.open("w", encoding="utf-8") as output:
        for index in range(1, 120_001):
            value = "SELECTED" if index in {60_000, 60_001} else f"outside-{index:06d}"
            output.write(f"{value}\n")
    gate = make_gate(tmp_path)
    plan = make_plan(gate, root, decision=decision(evidence_ranges=[
        {"path": "large.txt", "start_line": 60_000, "end_line": 60_001},
    ]))

    def read_bytes_forbidden(_):
        raise AssertionError("Capsule range extraction must not call Path.read_bytes")

    monkeypatch.setattr(Path, "read_bytes", read_bytes_forbidden)
    result = create_evidence_capsule(gate.store, plan["plan_id"])

    assert result["status"] == "READY"
    manifest = json.loads((capsule_dir(gate, plan) / "EVIDENCE_MANIFEST.json").read_text(encoding="utf-8"))
    snippet = (capsule_dir(gate, plan) / manifest["evidence"][0]["capsule_path"]).read_text(encoding="utf-8")
    assert "60000: SELECTED" in snippet and "60001: SELECTED" in snippet
    assert "outside-000001" not in snippet and "outside-120000" not in snippet


def test_range_with_an_oversized_single_line_holds_without_copying_it(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "long.txt").write_bytes(b"x" * (MAX_SINGLE_LINE_BYTES + 1) + b"\n")
    gate = make_gate(tmp_path)
    plan = make_plan(gate, root, decision=decision(evidence_ranges=[
        {"path": "long.txt", "start_line": 1, "end_line": 1},
    ]))

    result = create_evidence_capsule(gate.store, plan["plan_id"])

    assert result["status"] == "HOLD"
    assert str(MAX_SINGLE_LINE_BYTES) in result["hold_reasons"][0]


def test_source_replacement_during_streaming_marks_capsule_invalid(tmp_path, monkeypatch):
    root = tmp_path / "project"
    root.mkdir()
    source = root / "source.py"
    source.write_text("before\n", encoding="utf-8")
    gate = make_gate(tmp_path)
    plan = make_plan(gate, root, decision=decision(evidence_files=["source.py"]))
    original_fstat = capsule_module.os.fstat
    replaced = False

    def racing_fstat(file_descriptor):
        nonlocal replaced
        value = original_fstat(file_descriptor)
        if not replaced:
            replaced = True
            source.write_text("after\n", encoding="utf-8")
        return value

    monkeypatch.setattr(capsule_module.os, "fstat", racing_fstat)
    result = create_evidence_capsule(gate.store, plan["plan_id"])

    assert result["status"] == "INVALID"
    assert "replaced or changed" in result["hold_reasons"][0]


def test_capsule_symlink_or_junction_is_invalidated_on_recheck(tmp_path):
    gate, plan, directory = _make_ready_capsule(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    os.chmod(directory, stat.S_IREAD | stat.S_IWRITE | stat.S_IEXEC)
    _create_link_or_junction(directory / "linked", outside)

    result = create_evidence_capsule(gate.store, plan["plan_id"])

    assert result["status"] == "INVALID"
    assert "symlink or junction" in result["hold_reasons"][0]


def test_evidence_fingerprint_is_plan_id_independent_while_capsule_hash_is_instance_bound(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "source.py").write_text("value = 1\n", encoding="utf-8")
    gate = make_gate(tmp_path)
    first_plan = make_plan(gate, root, decision=decision(evidence_files=["source.py"]))
    second_plan = make_plan(gate, root, decision=decision(evidence_files=["source.py"]))

    first = create_evidence_capsule(gate.store, first_plan["plan_id"])
    second = create_evidence_capsule(gate.store, second_plan["plan_id"])

    assert first["evidence_fingerprint"] == second["evidence_fingerprint"]
    assert first["capsule_hash"] != second["capsule_hash"]
