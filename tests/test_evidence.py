from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from app.bridge import ARCHITECT_RESPONSE, BridgeService
from app.evidence import EDGE_BYTES, collect, normalize_requested_evidence
from app.policy import PolicyError
from app.storage import Store


class PlanCreator:
    def __call__(self, payload):
        return {"plan_id": "00000000-0000-4000-8000-000000000001", "status": "PREVIEW"}


def requested(kind="file_metadata", *, required=True, label="source"):
    return {"type": kind, "label": label, "reason": "bounded local fact", "required": required, "target_hint": "user must map an exact relative path"}


def bridge_for(root: Path):
    return BridgeService(Store(root / ".data"), PlanCreator())


def need_evidence(root: Path, entries):
    bridge = bridge_for(root)
    task = bridge.create({"project_name": "Demo", "project_id": "demo", "root": str(root), "task": "Inspect bounded local facts", "permission": "read-only"})
    waiting = bridge.copied(task["task_id"])
    envelope = {"TYPE": ARCHITECT_RESPONSE, "TASK_ID": waiting["task_id"], "PHASE": "ARCHITECT", "NONCE": waiting["pending_nonce"], "SCHEMA_VERSION": "2.0", "BODY": {"outcome": "need_more_evidence", "requested_evidence": entries}}
    raw = "----- CODEXGATE BRIDGE BEGIN -----\n" + json.dumps(envelope) + "\n----- CODEXGATE BRIDGE END -----"
    return bridge, bridge.import_response(waiting["task_id"], raw)


def test_requested_evidence_is_strictly_structured_and_hint_is_not_a_path(tmp_path):
    entries = normalize_requested_evidence([requested()])
    assert entries[0]["target_hint"] == "user must map an exact relative path"
    with pytest.raises(PolicyError):
        normalize_requested_evidence(["old string shape"])
    with pytest.raises(PolicyError, match="absolute user paths"):
        normalize_requested_evidence([requested(label=r"C:\Users\Alice\a.txt")])


@pytest.mark.parametrize("bad", ["../secret.txt", r"C:\Windows\x.txt", "*.txt", "folder/"])
def test_mapping_blocks_absolute_glob_directory_and_escape(tmp_path, bad):
    (tmp_path / "safe.txt").write_text("safe", encoding="utf-8")
    bridge, task = need_evidence(tmp_path, [requested()])
    request_id = task["evidence_requests"][0]["request_id"]
    with pytest.raises(PolicyError):
        bridge.map_evidence(task["task_id"], request_id, bad)


def test_mapping_blocks_link_and_forbidden_windows_paths_without_reading(tmp_path, monkeypatch):
    (tmp_path / "linked.txt").write_text("local placeholder", encoding="utf-8")
    monkeypatch.setattr("app.policy.is_link_or_junction", lambda path: path.name == "linked.txt")
    bridge, task = need_evidence(tmp_path, [requested()])
    request_id = task["evidence_requests"][0]["request_id"]
    with pytest.raises(PolicyError):
        bridge.map_evidence(task["task_id"], request_id, "linked.txt")
    with pytest.raises(PolicyError):
        bridge.map_evidence(task["task_id"], request_id, r"E:\.codex\x")


def test_large_fast_fingerprint_reads_only_two_edges(tmp_path, monkeypatch):
    source = tmp_path / "large.bin"; source.write_bytes(b"a" * (EDGE_BYTES + 9) + b"z" * EDGE_BYTES)
    request = {"request_id": "r", "type": "fast_fingerprint", "label": "large", "mapped_path": "large.bin"}
    opened = {"bytes": 0}
    original = Path.open
    class Counting:
        def __init__(self, wrapped): self.wrapped = wrapped
        def read(self, size=-1):
            data = self.wrapped.read(size); opened["bytes"] += len(data); return data
        def __enter__(self): return self
        def __exit__(self, *args): self.wrapped.close()
        def __getattr__(self, name): return getattr(self.wrapped, name)
    def wrapped(self, *args, **kwargs):
        file = original(self, *args, **kwargs)
        return Counting(file) if self == source else file
    monkeypatch.setattr(Path, "open", wrapped)
    result = collect(request, tmp_path)
    assert result["edge_sha256"] and opened["bytes"] <= 2 * EDGE_BYTES


def test_text_log_and_json_collectors_are_bounded_and_redacted(tmp_path):
    (tmp_path / "text.txt").write_text("".join(f"line {i}\n" for i in range(1, 400)), encoding="utf-8")
    (tmp_path / "data.json").write_text('{"password":"not exposed","items":[{"value":7}]}', encoding="utf-8")
    text = collect({"request_id":"t", "type":"text_range", "label":"text", "mapped_path":"text.txt", "start_line": 3, "end_line": 252}, tmp_path)
    log = collect({"request_id":"l", "type":"log_excerpt", "label":"log", "mapped_path":"text.txt", "line": 100, "context_before": 99, "context_after": 100}, tmp_path)
    shape = collect({"request_id":"j", "type":"json_structure", "label":"json", "mapped_path":"data.json"}, tmp_path)
    assert len(text["lines"]) == 250 and len(log["lines"]) == 200
    rendered = json.dumps(shape)
    assert "not exposed" not in rendered and '"value":7' not in rendered and "password" in rendered


def test_sensitive_names_and_contents_fail_collection(tmp_path):
    (tmp_path / ".env").write_text("TOKEN=abc", encoding="utf-8")
    (tmp_path / "log.txt").write_text("postgres://real-user:pw@host/db", encoding="utf-8")
    bridge, task = need_evidence(tmp_path, [requested(kind="text_range")])
    request_id = task["evidence_requests"][0]["request_id"]
    with pytest.raises(PolicyError):
        bridge.map_evidence(task["task_id"], request_id, ".env")
    bridge.map_evidence(task["task_id"], request_id, "log.txt", {"start_line": 1, "end_line": 1})
    collected = bridge.collect_evidence(task["task_id"], request_id)
    assert collected["evidence_requests"][0]["state"] == "FAILED"


def test_required_ready_results_are_added_to_next_architect_packet_and_concurrent_collect_is_idempotent(tmp_path):
    (tmp_path / "safe.txt").write_text("only a safe summary\n", encoding="utf-8")
    bridge, task = need_evidence(tmp_path, [requested(kind="text_range")])
    request_id = task["evidence_requests"][0]["request_id"]
    bridge.map_evidence(task["task_id"], request_id, "safe.txt", {"start_line": 1, "end_line": 1})
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: bridge.collect_evidence(task["task_id"], request_id), range(2)))
    assert all(item["status"] == "ARCHITECT_READY" for item in results)
    packet = json.loads(bridge.packet(task["task_id"]).splitlines()[1])
    evidence = packet["BODY"]["collected_evidence"]
    assert len(evidence) == 1 and evidence[0]["path"] == "PROJECT_ROOT/safe.txt" and evidence[0]["result_hash"]
    assert "C:\\" not in json.dumps(packet)


def test_required_evidence_blocks_packet_until_ready_and_no_rpc(tmp_path):
    (tmp_path / "safe.txt").write_text("safe", encoding="utf-8")
    bridge, task = need_evidence(tmp_path, [requested()])
    with pytest.raises(PolicyError, match="EVIDENCE_REQUIRED"):
        bridge.packet(task["task_id"])
    request_id = task["evidence_requests"][0]["request_id"]
    bridge.map_evidence(task["task_id"], request_id, "safe.txt")
    ready = bridge.collect_evidence(task["task_id"], request_id)
    assert ready["status"] == "ARCHITECT_READY"
    # Bridge/collector use only Store and filesystem primitives; no app-server object exists here.
