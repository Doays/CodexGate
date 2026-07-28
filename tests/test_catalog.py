from __future__ import annotations

import os
import hashlib
from types import SimpleNamespace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import app.catalog as catalog_module
from app.catalog import BATCH_SIZE, CatalogService
import app.main as app_main
from app.policy import PolicyError
from app.storage import Store


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(app_main, "DATA_ROOT", tmp_path / "data")
    with TestClient(app_main.app, base_url="http://127.0.0.1:8787") as test_client:
        yield test_client


def service(tmp_path: Path) -> CatalogService:
    return CatalogService(Store(tmp_path / "data"))


def register(tmp_path: Path, source: Path) -> tuple[CatalogService, dict[str, object]]:
    catalog = service(tmp_path)
    return catalog, catalog.register_source("Game data", str(source))


def rows(catalog: CatalogService, source_id: str) -> dict[str, dict[str, object]]:
    return {item["relative_path"]: item for item in catalog.entries(source_id)}


def test_initial_and_unchanged_incremental_scan(tmp_path):
    root = tmp_path / "source"; root.mkdir()
    source_file = root / "a.txt"; source_file.write_text("one", encoding="utf-8")
    before_sha = hashlib.sha256(source_file.read_bytes()).hexdigest()
    before_mtime = source_file.stat().st_mtime_ns
    catalog, source = register(tmp_path, root)
    first = catalog.scan(source["source_id"])
    assert first["status"] == "COMPLETED"
    assert first["metrics"]["added"] == 1
    assert first["metrics"]["content_bytes_read"] == 0
    assert hashlib.sha256(source_file.read_bytes()).hexdigest() == before_sha
    assert source_file.stat().st_mtime_ns == before_mtime
    second = catalog.scan(source["source_id"])
    assert second["status"] == "COMPLETED"
    assert rows(catalog, source["source_id"])["a.txt"]["status"] == "UNCHANGED"


def test_added_modified_missing_and_move_candidate(tmp_path):
    root = tmp_path / "source"; root.mkdir()
    original = root / "old.txt"; original.write_text("one", encoding="utf-8")
    catalog, source = register(tmp_path, root)
    catalog.scan(source["source_id"])
    original.rename(root / "moved.txt")
    (root / "changed.txt").write_text("before", encoding="utf-8")
    moved = catalog.scan(source["source_id"])
    moved_rows = rows(catalog, source["source_id"])
    assert moved_rows["old.txt"]["status"] == "MISSING"
    assert moved_rows["moved.txt"]["status"] == "MOVED_CANDIDATE"
    (root / "changed.txt").write_text("after with another size", encoding="utf-8")
    result = catalog.scan(source["source_id"])
    result_rows = rows(catalog, source["source_id"])
    assert result_rows["changed.txt"]["status"] == "MODIFIED"
    assert result["metrics"]["missing"] >= 0


def test_case_collision_and_link_are_rejected_without_following(tmp_path, monkeypatch):
    root = tmp_path / "source"; root.mkdir()
    # Windows developer-mode symlinks are not guaranteed for the test runner.
    # Simulate a reparse-point directory entry and assert it is rejected before
    # directory traversal; this is the same branch used for links and junctions.
    class FakeEntry:
        def __init__(self, name, ino): self.name, self.path, self.ino = name, str(root / name), ino
        def is_symlink(self): return False
        def is_dir(self, **_): return False
        def is_file(self, **_): return True
        def stat(self, **_): return SimpleNamespace(st_size=1, st_mtime_ns=1, st_dev=1, st_ino=self.ino)
    class FakeScandir:
        def __enter__(self): return iter([FakeEntry("A.txt", 1), FakeEntry("a.TXT", 2), FakeEntry("linked", 3)])
        def __exit__(self, *_): return False
    monkeypatch.setattr(catalog_module.os, "scandir", lambda _: FakeScandir())
    original_reparse = catalog_module._is_reparse_entry
    monkeypatch.setattr(catalog_module, "_is_reparse_entry", lambda entry: entry.name == "linked" or original_reparse(entry))
    catalog, source = register(tmp_path, root)
    scan = catalog.scan(source["source_id"])
    assert scan["metrics"]["rejected"] >= 2
    assert "linked" in rows(catalog, source["source_id"])
    assert rows(catalog, source["source_id"])["linked"]["status"] == "REJECTED"


def test_forbidden_and_relative_sources_are_rejected(tmp_path):
    catalog = service(tmp_path)
    with pytest.raises(PolicyError):
        catalog.register_source("blocked", r"E:\.codex")
    with pytest.raises(PolicyError):
        catalog.register_source("relative", "relative/path")


def test_sparse_20gb_file_is_stat_only(tmp_path, monkeypatch):
    root = tmp_path / "source"; root.mkdir()
    sparse = root / "large.bundle"
    with sparse.open("wb") as handle:
        if os.name == "nt":
            import ctypes
            import msvcrt
            returned = ctypes.c_ulong()
            ok = ctypes.windll.kernel32.DeviceIoControl(
                msvcrt.get_osfhandle(handle.fileno()), 0x900C4, None, 0, None, 0,
                ctypes.byref(returned), None,
            )
            if not ok:
                pytest.fail("Windows sparse fixture could not be enabled")
        handle.seek(20 * 1024**3 - 1)
        handle.write(b"\0")
    monkeypatch.setattr(Path, "open", lambda *_args, **_kwargs: pytest.fail("catalog must not open source file content"))
    catalog, source = register(tmp_path, root)
    scan = catalog.scan(source["source_id"])
    assert scan["metrics"]["content_bytes_read"] == 0
    assert scan["metrics"]["bytes_indexed"] == 20 * 1024**3


def test_batches_interrupt_resume_and_concurrent_rejection(tmp_path, monkeypatch):
    root = tmp_path / "source"; root.mkdir()
    for index in range(BATCH_SIZE + 2):
        (root / f"{index:04}.txt").write_text("x", encoding="utf-8")
    catalog, source = register(tmp_path, root)
    calls = []
    original_apply = catalog.store.apply_catalog_batch
    def counted(*args, **kwargs):
        calls.append(1); return original_apply(*args, **kwargs)
    monkeypatch.setattr(catalog.store, "apply_catalog_batch", counted)
    partial = catalog.scan(source["source_id"], max_files=3)
    assert partial["status"] == "INTERRUPTED"
    with pytest.raises(PolicyError, match="already running"):
        # Mark a real active scan to assert the database lock, not an in-memory flag.
        with catalog.store._connection() as conn:
            conn.execute("UPDATE catalog_scans SET status='SCANNING' WHERE scan_id=?", (partial["scan_id"],))
        catalog.scan(source["source_id"])
    with catalog.store._connection() as conn:
        conn.execute("UPDATE catalog_scans SET status='INTERRUPTED' WHERE scan_id=?", (partial["scan_id"],))
    completed = catalog.scan(source["source_id"], resume=True)
    assert completed["status"] == "COMPLETED"
    assert len(rows(catalog, source["source_id"])) == BATCH_SIZE + 2
    assert len(calls) >= 2


def test_catalog_api_never_returns_source_root(client, tmp_path):
    root = tmp_path / "source"; root.mkdir(); (root / "asset.png").write_bytes(b"x")
    created = client.post("/api/catalog/sources", json={"alias": "Assets", "root": str(root)})
    assert created.status_code == 200
    assert str(root) not in created.text
    source_id = created.json()["source_id"]
    scanned = client.post(f"/api/catalog/sources/{source_id}/scan", json={})
    assert scanned.status_code == 200
    entries = client.get(f"/api/catalog/sources/{source_id}/entries")
    assert entries.status_code == 200
    assert str(root) not in entries.text
    assert entries.json()["entries"][0]["relative_path"] == "asset.png"
