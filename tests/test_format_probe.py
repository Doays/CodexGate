from __future__ import annotations

import hashlib
import os
import struct
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import app.format_probe as format_probe_module
import app.main as app_main
from app.catalog import CatalogService
from app.format_probe import MAX_CONTENT_BYTES_READ, PROBE_VERSION, FormatProbeService
from app.policy import PolicyError
from app.storage import Store


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(app_main, "DATA_ROOT", tmp_path / "data")
    with TestClient(app_main.app, base_url="http://127.0.0.1:8787") as test_client:
        yield test_client


def services(tmp_path: Path) -> tuple[CatalogService, FormatProbeService]:
    store = Store(tmp_path / "data")
    return CatalogService(store), FormatProbeService(store)


def register_source(tmp_path: Path, root: Path) -> tuple[CatalogService, FormatProbeService, dict[str, object]]:
    catalog, probe = services(tmp_path)
    source = catalog.register_source("Game data", str(root))
    catalog.scan(source["source_id"])
    return catalog, probe, source


def entry_for(catalog: CatalogService, source_id: str, relative_path: str) -> dict[str, object]:
    for item in catalog.entries(source_id):
        if item["relative_path"] == relative_path:
            return item
    raise AssertionError(f"missing catalog entry for {relative_path}")


def strong_glb(file_size: int = 12) -> bytes:
    return b"glTF" + (2).to_bytes(4, "little") + file_size.to_bytes(4, "little")


def strong_pmx() -> bytes:
    return b"PMX " + struct.pack("<f", 2.0) + bytes([8]) + b"\x00" * 8


def strong_pmd() -> bytes:
    return b"Pmd" + struct.pack("<f", 1.0) + b"\x00" * 8


def strong_bmp() -> bytes:
    header = bytearray(54)
    header[0:2] = b"BM"
    header[2:6] = (54).to_bytes(4, "little")
    header[10:14] = (54).to_bytes(4, "little")
    header[14:18] = (40).to_bytes(4, "little")
    return bytes(header)


@pytest.mark.parametrize(
    ("name", "payload", "expected"),
    [
        ("bundle.assetbundle", b"UnityFS\x00more", "UNITYFS"),
        ("bundle.raw", b"UnityRaw\x00more", "UNITYRAW"),
        ("bundle.web", b"UnityWeb\x00more", "UNITYWEB"),
        ("model.pmx", strong_pmx(), "PMX"),
        ("model.pmd", strong_pmd(), "PMD"),
        ("mesh.fbx", b"Kaydara FBX Binary  \x00\x1a\x00rest", "FBX_BINARY"),
        ("mesh_ascii.fbx", b"; FBX 7.4.0 project\nFBXHeaderExtension: {\n}\n", "FBX_ASCII"),
        ("scene.glb", strong_glb(), "GLB"),
        ("scene.gltf", b'{"asset":{"version":"2.0"},"scene":0}', "GLTF"),
        ("image.png", b"\x89PNG\r\n\x1a\nrest", "PNG"),
        ("image.jpg", b"\xff\xd8\xff\xe0rest", "JPEG"),
        ("image.dds", b"DDS \x7c\x00\x00\x00", "DDS"),
        ("image.ktx", b"\xabKTX 11\xbb\r\n\x1a\nrest", "KTX1"),
        ("image.ktx2", b"\xabKTX 20\xbb\r\n\x1a\nrest", "KTX2"),
        ("image.webp", b"RIFF\x08\x00\x00\x00WEBPrest", "WEBP"),
        ("image.bmp", strong_bmp(), "BMP"),
        ("image.tiff", b"II*\x00rest", "TIFF"),
        ("archive.zip", b"PK\x03\x04rest", "ZIP"),
        ("archive.7z", b"7z\xbc\xaf\x27\x1crest", "7Z"),
        ("archive.rar", b"Rar!\x1a\x07\x00rest", "RAR"),
        ("archive.gz", b"\x1f\x8b\x08rest", "GZIP"),
        ("archive.xz", b"\xfd7zXZ\x00rest", "XZ"),
        ("binary.elf", b"\x7fELFrest", "ELF"),
        ("audio.wav", b"RIFF\x10\x00\x00\x00WAVErest", "WAV"),
        ("audio.ogg", b"OggSrest", "OGG"),
        ("audio.flac", b"fLaCrest", "FLAC"),
        ("audio.mp3", b"\xff\xfb\x90drest", "MP3"),
    ],
)
def test_supported_signatures_detect_minimal_formats(tmp_path, name, payload, expected):
    root = tmp_path / "source"
    root.mkdir()
    (root / name).write_bytes(payload)
    catalog, probe, source = register_source(tmp_path, root)
    entry = entry_for(catalog, source["source_id"], name)
    result = probe.probe([entry["entry_id"]])[0]
    assert result["status"] == "COMPLETED"
    assert result["detected_format"] == expected
    assert result["detected_confidence"] == "HIGH"
    assert result["next_inspector"] != "NONE"


def test_extension_match_mismatch_and_unknown(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    (root / "good.png").write_bytes(b"\x89PNG\r\n\x1a\nrest")
    (root / "wrong.txt").write_bytes(b"\x89PNG\r\n\x1a\nrest")
    (root / "plain").write_bytes(b"\x89PNG\r\n\x1a\nrest")
    catalog, probe, source = register_source(tmp_path, root)
    good = probe.probe([entry_for(catalog, source["source_id"], "good.png")["entry_id"]])[0]
    wrong = probe.probe([entry_for(catalog, source["source_id"], "wrong.txt")["entry_id"]])[0]
    plain = probe.probe([entry_for(catalog, source["source_id"], "plain")["entry_id"]])[0]
    assert good["extension_match"] == "MATCH"
    assert wrong["extension_match"] == "MISMATCH"
    assert plain["extension_match"] == "UNKNOWN"


def test_fake_signatures_do_not_become_high_confidence(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    fixtures = {
        "fake.bmp": b"BMbad",
        "fake.pmd": b"Pmdbad",
        "fake.mp3": b"\xff\xe0\x00\x00",
        "fake.gltf": b'{"asset":{}}',
        "fake.glb": b"glTF" + (1).to_bytes(4, "little") + (12).to_bytes(4, "little"),
        "fake_ascii.fbx": b"; FBX 7.4.0 project\n",
    }
    for name, payload in fixtures.items():
        (root / name).write_bytes(payload)
    catalog, probe, source = register_source(tmp_path, root)
    for name in fixtures:
        result = probe.probe([entry_for(catalog, source["source_id"], name)["entry_id"]])[0]
        assert result["status"] == "COMPLETED"
        assert result["detected_confidence"] is None
        assert result["detected_format"] == "UNKNOWN"
        assert result["next_inspector"] == "NONE"


def test_sparse_20gb_probe_stays_under_read_budget(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    sparse = root / "huge.bin"
    with sparse.open("wb") as handle:
        if os.name == "nt":
            import ctypes
            import msvcrt

            returned = ctypes.c_ulong()
            ok = ctypes.windll.kernel32.DeviceIoControl(
                msvcrt.get_osfhandle(handle.fileno()),
                0x900C4,
                None,
                0,
                None,
                0,
                ctypes.byref(returned),
                None,
            )
            if not ok:
                pytest.fail("Windows sparse fixture could not be enabled")
        handle.seek(20 * 1024**3 - 1)
        handle.write(b"\0")
    catalog, probe, source = register_source(tmp_path, root)
    result = probe.probe([entry_for(catalog, source["source_id"], "huge.bin")["entry_id"]])[0]
    assert result["status"] == "COMPLETED"
    assert result["bytes_read"] <= MAX_CONTENT_BYTES_READ
    assert result["detected_format"] == "UNKNOWN"


def test_stale_catalog_entry_requires_rescan(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    target = root / "asset.bin"
    target.write_bytes(b"one")
    catalog, probe, source = register_source(tmp_path, root)
    entry = entry_for(catalog, source["source_id"], "asset.bin")
    target.write_bytes(b"changed bytes")
    result = probe.probe([entry["entry_id"]])[0]
    assert result["status"] == "STALE"
    assert result["reason_code"] == "STALE_CATALOG_ENTRY"


def test_file_changed_during_probe_is_detected(tmp_path, monkeypatch):
    root = tmp_path / "source"
    root.mkdir()
    target = root / "asset.bin"
    target.write_bytes(b"stable")
    catalog, probe, source = register_source(tmp_path, root)
    entry = entry_for(catalog, source["source_id"], "asset.bin")
    original = format_probe_module._read_detector_sample

    def replace_after_read(handle, size):
        sample = original(handle, size)
        target.write_bytes(b"replaced during probe")
        return sample

    monkeypatch.setattr(format_probe_module, "_read_detector_sample", replace_after_read)
    result = probe.probe([entry["entry_id"]])[0]
    assert result["status"] == "STALE"
    assert result["reason_code"] == "FILE_CHANGED_DURING_PROBE"


def test_same_metadata_but_different_sample_creates_new_probe(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    target = root / "asset.dat"
    first_bytes = b"\x89PNG\r\n\x1a\nrest"
    second_bytes = b"PK\x03\x04restrest"
    target.write_bytes(first_bytes)
    catalog, probe, source = register_source(tmp_path, root)
    entry = entry_for(catalog, source["source_id"], "asset.dat")
    first = probe.probe([entry["entry_id"]])[0]
    original_mtime = target.stat().st_mtime_ns
    target.write_bytes(second_bytes)
    os.utime(target, ns=(original_mtime, original_mtime))
    second = probe.probe([entry["entry_id"]])[0]
    assert first["probe_id"] != second["probe_id"]
    assert first["sample_sha256"] != second["sample_sha256"]
    assert second["detected_format"] == "ZIP"


def test_rejected_and_failed_probes_can_retry_with_same_metadata(tmp_path, monkeypatch):
    root = tmp_path / "source"
    root.mkdir()
    target = root / "asset.png"
    target.write_bytes(b"\x89PNG\r\n\x1a\nrest")
    catalog, probe, source = register_source(tmp_path, root)
    entry = entry_for(catalog, source["source_id"], "asset.png")
    original_resolver = format_probe_module.resolve_catalog_entry_file

    monkeypatch.setattr(
        format_probe_module,
        "resolve_catalog_entry_file",
        lambda *_: (_ for _ in ()).throw(PolicyError("catalog entry traverses a symlink or junction")),
    )
    rejected = probe.probe([entry["entry_id"]])[0]
    assert rejected["status"] == "REJECTED"

    monkeypatch.setattr(format_probe_module, "resolve_catalog_entry_file", original_resolver)
    retry_after_reject = probe.probe([entry["entry_id"]])[0]
    assert retry_after_reject["status"] == "COMPLETED"
    assert retry_after_reject["probe_id"] != rejected["probe_id"]

    original_reader = format_probe_module._read_detector_sample

    def broken_reader(*_args, **_kwargs):
        raise OSError("boom")

    monkeypatch.setattr(format_probe_module, "_read_detector_sample", broken_reader)
    failed = probe.probe([entry["entry_id"]])[0]
    assert failed["status"] == "FAILED"

    monkeypatch.setattr(format_probe_module, "_read_detector_sample", original_reader)
    retry_after_fail = probe.probe([entry["entry_id"]])[0]
    assert retry_after_fail["status"] == "COMPLETED"
    assert retry_after_fail["probe_id"] != failed["probe_id"]


def test_completed_only_reuses_identical_sample(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    target = root / "asset.png"
    target.write_bytes(b"\x89PNG\r\n\x1a\nrest")
    catalog, probe, source = register_source(tmp_path, root)
    entry = entry_for(catalog, source["source_id"], "asset.png")
    first = probe.probe([entry["entry_id"]])[0]
    second = probe.probe([entry["entry_id"]])[0]
    assert second["reused"] is True
    assert first["probe_id"] == second["probe_id"]


def test_orphan_probing_recovers_on_startup(tmp_path, monkeypatch):
    data_root = tmp_path / "data"
    root = tmp_path / "source"
    root.mkdir()
    target = root / "asset.png"
    target.write_bytes(b"\x89PNG\r\n\x1a\nrest")
    store = Store(data_root)
    catalog = CatalogService(store)
    source = catalog.register_source("Assets", str(root))
    catalog.scan(source["source_id"])
    entry = entry_for(catalog, source["source_id"], "asset.png")
    pending = store.begin_format_probe(
        entry["entry_id"],
        PROBE_VERSION,
        "cache:pending",
        "sample:pending",
        {
            "alias": source["alias"],
            "relative_path": "asset.png",
            "catalog_asset_kind": entry["asset_kind"],
            "probe_asset_kind": "unknown",
            "format_candidates": [],
            "detected_format": "UNKNOWN",
            "detected_confidence": None,
            "extension_match": "UNKNOWN",
            "next_inspector": "NONE",
            "full_parse_allowed": False,
            "bytes_read": 0,
            "sample_sha256": "sample:pending",
            "detector_version": PROBE_VERSION,
            "reason_code": None,
        },
    )
    store.mark_format_probe_probing(pending["probe_id"])
    monkeypatch.setattr(app_main, "DATA_ROOT", data_root)
    with TestClient(app_main.app, base_url="http://127.0.0.1:8787"):
        pass
    recovered = Store(data_root).load_format_probe(pending["probe_id"])
    assert recovered["status"] == "FAILED"
    assert recovered["reason_code"] == "probe_interrupted"
    assert recovered["finished_at"] is not None


def test_missing_and_rejected_catalog_entry_are_blocked_before_read(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    target = root / "asset.png"
    target.write_bytes(b"\x89PNG\r\n\x1a\nrest")
    catalog, probe, source = register_source(tmp_path, root)
    entry = entry_for(catalog, source["source_id"], "asset.png")
    with probe.store._connection() as conn:
        conn.execute("UPDATE catalog_entries SET status='MISSING' WHERE entry_id=?", (entry["entry_id"],))
    missing = probe.probe([entry["entry_id"]])[0]
    assert missing["status"] == "REJECTED"
    assert missing["reason_code"] == "CATALOG_STATUS_MISSING"
    with probe.store._connection() as conn:
        conn.execute("UPDATE catalog_entries SET status='REJECTED' WHERE entry_id=?", (entry["entry_id"],))
    rejected = probe.probe([entry["entry_id"]])[0]
    assert rejected["status"] == "REJECTED"
    assert rejected["reason_code"] == "CATALOG_STATUS_REJECTED"


def test_idempotent_recovery_method_is_atomic(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    target = root / "asset.png"
    target.write_bytes(b"\x89PNG\r\n\x1a\nrest")
    store = Store(tmp_path / "data")
    catalog = CatalogService(store)
    source = catalog.register_source("Assets", str(root))
    catalog.scan(source["source_id"])
    entry = entry_for(catalog, source["source_id"], "asset.png")
    pending = store.begin_format_probe(
        entry["entry_id"],
        PROBE_VERSION,
        "cache:pending",
        "sample:pending",
        {
            "alias": source["alias"],
            "relative_path": "asset.png",
            "catalog_asset_kind": entry["asset_kind"],
            "probe_asset_kind": "unknown",
            "format_candidates": [],
            "detected_format": "UNKNOWN",
            "detected_confidence": None,
            "extension_match": "UNKNOWN",
            "next_inspector": "NONE",
            "full_parse_allowed": False,
            "bytes_read": 0,
            "sample_sha256": "sample:pending",
            "detector_version": PROBE_VERSION,
            "reason_code": None,
        },
    )
    store.mark_format_probe_probing(pending["probe_id"])
    assert store.recover_interrupted_format_probes() == 1
    assert store.recover_interrupted_format_probes() == 0


def test_api_response_hides_absolute_path_and_limits_batch(client, tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    (root / "asset.png").write_bytes(b"\x89PNG\r\n\x1a\nrest")
    created = client.post("/api/catalog/sources", json={"alias": "Assets", "root": str(root)})
    source_id = created.json()["source_id"]
    client.post(f"/api/catalog/sources/{source_id}/scan", json={})
    entries = client.get(f"/api/catalog/sources/{source_id}/entries").json()["entries"]
    response = client.post("/api/format-probes", json={"catalog_entry_ids": [entries[0]["entry_id"]]})
    assert response.status_code == 200
    assert str(root) not in response.text
    assert "UnityFS" not in response.text
    too_many = client.post("/api/format-probes", json={"catalog_entry_ids": ["x"] * 51})
    assert too_many.status_code == 422


def test_probe_does_not_mutate_original_file(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    target = root / "asset.png"
    target.write_bytes(b"\x89PNG\r\n\x1a\nrest")
    before_hash = hashlib.sha256(target.read_bytes()).hexdigest()
    before_size = target.stat().st_size
    before_mtime = target.stat().st_mtime_ns
    catalog, probe, source = register_source(tmp_path, root)
    entry = entry_for(catalog, source["source_id"], "asset.png")
    probe.probe([entry["entry_id"]])
    assert hashlib.sha256(target.read_bytes()).hexdigest() == before_hash
    assert target.stat().st_size == before_size
    assert target.stat().st_mtime_ns == before_mtime


def test_probe_source_contains_no_app_server_rpc_calls():
    source = Path(format_probe_module.__file__).read_text(encoding="utf-8")
    assert "command/exec" not in source
    assert "thread/start" not in source
    assert "turn/start" not in source
