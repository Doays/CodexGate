from __future__ import annotations

import hashlib
import json
import os
import struct
from pathlib import Path
from typing import Any, Callable

from .policy import PolicyError, resolve_catalog_entry_file, validate_catalog_source_root
from .storage import Store


PROBE_VERSION = "format-probe-phase2.v2"
MAX_BATCH_ENTRIES = 50
MAX_CONTENT_BYTES_READ = 128 * 1024
TERMINAL_STATES = frozenset({"COMPLETED", "STALE", "REJECTED", "FAILED"})
ALLOWED_ENTRY_STATUSES = frozenset({"ADDED", "MODIFIED", "UNCHANGED", "MOVED_CANDIDATE"})
CONFIDENCE_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}


def _candidate(format_name: str, confidence: str, evidence: str) -> dict[str, str]:
    return {"format": format_name, "confidence": confidence, "evidence": evidence}


def _file_id(info: os.stat_result) -> str:
    return f"{int(info.st_dev)}:{int(info.st_ino)}"


def _signature(info: os.stat_result) -> tuple[int, int, str]:
    return int(info.st_size), int(info.st_mtime_ns), _file_id(info)


def _same_signature(left: tuple[int, int, str], right: tuple[int, int, str]) -> bool:
    if left[0] != right[0] or left[1] != right[1]:
        return False
    if left[2] == "0:0" or right[2] == "0:0":
        return True
    return left[2] == right[2]


def cache_identity_for(size: int, mtime_ns: int, file_id: str, sample_sha256: str) -> str:
    return f"{int(size)}:{int(mtime_ns)}:{file_id}:{sample_sha256}"


def _decode_ascii(sample: bytes) -> str:
    try:
        return sample.decode("utf-8")
    except UnicodeDecodeError:
        return sample.decode("latin-1", errors="ignore")


def _float32_le(data: bytes) -> float | None:
    if len(data) != 4:
        return None
    return struct.unpack("<f", data)[0]


def _valid_mp3_frame_header(header: bytes) -> bool:
    if len(header) < 4:
        return False
    value = int.from_bytes(header[:4], "big")
    if (value >> 21) & 0x7FF != 0x7FF:
        return False
    version_id = (value >> 19) & 0x3
    layer = (value >> 17) & 0x3
    bitrate_index = (value >> 12) & 0xF
    sample_rate_index = (value >> 10) & 0x3
    if version_id == 0x1 or layer == 0x0:
        return False
    if bitrate_index in {0x0, 0xF}:
        return False
    if sample_rate_index == 0x3:
        return False
    return True


def _detect_unity(sample: bytes, _: int) -> list[dict[str, str]]:
    if sample.startswith(b"UnityFS\x00"):
        return [_candidate("UNITYFS", "HIGH", "UnityFS signature and header prefix")]
    if sample.startswith(b"UnityRaw\x00"):
        return [_candidate("UNITYRAW", "HIGH", "UnityRaw signature and header prefix")]
    if sample.startswith(b"UnityWeb\x00"):
        return [_candidate("UNITYWEB", "HIGH", "UnityWeb signature and header prefix")]
    return []


def _detect_mmd(sample: bytes, _: int) -> list[dict[str, str]]:
    candidates: list[dict[str, str]] = []
    if sample.startswith(b"PMX "):
        version = _float32_le(sample[4:8])
        header_size = sample[8] if len(sample) >= 9 else 0
        if version is not None and 1.0 <= version <= 3.1 and header_size >= 8:
            candidates.append(_candidate("PMX", "HIGH", "PMX signature, version, and header size"))
        else:
            candidates.append(_candidate("PMX", "MEDIUM", "PMX signature without a valid version/header layout"))
    if sample.startswith(b"Pmd"):
        version = _float32_le(sample[3:7])
        if version is not None and 0.9 <= version <= 1.1 and len(sample) >= 10:
            candidates.append(_candidate("PMD", "HIGH", "PMD signature and expected header version"))
        else:
            candidates.append(_candidate("PMD", "MEDIUM", "PMD signature without a valid header version"))
    return candidates


def _detect_fbx(sample: bytes, _: int) -> list[dict[str, str]]:
    text = _decode_ascii(sample).lstrip("\ufeff\r\n\t ")
    if sample.startswith(b"Kaydara FBX Binary  \x00\x1a\x00"):
        return [_candidate("FBX_BINARY", "HIGH", "FBX binary magic and sentinel")]
    if text.startswith("; FBX "):
        if "FBXHeaderExtension" in text:
            return [_candidate("FBX_ASCII", "HIGH", "FBX ASCII header with FBXHeaderExtension block")]
        return [_candidate("FBX_ASCII", "MEDIUM", "FBX ASCII banner without a validated header block")]
    return []


def _detect_gltf(sample: bytes, file_size: int) -> list[dict[str, str]]:
    candidates: list[dict[str, str]] = []
    if sample.startswith(b"glTF"):
        if len(sample) >= 12:
            version = int.from_bytes(sample[4:8], "little")
            declared_length = int.from_bytes(sample[8:12], "little")
            if version == 2 and declared_length == file_size and declared_length >= 12:
                candidates.append(_candidate("GLB", "HIGH", "GLB magic, version 2, and declared length"))
            else:
                candidates.append(_candidate("GLB", "MEDIUM", "GLB magic without a valid version/declared length"))
        else:
            candidates.append(_candidate("GLB", "MEDIUM", "GLB magic without a complete header"))
        return candidates

    text = _decode_ascii(sample).strip()
    if not text.startswith("{"):
        return []
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return []
    if not isinstance(parsed, dict):
        return []
    asset = parsed.get("asset")
    if isinstance(asset, dict) and isinstance(asset.get("version"), str):
        candidates.append(_candidate("GLTF", "HIGH", "glTF JSON asset.version field"))
    elif "asset" in parsed:
        candidates.append(_candidate("GLTF", "MEDIUM", "glTF-like JSON without a valid asset.version"))
    return candidates


def _detect_textures(sample: bytes, file_size: int) -> list[dict[str, str]]:
    candidates: list[dict[str, str]] = []
    if sample.startswith(b"\x89PNG\r\n\x1a\n"):
        candidates.append(_candidate("PNG", "HIGH", "PNG signature"))
    if sample[:3] == b"\xff\xd8\xff":
        candidates.append(_candidate("JPEG", "HIGH", "JPEG SOI marker"))
    if sample.startswith(b"DDS "):
        candidates.append(_candidate("DDS", "HIGH", "DDS signature"))
    if sample.startswith(b"\xabKTX 11\xbb\r\n\x1a\n"):
        candidates.append(_candidate("KTX1", "HIGH", "KTX1 signature"))
    if sample.startswith(b"\xabKTX 20\xbb\r\n\x1a\n"):
        candidates.append(_candidate("KTX2", "HIGH", "KTX2 signature"))
    if sample.startswith(b"RIFF") and sample[8:12] == b"WEBP":
        candidates.append(_candidate("WEBP", "HIGH", "RIFF WEBP signature"))
    if sample.startswith((b"II*\x00", b"MM\x00*")):
        candidates.append(_candidate("TIFF", "HIGH", "TIFF signature"))
    if sample.startswith(b"BM"):
        if len(sample) >= 26:
            declared_size = int.from_bytes(sample[2:6], "little")
            pixel_offset = int.from_bytes(sample[10:14], "little")
            dib_size = int.from_bytes(sample[14:18], "little")
            if declared_size == file_size and 14 <= pixel_offset <= file_size and dib_size in {12, 16, 40, 52, 56, 64, 108, 124}:
                candidates.append(_candidate("BMP", "HIGH", "BMP signature, declared size, pixel offset, and DIB header"))
            else:
                candidates.append(_candidate("BMP", "MEDIUM", "BMP signature without a valid size/offset/DIB header"))
        else:
            candidates.append(_candidate("BMP", "MEDIUM", "BMP signature without a complete header"))
    return candidates


def _detect_archives(sample: bytes, _: int) -> list[dict[str, str]]:
    candidates: list[dict[str, str]] = []
    if sample.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        candidates.append(_candidate("ZIP", "HIGH", "ZIP signature"))
    if sample.startswith(b"7z\xbc\xaf\x27\x1c"):
        candidates.append(_candidate("7Z", "HIGH", "7z signature"))
    if sample.startswith((b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00")):
        candidates.append(_candidate("RAR", "HIGH", "RAR signature"))
    if sample.startswith(b"\x1f\x8b\x08"):
        candidates.append(_candidate("GZIP", "HIGH", "gzip signature"))
    if sample.startswith(b"\xfd7zXZ\x00"):
        candidates.append(_candidate("XZ", "HIGH", "xz signature"))
    return candidates


def _detect_executables(sample: bytes, _: int) -> list[dict[str, str]]:
    candidates: list[dict[str, str]] = []
    if sample.startswith(b"\x7fELF"):
        candidates.append(_candidate("ELF", "HIGH", "ELF signature"))
    if sample.startswith(b"MZ") and len(sample) >= 64:
        pe_offset = int.from_bytes(sample[0x3C:0x40], "little", signed=False)
        if 0 <= pe_offset <= len(sample) - 4 and sample[pe_offset:pe_offset + 4] == b"PE\x00\x00":
            candidates.append(_candidate("PE", "HIGH", "PE DOS header and COFF signature"))
    return candidates


def _detect_audio(sample: bytes, _: int) -> list[dict[str, str]]:
    candidates: list[dict[str, str]] = []
    if sample.startswith(b"RIFF") and sample[8:12] == b"WAVE":
        candidates.append(_candidate("WAV", "HIGH", "WAV RIFF signature"))
    if sample.startswith(b"OggS"):
        candidates.append(_candidate("OGG", "HIGH", "Ogg page signature"))
    if sample.startswith(b"fLaC"):
        candidates.append(_candidate("FLAC", "HIGH", "FLAC signature"))
    if sample.startswith(b"ID3"):
        if len(sample) >= 10:
            tag_size = (
                ((sample[6] & 0x7F) << 21)
                | ((sample[7] & 0x7F) << 14)
                | ((sample[8] & 0x7F) << 7)
                | (sample[9] & 0x7F)
            )
            frame_offset = 10 + tag_size
            if frame_offset + 4 <= len(sample) and _valid_mp3_frame_header(sample[frame_offset:frame_offset + 4]):
                candidates.append(_candidate("MP3", "HIGH", "ID3 tag followed by a valid MPEG frame header"))
            else:
                candidates.append(_candidate("MP3", "MEDIUM", "ID3 tag without a validated MPEG frame header"))
    elif _valid_mp3_frame_header(sample[:4]):
        candidates.append(_candidate("MP3", "HIGH", "Validated MPEG frame header"))
    elif len(sample) >= 2 and sample[0] == 0xFF and (sample[1] & 0xE0) == 0xE0:
        candidates.append(_candidate("MP3", "MEDIUM", "Frame sync bits without a valid MPEG header"))
    return candidates


FORMAT_DETECTOR_REGISTRY = (
    {"name": "unity_bundle", "window": 32, "detector": _detect_unity},
    {"name": "mmd", "window": 32, "detector": _detect_mmd},
    {"name": "fbx", "window": 1024, "detector": _detect_fbx},
    {"name": "gltf", "window": 4096, "detector": _detect_gltf},
    {"name": "texture", "window": 64, "detector": _detect_textures},
    {"name": "archive", "window": 64, "detector": _detect_archives},
    {"name": "executable", "window": 4096, "detector": _detect_executables},
    {"name": "audio", "window": 256, "detector": _detect_audio},
)


FORMAT_EXTENSIONS = {
    "UNITYFS": {".bundle", ".assetbundle", ".unity3d", ".assets"},
    "UNITYRAW": {".bundle", ".assetbundle", ".unity3d", ".assets", ".raw"},
    "UNITYWEB": {".bundle", ".assetbundle", ".unity3d", ".assets", ".web"},
    "PMX": {".pmx"},
    "PMD": {".pmd"},
    "FBX_BINARY": {".fbx"},
    "FBX_ASCII": {".fbx"},
    "GLB": {".glb"},
    "GLTF": {".gltf"},
    "PNG": {".png"},
    "JPEG": {".jpg", ".jpeg"},
    "DDS": {".dds"},
    "KTX1": {".ktx"},
    "KTX2": {".ktx2"},
    "WEBP": {".webp"},
    "BMP": {".bmp"},
    "TIFF": {".tif", ".tiff"},
    "ZIP": {".zip"},
    "7Z": {".7z"},
    "RAR": {".rar"},
    "GZIP": {".gz"},
    "XZ": {".xz"},
    "PE": {".exe", ".dll"},
    "ELF": {".elf", ".so"},
    "WAV": {".wav"},
    "OGG": {".ogg"},
    "FLAC": {".flac"},
    "MP3": {".mp3"},
}
INSPECTOR_BY_FORMAT = {
    "UNITYFS": "UNITY_BUNDLE",
    "UNITYRAW": "UNITY_BUNDLE",
    "UNITYWEB": "UNITY_BUNDLE",
    "PMX": "PMX",
    "PMD": "PMX",
    "FBX_BINARY": "FBX",
    "FBX_ASCII": "FBX",
    "GLB": "GLTF",
    "GLTF": "GLTF",
    "PNG": "TEXTURE",
    "JPEG": "TEXTURE",
    "DDS": "TEXTURE",
    "KTX1": "TEXTURE",
    "KTX2": "TEXTURE",
    "WEBP": "TEXTURE",
    "BMP": "TEXTURE",
    "TIFF": "TEXTURE",
    "ZIP": "ARCHIVE",
    "7Z": "ARCHIVE",
    "RAR": "ARCHIVE",
    "GZIP": "ARCHIVE",
    "XZ": "ARCHIVE",
    "PE": "EXECUTABLE",
    "ELF": "EXECUTABLE",
    "WAV": "AUDIO",
    "OGG": "AUDIO",
    "FLAC": "AUDIO",
    "MP3": "AUDIO",
}
ASSET_KIND_BY_FORMAT = {
    "UNITYFS": "bundle",
    "UNITYRAW": "bundle",
    "UNITYWEB": "bundle",
    "PMX": "model",
    "PMD": "model",
    "FBX_BINARY": "model",
    "FBX_ASCII": "model",
    "GLB": "model",
    "GLTF": "model",
    "PNG": "texture",
    "JPEG": "texture",
    "DDS": "texture",
    "KTX1": "texture",
    "KTX2": "texture",
    "WEBP": "texture",
    "BMP": "texture",
    "TIFF": "texture",
    "ZIP": "archive",
    "7Z": "archive",
    "RAR": "archive",
    "GZIP": "archive",
    "XZ": "archive",
    "PE": "executable",
    "ELF": "executable",
    "WAV": "audio",
    "OGG": "audio",
    "FLAC": "audio",
    "MP3": "audio",
}


def _read_detector_sample(handle, size: int) -> bytes:
    limit = min(size, max(item["window"] for item in FORMAT_DETECTOR_REGISTRY), MAX_CONTENT_BYTES_READ)
    if limit <= 0:
        return b""
    return handle.read(limit)


def _run_detectors(sample: bytes, file_size: int) -> list[dict[str, str]]:
    candidates: list[dict[str, str]] = []
    for entry in FORMAT_DETECTOR_REGISTRY:
        detector: Callable[[bytes, int], list[dict[str, str]]] = entry["detector"]
        window = int(entry["window"])
        candidates.extend(detector(sample[:window], file_size))
    return candidates


def _pick_detected_format(candidates: list[dict[str, str]]) -> tuple[str, str | None]:
    if not candidates:
        return "UNKNOWN", None
    ranked = sorted(candidates, key=lambda item: CONFIDENCE_RANK[item["confidence"]], reverse=True)
    best = ranked[0]
    if best["confidence"] != "HIGH":
        return "UNKNOWN", None
    high_matches = [item for item in ranked if item["confidence"] == "HIGH"]
    if len(high_matches) != 1:
        return "UNKNOWN", None
    return best["format"], best["confidence"]


def _extension_match(relative_path: str, detected_format: str) -> str:
    if detected_format == "UNKNOWN":
        return "UNKNOWN"
    extension = Path(relative_path).suffix.casefold()
    expected = FORMAT_EXTENSIONS.get(detected_format)
    if not expected or not extension:
        return "UNKNOWN"
    return "MATCH" if extension in expected else "MISMATCH"


def _next_inspector(detected_format: str, confidence: str | None) -> str:
    if detected_format == "UNKNOWN" or confidence != "HIGH":
        return "NONE"
    return INSPECTOR_BY_FORMAT.get(detected_format, "NONE")


def _probed_asset_kind(detected_format: str) -> str:
    return ASSET_KIND_BY_FORMAT.get(detected_format, "unknown")


class FormatProbeService:
    def __init__(self, store: Store):
        self.store = store

    def probe(self, catalog_entry_ids: list[str]) -> list[dict[str, Any]]:
        if not isinstance(catalog_entry_ids, list) or not catalog_entry_ids:
            raise PolicyError("catalog_entry_ids must be a non-empty list")
        if len(catalog_entry_ids) > MAX_BATCH_ENTRIES:
            raise PolicyError("at most 50 catalog entries may be probed at once")
        results: list[dict[str, Any]] = []
        seen: set[str] = set()
        for entry_id in catalog_entry_ids:
            if entry_id in seen:
                continue
            seen.add(entry_id)
            results.append(self._probe_one(entry_id))
        return results

    def _base_payload(self, entry: dict[str, Any], relative_path: str) -> dict[str, Any]:
        return {
            "alias": entry["alias"],
            "relative_path": relative_path,
            "catalog_asset_kind": entry["asset_kind"],
            "probe_asset_kind": "unknown",
            "format_candidates": [],
            "detected_format": "UNKNOWN",
            "detected_confidence": None,
            "extension_match": "UNKNOWN",
            "next_inspector": "NONE",
            "full_parse_allowed": False,
            "bytes_read": 0,
            "sample_sha256": None,
            "detector_version": PROBE_VERSION,
            "reason_code": None,
        }

    def _probe_one(self, entry_id: str) -> dict[str, Any]:
        entry = self.store.catalog_entry_private(entry_id)
        if entry["status"] not in ALLOWED_ENTRY_STATUSES:
            payload = self._base_payload(entry, entry["relative_path"])
            payload["reason_code"] = f"CATALOG_STATUS_{entry['status']}"
            session = self.store.begin_format_probe(
                entry_id,
                PROBE_VERSION,
                cache_identity_for(entry["size"], entry["mtime_ns"], entry["file_id"], "unread"),
                "unread",
                payload,
            )
            if session["status"] in TERMINAL_STATES:
                return session
            return self.store.complete_format_probe(session["probe_id"], "REJECTED", {**session, "reason_code": payload["reason_code"]})

        try:
            root = validate_catalog_source_root(entry["root"])
            path, relative = resolve_catalog_entry_file(root, entry["relative_path"])
        except PolicyError as exc:
            payload = self._base_payload(entry, entry["relative_path"])
            payload["reason_code"] = str(exc)
            session = self.store.begin_format_probe(
                entry_id,
                PROBE_VERSION,
                cache_identity_for(entry["size"], entry["mtime_ns"], entry["file_id"], "unread"),
                "unread",
                payload,
            )
            if session["status"] in TERMINAL_STATES:
                return session
            return self.store.complete_format_probe(session["probe_id"], "REJECTED", {**session, "reason_code": payload["reason_code"]})

        try:
            before = path.stat()
        except OSError as exc:
            payload = self._base_payload(entry, relative)
            payload["reason_code"] = exc.__class__.__name__
            session = self.store.begin_format_probe(
                entry_id,
                PROBE_VERSION,
                cache_identity_for(entry["size"], entry["mtime_ns"], entry["file_id"], "stat-error"),
                "stat-error",
                payload,
            )
            if session["status"] in TERMINAL_STATES:
                return session
            return self.store.complete_format_probe(session["probe_id"], "FAILED", {**session, "reason_code": payload["reason_code"]})

        catalog_signature = (int(entry["size"]), int(entry["mtime_ns"]), str(entry["file_id"]))
        before_signature = _signature(before)

        try:
            with path.open("rb") as handle:
                opened_signature = _signature(os.fstat(handle.fileno()))
                if not _same_signature(opened_signature, before_signature):
                    raise PolicyError("FILE_CHANGED_DURING_PROBE")
                sample = _read_detector_sample(handle, int(before.st_size))
                if len(sample) > MAX_CONTENT_BYTES_READ:
                    raise PolicyError("format probe exceeded the per-file read budget")
                after_handle_signature = _signature(os.fstat(handle.fileno()))
            after_signature = _signature(path.stat())
        except PolicyError as exc:
            payload = self._base_payload(entry, relative)
            payload["reason_code"] = str(exc)
            session = self.store.begin_format_probe(
                entry_id,
                PROBE_VERSION,
                cache_identity_for(entry["size"], entry["mtime_ns"], entry["file_id"], "read-error"),
                "read-error",
                payload,
            )
            if session["status"] in TERMINAL_STATES:
                return session
            stale_status = "STALE" if str(exc) == "FILE_CHANGED_DURING_PROBE" else "FAILED"
            return self.store.complete_format_probe(session["probe_id"], stale_status, {**session, "reason_code": payload["reason_code"]})
        except OSError as exc:
            payload = self._base_payload(entry, relative)
            payload["reason_code"] = exc.__class__.__name__
            session = self.store.begin_format_probe(
                entry_id,
                PROBE_VERSION,
                cache_identity_for(entry["size"], entry["mtime_ns"], entry["file_id"], "io-error"),
                "io-error",
                payload,
            )
            if session["status"] in TERMINAL_STATES:
                return session
            return self.store.complete_format_probe(session["probe_id"], "FAILED", {**session, "reason_code": payload["reason_code"]})

        sample_sha256 = hashlib.sha256(sample).hexdigest() if sample else hashlib.sha256(b"").hexdigest()
        cache_identity = cache_identity_for(before_signature[0], before_signature[1], before_signature[2], sample_sha256)
        base_payload = self._base_payload(entry, relative)
        base_payload["sample_sha256"] = sample_sha256
        session = self.store.begin_format_probe(entry_id, PROBE_VERSION, cache_identity, sample_sha256, base_payload)
        if session["status"] in TERMINAL_STATES:
            return session

        if not _same_signature(before_signature, catalog_signature):
            return self.store.complete_format_probe(
                session["probe_id"],
                "STALE",
                {**session, "relative_path": relative, "bytes_read": len(sample), "sample_sha256": sample_sha256, "reason_code": "STALE_CATALOG_ENTRY"},
            )
        if not _same_signature(after_handle_signature, before_signature) or not _same_signature(after_signature, before_signature):
            return self.store.complete_format_probe(
                session["probe_id"],
                "STALE",
                {**session, "relative_path": relative, "bytes_read": len(sample), "sample_sha256": sample_sha256, "reason_code": "FILE_CHANGED_DURING_PROBE"},
            )

        probing = self.store.mark_format_probe_probing(session["probe_id"])
        candidates = _run_detectors(sample, int(before.st_size))
        detected_format, detected_confidence = _pick_detected_format(candidates)
        return self.store.complete_format_probe(
            probing["probe_id"],
            "COMPLETED",
            {
                **probing,
                "relative_path": relative,
                "format_candidates": candidates,
                "detected_format": detected_format,
                "detected_confidence": detected_confidence,
                "extension_match": _extension_match(relative, detected_format),
                "probe_asset_kind": _probed_asset_kind(detected_format),
                "next_inspector": _next_inspector(detected_format, detected_confidence),
                "full_parse_allowed": False,
                "bytes_read": len(sample),
                "sample_sha256": sample_sha256,
                "detector_version": PROBE_VERSION,
                "reason_code": None,
            },
        )
