from __future__ import annotations

import os
import stat
import time
from collections import deque
from pathlib import Path
from typing import Any, Callable

from .policy import PolicyError, validate_catalog_source_root
from .storage import Store


BATCH_SIZE = 500
SCAN_STATES = frozenset({"PENDING", "SCANNING", "COMPLETED", "INTERRUPTED", "FAILED"})
ASSET_EXTENSIONS = {
    "bundle": {".assetbundle", ".bundle", ".unity3d", ".assets"},
    "model": {".fbx", ".pmx", ".obj", ".gltf", ".glb", ".dae"},
    "texture": {".png", ".jpg", ".jpeg", ".tga", ".dds", ".bmp", ".webp", ".ktx", ".ktx2"},
    "archive": {".zip", ".7z", ".rar", ".tar", ".gz", ".pak"},
    "text": {".txt", ".md", ".json", ".xml", ".yaml", ".yml", ".csv", ".ini", ".cfg", ".log"},
    "audio": {".wav", ".mp3", ".ogg", ".flac", ".m4a"},
    "executable": {".exe", ".dll", ".bat", ".cmd", ".com", ".msi"},
}


def asset_kind_for(relative_path: str) -> str:
    extension = Path(relative_path).suffix.casefold()
    for kind, extensions in ASSET_EXTENSIONS.items():
        if extension in extensions:
            return kind
    return "unknown"


def _is_reparse_entry(entry: os.DirEntry[str]) -> bool:
    if entry.is_symlink():
        return True
    try:
        attributes = getattr(entry.stat(follow_symlinks=False), "st_file_attributes", 0)
    except OSError:
        return False
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x0400))


def _entry_record(root: Path, entry: os.DirEntry[str], info: os.stat_result, status: str) -> dict[str, Any]:
    relative = Path(entry.path).relative_to(root).as_posix()
    return {
        "relative_path": relative,
        "normalized_path": relative.casefold(),
        "extension": Path(relative).suffix.casefold(),
        "size": int(info.st_size),
        "mtime_ns": int(info.st_mtime_ns),
        "file_id": f"{int(info.st_dev)}:{int(info.st_ino)}",
        "asset_kind": asset_kind_for(relative),
        "status": status,
    }


class CatalogService:
    """Phase 1 metadata catalog: scandir/stat only, never file content."""

    def __init__(self, store: Store):
        self.store = store

    def register_source(self, alias: str, root: str) -> dict[str, Any]:
        safe_root = validate_catalog_source_root(root)
        return self.store.create_catalog_source(alias, safe_root)

    def sources(self) -> list[dict[str, Any]]:
        return self.store.catalog_sources()

    def cancel(self, source_id: str) -> dict[str, Any]:
        self.store.catalog_source_private(source_id)
        self.store.request_catalog_scan_cancel(source_id)
        return {"source_id": source_id, "status": "cancel_requested"}

    def entries(self, source_id: str, **filters: Any) -> list[dict[str, Any]]:
        return self.store.catalog_entries(source_id, **filters)

    def scan(
        self,
        source_id: str,
        *,
        resume: bool = False,
        max_files: int | None = None,
        cancel_check: Callable[[], bool] | None = None,
    ) -> dict[str, Any]:
        session = self.store.begin_catalog_scan(source_id, resume=resume)
        source = session["source"]
        root = validate_catalog_source_root(source["root"])
        scan_id, generation = session["scan_id"], int(session["generation"])
        metrics = dict(session["payload"])
        metrics.setdefault("content_bytes_read", 0)
        started = time.monotonic()
        pending = deque(session.get("cursor") or [""])
        previous = self.store.catalog_entry_metadata(source_id)
        # Only this process's traversal participates in collision detection.  A
        # resumed scan deliberately revisits its last incomplete directory.
        seen: set[str] = set()
        batch: list[dict[str, Any]] = []
        rejected: list[dict[str, Any]] = []

        def flush() -> None:
            nonlocal batch, rejected
            if not batch and not rejected:
                return
            metrics["duration"] = round(time.monotonic() - started, 6)
            self.store.apply_catalog_batch(scan_id, source_id, generation, batch, rejected, list(pending), metrics)
            batch, rejected = [], []

        try:
            while pending:
                if self.store.catalog_scan_cancel_requested(scan_id) or (cancel_check and cancel_check()):
                    flush()
                    metrics["duration"] = round(time.monotonic() - started, 6)
                    return self.store.finish_catalog_scan(scan_id, source_id, generation, "INTERRUPTED", metrics, list(pending))
                directory_relative = pending.popleft()
                directory = root / directory_relative
                try:
                    with os.scandir(directory) as entries:
                        # Keep directory walking streaming as well: a game data
                        # directory may contain millions of entries.
                        for entry in entries:
                            if self.store.catalog_scan_cancel_requested(scan_id) or (cancel_check and cancel_check()):
                                flush()
                                pending.appendleft(directory_relative)
                                metrics["duration"] = round(time.monotonic() - started, 6)
                                return self.store.finish_catalog_scan(scan_id, source_id, generation, "INTERRUPTED", metrics, list(pending))
                            relative = Path(entry.path).relative_to(root).as_posix()
                            normalized = relative.casefold()
                            if _is_reparse_entry(entry):
                                rejected.append({"relative_path": relative, "normalized_path": normalized, "extension": Path(relative).suffix.casefold()})
                                metrics["rejected"] = int(metrics.get("rejected", 0)) + 1
                                continue
                            try:
                                if entry.is_dir(follow_symlinks=False):
                                    pending.append(relative)
                                    continue
                                if not entry.is_file(follow_symlinks=False):
                                    continue
                                info = entry.stat(follow_symlinks=False)
                            except OSError:
                                rejected.append({"relative_path": relative, "normalized_path": normalized, "extension": Path(relative).suffix.casefold()})
                                metrics["rejected"] = int(metrics.get("rejected", 0)) + 1
                                continue
                            if normalized in seen:
                                # Two spellings that collide on Windows must not silently merge.
                                rejected.append({"relative_path": relative, "normalized_path": normalized, "extension": Path(relative).suffix.casefold()})
                                metrics["rejected"] = int(metrics.get("rejected", 0)) + 1
                                continue
                            seen.add(normalized)
                            old = previous.get(normalized)
                            already_in_generation = bool(old and int(old["scan_generation"]) == generation)
                            status = "ADDED"
                            if old:
                                same = (old["size"], old["mtime_ns"], old["file_id"]) == (int(info.st_size), int(info.st_mtime_ns), f"{int(info.st_dev)}:{int(info.st_ino)}")
                                status = "UNCHANGED" if same else "MODIFIED"
                            record = _entry_record(root, entry, info, status)
                            batch.append(record)
                            if not already_in_generation:
                                metrics["files_seen"] = int(metrics.get("files_seen", 0)) + 1
                                metrics["bytes_indexed"] = int(metrics.get("bytes_indexed", 0)) + int(info.st_size)
                                metrics[status.lower()] = int(metrics.get(status.lower(), 0)) + 1
                                if max_files is not None and metrics["files_seen"] >= max_files:
                                    flush()
                                    pending.appendleft(directory_relative)
                                    metrics["duration"] = round(time.monotonic() - started, 6)
                                    return self.store.finish_catalog_scan(scan_id, source_id, generation, "INTERRUPTED", metrics, list(pending))
                            if len(batch) + len(rejected) >= BATCH_SIZE:
                                flush()
                except OSError as exc:
                    raise PolicyError("catalog directory could not be scanned") from exc
            flush()
            metrics["duration"] = round(time.monotonic() - started, 6)
            return self.store.finish_catalog_scan(scan_id, source_id, generation, "COMPLETED", metrics)
        except Exception:
            flush()
            metrics["duration"] = round(time.monotonic() - started, 6)
            self.store.finish_catalog_scan(scan_id, source_id, generation, "FAILED", metrics, list(pending))
            raise
