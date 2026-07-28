from __future__ import annotations

import codecs
import hashlib
import json
import os
import shutil
import stat
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from .policy import (
    PolicyError,
    canonical_json,
    canonical_path_text,
    evidence_fingerprint,
    is_link_or_junction,
    resolve_evidence_file,
    sha256_json,
    sha256_text,
)
from .storage import Store


CAPSULE_VERSION = 2
STREAM_CHUNK_BYTES = 64 * 1024
MAX_FULL_FILE_BYTES = 128 * 1024
MAX_RANGE_LINES = 250
MAX_FILE_RANGE_LINES = 1_000
MAX_SINGLE_LINE_BYTES = 64 * 1024
MAX_CAPSULE_FILES = 15
MAX_CAPSULE_BYTES = 1 * 1024 * 1024


@dataclass
class SourceScan:
    status: str
    source_sha256: str | None = None
    source_size: int = 0
    encoding: str | None = None
    full_content: bytes | None = None
    selected_lines: list[tuple[int, bytes]] | None = None
    line_count: int = 0
    reason: str | None = None


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _inside(root: Path, candidate: Path) -> Path:
    resolved_root = root.resolve(strict=False)
    resolved_candidate = candidate.resolve(strict=False)
    try:
        resolved_candidate.relative_to(resolved_root)
    except ValueError as exc:
        raise PolicyError("Capsule path escapes DATA_ROOT") from exc
    return resolved_candidate


def _stat_signature(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _source_key(entry: Mapping[str, Any]) -> str:
    return canonical_path_text(str(entry["path"]))


def _readonly_tree(root: Path) -> None:
    for directory, _, names in os.walk(root):
        folder = Path(directory)
        for name in names:
            os.chmod(folder / name, stat.S_IREAD)
    for directory, _, _ in os.walk(root, topdown=False):
        os.chmod(Path(directory), stat.S_IREAD | stat.S_IEXEC)


def _remove_tree(root: Path) -> None:
    if not root.exists():
        return

    def restore_write(function: Any, path: str, _: Any) -> None:
        os.chmod(path, stat.S_IREAD | stat.S_IWRITE | stat.S_IEXEC)
        function(path)

    shutil.rmtree(root, onerror=restore_write)


class CapsuleBuilder:
    """Create and revalidate deterministic evidence bundles without contacting app-server."""

    def __init__(self, store: Store):
        self.store = store

    def create(self, route_plan_id: str) -> dict[str, Any]:
        plan = self.store.load_route_plan(route_plan_id)
        self._validate_plan_eligibility(plan)
        evidence_files, ranges_by_path, sources = self._sealed_scope(plan)
        fingerprint = evidence_fingerprint(
            plan["task_hash"], plan["decision_hash"], evidence_files, plan["evidence_ranges"], sources,
        )
        capsule_id = self._capsule_id(plan, sources)
        overlap = set(evidence_files) & set(ranges_by_path)
        if overlap:
            return self._save_result(
                plan, capsule_id, fingerprint, "HOLD", None,
                ["evidence_files and evidence_ranges must not select the same path."],
            )

        full_preflight = self._preflight_full_file_limits(plan, evidence_files, sources)
        if full_preflight:
            status, reason = full_preflight
            return self._save_result(plan, capsule_id, fingerprint, status, None, [reason])

        existing = self.store.load_evidence_capsule(plan["plan_id"])
        if existing:
            if existing["status"] == "INVALID":
                raise PolicyError("Evidence Capsule is invalid; create a new Route Plan")
            if existing["status"] == "HOLD":
                return existing
            captured = self._capture_evidence(plan, evidence_files, ranges_by_path, sources, capture=False)
            if captured[2]:
                return self._save_result(plan, capsule_id, fingerprint, "INVALID", None, captured[2])
            if captured[3]:
                return self._save_result(plan, capsule_id, fingerprint, "HOLD", None, captured[3])
            valid, reason = self._verify_existing_capsule(plan, existing, fingerprint)
            if valid:
                return existing
            return self._save_result(plan, capsule_id, fingerprint, "INVALID", None, [reason])

        try:
            existing_path = self._capsule_dir(plan["plan_id"], capsule_id)
        except PolicyError as exc:
            return self._save_result(plan, capsule_id, fingerprint, "INVALID", None, [str(exc)])
        if existing_path.exists():
            return self._save_result(
                plan, capsule_id, fingerprint, "INVALID", None,
                ["Evidence Capsule directory exists without a verified READY record."],
            )

        generated, evidence_entries, invalid_reasons, hold_reasons = self._capture_evidence(
            plan, evidence_files, ranges_by_path, sources, capture=True,
        )
        if invalid_reasons:
            return self._save_result(plan, capsule_id, fingerprint, "INVALID", None, invalid_reasons)
        if hold_reasons:
            return self._save_result(plan, capsule_id, fingerprint, "HOLD", None, hold_reasons)

        generated = {**self._metadata_files(plan), **generated}
        if len(generated) + 1 > MAX_CAPSULE_FILES:
            return self._save_result(
                plan, capsule_id, fingerprint, "HOLD", None,
                [f"Evidence Capsule would contain {len(generated) + 1} files; the maximum is {MAX_CAPSULE_FILES}."],
            )

        content_hashes = {path: _sha256_bytes(value) for path, value in sorted(generated.items())}
        manifest_base = {
            "version": CAPSULE_VERSION,
            "route_plan": {
                "plan_id": plan["plan_id"],
                "decision_hash": plan["decision_hash"],
                "task_hash": plan["task_hash"],
                "integrity_hash": plan["integrity_hash"],
            },
            "evidence_fingerprint": fingerprint,
            "evidence": evidence_entries,
            "content_file_hashes": content_hashes,
        }
        manifest_canonical_hash = sha256_json(manifest_base)
        capsule_hash = self._capsule_hash(manifest_base)
        manifest = {
            **manifest_base,
            "capsule_id": capsule_id,
            "capsule_hash": capsule_hash,
            "manifest_canonical_hash": manifest_canonical_hash,
        }
        generated["EVIDENCE_MANIFEST.json"] = (canonical_json(manifest) + "\n").encode("utf-8")
        total_bytes = sum(len(value) for value in generated.values())
        if total_bytes > MAX_CAPSULE_BYTES:
            return self._save_result(
                plan, capsule_id, fingerprint, "HOLD", None,
                [f"Evidence Capsule would contain {total_bytes} bytes; the maximum is {MAX_CAPSULE_BYTES} bytes."],
            )

        self._write_capsule(plan["plan_id"], capsule_id, generated)
        _, _, invalid_reasons, hold_reasons = self._capture_evidence(
            plan, evidence_files, ranges_by_path, sources, capture=False,
        )
        if invalid_reasons or hold_reasons:
            _remove_tree(self._capsule_dir(plan["plan_id"], capsule_id))
            status = "INVALID" if invalid_reasons else "HOLD"
            return self._save_result(plan, capsule_id, fingerprint, status, None, invalid_reasons or hold_reasons)
        return self._save_result(
            plan, capsule_id, fingerprint, "READY", capsule_hash, [],
            file_count=len(generated),
            total_bytes=total_bytes,
        )

    def _validate_plan_eligibility(self, plan: Mapping[str, Any]) -> None:
        if plan.get("status") != "PREVIEW":
            raise PolicyError("Evidence Capsules require a PREVIEW Route Plan")
        if plan.get("permission") != "read-only":
            raise PolicyError("Evidence Capsules require a Read Only Route Plan")
        if plan.get("used"):
            raise PolicyError("Evidence Capsules cannot be created for a claimed Route Plan")
        try:
            expires_at = datetime.fromisoformat(str(plan["expires_at"]))
        except (KeyError, TypeError, ValueError) as exc:
            raise PolicyError("Route Plan expiry was modified") from exc
        if expires_at.tzinfo is None:
            raise PolicyError("Route Plan expiry was modified")
        if expires_at <= datetime.now(timezone.utc):
            raise PolicyError("Route Plan has expired")

    def _sealed_scope(
        self,
        plan: Mapping[str, Any],
    ) -> tuple[set[str], dict[str, list[dict[str, int | str]]], list[dict[str, Any]]]:
        evidence_files = plan.get("evidence_files")
        evidence_ranges = plan.get("evidence_ranges")
        sources = plan.get("evidence_sources")
        if not isinstance(evidence_files, list) or not isinstance(evidence_ranges, list) or not isinstance(sources, list):
            raise PolicyError("Route Plan does not contain sealed evidence metadata")
        if not all(isinstance(item, str) for item in evidence_files):
            raise PolicyError("Route Plan evidence_files were modified")
        if not all(isinstance(item, dict) for item in evidence_ranges + sources):
            raise PolicyError("Route Plan evidence metadata was modified")
        files = {canonical_path_text(item) for item in evidence_files}
        ranges_by_path: dict[str, list[dict[str, int | str]]] = {}
        for entry in evidence_ranges:
            try:
                path = canonical_path_text(str(entry["path"]))
                start_line = int(entry["start_line"])
                end_line = int(entry["end_line"])
            except (KeyError, TypeError, ValueError) as exc:
                raise PolicyError("Route Plan evidence_ranges were modified") from exc
            ranges_by_path.setdefault(path, []).append({
                "path": str(entry["path"]), "start_line": start_line, "end_line": end_line,
            })
        source_paths = {_source_key(entry) for entry in sources}
        if source_paths != files | set(ranges_by_path):
            raise PolicyError("Route Plan source metadata does not match its evidence scope")
        for entry in sources:
            if not isinstance(entry.get("sha256"), str) or not isinstance(entry.get("size"), int):
                raise PolicyError("Route Plan evidence source metadata was modified")
        return files, ranges_by_path, sorted(sources, key=_source_key)

    def _preflight_full_file_limits(
        self,
        plan: Mapping[str, Any],
        evidence_files: set[str],
        sources: Sequence[dict[str, Any]],
    ) -> tuple[str, str] | None:
        for source in sources:
            if _source_key(source) not in evidence_files:
                continue
            path_text = str(source["path"])
            try:
                path, _ = resolve_evidence_file(str(plan["root"]), path_text)
                source_stat = path.stat()
            except (OSError, PolicyError) as exc:
                return "INVALID", f"Evidence source is unavailable: {path_text} ({exc})"
            if source_stat.st_size != source["size"]:
                return "INVALID", f"{path_text} size no longer matches the Route Plan"
            if source_stat.st_size > MAX_FULL_FILE_BYTES:
                return "HOLD", (
                    f"{path_text} is {source_stat.st_size} bytes; whole-file evidence is limited to "
                    f"{MAX_FULL_FILE_BYTES} bytes."
                )
        return None

    def _capture_evidence(
        self,
        plan: Mapping[str, Any],
        evidence_files: set[str],
        ranges_by_path: Mapping[str, list[dict[str, int | str]]],
        sources: Sequence[dict[str, Any]],
        *,
        capture: bool,
    ) -> tuple[dict[str, bytes], list[dict[str, Any]], list[str], list[str]]:
        generated: dict[str, bytes] = {}
        manifest_entries: list[dict[str, Any]] = []
        invalid_reasons: list[str] = []
        hold_reasons: list[str] = []
        for source in sources:
            source_path = str(source["path"])
            key = _source_key(source)
            try:
                path, relative = resolve_evidence_file(str(plan["root"]), source_path)
            except (OSError, PolicyError) as exc:
                invalid_reasons.append(f"Evidence source is unavailable: {source_path} ({exc})")
                continue
            if key in evidence_files:
                scan = self._scan_full_source(path, source, capture=capture)
                mode = "full"
                line_ranges: list[dict[str, int]] = []
            else:
                ranges = ranges_by_path.get(key, [])
                scan = self._scan_range_source(path, source, ranges, capture=capture)
                mode = "ranges"
                line_ranges = [
                    {"start_line": int(entry["start_line"]), "end_line": int(entry["end_line"])}
                    for entry in ranges
                ]
            if scan.status == "INVALID":
                invalid_reasons.append(f"{source_path}: {scan.reason}")
                continue
            if scan.status == "HOLD":
                hold_reasons.append(f"{source_path}: {scan.reason}")
                continue
            if not capture:
                continue
            if mode == "full":
                assert scan.full_content is not None
                output_path = f"files/{relative}"
                generated[output_path] = scan.full_content
            else:
                assert scan.selected_lines is not None and scan.encoding is not None
                output_path = f"snippets/{sha256_text(relative)[:16]}.txt"
                generated[output_path] = self._snippet_bytes(scan.selected_lines, scan.encoding)
            manifest_entries.append({
                "path": relative,
                "mode": mode,
                "source_sha256": source["sha256"],
                "source_size": source["size"],
                "captured_size": len(generated[output_path]),
                "encoding": scan.encoding,
                "line_ranges": line_ranges,
                "capsule_path": output_path,
            })
        return generated, manifest_entries, invalid_reasons, hold_reasons

    def _scan_full_source(self, path: Path, expected: Mapping[str, Any], *, capture: bool) -> SourceScan:
        try:
            before_path = path.stat()
            with path.open("rb") as source:
                before_open = os.fstat(source.fileno())
                if _stat_signature(before_path) != _stat_signature(before_open):
                    return SourceScan("INVALID", reason="source was replaced before streaming")
                if before_open.st_size != expected["size"]:
                    return SourceScan("INVALID", reason="source size no longer matches the Route Plan")
                if before_open.st_size > MAX_FULL_FILE_BYTES:
                    return SourceScan("HOLD", reason=f"whole-file evidence exceeds {MAX_FULL_FILE_BYTES} bytes")
                digest = hashlib.sha256()
                inspector = _TextInspector()
                total = 0
                content = bytearray()
                while chunk := source.read(STREAM_CHUNK_BYTES):
                    total += len(chunk)
                    digest.update(chunk)
                    inspector.feed(chunk)
                    if capture and total <= MAX_FULL_FILE_BYTES:
                        content.extend(chunk)
                after_open = os.fstat(source.fileno())
            after_path = path.stat()
        except OSError as exc:
            return SourceScan("INVALID", reason=f"source cannot be streamed ({exc})")
        return self._finish_scan(
            expected, before_path, before_open, after_open, after_path, digest.hexdigest(), total, inspector,
            full_content=bytes(content) if capture else None,
        )

    def _scan_range_source(
        self,
        path: Path,
        expected: Mapping[str, Any],
        ranges: Sequence[dict[str, int | str]],
        *,
        capture: bool,
    ) -> SourceScan:
        requested_lines = sum(int(entry["end_line"]) - int(entry["start_line"]) + 1 for entry in ranges)
        if requested_lines > MAX_FILE_RANGE_LINES:
            return SourceScan("HOLD", reason=f"requested ranges exceed {MAX_FILE_RANGE_LINES} lines")
        try:
            before_path = path.stat()
            with path.open("rb") as source:
                before_open = os.fstat(source.fileno())
                if _stat_signature(before_path) != _stat_signature(before_open):
                    return SourceScan("INVALID", reason="source was replaced before streaming")
                digest = hashlib.sha256()
                inspector = _TextInspector()
                selected: list[tuple[int, bytes]] = []
                selected_bytes = 0
                total_bytes = 0
                line_number = 0
                long_line = False
                read_limit = MAX_SINGLE_LINE_BYTES + 1
                while first := source.readline(read_limit):
                    line_number += 1
                    self._feed_part(digest, inspector, first)
                    line_size = len(first)
                    requires_continuation = len(first) == read_limit and not first.endswith(b"\n")
                    while requires_continuation:
                        continuation = source.readline(read_limit)
                        if not continuation:
                            break
                        self._feed_part(digest, inspector, continuation)
                        line_size += len(continuation)
                        requires_continuation = len(continuation) == read_limit and not continuation.endswith(b"\n")
                    total_bytes += line_size
                    if line_size > MAX_SINGLE_LINE_BYTES:
                        long_line = True
                        continue
                    if capture and self._line_is_selected(line_number, ranges):
                        if selected_bytes + line_size > MAX_CAPSULE_BYTES:
                            long_line = True
                            continue
                        selected.append((line_number, first))
                        selected_bytes += line_size
                after_open = os.fstat(source.fileno())
            after_path = path.stat()
        except OSError as exc:
            return SourceScan("INVALID", reason=f"source cannot be streamed ({exc})")
        result = self._finish_scan(
            expected, before_path, before_open, after_open, after_path,
            digest.hexdigest(), total_bytes, inspector,
            selected_lines=selected if capture else None,
            line_count=line_number,
        )
        if result.status != "OK":
            return result
        if long_line:
            return SourceScan("HOLD", reason=f"a source line exceeds {MAX_SINGLE_LINE_BYTES} bytes")
        if any(int(entry["end_line"]) > line_number for entry in ranges):
            return SourceScan("HOLD", reason="a requested range is outside the source file")
        return result

    @staticmethod
    def _feed_part(digest: hashlib._Hash, inspector: "_TextInspector", value: bytes) -> None:
        digest.update(value)
        inspector.feed(value)

    @staticmethod
    def _line_is_selected(line_number: int, ranges: Sequence[dict[str, int | str]]) -> bool:
        return any(int(item["start_line"]) <= line_number <= int(item["end_line"]) for item in ranges)

    def _finish_scan(
        self,
        expected: Mapping[str, Any],
        before_path: os.stat_result,
        before_open: os.stat_result,
        after_open: os.stat_result,
        after_path: os.stat_result,
        source_hash: str,
        source_size: int,
        inspector: "_TextInspector",
        *,
        full_content: bytes | None = None,
        selected_lines: list[tuple[int, bytes]] | None = None,
        line_count: int = 0,
    ) -> SourceScan:
        if not (
            _stat_signature(before_path) == _stat_signature(before_open) == _stat_signature(after_open)
            and _stat_signature(after_open) == _stat_signature(after_path)
        ):
            return SourceScan("INVALID", reason="source was replaced or changed during streaming")
        text_status, encoding = inspector.finish()
        if source_hash != expected["sha256"] or source_size != expected["size"]:
            return SourceScan("INVALID", reason="source SHA-256 or size no longer matches the Route Plan")
        if text_status:
            return SourceScan("HOLD", reason=text_status)
        return SourceScan(
            "OK", source_sha256=source_hash, source_size=source_size, encoding=encoding,
            full_content=full_content, selected_lines=selected_lines, line_count=line_count,
        )

    @staticmethod
    def _snippet_bytes(selected_lines: Sequence[tuple[int, bytes]], encoding: str) -> bytes:
        rendered: list[str] = []
        for line_number, raw in selected_lines:
            decoder = "utf-8-sig" if encoding == "utf-8-sig" and line_number == 1 else "utf-8"
            if encoding == "ascii":
                decoder = "ascii"
            text = raw.decode(decoder).rstrip("\r\n")
            rendered.append(f"{line_number}: {text}")
        return ("\n".join(rendered) + "\n").encode("utf-8")

    def _verify_existing_capsule(
        self,
        plan: Mapping[str, Any],
        existing: Mapping[str, Any],
        fingerprint: str,
    ) -> tuple[bool, str]:
        if existing.get("evidence_fingerprint") != fingerprint:
            return False, "stored Evidence Capsule fingerprint does not match the Route Plan"
        try:
            capsule_dir = self._capsule_dir(str(plan["plan_id"]), str(existing["capsule_id"]))
            manifest_path = capsule_dir / "EVIDENCE_MANIFEST.json"
            if is_link_or_junction(manifest_path):
                return False, "Evidence Capsule manifest is a symlink or junction"
            if manifest_path.stat().st_size > MAX_CAPSULE_BYTES:
                return False, "Evidence Capsule manifest exceeds the capsule size limit"
            with manifest_path.open("r", encoding="utf-8") as source:
                manifest = json.load(source)
        except (OSError, ValueError, PolicyError) as exc:
            return False, f"Evidence Capsule manifest cannot be verified ({exc})"
        if not isinstance(manifest, dict):
            return False, "Evidence Capsule manifest is malformed"
        instance_fields = {"capsule_id", "capsule_hash", "manifest_canonical_hash"}
        if not instance_fields <= set(manifest):
            return False, "Evidence Capsule manifest is missing integrity fields"
        manifest_base = {key: value for key, value in manifest.items() if key not in instance_fields}
        if sha256_json(manifest_base) != manifest.get("manifest_canonical_hash"):
            return False, "Evidence Capsule manifest canonical hash does not match"
        if manifest.get("capsule_id") != existing.get("capsule_id"):
            return False, "Evidence Capsule manifest instance ID does not match"
        actual_hash = self._capsule_hash(manifest_base)
        if manifest.get("capsule_hash") != actual_hash or existing.get("capsule_hash") != actual_hash:
            return False, "Evidence Capsule instance hash does not match"
        route_plan = manifest_base.get("route_plan")
        if not isinstance(route_plan, dict) or route_plan != {
            "plan_id": plan["plan_id"],
            "decision_hash": plan["decision_hash"],
            "task_hash": plan["task_hash"],
            "integrity_hash": plan["integrity_hash"],
        }:
            return False, "Evidence Capsule manifest Route Plan binding does not match"
        if manifest_base.get("evidence_fingerprint") != fingerprint:
            return False, "Evidence Capsule manifest fingerprint does not match"
        content_hashes = manifest_base.get("content_file_hashes")
        if not isinstance(content_hashes, dict) or not all(isinstance(path, str) and isinstance(value, str) for path, value in content_hashes.items()):
            return False, "Evidence Capsule manifest file hashes are malformed"
        actual_files, actual_dirs, error = self._capsule_tree(capsule_dir)
        if error:
            return False, error
        expected_files = set(content_hashes) | {"EVIDENCE_MANIFEST.json"}
        expected_dirs: set[str] = set()
        for relative in content_hashes:
            parent = Path(relative).parent
            while parent != Path("."):
                expected_dirs.add(parent.as_posix())
                parent = parent.parent
        if set(actual_files) != expected_files or actual_dirs != expected_dirs:
            return False, "Evidence Capsule has missing or additional files"
        for relative, expected_hash in content_hashes.items():
            path = capsule_dir / relative
            if not self._safe_capsule_member(capsule_dir, path):
                return False, "Evidence Capsule file path escapes its directory"
            try:
                digest = hashlib.sha256()
                with path.open("rb") as source:
                    while chunk := source.read(STREAM_CHUNK_BYTES):
                        digest.update(chunk)
            except OSError as exc:
                return False, f"Evidence Capsule file cannot be read ({exc})"
            if digest.hexdigest() != expected_hash:
                return False, "Evidence Capsule file hash does not match the manifest"
        return True, ""

    def _capsule_tree(self, capsule_dir: Path) -> tuple[set[str], set[str], str | None]:
        files: set[str] = set()
        directories: set[str] = set()
        pending = [capsule_dir]
        while pending:
            current = pending.pop()
            if is_link_or_junction(current):
                return files, directories, "Evidence Capsule contains a symlink or junction"
            try:
                entries = list(current.iterdir())
            except OSError as exc:
                return files, directories, f"Evidence Capsule directory cannot be read ({exc})"
            for entry in entries:
                if is_link_or_junction(entry):
                    return files, directories, "Evidence Capsule contains a symlink or junction"
                relative = entry.relative_to(capsule_dir).as_posix()
                if entry.is_dir():
                    directories.add(relative)
                    pending.append(entry)
                elif entry.is_file():
                    files.add(relative)
                else:
                    return files, directories, "Evidence Capsule contains a non-regular file"
        return files, directories, None

    @staticmethod
    def _safe_capsule_member(root: Path, candidate: Path) -> bool:
        try:
            candidate.relative_to(root)
        except ValueError:
            return False
        return not is_link_or_junction(candidate)

    def _metadata_files(self, plan: Mapping[str, Any]) -> dict[str, bytes]:
        task = f"# Task\n\n{plan['task']}\n"
        route_plan = {
            "plan_id": plan["plan_id"],
            "decision_hash": plan["decision_hash"],
            "task_hash": plan["task_hash"],
            "project_id": plan["project_id"],
            "permission": plan["permission"],
            "decision": plan["decision"],
            "evidence_files": plan["evidence_files"],
            "evidence_ranges": plan["evidence_ranges"],
            "evidence_sources": plan["evidence_sources"],
        }
        return {
            "TASK.md": task.encode("utf-8"),
            "ROUTE_PLAN.json": (canonical_json(route_plan) + "\n").encode("utf-8"),
        }

    def _capsule_dir(self, plan_id: str, capsule_id: str) -> Path:
        root = self.store.root.resolve(strict=False)
        candidate = root
        for part in ("capsules", plan_id, capsule_id):
            candidate /= part
            if candidate.exists() and is_link_or_junction(candidate):
                raise PolicyError("Evidence Capsule path contains a symlink or junction")
        return _inside(root, candidate)

    def _write_capsule(self, plan_id: str, capsule_id: str, generated: Mapping[str, bytes]) -> None:
        capsule_dir = self._capsule_dir(plan_id, capsule_id)
        root = self.store.root.resolve(strict=False)
        plan_dir = _inside(root, capsule_dir.parent)
        plan_dir.mkdir(parents=True, exist_ok=True)
        if capsule_dir.exists():
            raise PolicyError("Evidence Capsule path already exists without verified contents")
        temporary = Path(tempfile.mkdtemp(prefix=f".{capsule_id[:12]}-", dir=plan_dir))
        try:
            for relative, content in generated.items():
                destination = _inside(temporary, temporary / relative)
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(content)
            _readonly_tree(temporary)
            temporary.rename(capsule_dir)
        except Exception:
            _remove_tree(temporary)
            raise

    @staticmethod
    def _capsule_hash(manifest_base: Mapping[str, Any]) -> str:
        return sha256_json({
            "manifest": manifest_base,
            "generated_file_hashes": manifest_base["content_file_hashes"],
        })

    def _capsule_id(self, plan: Mapping[str, Any], sources: Sequence[dict[str, Any]]) -> str:
        return sha256_json({
            "version": CAPSULE_VERSION,
            "plan_id": plan["plan_id"],
            "route_plan_integrity_hash": plan["integrity_hash"],
            "evidence_sources": sources,
        })[:32]

    def _save_result(
        self,
        plan: Mapping[str, Any],
        capsule_id: str,
        fingerprint: str,
        status: str,
        capsule_hash: str | None,
        reasons: Sequence[str],
        *,
        file_count: int = 0,
        total_bytes: int = 0,
    ) -> dict[str, Any]:
        return self.store.save_evidence_capsule(plan["plan_id"], {
            "plan_id": plan["plan_id"],
            "capsule_id": capsule_id,
            "status": status,
            "capsule_hash": capsule_hash,
            "evidence_fingerprint": fingerprint,
            "file_count": file_count,
            "total_bytes": total_bytes,
            "hold_reasons": list(dict.fromkeys(reasons)),
        })


class _TextInspector:
    def __init__(self):
        self._decoder = codecs.getincrementaldecoder("utf-8")("strict")
        self._prefix = bytearray()
        self._has_non_ascii = False
        self._has_nul = False
        self._decode_error = False

    def feed(self, value: bytes) -> None:
        if len(self._prefix) < 3:
            self._prefix.extend(value[:3 - len(self._prefix)])
        self._has_nul = self._has_nul or b"\0" in value
        self._has_non_ascii = self._has_non_ascii or any(byte > 0x7F for byte in value)
        if not self._decode_error:
            try:
                self._decoder.decode(value, final=False)
            except UnicodeDecodeError:
                self._decode_error = True

    def finish(self) -> tuple[str | None, str | None]:
        if not self._decode_error:
            try:
                self._decoder.decode(b"", final=True)
            except UnicodeDecodeError:
                self._decode_error = True
        if self._has_nul:
            return "binary source files cannot be copied into an Evidence Capsule", None
        if self._decode_error:
            return "source file has an unsupported encoding", None
        if bytes(self._prefix).startswith(b"\xef\xbb\xbf"):
            return None, "utf-8-sig"
        return None, "utf-8" if self._has_non_ascii else "ascii"


def create_evidence_capsule(store: Store, route_plan_id: str) -> dict[str, Any]:
    return CapsuleBuilder(store).create(route_plan_id)
