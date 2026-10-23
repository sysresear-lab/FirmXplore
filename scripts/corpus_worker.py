"""Bounded, networkless worker for one local firmware corpus input.

This file runs inside the FirmXplore analysis image. It extracts a canonical
Linux root filesystem, optionally executes the deterministic deep-static
pipeline, and exports evidence without materializing device nodes on Windows.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tarfile
import time
import traceback

from fwagent.pipeline.analyzer import analyze_firmware
from fwagent.pipeline.product import AnalysisPipelineController, validate_rootfs_candidate


MAX_SOURCE_BYTES = 256 * 1024 * 1024
MAX_EXPANDED_BYTES = 5 * 1024 * 1024 * 1024
MAX_CANDIDATES = 96
SQUASHFS_MAGICS = (b"hsqs", b"sqsh", b"shsq", b"qshs")


def write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def run(command: list[str], timeout: int, *, cwd: Path | None = None) -> dict:
    started = time.monotonic()
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, cwd=cwd)
        return {"command": command, "exit_code": result.returncode,
                "stdout": result.stdout[-8000:], "stderr": result.stderr[-8000:],
                "duration_seconds": round(time.monotonic() - started, 3)}
    except subprocess.TimeoutExpired as exc:
        return {"command": command, "exit_code": None, "timed_out": True,
                "stdout": (exc.stdout or "")[-8000:] if isinstance(exc.stdout, str) else "",
                "stderr": (exc.stderr or "")[-8000:] if isinstance(exc.stderr, str) else "",
                "duration_seconds": round(time.monotonic() - started, 3)}


def regular_files(root: Path) -> list[Path]:
    result, total = [], 0
    if not root.exists():
        return result
    for base, dirs, files in os.walk(root, followlinks=False):
        dirs.sort()
        files.sort()
        for name in files:
            path = Path(base) / name
            try:
                info = path.lstat()
            except OSError:
                continue
            if stat.S_ISREG(info.st_mode):
                total += info.st_size
                if total > MAX_EXPANDED_BYTES:
                    raise ValueError("expanded archive budget exceeded")
                if 4096 <= info.st_size <= MAX_SOURCE_BYTES:
                    result.append(path)
            if len(result) > 20000:
                raise ValueError("archive member budget exceeded")
    return result


def unpack_wrappers(source: Path, destination: Path) -> tuple[list[Path], list[dict]]:
    """Unpack ordinary wrappers; never trust names as filesystem destinations."""
    attempts = []
    destination.mkdir(parents=True, exist_ok=True)
    first = run(["7z", "x", "-y", "-bd", f"-o{destination}", str(source)], 180)
    attempts.append({"stage": "wrapper", **first})
    candidates = [source] + regular_files(destination)
    # Common releases contain a second ZIP/TAR/GZ wrapper. Extract at most 16
    # bounded nested candidates into separate directories.
    nested_ext = {".zip", ".rar", ".tar", ".tgz", ".gz", ".xz", ".bz2", ".7z"}
    nested = [p for p in candidates[1:] if p.suffix.lower() in nested_ext][:16]
    for index, item in enumerate(nested):
        target = destination / f"nested-{index:02d}"
        target.mkdir()
        attempt = run(["7z", "x", "-y", "-bd", f"-o{target}", str(item)], 120)
        attempts.append({"stage": "nested_wrapper", "input": str(item.relative_to(destination)), **attempt})
    return [source] + regular_files(destination), attempts


def squashfs_offsets(path: Path) -> list[int]:
    offsets, absolute, tail = [], 0, b""
    with path.open("rb") as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                break
            data = tail + block
            origin = absolute - len(tail)
            for magic in SQUASHFS_MAGICS:
                start = 0
                while len(offsets) < 32:
                    found = data.find(magic, start)
                    if found < 0:
                        break
                    value = origin + found
                    if value >= 0 and value not in offsets:
                        offsets.append(value)
                    start = found + 1
            tail = data[-3:]
            absolute += len(block)
    return sorted(offsets)


def try_squashfs(candidate: Path, offset: int, work: Path, serial: int) -> tuple[Path | None, list[dict]]:
    attempts = []
    work.mkdir(parents=True, exist_ok=True)
    carved = work / f"carved-{serial:04d}-{offset}.bin"
    with candidate.open("rb") as source, carved.open("wb") as output:
        source.seek(offset)
        shutil.copyfileobj(source, output, 1024 * 1024)
    for tool in ("unsquashfs", "sasquatch"):
        target = work / f"rootfs-{serial:04d}-{offset}-{tool}"
        command = [tool, "-no-progress", "-processors", "2", "-d", str(target), str(carved)]
        outcome = run(command, 180)
        record = {"stage": "squashfs", "candidate": candidate.name,
                  "candidate_sha256": file_sha256(candidate),
                  "offset": offset, "tool": tool, **outcome}
        if outcome.get("exit_code") == 0:
            validation = validate_rootfs_candidate(target)
            record["validation"] = validation
            attempts.append(record)
            if validation.get("valid"):
                return target, attempts
        else:
            attempts.append(record)
    return None, attempts


def find_rootfs(source: Path, work: Path) -> tuple[Path | None, list[dict], list[Path]]:
    candidates, attempts = unpack_wrappers(source, work / "wrappers")
    candidates = sorted(set(candidates), key=lambda p: (-p.stat().st_size, str(p)))[:MAX_CANDIDATES]
    serial = 0
    valid = []
    for candidate in candidates:
        offsets = squashfs_offsets(candidate)
        if offsets:
            attempts.append({"stage": "signature_scan", "candidate": candidate.name,
                             "bytes": candidate.stat().st_size, "squashfs_offsets": offsets})
        for offset in offsets[:8]:
            serial += 1
            rootfs, records = try_squashfs(candidate, offset, work / "squashfs", serial)
            attempts.extend(records)
            if rootfs:
                valid.append(rootfs)
    if valid:
        ranked = sorted(valid, key=lambda p: (
            -int(validate_rootfs_candidate(p).get("elf_count") or 0),
            -int(validate_rootfs_candidate(p).get("file_count") or 0), str(p)))
        return ranked[0], attempts, candidates
    # Some camera images embed an initramfs inside a compressed kernel and have
    # no standalone SquashFS. Use binwalk only as a bounded fallback on up to
    # four largest non-wrapper members. The worker is already cap-less,
    # networkless, read-only, and constrained by the /work tmpfs quota.
    wrappers = {".zip", ".rar", ".tar", ".tgz", ".gz", ".xz", ".bz2", ".7z"}
    fallback = [p for p in candidates if p.suffix.lower() not in wrappers][:4]
    for index, candidate in enumerate(fallback):
        target = work / "binwalk" / f"candidate-{index:02d}"
        target.mkdir(parents=True, exist_ok=True)
        local = target / "firmware.bin"
        shutil.copyfile(candidate, local)
        outcome = run(["binwalk", "-Me", "--run-as=root", str(local)], 300, cwd=target)
        attempts.append({"stage": "recursive_binwalk", "candidate": candidate.name,
                         "candidate_sha256": file_sha256(candidate), **outcome})
        possible = []
        for base, dirs, files in os.walk(target, followlinks=False):
            base_path = Path(base)
            if "busybox" in files and base_path.name in {"bin", "sbin"}:
                possible.append(base_path.parent)
            if len(possible) > 64:
                break
        checked = set()
        for rootfs in possible:
            resolved = rootfs.resolve()
            if resolved in checked:
                continue
            checked.add(resolved)
            validation = validate_rootfs_candidate(rootfs)
            attempts.append({"stage": "binwalk_rootfs_validation",
                             "path": str(rootfs.relative_to(work)), "validation": validation})
            if validation.get("valid"):
                return rootfs, attempts, candidates
    return None, attempts, candidates


def archive_rootfs(rootfs: Path, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(target, "w:gz", dereference=False) as archive:
        archive.add(rootfs, arcname="rootfs", recursive=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--vendor", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--mode", choices=("extract", "static"), default="extract")
    args = parser.parse_args()
    source = Path("/input/firmware")
    output = Path("/out")
    task = output / args.task_id
    task.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    source_hash = file_sha256(source)
    identity = {"task_id": args.task_id, "vendor": args.vendor, "model": args.model,
                "filename": args.name, "source_sha256": source_hash,
                "source_bytes": source.stat().st_size, "mode": args.mode}
    write_json(task / "corpus_identity.json", identity)
    result = {**identity, "extraction_success": False, "static_requested": args.mode == "static"}
    try:
        if source.stat().st_size > MAX_SOURCE_BYTES:
            raise ValueError("source input budget exceeded")
        rootfs, attempts, candidates = find_rootfs(source, Path("/work"))
        result["candidate_files_scanned"] = len(candidates)
        result["attempts"] = attempts
        if not rootfs:
            result.update(status="no_canonical_rootfs", error_code="ROOTFS_NOT_FOUND")
        else:
            validation = validate_rootfs_candidate(rootfs)
            archive = task / "canonical-rootfs.tar.gz"
            archive_rootfs(rootfs, archive)
            result.update(status="extracted", extraction_success=True,
                          validation=validation, archive_sha256=file_sha256(archive),
                          archive_bytes=archive.stat().st_size)
            if args.mode == "static":
                os.chdir("/src")
                # Create the base report and task state, then import the verified
                # Linux filesystem and resume through the deterministic pipeline.
                if not (task / "task.json").is_file() and not (task / "state.json").is_file():
                    analyze_firmware(source, workspace=output, task_id=args.task_id, timeout=120)
                controller = AnalysisPipelineController(output)
                controller.import_extracted_rootfs(args.task_id, rootfs, source_firmware=source,
                    source_firmware_hash=source_hash, extraction_method="bounded-corpus-squashfs")
                summary = controller.analyze(source, task_id=args.task_id, resume=True, deep=True,
                    no_dynamic=True, timeout=1200, scan_timeout=2400,
                    report_formats={"json", "md", "html"}, progress=lambda value: print(value, flush=True))
                result["pipeline"] = summary
                result["static_completed"] = (task / "ghidra/analysis_summary.json").is_file()
                result["status"] = "static_complete" if result["static_completed"] else "static_incomplete"
    except Exception as exc:  # evidence must remain available for every input
        result.update(status="worker_failed", error_type=type(exc).__name__, error=str(exc)[:1000],
                      traceback=traceback.format_exc()[-8000:])
    result["duration_seconds"] = round(time.monotonic() - started, 3)
    write_json(task / "corpus_result.json", result)
    print(json.dumps({k: result.get(k) for k in ("task_id", "status", "extraction_success", "static_completed", "duration_seconds")}), flush=True)
    return 0 if result.get("extraction_success") else 2


if __name__ == "__main__":
    raise SystemExit(main())
