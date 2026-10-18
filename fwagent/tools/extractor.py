from __future__ import annotations

import gzip
import io
import os
import shutil
import stat
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from fwagent.runtime.command import CommandRunner
from fwagent.runtime.scanning import run_bounded_scan
from fwagent.dynamic.guest_paths import guest_parts, guest_path
from fwagent.tools.common import _raise_walk_error, is_regular_file, is_scan_directory, is_within, iter_files, open_regular_file, read_prefix, safe_exists, safe_is_dir


@dataclass(frozen=True)
class ExtractionLimits:
    members: int = 4096
    depth: int = 32
    file_bytes: int = 64 * 1024 * 1024
    total_bytes: int = 128 * 1024 * 1024
    input_bytes: int = 64 * 1024 * 1024
    metadata_bytes: int = 4 * 1024 * 1024


class ExtractionQuotaError(ValueError):
    pass


class _ExtractionBudget:
    def __init__(self, destination: Path, limits: ExtractionLimits):
        self.limits = limits;self.members = 0;self.declared = 0;self.written = 0
        stack = [destination]
        while stack:
            parent = stack.pop()
            for path in parent.iterdir():
                relative = path.relative_to(destination).as_posix()
                guest_path(destination, relative)
                info = path.lstat();self.members += 1
                if self.members > limits.members or len(guest_parts(relative)) > limits.depth:
                    raise ExtractionQuotaError("existing extraction tree exceeds member/depth budget")
                if stat.S_ISDIR(info.st_mode):stack.append(path)
                elif stat.S_ISREG(info.st_mode):self.written += info.st_size
                else:raise ExtractionQuotaError("extraction tree contains non-ordinary entries")
                if self.written > limits.total_bytes:raise ExtractionQuotaError("existing extraction tree exceeds byte budget")
        self.declared = self.written

    def member(self, name: str, size: int) -> str:
        if not isinstance(name, str) or name.startswith("/"):
            raise ExtractionQuotaError("archive member must be relative")
        parts = guest_parts(name)
        if not parts or len(parts) > self.limits.depth or type(size) is not int or size < 0:
            raise ExtractionQuotaError("invalid archive member depth/size")
        self.members += 1;self.declared += size
        if self.members > self.limits.members or size > self.limits.file_bytes or self.declared > self.limits.total_bytes:
            raise ExtractionQuotaError("archive member/expanded-byte budget exceeded")
        return "/".join(parts)

    def copy(self, source, destination, *, maximum: int | None = None):
        count = 0
        while True:
            data = source.read(64*1024)
            if not data:break
            count += len(data)
            if count > (self.limits.file_bytes if maximum is None else maximum) or self.written + len(data) > self.limits.total_bytes:
                raise ExtractionQuotaError("actual decoded/write byte budget exceeded")
            destination.write(data);self.written += len(data)


def _target(destination: Path, relative: str, *, directory: bool = False) -> Path:
    path = guest_path(destination, relative)
    (path if directory else path.parent).mkdir(parents=True, exist_ok=True)
    guest_path(destination, relative)
    return path


class _MetadataBoundedFile:
    """Prevent tar metadata from requesting an arbitrarily large allocation."""
    def __init__(self, source, maximum: int):self.source,self.maximum = source,maximum
    def read(self, size=-1):
        if size < 0 or size > self.maximum:raise ExtractionQuotaError("tar metadata read budget exceeded")
        return self.source.read(size)
    def __getattr__(self, name):return getattr(self.source, name)


def extract_firmware(
    path: str | Path,
    output_dir: str | Path,
    runner: CommandRunner | None = None,
    timeout: int = 600,
) -> dict:
    firmware_path = Path(path).absolute()
    extract_dir = Path(output_dir).resolve()
    extract_dir.mkdir(parents=True, exist_ok=True)

    errors: list[dict] = []
    extractor = None
    if not is_regular_file(firmware_path):
        return {"success": False, "extractor": "none", "rootfs_candidates": [], "files_extracted": 0,
                "errors": [{"module": "extractor", "error_type": "NonRegularFileError",
                            "error": f"input is not an ordinary file: {firmware_path}", "recoverable": False}]}

    fallback = _stdlib_extract(firmware_path, extract_dir)
    if fallback["success"]:
        extractor = fallback["extractor"]
    else:
        errors.extend(fallback["errors"])
        for name, command in _external_extractors(firmware_path, extract_dir):
            if not runner:
                continue
            before = _count_files(extract_dir)
            result = runner.run(command, timeout=timeout, cwd=extract_dir)
            after = _count_files(extract_dir)
            if after > before:
                if result.exit_code == 0:
                    extractor = name
                elif extractor is None:
                    extractor = f"{name}:partial"
                post_processed = _post_process_embedded_files(extract_dir, runner, timeout, errors)
                if post_processed:
                    extractor = f"{extractor}+postprocess" if extractor else "postprocess"
                if find_rootfs_candidates(extract_dir):
                    break
            if result.exit_code != 0 or after <= before:
                errors.append(
                    {
                        "module": "extractor",
                        "tool": name,
                        "error": (result.stderr or result.stdout or "extractor failed")[:2000],
                        "recoverable": True,
                    }
                )

    if runner and fallback["success"]:
        post_processed = _post_process_embedded_files(extract_dir, runner, timeout, errors)
        if post_processed:
            extractor = f"{extractor}+postprocess" if extractor else "postprocess"

    files_extracted = _count_files(extract_dir)
    # Partial output after a quota/format failure is diagnostic data, not a
    # successfully extracted firmware tree.
    success = bool(extractor) and bool(fallback["success"])
    rootfs_candidates = find_rootfs_candidates(extract_dir) if success else []
    return {
        "success": success,
        "extractor": extractor or "none",
        "rootfs_candidates": [str(path) for path in rootfs_candidates],
        "files_extracted": files_extracted,
        "errors": errors,
    }


def _external_extractors(firmware_path: Path, extract_dir: Path) -> list[tuple[str, list[str]]]:
    # Host/bind-mount writes have no enforceable filesystem quota. Do not run
    # untrusted extraction until a quota-backed worker is available.
    return []


def _post_process_embedded_files(
    extract_dir: Path,
    runner: CommandRunner,
    timeout: int,
    errors: list[dict],
) -> int:
    squashfs_extractors = _squashfs_extractors()
    if not squashfs_extractors:
        return 0

    extracted = 0
    for path in list(iter_files(extract_dir)):
        if not _is_squashfs_image(path):
            continue
        for name, command_builder in squashfs_extractors:
            target = path.with_name(f"{path.name}_{name}")
            before = _count_files(target)
            if before > 0:
                break
            result = runner.run(command_builder(target, path), timeout=timeout, cwd=extract_dir)
            after = _count_files(target)
            if result.exit_code == 0 and after > before:
                extracted += after - before
                break
            if after > before:
                extracted += after - before
                break
            errors.append(
                {
                    "module": "extractor",
                    "tool": name,
                    "error": (result.stderr or result.stdout or f"{name} failed")[:2000],
                    "recoverable": True,
                }
            )
    return extracted


def _squashfs_extractors() -> list[tuple[str, Callable[[Path, Path], list[str]]]]:
    return []


def _is_squashfs_image(path: Path) -> bool:
    prefix = read_prefix(path, 4)
    return prefix in {b"hsqs", b"sqsh", b"qshs", b"shsq"}


def _stdlib_extract(firmware_path: Path, extract_dir: Path) -> dict:
    errors = []
    try:
        # Keep the validated descriptor for format probing AND extraction.
        with open_regular_file(firmware_path) as source:
            limits = ExtractionLimits()
            if os.fstat(source.fileno()).st_size > limits.input_bytes:raise ExtractionQuotaError("archive input byte budget exceeded")
            if zipfile.is_zipfile(source):
                source.seek(0)
                end = zipfile._EndRecData(source)
                if end is None or end[zipfile._ECD_ENTRIES_TOTAL] > limits.members or end[zipfile._ECD_SIZE] > limits.metadata_bytes:
                    raise ExtractionQuotaError("ZIP central directory member/metadata budget exceeded")
                source.seek(0)
                with zipfile.ZipFile(source) as archive:
                    _safe_extract_zip(archive, extract_dir, limits=limits)
                return {"success": True, "extractor": "zipfile", "errors": []}
            source.seek(0)
            # Decode compressed data into an owned bounded spool before tar's
            # metadata parser can allocate/read from an unlimited decoder.
            if source.read(2) == b"\x1f\x8b":
                source.seek(0)
                with tempfile.TemporaryFile(dir=extract_dir.parent) as spool, gzip.GzipFile(fileobj=source, mode="rb") as decoded:
                    written = 0
                    while True:
                        chunk = decoded.read(64*1024)
                        if not chunk:break
                        written += len(chunk)
                        if written > limits.total_bytes:raise ExtractionQuotaError("gzip decoded byte budget exceeded")
                        spool.write(chunk)
                    spool.seek(0)
                    if tarfile.is_tarfile(_MetadataBoundedFile(spool, limits.metadata_bytes)):
                        spool.seek(0)
                        with tarfile.open(fileobj=_MetadataBoundedFile(spool, limits.metadata_bytes), mode="r:") as archive:
                            _safe_extract_tar(archive, extract_dir, limits=limits)
                        return {"success": True, "extractor": "tarfile", "errors": []}
                    spool.seek(0)
                    budget = _ExtractionBudget(extract_dir, limits)
                    relative = budget.member(firmware_path.with_suffix("").name, written)
                    with _target(extract_dir, relative).open("xb") as destination:budget.copy(spool, destination)
                    return {"success": True, "extractor": "gzip", "errors": []}
            source.seek(0)
            try:
                archive = tarfile.open(fileobj=_MetadataBoundedFile(source, limits.metadata_bytes), mode="r:")
            except tarfile.ReadError:
                archive = None
            if archive is not None:
                with archive:
                    _safe_extract_tar(archive, extract_dir, limits=limits)
                return {"success": True, "extractor": "tarfile", "errors": []}
    except (OSError, ValueError, RuntimeError, tarfile.TarError, zipfile.BadZipFile) as exc:
        errors.append(
            {
                "module": "extractor",
                "tool": "stdlib",
                "error": str(exc),
                "recoverable": False,
            }
        )
    if not errors:
        errors.append(
            {
                "module": "extractor",
                "tool": "stdlib",
                "error": "no supported bounded stdlib archive format detected; external extraction requires a quota-backed worker and is disabled",
                "recoverable": True,
            }
        )
    return {"success": False, "extractor": None, "errors": errors}


def _safe_extract_tar(archive: tarfile.TarFile, destination: Path, *, limits: ExtractionLimits | None = None) -> None:
    if not callable(getattr(tarfile, "data_filter", None)):
        raise tarfile.TarError("safe tar extraction unavailable: this Python lacks the data filter")
    limits = limits or ExtractionLimits();budget = _ExtractionBudget(destination, limits);members = []
    for member in archive:
        if not (member.isfile() or member.isdir()) or getattr(member, "sparse", None):
            raise tarfile.TarError("archive links, devices and sparse files are unsupported")
        member = tarfile.data_filter(member, str(destination))
        relative = budget.member(member.name, member.size if member.isfile() else 0)
        members.append((member, relative))
    for member, relative in members:
        if member.isdir():_target(destination, relative, directory=True);continue
        with archive.extractfile(member) as source, _target(destination, relative).open("xb") as output:
            budget.copy(source, output, maximum=min(member.size, limits.file_bytes))
            if hasattr(os, "fchmod"):os.fchmod(output.fileno(), member.mode & 0o777)


def _safe_extract_zip(archive: zipfile.ZipFile, destination: Path, *, limits: ExtractionLimits | None = None) -> None:
    limits = limits or ExtractionLimits();budget = _ExtractionBudget(destination, limits);members = []
    for member in archive.infolist():
        mode = member.external_attr >> 16
        if member.flag_bits & 1 or (stat.S_IFMT(mode) and not (stat.S_ISREG(mode) or stat.S_ISDIR(mode))):
            raise zipfile.BadZipFile("encrypted/link/special ZIP member unsupported")
        relative = budget.member(member.filename, 0 if member.is_dir() else member.file_size)
        members.append((member, relative))
    for member, relative in members:
        if member.is_dir():_target(destination, relative, directory=True);continue
        with archive.open(member) as source, _target(destination, relative).open("xb") as output:
            budget.copy(source, output, maximum=min(member.file_size, limits.file_bytes))


def find_rootfs_candidates(extract_dir: Path) -> list[Path]:
    return run_bounded_scan("rootfs_candidates", _find_rootfs_candidates, extract_dir)


def _find_rootfs_candidates(extract_dir: Path) -> list[Path]:
    if not is_scan_directory(extract_dir):
        return []
    candidates: list[tuple[int, Path]] = []
    directories = [extract_dir]
    for current, dirnames, _ in os.walk(extract_dir, followlinks=False, onerror=_raise_walk_error):
        current_path = Path(current)
        kept = []
        for name in dirnames:
            path = current_path / name
            if is_scan_directory(path):
                kept.append(name)
        dirnames[:] = kept
        if current_path != extract_dir:
            directories.append(current_path)

    for directory in directories:
        score = 0
        if safe_exists(directory / "etc" / "passwd"):
            score += 5
        if safe_is_dir(directory / "bin") or safe_is_dir(directory / "sbin"):
            score += 3
        if safe_is_dir(directory / "usr" / "bin") or safe_is_dir(directory / "usr" / "sbin"):
            score += 2
        if safe_is_dir(directory / "www") or safe_is_dir(directory / "htdocs"):
            score += 2
        if safe_is_dir(directory / "etc" / "init.d"):
            score += 2
        if score:
            candidates.append((score, directory))
    if not candidates and _count_files(extract_dir) > 0:
        return [extract_dir]
    candidates.sort(key=lambda item: (-item[0], len(item[1].parts)))
    deduped: list[Path] = []
    for _, candidate in candidates:
        if candidate not in deduped:
            deduped.append(candidate)
    return deduped[:5]


def _count_files(root: Path) -> int:
    if not safe_exists(root, allow_symlink=True):
        return 0
    return sum(1 for _ in iter_files(root))
