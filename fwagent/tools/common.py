from __future__ import annotations

import os
import re
import hashlib
import logging
import stat
import time
from contextlib import contextmanager
from pathlib import Path


ELF_MAGIC = b"\x7fELF"
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
scan_logger = logging.getLogger("fwagent.scan.files")


class NonRegularFileError(OSError):
    """Expected skip, distinct from an unreadable ordinary file."""


def _special_windows_path(path: Path) -> bool:
    if os.name != "nt":
        return False
    text = str(path).replace("\\", "/")
    if text.startswith("//./"):
        return True
    if text.startswith("//?/") and not (re.match(r"^[A-Za-z]:/", text[4:]) or text[4:].upper().startswith("UNC/")):
        return True
    reserved = {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}
    return any(part.rstrip(" .").split(".")[0].upper() in reserved for part in path.parts)


def is_regular_file(path: Path) -> bool:
    """No final symlink/reparse traversal; stat failures other than disappearance propagate."""
    path = Path(path)
    if _special_windows_path(path):
        scan_logger.info("path=%s reason=windows_device_namespace", path)
        return False
    try:
        info = path.stat(follow_symlinks=False)
    except FileNotFoundError:
        return False
    if not stat.S_ISREG(info.st_mode) or is_windows_reparse_point(path):
        scan_logger.info("path=%s reason=non_regular mode=%s", path, oct(info.st_mode))
        return False
    return True


def is_scan_directory(path: Path) -> bool:
    """Metadata-only traversal check; permission errors must reach the scan result."""
    try:
        info = path.stat(follow_symlinks=False)
    except FileNotFoundError:
        return False
    return stat.S_ISDIR(info.st_mode) and not is_windows_reparse_point(path)


@contextmanager
def open_regular_file(path: Path):
    """Check before open AND on the descriptor; NONBLOCK prevents a raced FIFO open."""
    path = Path(path)
    scan_logger.info("path=%s", path, extra={"scan_event": "read_start"})
    if not is_regular_file(path):
        raise NonRegularFileError(f"not an ordinary file: {path}")
    before = path.stat(follow_symlinks=False)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    started = time.monotonic()
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or getattr(opened, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino) or not is_regular_file(path):
            scan_logger.info("path=%s reason=replaced_during_open", path)
            raise NonRegularFileError(f"file changed during open: {path}")
        with os.fdopen(fd, "rb") as handle:
            fd = None
            yield handle
    finally:
        if fd is not None:
            os.close(fd)
        scan_logger.info("path=%s duration=%.6f", path, time.monotonic() - started, extra={"scan_event": "read_end"})


def _raise_walk_error(error: OSError) -> None:
    raise error


def display_path(path: Path, root: Path | None = None) -> str:
    candidate = Path(path)
    try:
        if root:
            return "/" + candidate.absolute().relative_to(Path(root).resolve()).as_posix()
    except ValueError:
        pass
    return candidate.as_posix()


def is_within(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def iter_files(root: Path):
    # Do not turn an inaccessible scan root into a successful empty inventory.
    try:
        root.stat(follow_symlinks=False)
    except FileNotFoundError:
        return
    if not is_scan_directory(root):
        return
    for current, dirnames, filenames in os.walk(root, followlinks=False, onerror=_raise_walk_error):
        current_path = Path(current)
        kept_dirs = []
        for name in dirnames:
            path = current_path / name
            if is_scan_directory(path):
                kept_dirs.append(name)
        dirnames[:] = kept_dirs
        for filename in filenames:
            path = current_path / filename
            if is_regular_file(path):
                yield path


def is_windows_reparse_point(path: Path) -> bool:
    try:
        return bool(path.stat(follow_symlinks=False).st_file_attributes & FILE_ATTRIBUTE_REPARSE_POINT)
    except AttributeError:
        return False
    except OSError:
        return True


def safe_exists(path: Path, *, allow_symlink: bool = False) -> bool:
    try:
        if not allow_symlink and (path.is_symlink() or is_windows_reparse_point(path)):
            return False
        return path.exists()
    except OSError:
        return False


def safe_is_dir(path: Path, *, allow_symlink: bool = False) -> bool:
    try:
        if not allow_symlink and (path.is_symlink() or is_windows_reparse_point(path)):
            return False
        return path.is_dir()
    except OSError:
        return False


def read_prefix(path: Path, size: int = 4096) -> bytes:
    try:
        with open_regular_file(path) as handle:
            return handle.read(size)
    except NonRegularFileError:
        return b""


def is_elf(path: Path) -> bool:
    return read_prefix(path, 4) == ELF_MAGIC


def safe_read_text(path: Path, limit: int = 1024 * 1024, *, errors: str = "ignore") -> str:
    try:
        with open_regular_file(path) as handle:
            data = handle.read(limit)
        return data.decode("utf-8", errors=errors)
    except NonRegularFileError:
        return ""


def extract_ascii_strings(path: Path, *, min_length: int = 4, max_bytes: int | None = None) -> list[str]:
    try:
        with open_regular_file(path) as handle:
            data = handle.read(max_bytes or -1)
    except NonRegularFileError:
        return []
    pattern = rb"[ -~]{" + str(min_length).encode("ascii") + rb",}"
    return [match.decode("ascii", errors="ignore") for match in re.findall(pattern, data)]


def normalize_token(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", value.lower()).strip()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open_regular_file(path) as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
