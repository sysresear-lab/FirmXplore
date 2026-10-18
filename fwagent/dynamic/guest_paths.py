"""Guest paths are POSIX names inside a root, never host paths.

Runtime writes require POSIX no-follow directory descriptors. Unsupported hosts
fail closed; metadata-only/static path resolution remains available on Windows.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
import stat

_SECURE_WRITES = (os.name != "nt" and bool(getattr(os, "O_NOFOLLOW", 0)) and bool(getattr(os, "O_DIRECTORY", 0))
                  and os.open in os.supports_dir_fd and os.mkdir in os.supports_dir_fd)


class GuestPathError(ValueError):
    pass


class SecurePathUnavailable(GuestPathError):
    pass


def artifact_name(value: str) -> str:
    """Service/backend labels are identifiers, not guest or host paths."""
    if not isinstance(value, str) or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", value) is None:
        raise GuestPathError("service/backend must be a plain identifier")
    guest_parts(value)
    return value


def guest_parts(value: str) -> tuple[str, ...]:
    if (not isinstance(value, str) or not value or "\0" in value or "\\" in value or ":" in value
            or value.startswith("//")):
        raise GuestPathError("expected a POSIX guest path without host/UNC/device semantics")
    parts = tuple(p for p in value.split("/") if p not in {"", "."})
    if any(p == ".." for p in parts):
        raise GuestPathError("parent traversal is not allowed in guest paths")
    if os.name == "nt":
        reserved = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}
        if any(p.endswith((" ", ".")) or p.split(".")[0].upper() in reserved for p in parts):
            raise GuestPathError("unsupported Windows path component")
    return parts


def _reject_link(info) -> None:
    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        raise GuestPathError("linked/reparse guest paths are not allowed")


def guest_path(root: str | Path, value: str) -> Path:
    parts = guest_parts(value)
    base = Path(root).absolute()
    # Check host ancestors as well as the guest components before static reads.
    current = Path(base.anchor)
    for component in (*base.parts[1:], *parts):
        current /= component
        try:
            _reject_link(current.lstat())
        except FileNotFoundError:
            break
    return base.joinpath(*parts)


def require_secure_writes() -> None:
    if not _SECURE_WRITES:
        raise SecurePathUnavailable("secure runtime writes require no-follow directory descriptors; unavailable on this host")


def _host_directory(path: Path, *, create: bool = False) -> int:
    require_secure_writes()
    path = path.absolute()
    fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            if part in {".", ".."}:
                raise GuestPathError("unresolved host directory component")
            try:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(part, mode=0o700, dir_fd=fd)
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def create_private_root(target: Path) -> None:
    """Exclusive creation only. Never remove or adopt an existing target."""
    parent = _host_directory(target.parent, create=True)
    try:
        info = os.fstat(parent)
        if info.st_uid != os.geteuid() or info.st_mode & 0o022:
            raise GuestPathError("runtime parent must be owned by the service and not writable by group/others")
        os.mkdir(target.name, mode=0o700, dir_fd=parent)
    finally:
        os.close(parent)


class GuestRoot:
    def __init__(self, root: str | Path):
        self.root = Path(root).absolute()
        self.fd: int | None = None

    def __enter__(self):
        self.fd = _host_directory(self.root)
        return self

    def __exit__(self, *args):
        os.close(self.fd)
        self.fd = None

    def _directory(self, parts: tuple[str, ...], *, create: bool) -> int:
        fd = os.dup(self.fd)
        try:
            for part in parts:
                try:
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                except FileNotFoundError:
                    if not create:
                        raise
                    os.mkdir(part, mode=0o700, dir_fd=fd)
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd); fd = child
            return fd
        except BaseException:
            os.close(fd)
            raise

    def mkdir(self, value: str) -> Path:
        parts = guest_parts(value)
        fd = self._directory(parts, create=True)
        os.close(fd)
        return self.root.joinpath(*parts)

    def write_new(self, value: str, data: bytes, *, mode: int = 0o600) -> Path:
        parts = guest_parts(value)
        if not parts or not isinstance(data, bytes):
            raise GuestPathError("a file path and bytes are required")
        parent = self._directory(parts[:-1], create=True)
        try:
            fd = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=parent)
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
        finally:
            os.close(parent)
        return self.root.joinpath(*parts)
