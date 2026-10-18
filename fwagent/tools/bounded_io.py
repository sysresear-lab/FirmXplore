"""Read one ordinary file beneath a fixed root using a bounded, pinned handle."""
from contextlib import contextmanager
import os
from pathlib import Path
import stat

from fwagent.dynamic.guest_paths import GuestPathError, GuestRoot, guest_parts, guest_path
from fwagent.tools.common import open_regular_file


def _windows_final_path(handle) -> str:
    import ctypes
    from ctypes import wintypes
    import msvcrt
    function = ctypes.WinDLL('kernel32', use_last_error=True).GetFinalPathNameByHandleW
    function.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
    function.restype = wintypes.DWORD
    buffer = ctypes.create_unicode_buffer(32768)
    count = function(msvcrt.get_osfhandle(handle.fileno()), buffer, len(buffer), 0)
    if not count or count >= len(buffer):
        raise OSError('cannot verify the opened file location')
    value = buffer.value
    if value.startswith('\\\\?\\UNC\\'):value = '\\\\' + value[8:]
    elif value.startswith('\\\\?\\'):value = value[4:]
    return os.path.normcase(os.path.abspath(value))


@contextmanager
def open_beneath(root: str | Path, relative: str):
    parts = guest_parts(relative)
    if not parts:raise GuestPathError('ordinary file path required')
    target = guest_path(root, relative)
    if os.name == 'nt':
        target.lstat()  # Preserve missing-file semantics for SPA route fallback.
        expected = os.path.normcase(os.path.abspath(target))
        if expected.startswith('\\\\?\\'):expected = expected[4:]
        with open_regular_file(target) as handle:
            if _windows_final_path(handle) != expected:
                raise GuestPathError('opened file escaped its declared root')
            yield handle
            if _windows_final_path(handle) != expected:
                raise GuestPathError('opened file location changed during read')
    else:
        with GuestRoot(root) as owned:
            parent = owned._directory(parts[:-1], create=False)
            try:fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | getattr(os, 'O_NONBLOCK', 0), dir_fd=parent)
            finally:os.close(parent)
            with os.fdopen(fd, 'rb') as handle:
                if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):raise GuestPathError('not an ordinary file')
                yield handle


def read_beneath(root: str | Path, relative: str, *, limit: int) -> bytes:
    if type(limit) is not int or limit <= 0:raise ValueError('positive read limit required')
    with open_beneath(root, relative) as handle:
        before = os.fstat(handle.fileno())
        if before.st_size > limit:raise ValueError('file exceeds byte budget')
        data = handle.read(limit + 1)
        after = os.fstat(handle.fileno())
        fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        if len(data) > limit or any(getattr(before,k) != getattr(after,k) for k in fields):
            raise ValueError('file changed or exceeded byte budget during read')
        return data
