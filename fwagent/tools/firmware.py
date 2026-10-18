from __future__ import annotations

from pathlib import Path

from fwagent.runtime.command import CommandRunner
from fwagent.tools.common import open_regular_file, sha256_file


FORMAT_SIGNATURES: list[tuple[str, bytes]] = [
    ("squashfs", b"hsqs"),
    ("squashfs", b"sqsh"),
    ("uimage", b"\x27\x05\x19\x56"),
    ("zip", b"PK\x03\x04"),
    ("gzip", b"\x1f\x8b"),
    ("xz", b"\xfd7zXZ\x00"),
    ("tar", b"ustar"),
    ("cramfs", b"E=\xcd\x28"),
    ("jffs2", b"\x85\x19"),
    ("ubifs", b"\x31\x18\x10\x06"),
]


def identify_firmware(path: str | Path, runner: CommandRunner | None = None) -> dict:
    firmware_path = Path(path)
    prefix = _read_prefix(firmware_path, 4 * 1024 * 1024)
    sha256 = sha256_file(firmware_path)
    file_output = ""
    if runner:
        result = runner.run(["file", "-b", str(firmware_path)], timeout=10)
        if result.exit_code == 0:
            file_output = result.stdout.strip()

    detected_formats = detect_formats(prefix, file_output)
    magic = prefix[:16].hex()
    return {
        "path": str(firmware_path),
        "filename": firmware_path.name,
        "size": firmware_path.stat().st_size,
        "sha256": sha256,
        "file_type": file_output or "unknown",
        "detected_formats": detected_formats,
        "magic": magic,
    }


def detect_formats(data: bytes, file_output: str = "") -> list[str]:
    formats: set[str] = set()
    lower_output = file_output.lower()
    for name, signature in FORMAT_SIGNATURES:
        if signature in data[: 4 * 1024 * 1024]:
            formats.add(name)
    for name in (
        "squashfs",
        "uimage",
        "gzip",
        "xz",
        "zip",
        "tar",
        "cramfs",
        "jffs2",
        "ubifs",
    ):
        if name in lower_output:
            formats.add(name)
    if "7-zip" in lower_output or "7z" in lower_output:
        formats.add("7zip")
    return sorted(formats)


def _read_prefix(path: Path, size: int) -> bytes:
    with open_regular_file(path) as handle:
        return handle.read(size)
