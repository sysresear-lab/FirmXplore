from __future__ import annotations

from collections import Counter
from pathlib import Path

from fwagent.tools.common import display_path, is_regular_file, read_prefix


ELF_MACHINES = {
    3: "x86",
    8: "mips",
    20: "powerpc",
    21: "powerpc64",
    40: "arm",
    50: "ia64",
    62: "x86_64",
    183: "aarch64",
    243: "riscv",
}


def identify_architecture(rootfs: str | Path, elf_files: list[str] | None = None) -> dict:
    root = Path(rootfs).resolve()
    samples: list[dict] = []
    arch_counter: Counter[str] = Counter()
    bitness_counter: Counter[int] = Counter()
    endian_counter: Counter[str] = Counter()

    paths = _resolve_elf_paths(root, elf_files or [])
    for path in paths:
        info = parse_elf_header(path)
        if not info:
            continue
        arch_counter[info["architecture"]] += 1
        bitness_counter[info["bitness"]] += 1
        endian_counter[info["endianness"]] += 1
        if len(samples) < 10:
            samples.append({"path": display_path(path, root), **info})

    total = sum(arch_counter.values())
    primary_arch = arch_counter.most_common(1)[0][0] if arch_counter else None
    bitness = bitness_counter.most_common(1)[0][0] if bitness_counter else None
    endianness = endian_counter.most_common(1)[0][0] if endian_counter else None
    confidence = round(arch_counter[primary_arch] / total, 2) if primary_arch and total else 0.0
    return {
        "primary_architecture": primary_arch,
        "endianness": endianness,
        "bitness": bitness,
        "confidence": confidence,
        "architectures": dict(sorted(arch_counter.items())),
        "samples": samples,
    }


def parse_elf_header(path: Path) -> dict | None:
    header = read_prefix(path, 64)
    if header[:4] == b"\x7fELF" and len(header) < 20:
        raise ValueError(f"truncated ELF header: {path}")
    if len(header) < 20 or header[:4] != b"\x7fELF":
        return None
    elf_class = header[4]
    data_encoding = header[5]
    if elf_class == 1:
        bitness = 32
    elif elf_class == 2:
        bitness = 64
    else:
        bitness = None
    if data_encoding == 1:
        endianness = "little"
        machine = int.from_bytes(header[18:20], "little")
    elif data_encoding == 2:
        endianness = "big"
        machine = int.from_bytes(header[18:20], "big")
    else:
        endianness = None
        machine = 0
    return {
        "architecture": ELF_MACHINES.get(machine, f"machine_{machine}"),
        "endianness": endianness,
        "bitness": bitness,
    }


def _resolve_elf_paths(root: Path, elf_files: list[str]) -> list[Path]:
    paths: list[Path] = []
    for entry in elf_files:
        if entry.startswith("/"):
            path = root / entry.lstrip("/")
        else:
            path = Path(entry)
        if is_regular_file(path):
            paths.append(path.absolute())
    return paths

