from __future__ import annotations

import os
from pathlib import Path

from fwagent.tools.common import _raise_walk_error, display_path, is_elf, is_regular_file, is_scan_directory, is_windows_reparse_point, read_prefix


SCRIPT_EXTENSIONS = {".sh", ".py", ".lua", ".php", ".pl", ".cgi", ".asp"}
WEB_EXTENSIONS = {".html", ".htm", ".js", ".css", ".php", ".cgi", ".asp", ".lua", ".json"}
CONFIG_EXTENSIONS = {".conf", ".cfg", ".ini", ".json", ".xml", ".yaml", ".yml", ".properties"}
CERT_EXTENSIONS = {".pem", ".crt", ".cer", ".der", ".key"}
LIB_PATTERNS = (".so", ".so.")


def inventory_filesystem(rootfs: str | Path) -> dict:
    root = Path(rootfs).absolute()
    root.stat(follow_symlinks=False)
    if not is_scan_directory(root):
        raise NotADirectoryError(f"rootfs must be an ordinary directory: {root}")
    root = root.resolve()  # normalize Windows short names after rejecting linked roots
    counts = {
        "total_files": 0,
        "directories": 0,
        "symlinks": 0,
        "special_files_skipped": 0,
        "elf_files": 0,
        "scripts": 0,
        "config_files": 0,
        "web_files": 0,
        "certificates": 0,
        "private_keys": 0,
        "libraries": 0,
    }
    categories: dict[str, list[str]] = {
        "elf": [],
        "shell_scripts": [],
        "python": [],
        "lua": [],
        "php": [],
        "cgi": [],
        "html_js": [],
        "config": [],
        "certificates": [],
        "private_keys": [],
        "libraries": [],
    }

    for current, dirnames, filenames in os.walk(root, followlinks=False, onerror=_raise_walk_error):
        current_path = Path(current)
        kept_dirs = []
        for dirname in dirnames:
            path = current_path / dirname
            if is_scan_directory(path):
                kept_dirs.append(dirname)
            else:
                counts["symlinks"] += 1
        dirnames[:] = kept_dirs
        counts["directories"] += len(kept_dirs)
        for filename in filenames:
            path = current_path / filename
            if not is_regular_file(path):
                if path.is_symlink() or is_windows_reparse_point(path):
                    counts["symlinks"] += 1
                else:
                    counts["special_files_skipped"] += 1
                continue
            _inventory_regular_file(path, root, counts, categories)

    return {**counts, "categories": categories}


def _inventory_regular_file(path: Path, root: Path, counts: dict[str, int], categories: dict[str, list[str]]) -> None:
    rel = display_path(path, root)
    suffix = path.suffix.lower()
    counts["total_files"] += 1

    if is_elf(path):
        counts["elf_files"] += 1
        categories["elf"].append(rel)
        if any(part in path.name for part in LIB_PATTERNS):
            counts["libraries"] += 1
            categories["libraries"].append(rel)
        return

    prefix = read_prefix(path, 128)
    shebang = prefix.startswith(b"#!")
    if suffix in SCRIPT_EXTENSIONS or shebang:
        counts["scripts"] += 1
        _append_script_category(categories, rel, suffix, prefix)

    if suffix in CONFIG_EXTENSIONS or _looks_like_config_path(path, root):
        counts["config_files"] += 1
        categories["config"].append(rel)

    if suffix in WEB_EXTENSIONS or _looks_like_web_path(path, root):
        counts["web_files"] += 1
        _append_web_category(categories, rel, suffix)

    if suffix in CERT_EXTENSIONS:
        counts["certificates"] += 1
        categories["certificates"].append(rel)
        if suffix == ".key":
            counts["private_keys"] += 1
            categories["private_keys"].append(rel)


def _append_script_category(categories: dict[str, list[str]], rel: str, suffix: str, prefix: bytes) -> None:
    first_line = prefix.decode("utf-8", errors="ignore").splitlines()[0:1]
    shebang = first_line[0].lower() if first_line else ""
    if suffix == ".py" or "python" in shebang:
        categories["python"].append(rel)
    elif suffix == ".lua" or "lua" in shebang:
        categories["lua"].append(rel)
    elif suffix == ".php" or "php" in shebang:
        categories["php"].append(rel)
    elif suffix == ".cgi":
        categories["cgi"].append(rel)
    else:
        categories["shell_scripts"].append(rel)


def _append_web_category(categories: dict[str, list[str]], rel: str, suffix: str) -> None:
    if suffix == ".cgi":
        categories["cgi"].append(rel)
    elif suffix == ".php":
        categories["php"].append(rel)
    elif suffix == ".lua":
        categories["lua"].append(rel)
    elif suffix in {".html", ".htm", ".js", ".css"}:
        categories["html_js"].append(rel)


def _looks_like_config_path(path: Path, root: Path) -> bool:
    rel_parts = path.absolute().relative_to(root).parts
    return len(rel_parts) >= 2 and rel_parts[0] == "etc"


def _looks_like_web_path(path: Path, root: Path) -> bool:
    rel_parts = path.absolute().relative_to(root).parts
    if not rel_parts:
        return False
    return rel_parts[0] in {"www", "htdocs", "web"} or "cgi-bin" in rel_parts
