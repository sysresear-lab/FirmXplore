from __future__ import annotations

import re
from pathlib import Path

from fwagent.runtime.command import CommandRunner
from fwagent.tools.architecture import parse_elf_header
from fwagent.tools.common import display_path, extract_ascii_strings, is_regular_file


DANGEROUS_FUNCTIONS = (
    "system",
    "popen",
    "execl",
    "execlp",
    "execle",
    "execv",
    "execvp",
    "execve",
    "strcpy",
    "strcat",
    "sprintf",
    "vsprintf",
    "gets",
    "scanf",
    "memcpy",
)

NETWORK_DAEMONS = {
    "telnetd",
    "dropbear",
    "sshd",
    "dnsmasq",
    "upnp",
    "miniupnpd",
    "mqtt",
    "mosquitto",
    "ftpd",
    "tftpd",
    "snmpd",
}
WEB_SERVERS = {"httpd", "lighttpd", "nginx", "boa", "uhttpd"}


def analyze_binaries(
    rootfs: str | Path,
    elf_files: list[str],
    runner: CommandRunner | None = None,
) -> list[dict]:
    root = Path(rootfs).resolve()
    binaries: list[dict] = []
    for entry in elf_files:
        path = root / entry.lstrip("/") if entry.startswith("/") else Path(entry)
        if not is_regular_file(path):
            continue
        header = parse_elf_header(path) or {}
        strings = extract_ascii_strings(path, max_bytes=16 * 1024 * 1024)
        symbol_data = _discover_dangerous_symbols(path, strings, runner)
        libs = _linked_libraries(strings)
        interesting_strings = _interesting_strings(strings)
        binaries.append(
            {
                "path": display_path(path, root),
                "architecture": header.get("architecture"),
                "endianness": header.get("endianness"),
                "bitness": header.get("bitness"),
                "dynamic": bool(libs),
                "stripped": _looks_stripped(path, strings),
                "size": path.stat().st_size,
                "linked_libraries": libs,
                "dangerous_symbols": symbol_data["symbols"],
                "possible_dangerous_references": symbol_data["possible_references"],
                "interesting_strings": interesting_strings,
            }
        )
    return binaries


def rank_binaries(binaries: list[dict], services: list[dict], web: dict) -> list[dict]:
    service_paths = {service.get("binary") for service in services if service.get("binary")}
    startup_paths = {service.get("binary") for service in services if service.get("source")}
    service_names_by_path: dict[str, set[str]] = {}
    for service in services:
        binary_path = service.get("binary")
        if binary_path:
            service_names_by_path.setdefault(binary_path, set()).add(service.get("name", ""))
    web_backend_paths = set(web.get("candidate_backend_binaries", []))
    cgi_names = {Path(path).name for path in web.get("cgi", [])}
    ranked: list[dict] = []

    for binary in binaries:
        path = binary.get("path", "")
        name = Path(path).name.lower()
        reasons: list[str] = []
        score = 0

        if name in WEB_SERVERS or path in web_backend_paths:
            score += 30
            reasons.append("web server")
        if name in cgi_names or "/cgi-bin/" in path:
            score += 25
            reasons.append("cgi handler")
        if name in NETWORK_DAEMONS:
            score += 20
            reasons.append("network-facing daemon")
        if path in startup_paths:
            score += 15
            reasons.append("startup service")
        if service_names_by_path.get(path, set()) & {"telnetd", "dropbear", "sshd"}:
            score += 15
            reasons.append("remote access service")

        dangerous = set(binary.get("dangerous_symbols", []))
        possible = set(binary.get("possible_dangerous_references", []))
        for symbol in ("system", "popen", "strcpy", "sprintf", "memcpy"):
            if symbol in dangerous:
                score += 10
                reasons.append(f"imports {symbol}")
            elif symbol in possible:
                score += 6
                reasons.append(f"possibly references {symbol}")

        interesting = set(binary.get("interesting_strings", []))
        if any(item.startswith("HTTP") or item in {"GET", "POST"} for item in interesting):
            score += 10
            reasons.append("contains HTTP strings")
        if "/bin/sh" in interesting:
            score += 10
            reasons.append("contains /bin/sh")
        if binary.get("stripped"):
            score += 5
            reasons.append("stripped")

        if score:
            ranked.append({"path": path, "score": score, "reasons": reasons})

    return sorted(ranked, key=lambda item: (-item["score"], item["path"]))


def _discover_dangerous_symbols(
    path: Path,
    strings: list[str],
    runner: CommandRunner | None,
) -> dict[str, list[str]]:
    confirmed: set[str] = set()
    if runner:
        for command in (["readelf", "-Ws", str(path)], ["nm", "-D", str(path)]):
            result = runner.run(command, timeout=10)
            if result.exit_code == 0:
                confirmed.update(_symbols_from_tool_output(result.stdout))
    possible = {
        symbol
        for symbol in DANGEROUS_FUNCTIONS
        if symbol not in confirmed and any(_string_mentions_symbol(item, symbol) for item in strings)
    }
    return {"symbols": sorted(confirmed), "possible_references": sorted(possible)}


def _symbols_from_tool_output(output: str) -> set[str]:
    found = set()
    for symbol in DANGEROUS_FUNCTIONS:
        pattern = re.compile(rf"(^|\s){re.escape(symbol)}(@@?.*)?$", re.MULTILINE)
        if pattern.search(output):
            found.add(symbol)
    return found


def _string_mentions_symbol(value: str, symbol: str) -> bool:
    return bool(re.search(rf"(^|[^A-Za-z0-9_]){re.escape(symbol)}([^A-Za-z0-9_]|$)", value))


def _linked_libraries(strings: list[str]) -> list[str]:
    libs = sorted({item for item in strings if re.fullmatch(r"lib[\w.+-]+\.so(\.\d+)*", item)})
    return libs[:100]


def _interesting_strings(strings: list[str]) -> list[str]:
    interesting: list[str] = []
    wanted = ("HTTP", "GET", "POST", "/bin/sh", "cgi-bin", "Content-Type", "Authorization")
    for item in strings:
        if any(token in item for token in wanted):
            interesting.append(item[:200])
    return sorted(set(interesting))[:50]


def _looks_stripped(path: Path, strings: list[str]) -> bool:
    if ".symtab" not in strings:
        return True
    return False
