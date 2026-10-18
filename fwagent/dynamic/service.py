from __future__ import annotations

import json
import hashlib
import os
import re
import shlex
import shutil
import socket
import ssl
import time
import urllib.request
import urllib.error
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from fwagent.tools.common import open_regular_file, safe_read_text
from fwagent.dynamic.guest_paths import GuestPathError, GuestRoot, create_private_root, guest_parts, guest_path, require_secure_writes


SERVICE_EVIDENCE_TYPES = {
    "service_start_success",
    "service_start_failure",
    "service_process_alive",
    "service_process_exit",
    "service_port_listening",
    "service_reachable",
    "service_http_response",
    "runtime_dependency_missing",
    "nvram_dependency",
    "config_dependency",
}

SERVICE_STATES = {"not_started", "preparing", "starting", "running", "exited", "failed", "stopped"}

RUNTIME_FAILURE_CATEGORIES = {
    "runtime_backend_unavailable",
    "emulator_unavailable",
    "unsupported_architecture",
    "loader_missing",
    "shared_library_missing",
    "config_missing",
    "dependency_missing",
    "device_node_missing",
    "procfs_required",
    "sysfs_required",
    "vendor_nvram_required",
    "ipc_dependency_missing",
    "unix_socket_dependency_missing",
    "permission_blocked",
    "network_bind_failed",
    "service_exited",
    "protocol_unavailable",
    "timeout",
    "runtime_environment_incompatible",
    "runtime_repair_insufficient",
}


@dataclass(frozen=True)
class UserRuntimeMapping:
    architecture: str
    endianness: str
    emulator: str
    system_emulator: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ServiceRuntimeFeasibility:
    service: str
    binary: str
    architecture: str
    entry_point: str | None
    protocol: str | None
    runtime_candidate: str
    required_files: list[str] = field(default_factory=list)
    required_libraries: list[str] = field(default_factory=list)
    required_environment: list[str] = field(default_factory=list)
    required_dependencies: list[str] = field(default_factory=list)
    runtime_feasible: bool = False
    feasibility_score: float = 0.0
    blocking_reasons: list[str] = field(default_factory=list)
    estimated_cost: str = "bounded-medium"
    selected_backend: str = "service-qemu"
    selection_reason: str = "least-cost runtime capable of executing the selected firmware service"
    endianness: str | None = None
    emulator: str | None = None
    loader: str | None = None
    rootfs_source: str | None = None
    rootfs_semantic_fidelity: str | None = None
    failure_category: str | None = None

    def __post_init__(self) -> None:
        self.feasibility_score = round(max(0.0, min(1.0, float(self.feasibility_score))), 3)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RuntimeAttemptStatus:
    status: str
    failure_category: str | None
    short_reason: str
    evidence_refs: list[str]
    runtime_backend: str
    process_started: bool = False
    service_bound: bool = False
    request_sent: bool = False
    response_received: bool = False
    observation_level: int = 1
    failure_fingerprint: str | None = None
    repeated_failure_count: int = 0
    stop_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ServiceLaunchProfile:
    binary: str
    arguments: list[str]
    environment: dict[str, str] = field(default_factory=dict)
    working_directory: str | None = "/"
    config_files: list[str] = field(default_factory=list)
    required_paths: list[str] = field(default_factory=list)
    writable_paths: list[str] = field(default_factory=list)
    expected_ports: list[int] = field(default_factory=list)
    startup_source: str | None = None
    confidence: float = 0.0
    service: str | None = None
    config: dict[str, Any] = field(default_factory=dict)
    missing_information: list[str] = field(default_factory=list)
    nvram_dependencies: list[dict[str, str]] = field(default_factory=list)
    architecture: str | None = None
    endianness: str | None = None
    entry_point: str | None = None
    protocol: str | None = None
    required_dependencies: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RuntimeRepair:
    id: str
    type: str
    target: str
    reason: str
    source_evidence: list[str] = field(default_factory=list)
    reversible: bool = True
    original_environment_gap: str | None = None
    files_modified: list[str] = field(default_factory=list)
    source_rootfs_modified: bool = False
    runtime_copy_modified: bool = True
    transport_changes: list[str] = field(default_factory=list)
    environment_changes: dict[str, str] = field(default_factory=dict)
    original_startup_confirmed: bool = False
    fidelity_limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ServiceRuntimeState:
    service: str
    state: str
    backend: str = "service-qemu"
    pid: int | None = None
    start_time: float | None = None
    exit_code: int | None = None
    signal: int | None = None
    duration: float | None = None
    guest_port: int | None = None
    probe_endpoint: str | None = None
    diagnosis: str | None = None
    errors: list[str] = field(default_factory=list)
    repairs: list[RuntimeRepair] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["repairs"] = [repair.to_dict() for repair in self.repairs]
        return data


@dataclass
class BootProgress:
    kernel_started: bool = False
    rootfs_mounted: bool = False
    init_started: bool = False
    shell_available: bool = False
    nvram_started: bool = False
    network_started: bool = False
    services_started: list[str] = field(default_factory=list)
    last_stage: str = "not_started"
    blockers: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def reconstruct_service_startup(rootfs: str | Path, binary: str) -> ServiceLaunchProfile:
    root = Path(rootfs)
    service = Path(binary).name
    binary_path = _resolve_binary(root, binary)
    startup_source, startup_args = _find_startup_command(root, service, binary_path)
    arguments = startup_args
    confidence = 0.35
    missing_information: list[str] = []
    if startup_source and arguments:
        confidence = 0.85
    elif service == "lighttpd":
        arguments = ["-D", "-f", "/etc/lighttpd/lighttpd.conf"]
        missing_information.append("startup script did not provide a command; used firmware lighttpd config location")
        confidence = 0.55
    else:
        missing_information.append("startup command not found")

    config_files = _config_files_from_args(arguments)
    config = parse_lighttpd_config(root / config_files[0].lstrip("/")) if service == "lighttpd" and config_files else {}
    expected_ports = _expected_ports(config)
    required_paths = [binary_path]
    required_paths.extend(config_files)
    document_root = config.get("server.document-root")
    if isinstance(document_root, str):
        guest_parts(document_root)
        required_paths.append(document_root)
    writable_paths = sorted(
        {
            "/tmp",
            "/var/tmp",
            "/var/run",
            "/var/log",
            *_writable_paths_from_config(config),
        }
    )
    nvram_dependencies = detect_nvram_dependencies(root, [startup_source, *config_files])
    required_dependencies: list[str] = []
    if startup_source == "/etc/inetd.conf":
        required_dependencies.append("inetd socket activation with an accepted connection on standard input")
    return ServiceLaunchProfile(
        service=service,
        binary=binary_path,
        arguments=arguments,
        environment={},
        working_directory="/",
        config_files=config_files,
        required_paths=sorted(dict.fromkeys(required_paths)),
        writable_paths=writable_paths,
        expected_ports=expected_ports,
        startup_source=startup_source,
        confidence=confidence,
        config=config,
        missing_information=missing_information,
        nvram_dependencies=nvram_dependencies,
        entry_point=startup_source,
        protocol="http" if service in {"httpd", "lighttpd", "uhttpd"} else None,
        required_dependencies=required_dependencies,
    )


def parse_lighttpd_config(path: str | Path) -> dict[str, Any]:
    config_path = Path(path)
    if not config_path.exists():
        return {}
    text = safe_read_text(config_path, limit=-1)
    parsed: dict[str, Any] = {}
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        raw = _strip_comment(lines[index]).strip()
        if not raw:
            index += 1
            continue
        if re.match(r"^[A-Za-z0-9_.-]+\s*(\+?=)\s*\(", raw):
            block = raw
            while ")" not in block and index + 1 < len(lines):
                index += 1
                block += "\n" + _strip_comment(lines[index])
            key, values = _parse_array_assignment(block)
            if key:
                current = parsed.get(key, [])
                parsed[key] = [*current, *values] if isinstance(current, list) else values
            index += 1
            continue
        match = re.match(r"^([A-Za-z0-9_.-]+)\s*=\s*(.+?)\s*$", raw)
        if match:
            parsed[match.group(1)] = _parse_lighttpd_value(match.group(2).strip())
        index += 1
    includes = []
    for line in lines:
        raw = _strip_comment(line).strip()
        if raw.startswith("include"):
            includes.append(raw)
    if includes:
        parsed["includes"] = includes
    return parsed


def check_runtime_dependencies(rootfs: str | Path, profile: ServiceLaunchProfile, runner: Any = None) -> dict[str, Any]:
    root = Path(rootfs)
    missing_paths = [path for path in profile.required_paths if not _root_path(root, path).exists()]
    result = {
        "success": not missing_paths,
        "missing_paths": missing_paths,
        "interpreter": None,
        "needed_libraries": [],
        "missing_libraries": [],
    }
    binary = _root_path(root, profile.binary)
    if runner is None or not binary.exists():
        return result
    program_headers = runner.run(["readelf", "-l", str(binary)], timeout=10)
    dynamic = runner.run(["readelf", "-d", str(binary)], timeout=10)
    interpreter = _parse_interpreter(program_headers.stdout or "")
    needed = _parse_needed(dynamic.stdout or "")
    missing_libs = [library for library in needed if not _find_library(root, library)]
    result.update(
        {
            "success": not missing_paths and not missing_libs and (interpreter is None or _root_path(root, interpreter).exists()),
            "interpreter": interpreter,
            "needed_libraries": needed,
            "missing_libraries": missing_libs,
        }
    )
    if interpreter and not _root_path(root, interpreter).exists():
        result["missing_paths"].append(interpreter)
    return result


def resolve_user_runtime_mapping(architecture: str | None, endianness: str | None) -> UserRuntimeMapping | None:
    arch = str(architecture or "").strip().lower().replace("_", "-")
    endian = str(endianness or "").strip().lower()
    if arch in {"arm", "arm32", "armel"}:
        return UserRuntimeMapping("arm", "little", "qemu-arm-static", "qemu-system-arm")
    if arch in {"mipsel", "mips32el", "mips-le"} or (arch in {"mips", "mips32"} and endian in {"little", "le", "little-endian"}):
        return UserRuntimeMapping("mips", "little", "qemu-mipsel-static", "qemu-system-mipsel")
    if arch in {"mipsbe", "mipseb", "mips32be", "mips-be"} or (arch in {"mips", "mips32"} and endian in {"big", "be", "big-endian"}):
        return UserRuntimeMapping("mips", "big", "qemu-mips-static", "qemu-system-mips")
    return None


def resolve_runtime_rootfs(task_dir: str | Path, analysis: dict[str, Any] | None = None) -> dict[str, Any]:
    """Resolve runtime RootFS without silently preferring a lossy host-safe view."""
    task = Path(task_dir)
    artifact_path = task / "artifacts" / "rootfs.json"
    artifact: dict[str, Any] = {}
    if artifact_path.exists():
        try:
            artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            artifact = {}
    analysis = analysis or {}
    canonical = (analysis.get("extraction") or {}).get("canonical_rootfs") or {}
    if artifact:
        canonical = {**canonical, **artifact}

    candidates: list[tuple[str, Any, bool]] = [
        ("canonical_linux_rootfs", canonical.get("canonical_linux_rootfs"), False),
        ("workspace_relative_path", canonical.get("workspace_relative_path"), False),
        ("path", canonical.get("path"), False),
        ("host_path", canonical.get("host_path"), False),
        ("host_safe_view", canonical.get("host_safe_view"), True),
    ]
    extraction_root = (analysis.get("extraction") or {}).get("rootfs")
    if extraction_root:
        candidates.append(("legacy_extraction_rootfs", extraction_root, False))
    for source_field, raw, degraded in candidates:
        if not raw:
            continue
        path = Path(str(raw))
        if not path.is_absolute():
            path = task / path
        try:
            exists = path.is_dir()
        except OSError:
            exists = False
        if not exists:
            continue
        semantic_fidelity = str(canonical.get("semantic_fidelity") or "unknown")
        linux_semantics_value = canonical.get("linux_semantics_preserved")
        linux_semantics = bool(linux_semantics_value) if linux_semantics_value is not None else source_field != "host_safe_view"
        degraded = degraded or source_field == "host_safe_view" or semantic_fidelity == "host-safe-view" or linux_semantics_value is False
        return {
            "success": True,
            "path": str(path),
            "source_field": source_field,
            "canonical": bool(canonical.get("canonical", source_field != "legacy_extraction_rootfs")),
            "linux_semantics_preserved": linux_semantics,
            "semantic_fidelity": semantic_fidelity,
            "degraded_provenance": degraded,
            "blocking_reason": None,
        }
    return {
        "success": False,
        "path": None,
        "source_field": None,
        "canonical": False,
        "linux_semantics_preserved": False,
        "semantic_fidelity": "unavailable",
        "degraded_provenance": False,
        "blocking_reason": "canonical runtime rootfs is unavailable",
    }


def normalize_runtime_failure_category(diagnosis: str | None) -> str:
    mapping = {
        "qemu_user_failure": "runtime_backend_unavailable",
        "missing_config": "config_missing",
        "missing_file": "dependency_missing",
        "missing_library": "shared_library_missing",
        "permission_error": "permission_blocked",
        "invalid_argument": "runtime_environment_incompatible",
        "missing_device": "device_node_missing",
        "missing_nvram": "vendor_nvram_required",
        "port_in_use": "network_bind_failed",
        "bind_failure": "network_bind_failed",
        "fastcgi_backend_failure": "ipc_dependency_missing",
        "unsupported_syscall": "runtime_environment_incompatible",
        "daemon_exit": "service_exited",
        "unknown_runtime_failure": "runtime_environment_incompatible",
    }
    category = mapping.get(str(diagnosis or ""), str(diagnosis or "runtime_environment_incompatible"))
    return category if category in RUNTIME_FAILURE_CATEGORIES else "runtime_environment_incompatible"


def classify_runtime_trace(stderr: str, exit_code: int | None) -> tuple[str | None, str | None]:
    """Classify the deepest dependency reached by a bounded qemu-user syscall trace."""
    trace = str(stderr or "")
    lowered = trace.lower()
    unix_socket_created = "socket(pf_unix" in lowered or "socket(af_unix" in lowered
    missing_connect = bool(
        re.search(r"connect\([^\n]*\)\s*=\s*-1\s+errno=2\b", trace, flags=re.IGNORECASE)
    )
    if unix_socket_created and missing_connect:
        return (
            "unix_socket_dependency_missing",
            "ELF loader and shared libraries resolved, then the service created a Unix-domain socket and its connect call failed with ENOENT; the required vendor IPC endpoint was absent.",
        )
    if "can't load library" in lowered or "error while loading shared libraries" in lowered:
        return "shared_library_missing", "qemu-user reached the firmware loader but a required shared library could not be loaded."
    if "could not open" in lowered and exit_code in {126, 127}:
        return "loader_missing", "qemu-user could not open the firmware executable or its requested loader."
    return None, None


def runtime_failure_fingerprint(
    failure_category: str | None,
    short_reason: str,
    *,
    backend: str,
    binary: str,
) -> str:
    normalized = " ".join(str(short_reason or "").lower().split())[:500]
    material = f"{failure_category or 'none'}|{backend}|{binary}|{normalized}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def repeated_failure_stop_reason(attempts: list[dict[str, Any]], *, max_repeats: int = 2) -> str | None:
    fingerprints = [str(item.get("failure_fingerprint") or "") for item in attempts if item.get("failure_fingerprint")]
    if len(fingerprints) < max(2, max_repeats):
        return None
    tail = fingerprints[-max_repeats:]
    return "same_failure_fingerprint_repeated" if len(set(tail)) == 1 else None


def assess_service_runtime_feasibility(
    rootfs: str | Path,
    profile: ServiceLaunchProfile,
    *,
    architecture: str | None,
    endianness: str | None,
    runner: Any = None,
    rootfs_provenance: dict[str, Any] | None = None,
    entry_point: str | None = None,
    protocol: str | None = None,
) -> ServiceRuntimeFeasibility:
    mapping = resolve_user_runtime_mapping(architecture, endianness)
    dependencies = check_runtime_dependencies(rootfs, profile, runner)
    blocking: list[str] = []
    failure_category = None
    if mapping is None:
        blocking.append(f"unsupported architecture/endian mapping: {architecture}/{endianness}")
        failure_category = "unsupported_architecture"
    elif shutil.which(mapping.emulator) is None:
        blocking.append(f"required emulator is unavailable: {mapping.emulator}")
        failure_category = "emulator_unavailable"
    if dependencies.get("interpreter") and dependencies.get("interpreter") in dependencies.get("missing_paths", []):
        blocking.append(f"ELF loader is missing: {dependencies['interpreter']}")
        failure_category = failure_category or "loader_missing"
    if dependencies.get("missing_libraries"):
        blocking.append("shared libraries are missing: " + ", ".join(dependencies["missing_libraries"]))
        failure_category = failure_category or "shared_library_missing"
    missing_non_loader = [item for item in dependencies.get("missing_paths", []) if item != dependencies.get("interpreter")]
    if missing_non_loader:
        blocking.append("required files are missing: " + ", ".join(missing_non_loader))
        failure_category = failure_category or ("config_missing" if any("conf" in item.lower() for item in missing_non_loader) else "dependency_missing")
    provenance = rootfs_provenance or {}
    if provenance.get("degraded_provenance"):
        blocking.append("only a degraded host-safe RootFS view is available for runtime")
        failure_category = failure_category or "runtime_environment_incompatible"
    feasible = not blocking
    base_score = 0.88 if feasible else max(0.05, 0.62 - (0.14 * len(blocking)))
    return ServiceRuntimeFeasibility(
        service=profile.service or Path(profile.binary).name,
        binary=profile.binary,
        architecture=mapping.architecture if mapping else str(architecture or "unknown"),
        endianness=mapping.endianness if mapping else str(endianness or "unknown"),
        entry_point=entry_point,
        protocol=protocol,
        runtime_candidate="service-level user-mode emulation",
        required_files=list(profile.required_paths),
        required_libraries=list(dependencies.get("needed_libraries") or []),
        required_environment=sorted(profile.environment),
        required_dependencies=sorted({*profile.required_dependencies, *[item for item in profile.missing_information if item]}),
        runtime_feasible=feasible,
        feasibility_score=base_score,
        blocking_reasons=blocking,
        selected_backend="service-qemu",
        selection_reason="service-level emulation is lower cost than whole-system boot and preserves the firmware binary, loader, and libraries",
        emulator=mapping.emulator if mapping else None,
        loader=dependencies.get("interpreter"),
        rootfs_source=provenance.get("source_field"),
        rootfs_semantic_fidelity=provenance.get("semantic_fidelity"),
        failure_category=failure_category,
    )


def _copy_runtime_regular(source, target):
    with open_regular_file(Path(source)) as handle, Path(target).open("xb") as output:
        mode = os.fstat(handle.fileno()).st_mode & 0o777
        shutil.copyfileobj(handle, output)
    Path(target).chmod(mode)
    return str(target)


def prepare_service_rootfs(
    source_rootfs: str | Path,
    service_rootfs: str | Path,
    profile: ServiceLaunchProfile,
) -> dict[str, Any]:
    # Validate every config-derived path before any mutation, even on hosts
    # without secure write primitives. Fresh copies never adopt marker files.
    for value in [profile.binary, *profile.config_files, *profile.required_paths, *profile.writable_paths]:
        guest_parts(value)
    source = guest_path(source_rootfs, "/")
    target = Path(service_rootfs).absolute()
    require_secure_writes()
    create_private_root(target)
    for child in source.iterdir():
        if child.name in {"dev", "proc", "sys", ".firmxplore-runtime-copy.json"}:
            continue
        # Preserve links as links; never use their targets as writable paths.
        if child.is_symlink():
            (target / child.name).symlink_to(child.readlink())
        elif child.is_dir():
            shutil.copytree(child, target / child.name, symlinks=True, ignore_dangling_symlinks=True, copy_function=_copy_runtime_regular)
        elif child.is_file():
            _copy_runtime_regular(child, target / child.name)
    repairs: list[RuntimeRepair] = []
    for pseudo_path in ("/dev", "/proc", "/sys"):
        with GuestRoot(target) as owned:
            owned.mkdir(pseudo_path)
        repairs.append(
            RuntimeRepair(
                id=f"RR-{len(repairs) + 1:04d}",
                type="create_pseudo_filesystem_mountpoint",
                target=pseudo_path,
                reason="avoid copying firmware device and pseudo-filesystem entries into the temporary user-mode runtime",
                original_environment_gap=f"{pseudo_path} requires runtime-specific mounts or controlled bindings",
                files_modified=[pseudo_path],
                source_rootfs_modified=False,
                runtime_copy_modified=True,
                original_startup_confirmed=False,
                fidelity_limitations=[f"stock {pseudo_path} contents are not reproduced; dependent services must block or use explicit safe bindings"],
            )
        )
    for index, path in enumerate(profile.writable_paths, start=1):
        candidate = _root_path(target, path)
        if not _path_is_real_directory(candidate):
            _materialize_directory(target, candidate)
            repairs.append(
                RuntimeRepair(
                    id=f"RR-{len(repairs) + 1:04d}",
                    type="create_writable_directory",
                    target=path,
                    reason="required writable runtime path for service startup",
                    source_evidence=profile.config_files or ([profile.startup_source] if profile.startup_source else []),
                    original_environment_gap=f"writable directory absent or not materialized in runtime copy: {path}",
                    files_modified=[path],
                    source_rootfs_modified=False,
                    runtime_copy_modified=True,
                    original_startup_confirmed=False,
                    fidelity_limitations=["directory lifecycle is reconstructed outside vendor init"],
                )
            )
    with GuestRoot(target) as owned:
        owned.write_new("/.firmxplore-runtime-copy.json", (json.dumps({"source_rootfs": str(source), "source_rootfs_modified": False, "complete": True}, indent=2, sort_keys=True) + "\n").encode())
    return {
        "success": True,
        "service_rootfs": str(target),
        "reused": False,
        "repairs": [repair.to_dict() for repair in repairs],
    }


def _path_exists(path: Path) -> bool:
    try:
        return path.exists()
    except OSError:
        return False


def _path_is_real_directory(path: Path) -> bool:
    try:
        return path.is_dir() and not path.is_symlink()
    except OSError:
        return False


def _materialize_directory(root: Path, target: Path) -> None:
    try:
        relative = target.relative_to(root).as_posix()
    except ValueError:
        raise GuestPathError("runtime directory is outside the owned root") from None
    with GuestRoot(root) as owned:
        owned.mkdir(relative)


def _remove_inaccessible_path(path: Path) -> None:
    raise GuestPathError("automatic removal of conflicting runtime paths is forbidden")


def classify_service_failure(stdout: str, stderr: str, exit_code: int | None, timed_out: bool = False) -> str:
    text = f"{stdout}\n{stderr}".lower()
    if timed_out:
        return "qemu_user_failure"
    if "no such file" in text or "not found" in text:
        if "conf" in text:
            return "missing_config"
        return "missing_file"
    if "error while loading shared libraries" in text or "can't load library" in text:
        return "missing_library"
    if "permission denied" in text:
        return "permission_error"
    if "invalid option" in text or "unknown option" in text:
        return "invalid_argument"
    if "/dev/" in text and ("no such" in text or "not found" in text):
        return "missing_device"
    if "not enough entropy" in text:
        return "missing_device"
    if "nvram" in text:
        return "missing_nvram"
    if "address already in use" in text:
        return "port_in_use"
    if "bind failed" in text or "can't bind" in text or "cannot bind" in text:
        return "bind_failure"
    if "spawning fcgi failed" in text or "mod_fastcgi" in text:
        return "fastcgi_backend_failure"
    if "segmentation fault" in text or exit_code == 139:
        return "segmentation_fault"
    if "unsupported syscall" in text:
        return "unsupported_syscall"
    if exit_code not in (None, 0):
        return "daemon_exit"
    return "unknown_runtime_failure"


def parse_boot_progress(console: str) -> BootProgress:
    text = console.lower()
    progress = BootProgress()
    progress.kernel_started = "linux version" in text or "booting linux" in text
    progress.rootfs_mounted = "mounted root" in text or "vfs: mounted root" in text or "do_execve: /sbin/init" in text
    progress.init_started = "/sbin/init" in text or "init started" in text or "do_execve: /etc/preinit" in text
    progress.shell_available = "do_execve" in text and ("/bin/sh" in text or "(sh)" in text)
    progress.nvram_started = "nvrammanager" in text or "nvram_get" in text or "libnvram" in text
    progress.network_started = any(marker in text for marker in ("eth0", "br0", "lan", "wan", "ifconfig", "udhcpc"))
    for service in ("lighttpd", "dnsmasq", "miniupnpd", "uhttpd"):
        if service in text:
            progress.services_started.append(service)
    if "kernel panic" in text:
        progress.blockers.append("kernel_boot_failure")
    if "unable to mount root" in text or "no filesystem could mount root" in text:
        progress.blockers.append("rootfs_mount_failure")
    if "nvrammanager" in text and "lighttpd" not in text:
        progress.blockers.append("firmware_initialization_or_nvram")
    if "boot_timeout" in text:
        progress.blockers.append("boot_timeout")
    if progress.services_started:
        progress.last_stage = f"service:{progress.services_started[-1]}"
    elif progress.nvram_started:
        progress.last_stage = "nvram"
    elif progress.shell_available:
        progress.last_stage = "shell"
    elif progress.init_started:
        progress.last_stage = "init"
    elif progress.rootfs_mounted:
        progress.last_stage = "rootfs"
    elif progress.kernel_started:
        progress.last_stage = "kernel"
    return progress


def detect_nvram_dependencies(rootfs: Path, firmware_paths: list[str | None]) -> list[dict[str, str]]:
    dependencies: list[dict[str, str]] = []
    for firmware_path in firmware_paths:
        if not firmware_path:
            continue
        path = _root_path(rootfs, firmware_path)
        if not path.exists() or not path.is_file():
            continue
        text = safe_read_text(path, limit=-1)
        for line in text.splitlines():
            if "nvram" in line.lower():
                dependencies.append(
                    {
                        "source": firmware_path,
                        "access_method": "startup_or_config_reference",
                        "key": "",
                    }
                )
    return dependencies


def wait_for_port(host: str, port: int, timeout_seconds: float) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def probe_http(
    url: str,
    timeout_seconds: int = 5,
    max_body_preview: int = 4096,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: str | bytes | None = None,
) -> dict[str, Any]:
    data = None
    if body is not None and method.upper() not in {"GET", "HEAD"}:
        data = body.encode("utf-8") if isinstance(body, str) else body
    request = urllib.request.Request(url, data=data, headers=headers or {}, method=method.upper())
    start = time.monotonic()
    context = _legacy_tls_context() if url.startswith("https://") else None
    try:
        response_context = urllib.request.urlopen(request, timeout=timeout_seconds, context=context)
    except urllib.error.HTTPError as exc:
        response_context = exc
    with response_context as response:
        body = response.read(max_body_preview)
        return {
            "method": method.upper(),
            "url": url,
            "status": response.status,
            "headers": {key: value for key, value in response.headers.items()},
            "body_preview": body.decode("utf-8", errors="replace"),
            "duration": round(time.monotonic() - start, 3),
        }


def _legacy_tls_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        context.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    if hasattr(ssl, "TLSVersion"):
        context.minimum_version = ssl.TLSVersion.TLSv1
    return context


def save_json(path: str | Path, payload: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _resolve_binary(rootfs: Path, binary: str) -> str:
    guest_parts(binary)
    if binary.startswith("/"):
        return binary
    for prefix in ("/usr/sbin", "/usr/bin", "/sbin", "/bin"):
        candidate = _root_path(rootfs, f"{prefix}/{binary}")
        if candidate.exists():
            return f"{prefix}/{binary}"
    return f"/usr/sbin/{binary}"


def _find_startup_command(rootfs: Path, service: str, binary_path: str) -> tuple[str | None, list[str]]:
    init_dir = rootfs / "etc" / "init.d"
    if init_dir.exists():
        for path in sorted(init_dir.iterdir()):
            if not path.is_file():
                continue
            text = safe_read_text(path, limit=-1)
            if service not in text and binary_path not in text:
                continue
            for line in text.splitlines():
                if binary_path not in line and service not in line:
                    continue
                if "service_start" not in line and binary_path not in line:
                    continue
                try:
                    parts = shlex.split(line.strip(), comments=True, posix=True)
                except ValueError:
                    continue
                if "service_start" in parts:
                    parts = parts[parts.index("service_start") + 1 :]
                if parts and (parts[0] == binary_path or Path(parts[0]).name == service):
                    return f"/etc/init.d/{path.name}", parts[1:]
    inetd = rootfs / "etc" / "inetd.conf"
    if inetd.exists():
        for line in safe_read_text(inetd, limit=-1).splitlines():
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            try:
                parts = shlex.split(line, comments=True, posix=True)
            except ValueError:
                continue
            if len(parts) < 7:
                continue
            server = parts[6]
            if server != binary_path and Path(server).name != service:
                continue
            arguments = parts[7:]
            if arguments and Path(arguments[0]).name == service:
                arguments = arguments[1:]
            return "/etc/inetd.conf", arguments
    return None, []


def _config_files_from_args(arguments: list[str]) -> list[str]:
    files = []
    for index, item in enumerate(arguments):
        if item == "-f" and index + 1 < len(arguments):
            guest_parts(arguments[index + 1])
            files.append(arguments[index + 1])
    return files


def _expected_ports(config: dict[str, Any]) -> list[int]:
    value = config.get("server.port")
    if isinstance(value, int):
        return [value]
    if isinstance(value, str) and value.isdigit():
        return [int(value)]
    return []


def _writable_paths_from_config(config: dict[str, Any]) -> list[str]:
    paths = []
    for key in ("server.pid-file", "server.errorlog"):
        value = config.get(key)
        if value is not None:
            parts = guest_parts(value)
            if not parts:
                raise GuestPathError("log/PID configuration requires a guest file path")
            paths.append("/" + "/".join(parts[:-1]))
    return paths


def _root_path(rootfs: Path, firmware_path: str) -> Path:
    return guest_path(rootfs, firmware_path)


def _strip_comment(line: str) -> str:
    in_quote = False
    output = []
    for char in line:
        if char == '"':
            in_quote = not in_quote
        if char == "#" and not in_quote:
            break
        output.append(char)
    return "".join(output)


def _parse_lighttpd_value(value: str) -> Any:
    value = value.strip()
    if value.startswith('"') and value.endswith('"'):
        return value[1:-1]
    if value.isdigit():
        return int(value)
    return value


def _parse_array_assignment(block: str) -> tuple[str | None, list[str]]:
    match = re.match(r"^([A-Za-z0-9_.-]+)\s*\+?=\s*\((.*)\)\s*$", block.strip(), re.S)
    if not match:
        return None, []
    values = re.findall(r'"([^"]+)"', match.group(2))
    return match.group(1), values


def _parse_interpreter(output: str) -> str | None:
    match = re.search(r"Requesting program interpreter:\s*([^\]]+)", output)
    return match.group(1).strip() if match else None


def _parse_needed(output: str) -> list[str]:
    return re.findall(r"Shared library: \[([^\]]+)\]", output)


def _find_library(rootfs: Path, library: str) -> bool:
    for directory in ("lib", "usr/lib", "usr/local/lib"):
        if (rootfs / directory / library).exists():
            return True
    return False
