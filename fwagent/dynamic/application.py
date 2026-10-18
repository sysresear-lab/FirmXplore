from __future__ import annotations

import json
import fnmatch
import io
import re
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from fwagent.runtime.command import CommandRunner
from fwagent.dynamic.guest_paths import guest_parts, guest_path
from fwagent.tools.bounded_io import read_beneath
from fwagent.tools.common import extract_ascii_strings, iter_files, safe_read_text, sha256_file


APPLICATION_EVIDENCE_TYPES = {
    "backend_start_success",
    "backend_start_failure",
    "backend_socket_ready",
    "backend_dependency_missing",
    "backend_nvram_dependency",
    "backend_ipc_dependency",
    "endpoint_discovered",
    "endpoint_backend_link",
    "endpoint_reachable",
    "application_endpoint_reachable",
    "fastcgi_context_difference",
    "fastcgi_fd_missing",
    "fastcgi_socket_ready",
    "fastcgi_socket_failure",
    "fastcgi_backend_alive",
    "fastcgi_request_sent",
    "fastcgi_response_received",
    "fastcgi_init_failure",
    "fastcgi_exit_code_explained",
    "fastcgi_runtime_context",
    "fastcgi_runtime_difference",
    "fastcgi_child_started",
    "fastcgi_child_exit",
    "fastcgi_request_received",
    "fastcgi_application_response",
    "fastcgi_integration_reachable",
    "fastcgi_validation_blocked",
    "fastcgi_validation_inconclusive",
}


@dataclass
class ApplicationBackendFailure:
    backend: str
    binary: str
    exit_code: int | None
    signal: int | None
    stdout_preview: str
    stderr_preview: str
    runtime_duration: float
    dependencies: list[str] = field(default_factory=list)
    missing_dependencies: list[str] = field(default_factory=list)
    diagnosis: str = "unknown_application_failure"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ApplicationDependency:
    type: str
    path_or_name: str
    source: str
    required: bool
    available: bool
    evidence_ids: list[str] = field(default_factory=list)
    requirement: str = "unknown"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FastCGILaunchProfile:
    binary: str
    arguments: list[str] = field(default_factory=list)
    environment: dict[str, str] = field(default_factory=dict)
    cwd: str = "/"
    socket: str | None = None
    config_files: list[str] = field(default_factory=list)
    dependencies: list[ApplicationDependency] = field(default_factory=list)
    parent_service: str = "lighttpd"
    route: str | None = None
    max_procs: int | None = None
    source: str | None = None
    confidence: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["dependencies"] = [dependency.to_dict() for dependency in self.dependencies]
        return data


@dataclass
class WebEndpoint:
    path: str
    method_candidates: list[str]
    backend: str | None
    source: str
    parameters: list[str] = field(default_factory=list)
    authentication_hint: str | None = None
    confidence: float = 0.5

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AuthSurface:
    login_endpoint: str | None = None
    cookies: list[str] = field(default_factory=list)
    tokens: list[str] = field(default_factory=list)
    auth_related_endpoints: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FastCGIProcessContext:
    argv: list[str]
    environment: dict[str, str]
    cwd: str
    uid: int | None = None
    gid: int | None = None
    stdin_fd: dict[str, Any] = field(default_factory=dict)
    stdout_fd: dict[str, Any] = field(default_factory=dict)
    stderr_fd: dict[str, Any] = field(default_factory=dict)
    open_fds: list[dict[str, Any]] = field(default_factory=list)
    listen_socket_fd: int | None = None
    parent_pid: int | None = None
    process_group: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class BackendStartupStage:
    name: str
    entered: bool
    completed: bool
    evidence_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FastCGIHarnessResult:
    backend_started: bool
    backend_alive: bool
    socket_ready: bool
    request_sent: bool
    response_received: bool
    response_status_hint: int | None
    stdout_preview: str
    stderr_preview: str
    exit_code: int | None
    diagnosis: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FastCGIRuntimeSnapshot:
    mode: str
    backend: str
    executable: str
    argv: list[str]
    cwd: str
    uid: int | None = None
    gid: int | None = None
    supplementary_groups: list[int] = field(default_factory=list)
    environment: dict[str, str] = field(default_factory=dict)
    stdin: dict[str, Any] = field(default_factory=dict)
    stdout: dict[str, Any] = field(default_factory=dict)
    stderr: dict[str, Any] = field(default_factory=dict)
    open_fds: list[dict[str, Any]] = field(default_factory=list)
    fastcgi_listener_fd: int | None = None
    socket_type: str | None = None
    socket_address: str | None = None
    filesystem_root: str | None = None
    writable_directories: list[str] = field(default_factory=list)
    required_files: list[str] = field(default_factory=list)
    config_files: list[str] = field(default_factory=list)
    nvram_dependencies: list[dict[str, Any]] = field(default_factory=list)
    parent_process: dict[str, Any] = field(default_factory=dict)
    process_hierarchy: list[str] = field(default_factory=list)
    resource_limits: dict[str, Any] = field(default_factory=dict)
    signal_state: dict[str, Any] = field(default_factory=dict)
    loader: str | None = None
    shared_libraries: list[str] = field(default_factory=list)
    file_access: list[dict[str, Any]] = field(default_factory=list)
    qemu_user_args: list[str] = field(default_factory=list)
    proot_args: list[str] = field(default_factory=list)
    runtime_repair_ids: list[str] = field(default_factory=list)
    observations: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FastCGIRuntimeDifference:
    field: str
    standalone_value: Any
    lighttpd_value: Any
    severity: str
    possible_relevance: str
    confidence: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FastCGIRuntimeDiff:
    backend: str
    differences: list[FastCGIRuntimeDifference] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "backend": self.backend,
            "differences": [difference.to_dict() for difference in self.differences],
            "summary": self.summary,
        }


def inspect_backend_binary(rootfs: str | Path, binary: str, runner: CommandRunner | None = None) -> dict[str, Any]:
    root = Path(rootfs)
    path = _root_path(root, binary)
    if not path.exists():
        return {"success": False, "errors": [f"backend binary not found: {binary}"]}
    strings = extract_ascii_strings(path, max_bytes=4 * 1024 * 1024)
    file_output = _run_or_empty(runner, ["file", str(path)])
    program_headers = _run_or_empty(runner, ["readelf", "-l", str(path)])
    dynamic = _run_or_empty(runner, ["readelf", "-d", str(path)])
    symbols = _run_or_empty(runner, ["readelf", "-Ws", str(path)])
    imports = _parse_imports(symbols)
    needed = _parse_needed(dynamic)
    interpreter = _parse_interpreter(program_headers)
    missing = [library for library in needed if not _find_library(root, library)]
    interesting = _interesting_strings(strings)
    result = {
        "success": True,
        "binary": binary,
        "path": str(path),
        "sha256": sha256_file(path),
        "file": file_output,
        "architecture": _architecture_from_file(file_output),
        "endianness": _endianness_from_file(file_output),
        "interpreter": interpreter,
        "needed_libraries": needed,
        "missing_libraries": missing,
        "rpath": _parse_dynamic_tag(dynamic, "RPATH"),
        "runpath": _parse_dynamic_tag(dynamic, "RUNPATH"),
        "imports": imports[:200],
        "interesting_strings": interesting[:200],
        "strings_examined": len(strings),
    }
    return result


def resolve_lighttpd_config(rootfs: str | Path, config_file: str = "/etc/lighttpd/lighttpd.conf") -> dict[str, Any]:
    root = Path(rootfs)
    visited: set[str] = set()
    lines: list[dict[str, Any]] = []
    _collect_lighttpd_config(root, config_file, visited, lines)
    text = "\n".join(item["text"] for item in lines)
    return {
        "success": True,
        "config_file": config_file,
        "sources": sorted(visited),
        "lines": lines,
        "effective_text": text,
        "fastcgi": parse_fastcgi_stanzas(text, source=config_file),
    }


def parse_fastcgi_stanzas(config_text: str, *, source: str = "lighttpd.conf") -> list[dict[str, Any]]:
    variables = _lighttpd_variables(config_text)
    stanzas: list[dict[str, Any]] = []
    for match in re.finditer(r'(?P<route>"/[^"]+"\s*=>\s*\("localhost"\s*=>\s*\((?P<body>.*?)\)\s*\))', config_text, re.S):
        route_match = re.search(r'"([^"]+)"', match.group("route"))
        route = route_match.group(1) if route_match else None
        body = match.group("body")
        stanza = {
            "route": route,
            "source": source,
            "socket": _eval_lighttpd_expr(_extract_arrow_value(body, "socket"), variables),
            "bin-path": _eval_lighttpd_expr(_extract_arrow_value(body, "bin-path"), variables),
            "bin-environment": _extract_array_value(body, "bin-environment"),
            "max-procs": _extract_int_value(body, "max-procs"),
            "idle-timeout": _extract_int_value(body, "idle-timeout"),
            "check-local": _extract_arrow_value(body, "check-local"),
            "raw": body.strip(),
        }
        stanzas.append(stanza)
    return stanzas


def reconstruct_fastcgi_launch(
    rootfs: str | Path,
    backend_binary: str = "/www/services/device_manager/device_manager.fcgi",
    runner: CommandRunner | None = None,
) -> FastCGILaunchProfile:
    root = Path(rootfs)
    config = resolve_lighttpd_config(root)
    fastcgi = config.get("fastcgi") or []
    selected = _select_fastcgi_stanza(fastcgi, backend_binary)
    dependencies = discover_application_dependencies(root, backend_binary, runner)
    if selected:
        binary = selected.get("bin-path") or backend_binary
        socket = selected.get("socket")
        route = selected.get("route")
        max_procs = selected.get("max-procs")
        source = selected.get("source")
        confidence = 0.9
    else:
        binary = backend_binary
        socket = None
        route = None
        max_procs = None
        source = None
        confidence = 0.4
    return FastCGILaunchProfile(
        binary=binary,
        arguments=[],
        environment={},
        cwd="/",
        socket=socket,
        config_files=config.get("sources") or ["/etc/lighttpd/lighttpd.conf"],
        dependencies=dependencies,
        parent_service="lighttpd",
        route=route,
        max_procs=max_procs,
        source=source,
        confidence=confidence,
    )


def discover_application_dependencies(
    rootfs: str | Path,
    backend_binary: str,
    runner: CommandRunner | None = None,
) -> list[ApplicationDependency]:
    root = Path(rootfs)
    inspected = inspect_backend_binary(root, backend_binary, runner)
    dependencies: list[ApplicationDependency] = []
    for library in inspected.get("needed_libraries", []):
        dependencies.append(
            ApplicationDependency(
                type="shared_library",
                path_or_name=library,
                source="DT_NEEDED",
                required=True,
                available=_find_library(root, library),
                requirement="required_for_startup",
            )
        )
    for path in _path_strings(inspected.get("interesting_strings", [])):
        dependencies.append(
            ApplicationDependency(
                type=_dependency_type_for_path(path),
                path_or_name=path,
                source="binary_strings",
                required=_path_likely_required(path),
                available=_dependency_available(root, path),
                requirement=_requirement_for_path(path),
            )
        )
    for token in _nvram_tokens(inspected.get("imports", []), inspected.get("interesting_strings", [])):
        dependencies.append(
            ApplicationDependency(
                type="nvram",
                path_or_name=token,
                source="imports_or_strings",
                required=False,
                available=False,
                requirement="unknown",
            )
        )
    return _dedupe_dependencies(dependencies)


def reconstruct_endpoints(rootfs: str | Path, profile: FastCGILaunchProfile) -> dict[str, Any]:
    root = Path(rootfs)
    endpoints: dict[str, WebEndpoint] = {}
    if profile.route:
        endpoints[profile.route] = WebEndpoint(
            path=profile.route,
            method_candidates=["GET", "POST"],
            backend=profile.binary,
            source=profile.source or "lighttpd fastcgi.server",
            parameters=[],
            authentication_hint=None,
            confidence=0.9,
        )
    www = root / "www"
    if www.exists():
        for path in iter_files(www):
            if path.suffix.lower() not in {".html", ".htm", ".js", ".json", ".css"}:
                continue
            text = safe_read_text(path, errors="replace")
            source = "/" + path.relative_to(root).as_posix()
            for endpoint, methods, params in _extract_frontend_endpoints(text):
                backend = profile.binary if profile.route and endpoint.startswith(profile.route.rstrip("/") + "/") or endpoint == profile.route else None
                current = endpoints.get(endpoint)
                if current:
                    current.method_candidates = sorted(set(current.method_candidates + methods))
                    current.parameters = sorted(set(current.parameters + params))
                    if backend:
                        current.backend = backend
                    continue
                endpoints[endpoint] = WebEndpoint(
                    path=endpoint,
                    method_candidates=methods,
                    backend=backend,
                    source=source,
                    parameters=params,
                    authentication_hint=_auth_hint(endpoint, text),
                    confidence=0.7 if backend else 0.5,
                )
    auth = AuthSurface(
        login_endpoint=_first_endpoint_containing(endpoints, "login"),
        cookies=sorted(_extract_tokens_from_frontend(root, r"\b[A-Za-z0-9_]*(?:sid|session|token|auth)[A-Za-z0-9_]*\b")),
        tokens=sorted(_extract_tokens_from_frontend(root, r"\b(?:token|csrf|stok|Authorization)\b")),
        auth_related_endpoints=sorted(path for path in endpoints if any(token in path.lower() for token in ("login", "auth", "session", "token"))),
    )
    links = [
        {
            "endpoint": endpoint.path,
            "backend": endpoint.backend,
            "route": profile.route,
            "source": endpoint.source,
            "confidence": endpoint.confidence,
        }
        for endpoint in endpoints.values()
        if endpoint.backend
    ]
    return {
        "success": True,
        "endpoints": [endpoint.to_dict() for endpoint in sorted(endpoints.values(), key=lambda item: item.path)],
        "links": links,
        "auth_surface": auth.to_dict(),
    }


def parse_qemu_strace(trace_text: str, *, max_events: int = 2000) -> dict[str, Any]:
    events = []
    missing_files = []
    failed_connects = []
    failed_ioctls = []
    for line in trace_text.splitlines():
        match = re.match(r"^\s*(?P<pid>\d+)\s+(?P<syscall>[A-Za-z0-9_]+)\((?P<args>.*)\)\s+=\s+(?P<result>.*)$", line)
        if not match:
            continue
        event = match.groupdict()
        events.append(event)
        result = event["result"]
        args = event["args"]
        if re.search(r"errno=2\b", result):
            missing_files.append({"syscall": event["syscall"], "target": _first_quoted(args), "result": result})
        if event["syscall"] == "connect" and "errno=" in result:
            failed_connects.append({"target": _first_quoted(args), "result": result})
        if event["syscall"] == "ioctl" and "errno=" in result:
            failed_ioctls.append({"target": _first_quoted(args), "result": result})
        if len(events) >= max_events:
            break
    return {
        "success": True,
        "event_count": len(events),
        "missing_files": missing_files[:100],
        "failed_connects": failed_connects[:100],
        "failed_ioctls": failed_ioctls[:100],
        "last_events": events[-25:],
    }


def infer_direct_context(command: list[str], trace_text: str, *, cwd: str = "/", environment: dict[str, str] | None = None) -> FastCGIProcessContext:
    exec_event = _first_execve(trace_text)
    argv = _parse_execve_argv(exec_event.get("args", "")) if exec_event else command
    return FastCGIProcessContext(
        argv=argv or command,
        environment=environment or {},
        cwd=cwd,
        uid=_first_syscall_result_int(trace_text, "getuid32"),
        gid=_first_syscall_result_int(trace_text, "getgid32"),
        stdin_fd={"fd": 0, "type": "inherited_stdio", "role": "stdin"},
        stdout_fd={"fd": 1, "type": "captured_pipe", "role": "stdout"},
        stderr_fd={"fd": 2, "type": "captured_pipe", "role": "stderr"},
        open_fds=_infer_fd_events(trace_text),
        listen_socket_fd=None,
        parent_pid=None,
        process_group=None,
    )


def infer_fastcgi_context(trace_text: str, profile: FastCGILaunchProfile) -> FastCGIProcessContext:
    exec_event = _first_execve(trace_text, profile.binary)
    argv = _parse_execve_argv(exec_event.get("args", "")) if exec_event else [profile.binary]
    cwd = _last_chdir_before_exec(trace_text, profile.binary) or PurePosixPath(profile.binary).parent.as_posix()
    open_fds = _infer_fd_events(trace_text)
    return FastCGIProcessContext(
        argv=argv or [profile.binary],
        environment=profile.environment,
        cwd=cwd,
        uid=_first_syscall_result_int(trace_text, "getuid32"),
        gid=_first_syscall_result_int(trace_text, "getgid32"),
        stdin_fd={"fd": 0, "type": "fastcgi_listen_socket", "role": "FCGI_LISTENSOCK_FILENO"},
        stdout_fd={"fd": 1, "type": "inherited_or_closed", "role": "stdout"},
        stderr_fd={"fd": 2, "type": "lighttpd_error_log", "role": "stderr"},
        open_fds=open_fds,
        listen_socket_fd=0,
        parent_pid=_parent_pid_from_sigchld(trace_text),
        process_group=None,
    )


def compare_runtime_contexts(direct: FastCGIProcessContext, fastcgi: FastCGIProcessContext) -> dict[str, Any]:
    direct_env = direct.environment
    fastcgi_env = fastcgi.environment
    env_changed = {
        key: {"direct": direct_env.get(key), "fastcgi": fastcgi_env.get(key)}
        for key in sorted(set(direct_env) & set(fastcgi_env))
        if direct_env.get(key) != fastcgi_env.get(key)
    }
    return {
        "env_only_in_direct": sorted(set(direct_env) - set(fastcgi_env)),
        "env_only_in_fastcgi": sorted(set(fastcgi_env) - set(direct_env)),
        "env_changed": env_changed,
        "argv_diff": {"direct": direct.argv, "fastcgi": fastcgi.argv, "different": direct.argv != fastcgi.argv},
        "cwd_diff": {"direct": direct.cwd, "fastcgi": fastcgi.cwd, "different": direct.cwd != fastcgi.cwd},
        "fd_diff": {
            "direct_stdin": direct.stdin_fd,
            "fastcgi_stdin": fastcgi.stdin_fd,
            "direct_listen_socket_fd": direct.listen_socket_fd,
            "fastcgi_listen_socket_fd": fastcgi.listen_socket_fd,
            "different": direct.listen_socket_fd != fastcgi.listen_socket_fd or direct.stdin_fd != fastcgi.stdin_fd,
        },
        "uid_gid_diff": {
            "direct": {"uid": direct.uid, "gid": direct.gid},
            "fastcgi": {"uid": fastcgi.uid, "gid": fastcgi.gid},
            "different": direct.uid != fastcgi.uid or direct.gid != fastcgi.gid,
        },
    }


def build_fastcgi_runtime_snapshot(
    *,
    mode: str,
    backend: str,
    executable: str,
    command: list[str],
    context: FastCGIProcessContext,
    profile: FastCGILaunchProfile | None = None,
    filesystem_root: str | None = None,
    harness_result: dict[str, Any] | None = None,
    startup_result: dict[str, Any] | None = None,
    trace: dict[str, Any] | None = None,
    runtime_repairs: list[dict[str, Any]] | None = None,
) -> FastCGIRuntimeSnapshot:
    profile = profile or FastCGILaunchProfile(binary=executable)
    trace = trace or {}
    parsed_trace = trace.get("trace") if isinstance(trace.get("trace"), dict) else trace
    harness_result = harness_result or {}
    startup_result = startup_result or {}
    socket_address = profile.socket
    if mode == "standalone":
        socket_address = harness_result.get("socket_path") or socket_address
    file_access = []
    if isinstance(parsed_trace, dict):
        file_access = list(parsed_trace.get("missing_files") or [])
    return FastCGIRuntimeSnapshot(
        mode=mode,
        backend=backend,
        executable=executable,
        argv=list(command or context.argv),
        cwd=context.cwd,
        uid=context.uid,
        gid=context.gid,
        environment=dict(context.environment or profile.environment),
        stdin=dict(context.stdin_fd),
        stdout=dict(context.stdout_fd),
        stderr=dict(context.stderr_fd),
        open_fds=list(context.open_fds),
        fastcgi_listener_fd=context.listen_socket_fd,
        socket_type="AF_UNIX/SOCK_STREAM" if context.listen_socket_fd is not None or socket_address else None,
        socket_address=socket_address,
        filesystem_root=filesystem_root,
        writable_directories=["/tmp", "/var/tmp", "/var/run", "/var/log"],
        required_files=[profile.binary, *profile.config_files],
        config_files=list(profile.config_files),
        nvram_dependencies=[
            dependency.to_dict() for dependency in profile.dependencies if dependency.type == "nvram"
        ],
        parent_process={"pid": context.parent_pid, "service": profile.parent_service if mode == "lighttpd" else "fwagent_harness"},
        process_hierarchy=_command_hierarchy(command, executable, mode),
        resource_limits=_extract_resource_limits(context.open_fds, parsed_trace),
        signal_state=_extract_signal_state(parsed_trace, startup_result),
        loader=None,
        shared_libraries=[dependency.path_or_name for dependency in profile.dependencies if dependency.type == "shared_library"],
        file_access=file_access,
        qemu_user_args=_extract_qemu_args(command),
        proot_args=_extract_proot_args(command),
        runtime_repair_ids=[str(repair.get("id")) for repair in runtime_repairs or [] if repair.get("id")],
        observations={
            "harness": _snapshot_result_summary(harness_result),
            "startup": _snapshot_result_summary(startup_result),
        },
    )


def compare_fastcgi_runtime_snapshots(
    standalone: FastCGIRuntimeSnapshot,
    lighttpd: FastCGIRuntimeSnapshot,
) -> FastCGIRuntimeDiff:
    differences: list[FastCGIRuntimeDifference] = []

    def add(field: str, left: Any, right: Any, severity: str, relevance: str, confidence: float) -> None:
        if left != right:
            differences.append(FastCGIRuntimeDifference(field, left, right, severity, relevance, confidence))

    add("argv", standalone.argv, lighttpd.argv, "medium", "Wrapper and parent process differences can affect inherited descriptors and process setup.", 0.85)
    add("cwd", standalone.cwd, lighttpd.cwd, "high", "Relative config/state paths can depend on working directory.", 0.9)
    add("environment", _selected_environment(standalone.environment), _selected_environment(lighttpd.environment), "medium", "FastCGI/CGI and firmware variables can alter initialization.", 0.8)
    add("uid_gid", {"uid": standalone.uid, "gid": standalone.gid}, {"uid": lighttpd.uid, "gid": lighttpd.gid}, "low", "Privileges differ only if one side drops user/group.", 0.65)
    add("stdio", {"stdin": standalone.stdin, "stdout": standalone.stdout, "stderr": standalone.stderr}, {"stdin": lighttpd.stdin, "stdout": lighttpd.stdout, "stderr": lighttpd.stderr}, "high", "FastCGI responders rely on listener FD semantics and stdio inheritance.", 0.95)
    add("fastcgi_listener_fd", standalone.fastcgi_listener_fd, lighttpd.fastcgi_listener_fd, "critical", "Incorrect listener FD prevents FastCGI accept from working.", 0.95)
    add("socket", {"type": standalone.socket_type, "address": standalone.socket_address}, {"type": lighttpd.socket_type, "address": lighttpd.socket_address}, "high", "Socket family/address/lifecycle differences explain spawn-vs-request behavior.", 0.9)
    add("filesystem_root", standalone.filesystem_root, lighttpd.filesystem_root, "medium", "Different runtime roots can change file availability.", 0.8)
    add("required_files", sorted(standalone.required_files), sorted(lighttpd.required_files), "medium", "Missing required files can force initialization exits.", 0.75)
    add("config_files", sorted(standalone.config_files), sorted(lighttpd.config_files), "medium", "Different config inputs can alter backend startup.", 0.75)
    add("parent_process", standalone.parent_process, lighttpd.parent_process, "high", "lighttpd supervision may treat early child exit differently than an external harness.", 0.9)
    add("process_hierarchy", standalone.process_hierarchy, lighttpd.process_hierarchy, "medium", "Parent chain affects inherited descriptors and cleanup.", 0.8)
    add("qemu_user_args", standalone.qemu_user_args, lighttpd.qemu_user_args, "low", "Tracing and qemu flags can perturb timing.", 0.6)
    add("proot_args", standalone.proot_args, lighttpd.proot_args, "low", "proot root/bind/workdir arguments define guest runtime view.", 0.65)
    add("runtime_repair_ids", standalone.runtime_repair_ids, lighttpd.runtime_repair_ids, "medium", "Repairs indicate reconstructed runtime parity rather than source firmware behavior.", 0.8)
    summary = {
        "difference_count": len(differences),
        "critical": sum(1 for difference in differences if difference.severity == "critical"),
        "high": sum(1 for difference in differences if difference.severity == "high"),
        "strongest_fields": [difference.field for difference in differences if difference.severity in {"critical", "high"}],
    }
    return FastCGIRuntimeDiff(backend=standalone.backend, differences=differences, summary=summary)


def classify_fastcgi_child_failure(
    *,
    exit_code: int | None,
    signal: int | None,
    stderr: str = "",
    stdout: str = "",
    context: FastCGIRuntimeSnapshot | None = None,
    diff: FastCGIRuntimeDiff | None = None,
) -> dict[str, Any]:
    text = f"{stderr}\n{stdout}".lower()
    confirmed: list[str] = []
    likely: list[str] = []
    unknown: list[str] = []
    if signal is not None:
        confirmed.append(f"terminated_by_signal_{signal}")
        category = "fastcgi_child_signal_exit"
    elif "child exited with status 182" in text or exit_code == 182:
        confirmed.append("linux_process_exit_status_182")
        category = "fastcgi_child_unknown_exit"
    elif "spawning fcgi failed" in text:
        confirmed.append("lighttpd_fastcgi_spawn_failure")
        category = "fastcgi_application_init_failure"
    elif exit_code not in (None, 0):
        confirmed.append(f"nonzero_process_exit_{exit_code}")
        category = "fastcgi_child_unknown_exit"
    else:
        category = "unknown"
    if "can't load library" in text or "error while loading shared libraries" in text:
        category = "fastcgi_loader_failure"
        confirmed.append("loader_reported_missing_library")
    if "no such file" in text and "/etc/" in text:
        category = "fastcgi_config_failure"
        likely.append("config_file_missing")
    if context and context.fastcgi_listener_fd is None:
        category = "fastcgi_fd_inheritance_failure"
        confirmed.append("fastcgi_listener_fd_missing")
    if diff:
        high_fields = set(diff.summary.get("strongest_fields") or [])
        if "stdio" in high_fields or "fastcgi_listener_fd" in high_fields or "socket" in high_fields:
            likely.append("fd_or_socket_lifecycle_difference")
        if "environment" in high_fields:
            likely.append("environment_difference")
        if "cwd" in high_fields:
            likely.append("cwd_difference")
    if category == "fastcgi_child_unknown_exit":
        unknown.append("exact application branch producing exit 182")
    confidence = 0.9 if confirmed else 0.55
    if unknown:
        confidence = min(confidence, 0.75)
    return {
        "category": category,
        "exit_code": exit_code,
        "signal": signal,
        "confirmed": confirmed,
        "likely": sorted(dict.fromkeys(likely)),
        "unknown": unknown,
        "confidence": confidence,
    }


def _selected_environment(environment: dict[str, str]) -> dict[str, str | None]:
    interesting = (
        "PATH",
        "LD_LIBRARY_PATH",
        "HOME",
        "USER",
        "LOGNAME",
        "TMPDIR",
        "FCGI_ROLE",
        "SERVER_PROTOCOL",
        "SERVER_NAME",
        "SERVER_PORT",
        "REMOTE_ADDR",
        "REMOTE_PORT",
        "SCRIPT_NAME",
        "DOCUMENT_ROOT",
        "REQUEST_METHOD",
        "REQUEST_URI",
        "QUERY_STRING",
        "CONTENT_LENGTH",
    )
    return {key: environment.get(key) for key in interesting if key in environment}


def _command_hierarchy(command: list[str], executable: str, mode: str) -> list[str]:
    hierarchy = []
    if any("proot" in PurePosixPath(part).name for part in command):
        hierarchy.append("proot")
    if any("qemu-" in PurePosixPath(part).name for part in command):
        hierarchy.append("qemu-user")
    if mode == "lighttpd":
        hierarchy.append("lighttpd")
    hierarchy.append(PurePosixPath(executable).name)
    return hierarchy


def _extract_qemu_args(command: list[str]) -> list[str]:
    for index, part in enumerate(command):
        if "qemu-" in PurePosixPath(part).name:
            args = []
            for value in command[index + 1 :]:
                if value.startswith("-"):
                    args.append(value)
                    continue
                break
            return args
    return []


def _extract_proot_args(command: list[str]) -> list[str]:
    for index, part in enumerate(command):
        if "proot" in PurePosixPath(part).name:
            args = []
            for value in command[index + 1 :]:
                if "qemu-" in PurePosixPath(value).name:
                    break
                args.append(value)
            return args
    return []


def _extract_resource_limits(open_fds: list[dict[str, Any]], trace: dict[str, Any]) -> dict[str, Any]:
    limits: dict[str, Any] = {}
    for event in trace.get("last_events", []) if isinstance(trace, dict) else []:
        if event.get("syscall") in {"ugetrlimit", "setrlimit"}:
            limits.setdefault("events", []).append(event)
    if open_fds:
        limits["observed_open_fd_count"] = len(open_fds)
    return limits


def _extract_signal_state(trace: dict[str, Any], startup_result: dict[str, Any]) -> dict[str, Any]:
    state: dict[str, Any] = {}
    if isinstance(trace, dict):
        last_events = trace.get("last_events") or []
        signal_events = [event for event in last_events if str(event.get("syscall", "")).startswith("rt_sig")]
        if signal_events:
            state["last_signal_events"] = signal_events[-5:]
    failure = startup_result.get("failure") if isinstance(startup_result, dict) else None
    if isinstance(failure, dict):
        state["exit_code"] = failure.get("exit_code")
        state["signal"] = failure.get("signal")
        state["diagnosis"] = failure.get("diagnosis")
    return state


def _snapshot_result_summary(result: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "success",
        "diagnosis",
        "exit_code",
        "timed_out",
        "backend_alive",
        "socket_ready",
        "request_sent",
        "response_received",
        "response_status_hint",
    )
    return {key: result.get(key) for key in keys if key in result}


def infer_startup_stages(trace_text: str, stderr_text: str = "") -> list[BackendStartupStage]:
    combined = f"{trace_text}\n{stderr_text}"
    return [
        BackendStartupStage("runtime_init", "execve(" in combined, "SIGCHLD" in combined or "exit(" in combined),
        BackendStartupStage("config_init", "open(\"/etc/" in combined, "errno=2" not in combined),
        BackendStartupStage("fastcgi_init", "FCGI" in combined or "fastcgi" in combined.lower(), "spawning fcgi failed" not in combined.lower()),
        BackendStartupStage("socket_init", "socket(" in combined or "listen(" in combined, "si_status=182" not in combined),
        BackendStartupStage("request_loop", "FCGI_Accept" in combined or "epoll_wait" in combined, "response" in combined.lower()),
    ]


def classify_application_failure(stderr: str, exit_code: int | None) -> str:
    lowered = stderr.lower()
    if "child exited with status 182" in lowered and "fastcgi" in lowered:
        return "fastcgi_child_exit_182"
    if "spawning fcgi failed" in lowered:
        return "fastcgi_spawn_failure"
    if "no such file" in lowered or "not found" in lowered:
        return "missing_file"
    if "can't load library" in lowered or "shared libraries" in lowered:
        return "missing_library"
    if exit_code not in (None, 0):
        return "application_exit"
    return "unknown_application_failure"


def save_application_json(path: str | Path, payload: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _run_or_empty(runner: CommandRunner | None, command: list[str]) -> str:
    if runner is None:
        return ""
    result = runner.run(command, timeout=20)
    return (result.stdout or result.stderr or "")[:512 * 1024]


MAX_INCLUDE_DEPTH = 16
MAX_INCLUDE_FILES = 128
MAX_INCLUDE_FILE_BYTES = 256 * 1024
MAX_INCLUDE_TOTAL_BYTES = 2 * 1024 * 1024
MAX_INCLUDE_LINES = 20000
MAX_INCLUDE_ENUMERATED = 4096


def _collect_lighttpd_config(root: Path, config_file: str, visited: set[str], lines: list[dict[str, Any]], *, depth: int = 0, budget: dict | None = None) -> None:
    normalized = "/" + "/".join(guest_parts(config_file))
    if normalized in visited:
        return
    if depth >= MAX_INCLUDE_DEPTH:raise ValueError("include recursion depth budget exceeded")
    budget = budget if budget is not None else {"files": 0, "bytes": 0, "lines": 0}
    if budget["files"] >= MAX_INCLUDE_FILES:raise ValueError("include file count budget exceeded")
    remaining = MAX_INCLUDE_TOTAL_BYTES - budget["bytes"]
    if remaining <= 0:raise ValueError("include cumulative byte budget exceeded")
    try:data = read_beneath(root, normalized, limit=min(MAX_INCLUDE_FILE_BYTES, remaining))
    except FileNotFoundError:
        return
    visited.add(normalized)
    budget["files"] += 1;budget["bytes"] += len(data)
    for lineno, raw_line in enumerate(io.StringIO(data.decode("utf-8", errors="replace")), start=1):
        budget["lines"] += 1
        if budget["lines"] > MAX_INCLUDE_LINES:raise ValueError("include line count budget exceeded")
        line = raw_line.rstrip("\r\n")
        stripped = line.strip()
        include_match = re.match(r'include(?:_shell)?\s+"([^"]+)"', stripped)
        if include_match and not stripped.startswith("#"):
            pattern = include_match.group(1)
            for included in _resolve_include_pattern(root, pattern):
                _collect_lighttpd_config(root, included, visited, lines, depth=depth+1, budget=budget)
        lines.append({"source": normalized, "line": lineno, "text": line})


def _resolve_include_pattern(root: Path, pattern: str) -> list[str]:
    parts = guest_parts(pattern)
    if any(char in pattern for char in "*?[]"):
        if not parts or any(any(c in part for c in "*?[]") for part in parts[:-1]) or "**" in parts[-1]:
            raise ValueError("include wildcard directories/recursive globs are unsupported")
        parent = _root_path(root, "/" + "/".join(parts[:-1]))
        matches = []
        for index, child in enumerate(parent.iterdir()):
            if index >= MAX_INCLUDE_ENUMERATED:raise ValueError("include directory enumeration budget exceeded")
            if fnmatch.fnmatchcase(child.name, parts[-1]):
                relative = "/" + "/".join((*parts[:-1], child.name))
                candidate = _root_path(root, relative)
                if candidate.is_file():matches.append(relative)
                if len(matches) > MAX_INCLUDE_FILES:raise ValueError("include wildcard file budget exceeded")
        return sorted(matches)
    candidate = _root_path(root, pattern)
    return [pattern] if candidate.exists() else []


def _lighttpd_variables(config: str) -> dict[str, str]:
    variables = {"PID": "${PID}"}
    for match in re.finditer(r'(?:var\.)?(?P<name>[A-Za-z0-9_.-]+)\s*=\s*"(?P<value>[^"]*)"', config):
        name = match.group("name")
        value = match.group("value")
        variables[name] = value
        if name.startswith("var."):
            variables[name[4:]] = value
    return variables


def _extract_arrow_value(body: str, key: str) -> str | None:
    match = re.search(rf'"{re.escape(key)}"\s*=>\s*(?P<value>.*?)(?:,\s*\n|,\s*"|\n\s*\))', body, re.S)
    return match.group("value").strip() if match else None


def _extract_array_value(body: str, key: str) -> dict[str, str]:
    value = _extract_arrow_value(body, key)
    if not value:
        return {}
    pairs = re.findall(r'"([^"]+)"\s*=>\s*"([^"]*)"', value)
    return {key: val for key, val in pairs}


def _extract_int_value(body: str, key: str) -> int | None:
    match = re.search(rf'"{re.escape(key)}"\s*=>\s*(\d+)', body)
    return int(match.group(1)) if match else None


def _eval_lighttpd_expr(expression: str | None, variables: dict[str, str]) -> str | None:
    if expression is None:
        return None
    parts = [part.strip() for part in expression.split("+")]
    output = ""
    for part in parts:
        if not part:
            continue
        if part.startswith('"') and part.endswith('"'):
            output += part[1:-1]
        else:
            output += variables.get(part, part)
    return output or None


def _select_fastcgi_stanza(stanzas: list[dict[str, Any]], backend_binary: str) -> dict[str, Any] | None:
    for stanza in stanzas:
        if stanza.get("bin-path") == backend_binary or str(stanza.get("bin-path", "")).endswith(PurePosixPath(backend_binary).name):
            return stanza
    return stanzas[0] if stanzas else None


def _interesting_strings(strings: list[str]) -> list[str]:
    patterns = (
        "/etc/",
        "/tmp/",
        "/var/",
        "/proc/",
        "/dev/",
        ".sock",
        "socket",
        "nvram",
        "ubus",
        "uci",
        "login",
        "token",
        "session",
        "SOAP",
        "SoapAction",
        "URI",
        "REQUEST_METHOD",
        "QUERY_STRING",
    )
    return [value for value in strings if any(pattern.lower() in value.lower() for pattern in patterns)]


def _path_strings(strings: list[str]) -> list[str]:
    paths = set()
    for value in strings:
        for match in re.findall(r"(/[A-Za-z0-9_./+-]+)", value):
            if len(match) > 1:
                paths.add(match.rstrip(".,;:"))
    return sorted(paths)


def _nvram_tokens(imports: list[str], strings: list[str]) -> list[str]:
    tokens = set()
    for value in imports + strings:
        if "nvram" in value.lower():
            tokens.add(value)
    return sorted(tokens)


def _dependency_type_for_path(path: str) -> str:
    if path.startswith("/tmp/") and (".sock" in path or "socket" in path.lower()):
        return "unix_socket"
    if path.startswith("/dev/"):
        return "device"
    if path.startswith("/proc/"):
        return "proc"
    if path.startswith("/etc/"):
        return "config_file"
    if path.startswith("/var/") or path.startswith("/tmp/"):
        return "writable_state"
    return "filesystem"


def _path_likely_required(path: str) -> bool:
    return path.startswith(("/etc/", "/dev/", "/proc/"))


def _requirement_for_path(path: str) -> str:
    if path.startswith(("/etc/", "/dev/")):
        return "required_for_startup"
    if path.startswith(("/tmp/", "/var/")):
        return "required_for_endpoint"
    return "unknown"


def _dependency_available(root: Path, path: str) -> bool:
    if path.startswith("/proc/"):
        return False
    return _root_path(root, path).exists()


def _dedupe_dependencies(dependencies: list[ApplicationDependency]) -> list[ApplicationDependency]:
    seen = set()
    output = []
    for dependency in dependencies:
        key = (dependency.type, dependency.path_or_name)
        if key in seen:
            continue
        seen.add(key)
        output.append(dependency)
    return output


def _extract_frontend_endpoints(text: str) -> list[tuple[str, list[str], list[str]]]:
    endpoints = []
    for match in re.finditer(r'(?:fetch|open)\s*\(\s*["\']([^"\']+)["\']', text):
        endpoints.append((match.group(1), ["GET", "POST"], []))
    for match in re.finditer(r'\b(?:href|src|action)\s*=\s*["\']([^"\']+)["\']', text, re.I):
        path = match.group(1)
        if path.startswith("/") and not path.lower().endswith((".css", ".png", ".jpg", ".gif")):
            endpoints.append((path, ["GET"], _form_params_near(text, match.start())))
    for match in re.finditer(r'["\'](/services/[^"\']+)["\']', text):
        endpoints.append((match.group(1), ["GET", "POST"], []))
    return [(path, methods, params) for path, methods, params in endpoints if path.startswith("/")]


def _form_params_near(text: str, offset: int) -> list[str]:
    window = text[max(0, offset - 2000) : offset + 2000]
    return sorted(set(re.findall(r'\bname\s*=\s*["\']([^"\']+)["\']', window, re.I)))


def _auth_hint(endpoint: str, text: str) -> str | None:
    lowered = f"{endpoint}\n{text[:2000]}".lower()
    if "login" in lowered:
        return "login"
    if "token" in lowered or "session" in lowered or "cookie" in lowered:
        return "session_or_token"
    return None


def _extract_tokens_from_frontend(root: Path, pattern: str) -> set[str]:
    www = root / "www"
    if not www.exists():
        return set()
    tokens = set()
    compiled = re.compile(pattern, re.I)
    for path in iter_files(www):
        if path.suffix.lower() not in {".html", ".htm", ".js"}:
            continue
        tokens.update(compiled.findall(safe_read_text(path, errors="replace")))
    return tokens


def _first_endpoint_containing(endpoints: dict[str, WebEndpoint], token: str) -> str | None:
    for path in sorted(endpoints):
        if token in path.lower():
            return path
    return None


def _parse_interpreter(output: str) -> str | None:
    match = re.search(r"Requesting program interpreter:\s*([^\]]+)", output)
    return match.group(1).strip() if match else None


def _parse_needed(output: str) -> list[str]:
    return re.findall(r"Shared library: \[([^\]]+)\]", output)


def _parse_imports(output: str) -> list[str]:
    imports = []
    for line in output.splitlines():
        if " UND " not in line:
            continue
        parts = line.split()
        if parts:
            imports.append(parts[-1].split("@")[0])
    return sorted(set(imports))


def _parse_dynamic_tag(output: str, tag: str) -> str | None:
    match = re.search(rf"\({tag}\).*?\[([^\]]+)\]", output)
    return match.group(1) if match else None


def _architecture_from_file(output: str) -> str | None:
    if "ARM" in output:
        return "ARM"
    if "MIPS" in output:
        return "MIPS"
    return None


def _endianness_from_file(output: str) -> str | None:
    if "LSB" in output:
        return "little"
    if "MSB" in output:
        return "big"
    return None


def _find_library(rootfs: Path, library: str) -> bool:
    for directory in ("lib", "usr/lib", "usr/local/lib"):
        if _path_exists(rootfs / directory / library):
            return True
    return False


def _path_exists(path: Path) -> bool:
    try:
        return path.exists()
    except OSError:
        return False


def _root_path(rootfs: Path, firmware_path: str) -> Path:
    return guest_path(rootfs, firmware_path)


def _first_quoted(value: str) -> str | None:
    match = re.search(r'"([^"]+)"', value)
    return match.group(1) if match else None


def _first_execve(trace_text: str, binary: str | None = None) -> dict[str, str] | None:
    for line in trace_text.splitlines():
        if "execve(" not in line:
            continue
        match = re.match(r"^\s*(?P<pid>\d+)\s+execve\((?P<args>.*)\)\s+=\s+(?P<result>.*)$", line)
        if not match:
            continue
        event = match.groupdict()
        if binary is None or binary in event["args"]:
            return event
    return None


def _parse_execve_argv(args: str) -> list[str]:
    values = re.findall(r'"([^"]+)"', args)
    return values[:1] if len(values) == 1 else values


def _first_syscall_result_int(trace_text: str, syscall: str) -> int | None:
    match = re.search(rf"\b{re.escape(syscall)}\([^)]*\)\s+=\s+(-?\d+)", trace_text)
    if not match:
        return None
    value = int(match.group(1))
    return value if value >= 0 else None


def _infer_fd_events(trace_text: str) -> list[dict[str, Any]]:
    fds: list[dict[str, Any]] = []
    for line in trace_text.splitlines():
        open_match = re.match(r'^\s*(?P<pid>\d+)\s+open\("(?P<path>[^"]+)",(?P<flags>[^)]*)\)\s+=\s+(?P<fd>-?\d+)', line)
        if open_match:
            data = open_match.groupdict()
            if int(data["fd"]) >= 0:
                fds.append({"fd": int(data["fd"]), "type": "file", "target": data["path"], "flags": data["flags"]})
            continue
        socket_match = re.match(r"^\s*(?P<pid>\d+)\s+socket\((?P<domain>[^,]+),(?P<kind>[^,]+),(?P<proto>[^)]*)\)\s+=\s+(?P<fd>-?\d+)", line)
        if socket_match:
            data = socket_match.groupdict()
            if int(data["fd"]) >= 0:
                fds.append({"fd": int(data["fd"]), "type": "socket", "domain": data["domain"], "kind": data["kind"], "proto": data["proto"]})
    return fds[-100:]


def _last_chdir_before_exec(trace_text: str, binary: str) -> str | None:
    cwd = None
    for line in trace_text.splitlines():
        if "chdir(" in line:
            quoted = _first_quoted(line)
            if quoted:
                cwd = quoted
        if "execve(" in line and binary in line:
            return cwd
    return cwd


def _parent_pid_from_sigchld(trace_text: str) -> int | None:
    match = re.search(r"si_pid=(\d+).+si_status=182", trace_text)
    return int(match.group(1)) if match else None
