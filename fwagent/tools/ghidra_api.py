from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any

from fwagent.config import Round2Config, load_round2_config
from fwagent.models import ToolResult
from fwagent.runtime.command import CommandRunner
from fwagent.runtime.ghidra import ExportValidationError, GhidraRuntime, validate_export_payload
from fwagent.tools.architecture import parse_elf_header
from fwagent.tools.common import extract_ascii_strings, is_elf, is_regular_file, sha256_file


DANGEROUS_NAMES = {
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
}


class BinaryToolAPI:
    def __init__(
        self,
        workspace: str | Path,
        *,
        config: Round2Config | None = None,
        runner: CommandRunner | None = None,
    ):
        self.workspace = Path(workspace).resolve()
        self.workspace.mkdir(parents=True, exist_ok=True)
        (self.workspace / "logs").mkdir(parents=True, exist_ok=True)
        self.config = config or load_round2_config()
        self.runner = runner or CommandRunner(self.workspace / "logs")
        self.runtime = GhidraRuntime(self.workspace, settings=self.config.ghidra, runner=self.runner)
        self.cache_dir = self.workspace / "ghidra" / "cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def analyze_binary(self, binary: str | Path, *, force: bool = False, allow_fallback: bool = True) -> dict[str, Any]:
        start = time.monotonic()
        binary_path = Path(binary).absolute()
        if not is_regular_file(binary_path) or not is_elf(binary_path):
            return ToolResult(
                success=False,
                tool="ghidra.analyze_binary",
                binary=str(binary_path),
                duration=0,
                errors=["binary must be an ordinary ELF file"],
                result={},
            ).to_dict()

        size_mb = binary_path.stat().st_size / (1024 * 1024)
        if size_mb > self.config.ghidra.max_binary_size_mb:
            return ToolResult(
                success=False,
                tool="ghidra.analyze_binary",
                binary=str(binary_path),
                duration=round(time.monotonic() - start, 3),
                errors=[f"binary exceeds max size: {size_mb:.1f} MB"],
                result={"oversized": True, "max_binary_size_mb": self.config.ghidra.max_binary_size_mb},
            ).to_dict()

        cache_path = self._cache_path(binary_path)
        if cache_path.exists() and not force:
            try:
                cached = _load_json(cache_path)
                if not isinstance(cached, dict):
                    raise ValueError("cache must be an object")
                metadata = cached.get("metadata") or {}
                if not isinstance(metadata, dict):
                    raise ValueError("cache metadata must be an object")
                if not metadata.get("fallback"):
                    validate_export_payload(cached, expected_hash=sha256_file(binary_path))
                elif not allow_fallback:
                    raise ValueError("fallback cache cannot satisfy no-fallback request")
                elif not isinstance(cached.get("summary"), dict) or cached["summary"].get("sha256") != sha256_file(binary_path):
                    raise ValueError("fallback cache target mismatch")
            except (OSError, ValueError, UnicodeError) as exc:
                return ToolResult(success=False, tool="ghidra.analyze_binary", binary=str(binary_path), duration=round(time.monotonic()-start, 3),
                                  result={"metadata": {"error_code": "GHIDRA_CACHE_INVALID"}}, errors=[f"GHIDRA_CACHE_INVALID: {exc}"]).to_dict()
            return ToolResult(success=True, tool="ghidra.analyze_binary", binary=str(binary_path),
                              duration=round(time.monotonic()-start, 3), result=cached, warnings=["cache hit"]).to_dict()

        environment = self.runtime.check_environment()
        warnings: list[str] = []
        errors: list[str] = []
        requested_backend = "ghidra"
        backend_used = "unavailable"
        fallback_reason = None
        if environment["success"]:
            ghidra_result = self.runtime.export_binary(binary_path).to_dict()
            failure_code = (ghidra_result.get("result", {}).get("metadata") or {}).get("error_code")
            if failure_code in {"GHIDRA_OUTPUT_MISSING", "GHIDRA_JSON_INVALID", "GHIDRA_OUTPUT_INVALID", "GHIDRA_TARGET_MISMATCH", "GHIDRA_OUTPUT_UNREADABLE"}:
                return ghidra_result
            if ghidra_result["success"]:
                ghidra_payload = ghidra_result["result"] if isinstance(ghidra_result.get("result"), dict) else {}
                runtime_metadata = ghidra_payload.get("metadata", {}) if isinstance(ghidra_payload.get("metadata"), dict) else {}
                normalized = _normalize_ghidra_result(binary_path, ghidra_payload, self.runtime.ghidra_version())
                normalized.setdefault("metadata", {}).update(
                    {
                        **runtime_metadata,
                        "requested_backend": requested_backend,
                        "backend_used": "host_ghidra",
                        "real_ghidra": True,
                        "fallback": False,
                        "fallback_used": False,
                    }
                )
                self._save_cache(cache_path, normalized)
                ghidra_result["duration"] = round(time.monotonic() - start, 3)
                ghidra_result["result"] = normalized
                return ghidra_result
            warnings.extend(ghidra_result.get("warnings", []))
            errors.extend(ghidra_result.get("errors", []))
            fallback_reason = _fallback_reason_from_errors(errors, default="GHIDRA_SCRIPT_FAILED")
        else:
            warnings.extend(environment.get("warnings", []))
            errors.extend(environment.get("errors", []))
            fallback_reason = _fallback_reason_from_errors(errors, default="GHIDRA_WORKER_UNAVAILABLE")

        container_environment = self.runtime.check_container_environment()
        if container_environment.get("success"):
            container_result = self.runtime.export_binary_containerized(binary_path).to_dict()
            failure_code = (container_result.get("result", {}).get("metadata") or {}).get("error_code")
            if failure_code in {"GHIDRA_OUTPUT_MISSING", "GHIDRA_JSON_INVALID", "GHIDRA_OUTPUT_INVALID", "GHIDRA_TARGET_MISMATCH", "GHIDRA_OUTPUT_UNREADABLE"}:
                return container_result
            if container_result["success"]:
                result_payload = container_result.get("result") if isinstance(container_result.get("result"), dict) else {}
                container_meta = container_environment.get("result") if isinstance(container_environment.get("result"), dict) else {}
                runtime_metadata = result_payload.get("metadata", {}) if isinstance(result_payload.get("metadata"), dict) else {}
                normalized = _normalize_ghidra_result(binary_path, result_payload, str(container_meta.get("ghidra_version") or "containerized-ghidra"))
                normalized.setdefault("metadata", {}).update(
                    {
                        **runtime_metadata,
                        "requested_backend": requested_backend,
                        "backend_used": "dockerized_ghidra",
                        "real_ghidra": True,
                        "fallback": False,
                        "fallback_used": False,
                        "worker": {
                            "type": "docker",
                            "image": self.config.ghidra.docker_image,
                            "java_version": container_meta.get("java"),
                            "ghidra_version": container_meta.get("ghidra_version"),
                            "analyze_headless": container_meta.get("analyze_headless"),
                        },
                    }
                )
                self._save_cache(cache_path, normalized)
                container_result["duration"] = round(time.monotonic() - start, 3)
                container_result["result"] = normalized
                container_result["warnings"] = warnings + container_result.get("warnings", [])
                return container_result
            warnings.extend(container_result.get("warnings", []))
            errors.extend(container_result.get("errors", []))
            fallback_reason = _fallback_reason_from_errors(container_result.get("errors", []), default="GHIDRA_CONTAINER_FAILED")
        else:
            container_errors = container_environment.get("errors", [])
            if container_errors:
                warnings.extend([str(item) for item in container_errors])
                fallback_reason = _fallback_reason_from_errors(container_errors, default=fallback_reason or "GHIDRA_CONTAINER_FAILED")

        if not allow_fallback:
            return ToolResult(
                success=False,
                tool="ghidra.analyze_binary",
                binary=str(binary_path),
                duration=round(time.monotonic() - start, 3),
                result={
                    "metadata": {
                        "requested_backend": requested_backend,
                        "backend_used": "none",
                        "real_ghidra": False,
                        "fallback": False,
                        "fallback_used": False,
                        "fallback_reason": fallback_reason,
                        "ghidra_errors": errors,
                    }
                },
                warnings=warnings,
                errors=errors,
            ).to_dict()

        fallback = self._fallback_analyze(binary_path)
        backend_used = "static_elf_fallback"
        fallback.setdefault("metadata", {}).update(
            {
                "requested_backend": requested_backend,
                "backend_used": backend_used,
                "real_ghidra": False,
                "fallback": True,
                "fallback_used": True,
                "fallback_reason": fallback_reason or "UNKNOWN_GHIDRA_FAILURE",
                "ghidra_errors": errors,
                "worker": {
                    "type": "docker",
                    "image": self.config.ghidra.docker_image,
                    "available": bool(container_environment.get("success")),
                },
            }
        )
        warnings.append("Ghidra unavailable or failed; used static ELF fallback")
        if errors:
            warnings.extend(errors)
        self._save_cache(cache_path, fallback)
        return ToolResult(
            success=True,
            tool="ghidra.analyze_binary",
            binary=str(binary_path),
            duration=round(time.monotonic() - start, 3),
            result=fallback,
            warnings=warnings,
            errors=[],
        ).to_dict()

    def get_binary_summary(self, binary: str | Path) -> dict[str, Any]:
        analysis = self.analyze_binary(binary)
        result = analysis.get("result", {})
        return _wrap("ghidra.get_binary_summary", binary, analysis, result.get("summary", {}))

    def list_functions(self, binary: str | Path) -> dict[str, Any]:
        analysis = self.analyze_binary(binary)
        result = analysis.get("result", {})
        return _wrap("ghidra.list_functions", binary, analysis, {"functions": result.get("functions", [])})

    def search_functions(self, binary: str | Path, query: str) -> dict[str, Any]:
        analysis = self.analyze_binary(binary)
        functions = analysis.get("result", {}).get("functions", [])
        lowered = query.lower()
        matches = [item for item in functions if lowered in item.get("name", "").lower() or lowered in item.get("address", "").lower()]
        return _wrap("ghidra.search_functions", binary, analysis, {"query": query, "functions": matches})

    def decompile_function(self, binary: str | Path, function: str) -> dict[str, Any]:
        if not is_regular_file(Path(binary)) or not is_elf(Path(binary)):
            return ToolResult(success=False, tool="ghidra.decompile_function", binary=str(binary), result={}, errors=["binary is not an ordinary file"]).to_dict()
        environment = self.runtime.check_environment()
        if environment["success"]:
            result = self.runtime.decompile_function(binary, function).to_dict()
            return result
        disassembly = self._fallback_disassemble_function(Path(binary).resolve(), function)
        return ToolResult(
            success=False,
            tool="ghidra.decompile_function",
            binary=str(Path(binary).resolve()),
            result={
                "name": function,
                "decompiled_code": None,
                "disassembly": disassembly,
            },
            warnings=environment.get("warnings", []) + ["Ghidra unavailable; returned fallback disassembly only"],
            errors=environment.get("errors", []),
        ).to_dict()

    def get_callers(self, binary: str | Path, function: str) -> dict[str, Any]:
        analysis = self.analyze_binary(binary)
        callgraph = analysis.get("result", {}).get("callgraph", [])
        callers = [edge for edge in callgraph if edge.get("callee") == function or edge.get("callee_address") == function]
        return _wrap("ghidra.get_callers", binary, analysis, {"function": function, "callers": callers})

    def get_callees(self, binary: str | Path, function: str) -> dict[str, Any]:
        analysis = self.analyze_binary(binary)
        callgraph = analysis.get("result", {}).get("callgraph", [])
        callees = [edge for edge in callgraph if edge.get("caller") == function or edge.get("caller_address") == function]
        return _wrap("ghidra.get_callees", binary, analysis, {"function": function, "callees": callees})

    def find_string(self, binary: str | Path, query: str) -> dict[str, Any]:
        analysis = self.analyze_binary(binary)
        strings = analysis.get("result", {}).get("strings", [])
        lowered = query.lower()
        matches = [item for item in strings if lowered in item.get("value", "").lower()]
        return _wrap("ghidra.find_string", binary, analysis, {"query": query, "strings": matches})

    def find_references(self, binary: str | Path, address: str) -> dict[str, Any]:
        analysis = self.analyze_binary(binary)
        callgraph = analysis.get("result", {}).get("callgraph", [])
        references = [edge for edge in callgraph if address in {edge.get("caller_address"), edge.get("callee_address")}]
        return _wrap("ghidra.find_references", binary, analysis, {"address": address, "references": references})

    def find_function_references(self, binary: str | Path, function: str) -> dict[str, Any]:
        analysis = self.analyze_binary(binary)
        callgraph = analysis.get("result", {}).get("callgraph", [])
        references = [edge for edge in callgraph if function in {edge.get("caller"), edge.get("callee")}]
        return _wrap("ghidra.find_function_references", binary, analysis, {"function": function, "references": references})

    def _fallback_analyze(self, binary: Path) -> dict[str, Any]:
        if not is_elf(binary):raise ValueError("static fallback requires an ELF asset")
        header = parse_elf_header(binary) or {}
        strings = extract_ascii_strings(binary, max_bytes=self.config.ghidra.max_binary_size_mb * 1024 * 1024)
        functions = self._functions_from_nm(binary)
        imports = self._imports_from_readelf(binary)
        exports = [item for item in functions if item.get("binding") in {"T", "W"}]
        callgraph = self._callgraph_from_objdump(binary)
        interesting_strings = _interesting_strings(strings)
        summary = {
            "binary": str(binary),
            "sha256": sha256_file(binary),
            "language": _language_from_header(header),
            "compiler": None,
            "function_count": len(functions),
            "imports": imports,
            "exports": exports,
            "interesting_strings": interesting_strings,
            "analysis_timed_out": False,
            "analyzer": "static-fallback",
            "ghidra_version": "unavailable",
        }
        return {
            "summary": summary,
            "functions": functions,
            "imports": imports,
            "exports": exports,
            "strings": [{"value": value} for value in strings[:5000]],
            "callgraph": callgraph,
            "references": [],
            "metadata": {
                "requested_backend": "ghidra",
                "backend_used": "static_elf_fallback",
                "real_ghidra": False,
                "fallback": True,
                "fallback_used": True,
            },
        }

    def _functions_from_nm(self, binary: Path) -> list[dict[str, Any]]:
        result = self.runner.run(["nm", "-n", str(binary)], timeout=20)
        functions: list[dict[str, Any]] = []
        if result.exit_code != 0:
            return functions
        for line in result.stdout.splitlines():
            match = re.match(r"^([0-9a-fA-F]+)\s+([A-Za-z])\s+(.+)$", line.strip())
            if not match:
                continue
            address, binding, name = match.groups()
            if binding.upper() not in {"T", "W"}:
                continue
            functions.append(
                {
                    "name": name.strip(),
                    "address": "0x" + address.lower(),
                    "size": None,
                    "is_external": False,
                    "is_thunk": name.endswith("@plt"),
                    "binding": binding,
                }
            )
        return functions

    def _imports_from_readelf(self, binary: Path) -> list[dict[str, Any]]:
        result = self.runner.run(["readelf", "-Ws", str(binary)], timeout=20)
        imports: list[dict[str, Any]] = []
        if result.exit_code != 0:
            return imports
        seen: set[str] = set()
        for line in result.stdout.splitlines():
            if " UND " not in line:
                continue
            match = re.search(r"\bUND\s+([^\s]+)", line)
            if not match:
                continue
            name = match.group(1).split("@", 1)[0]
            if name.startswith("("):
                continue
            if name in seen or not name:
                continue
            seen.add(name)
            imports.append({"name": name, "address": None, "dangerous": name in DANGEROUS_NAMES})
        return imports

    def _callgraph_from_objdump(self, binary: Path) -> list[dict[str, Any]]:
        result = self.runner.run(["objdump", "-d", str(binary)], timeout=30)
        if result.exit_code != 0:
            return []
        edges: list[dict[str, Any]] = []
        current_name = None
        current_address = None
        for line in result.stdout.splitlines():
            function_match = re.match(r"^([0-9a-fA-F]+)\s+<(.+)>:$", line.strip())
            if function_match:
                current_address = "0x" + function_match.group(1).lower()
                current_name = function_match.group(2)
                continue
            call_match = re.search(r"\bcall\w*\s+[0-9a-fA-Fx]+\s+<([^>]+)>", line)
            if current_name and call_match:
                callee = call_match.group(1)
                callee_address = None
                address_match = re.search(r"\bcall\w*\s+([0-9a-fA-Fx]+)", line)
                if address_match:
                    raw = address_match.group(1).lower()
                    callee_address = raw if raw.startswith("0x") else "0x" + raw
                edges.append(
                    {
                        "caller": current_name,
                        "callee": callee,
                        "caller_address": current_address,
                        "callee_address": callee_address,
                    }
                )
        return edges

    def _fallback_disassemble_function(self, binary: Path, function: str) -> str:
        if not is_elf(binary):raise ValueError("disassembly fallback requires an ELF asset")
        result = self.runner.run(["objdump", "-d", str(binary)], timeout=30)
        if result.exit_code != 0:
            return ""
        capture = False
        lines: list[str] = []
        for line in result.stdout.splitlines():
            if re.match(r"^[0-9a-fA-F]+\s+<.+>:$", line.strip()):
                capture = f"<{function}>" in line
                if capture:
                    lines.append(line)
                elif lines:
                    break
                continue
            if capture:
                lines.append(line)
        return "\n".join(lines[:300])

    def _cache_path(self, binary: Path) -> Path:
        return self.cache_dir / f"{self.runtime.cache_key(binary)}.json"

    def _save_cache(self, path: Path, result: dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as handle:
            json.dump(result, handle, indent=2, sort_keys=True)
            handle.write("\n")


def _normalize_ghidra_result(binary: Path, result: dict[str, Any], version: str) -> dict[str, Any]:
    validate_export_payload(result, expected_hash=sha256_file(binary))
    summary = result.get("summary") or {}
    functions = result.get("functions") or []
    imports = result.get("imports") or []
    exports = result.get("exports") or []
    strings = result.get("strings") or []
    callgraph = result.get("callgraph") or []
    summary.setdefault("binary", str(binary))
    summary.setdefault("sha256", sha256_file(binary))
    summary.setdefault("function_count", len(functions))
    summary.setdefault("imports", imports)
    summary.setdefault("exports", exports)
    summary.setdefault("interesting_strings", [item for item in strings if "HTTP" in str(item)][:50])
    summary.setdefault("analysis_timed_out", False)
    summary["analyzer"] = "ghidra"
    summary["ghidra_version"] = version
    return {
        "summary": summary,
        "functions": functions,
        "imports": imports,
        "exports": exports,
        "strings": strings,
        "callgraph": callgraph,
        "references": result.get("references", []),
        "metadata": {"fallback": False, "fallback_used": False, "real_ghidra": True},
    }


def _language_from_header(header: dict[str, Any]) -> str | None:
    arch = header.get("architecture")
    endian = "LE" if header.get("endianness") == "little" else "BE"
    bitness = header.get("bitness")
    if arch == "x86":
        return f"x86:{endian}:{bitness}:default"
    if arch == "x86_64":
        return f"x86:{endian}:64:default"
    if arch == "mips":
        return f"MIPS:{endian}:{bitness}:default"
    if arch == "arm":
        return f"ARM:{endian}:{bitness}:default"
    if arch == "aarch64":
        return f"AARCH64:{endian}:64:default"
    return None


def _interesting_strings(strings: list[str]) -> list[str]:
    tokens = ("HTTP", "GET ", "POST ", "/bin/sh", "cgi", "password", "token", "system")
    return sorted({value[:200] for value in strings if any(token in value for token in tokens)})[:100]


def _wrap(tool: str, binary: str | Path, analysis: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    return ToolResult(
        success=bool(analysis.get("success")),
        tool=tool,
        binary=str(Path(binary).resolve()),
        duration=analysis.get("duration", 0.0),
        result=result,
        warnings=analysis.get("warnings", []),
        errors=analysis.get("errors", []),
    ).to_dict()


def _load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _fallback_reason_from_errors(errors: list[Any], *, default: str) -> str:
    text = "\n".join(str(item) for item in errors).lower()
    if "analyzeheadless" in text and ("not found" in text or "no such file" in text):
        return "GHIDRA_ANALYZE_HEADLESS_NOT_FOUND"
    if "permission denied" in text or "access is denied" in text or "docker_engine" in text:
        return "GHIDRA_CONTAINER_DOCKER_PERMISSION_DENIED"
    if "timeout" in text or "timed out" in text:
        return "GHIDRA_TIMEOUT"
    if "image" in text and ("not found" in text or "pull access denied" in text):
        return "GHIDRA_WORKER_IMAGE_NOT_FOUND"
    if "missing export files" in text:
        return "GHIDRA_OUTPUT_MISSING"
    if "import" in text and "failed" in text:
        return "GHIDRA_IMPORT_FAILED"
    if "script" in text and "failed" in text:
        return "GHIDRA_SCRIPT_FAILED"
    if "container" in text or "docker" in text:
        return "GHIDRA_CONTAINER_FAILED"
    return default
