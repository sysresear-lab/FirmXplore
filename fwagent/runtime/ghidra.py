from __future__ import annotations

import json
import shutil
import time
import uuid
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any

from fwagent.config import GhidraSettings, load_round2_config
from fwagent.models import ToolResult
from fwagent.runtime.command import CommandRunner
from fwagent.tools.common import sha256_file


EXPORT_SCRIPTS = {
    "summary": ("ExportBinarySummary.java", "summary.json"),
    "functions": ("ExportFunctions.java", "functions.json"),
    "imports": ("ExportImports.java", "imports.json"),
    "exports": ("ExportExports.java", "exports.json"),
    "strings": ("ExportStrings.java", "strings.json"),
    "callgraph": ("ExportCallGraph.java", "callgraph.json"),
}


class ExportValidationError(ValueError):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(f"{code}: {message}")


def validate_export_payload(payload: dict[str, Any], *, expected_hash: str | None = None) -> None:
    if not isinstance(payload, dict) or not isinstance(payload.get("summary"), dict):
        raise ExportValidationError("GHIDRA_OUTPUT_INVALID", "summary must be an object")
    summary = payload["summary"]
    count = summary.get("function_count")
    if isinstance(count, bool) or not isinstance(count, int) or count < 0:
        raise ExportValidationError("GHIDRA_OUTPUT_INVALID", "invalid function_count")
    digest = summary.get("sha256")
    if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdefABCDEF" for c in digest):
        raise ExportValidationError("GHIDRA_OUTPUT_INVALID", "missing/invalid target sha256")
    if expected_hash and digest.lower() != expected_hash.lower():
        raise ExportValidationError("GHIDRA_TARGET_MISMATCH", "export belongs to a different binary")
    if not isinstance(summary.get("language"), str) or not summary["language"]:
        raise ExportValidationError("GHIDRA_OUTPUT_INVALID", "missing language")
    if not isinstance(summary.get("analysis_timed_out"), bool):
        raise ExportValidationError("GHIDRA_OUTPUT_INVALID", "analysis_timed_out must be boolean")
    if summary.get("analysis_timed_out") is True:
        raise ExportValidationError("GHIDRA_TIMEOUT", "export reports analysis timeout")
    fields = {"functions": ("name", "address"), "imports": ("name",), "exports": ("name", "address"),
              "strings": ("address", "value"), "callgraph": ("caller", "callee", "caller_address", "callee_address")}
    for name, required in fields.items():
        rows = payload.get(name)
        if not isinstance(rows, list):
            raise ExportValidationError("GHIDRA_OUTPUT_INVALID", f"{name} must be an array")
        for row in rows:
            if not isinstance(row, dict) or any(not isinstance(row.get(field), str) for field in required):
                raise ExportValidationError("GHIDRA_OUTPUT_INVALID", f"invalid {name} record")
            if any(not row[field] for field in required if field != "value"):
                raise ExportValidationError("GHIDRA_OUTPUT_INVALID", f"empty {name} identity")
            if name == "imports" and not isinstance(row.get("dangerous"), bool):
                raise ExportValidationError("GHIDRA_OUTPUT_INVALID", "imports.dangerous must be boolean")
    if count != len(payload["functions"]):
        raise ExportValidationError("GHIDRA_OUTPUT_INVALID", "function_count differs from functions export")


class GhidraRuntime:
    def __init__(
        self,
        workspace: str | Path,
        *,
        settings: GhidraSettings | None = None,
        runner: CommandRunner | None = None,
    ):
        self.workspace = Path(workspace).resolve()
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.settings = settings or load_round2_config().ghidra
        self.ghidra_dir = self.workspace / "ghidra"
        self.ghidra_dir.mkdir(parents=True, exist_ok=True)
        self.project_dir = self._local_project_dir()
        self.script_dir = self._local_script_dir()
        self.output_dir = self.ghidra_dir / "outputs"
        self.project_dir.mkdir(parents=True, exist_ok=True)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.runner = runner or CommandRunner(self.workspace / "logs")

    def check_environment(self) -> dict[str, Any]:
        start = time.monotonic()
        warnings: list[str] = []
        errors: list[str] = []
        java = self.runner.run(["java", "-version"], timeout=15)
        java_output = (java.stderr or java.stdout).strip()
        if java.exit_code != 0:
            errors.append("java is not available")
        elif "version \"11." in java_output:
            warnings.append("Java 11 detected; Ghidra worker requires JDK 21")

        headless = self.analyze_headless_path()
        if not headless:
            errors.append("Ghidra analyzeHeadless was not found")

        if not self.script_dir.exists():
            errors.append(f"Ghidra script directory is not readable: {self.script_dir}")

        writable_probe = self.workspace / ".fwagent-write-test"
        try:
            writable_probe.write_text("ok", encoding="utf-8")
            writable_probe.unlink()
        except OSError as exc:
            errors.append(f"workspace is not writable: {exc}")

        return {
            "success": not errors,
            "tool": "ghidra.check",
            "duration": round(time.monotonic() - start, 3),
            "result": {
                "java": java_output,
                "ghidra_home": str(self.settings.home),
                "analyze_headless": str(headless) if headless else None,
                "script_dir": str(self.script_dir),
                "workspace": str(self.workspace),
                "ghidra_version": self.ghidra_version(),
            },
            "warnings": warnings,
            "errors": errors,
        }

    def check_container_environment(self) -> dict[str, Any]:
        return {"success": False, "tool": "ghidra.container_check", "duration": 0,
                "result": {"image": self.settings.docker_image}, "warnings": [],
                "errors": ["UNMANAGED_CONTAINER_EXECUTION_BLOCKED: Docker worker lacks durable cancellation supervision and output quotas"]}

    def analyze_headless_path(self) -> Path | None:
        candidates = [
            self.settings.home / "support" / "analyzeHeadless",
            self.settings.home / "support" / "analyzeHeadless.bat",
        ]
        for candidate in candidates:
            if candidate.exists():
                return candidate
        found = shutil.which("analyzeHeadless") or shutil.which("analyzeHeadless.bat")
        return Path(found) if found else None

    def ghidra_version(self) -> str:
        properties = self.settings.home / "Ghidra" / "application.properties"
        if properties.exists():
            for line in properties.read_text(encoding="utf-8", errors="ignore").splitlines():
                if line.startswith("application.version="):
                    return line.split("=", 1)[1].strip()
        headless = self.analyze_headless_path()
        if headless:
            result = self.runner.run([str(headless), "-version"], timeout=15)
            output = (result.stdout or result.stderr).strip().splitlines()
            if output:
                return output[0][:80]
        return "unavailable"

    def build_export_command(self, binary: str | Path, project_name: str, output_dir: Path) -> list[str]:
        headless = self.analyze_headless_path()
        if not headless:
            raise FileNotFoundError("analyzeHeadless")
        command = [
            str(headless),
            str(self.project_dir),
            project_name,
            "-import",
            str(Path(binary).resolve()),
            "-scriptPath",
            str(self.script_dir),
            "-analysisTimeoutPerFile",
            str(self.settings.timeout_seconds),
        ]
        for script, filename in EXPORT_SCRIPTS.values():
            command.extend(["-postScript", script, str(output_dir / filename)])
        if self.settings.delete_after_export:
            command.append("-deleteProject")
        return command

    def build_decompile_command(
        self,
        binary: str | Path,
        function: str,
        project_name: str,
        output_json: Path,
    ) -> list[str]:
        headless = self.analyze_headless_path()
        if not headless:
            raise FileNotFoundError("analyzeHeadless")
        return [
            str(headless),
            str(self.project_dir),
            project_name,
            "-import",
            str(Path(binary).resolve()),
            "-scriptPath",
            str(self.script_dir),
            "-analysisTimeoutPerFile",
            str(self.settings.timeout_seconds),
            "-postScript",
            "DecompileFunction.java",
            str(output_json),
            function,
            str(self.settings.max_function_chars),
            "-deleteProject",
        ]

    def export_binary(self, binary: str | Path) -> ToolResult:
        start = time.monotonic()
        binary_path = Path(binary).resolve()
        project_name = self._project_name(binary_path)
        output_dir = self.output_dir / project_name
        output_dir.mkdir(parents=True, exist_ok=True)
        try:
            command = self.build_export_command(binary_path, project_name, output_dir)
        except FileNotFoundError as exc:
            return ToolResult(
                success=False,
                tool="ghidra.analyze_binary",
                binary=str(binary_path),
                duration=round(time.monotonic() - start, 3),
                result={},
                errors=[str(exc)],
            )

        command_result = self.runner.run(command, timeout=self.settings.timeout_seconds + 30)
        return self._finish_export(binary_path, output_dir, command_result, start,
                                   backend="host_ghidra", image=None)

    def export_binary_containerized(self, binary: str | Path) -> ToolResult:
        return ToolResult(success=False, tool="ghidra.analyze_binary", binary=str(binary),
                          result={}, errors=["UNMANAGED_CONTAINER_EXECUTION_BLOCKED: Docker export disabled until output quotas and daemon cleanup supervision are verified; host static tools remain available"])

    def decompile_function(self, binary: str | Path, function: str) -> ToolResult:
        start = time.monotonic()
        binary_path = Path(binary).resolve()
        project_name = self._project_name(binary_path)
        output_json = self.output_dir / project_name / f"decompile-{_safe_name(function)}.json"
        output_json.parent.mkdir(parents=True, exist_ok=True)
        try:
            command = self.build_decompile_command(binary_path, function, project_name, output_json)
        except FileNotFoundError as exc:
            return ToolResult(
                success=False,
                tool="ghidra.decompile_function",
                binary=str(binary_path),
                duration=round(time.monotonic() - start, 3),
                result={},
                errors=[str(exc)],
            )
        command_result = self.runner.run(command, timeout=self.settings.timeout_seconds + 30)
        errors = []
        try:
            from fwagent.tools.bounded_io import read_beneath
            result = json.loads(read_beneath(output_json.parent,output_json.name,limit=2*1024*1024).decode('utf-8'))
        except (OSError,ValueError,RuntimeError) as exc:
            result = {};errors.append(f"DECOMPILATION_OUTPUT_INVALID: {type(exc).__name__}")
        if command_result.timed_out:
            errors.append("Ghidra decompilation timeout")
        elif command_result.exit_code != 0:
            errors.append((command_result.stderr or command_result.stdout or "Ghidra decompilation failed")[:2000])
        valid = (isinstance(result,dict) and result.get('status') == 'observed'
                 and result.get('completed') is True and result.get('timed_out') is False
                 and isinstance(result.get('name'),str) and bool(result['name'].strip())
                 and isinstance(result.get('address'),str) and bool(result['address'].strip())
                 and isinstance(result.get('decompiled_code'),str) and bool(result['decompiled_code'].strip()))
        if not valid:
            errors.append("DECOMPILATION_UNAVAILABLE: completed nonempty function output is required")
        return ToolResult(
            success=not errors and valid,
            tool="ghidra.decompile_function",
            binary=str(binary_path),
            duration=round(time.monotonic() - start, 3),
            result=result,
            errors=errors,
        )

    def cache_key(self, binary: str | Path) -> str:
        version = self.ghidra_version()
        material = f"{sha256_file(Path(binary))}:{version}:{self.settings.config_version}"
        return _safe_name(material)[:120]

    def _finish_export(self, binary: Path, output_dir: Path, command_result, started: float, *, backend: str, image) -> ToolResult:
        parsed = {}
        code = None
        errors = []
        if command_result.timed_out:
            code = "GHIDRA_TIMEOUT"
            errors = ["Ghidra analysis timeout"]
        elif command_result.exit_code != 0:
            code = "GHIDRA_ANALYSIS_FAILED"
            errors = [(command_result.stderr or command_result.stdout or "Ghidra analysis failed")[:2000]]
        else:
            try:
                parsed = self._collect_export_outputs(output_dir)
                validate_export_payload(parsed, expected_hash=sha256_file(binary))
            except ExportValidationError as exc:
                code, errors = exc.code, [str(exc)]
            except OSError as exc:
                code, errors = "GHIDRA_OUTPUT_UNREADABLE", [f"{type(exc).__name__}: {exc}"]
        metadata = _execution_metadata(command_result, backend=backend, image=image)
        metadata.update(error_code=code, output_dir=str(output_dir), export_contract="v1")
        return ToolResult(success=code is None, tool="ghidra.analyze_binary", binary=str(binary),
                          duration=round(time.monotonic() - started, 3), result={**parsed, "metadata": metadata}, errors=errors)

    def _collect_export_outputs(self, output_dir: Path) -> dict[str, Any]:
        # Every file below is emitted unconditionally by build_export_command.
        # Empty arrays are valid; absent files and malformed arrays are not.
        collected = {}
        for name, (_, filename) in EXPORT_SCRIPTS.items():
            path = output_dir / filename
            if not path.is_file():
                raise ExportValidationError("GHIDRA_OUTPUT_MISSING", f"missing required export: {filename}")
            try:
                collected[name] = _load_json(path)
            except (json.JSONDecodeError, UnicodeError) as exc:
                raise ExportValidationError("GHIDRA_JSON_INVALID", f"{filename}: {exc}") from exc
        validate_export_payload(collected)
        return collected

    def _project_name(self, binary: Path) -> str:
        return f"fwagent-{binary.stem}-{uuid.uuid4().hex[:10]}"

    def _local_project_dir(self) -> Path:
        if self.settings.project_dir.as_posix().startswith("/workspace"):
            return self.ghidra_dir / "projects"
        return self.settings.project_dir

    def _local_script_dir(self) -> Path:
        local_scripts = Path("ghidra_scripts").resolve()
        if self.settings.script_dir.as_posix().startswith("/opt/fwagent") and local_scripts.exists():
            return local_scripts
        return self.settings.script_dir


def _load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _safe_name(value: str) -> str:
    return "".join(char if char.isalnum() or char in "._-" else "_" for char in value)


def _container_task_path(relative: str) -> str:
    return str(PurePosixPath("/workspace/task") / PurePosixPath(relative))


def _extract_line_value(output: str, prefix: str) -> str | None:
    for line in output.splitlines():
        if line.startswith(prefix):
            return line.split("=", 1)[1].strip()
    return None


def _extract_java_version(output: str) -> str | None:
    for line in output.splitlines():
        if "version" in line.lower() and ("openjdk" in line.lower() or "java" in line.lower()):
            stripped = line.strip()
            if '"' in stripped:
                parts = stripped.split('"')
                if len(parts) >= 2 and parts[1]:
                    return parts[1]
            return stripped
    return None


def _extract_ghidra_version(output: str) -> str | None:
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("application.version="):
            return stripped.split("=", 1)[1].strip()
        if stripped.startswith("Ghidra") or "Ghidra" in stripped:
            parts = stripped.split()
            if len(parts) >= 2 and parts[0].lower() == "ghidra":
                return parts[1]
            return stripped[:120]
    return None


def _classify_container_error(result) -> str:
    text = f"{result.stderr or ''}\n{result.stdout or ''}".lower()
    if result.timed_out:
        return "GHIDRA_CONTAINER_CHECK_TIMEOUT"
    if "permission denied" in text or "access is denied" in text or "docker_engine" in text:
        return "GHIDRA_CONTAINER_DOCKER_PERMISSION_DENIED"
    if "pull access denied" in text or "no such image" in text or "unable to find image" in text:
        return "GHIDRA_WORKER_IMAGE_NOT_FOUND"
    if "analyzeheadless" in text and ("not found" in text or "no such file" in text):
        return "GHIDRA_ANALYZE_HEADLESS_NOT_FOUND"
    return "GHIDRA_CONTAINER_FAILED"


def _execution_metadata(result, *, backend: str, image: str | None) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "backend_used": backend,
        "ghidra_exit_code": result.exit_code,
        "timed_out": bool(result.timed_out),
        "duration_seconds": round(float(result.duration), 3),
    }
    if image:
        metadata["worker"] = {"type": "docker", "image": image}
    return metadata
