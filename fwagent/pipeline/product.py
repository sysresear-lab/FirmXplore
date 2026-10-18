from __future__ import annotations

import json
import logging
import shutil
import subprocess
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from fwagent.config import Round2Config, load_round2_config
from fwagent.dynamic.config import DynamicConfig, load_dynamic_config
from fwagent.dynamic.correlation import ComponentGraphBuilder
from fwagent.dynamic.investigation import InvestigationController
from fwagent.dynamic.models import DynamicEvidence, is_canonical_runtime_evidence
from fwagent.dynamic.prioritization import HypothesisValidationScheduler
from fwagent.dynamic.service import reconstruct_service_startup
from fwagent.dynamic.surface import AttackSurfaceBuilder
from fwagent.dynamic.surface_contract import surface_counts
from fwagent.dynamic.synthesis import HypothesisSynthesizer
from fwagent.dynamic.taint import TaintAnalysisBuilder
from fwagent.dynamic.workspace import DynamicWorkspace
from fwagent.findings import FindingFinalizer
from fwagent.pipeline.analyzer import analyze_firmware
from fwagent.pipeline.context import WorkspaceStateError, validate_workspace_input
from fwagent.reporting.final_report import ReportGenerator, ReportValidator, REPORT_SCHEMA_VERSION
from fwagent.reporting.json_report import load_analysis_json, save_analysis_json
from fwagent.runtime.ghidra import GhidraRuntime
from fwagent.runtime.scanning import ScanTimeoutError, recover_interrupted_scan, remaining_scan_seconds, run_bounded_scan, scan_budget, scan_owner_active
from fwagent.tools import analyze_binaries, discover_services, discover_web_surface, identify_architecture, inventory_filesystem, rank_binaries, scan_sensitive_files
from fwagent.tools.common import _raise_walk_error, is_elf, is_regular_file, is_scan_directory, safe_exists, safe_is_dir, sha256_file
from fwagent.tools.extractor import find_rootfs_candidates
from fwagent.tools.ghidra_api import BinaryToolAPI


EXIT_ANALYSIS_COMPLETED = 0
EXIT_PARTIAL = 1
EXIT_INVALID_INPUT = 2
EXIT_ENVIRONMENT_MISSING = 3
EXIT_PIPELINE_FAILURE = 4
EXIT_SAFETY_STOP = 5

PIPELINE_PHASES = {
    "task_create",
    "input_prepare",
    "environment_check",
    "static_analysis",
    "investigation_prepare",
    "investigation",
    "finding_finalize",
    "report_generation",
    "completed",
    "blocked",
    "failed",
    "interrupted",
}

V01_PIPELINE_STAGES = [
    "INPUT_PREPARE",
    "ENVIRONMENT_CHECK",
    "EXTRACTION",
    "ROOTFS_INVENTORY",
    "STATIC_TARGET_SELECTION",
    "GHIDRA_ANALYSIS",
    "COMPONENT_CORRELATION",
    "ATTACK_SURFACE",
    "TAINT_CORRELATION",
    "HYPOTHESIS_SYNTHESIS",
    "PRIORITIZATION",
    "INVESTIGATION",
    "DYNAMIC_VALIDATION",
    "FINDING_FINALIZATION",
    "REPORT_GENERATION",
    "COMPLETED",
]


@dataclass
class PipelineStageResult:
    stage: str
    status: str = "pending"
    started_at: str | None = None
    finished_at: str | None = None
    duration: float = 0.0
    input_artifacts: list[str] = field(default_factory=list)
    output_artifacts: list[str] = field(default_factory=list)
    items_processed: int | None = 0
    items_succeeded: int = 0
    items_failed: int = 0
    items_skipped: int = 0
    blocking_reason: str | None = None
    partial_reason: str | None = None
    item_count_status: str | None = None

    def __post_init__(self) -> None:
        if self.stage == "ATTACK_SURFACE" and self.item_count_status is None and self.items_processed == 0:
            self.items_processed = None
            self.item_count_status = "not_executed" if self.status in {"pending", "skipped", "blocked"} else "unknown"

    def start(self) -> None:
        self.started_at = utc_now_iso()

    def finish(
        self,
        status: str,
        *,
        input_artifacts: list[str] | None = None,
        output_artifacts: list[str] | None = None,
        items_processed: int | None = None,
        items_succeeded: int | None = None,
        items_failed: int | None = None,
        items_skipped: int | None = None,
        blocking_reason: str | None = None,
        partial_reason: str | None = None,
        started_monotonic: float | None = None,
    ) -> None:
        self.status = status
        self.finished_at = utc_now_iso()
        if started_monotonic is not None:
            self.duration = round(time.monotonic() - started_monotonic, 3)
        if input_artifacts is not None:
            self.input_artifacts = input_artifacts
        if output_artifacts is not None:
            self.output_artifacts = output_artifacts
        if items_processed is not None:
            self.items_processed = items_processed
        if items_succeeded is not None:
            self.items_succeeded = items_succeeded
        if items_failed is not None:
            self.items_failed = items_failed
        if items_skipped is not None:
            self.items_skipped = items_skipped
        self.blocking_reason = blocking_reason
        self.partial_reason = partial_reason

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RootfsArtifact:
    artifact_id: str
    source_firmware: str
    source_firmware_hash: str | None
    path: str
    host_path: str
    container_path: str | None
    workspace_relative_path: str
    source: str
    extraction_method: str
    filesystem_type: str | None = None
    architecture: str | None = None
    endianness: str | None = None
    file_count: int = 0
    elf_count: int = 0
    canonical: bool = True
    validated: bool = False
    validation_reason: str = ""
    canonical_linux_rootfs: str | None = None
    linux_semantics_preserved: bool = True
    host_readable: bool = True
    host_safe_view: str | None = None
    semantic_fidelity: str = "canonical-linux-rootfs"
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).replace(microsecond=0).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass
class AnalysisTask:
    task_id: str
    input_path: str
    input_hash: str
    firmware_name: str
    workspace: str
    created_at: str = field(default_factory=utc_now_iso)
    status: str = "created"
    pipeline_phase: str = "task_create"
    analysis_mode: str = "full"
    provider_backed: bool = False
    report_paths: dict[str, str] = field(default_factory=dict)
    error: dict[str, Any] | None = None
    resume_available: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ProductDeepStaticSettings:
    enabled: bool = True
    top_n: int = 10
    max_targets: int = 20
    dependency_expansion: bool = True


@dataclass(frozen=True)
class ProductAdvancedPipelineSettings:
    correlation: bool = True
    surface: bool = True
    taint: bool = True
    synthesis: bool = True
    prioritization: bool = True
    investigation: bool = True


@dataclass(frozen=True)
class ProductPipelineSettings:
    deep_static_analysis: ProductDeepStaticSettings = ProductDeepStaticSettings()
    advanced_pipeline: ProductAdvancedPipelineSettings = ProductAdvancedPipelineSettings()


class AnalysisPipelineController:
    def __init__(
        self,
        workspace_root: str | Path = "workspace",
        *,
        config: DynamicConfig | None = None,
        round2_config: Round2Config | None = None,
        product_config: ProductPipelineSettings | None = None,
    ):
        self.workspace_root = Path(workspace_root).resolve()
        self.workspace_root.mkdir(parents=True, exist_ok=True)
        self.config = config or load_dynamic_config()
        self.round2_config = round2_config or load_round2_config()
        self.product_config = product_config or _load_product_config()

    def analyze(
        self,
        firmware: str | Path,
        *,
        task_id: str | None = None,
        resume: bool = False,
        report_formats: set[str] | None = None,
        static_only: bool = False,
        no_dynamic: bool = False,
        fast: bool = False,
        deep: bool = False,
        max_iterations: int | None = None,
        output_dir: str | Path | None = None,
        progress: bool = True,
        timeout: int = 600,
        scan_timeout: float | None = None,
    ) -> dict[str, Any]:
        started = time.monotonic()
        source = Path(firmware)
        if resume and task_id and not source.exists():
            task = self.load_task(task_id)
            if not task:
                return self._invalid(str(source), task_id, "RESUME_STATE_INVALID", "resume task not found")
            source = Path(task.input_path)
            if not source.exists():
                stored = self.workspace_root / task_id / "input" / task.firmware_name
                if is_regular_file(stored):
                    source = stored
        if not source.exists():
            return self._invalid(str(source), task_id, "INPUT_NOT_FOUND", "firmware input not found")
        input_hash = sha256_file(source)
        task_id = task_id or self._new_task_id(input_hash)
        task_dir = self.workspace_root / task_id
        existing_task = self.load_task(task_id)
        if not resume and (existing_task or (task_dir / "input").exists()):
            return self._invalid(str(source), task_id, "TASK_EXISTS", "task already exists; use --resume or a new task id")
        if resume:
            if existing_task and existing_task.status == "running" and scan_owner_active(task_dir):
                return self._invalid(str(source), task_id, "TASK_RUNNING", "task owner is still alive; cannot resume concurrently")
            try:
                validate_workspace_input(task_dir, source, task_id)
            except (WorkspaceStateError, OSError, ValueError) as exc:
                return self._invalid(str(source), task_id, "RESUME_STATE_INVALID", str(exc))
            if existing_task and existing_task.pipeline_phase == "completed":
                saved = _load_json_if_exists(task_dir / "pipeline_summary.json")
                if not isinstance(saved, dict) or saved.get("task_id") != task_id:
                    return self._invalid(str(source), task_id, "RESUME_STATE_INVALID", "completed task summary is missing or invalid; existing reports preserved")
                return {**saved, "resume_reused_complete": True}
        task = existing_task if resume else None
        analysis_mode = "fast" if fast else "deep" if deep else "static-only" if static_only else "no-dynamic" if no_dynamic else "normal"
        if not task:
            task = AnalysisTask(
                task_id=task_id,
                input_path=str(source.resolve()),
                input_hash=input_hash,
                firmware_name=source.name,
                workspace=str(task_dir),
                analysis_mode=analysis_mode,
            )
            self._save_task(task)
        else:
            task.analysis_mode = analysis_mode
            self._save_task(task)

        dynamic_executed = False
        errors: list[dict[str, Any]] = []
        timings: dict[str, float] = {}
        stage_results = {stage: PipelineStageResult(stage) for stage in V01_PIPELINE_STAGES}

        try:
            self._run_stage(stage_results, "INPUT_PREPARE", timings, lambda: self._prepare_input_stage(task, source), progress, "[1/8] Preparing firmware\n[1/15] FirmXplore input preparation")
            self._run_stage(stage_results, "ENVIRONMENT_CHECK", timings, lambda: self._environment_stage(task), progress, "[2/15] FirmXplore environment check")

            with scan_budget(scan_timeout, event_path=task_dir / "scan_events.jsonl"):
                if not resume or not (task_dir / "reports" / "analysis.json").exists():
                    self._phase(task, "static_analysis", "running")
                    self._run_stage(
                        stage_results,
                        "EXTRACTION",
                        timings,
                        lambda: analyze_firmware(source, workspace=self.workspace_root, timeout=timeout, task_id=task_id, resume=resume),
                        progress,
                        "[3/15] Extracting firmware and building base inventory",
                    )
                else:
                    self._skip_stage(stage_results, "EXTRACTION", "resume reused existing reports/analysis.json")
                    timings["extraction"] = 0.0

                rootfs_artifact = self._ensure_canonical_rootfs(task_id, source, stage_results, timings, errors, timeout=timeout)
                inventory_result: dict[str, Any] | None = None
                if rootfs_artifact:
                    inventory_result = self._run_stage(stage_results, "ROOTFS_INVENTORY", timings, lambda: self._refresh_inventory_for_canonical_rootfs(task_id, rootfs_artifact), progress, "[4/15] Canonical rootfs inventory")
                else:
                    self._block_stage(stage_results, "ROOTFS_INVENTORY", "no canonical rootfs established")

            inventory_ready = bool(inventory_result and inventory_result.get("success"))
            if inventory_ready:
                # 静态可行性评估（P2-2）：动态阶段未运行时为报告提供具体原因，
                # 而不是笼统的 not_assessed。动态阶段已评估过时不覆盖。
                try:
                    from fwagent.dynamic.feasibility import write_if_missing
                    write_if_missing(task_dir)
                except Exception:  # noqa: BLE001  可行性评估失败不影响主流程
                    pass
            if not inventory_ready:
                self._block_stage(stage_results, "STATIC_TARGET_SELECTION", "no valid canonical rootfs inventory")
                self._block_stage(stage_results, "GHIDRA_ANALYSIS", "no static targets because canonical rootfs inventory is unavailable")
            elif fast:
                self._skip_stage(stage_results, "STATIC_TARGET_SELECTION", "fast mode uses scanner-only target hints")
                self._skip_stage(stage_results, "GHIDRA_ANALYSIS", "fast mode skips deep static analysis")
            else:
                targets_result = self._run_stage(stage_results, "STATIC_TARGET_SELECTION", timings, lambda: self._select_static_targets(task_id, deep=deep), progress, "[5/15] Selecting deep static targets")
                targets = targets_result if isinstance(targets_result, list) else targets_result.get("targets", []) if isinstance(targets_result, dict) else []
                if stage_results["STATIC_TARGET_SELECTION"].status != "completed" or not targets:
                    self._block_stage(stage_results, "GHIDRA_ANALYSIS", "no ELF static targets were scheduled")
                else:
                    self._run_stage(stage_results, "GHIDRA_ANALYSIS", timings, lambda: self._run_ghidra_stage(task_id, targets), progress, "[6/15] Running Ghidra/static deep analysis")

            if not inventory_ready:
                for stage in ("COMPONENT_CORRELATION", "ATTACK_SURFACE", "TAINT_CORRELATION", "HYPOTHESIS_SYNTHESIS", "PRIORITIZATION", "INVESTIGATION", "DYNAMIC_VALIDATION"):
                    self._block_stage(stage_results, stage, "no canonical rootfs inventory")
            elif static_only or fast:
                self._skip_stage(stage_results, "COMPONENT_CORRELATION", "advanced pipeline skipped by analysis mode" if fast else "static-only mode stops before advanced investigation")
                self._skip_stage(stage_results, "ATTACK_SURFACE", "advanced pipeline skipped by analysis mode" if fast else "static-only mode stops before advanced investigation")
                self._skip_stage(stage_results, "TAINT_CORRELATION", "advanced pipeline skipped by analysis mode" if fast else "static-only mode stops before advanced investigation")
                self._skip_stage(stage_results, "HYPOTHESIS_SYNTHESIS", "advanced pipeline skipped by analysis mode" if fast else "static-only mode stops before advanced investigation")
                self._skip_stage(stage_results, "PRIORITIZATION", "advanced pipeline skipped by analysis mode" if fast else "static-only mode stops before advanced investigation")
                self._skip_stage(stage_results, "INVESTIGATION", "advanced pipeline skipped by analysis mode" if fast else "static-only mode stops before advanced investigation")
                self._skip_stage(stage_results, "DYNAMIC_VALIDATION", "not requested in this analysis mode")
            else:
                self._phase(task, "investigation_prepare", "running")
                self._run_advanced_stage(stage_results, "COMPONENT_CORRELATION", timings, lambda: ComponentGraphBuilder(self.workspace_root, task_id, config=self.config).build(), errors, progress, "[7/15] Building component graph")
                self._run_advanced_stage(stage_results, "ATTACK_SURFACE", timings, lambda: AttackSurfaceBuilder(self.workspace_root, task_id, config=self.config).build(), errors, progress, "[8/15] Mapping attack surface")
                self._run_advanced_stage(stage_results, "TAINT_CORRELATION", timings, lambda: TaintAnalysisBuilder(self.workspace_root, task_id, config=self.config).build(), errors, progress, "[9/15] Correlating input-to-sink paths")
                self._run_advanced_stage(stage_results, "HYPOTHESIS_SYNTHESIS", timings, lambda: HypothesisSynthesizer(self.workspace_root, task_id, config=self.config).build(), errors, progress, "[10/15] Synthesizing hypotheses")
                self._run_advanced_stage(stage_results, "PRIORITIZATION", timings, lambda: HypothesisValidationScheduler(self.workspace_root, task_id, config=self.config).assess(), errors, progress, "[11/15] Prioritizing validation work")
                if no_dynamic:
                    errors.append(self._error("DYNAMIC_NOT_EXECUTED", "dynamic validation skipped by --no-dynamic", recoverable=True))
                    self._skip_stage(stage_results, "INVESTIGATION", "dynamic investigation skipped by --no-dynamic")
                    self._skip_stage(stage_results, "DYNAMIC_VALIDATION", "dynamic validation skipped by --no-dynamic")
                else:
                    self._phase(task, "investigation", "running")
                    investigation = self._run_advanced_stage(
                        stage_results,
                        "INVESTIGATION",
                        timings,
                        lambda: InvestigationController(self.workspace_root, task_id, config=self.config).run(resume=resume, max_iterations=max_iterations),
                        errors,
                        progress,
                        "[12/15] Running deterministic investigation",
                    )
                    dynamic_executed = bool((investigation or {}).get("success"))
                    self._finish_dynamic_validation_stage(stage_results, timings, task_id, dynamic_executed)

            self._phase(task, "finding_finalize", "running")
            findings = self._run_stage(stage_results, "FINDING_FINALIZATION", timings, lambda: FindingFinalizer(str(self.workspace_root), task_id).finalize(dynamic_executed=dynamic_executed), progress, "[13/15] Finalizing findings")
            self._phase(task, "report_generation", "running")
            status = self._analysis_status(errors, static_only=static_only, no_dynamic=no_dynamic, fast=fast, stage_results=stage_results)
            self._write_pipeline_artifacts(task_id, stage_results, status)

            def report_step() -> tuple[dict[str, str], Path, dict[str, Any]]:
                generator = ReportGenerator(self.workspace_root, task_id)
                model = generator.build_model(findings, analysis_status=status)
                report_paths = generator.generate_all(model, report_formats)
                artifact_manifest = generator.write_artifact_manifest()
                validation = ReportValidator().validate(model)
                return report_paths, artifact_manifest, validation

            report_paths, artifact_manifest, validation = self._run_stage(stage_results, "REPORT_GENERATION", timings, report_step, progress, "[14/15] Generating FirmXplore reports")
            if not validation["success"]:
                errors.append(self._error("REPORT_VALIDATION_FAILED", "; ".join(validation["errors"]), recoverable=False))
            if output_dir:
                self._copy_reports(task_id, output_dir)
            total = round(time.monotonic() - started, 3)
            stage_results["COMPLETED"].start()
            stage_results["COMPLETED"].finish("completed", started_monotonic=time.monotonic())
            self._write_pipeline_artifacts(task_id, stage_results, status)
            generator = ReportGenerator(self.workspace_root, task_id)
            refreshed_model = generator.build_model(findings, analysis_status=status)
            report_paths = generator.generate_all(refreshed_model, report_formats)
            artifact_manifest = generator.write_artifact_manifest()
            task.report_paths = report_paths
            task.status = "completed" if not errors else "partial"
            task.pipeline_phase = "completed"
            self._save_task(task)
            static_report = load_analysis_json(task_dir / "reports" / "analysis.json")
            summary = self._summary(task, load_analysis_json(task_dir / "reports" / "report.json"), timings, total, dynamic_executed, errors, artifact_manifest, static_report, stage_results)
            (task_dir / "pipeline_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            return summary
        except KeyboardInterrupt:
            task.status = "paused"
            task.pipeline_phase = "interrupted"
            self._save_task(task)
            raise
        except ScanTimeoutError as exc:
            task.status = "failed"
            task.pipeline_phase = "failed"
            task.error = self._error("BASE_SCAN_TIMEOUT", str(exc), recoverable=True)
            try:
                self._save_task(task)
            except OSError as state_error:
                logging.getLogger(__name__).warning("cannot save base scan timeout state: %s", state_error)
            return {"success": False, "exit_code": EXIT_PIPELINE_FAILURE, "error": task.error,
                    "scan_status": "timed_out", "task": task.to_dict(), "provider_backed": False}
        except Exception as exc:  # noqa: BLE001
            task.status = "failed"
            task.pipeline_phase = "failed"
            task.error = self._error("PIPELINE_FAILURE", str(exc), recoverable=True)
            self._save_task(task)
            return {
                "success": False,
                "exit_code": EXIT_PIPELINE_FAILURE,
                "error": task.error,
                "task": task.to_dict(),
                "provider_backed": False,
            }

    def _run_stage(
        self,
        stages: dict[str, PipelineStageResult],
        stage: str,
        timings: dict[str, float],
        func,
        progress: bool,
        message: str,
    ):
        self._progress(progress, message)
        result = stages[stage]
        result.start()
        if stage == "ATTACK_SURFACE":
            result.item_count_status = "unknown"
        started = time.monotonic()
        try:
            value = func()
            outputs = _artifact_outputs(value)
            if stage == "STATIC_TARGET_SELECTION" and not outputs:
                outputs = ["ghidra/targets.json"]
            items = _items_processed(value)
            if stage == "ATTACK_SURFACE":
                payload = value if isinstance(value, dict) else {}
                counts = surface_counts(payload.get("summary", payload), payload.get("entry_points"))
                items = counts["candidate_entries_total"]
                result.item_count_status = counts["count_status"]
                result.items_processed = items
            status = "completed"
            blocking_reason = None
            partial_reason = None
            items_failed = 0
            items_skipped = 0
            items_succeeded = items
            if isinstance(value, dict):
                if value.get("stage_status"):
                    status = str(value.get("stage_status"))
                if "items_succeeded" in value:
                    items_succeeded = int(value.get("items_succeeded") or 0)
                if "items_failed" in value:
                    items_failed = int(value.get("items_failed") or 0)
                if "items_skipped" in value:
                    items_skipped = int(value.get("items_skipped") or 0)
            if isinstance(value, dict) and value.get("success") is False:
                status = str(value.get("stage_status") or ("blocked" if value.get("blocking_reason") else "failed"))
                if status == "completed":
                    status = "failed"
                blocking_reason = value.get("blocking_reason")
                partial_reason = value.get("partial_reason") or value.get("error")
                if "items_succeeded" not in value:
                    items_succeeded = 0
                if status in {"blocked", "skipped"} and "items_skipped" not in value:
                    items_skipped = items or 1
                elif "items_failed" not in value:
                    items_failed = items
            elif isinstance(value, dict) and status in {"partial", "blocked", "skipped"}:
                blocking_reason = value.get("blocking_reason")
                partial_reason = value.get("partial_reason") or value.get("error")
            result.finish(
                status,
                output_artifacts=outputs,
                items_processed=items,
                items_succeeded=items_succeeded,
                items_failed=items_failed,
                items_skipped=items_skipped,
                blocking_reason=blocking_reason,
                partial_reason=partial_reason,
                started_monotonic=started,
            )
            timings[_stage_timing_key(stage)] = result.duration
            return value
        except ScanTimeoutError:
            result.finish("timed_out", blocking_reason="base scan deadline exceeded", started_monotonic=started)
            timings[_stage_timing_key(stage)] = result.duration
            raise
        except Exception:
            result.finish("failed", blocking_reason="stage raised an exception", started_monotonic=started)
            timings[_stage_timing_key(stage)] = result.duration
            raise

    def _run_advanced_stage(
        self,
        stages: dict[str, PipelineStageResult],
        stage: str,
        timings: dict[str, float],
        func,
        errors: list[dict[str, Any]],
        progress: bool,
        message: str,
    ):
        try:
            return self._run_stage(stages, stage, timings, func, progress, message)
        except Exception as exc:  # noqa: BLE001
            stages[stage].status = "partial"
            stages[stage].partial_reason = str(exc)
            errors.append(self._error(f"{stage}_FAILED", str(exc), recoverable=True))
            return {}

    def _skip_stage(self, stages: dict[str, PipelineStageResult], stage: str, reason: str) -> None:
        result = stages[stage]
        if result.status not in {"pending"}:
            return
        result.start()
        result.finish("skipped", items_skipped=1, blocking_reason=reason, started_monotonic=time.monotonic())

    def _block_stage(self, stages: dict[str, PipelineStageResult], stage: str, reason: str) -> None:
        result = stages[stage]
        if result.status not in {"pending"}:
            return
        result.start()
        result.finish("blocked", items_skipped=1, blocking_reason=reason, started_monotonic=time.monotonic())

    def _prepare_input_stage(self, task: AnalysisTask, source: Path) -> dict[str, Any]:
        task_dir = self.workspace_root / task.task_id
        input_dir = task_dir / "prepared_input"
        input_dir.mkdir(parents=True, exist_ok=True)
        copied = input_dir / source.name
        if not copied.exists():
            shutil.copy2(source, copied)
        return {"success": True, "output_artifacts": [copied.relative_to(task_dir).as_posix()], "items_processed": 1}

    def _environment_stage(self, task: AnalysisTask) -> dict[str, Any]:
        task_dir = self.workspace_root / task.task_id
        ghidra_runtime = GhidraRuntime(task_dir / "environment_check", settings=self.round2_config.ghidra)
        host_ghidra = ghidra_runtime.check_environment()
        container_ghidra = ghidra_runtime.check_container_environment()
        container_errors = container_ghidra.get("errors", [])
        payload = {
            "success": True,
            "product": "FirmXplore",
            "python_package": "fwagent",
            "provider_backed": False,
            "real_model_validation": "deferred",
            "ghidra_home": str(self.round2_config.ghidra.home),
            "docker": "PASS" if container_ghidra.get("success") else "BLOCKED",
            "containerized_ghidra": "PASS" if container_ghidra.get("success") else "BLOCKED",
            "containerized_ghidra_check": container_ghidra,
            "host_ghidra": "PASS" if host_ghidra.get("success") else "OPTIONAL_NOT_REQUIRED",
            "host_ghidra_check": host_ghidra,
            "static_elf_fallback": "available",
            "ghidra_worker_image": self.round2_config.ghidra.docker_image,
            "ghidra_blocking_reason": "; ".join(str(item) for item in container_errors) if container_errors else None,
            "firmxplore_console": True,
        }
        path = task_dir / "environment.json"
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return {"success": True, "output_artifacts": [path.relative_to(task_dir).as_posix()], "items_processed": 1}

    def _ensure_canonical_rootfs(
        self,
        task_id: str,
        source: Path,
        stages: dict[str, PipelineStageResult],
        timings: dict[str, float],
        errors: list[dict[str, Any]],
        *,
        timeout: int,
    ) -> RootfsArtifact | None:
        task_dir = self.workspace_root / task_id
        report_path = task_dir / "reports" / "analysis.json"
        report = load_analysis_json(report_path)
        attempts: list[dict[str, Any]] = []
        extraction = report.get("extraction", {}) if isinstance(report.get("extraction"), dict) else {}
        primary_candidates = ([extraction.get("rootfs")] + list(extraction.get("rootfs_candidates") or [])
                              if extraction.get("success") is True else [])
        primary = select_canonical_rootfs_candidate(primary_candidates, task_dir=task_dir)
        attempts.append(
            {
                "method": str(extraction.get("extractor") or "primary"),
                "status": "success" if primary else "no_rootfs",
                "candidates": [str(item) for item in primary_candidates if item],
                "selected_rootfs": str(primary["host_path"]) if primary else None,
                "selection_reason": primary.get("validation_reason") if primary else "no valid Linux rootfs candidate",
            }
        )
        if primary:
            artifact = self._write_rootfs_artifact(
                task_id,
                primary["host_path"],
                source_firmware=source,
                source_firmware_hash=report.get("firmware", {}).get("sha256"),
                source="primary",
                method=str(extraction.get("extractor") or "extractor"),
                validation=primary,
                architecture=report.get("platform", {}).get("architecture"),
                endianness=report.get("platform", {}).get("endianness"),
            )
            report.setdefault("extraction", {})["rootfs"] = str(primary["host_path"])
            report["extraction"]["canonical_rootfs"] = artifact.to_dict()
            report["extraction"]["success"] = True
            save_analysis_json(report, task_dir / "reports")
            self._write_extraction_artifact(task_id, attempts, artifact, selected_reason=primary["validation_reason"])
            stages["EXTRACTION"].output_artifacts.append("artifacts/rootfs.json")
            stages["EXTRACTION"].output_artifacts.append("artifacts/extraction.json")
            return artifact
        docker_start = time.monotonic()
        docker_result = self._docker_extract_rootfs(task_id, source, timeout=timeout)
        timings["docker_rootfs_fallback"] = round(time.monotonic() - docker_start, 3)
        if not docker_result.get("success"):
            embedded_start = time.monotonic()
            embedded_result = self._try_embedded_firmware_rootfs(task_id, source, attempts, timeout=timeout)
            timings["embedded_firmware_fallback"] = round(time.monotonic() - embedded_start, 3)
            if embedded_result.get("success"):
                docker_result = embedded_result
        if not docker_result.get("success"):
            code = str(docker_result.get("error_code") or "ROOTFS_NOT_FOUND")
            message = docker_result.get("error") or "no canonical rootfs discovered"
            attempts.append(
                {
                    "method": "docker-binwalk",
                    "status": "blocked" if code == "DOCKER_PERMISSION_DENIED" else "no_rootfs",
                    "error_code": code,
                    "error": message,
                    "selected_rootfs": None,
                }
            )
            self._write_extraction_artifact(task_id, attempts, None, selected_reason="no canonical rootfs established")
            errors.append(self._error(code, message, recoverable=True))
            stages["EXTRACTION"].status = "blocked" if code == "DOCKER_PERMISSION_DENIED" else "partial"
            stages["EXTRACTION"].blocking_reason = message if code == "DOCKER_PERMISSION_DENIED" else None
            stages["EXTRACTION"].partial_reason = None if code == "DOCKER_PERMISSION_DENIED" else "primary extractor and Docker fallback did not produce a rootfs"
            stages["EXTRACTION"].output_artifacts.append("artifacts/extraction.json")
            return None
        rootfs_path = Path(docker_result["rootfs"])
        validation = docker_result.get("validation") or validate_rootfs_candidate(rootfs_path)
        artifact = self._write_rootfs_artifact(
            task_id,
            rootfs_path,
            source_firmware=source,
            source_firmware_hash=report.get("firmware", {}).get("sha256"),
            source="docker",
            method=str(docker_result.get("method") or "docker binwalk"),
            validation=validation,
            architecture=None,
            endianness=None,
        )
        attempts.append(
            {
                "method": "docker-binwalk",
                "status": "success",
                "exit_code": docker_result.get("exit_code"),
                "selected_rootfs": str(rootfs_path),
                "selection_reason": validation.get("validation_reason"),
            }
        )
        report.setdefault("extraction", {})["rootfs"] = str(rootfs_path)
        report["extraction"]["canonical_rootfs"] = artifact.to_dict()
        candidates = report["extraction"].setdefault("rootfs_candidates", [])
        if str(rootfs_path) not in candidates:
            candidates.insert(0, str(rootfs_path))
        report["extraction"]["success"] = True
        report["extraction"]["extractor"] = "docker-binwalk"
        save_analysis_json(report, task_dir / "reports")
        self._write_extraction_artifact(task_id, attempts, artifact, selected_reason=validation.get("validation_reason", "docker-binwalk selected canonical rootfs"))
        stages["EXTRACTION"].status = "completed"
        stages["EXTRACTION"].output_artifacts.extend(["artifacts/rootfs.json", "artifacts/extraction.json", "docker_extract.out"])
        return artifact

    def _docker_extract_rootfs(self, task_id: str, source: Path, *, timeout: int) -> dict[str, Any]:
        # A killed Docker client does not terminate daemon-owned containers.
        # Keep this fallback closed until a quota-backed worker and durable
        # cancellation/cleanup supervisor have both been implemented and tested.
        return {"success": False, "error_code": "UNMANAGED_CONTAINER_EXECUTION_BLOCKED",
                "error": "Docker extraction disabled: output quota and daemon cleanup supervision are unavailable; use bounded static archive extraction."}

    def _try_embedded_firmware_rootfs(self, task_id: str, source: Path, attempts: list[dict[str, Any]], *, timeout: int) -> dict[str, Any]:
        task_dir = self.workspace_root / task_id
        last_result: dict[str, Any] = {"success": False, "error_code": "ROOTFS_NOT_FOUND", "error": "no embedded firmware candidate produced a rootfs"}
        for embedded in _embedded_firmware_candidates(task_dir, source):
            result = self._docker_extract_rootfs(task_id, embedded, timeout=timeout)
            attempts.append(
                {
                    "method": "embedded-docker-binwalk",
                    "embedded_firmware": str(embedded),
                    "status": "success" if result.get("success") else "no_rootfs",
                    "exit_code": result.get("exit_code"),
                    "selected_rootfs": result.get("rootfs"),
                    "selection_reason": (result.get("validation") or {}).get("validation_reason"),
                    "error_code": result.get("error_code"),
                }
            )
            if result.get("success"):
                return {**result, "method": "embedded-docker-binwalk", "embedded_firmware": str(embedded)}
            last_result = result
        return last_result

    def _write_rootfs_artifact(
        self,
        task_id: str,
        rootfs: Path,
        *,
        source_firmware: Path,
        source_firmware_hash: str | None,
        source: str,
        method: str,
        validation: dict[str, Any],
        architecture: str | None,
        endianness: str | None,
        host_safe_view: Path | None = None,
        linux_semantics_preserved: bool = True,
    ) -> RootfsArtifact:
        task_dir = self.workspace_root / task_id
        host_path = rootfs.resolve()
        try:
            workspace_relative = host_path.relative_to(task_dir.resolve()).as_posix()
        except ValueError:
            workspace_relative = host_path.as_posix()
        container_path = _host_to_container_path(host_path, task_dir)
        artifact = RootfsArtifact(
            artifact_id=f"ROOTFS-{task_id}",
            source_firmware=str(source_firmware.resolve()),
            source_firmware_hash=source_firmware_hash,
            path=workspace_relative,
            host_path=str(host_path),
            container_path=container_path,
            workspace_relative_path=workspace_relative,
            source=source,
            extraction_method=method,
            filesystem_type=validation.get("filesystem_type"),
            architecture=architecture,
            endianness=endianness,
            file_count=int(validation.get("file_count") or 0),
            elf_count=int(validation.get("elf_count") or 0),
            canonical=True,
            validated=bool(validation.get("valid")),
            validation_reason=str(validation.get("validation_reason") or validation.get("reason") or ""),
            canonical_linux_rootfs=str(host_path),
            linux_semantics_preserved=linux_semantics_preserved,
            host_readable=True,
            host_safe_view=str(host_safe_view.resolve()) if host_safe_view else None,
            semantic_fidelity="canonical-linux-rootfs" if linux_semantics_preserved else "host-safe-view",
        )
        artifacts_dir = task_dir / "artifacts"
        artifacts_dir.mkdir(parents=True, exist_ok=True)
        (artifacts_dir / "rootfs.json").write_text(json.dumps(artifact.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return artifact

    def _write_extraction_artifact(self, task_id: str, attempts: list[dict[str, Any]], rootfs: RootfsArtifact | None, *, selected_reason: str) -> Path:
        task_dir = self.workspace_root / task_id
        payload = {
            "schema_version": "firmxplore.extraction.v0.1",
            "attempts": attempts,
            "selected_rootfs": rootfs.to_dict() if rootfs else None,
            "selection_reason": selected_reason,
            "provider_backed": False,
            "created_at": utc_now_iso(),
        }
        artifacts_dir = task_dir / "artifacts"
        artifacts_dir.mkdir(parents=True, exist_ok=True)
        path = artifacts_dir / "extraction.json"
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return path

    def import_extracted_rootfs(
        self,
        task_id: str,
        rootfs: str | Path,
        *,
        source_firmware: str | Path | None = None,
        source_firmware_hash: str | None = None,
        extraction_method: str = "imported-rootfs",
        host_safe_view: str | Path | None = None,
    ) -> RootfsArtifact:
        task_dir = self.workspace_root / task_id
        task_dir.mkdir(parents=True, exist_ok=True)
        (task_dir / "reports").mkdir(parents=True, exist_ok=True)
        rootfs_path = Path(rootfs).resolve()
        validation = validate_rootfs_candidate(rootfs_path)
        if not validation.get("valid"):
            raise ValueError(f"invalid imported rootfs: {validation.get('validation_reason')}")
        source_path = Path(source_firmware).resolve() if source_firmware else rootfs_path
        artifact = self._write_rootfs_artifact(
            task_id,
            rootfs_path,
            source_firmware=source_path,
            source_firmware_hash=source_firmware_hash,
            source="imported",
            method=extraction_method,
            validation=validation,
            architecture=None,
            endianness=None,
            host_safe_view=Path(host_safe_view).resolve() if host_safe_view else None,
            linux_semantics_preserved=host_safe_view is None,
        )
        report_path = task_dir / "reports" / "analysis.json"
        report = load_analysis_json(report_path) if report_path.exists() else {
            "firmware": {"filename": source_path.name, "path": str(source_path), "sha256": source_firmware_hash},
            "extraction": {},
            "platform": {},
            "filesystem": {},
            "services": [],
            "web": {},
            "binaries": [],
            "priority_binaries": [],
            "security_candidates": [],
            "errors": [],
        }
        report.setdefault("extraction", {})
        report["extraction"].update(
            {
                "success": True,
                "extractor": extraction_method,
                "rootfs": str(rootfs_path),
                "canonical_rootfs": artifact.to_dict(),
                "rootfs_candidates": [str(rootfs_path)],
                "host_safe_view": str(Path(host_safe_view).resolve()) if host_safe_view else None,
            }
        )
        save_analysis_json(report, task_dir / "reports")
        self._write_extraction_artifact(
            task_id,
            [{"method": extraction_method, "status": "imported_artifact", "selected_rootfs": str(rootfs_path), "selection_reason": validation.get("validation_reason")}],
            artifact,
            selected_reason="explicit imported real rootfs artifact",
        )
        return artifact

    def _refresh_inventory_for_canonical_rootfs(self, task_id: str, rootfs_artifact: RootfsArtifact | None) -> dict[str, Any]:
        return run_bounded_scan("canonical_inventory", _refresh_inventory_worker, self.workspace_root,
                                self.config, self.round2_config, self.product_config, task_id, rootfs_artifact)

    def _refresh_inventory_scan(self, task_id: str, rootfs_artifact: RootfsArtifact | None) -> dict[str, Any]:
        task_dir = self.workspace_root / task_id
        report = load_analysis_json(task_dir / "reports" / "analysis.json")
        if not rootfs_artifact:
            return {"success": False, "stage_status": "blocked", "blocking_reason": "no canonical rootfs established", "items_processed": 0, "output_artifacts": ["reports/analysis.json"]}
        rootfs = Path(rootfs_artifact.host_path)
        validation = validate_rootfs_candidate(rootfs)
        if not validation.get("valid"):
            return {
                "success": False,
                "stage_status": "partial",
                "partial_reason": validation.get("validation_reason"),
                "items_processed": validation.get("file_count", 0),
                "output_artifacts": ["reports/analysis.json"],
            }
        filesystem = run_bounded_scan("canonical.filesystem", inventory_filesystem, rootfs)
        elf_files = filesystem.get("categories", {}).get("elf", [])
        if filesystem.get("total_files", 0) <= 0:
            return {"success": False, "stage_status": "partial", "partial_reason": "canonical rootfs inventory produced zero files", "items_processed": 0, "output_artifacts": ["reports/analysis.json"]}
        architecture = run_bounded_scan("canonical.architecture", identify_architecture, rootfs, elf_files)
        services = run_bounded_scan("canonical.services", discover_services, rootfs).get("services", [])
        web = run_bounded_scan("canonical.web", discover_web_surface, rootfs)
        selected_elf = _select_lightweight_static_binary_paths(elf_files, services, web)
        binaries = run_bounded_scan("canonical.binaries", analyze_binaries, rootfs, selected_elf)
        priority = rank_binaries(binaries, services, web)
        security_candidates = run_bounded_scan("canonical.secrets", scan_sensitive_files, rootfs)
        platform = {
            "architecture": architecture.get("primary_architecture"),
            "endianness": architecture.get("endianness"),
            "bitness": architecture.get("bitness"),
            "confidence": architecture.get("confidence", 0.0),
            "architectures": architecture.get("architectures", {}),
            "samples": architecture.get("samples", []),
            "os": "linux" if safe_exists(rootfs / "etc", allow_symlink=True) else None,
        }
        report["extraction"]["rootfs"] = str(rootfs)
        report["extraction"]["canonical_rootfs"] = rootfs_artifact.to_dict()
        report["platform"] = platform
        report["filesystem"] = filesystem
        report["services"] = services
        report["web"] = web
        report["binaries"] = binaries
        report["priority_binaries"] = priority
        report["security_candidates"] = security_candidates
        report.setdefault("timing", {})
        report["analysis_mode"] = "canonical-rootfs-refresh"
        rootfs_artifact.file_count = int(filesystem.get("total_files", 0))
        rootfs_artifact.elf_count = int(filesystem.get("elf_files", 0))
        rootfs_artifact.architecture = architecture.get("primary_architecture")
        rootfs_artifact.endianness = architecture.get("endianness")
        rootfs_artifact.validated = True
        rootfs_artifact.validation_reason = validation.get("validation_reason", rootfs_artifact.validation_reason)
        self._write_rootfs_artifact(
            task_id,
            rootfs,
            source_firmware=Path(rootfs_artifact.source_firmware),
            source_firmware_hash=rootfs_artifact.source_firmware_hash,
            source=rootfs_artifact.source,
            method=rootfs_artifact.extraction_method,
            validation={**validation, "file_count": filesystem.get("total_files", 0), "elf_count": filesystem.get("elf_files", 0)},
            architecture=architecture.get("primary_architecture"),
            endianness=architecture.get("endianness"),
            host_safe_view=Path(rootfs_artifact.host_safe_view).resolve() if rootfs_artifact.host_safe_view else None,
            linux_semantics_preserved=rootfs_artifact.linux_semantics_preserved,
        )
        report["extraction"]["canonical_rootfs"] = _load_json_if_exists(task_dir / "artifacts" / "rootfs.json")
        save_analysis_json(report, task_dir / "reports")
        self._write_service_profiles(task_id, rootfs)
        return {"success": True, "items_processed": filesystem.get("total_files", 0), "output_artifacts": ["reports/analysis.json"]}

    def _write_service_profiles(self, task_id: str, rootfs: Path) -> None:
        workspace = DynamicWorkspace(self.workspace_root, task_id)
        report = workspace.load_report()
        for service in report.get("services", []):
            name = str(service.get("name") or "")
            if name not in {"lighttpd", "uhttpd", "dnsmasq", "miniupnpd"}:
                continue
            try:
                profile = reconstruct_service_startup(rootfs, name).to_dict()
            except Exception:  # noqa: BLE001
                continue
            service_dir = workspace.dynamic_dir / "services" / name
            service_dir.mkdir(parents=True, exist_ok=True)
            (service_dir / "launch_profile.json").write_text(json.dumps(profile, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def _select_static_targets(self, task_id: str, *, deep: bool = False) -> list[dict[str, Any]]:
        task_dir = self.workspace_root / task_id
        report = load_analysis_json(task_dir / "reports" / "analysis.json")
        rootfs = Path(report.get("extraction", {}).get("rootfs") or "")
        elf_files = report.get("filesystem", {}).get("categories", {}).get("elf", [])
        if not report.get("extraction", {}).get("canonical_rootfs") or not safe_exists(rootfs, allow_symlink=True):
            return {"success": False, "stage_status": "blocked", "blocking_reason": "canonical rootfs is unavailable", "targets": [], "items_processed": 0, "output_artifacts": ["ghidra/targets.json"]}
        if not elf_files:
            out = {"success": False, "stage_status": "skipped", "blocking_reason": "no ELF files discovered in canonical rootfs", "targets": [], "selected_static_targets": 0, "items_processed": 0, "output_artifacts": ["ghidra/targets.json"]}
            ghidra_dir = task_dir / "ghidra"
            ghidra_dir.mkdir(parents=True, exist_ok=True)
            (ghidra_dir / "targets.json").write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            return out
        priority = report.get("priority_binaries", []) if isinstance(report.get("priority_binaries"), list) else []
        top_n = self.product_config.deep_static_analysis.top_n + (10 if deep else 0)
        max_targets = self.product_config.deep_static_analysis.max_targets + (20 if deep else 0)
        selected = []
        seen: set[str] = set()
        for item in priority:
            rel = str(item.get("path") or "")
            if not rel or item.get("score", 0) < self.round2_config.ghidra.minimum_priority_score:
                continue
            selected.append({"path": rel, "reason": "priority", "score": item.get("score", 0)})
            seen.add(rel)
            if len(selected) >= top_n:
                break
        if self.product_config.deep_static_analysis.dependency_expansion:
            selected.extend(_dependency_expansion(selected, report.get("binaries", []), elf_files, seen, max_targets=max_targets))
        targets = []
        for item in selected[:max_targets]:
            host = rootfs / item["path"].lstrip("/")
            targets.append({**item, "host_path": str(host), "exists": safe_exists(host)})
        out = {
            "success": True,
            "targets": targets,
            "selected_static_targets": len(targets),
            "top_n": top_n,
            "max_targets": max_targets,
            "dependency_expansion": self.product_config.deep_static_analysis.dependency_expansion,
            "output_artifacts": ["ghidra/targets.json"],
            "items_processed": len(targets),
        }
        ghidra_dir = task_dir / "ghidra"
        ghidra_dir.mkdir(parents=True, exist_ok=True)
        (ghidra_dir / "targets.json").write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return targets

    def _run_ghidra_stage(self, task_id: str, targets: list[dict[str, Any]]) -> dict[str, Any]:
        task_dir = self.workspace_root / task_id
        ghidra_dir = task_dir / "ghidra"
        ghidra_dir.mkdir(parents=True, exist_ok=True)
        api = BinaryToolAPI(task_dir, config=self.round2_config)
        analyses: list[dict[str, Any]] = []
        evidence = DynamicWorkspace(self.workspace_root, task_id).load_evidence()
        existing_ids = {item.id for item in evidence}
        for index, target in enumerate(targets):
            started_at = utc_now_iso()
            started = time.monotonic()
            result = {"target": target, "success": False, "status": "running", "started_at": started_at}
            analyses.append(result)
            _atomic_json(ghidra_dir / "target_status.json", {"batch_complete": False, "scheduled": len(targets), "analyses": analyses})
            try:
                if not target.get("exists"):
                    value = {"success": False, "errors": ["target does not exist"], "result": {}, "error_code": "TARGET_NOT_FOUND"}
                else:
                    value = api.analyze_binary(target["host_path"], allow_fallback=True)
                    if not isinstance(value, dict) or not isinstance(value.get("success"), bool):
                        raise ValueError("invalid binary tool result schema")
                if value.get("binary") and Path(value["binary"]).resolve() != Path(target.get("host_path", "")).resolve():
                    raise ValueError("tool result target differs from scheduled binary")
                value["target"] = target
                value.update(_ghidra_backend_details(value))
                produced = _ghidra_evidence_for_result(value)
                value["evidence_ids"] = [item.id for item in produced]
                for item in produced:
                    if item.id not in existing_ids:
                        evidence.append(item)
                        existing_ids.add(item.id)
                result.update(value)
                if not result.get("success"):
                    metadata = (result.get("result") or {}).get("metadata") or {}
                    result["error_code"] = result.get("error_code") or metadata.get("error_code") or _ghidra_failure_reason(result.get("errors", []))
                elif result.get("fallback_used"):
                    result["error_code"] = result.get("fallback_reason")
            except Exception as exc:
                code = getattr(exc, "code", None) or ("GHIDRA_JSON_INVALID" if isinstance(exc, (json.JSONDecodeError, UnicodeError)) else "GHIDRA_TIMEOUT" if isinstance(exc, TimeoutError) else "GHIDRA_OUTPUT_MISSING" if isinstance(exc, FileNotFoundError) else "GHIDRA_TARGET_ERROR")
                result.update(success=False, errors=[f"{type(exc).__name__}: {exc}"], error_code=code,
                              result={}, backend_used="none", real_ghidra=False, fallback_used=False,
                              fallback_reason=code, status="failed", evidence_ids=[])
            finally:
                result.update(started_at=started_at, finished_at=utc_now_iso(), duration=round(time.monotonic() - started, 3))
                result["execution_status"] = "completed" if result.get("success") and result.get("real_ghidra") else "degraded" if result.get("success") else "skipped" if result.get("error_code") == "TARGET_NOT_FOUND" else "timed_out" if result.get("error_code") == "GHIDRA_TIMEOUT" else "failed"
                result["status"] = result["execution_status"]
                _atomic_json(ghidra_dir / "target_status.json", {"batch_complete": index + 1 == len(targets), "scheduled": len(targets), "analyses": analyses})
        DynamicWorkspace(self.workspace_root, task_id).save_evidence(evidence)
        scheduled = len(targets)
        analyzed = sum(1 for item in analyses if item.get("success"))
        skipped = sum(1 for item in analyses if item.get("execution_status") == "skipped")
        failed = sum(1 for item in analyses if not item.get("success") and item.get("execution_status") != "skipped")
        real_completed = sum(1 for item in analyses if item.get("real_ghidra") and item.get("success"))
        fallback_completed = sum(1 for item in analyses if item.get("fallback_used") and item.get("success"))
        timed_out = sum(1 for item in analyses if item.get("fallback_reason") == "GHIDRA_TIMEOUT" or any("timeout" in str(error).lower() for error in item.get("errors", [])))
        if scheduled == 0:
            stage_status = "skipped"
            partial_reason = None
            blocking_reason = "no static targets"
        elif real_completed == scheduled:
            stage_status = "completed"
            partial_reason = None
            blocking_reason = None
        elif real_completed > 0:
            stage_status = "partial"
            partial_reason = f"{real_completed}/{scheduled} targets completed with real Ghidra; {scheduled - real_completed} targets used fallback or failed"
            blocking_reason = None
        elif fallback_completed > 0:
            stage_status = "partial"
            partial_reason = f"0/{scheduled} targets completed with real Ghidra; {fallback_completed} targets analyzed using static ELF fallback"
            blocking_reason = None
        else:
            stage_status = "blocked"
            partial_reason = None
            blocking_reason = "no target completed with real Ghidra or fallback; see per-target failure reasons"
        fallback_reasons: dict[str, int] = {}
        for item in analyses:
            reason = item.get("fallback_reason")
            if reason:
                fallback_reasons[str(reason)] = fallback_reasons.get(str(reason), 0) + 1
        worker_detail = _first_ghidra_worker_detail(analyses)
        summary = {
            "success": stage_status == "completed",
            "stage_status": stage_status,
            "partial_reason": partial_reason,
            "blocking_reason": blocking_reason,
            "provider_backed": False,
            "targets": targets,
            "analyses": analyses,
            "worker": "dockerized_ghidra_preferred",
            "worker_detail": worker_detail,
            "java_version": worker_detail.get("java_version"),
            "ghidra_version": worker_detail.get("ghidra_version"),
            "analyze_headless": worker_detail.get("analyze_headless"),
            "selected_binary_count": scheduled,
            "scheduled": scheduled,
            "analyzed_binary_count": analyzed,
            "failed_binary_count": failed,
            "real_ghidra_count": real_completed,
            "real_completed": real_completed,
            "fallback_count": fallback_completed,
            "fallback_completed": fallback_completed,
            "timeout_count": timed_out,
            "real_success_rate": round(real_completed / scheduled, 3) if scheduled else 0.0,
            "fallback_reasons": fallback_reasons,
            "output_artifacts": ["ghidra/analysis_summary.json", "dynamic/evidence/evidence.json"],
            "items_processed": scheduled,
            "items_succeeded": real_completed,
            "items_failed": failed,
            "items_skipped": skipped,
            "items_degraded": fallback_completed,
            "batch_complete": True,
            "execution_completed": True,
            "failure_reasons": {str(item["target"].get("path")): item.get("error_code") for item in analyses if not item.get("success")},
        }
        (ghidra_dir / "analysis_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        (ghidra_dir / "evidence.json").write_text(json.dumps([item.to_dict() for item in evidence], indent=2, sort_keys=True) + "\n", encoding="utf-8")
        self._merge_ghidra_into_static_report(task_id, summary)
        return summary

    def _merge_ghidra_into_static_report(self, task_id: str, summary: dict[str, Any]) -> None:
        task_dir = self.workspace_root / task_id
        report = load_analysis_json(task_dir / "reports" / "analysis.json")
        by_path = {item.get("target", {}).get("path"): item for item in summary.get("analyses", [])}
        for binary in report.get("binaries", []) if isinstance(report.get("binaries"), list) else []:
            analysis = by_path.get(binary.get("path"))
            if not analysis:
                continue
            result = analysis.get("result") or {}
            binary["ghidra"] = {
                "success": bool(analysis.get("success")),
                "fallback": bool((result.get("metadata") or {}).get("fallback")),
                "real_ghidra": bool(analysis.get("real_ghidra")),
                "backend_used": analysis.get("backend_used"),
                "fallback_reason": analysis.get("fallback_reason"),
                "function_count": (result.get("summary") or {}).get("function_count", 0),
                "functions": [item.get("name") for item in result.get("functions", []) if item.get("name")],
                "import_count": len(result.get("imports") or []),
                "callgraph_edges": len(result.get("callgraph") or []),
                "evidence_ids": analysis.get("evidence_ids", []),
            }
            imported_dangerous = [item.get("name") for item in result.get("imports", []) if item.get("dangerous")]
            if imported_dangerous:
                binary["dangerous_symbols"] = sorted(set(binary.get("dangerous_symbols", [])) | set(imported_dangerous))
        report["ghidra_analysis"] = {k: v for k, v in summary.items() if k != "analyses"}
        save_analysis_json(report, task_dir / "reports")

    def _finish_dynamic_validation_stage(self, stages: dict[str, PipelineStageResult], timings: dict[str, float], task_id: str, dynamic_executed: bool) -> None:
        path = self.workspace_root / task_id / "dynamic" / "validation"
        validations = list(path.glob("*")) if path.exists() else []
        result = stages["DYNAMIC_VALIDATION"]
        result.start()
        status = "completed" if validations else "partial" if dynamic_executed else "skipped"
        result.finish(
            status,
            output_artifacts=[p.relative_to(self.workspace_root / task_id).as_posix() for p in validations],
            items_processed=len(validations),
            items_succeeded=len(validations),
            blocking_reason=None if validations else "no runtime-feasible validation produced a real runtime observation",
            partial_reason="investigation ran but no concrete validation directory was produced" if dynamic_executed and not validations else None,
            started_monotonic=time.monotonic(),
        )
        timings["dynamic_validation"] = result.duration

    def _write_pipeline_artifacts(self, task_id: str, stages: dict[str, PipelineStageResult], status: str) -> None:
        task_dir = self.workspace_root / task_id
        payload = {
            "schema_version": "firmxplore.pipeline.v0.1",
            "status": status,
            "stages": [stages[stage].to_dict() for stage in V01_PIPELINE_STAGES],
            "coverage": self._coverage_metrics(task_id, stages),
            "validation_gaps": self._validation_gaps(task_id, stages),
            # P2-2：用户主动跳过的阶段单独列出，避免与流水线失败混淆
            "user_skipped_stages": self._user_skipped_stages(task_id),
            "provider_backed": False,
            "real_model_validation": "deferred",
        }
        (task_dir / "pipeline_stages.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def _user_skipped_stages(self, task_id: str) -> list[str]:
        """按 analysis_mode 列出用户主动跳过的阶段（P2-2）。

        static-only / no-dynamic / fast 都是用户选择；这些阶段的 skipped 状态
        是预期行为，不属于流水线缺陷。
        """
        task = self.load_task(task_id)
        mode = getattr(task, "analysis_mode", None) or "normal"
        if mode == "static-only":
            return ["COMPONENT_CORRELATION", "ATTACK_SURFACE", "TAINT_CORRELATION", "HYPOTHESIS_SYNTHESIS", "PRIORITIZATION", "INVESTIGATION", "DYNAMIC_VALIDATION"]
        if mode == "fast":
            return ["STATIC_TARGET_SELECTION", "GHIDRA_ANALYSIS", "COMPONENT_CORRELATION", "ATTACK_SURFACE", "TAINT_CORRELATION", "HYPOTHESIS_SYNTHESIS", "PRIORITIZATION", "INVESTIGATION", "DYNAMIC_VALIDATION"]
        if mode == "no-dynamic":
            return ["INVESTIGATION", "DYNAMIC_VALIDATION"]
        return []

    def _coverage_metrics(self, task_id: str, stages: dict[str, PipelineStageResult]) -> dict[str, Any]:
        task_dir = self.workspace_root / task_id
        report = load_analysis_json(task_dir / "reports" / "analysis.json") if (task_dir / "reports" / "analysis.json").exists() else {}
        ghidra = _load_json_if_exists(task_dir / "ghidra" / "analysis_summary.json")
        graph = _load_json_if_exists(task_dir / "correlation" / "summary.json")
        surface = _load_json_if_exists(task_dir / "surface" / "attack_surface_summary.json")
        surface = surface_counts(
            surface,
            _load_json_if_exists(task_dir / "surface" / "entry_points.json"),
            _load_json_if_exists(task_dir / "surface" / "routes.json"),
        )
        taint = _load_json_if_exists(task_dir / "taint" / "summary.json")
        synthesis = _load_json_if_exists(task_dir / "hypotheses" / "summary.json")
        findings = _load_json_if_exists(task_dir / "findings" / "findings.json")
        rootfs = _load_json_if_exists(task_dir / "artifacts" / "rootfs.json")
        extraction_artifact = _load_json_if_exists(task_dir / "artifacts" / "extraction.json")
        runtime_summary = _load_json_if_exists(task_dir / "dynamic" / "runtime_summary.json")
        dynamic_evidence = _load_json_if_exists(task_dir / "dynamic" / "evidence" / "evidence.json")
        if not isinstance(dynamic_evidence, list):
            dynamic_evidence = []
        filesystem = report.get("filesystem", {}) if isinstance(report.get("filesystem"), dict) else {}
        ghidra_scheduled = ghidra.get("selected_binary_count", 0)
        ghidra_real = ghidra.get("real_ghidra_count", 0)
        ghidra_failed = ghidra.get("failed_binary_count", 0)
        ghidra_fallback = ghidra.get("fallback_count", 0)
        real_ghidra_status = "not_scheduled"
        if ghidra_scheduled and ghidra_real == ghidra_scheduled:
            real_ghidra_status = "completed"
        elif ghidra_scheduled and ghidra_real > 0:
            real_ghidra_status = "partial"
        elif ghidra_scheduled and ghidra_fallback > 0:
            real_ghidra_status = "blocked"
        elif ghidra_scheduled:
            real_ghidra_status = "failed"
        return {
            "canonical_rootfs": rootfs.get("workspace_relative_path") or rootfs.get("path"),
            "extraction_method": rootfs.get("extraction_method") or (report.get("extraction") or {}).get("extractor"),
            "extraction_attempts": extraction_artifact.get("attempts", []),
            "rootfs_source": rootfs.get("source"),
            "rootfs_validated": bool(rootfs.get("validated")),
            "rootfs_validation_reason": rootfs.get("validation_reason"),
            "rootfs_files_artifact": rootfs.get("file_count", 0),
            "rootfs_elf_artifact": rootfs.get("elf_count", 0),
            "stage_extraction": stages["EXTRACTION"].status,
            "stage_rootfs_inventory": stages["ROOTFS_INVENTORY"].status,
            "stage_static_target_selection": stages["STATIC_TARGET_SELECTION"].status,
            "stage_ghidra_analysis": stages["GHIDRA_ANALYSIS"].status,
            "rootfs_files": filesystem.get("total_files", 0),
            "elf_binaries": filesystem.get("elf_files", 0),
            "web_files": filesystem.get("web_files", 0),
            "static_targets": ghidra_scheduled,
            "deep_static_enabled": self.product_config.deep_static_analysis.enabled,
            "ghidra_targets_scheduled": ghidra_scheduled,
            "real_ghidra_completed": ghidra_real,
            "real_ghidra_status": real_ghidra_status,
            "static_elf_fallback_completed": ghidra_fallback,
            "ghidra_timeout": ghidra.get("timeout_count", 0),
            "ghidra_real_success_rate": ghidra.get("real_success_rate", 0.0),
            "ghidra_fallback_reasons": ghidra.get("fallback_reasons", {}),
            "ghidra_fallback_or_failed": ghidra_fallback + ghidra_failed,
            "total_files": filesystem.get("total_files", 0),
            "total_elf": filesystem.get("elf_files", 0),
            "selected_static_targets": ghidra_scheduled,
            "ghidra_analyzed": ghidra.get("analyzed_binary_count", 0),
            "ghidra_failed": ghidra_failed,
            "ghidra_real": ghidra_real,
            "ghidra_fallback": ghidra_fallback,
            "component_count": graph.get("total_components", graph.get("summary", {}).get("total_components", 0)),
            "relationship_count": graph.get("total_relationships", graph.get("summary", {}).get("total_relationships", 0)),
            # Compatibility alias: surface_entries counts candidate objects.
            "surface_entries": surface["candidate_entries_total"],
            **surface,
            "taint_sources": taint.get("sources", 0),
            "sensitive_sinks": taint.get("sinks", 0),
            "candidate_taint_paths": taint.get("candidate_paths", 0),
            "supported_taint_paths": taint.get("supported_paths", 0),
            "hypothesis_candidates": synthesis.get("candidate_count", 0),
            "promoted_hypotheses": synthesis.get("promoted_count", 0),
            "findings": len(findings.get("findings", [])),
            "runtime_validations": stages["DYNAMIC_VALIDATION"].items_processed,
            "dynamic_feasibility": runtime_summary.get("dynamic_feasibility", "not_assessed"),
            "selected_dynamic_service": runtime_summary.get("selected_dynamic_service"),
            "runtime_backend": runtime_summary.get("runtime_backend"),
            "binary_smoke": runtime_summary.get("binary_smoke", "not_attempted"),
            "process_started": bool(runtime_summary.get("process_started")),
            "endpoint_established": bool(runtime_summary.get("endpoint_established")),
            "request_sent": bool(runtime_summary.get("request_sent")),
            "response_observed": bool(runtime_summary.get("response_observed")),
            "runtime_repair_ids": runtime_summary.get("runtime_repair_ids") or [],
            "real_dynamic_evidence": sum(1 for item in dynamic_evidence if is_canonical_runtime_evidence(item)),
            "dynamic_status": runtime_summary.get("dynamic_status", "not_attempted"),
            "runtime_failure_category": runtime_summary.get("failure_category"),
        }

    def _validation_gaps(self, task_id: str, stages: dict[str, PipelineStageResult]) -> list[str]:
        gaps = []
        coverage = self._coverage_metrics(task_id, stages)
        for stage in V01_PIPELINE_STAGES:
            result = stages[stage]
            if result.status in {"failed", "partial", "skipped"} and stage not in {"COMPLETED"}:
                reason = result.blocking_reason or result.partial_reason or "not completed"
                gaps.append(f"{stage}: {result.status} ({reason})")
        if coverage.get("total_elf", 0) > 0 and coverage.get("ghidra_analyzed", 0) == 0 and stages["GHIDRA_ANALYSIS"].status == "completed":
            gaps.append("GHIDRA_ANALYSIS: completed stage produced zero analyzed binaries; deep static analysis is partial")
        if any(attempt.get("error_code") == "DOCKER_PERMISSION_DENIED" for attempt in coverage.get("extraction_attempts", [])):
            gaps.append("Docker extraction execution could not be revalidated in the current environment due to Docker API permission restrictions.")
        if coverage.get("rootfs_source") == "imported" and coverage.get("rootfs_validated"):
            gaps.append("Canonical rootfs handoff, inventory, ELF discovery, and Ghidra scheduling were validated using a previously extracted real firmware rootfs.")
        if coverage.get("ghidra_targets_scheduled", 0) > 0:
            scheduled = int(coverage.get("ghidra_targets_scheduled", 0) or 0)
            real = int(coverage.get("real_ghidra_completed", 0) or 0)
            fallback = int(coverage.get("static_elf_fallback_completed", 0) or 0)
            if real == 0 and fallback > 0:
                gaps.append(f"GHIDRA_ANALYSIS: real Ghidra analyzeHeadless did not complete for any selected target; static ELF fallback was used for {fallback}/{scheduled} targets.")
            elif 0 < real < scheduled:
                gaps.append(f"GHIDRA_ANALYSIS: {real}/{scheduled} real targets completed; {scheduled - real} used fallback or failed.")
        if coverage.get("candidate_taint_paths", 0) and not coverage.get("supported_taint_paths", 0):
            gaps.append("TAINT_CORRELATION: candidate source/sink paths exist but argument-level data-flow support is unresolved")
        return gaps

    def regenerate_report(self, task_id: str, *, report_formats: set[str] | None = None) -> dict[str, Any]:
        findings_path = self.workspace_root / task_id / "findings" / "findings.json"
        findings = json.loads(findings_path.read_text(encoding="utf-8")) if findings_path.exists() else FindingFinalizer(str(self.workspace_root), task_id).finalize(dynamic_executed=False)
        generator = ReportGenerator(self.workspace_root, task_id)
        model = generator.build_model(findings)
        paths = generator.generate_all(model, report_formats)
        manifest = generator.write_artifact_manifest()
        task = self.load_task(task_id)
        if task:
            task.report_paths = paths
            self._save_task(task)
        return {"success": True, "report_generation_status": "completed", "task_id": task_id,
                "task_status": task.status if task else None, "pipeline_phase": task.pipeline_phase if task else None,
                "report_paths": paths, "artifact_manifest": manifest.relative_to(self.workspace_root / task_id).as_posix(), "provider_backed": False}

    def status(self, task_id: str) -> dict[str, Any]:
        task = self.load_task(task_id)
        task_dir = self.workspace_root / task_id
        report = task_dir / "reports" / "report.json"
        findings = []
        if report.exists():
            findings = json.loads(report.read_text(encoding="utf-8")).get("findings") or []
        investigation = {}
        summary_path = task_dir / "investigation" / "summary.json"
        if summary_path.exists():
            investigation = json.loads(summary_path.read_text(encoding="utf-8")).get("state") or {}
        synthetic_task = task or (
            AnalysisTask(task_id, "", "", "", str(task_dir), status="unknown", pipeline_phase="completed")
            if task_dir.exists()
            else None
        )
        return {
            "success": synthetic_task is not None,
            "task": synthetic_task.to_dict() if synthetic_task else None,
            "pipeline_phase": synthetic_task.pipeline_phase if synthetic_task else "missing",
            "investigation_phase": investigation.get("phase", "not_executed"),
            "findings": len(findings),
            "reports": self._report_paths(task_id),
            "resume_available": bool(synthetic_task and synthetic_task.resume_available),
            "blockers": (synthetic_task.error if synthetic_task and synthetic_task.error else None),
            "provider_backed": False,
        }

    def cleanup(self, task_id: str, *, all_artifacts: bool = False) -> dict[str, Any]:
        task_dir = self.workspace_root / task_id
        if not task_dir.exists():
            return {"success": False, "error": "TASK_NOT_FOUND", "provider_backed": False}
        if all_artifacts:
            if self.workspace_root not in task_dir.resolve().parents:
                return {"success": False, "error": "WORKSPACE_BOUNDARY_VIOLATION", "provider_backed": False}
            shutil.rmtree(task_dir)
            return {"success": True, "removed_task": True, "provider_backed": False}
        removed = []
        for relative in ("scratch", "tmp", "dynamic/tmp", "dynamic/runtime_scratch"):
            path = task_dir / relative
            if path.exists():
                shutil.rmtree(path)
                removed.append(relative)
        cleanup_state = {"success": True, "removed": removed, "canonical_preserved": True, "provider_backed": False, "cleaned_at": utc_now_iso()}
        (task_dir / "cleanup.json").write_text(json.dumps(cleanup_state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return cleanup_state

    def load_task(self, task_id: str) -> AnalysisTask | None:
        path = self.workspace_root / task_id / "task.json"
        if not path.exists():
            return None
        task = AnalysisTask(**json.loads(path.read_text(encoding="utf-8")))
        if task.status == "running" and task.pipeline_phase == "static_analysis" and recover_interrupted_scan(path.parent):
            task.status = "paused"
            task.pipeline_phase = "interrupted"
            task.error = self._error("SCAN_OWNER_EXITED", "scan owner exited; explicit resume required", recoverable=True)
            self._save_task(task)
        return task

    def _static_artifacts(self, task_id: str, errors: list[dict[str, Any]], timings: dict[str, float]) -> None:
        builders = [
            ("component_graph", lambda: ComponentGraphBuilder(self.workspace_root, task_id, config=self.config).build()),
            ("attack_surface", lambda: AttackSurfaceBuilder(self.workspace_root, task_id, config=self.config).build()),
            ("taint", lambda: TaintAnalysisBuilder(self.workspace_root, task_id, config=self.config).build()),
            ("synthesis", lambda: HypothesisSynthesizer(self.workspace_root, task_id, config=self.config).build()),
            ("prioritization", lambda: HypothesisValidationScheduler(self.workspace_root, task_id, config=self.config).assess()),
        ]
        for name, func in builders:
            step = time.monotonic()
            try:
                func()
            except Exception as exc:  # noqa: BLE001
                errors.append(self._error(f"{name.upper()}_FAILED", str(exc), recoverable=True))
            finally:
                timings[name] = round(time.monotonic() - step, 3)

    def _save_task(self, task: AnalysisTask) -> None:
        task_dir = self.workspace_root / task.task_id
        task_dir.mkdir(parents=True, exist_ok=True)
        _atomic_json(task_dir / "task.json", task.to_dict())

    def _phase(self, task: AnalysisTask, phase: str, status: str) -> None:
        if phase not in PIPELINE_PHASES:
            raise ValueError(f"invalid pipeline phase: {phase}")
        task.pipeline_phase = phase
        task.status = status
        self._save_task(task)

    def _summary(
        self,
        task: AnalysisTask,
        report: dict[str, Any],
        timings: dict[str, float],
        total_duration: float,
        dynamic_executed: bool,
        errors: list[dict[str, Any]],
        artifact_manifest: Path,
        static_report: dict[str, Any],
        stage_results: dict[str, PipelineStageResult],
    ) -> dict[str, Any]:
        investigation = report.get("investigation") or {}
        coverage = self._coverage_metrics(task.task_id, stage_results)
        validation_gaps = self._validation_gaps(task.task_id, stage_results)
        payload = {
            "success": True,
            "exit_code": EXIT_ANALYSIS_COMPLETED if not errors or report.get("analysis_status") in {"STATIC_ONLY_COMPLETED", "FAST_TRIAGE_COMPLETED"} else EXIT_PARTIAL,
            "task": task.to_dict(),
            "task_id": task.task_id,
            "status": task.status,
            "analysis_status": report.get("analysis_status"),
            "findings": report.get("summary", {}),
            "report_paths": task.report_paths,
            "artifact_manifest": artifact_manifest.relative_to(self.workspace_root / task.task_id).as_posix(),
            "firmware": static_report.get("firmware") or {},
            "platform": static_report.get("platform") or {},
            "duration": {
                "total": total_duration,
                "static": timings.get("static", 0.0),
                "dynamic": timings.get("investigation", 0.0),
                "stages": timings,
            },
            "stage_results": [stage_results[stage].to_dict() for stage in V01_PIPELINE_STAGES],
            "coverage": coverage,
            "validation_gaps": validation_gaps,
            "user_skipped_stages": self._user_skipped_stages(task.task_id),
            "investigation_iterations": investigation.get("iterations", 0),
            "final_stop_reason": investigation.get("stop_reason") or "not_executed",
            "dynamic_executed": dynamic_executed,
            "errors": errors,
            "provider_backed": False,
            "planner": "deterministic",
            "real_model_validation": "deferred",
            "schema_version": REPORT_SCHEMA_VERSION,
        }
        return payload

    def _analysis_status(
        self,
        errors: list[dict[str, Any]],
        *,
        static_only: bool,
        no_dynamic: bool,
        fast: bool,
        stage_results: dict[str, PipelineStageResult],
    ) -> str:
        if fast:
            return "FAST_TRIAGE_COMPLETED"
        if static_only:
            return "STATIC_ONLY_COMPLETED"
        required = ["EXTRACTION", "ROOTFS_INVENTORY", "STATIC_TARGET_SELECTION", "GHIDRA_ANALYSIS", "COMPONENT_CORRELATION", "ATTACK_SURFACE", "TAINT_CORRELATION", "HYPOTHESIS_SYNTHESIS", "PRIORITIZATION", "FINDING_FINALIZATION", "REPORT_GENERATION"]
        if any(stage_results[stage].status in {"failed", "skipped"} for stage in required):
            return "PARTIAL"
        if no_dynamic or errors or stage_results["DYNAMIC_VALIDATION"].status in {"partial", "skipped"}:
            return "COMPLETED_WITH_UNCERTAINTY"
        return "COMPLETED_WITH_UNCERTAINTY"

    def _invalid(self, firmware: str, task_id: str | None, code: str, message: str) -> dict[str, Any]:
        return {
            "success": False,
            "exit_code": EXIT_INVALID_INPUT,
            "error": self._error(code, message, recoverable=False),
            "task_id": task_id,
            "firmware": firmware,
            "provider_backed": False,
        }

    def _error(self, code: str, message: str, *, recoverable: bool) -> dict[str, Any]:
        return {"code": code, "message": message, "recoverable": recoverable}

    def _new_task_id(self, input_hash: str) -> str:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        return f"{stamp}-{input_hash[:8]}"

    def _progress(self, enabled: bool, message: str) -> None:
        if enabled:
            print(message)

    def _copy_reports(self, task_id: str, output_dir: str | Path) -> None:
        target = Path(output_dir)
        target.mkdir(parents=True, exist_ok=True)
        for path in (self.workspace_root / task_id / "reports").glob("report.*"):
            shutil.copy2(path, target / path.name)

    def _report_paths(self, task_id: str) -> dict[str, str]:
        reports_dir = self.workspace_root / task_id / "reports"
        return {path.suffix.lstrip("."): path.relative_to(self.workspace_root / task_id).as_posix() for path in reports_dir.glob("report.*") if path.is_file()}


def _refresh_inventory_worker(workspace, config, round2_config, product_config, task_id, rootfs):
    controller = AnalysisPipelineController(workspace, config=config, round2_config=round2_config, product_config=product_config)
    return controller._refresh_inventory_scan(task_id, rootfs)


def parse_report_formats(value: str | None) -> set[str] | None:
    if not value or value == "all":
        return None
    aliases = {"markdown": "md", "json": "json", "html": "html", "md": "md"}
    formats = {aliases.get(item.strip().lower(), item.strip().lower()) for item in value.split(",") if item.strip()}
    invalid = formats - {"json", "md", "html"}
    if invalid:
        raise ValueError(f"invalid report format(s): {', '.join(sorted(invalid))}")
    return formats


def validate_rootfs_candidate(candidate: str | Path) -> dict[str, Any]:
    return run_bounded_scan("rootfs_validation", _validate_rootfs_candidate, candidate)


def _validate_rootfs_candidate(candidate: str | Path) -> dict[str, Any]:
    path = Path(candidate)
    result: dict[str, Any] = {
        "path": str(path),
        "host_path": None,
        "valid": False,
        "score": 0,
        "markers": [],
        "file_count": 0,
        "elf_count": 0,
        "filesystem_type": None,
        "validation_reason": "",
    }
    if _looks_like_container_only_path(path):
        result["validation_reason"] = "candidate is a container path and was not mapped to a host path"
        return result
    if not safe_exists(path, allow_symlink=True):
        result["validation_reason"] = "path does not exist"
        return result
    if not safe_is_dir(path, allow_symlink=True):
        result["validation_reason"] = "path is not a directory"
        return result
    markers = []
    for marker in ("bin", "etc", "usr", "sbin", "lib", "www", "htdocs"):
        try:
            if safe_is_dir(path / marker):
                markers.append(marker)
        except OSError:
            continue
    file_count = 0
    elf_count = 0
    for current, dirnames, filenames in _safe_walk(path):
        current_path = Path(current)
        for filename in filenames:
            file_path = current_path / filename
            try:
                if file_path.is_symlink():
                    continue
            except OSError:
                continue
            file_count += 1
            if is_elf(file_path):
                elf_count += 1
    score = score_rootfs_candidate(markers=markers, file_count=file_count, elf_count=elf_count)
    result.update(
        {
            "host_path": str(path.resolve()),
            "markers": markers,
            "file_count": file_count,
            "elf_count": elf_count,
            "score": score,
            "filesystem_type": "linux-rootfs" if markers else None,
        }
    )
    if file_count <= 0:
        result["validation_reason"] = "candidate directory is empty"
        return result
    if score < 5 or len(set(markers) & {"bin", "etc", "usr", "sbin", "lib"}) < 2:
        result["validation_reason"] = "candidate lacks enough Linux rootfs markers"
        return result
    result["valid"] = True
    result["validation_reason"] = f"valid Linux rootfs candidate with markers={','.join(markers)} files={file_count} elf={elf_count}"
    return result


def score_rootfs_candidate(*, markers: list[str], file_count: int, elf_count: int) -> int:
    score = 0
    marker_weights = {"etc": 8, "bin": 6, "sbin": 5, "usr": 5, "lib": 4, "www": 2, "htdocs": 2}
    score += sum(marker_weights.get(marker, 0) for marker in set(markers))
    if file_count > 0:
        score += min(20, file_count // 25 + 1)
    if elf_count > 0:
        score += min(20, elf_count * 2)
    return score


def select_canonical_rootfs_candidate(candidates: list[str | Path | None], *, task_dir: Path) -> dict[str, Any] | None:
    return run_bounded_scan("canonical_selection", _select_canonical_rootfs_candidate, candidates, task_dir=task_dir)


def _select_canonical_rootfs_candidate(candidates: list[str | Path | None], *, task_dir: Path) -> dict[str, Any] | None:
    scored = []
    for raw in candidates:
        if not raw:
            continue
        host_path = normalize_extraction_path(raw, task_dir=task_dir)
        validation = validate_rootfs_candidate(host_path)
        if not validation.get("valid"):
            continue
        validation["host_path"] = Path(str(validation["host_path"]))
        scored.append(validation)
    if not scored:
        return None
    scored.sort(key=lambda item: (-int(item.get("score", 0)), -int(item.get("elf_count", 0)), -int(item.get("file_count", 0)), len(Path(str(item["host_path"])).parts)))
    return scored[0]


def normalize_extraction_path(value: str | Path, *, task_dir: Path) -> Path:
    raw = str(value)
    candidate = Path(raw)
    try:
        if safe_exists(candidate, allow_symlink=True):
            return candidate.resolve()
    except OSError:
        return candidate
    normalized = raw.replace("\\", "/")
    task_dir = task_dir.resolve()
    task_id = task_dir.name
    for prefix in (f"/repo/workspace/{task_id}/", f"/workspace/{task_id}/", f"/work/{task_id}/", f"/output/{task_id}/"):
        if normalized.startswith(prefix):
            return task_dir / PurePosixPath(normalized[len(prefix) :])
    if normalized.startswith("/output/"):
        return task_dir / "docker-extract" / PurePosixPath(normalized[len("/output/") :])
    marker = f"/{task_id}/"
    if marker in normalized:
        return task_dir / PurePosixPath(normalized.split(marker, 1)[1])
    return candidate


def _safe_walk(root: Path):
    import os

    for current, dirnames, filenames in os.walk(root, followlinks=False, onerror=_raise_walk_error):
        current_path = Path(current)
        kept = []
        for dirname in dirnames:
            path = current_path / dirname
            if is_scan_directory(path):
                kept.append(dirname)
        dirnames[:] = kept
        kept_files = []
        for filename in filenames:
            path = current_path / filename
            if is_regular_file(path):
                kept_files.append(filename)
        yield current, dirnames, kept_files


def _looks_like_container_only_path(path: Path) -> bool:
    text = path.as_posix()
    return text.startswith(("/repo/", "/workspace/", "/work/", "/output/")) and not safe_exists(path, allow_symlink=True)


def _embedded_firmware_candidates(task_dir: Path, original_source: Path) -> list[Path]:
    return run_bounded_scan("embedded_candidates", _scan_embedded_firmware_candidates, task_dir, original_source)


def _scan_embedded_firmware_candidates(task_dir: Path, original_source: Path) -> list[Path]:
    extensions = {".bin", ".trx", ".img", ".chk", ".fw", ".upgrade"}
    candidates: list[Path] = []
    search_roots = [task_dir / "extracted", task_dir / "prepared_input"]
    original = original_source.resolve()
    for root in search_roots:
        if not safe_exists(root, allow_symlink=True):
            continue
        for path in root.rglob("*"):
            try:
                if not is_regular_file(path) or path.suffix.lower() not in extensions:
                    continue
                resolved = path.resolve()
                if resolved == original or resolved.stat().st_size < 1024 * 1024:
                    continue
            except OSError:
                continue
            candidates.append(resolved)
    return candidates[:5]


def _host_to_container_path(host_path: Path, task_dir: Path) -> str | None:
    try:
        rel = host_path.resolve().relative_to(task_dir.resolve()).as_posix()
        return f"/repo/workspace/{task_dir.name}/{rel}"
    except ValueError:
        return None


def _classify_docker_error(message: str) -> str:
    lowered = message.lower()
    if "permission denied" in lowered or "access is denied" in lowered or "docker_engine" in lowered and "denied" in lowered:
        return "DOCKER_PERMISSION_DENIED"
    if "not found" in lowered and "docker" in lowered:
        return "DOCKER_CLI_NOT_FOUND"
    return "DOCKER_EXTRACTION_FAILED"


def _load_product_config(path: str | Path | None = None) -> ProductPipelineSettings:
    from fwagent.config import _parse_simple_yaml

    config_path = Path(path) if path else Path("config") / "dynamic.yaml"
    data = _parse_simple_yaml(config_path) if config_path.exists() else {}
    product = data.get("product", {})
    deep_static = product.get("deep_static_analysis", {})
    advanced = product.get("advanced_pipeline", {})
    return ProductPipelineSettings(
        deep_static_analysis=ProductDeepStaticSettings(
            enabled=bool(deep_static.get("enabled", True)),
            top_n=int(deep_static.get("top_n", 10)),
            max_targets=int(deep_static.get("max_targets", 20)),
            dependency_expansion=bool(deep_static.get("dependency_expansion", True)),
        ),
        advanced_pipeline=ProductAdvancedPipelineSettings(
            correlation=bool(advanced.get("correlation", True)),
            surface=bool(advanced.get("surface", True)),
            taint=bool(advanced.get("taint", True)),
            synthesis=bool(advanced.get("synthesis", True)),
            prioritization=bool(advanced.get("prioritization", True)),
            investigation=bool(advanced.get("investigation", True)),
        ),
    )


def _stage_timing_key(stage: str) -> str:
    return stage.lower()


def _artifact_outputs(value: Any) -> list[str]:
    if isinstance(value, tuple) and value and isinstance(value[0], dict):
        value = value[0]
    if isinstance(value, tuple):
        return [str(item) for item in value if isinstance(item, (str, Path))]
    if isinstance(value, dict):
        outputs = value.get("output_artifacts")
        if isinstance(outputs, list):
            return [str(item) for item in outputs]
        if value.get("report_path"):
            return [str(value["report_path"])]
    return []


def _items_processed(value: Any) -> int:
    if isinstance(value, tuple) and value and isinstance(value[0], dict):
        value = value[0]
    if isinstance(value, list):
        return len(value)
    if not isinstance(value, dict):
        return 0
    if "items_processed" in value:
        return int(value.get("items_processed") or 0)
    if "entry_points" in value or "total_entries" in value or "candidate_entries_total" in value:
        return surface_counts(value.get("summary", value), value.get("entry_points"))["candidate_entries_total"] or 0
    if isinstance(value.get("summary"), dict) and any(key in value["summary"] for key in ("total_entries", "candidate_entries_total", "entry_points")):
        return surface_counts(value["summary"])["candidate_entries_total"] or 0
    for key in ("analyzed_binary_count", "selected_binary_count", "selected_static_targets", "files_extracted", "total_components", "component_count", "total_relationships", "relationship_count"):
        if key in value:
            return int(value.get(key) or 0)
    summary = value.get("summary") if isinstance(value.get("summary"), dict) else {}
    for key in ("total_components", "component_count", "total_relationships", "relationship_count"):
        if key in summary:
            return int(summary.get(key) or 0)
    if "targets" in value and isinstance(value["targets"], list):
        return len(value["targets"])
    return 0


def _load_json_if_exists(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def _select_lightweight_static_binary_paths(elf_files: list[str], services: list[dict[str, Any]], web: dict[str, Any]) -> list[str]:
    selected: list[str] = []
    seen: set[str] = set()
    service_paths = {str(service.get("binary")) for service in services if service.get("binary")}
    web_paths = {str(path) for path in web.get("candidate_backend_binaries", [])}
    interesting_names = {
        "httpd",
        "lighttpd",
        "nginx",
        "boa",
        "uhttpd",
        "telnetd",
        "dropbear",
        "sshd",
        "dnsmasq",
        "upnp",
        "miniupnpd",
        "ftpd",
        "tftpd",
        "snmpd",
        "proftpd",
    }
    for rel in elf_files:
        name = Path(rel).name.lower()
        if rel in service_paths or rel in web_paths or name in interesting_names or name.endswith(".fcgi") or "cgi" in name:
            selected.append(rel)
            seen.add(rel)
    for rel in elf_files:
        if len(selected) >= 80:
            break
        if rel in seen:
            continue
        parts = Path(rel).parts
        if parts and parts[0] in {"/bin", "/sbin", "/usr"} or rel.startswith(("/bin/", "/sbin/", "/usr/sbin/", "/usr/bin/")):
            selected.append(rel)
            seen.add(rel)
    return selected


def _dependency_expansion(
    selected: list[dict[str, Any]],
    binaries: list[dict[str, Any]],
    elf_files: list[str],
    seen: set[str],
    *,
    max_targets: int,
) -> list[dict[str, Any]]:
    by_path = {str(item.get("path")): item for item in binaries if item.get("path")}
    elf_by_name: dict[str, list[str]] = {}
    for rel in elf_files:
        elf_by_name.setdefault(Path(rel).name, []).append(rel)
    expanded: list[dict[str, Any]] = []
    for target in selected:
        binary = by_path.get(target["path"]) or {}
        for library in binary.get("linked_libraries", [])[:12]:
            candidates = elf_by_name.get(str(library), [])
            for rel in candidates:
                if rel in seen:
                    continue
                expanded.append({"path": rel, "reason": f"dependency:{target['path']}", "score": max(1, int(target.get("score", 0)) - 5)})
                seen.add(rel)
                if len(selected) + len(expanded) >= max_targets:
                    return expanded
    return expanded


def _ghidra_evidence_for_result(result: dict[str, Any]) -> list[DynamicEvidence]:
    if not result.get("success"):
        return []
    target = result.get("target") or {}
    rel = str(target.get("path") or Path(str(result.get("binary", "binary"))).name)
    payload = result.get("result") or {}
    metadata = payload.get("metadata") or {}
    real_ghidra = bool(metadata.get("real_ghidra")) and not bool(metadata.get("fallback"))
    evidence_execution_mode = "real" if real_ghidra else "static_elf_fallback"
    evidence_provenance = "real_ghidra" if real_ghidra else "static_elf_fallback"
    imports = payload.get("imports") or []
    evidences: list[DynamicEvidence] = []
    safe_slug = "".join(ch if ch.isalnum() else "-" for ch in rel.strip("/"))[:48].strip("-") or "binary"
    evidences.append(
        DynamicEvidence(
            id=f"SE-GHIDRA-{safe_slug}-SUMMARY",
            type="log_observation",
            observation=f"Deep static analysis produced function/import/callgraph summary for {rel}",
            source_tool="ghidra.analyze_binary",
            confidence=0.72,
            target=rel,
            metadata={
                "binary": rel,
                "tool": "ghidra",
                "execution_mode": evidence_execution_mode,
                "provenance": evidence_provenance,
                "fallback": bool(metadata.get("fallback")),
                "backend_used": metadata.get("backend_used"),
                "fallback_reason": metadata.get("fallback_reason"),
                "function_count": (payload.get("summary") or {}).get("function_count", 0),
                "import_count": len(imports),
                "callgraph_edges": len(payload.get("callgraph") or []),
            },
            provenance=evidence_provenance,
            execution_mode=evidence_execution_mode,
            provider_backed=False,
            runtime_observation_real=False,
        )
    )
    for item in imports:
        if not item.get("dangerous"):
            continue
        symbol = str(item.get("name"))
        evidences.append(
            DynamicEvidence(
                id=f"SE-GHIDRA-{safe_slug}-{symbol}",
                type="sensitive_sink_discovered",
                observation=f"Ghidra/static analysis identified sensitive import {symbol} in {rel}",
                source_tool="ghidra.analyze_binary",
                confidence=0.68,
                target=rel,
                metadata={
                    "binary": rel,
                    "symbol": symbol,
                    "source": "imports",
                    "tool": "ghidra",
                    "execution_mode": evidence_execution_mode,
                    "provenance": evidence_provenance,
                    "backend_used": metadata.get("backend_used"),
                    "fallback": bool(metadata.get("fallback")),
                    "fallback_reason": metadata.get("fallback_reason"),
                },
                provenance=evidence_provenance,
                execution_mode=evidence_execution_mode,
                provider_backed=False,
                runtime_observation_real=False,
            )
        )
    return evidences


def _ghidra_backend_details(result: dict[str, Any]) -> dict[str, Any]:
    payload = result.get("result") if isinstance(result.get("result"), dict) else {}
    metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
    fallback_used = bool(metadata.get("fallback") or metadata.get("fallback_used"))
    real_ghidra = bool(metadata.get("real_ghidra")) and not fallback_used and bool(result.get("success"))
    fallback_reason = metadata.get("fallback_reason") or metadata.get("error_code") or result.get("error_code")
    errors = result.get("errors") or []
    if fallback_used and not fallback_reason:
        fallback_reason = "UNKNOWN_GHIDRA_FAILURE"
    if not result.get("success") and not fallback_reason:
        fallback_reason = _ghidra_failure_reason(errors)
    return {
        "requested_backend": metadata.get("requested_backend") or "ghidra",
        "backend_used": metadata.get("backend_used") or ("static_elf_fallback" if fallback_used else "ghidra" if real_ghidra else "none"),
        "real_ghidra": real_ghidra,
        "fallback_used": fallback_used,
        "fallback_reason": fallback_reason,
        "ghidra_error": "; ".join(str(error) for error in errors[:3]) if errors else None,
        "ghidra_exit_code": metadata.get("ghidra_exit_code"),
        "status": "real_ghidra_completed" if real_ghidra else "fallback" if fallback_used and result.get("success") else "failed",
        "evidence_ids": [],
    }


def _first_ghidra_worker_detail(analyses: list[dict[str, Any]]) -> dict[str, Any]:
    for analysis in analyses:
        metadata = (analysis.get("result") or {}).get("metadata") or {}
        worker = metadata.get("worker")
        if isinstance(worker, dict) and worker:
            return dict(worker)
    return {}


def _ghidra_failure_reason(errors: list[Any]) -> str:
    text = "\n".join(str(item) for item in errors).lower()
    if "timeout" in text:
        return "GHIDRA_TIMEOUT"
    if "analyzeheadless" in text and ("not found" in text or "no such file" in text):
        return "GHIDRA_ANALYZE_HEADLESS_NOT_FOUND"
    if "permission denied" in text or "access is denied" in text or "docker_engine" in text:
        return "GHIDRA_CONTAINER_DOCKER_PERMISSION_DENIED"
    if "missing export" in text:
        return "GHIDRA_OUTPUT_MISSING"
    if "import" in text and "failed" in text:
        return "GHIDRA_IMPORT_FAILED"
    if "script" in text:
        return "GHIDRA_SCRIPT_FAILED"
    return "UNKNOWN_GHIDRA_FAILURE"


def _atomic_json(path: Path, payload: Any) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)
