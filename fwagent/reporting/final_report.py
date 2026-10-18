from __future__ import annotations

import hashlib
import html
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fwagent import __version__
from fwagent.dynamic.models import is_canonical_runtime_evidence
from fwagent.dynamic.surface_contract import surface_summary, COUNT_FIELDS
from fwagent.findings import FindingClaimGuard, FINDING_STATUSES


REPORT_SCHEMA_VERSION = "firmxplore.report.v1"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass
class ArtifactIndexItem:
    type: str
    path: str
    description: str
    exists: bool
    size: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AnalysisReport:
    metadata: dict[str, Any]
    firmware_summary: dict[str, Any]
    investigation_summary: dict[str, Any]
    attack_surface_summary: dict[str, Any]
    component_summary: dict[str, Any]
    findings: list[dict[str, Any]]
    rejected_hypotheses: list[dict[str, Any]]
    inconclusive_hypotheses: list[dict[str, Any]]
    blocked_items: list[dict[str, Any]]
    runtime_repairs: list[dict[str, Any]]
    evidence_summary: dict[str, Any]
    timeline: list[dict[str, Any]]
    remaining_problems: list[str]
    provider_status: dict[str, Any]
    artifact_index: list[dict[str, Any]]
    pipeline_stages: list[dict[str, Any]] = field(default_factory=list)
    coverage: dict[str, Any] = field(default_factory=dict)
    validation_gaps: list[str] = field(default_factory=list)
    taint_summary: dict[str, Any] = field(default_factory=dict)
    priority_summary: dict[str, Any] = field(default_factory=dict)
    validation: dict[str, Any] = field(default_factory=dict)
    components: list[dict[str, Any]] = field(default_factory=list)
    attack_surface: list[dict[str, Any]] = field(default_factory=list)
    hypotheses: list[dict[str, Any]] = field(default_factory=list)
    model_investigation: dict[str, Any] = field(default_factory=dict)
    model_hypotheses: list[dict[str, Any]] = field(default_factory=list)
    model_evidence: list[dict[str, Any]] = field(default_factory=list)
    user_skipped_stages: list[str] = field(default_factory=list)
    taint_quality: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": REPORT_SCHEMA_VERSION,
            "task_id": self.metadata.get("task_id"),
            "firmware": self.firmware_summary,
            "analysis_status": self.metadata.get("analysis_status"),
            "summary": {
                "findings": len(self.findings),
                "supported": sum(1 for item in self.findings if item.get("status") == "supported"),
                "runtime_supported": sum(1 for item in self.findings if item.get("status") == "runtime_supported"),
                "candidate_or_inconclusive": sum(1 for item in self.findings if item.get("status") in {"candidate", "inconclusive", "informational"}),
                "blocked": sum(1 for item in self.findings if item.get("status") == "blocked"),
                "remaining_problems": self.remaining_problems,
            },
            "components": self.components,
            "attack_surface": {
                "summary": self.attack_surface_summary,
                "entries": self.attack_surface,
            },
            "findings": self.findings,
            "hypotheses": self.hypotheses,
            "validation": self.validation,
            "model_investigation": self.model_investigation,
            "model_hypotheses": self.model_hypotheses,
            "model_evidence": self.model_evidence,
            "user_skipped_stages": self.user_skipped_stages,
            "taint_quality": self.taint_quality,
            "pipeline_stages": self.pipeline_stages,
            "coverage": self.coverage,
            "validation_gaps": self.validation_gaps,
            "taint": self.taint_summary,
            "prioritization": self.priority_summary,
            "evidence_statistics": self.evidence_summary,
            "investigation": self.investigation_summary,
            "runtime_repairs": self.runtime_repairs,
            "remaining_problems": self.remaining_problems,
            "provider_metadata": self.provider_status,
            "artifacts": self.artifact_index,
            "metadata": self.metadata,
            "rejected_hypotheses": self.rejected_hypotheses,
            "inconclusive_hypotheses": self.inconclusive_hypotheses,
            "blocked_items": self.blocked_items,
            "timeline": self.timeline,
        }


class ReportValidator:
    def __init__(self) -> None:
        self.guard = FindingClaimGuard()

    def validate(self, report: AnalysisReport) -> dict[str, Any]:
        errors: list[str] = []
        evidence_ids = set(report.evidence_summary.get("ids") or [])
        artifact_paths = {item.get("path") for item in report.artifact_index}
        for finding in report.findings:
            if not finding.get("title"):
                errors.append(f"{finding.get('finding_id')}: title empty")
            if finding.get("status") not in FINDING_STATUSES:
                errors.append(f"{finding.get('finding_id')}: invalid status")
            for evidence_id in list(finding.get("dynamic_evidence_ids") or []) + list(finding.get("static_evidence_ids") or []):
                if evidence_id.startswith("MDE-"):
                    errors.append(f"{finding.get('finding_id')}: mock evidence referenced")
                if evidence_id.startswith("DE-") and evidence_id not in evidence_ids:
                    errors.append(f"{finding.get('finding_id')}: missing evidence reference {evidence_id}")
            ok, reason = self.guard.validate(json.dumps(finding, sort_keys=True))
            if not ok:
                errors.append(f"{finding.get('finding_id')}: {reason}")
        for item in report.artifact_index:
            if item.get("exists") and item.get("path") not in artifact_paths:
                errors.append(f"artifact index inconsistent: {item.get('path')}")
            if Path(str(item.get("path"))).is_absolute():
                errors.append(f"artifact path should be workspace-relative: {item.get('path')}")
        return {"success": not errors, "errors": errors, "checked_at": utc_now_iso()}


class ReportGenerator:
    def __init__(self, workspace_root: str | Path, task_id: str):
        self.workspace_root = Path(workspace_root).resolve()
        self.task_id = task_id
        self.task_dir = self.workspace_root / task_id
        self.reports_dir = self.task_dir / "reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def build_model(self, findings_payload: dict[str, Any] | None = None, *, analysis_status: str = "COMPLETED_WITH_UNCERTAINTY") -> AnalysisReport:
        analysis = self._load("reports/analysis.json")
        investigation = self._load("investigation/summary.json")
        surface = self._load("surface/attack_surface_summary.json")
        raw_entries = self._load("surface/entry_points.json")
        entries = raw_entries if isinstance(raw_entries, list) else []
        surface = surface_summary(surface, raw_entries, self._load("surface/routes.json"))
        graph = self._load("correlation/summary.json")
        graph_full = self._load("correlation/component_graph.json")
        pipeline = self._load("pipeline_stages.json")
        coverage = dict(pipeline.get("coverage") or {}) if isinstance(pipeline, dict) else {}
        coverage.update({key: surface[key] for key in COUNT_FIELDS})
        coverage["surface_entries"] = surface["candidate_entries_total"]
        coverage["surface_count_status"] = surface["count_status"]
        stages = [dict(item) for item in pipeline.get("stages", [])] if isinstance(pipeline, dict) else []
        for stage in stages:
            if stage.get("stage") != "ATTACK_SURFACE":
                continue
            if stage.get("status") in {"pending", "skipped", "blocked"}:
                stage["items_processed"] = None
                stage["item_count_status"] = "not_executed"
            elif "item_count_status" not in stage or stage["item_count_status"] is None:
                stage["original_items_processed"] = stage.get("items_processed")
                stage["items_processed"] = surface["candidate_entries_total"]
                stage["item_count_status"] = surface["count_status"]
                stage["item_count_source"] = "surface candidate count adapter; not a new execution"
        taint = self._load("taint/summary.json")
        priority = self._load("prioritization/scheduler_state.json") or {"assessments": self._load("prioritization/assessment.json") or []}
        hypotheses = self._load("dynamic/hypotheses.json") or []
        evidence = self._load("dynamic/evidence/evidence.json") or []
        runtime_summary = self._load("dynamic/runtime_summary.json") or {}
        # 动态可行性兜底（P2-2）：动态阶段未运行时读取静态可行性评估，
        # 把笼统的 "not_assessed" 替换为具体原因。
        if not runtime_summary.get("dynamic_feasibility"):
            feasibility = self._load("dynamic/feasibility.json") or {}
            if feasibility:
                runtime_summary["dynamic_feasibility"] = str(feasibility.get("assessment") or "not_assessed")
                if feasibility.get("reasons"):
                    runtime_summary["dynamic_feasibility_reasons"] = feasibility["reasons"]
                runtime_summary["dynamic_feasibility_method"] = feasibility.get("method", "static_heuristic")
        # 模型调查成果（P3）：PiAgent 的输出（provider-backed、非 canonical），
        # 让用户从报告中直接看到模型做了什么、消耗了多少步。
        model_investigation = self._load("reports/investigation.json") or {}
        findings_payload = findings_payload or self._load("findings/findings.json") or {"findings": []}
        findings = findings_payload.get("findings") or []
        evidence_ids = [item.get("id") for item in evidence if item.get("id")]
        metadata = {
            "schema_version": REPORT_SCHEMA_VERSION,
            "firmxplore_version": __version__,
            "task_id": self.task_id,
            "generated_at": utc_now_iso(),
            "analysis_status": analysis_status,
            "host_mode": "Windows + Docker",
            "static_worker_image": "firmxplore:latest",
            "dynamic_worker_image": "firmxplore:latest",
            "provider_backed": False,
            "planner": "deterministic",
            "real_model_validation": "deferred",
        }
        rejected = [item for item in hypotheses if item.get("status") in {"rejected", "dynamically_rejected"} or item.get("dynamic_status") == "dynamically_rejected"]
        inconclusive = [item for item in hypotheses if item.get("status") == "validation_inconclusive" or item.get("dynamic_status") == "validation_inconclusive"]
        blocked = [item for item in hypotheses if item.get("status") == "validation_blocked" or item.get("dynamic_status") == "validation_blocked"]
        return AnalysisReport(
            metadata=metadata,
            firmware_summary=analysis.get("firmware") or {},
            investigation_summary=investigation.get("summary") or {},
            attack_surface_summary=surface or {},
            component_summary=graph or {},
            findings=findings,
            rejected_hypotheses=rejected,
            inconclusive_hypotheses=inconclusive,
            blocked_items=blocked,
            runtime_repairs=self._runtime_repairs(),
            evidence_summary={
                "total": len(evidence),
                "dynamic": len([item for item in evidence if str(item.get("id", "")).startswith("DE-")]),
                "real_dynamic": sum(1 for item in evidence if is_canonical_runtime_evidence(item)),
                "attempt_or_status": sum(1 for item in evidence if str(item.get("id", "")).startswith("DE-") and not is_canonical_runtime_evidence(item)),
                "ids": evidence_ids,
            },
            timeline=self._timeline(),
            remaining_problems=self._remaining_problems(findings, blocked),
            provider_status={"provider_backed": False, "planner": "deterministic", "real_model_validation": "deferred"},
            artifact_index=[item.to_dict() for item in self._artifact_index()],
            pipeline_stages=stages,
            coverage=coverage,
            validation_gaps=(pipeline.get("validation_gaps") if isinstance(pipeline, dict) else []) or [],
            taint_summary=taint if isinstance(taint, dict) else {},
            priority_summary=priority if isinstance(priority, dict) else {},
            validation={"investigation": investigation.get("summary") or {}, "runtime": runtime_summary, "provider_backed": False},
            components=(graph_full.get("components") if isinstance(graph_full, dict) else []) or [],
            attack_surface=entries,
            hypotheses=hypotheses,
            model_investigation=self._model_investigation_summary(model_investigation),
            model_hypotheses=self._model_hypotheses(model_investigation),
            model_evidence=self._model_evidence(model_investigation),
            user_skipped_stages=self._user_skipped_stages(),
            taint_quality=self._taint_quality(taint),
        )

    def _model_investigation_summary(self, trace: dict[str, Any]) -> dict[str, Any]:
        """把 PiAgent 输出压缩为报告的 model_investigation 段落（P3）。

        provider-backed 结果在确定性 Round-5 中仍是非 canonical 的，
        这里只做透明呈现：模型跑了多少步、产出了什么、停在哪里。
        """
        if not trace or trace.get("steps") is None:
            return {}
        model_info = trace.get("model") or {}
        summary_obj = {
            "provider": model_info.get("provider"),
            "model": model_info.get("model"),
            "steps": trace.get("steps"),
            "tool_calls": trace.get("tool_calls"),
            "stop_reason": trace.get("stop_reason"),
            "model_error": trace.get("model_error"),
            "degraded_reason": trace.get("model_error") if trace.get("degraded") else None,
            "last_error": (trace.get("model_errors") or [None])[-1] if trace.get("model_errors") else trace.get("model_error"),
            "total_tokens": self._model_usage_total(),
            "degraded": bool(trace.get("degraded")),
            "evidence_produced": len(trace.get("evidence") or []),
            "hypotheses_produced": len(trace.get("hypotheses") or []),
            "canonical": False,
            "note": "model-assisted results are non-canonical in deterministic Round 5; see reports/investigation.json for the full trace",
        }
        return summary_obj

    def _model_usage_total(self) -> int:
        """聚合 web_model_usage.jsonl 的总 token 消耗（P1-1(b)）。"""
        usage_path = self.task_dir / "web_model_usage.jsonl"
        if not usage_path.exists():
            return 0
        total = 0
        try:
            for line in usage_path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                total += int(record.get("total_tokens") or 0)
        except OSError:
            return 0
        return total

    def _model_hypotheses(self, trace: dict[str, Any]) -> list[dict[str, Any]]:
        """PiAgent 的假设清单（P1-1）。明确 canonical=False，不进入 findings。"""
        out = []
        for item in trace.get("hypotheses") or []:
            if not isinstance(item, dict):
                continue
            out.append({
                "id": item.get("id"),
                "title": item.get("title"),
                # PiAgent 的 Hypothesis 没有独立 rationale 字段，用 claim 语义的
                # title + missing_evidence 承载推理说明（适配说明见实现注释）
                "rationale": item.get("title"),
                "status": item.get("status"),
                "confidence": item.get("confidence"),
                "evidence_ids": item.get("evidence_ids") or [],
                "missing_evidence": item.get("missing_evidence") or [],
                "canonical": False,
            })
        return out

    def _model_evidence(self, trace: dict[str, Any]) -> list[dict[str, Any]]:
        """PiAgent 的证据清单（P1-1）：id / type / description / source。"""
        out = []
        for item in trace.get("evidence") or []:
            if not isinstance(item, dict):
                continue
            out.append({
                "id": item.get("id"),
                "type": item.get("type"),
                "description": item.get("description"),
                "source": item.get("source_tool"),
                "binary": item.get("binary"),
                "confidence": item.get("confidence"),
            })
        return out

    def _taint_quality(self, taint: dict[str, Any]) -> dict[str, Any]:
        """污点路径质量段落（P1-2）：区分合成路径与真实数据流。"""
        if not isinstance(taint, dict) or not taint:
            return {}
        return {
            "source_count": taint.get("sources", 0),
            "sink_count": taint.get("sinks", 0),
            "candidate_path_count": taint.get("candidate_paths", 0),
            "argument_mapped_path_count": taint.get("argument_mapped_paths", 0),
            "decompile_backed_path_count": taint.get("decompile_backed_paths", 0),
            "callgraph_synthetic_path_count": taint.get("callgraph_synthetic_paths", 0),
            "quality_note": (
                "callgraph_synthetic paths are reachability chains from Ghidra call graphs; "
                "argument-level data flow is NOT established unless argument_mapped_path_count > 0"
            ),
        }

    def _user_skipped_stages(self) -> list[str]:
        """P2-2：按 task.json 的 analysis_mode 列出用户主动跳过的阶段。

        直接从 task.json 派生而不是读 pipeline_stages.json——
        regenerate_report 不重写后者，读它会拿到过期数据。
        """
        mode = ""
        try:
            state = json.loads((self.task_dir / "task.json").read_text(encoding="utf-8"))
            mode = str(state.get("analysis_mode") or "normal")
        except (OSError, json.JSONDecodeError):
            return []
        if mode == "static-only":
            return ["COMPONENT_CORRELATION", "ATTACK_SURFACE", "TAINT_CORRELATION", "HYPOTHESIS_SYNTHESIS", "PRIORITIZATION", "INVESTIGATION", "DYNAMIC_VALIDATION"]
        if mode == "fast":
            return ["STATIC_TARGET_SELECTION", "GHIDRA_ANALYSIS", "COMPONENT_CORRELATION", "ATTACK_SURFACE", "TAINT_CORRELATION", "HYPOTHESIS_SYNTHESIS", "PRIORITIZATION", "INVESTIGATION", "DYNAMIC_VALIDATION"]
        if mode == "no-dynamic":
            return ["INVESTIGATION", "DYNAMIC_VALIDATION"]
        return []

    def generate_json(self, model: AnalysisReport) -> Path:
        path = self.reports_dir / "report.json"
        path.write_text(json.dumps(model.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return path

    def _stage_markdown(self, stages: list[dict[str, Any]]) -> list[str]:
        if not stages:
            return ["| not_recorded | skipped | 0 | 0 | 0 | 0 | 0 |"]
        rows = []
        for stage in stages:
            rows.append(
                "| {stage} | {status} | {processed} | {succeeded} | {failed} | {skipped} | {duration} |".format(
                    stage=stage.get("stage") or "unknown",
                    status=stage.get("status") or "unknown",
                    processed=self._processed_display(stage),
                    succeeded=stage.get("items_succeeded", 0),
                    failed=stage.get("items_failed", 0),
                    skipped=stage.get("items_skipped", 0),
                    duration=stage.get("duration", 0),
                )
            )
        return rows

    @staticmethod
    def _processed_display(stage: dict[str, Any]) -> Any:
        if stage.get("item_count_status") == "not_executed":
            return "not executed"
        value = stage.get("items_processed")
        return "unknown" if value is None else value

    @staticmethod
    def _surface_metrics(model: AnalysisReport) -> list[tuple[str, Any]]:
        summary = model.attack_surface_summary
        return [(label, summary.get(key)) for label, key in (
            ("Candidate entries", "candidate_entries_total"),
            ("Runtime confirmed entries", "runtime_confirmed_entries"),
            ("File/symlink candidates", "file_or_symlink_candidates"),
            ("API inferred candidates", "api_inferred_candidates"),
            ("Heuristic candidates", "heuristic_candidates"),
            ("Unknown evidence candidates", "unknown_evidence_candidates"),
            ("Route mappings", "route_mappings_total"),
            ("Static http_route candidates", "http_route_candidates"),
        )]

    def _surface_markdown(self, model: AnalysisReport) -> list[str]:
        return [f"- {label}: `{value if value is not None else 'unknown'}`" for label, value in self._surface_metrics(model)] + [
            "- Static candidates do not establish reachable services or verified URLs. Confidence is a rule score, not a probability.",
            "", "| Candidate ID | Evidence level | Runtime confirmed | Rootfs file | URL |",
            "| --- | --- | --- | --- | --- |",
            *["| " + " | ".join(str(value).replace("|", "\\|").replace("\n", " ") for value in (
                item.get("entry_id", "unknown"), item.get("evidence_level", "unknown"),
                item.get("runtime_confirmed", "unknown"), item.get("filesystem_path") or "unknown",
                item.get("url_path") or "unconfirmed",
            )) + " |" for item in model.attack_surface],
        ]

    def generate_markdown(self, model: AnalysisReport) -> Path:
        path = self.reports_dir / "report.md"
        stage_rows = self._stage_markdown(model.pipeline_stages)
        coverage = model.coverage or {}
        lines = [
            "# FirmXplore Firmware Security Analysis Report",
            "",
            "## 1. Executive Summary",
            "",
            f"Task: `{model.metadata.get('task_id')}`",
            f"Status: `{model.metadata.get('analysis_status')}`",
            f"Findings: `{len(model.findings)}`",
            "Provider: deterministic (`provider_backed=false`, real model validation deferred)",
            "",
            "## 2. Analysis Coverage",
            "",
            f"- Canonical rootfs: `{coverage.get('canonical_rootfs') or 'not established'}`",
            f"- Rootfs source: `{coverage.get('rootfs_source') or 'not established'}`",
            f"- Rootfs validated: `{coverage.get('rootfs_validated', False)}`",
            f"- Extraction stage: `{coverage.get('stage_extraction') or 'not recorded'}`",
            f"- Inventory stage: `{coverage.get('stage_rootfs_inventory') or 'not recorded'}`",
            f"- Static target stage: `{coverage.get('stage_static_target_selection') or 'not recorded'}`",
            f"- Ghidra stage: `{coverage.get('stage_ghidra_analysis') or 'not recorded'}`",
            f"- Real Ghidra analysis: `{coverage.get('real_ghidra_status') or 'not recorded'}`",
            f"- Static ELF fallback analysis: `{coverage.get('static_elf_fallback_completed', 0)}`",
            f"- Rootfs files: `{coverage.get('rootfs_files', 0)}`",
            f"- ELF binaries: `{coverage.get('elf_binaries', 0)}`",
            f"- Web files: `{coverage.get('web_files', 0)}`",
            f"- Ghidra scheduled: `{coverage.get('ghidra_targets_scheduled', 0)}`",
            f"- Real Ghidra completed: `{coverage.get('real_ghidra_completed', 0)}`",
            "",
            "| Stage | Status | Processed | Succeeded | Failed | Skipped | Duration(s) |",
            "| --- | --- | ---: | ---: | ---: | ---: | ---: |",
            *stage_rows,
            "",
            "## 3. Final Findings",
            "",
        ]
        if not model.findings:
            lines.append("No final findings were promoted from canonical evidence.")
        for finding in model.findings:
            lines.extend(self._finding_markdown(finding))
        lines.extend(
            [
                "",
                "## 4. Firmware Overview",
                "",
                f"- File: `{model.firmware_summary.get('filename') or 'unknown'}`",
                f"- SHA256: `{model.firmware_summary.get('sha256') or 'unknown'}`",
                f"- Type: `{model.firmware_summary.get('file_type') or 'unknown'}`",
                "",
                "## 5. Extraction & Rootfs",
                "",
                f"- Extraction mode: `{coverage.get('extraction_method') or 'not established'}`",
                f"- Canonical rootfs marker: `artifacts/rootfs.json`",
                f"- Extraction artifact: `artifacts/extraction.json`",
                f"- Rootfs validation reason: `{coverage.get('rootfs_validation_reason') or 'not established'}`",
                "",
                "## 6. Static Target Selection",
                "",
                f"- Target candidates: `{coverage.get('static_targets', 0)}`",
                f"- Deep static enabled: `{coverage.get('deep_static_enabled', False)}`",
                "",
                "## 7. Ghidra Analysis",
                "",
                f"- Scheduled: `{coverage.get('ghidra_targets_scheduled', 0)}`",
                f"- Completed with real Ghidra: `{coverage.get('real_ghidra_completed', 0)}`",
                f"- Static ELF fallback completed: `{coverage.get('static_elf_fallback_completed', 0)}`",
                f"- Fallback/blocked: `{coverage.get('ghidra_fallback_or_failed', 0)}`",
                f"- Real Ghidra status: `{coverage.get('real_ghidra_status') or 'not recorded'}`",
                "",
                "## 8. Component Correlation",
                "",
                f"- Components: `{len(model.components) or model.component_summary.get('total_components', 0)}`",
                f"- Relationships: `{model.component_summary.get('total_relationships', 0)}`",
                "",
                "## 9. Attack Surface",
                "",
                *self._surface_markdown(model),
                "",
                "## 10. Taint & Hypotheses",
                "",
                f"- Taint sources: `{model.taint_summary.get('sources', model.taint_summary.get('total_sources', 0))}`",
                f"- Taint sinks: `{model.taint_summary.get('sinks', model.taint_summary.get('total_sinks', 0))}`",
                f"- Hypotheses: `{len(model.hypotheses)}`",
                "",
                "## 11. Prioritization & Investigation",
                "",
                f"- Prioritized hypotheses: `{len(model.priority_summary.get('assessments') or []) or model.priority_summary.get('total_assessments', 0)}`",
                f"- Iterations: `{model.investigation_summary.get('iterations', 0)}`",
                f"- Stop reason: `{model.investigation_summary.get('stop_reason') or 'not_executed'}`",
                "",
                "## 12. Dynamic Validation",
                "",
                f"- Dynamic feasibility: `{(model.validation.get('runtime') or {}).get('dynamic_feasibility', 'not_assessed')}`",
                f"- Process started: `{(model.validation.get('runtime') or {}).get('process_started', False)}`",
                f"- Service reachable: `{(model.validation.get('runtime') or {}).get('service_reachable', False)}`",
                f"- Request sent: `{(model.validation.get('runtime') or {}).get('request_sent', False)}`",
                f"- Response observed: `{(model.validation.get('runtime') or {}).get('response_observed', False)}`",
                f"- Real DynamicEvidence: `{model.evidence_summary.get('real_dynamic', 0)}`",
                f"- Blocked items: `{len(model.blocked_items)}`",
                f"- Runtime repair artifacts: `{len(model.runtime_repairs)}`",
                f"- Validation gaps: `{len(model.validation_gaps)}`",
            ]
        )
        for gap in model.validation_gaps:
            lines.append(f"- Gap: {gap}")
        lines.extend(
            [
                "",
                "## 13. Safety / Scope Notes",
                "",
                "- Reachability does not imply exploitability.",
                "- Candidate findings require validation.",
                "- Mock/simulation evidence is excluded from canonical findings.",
                "- Model-assisted commentary is non-canonical until provider-backed validation is implemented.",
                "- No public target scanning was performed.",
                "",
                "## 14. Artifacts",
                "",
            ]
        )
        for artifact in model.artifact_index:
            lines.append(f"- `{artifact.get('path')}` ({artifact.get('type')}): {artifact.get('description')} — exists={artifact.get('exists')}")
        # Firmware text is literal report content, including for Markdown
        # renderers that enable raw HTML. JSON retains the original values.
        path.write_text(html.escape("\n".join(lines), quote=False) + "\n", encoding="utf-8")
        return path

    def _legacy_generate_markdown_unused(self, model: AnalysisReport) -> Path:
        path = self.reports_dir / "report.md"
        lines = [
            "# FirmXplore Firmware Security Analysis Report",
            "",
            "## Analysis Scope",
            "",
            "Analysis was performed against a local firmware artifact in an isolated environment. Reachability does not imply exploitability. Candidate findings require validation. No public target scanning was performed.",
            "",
            "## Firmware Overview",
            "",
            f"- File: `{model.firmware_summary.get('filename') or 'unknown'}`",
            f"- SHA256: `{model.firmware_summary.get('sha256') or 'unknown'}`",
            f"- Type: `{model.firmware_summary.get('file_type') or 'unknown'}`",
            "",
            "## Investigation Summary",
            "",
            f"- Iterations: `{model.investigation_summary.get('iterations', 0)}`",
            f"- Stop reason: `{model.investigation_summary.get('stop_reason') or 'not_executed'}`",
            f"- Provider backed: `{model.provider_status.get('provider_backed')}`",
            "",
            "## Attack Surface",
            "",
            *self._surface_markdown(model),
            "",
            "## Component Overview",
            "",
            f"- Components: `{len(model.components) or model.component_summary.get('total_components', 0)}`",
            "",
            "## Findings",
            "",
        ]
        if not model.findings:
            lines.append("No final findings were promoted from canonical evidence.")
        for finding in model.findings:
            lines.extend(self._finding_markdown(finding))
        lines.extend(
            [
                "",
                "## Rejected / Inconclusive Hypotheses",
                "",
                f"- Rejected: `{len(model.rejected_hypotheses)}`",
                f"- Inconclusive: `{len(model.inconclusive_hypotheses)}`",
                "",
                "## Blocked Analysis",
                "",
                f"- Blocked items: `{len(model.blocked_items)}`",
                "",
                "## Runtime Repairs",
                "",
                f"- Runtime repair artifacts: `{len(model.runtime_repairs)}`",
                "",
                "## Evidence Statistics",
                "",
                f"- Evidence total: `{model.evidence_summary.get('total', 0)}`",
                f"- Dynamic evidence: `{model.evidence_summary.get('dynamic', 0)}`",
                "",
                "## Investigation Timeline",
                "",
            ]
        )
        if model.timeline:
            for item in model.timeline:
                lines.append(f"- Iteration `{item.get('iteration')}`: {item.get('action')} `{item.get('target') or 'none'}` — {item.get('result')}")
        else:
            lines.append("- Not executed.")
        lines.extend(
            [
                "",
                "## Safety / Scope Notes",
                "",
                "- Reachability does not imply exploitability.",
                "- Candidate findings require validation.",
                "- Mock/simulation evidence is excluded from canonical findings.",
                "- No public target scanning was performed.",
                "",
                "## Artifacts",
                "",
            ]
        )
        for artifact in model.artifact_index:
            lines.append(f"- `{artifact.get('path')}` ({artifact.get('type')}): {artifact.get('description')} — exists={artifact.get('exists')}")
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return path

    def generate_html(self, model: AnalysisReport) -> Path:
        path = self.reports_dir / "report.html"
        coverage = model.coverage or {}
        finding_rows = "\n".join(
            f"<tr><td>{html.escape(item.get('finding_id',''))}</td><td>{html.escape(item.get('title',''))}</td><td><span class='badge'>{html.escape(item.get('status',''))}</span></td><td>{html.escape(item.get('severity_hint','unknown'))}</td><td>{html.escape(str(item.get('confidence',0)))}</td></tr>"
            for item in model.findings
        )
        finding_details = "\n".join(self._finding_html(item) for item in model.findings)
        attack_rows = "\n".join(
            f"<tr><td>{html.escape(str(item.get('entry_id') or item.get('id') or ''))}</td><td>{html.escape(str(item.get('entry_type') or item.get('type') or ''))}</td><td>{html.escape(str(item.get('component_id') or item.get('target_component_id') or ''))}</td><td>{html.escape(str(item.get('evidence_level') or 'unknown'))}</td><td>{html.escape(str(item.get('filesystem_path') or 'unknown'))}</td><td>{html.escape(str(item.get('url_path') or 'unconfirmed'))}</td></tr>"
            for item in model.attack_surface[:50]
        )
        surface_metrics = "\n".join(f"<p>{html.escape(label)}: <code>{html.escape(str(value if value is not None else 'unknown'))}</code></p>" for label, value in self._surface_metrics(model))
        stage_rows = "\n".join(
            f"<tr><td>{html.escape(str(item.get('stage')))}</td><td>{html.escape(str(item.get('status')))}</td><td>{html.escape(str(self._processed_display(item)))}</td><td>{html.escape(str(item.get('items_succeeded', 0)))}</td><td>{html.escape(str(item.get('items_failed', 0)))}</td><td>{html.escape(str(item.get('duration', 0)))}</td></tr>"
            for item in model.pipeline_stages
        )
        gaps = "".join(f"<li>{html.escape(str(item))}</li>" for item in model.validation_gaps)
        timeline = "\n".join(f"<li>Iteration {html.escape(str(item.get('iteration')))}: {html.escape(str(item.get('action')))} {html.escape(str(item.get('target') or 'none'))}</li>" for item in model.timeline)
        html_text = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>FirmXplore Firmware Security Analysis Report</title>
<style>
body {{ font-family: Segoe UI, Arial, sans-serif; margin: 2rem; color: #1f2937; background: #f8fafc; }}
h1, h2, h3 {{ color: #0f172a; }}
.cards {{ display: flex; flex-wrap: wrap; gap: 1rem; }}
.card {{ background: white; border: 1px solid #dbe3ef; border-radius: 8px; padding: 1rem; min-width: 10rem; box-shadow: 0 1px 2px #dbe3ef; }}
.badge {{ display: inline-block; padding: .15rem .5rem; border-radius: 999px; background: #e0f2fe; color: #075985; font-size: .85rem; }}
table {{ border-collapse: collapse; width: 100%; background: white; margin: 1rem 0; }}
th, td {{ border: 1px solid #dbe3ef; padding: .55rem; text-align: left; vertical-align: top; }}
th {{ background: #e2e8f0; }}
details {{ background: white; border: 1px solid #dbe3ef; border-radius: 8px; padding: .75rem; margin: .75rem 0; }}
code {{ background: #e2e8f0; padding: .1rem .25rem; border-radius: 4px; }}
</style>
</head>
<body>
<h1>FirmXplore Firmware Security Analysis Report</h1>
<p>Local isolated analysis. Reachability does not imply exploitability. No public target scanning was performed.</p>
<div class="cards">
<div class="card"><strong>Task</strong><br>{html.escape(str(model.metadata.get('task_id')))}</div>
<div class="card"><strong>Status</strong><br>{html.escape(str(model.metadata.get('analysis_status')))}</div>
<div class="card"><strong>Findings</strong><br>{len(model.findings)}</div>
<div class="card"><strong>Provider</strong><br>deterministic / provider_backed=false</div>
</div>
<h2>Analysis Coverage</h2>
<p>Canonical rootfs: <code>{html.escape(str(coverage.get('canonical_rootfs') or 'not established'))}</code></p>
<p>Rootfs source: <code>{html.escape(str(coverage.get('rootfs_source') or 'not established'))}</code>; validated: <code>{html.escape(str(coverage.get('rootfs_validated', False)))}</code></p>
<p>Extraction / Inventory / Target / Ghidra: <code>{html.escape(str(coverage.get('stage_extraction') or 'not recorded'))}</code> / <code>{html.escape(str(coverage.get('stage_rootfs_inventory') or 'not recorded'))}</code> / <code>{html.escape(str(coverage.get('stage_static_target_selection') or 'not recorded'))}</code> / <code>{html.escape(str(coverage.get('stage_ghidra_analysis') or 'not recorded'))}</code></p>
<p>Real Ghidra: <code>{html.escape(str(coverage.get('real_ghidra_status') or 'not recorded'))}</code>; static ELF fallback completed: <code>{html.escape(str(coverage.get('static_elf_fallback_completed', 0)))}</code></p>
<div class="cards">
<div class="card"><strong>Rootfs Files</strong><br>{html.escape(str(coverage.get('rootfs_files', 0)))}</div>
<div class="card"><strong>ELF Binaries</strong><br>{html.escape(str(coverage.get('elf_binaries', 0)))}</div>
<div class="card"><strong>Ghidra Scheduled</strong><br>{html.escape(str(coverage.get('ghidra_targets_scheduled', 0)))}</div>
<div class="card"><strong>Real Ghidra</strong><br>{html.escape(str(coverage.get('real_ghidra_completed', 0)))}</div>
</div>
<table><thead><tr><th>Stage</th><th>Status</th><th>Processed</th><th>Succeeded</th><th>Failed</th><th>Duration(s)</th></tr></thead><tbody>{stage_rows}</tbody></table>
<h2>Finding Table</h2>
<table><thead><tr><th>ID</th><th>Title</th><th>Status</th><th>Severity Hint</th><th>Confidence</th></tr></thead><tbody>{finding_rows}</tbody></table>
<h2>Finding Details</h2>
{finding_details or '<p>No final findings were promoted from canonical evidence.</p>'}
<h2>Attack Surface</h2>
{surface_metrics}
<p>Static candidates do not establish reachable services or verified URLs. Confidence is a rule score, not a probability.</p>
<table><thead><tr><th>Entry candidate</th><th>Type (unconfirmed unless runtime confirmed)</th><th>Component</th><th>Evidence level</th><th>Rootfs file</th><th>URL</th></tr></thead><tbody>{attack_rows}</tbody></table>
<h2>Component Summary</h2>
<p>Components: <code>{html.escape(str(len(model.components) or model.component_summary.get('total_components', 0)))}</code></p>
<h2>Investigation Timeline</h2>
<ul>{timeline or '<li>Not executed.</li>'}</ul>
<h2>Evidence Counts</h2>
<p>Total: <code>{html.escape(str(model.evidence_summary.get('total', 0)))}</code>, Dynamic: <code>{html.escape(str(model.evidence_summary.get('dynamic', 0)))}</code></p>
<h2>Validation Gaps</h2>
<ul>{gaps or '<li>No validation gaps recorded.</li>'}</ul>
<h2>Safety / Scope Notes</h2>
<ul><li>Candidate findings require validation.</li><li>Mock evidence is excluded from canonical findings.</li><li>Real model validation deferred.</li></ul>
</body>
</html>
"""
        path.write_text(html_text, encoding="utf-8")
        return path

    def generate_all(self, model: AnalysisReport, formats: set[str] | None = None) -> dict[str, str]:
        formats = formats or {"json", "md", "html"}
        paths: dict[str, Path] = {}
        if "json" in formats:
            paths["json"] = self.generate_json(model)
        if "md" in formats:
            paths["md"] = self.generate_markdown(model)
        if "html" in formats:
            paths["html"] = self.generate_html(model)
        self._write_report_manifest(paths)
        return {key: self._relative(path) for key, path in paths.items()}

    def _finding_markdown(self, finding: dict[str, Any]) -> list[str]:
        chain = finding.get("evidence_chain") or {}
        return [
            f"### {finding.get('finding_id')}: {finding.get('title')}",
            "",
            f"Status: `{finding.get('status')}`",
            f"Confidence: `{finding.get('confidence')}`",
            f"Category: `{finding.get('category')}`",
            f"Severity Hint: `{finding.get('severity_hint')}`",
            "",
            f"Affected Components: `{', '.join(finding.get('affected_components') or []) or 'not established'}`",
            f"Entry Point: `{', '.join(finding.get('entry_point_ids') or []) or 'not established'}`",
            "",
            f"Evidence Summary: {finding.get('summary')}",
            f"Static Support: `{', '.join(finding.get('static_evidence_ids') or []) or 'not established'}`",
            f"Runtime Support: `{finding.get('runtime_support')}`",
            f"Source-to-Sink Context: source `{', '.join(chain.get('source') or []) or 'not established'}` → sink `{', '.join(chain.get('sink') or []) or 'not established'}`",
            f"Validation Result: `{finding.get('validation_status')}`",
            f"Remaining Uncertainty: `{', '.join(finding.get('remaining_uncertainty') or []) or 'unknown'}`",
            f"Candidate CWE: `{', '.join(finding.get('candidate_cwe_ids') or []) or 'none'}`",
            "",
        ]

    def _finding_html(self, finding: dict[str, Any]) -> str:
        chain = finding.get("evidence_chain") or {}
        return f"""<details>
<summary>{html.escape(finding.get('finding_id',''))}: {html.escape(finding.get('title',''))}</summary>
<p><strong>Status:</strong> {html.escape(finding.get('status',''))} | <strong>Confidence:</strong> {html.escape(str(finding.get('confidence',0)))} | <strong>Severity:</strong> {html.escape(finding.get('severity_hint','unknown'))}</p>
<p>{html.escape(finding.get('summary',''))}</p>
<p><strong>Entry:</strong> {html.escape(', '.join(finding.get('entry_point_ids') or []) or 'not established')}</p>
<p><strong>Source → Sink:</strong> {html.escape(', '.join(chain.get('source') or []) or 'not established')} → {html.escape(', '.join(chain.get('sink') or []) or 'not established')}</p>
<p><strong>Validation:</strong> {html.escape(finding.get('validation_status','not_established'))}</p>
<p><strong>Remaining uncertainty:</strong> {html.escape(', '.join(finding.get('remaining_uncertainty') or []) or 'unknown')}</p>
</details>"""

    def _load(self, relative: str) -> Any:
        path = self.task_dir / relative
        if not path.exists():
            return {} if relative.endswith(".json") else None
        return json.loads(path.read_text(encoding="utf-8"))

    def _artifact_index(self) -> list[ArtifactIndexItem]:
        specs = [
            ("pipeline_stages", "pipeline_stages.json", "Integrated pipeline stage ledger"),
            ("extraction", "artifacts/extraction.json", "Extraction attempts and canonical rootfs selection"),
            ("canonical_rootfs", "artifacts/rootfs.json", "Canonical root filesystem selection"),
            ("static_analysis", "reports/analysis.json", "Static firmware analysis report"),
            ("ghidra_targets", "ghidra/targets.json", "Selected deep static analysis targets"),
            ("ghidra_summary", "ghidra/analysis_summary.json", "Ghidra analysis scheduling and ingestion summary"),
            ("component_graph", "correlation/component_graph.json", "Cross-component graph"),
            ("surface", "surface/attack_surface_summary.json", "Attack surface summary"),
            ("taint", "taint/summary.json", "Input-to-sink correlation summary"),
            ("prioritization", "prioritization/scheduler_state.json", "Hypothesis prioritization scheduler state"),
            ("hypotheses", "hypotheses/synthesis_analysis.json", "Hypothesis synthesis artifact"),
            ("investigation", "investigation/summary.json", "Autonomous investigation summary"),
            ("service_profile_lighttpd", "dynamic/services/lighttpd/launch_profile.json", "Reconstructed lighttpd service startup profile"),
            ("dynamic_evidence", "dynamic/evidence/evidence.json", "Canonical dynamic evidence"),
            ("runtime_logs", "dynamic/logs", "Runtime logs directory"),
            ("findings", "findings/findings.json", "Final findings"),
            ("reports", "reports", "Generated final reports"),
        ]
        items: list[ArtifactIndexItem] = []
        for artifact_type, relative, description in specs:
            path = self.task_dir / relative
            size = path.stat().st_size if path.exists() and path.is_file() else 0
            items.append(ArtifactIndexItem(artifact_type, relative, description, path.exists(), size))
        return items

    def write_artifact_manifest(self) -> Path:
        artifacts = []
        for item in self._artifact_index():
            path = self.task_dir / item.path
            artifacts.append(
                {
                    "artifact_id": f"ART-{len(artifacts)+1:04d}",
                    "type": item.type,
                    "relative_path": item.path,
                    "hash": _hash_path(path) if path.exists() and path.is_file() else None,
                    "size": item.size,
                    "created_at": utc_now_iso(),
                    "producer_phase": item.type,
                    "canonical": item.type not in {"runtime_logs"},
                }
            )
        output = self.task_dir / "artifact_manifest.json"
        output.write_text(json.dumps({"schema_version": REPORT_SCHEMA_VERSION, "artifacts": artifacts}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return output

    def _write_report_manifest(self, paths: dict[str, Path]) -> Path:
        reports = {
            key: {
                "relative_path": self._relative(path),
                "hash": _hash_path(path),
                "schema_version": REPORT_SCHEMA_VERSION,
            }
            for key, path in paths.items()
        }
        output = self.reports_dir / "report_manifest.json"
        output.write_text(json.dumps({"schema_version": REPORT_SCHEMA_VERSION, "reports": reports}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return output

    def _relative(self, path: Path) -> str:
        return path.relative_to(self.task_dir).as_posix()

    def _runtime_repairs(self) -> list[dict[str, Any]]:
        repairs = []
        for path in (self.task_dir / "dynamic").glob("**/*repair*.json") if (self.task_dir / "dynamic").exists() else []:
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                payload = {}
            repairs.append({
                "path": path.relative_to(self.task_dir).as_posix(),
                "exists": True,
                "repair_id": payload.get("repair_id") or payload.get("id"),
                "repair_type": payload.get("repair_type") or payload.get("type"),
                "source_rootfs_modified": bool(payload.get("source_rootfs_modified", False)),
                "runtime_copy_modified": bool(payload.get("runtime_copy_modified", False)),
                "fidelity_limitations": payload.get("fidelity_limitations") or [],
            })
        return repairs

    def _timeline(self) -> list[dict[str, Any]]:
        path = self.task_dir / "investigation" / "action_history.json"
        if not path.exists():
            return []
        return json.loads(path.read_text(encoding="utf-8"))

    def _remaining_problems(self, findings: list[dict[str, Any]], blocked: list[dict[str, Any]]) -> list[str]:
        problems = []
        if blocked:
            problems.append("Some hypotheses or validations are blocked.")
        if any(item.get("status") in {"candidate", "inconclusive"} for item in findings):
            problems.append("Some findings remain candidate or inconclusive.")
        problems.append("Real model validation deferred.")
        return problems


def _hash_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
