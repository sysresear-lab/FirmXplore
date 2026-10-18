from __future__ import annotations

import argparse
import json
import sys
import uuid
from dataclasses import replace
from pathlib import Path

from fwagent import __version__
from fwagent.config import AgentSettings, load_round2_config
from fwagent.doctor import run_doctor
from fwagent.dynamic.agent import DynamicValidationAgent
from fwagent.dynamic.api import DynamicToolAPI
from fwagent.dynamic.cleanup import cleanup_task
from fwagent.dynamic.config import load_dynamic_config
from fwagent.dynamic.correlation import ComponentGraphBuilder
from fwagent.dynamic.docker import DockerController, DockerUnavailableError
from fwagent.dynamic.investigation import InvestigationController
from fwagent.dynamic.prioritization import HypothesisValidationScheduler
from fwagent.dynamic.surface import AttackSurfaceBuilder
from fwagent.dynamic.synthesis import HypothesisSynthesizer
from fwagent.dynamic.taint import TaintAnalysisBuilder
from fwagent.dynamic.workspace import DynamicWorkspace
from fwagent.investigation import PiAgent, StaticInvestigator
from fwagent.model.config import ModelConfigError, load_model_config, load_model_config_with_overrides
from fwagent.model.diagnostics import ProviderSmokeRunner, classify_provider_error
from fwagent.model.provider import ModelProvider, ModelProviderError
from fwagent.model.redaction import redact_value
from fwagent.pipeline import AnalysisPipelineController, analyze_firmware, parse_report_formats
from fwagent.reporting.json_report import load_analysis_json
from fwagent.reporting.terminal import format_terminal_report
from fwagent.runtime.ghidra import GhidraRuntime
from fwagent.tools.common import sha256_file
from fwagent.tools.ghidra_api import BinaryToolAPI


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="firmxplore", description="FirmXplore firmware security analysis pipeline")
    parser.add_argument("--version", action="version", version=f"firmxplore {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    doctor = subparsers.add_parser("doctor", help="Check FirmXplore Docker/container analysis environment")
    doctor.add_argument("--dynamic", action="store_true", help="Include dynamic worker checks")

    analyze = subparsers.add_parser("analyze", help="Run FirmXplore firmware analysis")
    analyze.add_argument("firmware_file", help="Firmware image or archive to analyze")
    analyze.add_argument("--workspace", default="workspace", help="Workspace root directory")
    analyze.add_argument("--timeout", type=int, default=600, help="Extraction timeout in seconds")
    analyze.add_argument("--scan-timeout", type=float, default=None, help="Shared base scan deadline in seconds (default 300, max 3600; FWAGENT_SCAN_TIMEOUT_SECONDS)")
    analyze.add_argument("--task-id", default=None, help="Explicit task id to create or resume")
    analyze.add_argument("--resume", action="store_true", help="Resume an existing task id")
    analyze.add_argument("--report-format", default="json,md,html", help="Comma-separated report formats: json,md,html")
    analyze.add_argument("--fast", action="store_true", help="Run fast triage without deep static or runtime validation")
    analyze.add_argument("--deep", action="store_true", help="Prefer deeper static target coverage when available")
    analyze.add_argument("--static-only", action="store_true", help="Run static analysis and final reports without dynamic investigation")
    analyze.add_argument("--no-dynamic", action="store_true", help="Build static Round 4 artifacts but skip runtime validation")
    analyze.add_argument("--max-iterations", type=int, default=None, help="Bound autonomous investigation iterations")
    analyze.add_argument("--output", default=None, help="Optional directory to copy final reports")
    analyze.add_argument("--quiet", action="store_true", help="Suppress progress output")
    analyze.add_argument("--verbose", action="store_true", help="Print machine summary after human output")
    analyze.add_argument("--json", action="store_true", help="Print machine-readable pipeline summary")

    report = subparsers.add_parser("report", help="Show an existing task report")
    report.add_argument("task_id", help="Task id under the workspace")
    report.add_argument("--workspace", default="workspace", help="Workspace root directory")
    report.add_argument("--format", default=None, help="Regenerate report formats: json,md,html")
    report.add_argument("--json", action="store_true", help="Print machine-readable report generation output")

    status = subparsers.add_parser("status", help="Show Round 5 task status")
    status.add_argument("task_id", help="Task id under the workspace")
    status.add_argument("--workspace", default="workspace", help="Workspace root directory")
    status.add_argument("--json", action="store_true", help="Print machine-readable task status")

    ghidra = subparsers.add_parser("ghidra", help="Ghidra runtime commands")
    ghidra_subparsers = ghidra.add_subparsers(dest="ghidra_command", required=True)
    ghidra_check = ghidra_subparsers.add_parser("check", help="Check the Ghidra environment")
    ghidra_check.add_argument("--workspace", default="workspace/ghidra-check", help="Workspace for runtime checks")
    ghidra_check.add_argument("--config", default=None, help="Round 2 config path")

    model = subparsers.add_parser("model", help="Model API commands")
    model_subparsers = model.add_subparsers(dest="model_command", required=True)
    model_check = model_subparsers.add_parser("check", help="Run a minimal model connection smoke test")
    model_check.add_argument("--timeout", type=int, default=30, help="Request timeout in seconds")
    model_check.add_argument("--env", default=".env", help="Path to the .env file")
    model_check.add_argument("--config", default=None, help="Optional model YAML config path")
    model_check.add_argument("--provider", default=None, help="Override model provider name")
    model_check.add_argument("--model", default=None, help="Override model name")
    model_check.add_argument("--base-url", default=None, help="Override OpenAI-compatible base URL")

    model_doctor = subparsers.add_parser("model-doctor", help="Diagnose configured model provider without exposing secrets")
    model_doctor.add_argument("--timeout", type=int, default=30, help="Request timeout in seconds")
    model_doctor.add_argument("--env", default=".env", help="Path to the .env file")
    model_doctor.add_argument("--config", default=None, help="Optional model YAML config path")
    model_doctor.add_argument("--provider", default=None, help="Override model provider name")
    model_doctor.add_argument("--model", default=None, help="Override model name")
    model_doctor.add_argument("--base-url", default=None, help="Override OpenAI-compatible base URL")
    model_doctor.add_argument("--connect", action="store_true", help="Run connection and tool protocol smoke tests")

    model_smoke = subparsers.add_parser("model-smoke", help="Run model completion, structured output, and tool protocol smoke tests")
    model_smoke.add_argument("--timeout", type=int, default=30, help="Request timeout in seconds")
    model_smoke.add_argument("--env", default=".env", help="Path to the .env file")
    model_smoke.add_argument("--config", default=None, help="Optional model YAML config path")
    model_smoke.add_argument("--provider", default=None, help="Override model provider name")
    model_smoke.add_argument("--model", default=None, help="Override model name")
    model_smoke.add_argument("--base-url", default=None, help="Override OpenAI-compatible base URL")
    model_smoke.add_argument("--max-retries", type=int, default=1, help="Retry temporary provider failures")

    binary = subparsers.add_parser("binary", help="Binary static analysis commands")
    binary_subparsers = binary.add_subparsers(dest="binary_command", required=True)
    binary_analyze = binary_subparsers.add_parser("analyze", help="Analyze one ELF binary")
    binary_analyze.add_argument("binary_file")
    binary_analyze.add_argument("--workspace", default="workspace", help="Workspace root directory")
    binary_analyze.add_argument("--config", default=None, help="Round 2 config path")
    binary_analyze.add_argument("--force", action="store_true", help="Ignore existing binary analysis cache")
    binary_analyze.add_argument("--no-fallback", action="store_true", help="Fail if Ghidra is unavailable")

    binary_functions = binary_subparsers.add_parser("functions", help="List functions for one ELF binary")
    binary_functions.add_argument("binary_file")
    binary_functions.add_argument("--workspace", default="workspace", help="Workspace root directory")
    binary_functions.add_argument("--config", default=None, help="Round 2 config path")

    binary_decompile = binary_subparsers.add_parser("decompile", help="Decompile or disassemble one function")
    binary_decompile.add_argument("binary_file")
    binary_decompile.add_argument("function")
    binary_decompile.add_argument("--workspace", default="workspace", help="Workspace root directory")
    binary_decompile.add_argument("--config", default=None, help="Round 2 config path")

    investigate = subparsers.add_parser("investigate", help="Run bounded static investigation for an existing task")
    investigate.add_argument("task_id")
    investigate.add_argument("--workspace", default="workspace", help="Workspace root directory")
    investigate.add_argument("--config", default=None, help="Round 2 config path")
    investigate.add_argument("--binary", default=None, help="Restrict investigation to one priority binary")
    investigate.add_argument("--max-steps", type=int, default=None, help="Override agent max steps")
    investigate.add_argument("--max-binary-analyses", type=int, default=None, help="Override max binary analyses")
    investigate.add_argument(
        "--max-decompilations-per-binary",
        type=int,
        default=None,
        help="Override max decompilations per binary",
    )
    investigate.add_argument("--dry-run", action="store_true", help="Validate configuration without calling the model")
    investigate.add_argument("--autonomous", action="store_true", help="Run Round 4.6 autonomous investigation loop for prepared dynamic workspaces")
    investigate.add_argument("--resume", action="store_true", help="Resume autonomous investigation state")
    investigate.add_argument("--max-iterations", type=int, default=None, help="Bound autonomous investigation iterations")
    investigate.add_argument("--stop-after-iteration", action="store_true", help="Pause after one autonomous iteration")
    investigate.add_argument("--json", action="store_true", help="Print full JSON output for autonomous investigation")
    investigate.add_argument(
        "--tool-workspace",
        default=None,
        help="Workspace with cached Ghidra outputs to reuse",
    )

    investigate_status = subparsers.add_parser("investigate-status", help="Show autonomous investigation state")
    investigate_status.add_argument("task_id")
    investigate_status.add_argument("--workspace", default="workspace", help="Workspace root directory")
    investigate_status.add_argument("--config", default=None, help="Dynamic config path")
    investigate_status.add_argument("--json", action="store_true", help="Print full JSON output")

    investigate_resume = subparsers.add_parser("investigate-resume", help="Resume autonomous investigation")
    investigate_resume.add_argument("task_id")
    investigate_resume.add_argument("--workspace", default="workspace", help="Workspace root directory")
    investigate_resume.add_argument("--config", default=None, help="Dynamic config path")
    investigate_resume.add_argument("--max-iterations", type=int, default=None, help="Bound resume iterations")
    investigate_resume.add_argument("--json", action="store_true", help="Print full JSON output")

    investigate_stop = subparsers.add_parser("investigate-stop", help="Stop autonomous investigation")
    investigate_stop.add_argument("task_id")
    investigate_stop.add_argument("--workspace", default="workspace", help="Workspace root directory")
    investigate_stop.add_argument("--config", default=None, help="Dynamic config path")
    investigate_stop.add_argument("--reason", default="user_stop", help="Stop reason")

    investigate_history = subparsers.add_parser("investigate-history", help="Show autonomous investigation action history")
    investigate_history.add_argument("task_id")
    investigate_history.add_argument("--workspace", default="workspace", help="Workspace root directory")
    investigate_history.add_argument("--config", default=None, help="Dynamic config path")
    investigate_history.add_argument("--json", action="store_true", help="Print full JSON output")

    investigate_next = subparsers.add_parser("investigate-next", help="Show next autonomous investigation action")
    investigate_next.add_argument("task_id")
    investigate_next.add_argument("--workspace", default="workspace", help="Workspace root directory")
    investigate_next.add_argument("--config", default=None, help="Dynamic config path")
    investigate_next.add_argument("--json", action="store_true", help="Print full JSON output")

    emulate = subparsers.add_parser("emulate", help="Prepare and boot firmware in the dynamic worker")
    emulate.add_argument("task_id")
    emulate.add_argument("--workspace", default="workspace", help="Workspace root directory")
    emulate.add_argument("--config", default=None, help="Round 3 dynamic config path")
    emulate.add_argument("--timeout", type=int, default=None, help="Boot timeout in seconds")

    emulate_status = subparsers.add_parser("emulate-status", help="Show emulation state for a task")
    emulate_status.add_argument("task_id")
    emulate_status.add_argument("--workspace", default="workspace", help="Workspace root directory")
    emulate_status.add_argument("--config", default=None, help="Round 3 dynamic config path")

    emulate_stop = subparsers.add_parser("emulate-stop", help="Stop emulation for a task")
    emulate_stop.add_argument("task_id")
    emulate_stop.add_argument("--workspace", default="workspace", help="Workspace root directory")
    emulate_stop.add_argument("--config", default=None, help="Round 3 dynamic config path")

    dynamic_validate = subparsers.add_parser("dynamic-validate", help="Run Pi-controlled dynamic validation")
    dynamic_validate.add_argument("task_id")
    dynamic_validate.add_argument("--workspace", default="workspace", help="Workspace root directory")
    dynamic_validate.add_argument("--config", default=None, help="Round 3 dynamic config path")
    dynamic_validate.add_argument("--hypothesis", default=None, help="Hypothesis id to validate")
    dynamic_validate.add_argument("--service", default=None, help="Service target for Round 3.2 validation")
    dynamic_validate.add_argument("--dry-run", action="store_true", help="Validate configuration without calling the model")

    validate_hypothesis = subparsers.add_parser("validate-hypothesis", help="Run Round 4 agent-guided dynamic validation")
    validate_hypothesis.add_argument("task_id")
    validate_hypothesis.add_argument("hypothesis_id")
    validate_hypothesis.add_argument("--workspace", default="workspace", help="Workspace root directory")
    validate_hypothesis.add_argument("--config", default=None, help="Dynamic config path")
    validate_hypothesis.add_argument("--service", default=None, help="Optional service target hint")
    validate_hypothesis.add_argument("--dry-run", action="store_true", help="Validate configuration without calling the model")

    agent_smoke = subparsers.add_parser("agent-smoke", help="Run provider-backed Round 4 agent smoke validation")
    agent_smoke.add_argument("task_id")
    agent_smoke.add_argument("hypothesis_id")
    agent_smoke.add_argument("--workspace", default="workspace", help="Workspace root directory")
    agent_smoke.add_argument("--config", default=None, help="Dynamic config path")
    agent_smoke.add_argument("--env", default=".env", help="Path to the .env file")
    agent_smoke.add_argument("--model-config", default=None, help="Optional model YAML config path")
    agent_smoke.add_argument("--timeout", type=int, default=30, help="Model request timeout")
    agent_smoke.add_argument("--max-retries", type=int, default=1, help="Retry temporary provider failures during preflight smoke")

    validation_status = subparsers.add_parser("validation-status", help="Show Round 4 validation status")
    validation_status.add_argument("task_id")
    validation_status.add_argument("validation_id")
    validation_status.add_argument("--workspace", default="workspace", help="Workspace root directory")
    validation_status.add_argument("--config", default=None, help="Dynamic config path")

    validation_report = subparsers.add_parser("validation-report", help="Print Round 4 validation artifacts")
    validation_report.add_argument("task_id")
    validation_report.add_argument("validation_id")
    validation_report.add_argument("--workspace", default="workspace", help="Workspace root directory")
    validation_report.add_argument("--config", default=None, help="Dynamic config path")

    hypotheses = subparsers.add_parser("hypotheses", help="List hypotheses and deterministic priority summaries")
    hypotheses.add_argument("task_id")
    hypotheses.add_argument("--workspace", default="workspace", help="Workspace root directory")
    hypotheses.add_argument("--config", default=None, help="Dynamic config path")
    hypotheses.add_argument("--json", action="store_true", help="Print full JSON output")

    prioritize = subparsers.add_parser("prioritize", help="Rank hypotheses for dynamic validation")
    prioritize.add_argument("task_id")
    prioritize.add_argument("--workspace", default="workspace", help="Workspace root directory")
    prioritize.add_argument("--config", default=None, help="Dynamic config path")
    prioritize.add_argument("--explain", default=None, help="Explain one hypothesis assessment")
    prioritize.add_argument("--json", action="store_true", help="Print full JSON output")

    validation_budget = subparsers.add_parser("validation-budget", help="Show validation budget for prioritized hypotheses")
    validation_budget.add_argument("task_id")
    validation_budget.add_argument("--workspace", default="workspace", help="Workspace root directory")
    validation_budget.add_argument("--config", default=None, help="Dynamic config path")
    validation_budget.add_argument("--json", action="store_true", help="Print full JSON output")

    validation_queue = subparsers.add_parser("validation-queue", help="Show deterministic validation queue")
    validation_queue.add_argument("task_id")
    validation_queue.add_argument("--workspace", default="workspace", help="Workspace root directory")
    validation_queue.add_argument("--config", default=None, help="Dynamic config path")
    validation_queue.add_argument("--json", action="store_true", help="Print full JSON output")

    validate_next = subparsers.add_parser("validate-next", help="Execute the next validation queue item with deterministic mock semantics")
    validate_next.add_argument("task_id")
    validate_next.add_argument("--workspace", default="workspace", help="Workspace root directory")
    validate_next.add_argument("--config", default=None, help="Dynamic config path")
    validate_next.add_argument(
        "--mock-verdict",
        choices=["dynamically_supported", "dynamically_rejected", "validation_inconclusive", "validation_blocked"],
        default="validation_inconclusive",
        help="Mock verdict for offline scheduler integration",
    )
    validate_next.add_argument("--json", action="store_true", help="Print full JSON output")

    graph_build = subparsers.add_parser("graph-build", help="Build cross-component correlation graph")
    graph_build.add_argument("task_id")
    graph_build.add_argument("--workspace", default="workspace", help="Workspace root directory")
    graph_build.add_argument("--config", default=None, help="Dynamic config path")
    graph_build.add_argument("--json", action="store_true", help="Print full JSON output")

    graph_summary = subparsers.add_parser("graph-summary", help="Show cross-component graph summary")
    graph_summary.add_argument("task_id")
    graph_summary.add_argument("--workspace", default="workspace", help="Workspace root directory")
    graph_summary.add_argument("--config", default=None, help="Dynamic config path")
    graph_summary.add_argument("--json", action="store_true", help="Print full JSON output")

    component = subparsers.add_parser("component", help="Show one graph component")
    component.add_argument("task_id")
    component.add_argument("component")
    component.add_argument("--workspace", default="workspace", help="Workspace root directory")
    component.add_argument("--config", default=None, help="Dynamic config path")
    component.add_argument("--json", action="store_true", help="Print full JSON output")

    graph_path = subparsers.add_parser("graph-path", help="Find cross-component paths")
    graph_path.add_argument("task_id")
    graph_path.add_argument("source")
    graph_path.add_argument("target")
    graph_path.add_argument("--workspace", default="workspace", help="Workspace root directory")
    graph_path.add_argument("--config", default=None, help="Dynamic config path")
    graph_path.add_argument("--max-depth", type=int, default=None, help="Maximum graph path depth")
    graph_path.add_argument("--json", action="store_true", help="Print full JSON output")

    correlation_context = subparsers.add_parser("correlation-context", help="Show compressed graph context for a hypothesis")
    correlation_context.add_argument("task_id")
    correlation_context.add_argument("hypothesis_id")
    correlation_context.add_argument("--workspace", default="workspace", help="Workspace root directory")
    correlation_context.add_argument("--config", default=None, help="Dynamic config path")
    correlation_context.add_argument("--max-depth", type=int, default=None, help="Maximum context depth")
    correlation_context.add_argument("--max-nodes", type=int, default=None, help="Maximum context nodes")

    surface_build = subparsers.add_parser("surface-build", help="Build entry-point reachability attack-surface map")
    surface_build.add_argument("task_id")
    surface_build.add_argument("--workspace", default="workspace", help="Workspace root directory")
    surface_build.add_argument("--config", default=None, help="Dynamic config path")
    surface_build.add_argument("--json", action="store_true", help="Print full JSON output")

    surface_summary = subparsers.add_parser("surface-summary", help="Show attack-surface summary counts")
    surface_summary.add_argument("task_id")
    surface_summary.add_argument("--workspace", default="workspace", help="Workspace root directory")
    surface_summary.add_argument("--config", default=None, help="Dynamic config path")
    surface_summary.add_argument("--json", action="store_true", help="Print full JSON output")

    surface_list = subparsers.add_parser("surface-list", help="List discovered entry points")
    surface_list.add_argument("task_id")
    surface_list.add_argument("--workspace", default="workspace", help="Workspace root directory")
    surface_list.add_argument("--config", default=None, help="Dynamic config path")
    surface_list.add_argument("--json", action="store_true", help="Print full JSON output")

    surface_entry = subparsers.add_parser("surface-entry", help="Show one entry point context")
    surface_entry.add_argument("task_id")
    surface_entry.add_argument("entry_id")
    surface_entry.add_argument("--workspace", default="workspace", help="Workspace root directory")
    surface_entry.add_argument("--config", default=None, help="Dynamic config path")
    surface_entry.add_argument("--json", action="store_true", help="Print full JSON output")

    reachable_from = subparsers.add_parser("reachable-from", help="Show components reachable from one entry point")
    reachable_from.add_argument("task_id")
    reachable_from.add_argument("entry_id")
    reachable_from.add_argument("--workspace", default="workspace", help="Workspace root directory")
    reachable_from.add_argument("--config", default=None, help="Dynamic config path")
    reachable_from.add_argument("--json", action="store_true", help="Print full JSON output")

    hypothesis_entry = subparsers.add_parser("hypothesis-entry", help="Show entry-point mapping for one hypothesis")
    hypothesis_entry.add_argument("task_id")
    hypothesis_entry.add_argument("hypothesis_id")
    hypothesis_entry.add_argument("--workspace", default="workspace", help="Workspace root directory")
    hypothesis_entry.add_argument("--config", default=None, help="Dynamic config path")
    hypothesis_entry.add_argument("--json", action="store_true", help="Print full JSON output")

    taint_build = subparsers.add_parser("taint-build", help="Build lightweight source-to-sink taint correlation")
    taint_build.add_argument("task_id")
    taint_build.add_argument("--workspace", default="workspace", help="Workspace root directory")
    taint_build.add_argument("--config", default=None, help="Dynamic config path")
    taint_build.add_argument("--json", action="store_true", help="Print full JSON output")

    taint_summary = subparsers.add_parser("taint-summary", help="Show taint analysis summary")
    taint_summary.add_argument("task_id")
    taint_summary.add_argument("--workspace", default="workspace", help="Workspace root directory")
    taint_summary.add_argument("--config", default=None, help="Dynamic config path")
    taint_summary.add_argument("--json", action="store_true", help="Print full JSON output")

    taint_sources = subparsers.add_parser("taint-sources", help="List taint input sources")
    taint_sources.add_argument("task_id")
    taint_sources.add_argument("--workspace", default="workspace", help="Workspace root directory")
    taint_sources.add_argument("--config", default=None, help="Dynamic config path")
    taint_sources.add_argument("--json", action="store_true", help="Print full JSON output")

    taint_sinks = subparsers.add_parser("taint-sinks", help="List sensitive sinks")
    taint_sinks.add_argument("task_id")
    taint_sinks.add_argument("--workspace", default="workspace", help="Workspace root directory")
    taint_sinks.add_argument("--config", default=None, help="Dynamic config path")
    taint_sinks.add_argument("--json", action="store_true", help="Print full JSON output")

    taint_paths = subparsers.add_parser("taint-paths", help="List source-to-sink taint paths")
    taint_paths.add_argument("task_id")
    taint_paths.add_argument("--workspace", default="workspace", help="Workspace root directory")
    taint_paths.add_argument("--config", default=None, help="Dynamic config path")
    taint_paths.add_argument("--json", action="store_true", help="Print full JSON output")

    taint_hypothesis = subparsers.add_parser("taint-hypothesis", help="Show taint context for one hypothesis")
    taint_hypothesis.add_argument("task_id")
    taint_hypothesis.add_argument("hypothesis_id")
    taint_hypothesis.add_argument("--workspace", default="workspace", help="Workspace root directory")
    taint_hypothesis.add_argument("--config", default=None, help="Dynamic config path")
    taint_hypothesis.add_argument("--json", action="store_true", help="Print full JSON output")

    taint_path = subparsers.add_parser("taint-path", help="Show one source-to-sink taint path")
    taint_path.add_argument("task_id")
    taint_path.add_argument("path_id")
    taint_path.add_argument("--workspace", default="workspace", help="Workspace root directory")
    taint_path.add_argument("--config", default=None, help="Dynamic config path")
    taint_path.add_argument("--json", action="store_true", help="Print full JSON output")

    synthesize_hypotheses = subparsers.add_parser("synthesize-hypotheses", help="Build deterministic security hypothesis candidates")
    synthesize_hypotheses.add_argument("task_id")
    synthesize_hypotheses.add_argument("--workspace", default="workspace", help="Workspace root directory")
    synthesize_hypotheses.add_argument("--config", default=None, help="Dynamic config path")
    synthesize_hypotheses.add_argument("--json", action="store_true", help="Print full JSON output")

    synthesis_summary = subparsers.add_parser("synthesis-summary", help="Show hypothesis synthesis summary")
    synthesis_summary.add_argument("task_id")
    synthesis_summary.add_argument("--workspace", default="workspace", help="Workspace root directory")
    synthesis_summary.add_argument("--config", default=None, help="Dynamic config path")
    synthesis_summary.add_argument("--json", action="store_true", help="Print full JSON output")

    hypothesis_candidates = subparsers.add_parser("hypothesis-candidates", help="List generated hypothesis candidates")
    hypothesis_candidates.add_argument("task_id")
    hypothesis_candidates.add_argument("--workspace", default="workspace", help="Workspace root directory")
    hypothesis_candidates.add_argument("--config", default=None, help="Dynamic config path")
    hypothesis_candidates.add_argument("--json", action="store_true", help="Print full JSON output")

    hypothesis_candidate = subparsers.add_parser("hypothesis-candidate", help="Show one generated hypothesis candidate")
    hypothesis_candidate.add_argument("task_id")
    hypothesis_candidate.add_argument("candidate_id")
    hypothesis_candidate.add_argument("--workspace", default="workspace", help="Workspace root directory")
    hypothesis_candidate.add_argument("--config", default=None, help="Dynamic config path")
    hypothesis_candidate.add_argument("--json", action="store_true", help="Print full JSON output")

    hypothesis_generated = subparsers.add_parser("hypothesis-generated", help="List generated canonical hypothesis records")
    hypothesis_generated.add_argument("task_id")
    hypothesis_generated.add_argument("--workspace", default="workspace", help="Workspace root directory")
    hypothesis_generated.add_argument("--config", default=None, help="Dynamic config path")
    hypothesis_generated.add_argument("--json", action="store_true", help="Print full JSON output")

    finding_candidates = subparsers.add_parser("finding-candidates", help="List grouped finding candidates")
    finding_candidates.add_argument("task_id")
    finding_candidates.add_argument("--workspace", default="workspace", help="Workspace root directory")
    finding_candidates.add_argument("--config", default=None, help="Dynamic config path")
    finding_candidates.add_argument("--json", action="store_true", help="Print full JSON output")
    correlation_context.add_argument("--json", action="store_true", help="Print full JSON output")

    service_profile = subparsers.add_parser("service-profile", help="Reconstruct firmware service startup")
    service_profile.add_argument("task_id")
    service_profile.add_argument("service")
    service_profile.add_argument("--workspace", default="workspace", help="Workspace root directory")
    service_profile.add_argument("--config", default=None, help="Round 3 dynamic config path")

    service_start = subparsers.add_parser("service-start", help="Start a firmware service under service-qemu")
    service_start.add_argument("task_id")
    service_start.add_argument("service")
    service_start.add_argument("--workspace", default="workspace", help="Workspace root directory")
    service_start.add_argument("--config", default=None, help="Round 3 dynamic config path")
    service_start.add_argument("--stability-seconds", type=int, default=5, help="Process stability threshold")
    service_start.add_argument("--keep-running", action="store_true", help="Do not stop the service before exiting")

    service_status = subparsers.add_parser("service-status", help="Show service runtime status")
    service_status.add_argument("task_id")
    service_status.add_argument("service")
    service_status.add_argument("--workspace", default="workspace", help="Workspace root directory")
    service_status.add_argument("--config", default=None, help="Round 3 dynamic config path")

    service_stop = subparsers.add_parser("service-stop", help="Stop a service runtime")
    service_stop.add_argument("task_id")
    service_stop.add_argument("service")
    service_stop.add_argument("--workspace", default="workspace", help="Workspace root directory")
    service_stop.add_argument("--config", default=None, help="Round 3 dynamic config path")

    app_inspect = subparsers.add_parser("application-inspect", help="Inspect a firmware application backend")
    app_inspect.add_argument("task_id")
    app_inspect.add_argument("backend", nargs="?", default="device_manager")
    app_inspect.add_argument("--workspace", default="workspace", help="Workspace root directory")
    app_inspect.add_argument("--config", default=None, help="Round 3 dynamic config path")

    app_start = subparsers.add_parser("application-start", help="Attempt original FastCGI backend startup")
    app_start.add_argument("task_id")
    app_start.add_argument("backend", nargs="?", default="device_manager")
    app_start.add_argument("--workspace", default="workspace", help="Workspace root directory")
    app_start.add_argument("--config", default=None, help="Round 3 dynamic config path")
    app_start.add_argument("--stability-seconds", type=int, default=5, help="Process stability threshold")
    app_start.add_argument("--trace", action="store_true", help="Also run bounded qemu syscall trace")

    app_endpoints = subparsers.add_parser("application-endpoints", help="Reconstruct application endpoints")
    app_endpoints.add_argument("task_id")
    app_endpoints.add_argument("backend", nargs="?", default="device_manager")
    app_endpoints.add_argument("--workspace", default="workspace", help="Workspace root directory")
    app_endpoints.add_argument("--config", default=None, help="Round 3 dynamic config path")

    app_probe = subparsers.add_parser("application-probe", help="Probe one reconstructed application endpoint")
    app_probe.add_argument("task_id")
    app_probe.add_argument("path")
    app_probe.add_argument("backend", nargs="?", default="device_manager")
    app_probe.add_argument("--workspace", default="workspace", help="Workspace root directory")
    app_probe.add_argument("--config", default=None, help="Round 3 dynamic config path")
    app_probe.add_argument("--method", default="GET", choices=["GET", "HEAD"])

    fastcgi_context = subparsers.add_parser("fastcgi-context", help="Compare direct and FastCGI runtime contexts")
    fastcgi_context.add_argument("task_id")
    fastcgi_context.add_argument("backend", nargs="?", default="device_manager")
    fastcgi_context.add_argument("--workspace", default="workspace", help="Workspace root directory")
    fastcgi_context.add_argument("--config", default=None, help="Round 3 dynamic config path")
    fastcgi_context.add_argument("--timeout-seconds", type=int, default=10, help="Context trace timeout")

    fastcgi_harness = subparsers.add_parser("fastcgi-harness", help="Run standalone FastCGI harness for an application backend")
    fastcgi_harness.add_argument("task_id")
    fastcgi_harness.add_argument("backend", nargs="?", default="device_manager")
    fastcgi_harness.add_argument("--endpoint", default="/services/device_manager/", help="Reconstructed endpoint path")
    fastcgi_harness.add_argument("--workspace", default="workspace", help="Workspace root directory")
    fastcgi_harness.add_argument("--config", default=None, help="Round 3 dynamic config path")
    fastcgi_harness.add_argument("--timeout-seconds", type=int, default=10, help="Harness timeout")

    fastcgi_diff = subparsers.add_parser("fastcgi-diff", help="Generate standalone-vs-lighttpd FastCGI runtime diff")
    fastcgi_diff.add_argument("task_id")
    fastcgi_diff.add_argument("backend", nargs="?", default="device_manager")
    fastcgi_diff.add_argument("--workspace", default="workspace", help="Workspace root directory")
    fastcgi_diff.add_argument("--config", default=None, help="Round 3 dynamic config path")

    fastcgi_child_status = subparsers.add_parser("fastcgi-child-status", help="Classify lighttpd FastCGI child startup failure")
    fastcgi_child_status.add_argument("task_id")
    fastcgi_child_status.add_argument("backend", nargs="?", default="device_manager")
    fastcgi_child_status.add_argument("--workspace", default="workspace", help="Workspace root directory")
    fastcgi_child_status.add_argument("--config", default=None, help="Round 3 dynamic config path")
    fastcgi_child_status.add_argument("--stability-seconds", type=int, default=5, help="Startup observation window")

    fastcgi_integration = subparsers.add_parser("fastcgi-integration-validate", help="Validate lighttpd to FastCGI application integration")
    fastcgi_integration.add_argument("task_id")
    fastcgi_integration.add_argument("backend", nargs="?", default="device_manager")
    fastcgi_integration.add_argument("--endpoint", default="/services/device_manager/", help="Reconstructed endpoint path")
    fastcgi_integration.add_argument("--workspace", default="workspace", help="Workspace root directory")
    fastcgi_integration.add_argument("--config", default=None, help="Round 3 dynamic config path")
    fastcgi_integration.add_argument("--stability-seconds", type=int, default=3, help="Startup observation window")

    cleanup = subparsers.add_parser("cleanup", help="Clean stale emulation resources for a task")
    cleanup.add_argument("task_id")
    cleanup.add_argument("--workspace", default="workspace", help="Workspace root directory")
    cleanup.add_argument("--config", default=None, help="Round 3 dynamic config path")
    cleanup.add_argument("--all", action="store_true", help="Remove the entire task directory")
    cleanup.add_argument("--json", action="store_true", help="Print machine-readable cleanup output")

    docker_build = subparsers.add_parser("docker-build", help="Build analysis worker Docker images")
    docker_build.add_argument("--image", choices=["static", "dynamic", "all"], default="dynamic")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "analyze":
        try:
            formats = parse_report_formats(args.report_format)
        except ValueError as exc:
            print(f"ERROR: {exc}")
            return 2
        result = AnalysisPipelineController(args.workspace).analyze(
            args.firmware_file,
            task_id=args.task_id,
            resume=args.resume,
            report_formats=formats,
            fast=args.fast,
            deep=args.deep,
            static_only=args.static_only,
            no_dynamic=args.no_dynamic,
            max_iterations=args.max_iterations,
            output_dir=args.output,
            progress=not args.quiet and not args.json,
            timeout=args.timeout,
            scan_timeout=args.scan_timeout,
        )
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print(_format_pipeline_summary(result))
            if args.verbose:
                print(json.dumps(result, indent=2, sort_keys=True))
        return int(result.get("exit_code", 1))

    if args.command == "doctor":
        exit_code, output = run_doctor(dynamic=args.dynamic)
        print(output)
        return exit_code

    if args.command == "report":
        if args.format:
            try:
                formats = parse_report_formats(args.format)
            except ValueError as exc:
                print(f"ERROR: {exc}")
                return 2
            result = AnalysisPipelineController(args.workspace).regenerate_report(args.task_id, report_formats=formats)
            print(json.dumps(result, indent=2, sort_keys=True) if args.json else _format_report_regeneration(result))
            return 0 if result.get("success") else 1
        final_report = Path(args.workspace) / args.task_id / "reports" / "report.json"
        if final_report.exists():
            payload = load_analysis_json(final_report)
            print(_format_final_report_summary(payload))
            return 0
        report_path = Path(args.workspace) / args.task_id / "reports" / "analysis.json"
        report = load_analysis_json(report_path)
        print(format_terminal_report(report, str(report_path)))
        return 0

    if args.command == "status":
        result = AnalysisPipelineController(args.workspace).status(args.task_id)
        print(json.dumps(result, indent=2, sort_keys=True) if args.json else _format_task_status(result))
        return 0 if result.get("success") else 1

    if args.command == "ghidra":
        config = load_round2_config(args.config)
        runtime = GhidraRuntime(args.workspace, settings=config.ghidra)
        print(json.dumps(runtime.check_environment(), indent=2, sort_keys=True))
        return 0

    if args.command == "model":
        try:
            model_config = load_model_config_with_overrides(
                env_path=args.env,
                config_path=args.config,
                provider=args.provider,
                model=args.model,
                base_url=args.base_url,
            )
            model_config.require_credentials()
            provider = ModelProvider(model_config, timeout=args.timeout)
            result = provider.smoke_test()
        except ModelConfigError as exc:
            print("ERROR")
            print(str(exc))
            return 1
        except ModelProviderError as exc:
            print(f"MODEL_ERROR {exc.code}: {exc}")
            return 1
        print(json.dumps(redact_value(result, [model_config.api_key]), indent=2, sort_keys=True))
        return 0

    if args.command == "model-doctor":
        model_config = load_model_config_with_overrides(
            env_path=args.env,
            config_path=args.config,
            provider=args.provider,
            model=args.model,
            base_url=args.base_url,
        )
        try:
            provider = ModelProvider(model_config, timeout=args.timeout)
            status = ProviderSmokeRunner(provider, timeout=args.timeout).run_all() if args.connect else ProviderSmokeRunner(provider, timeout=args.timeout).doctor()
        except ModelConfigError as exc:
            status = ProviderSmokeRunner(_UninitializedProvider(model_config), timeout=args.timeout).doctor()
            status.details = str(exc).splitlines()[0]
        except ModelProviderError as exc:
            status = ProviderSmokeRunner(_UninitializedProvider(model_config), timeout=args.timeout).doctor()
            category = classify_provider_error(exc.code, str(exc))
            status.status = category
            status.failure_category = category
            status.connection = "fail"
            status.details = str(exc)
        safe = redact_value(status.to_dict(), [model_config.api_key])
        print(_format_model_doctor(safe))
        return 0 if status.status == "ready" and (not args.connect or status.connection == "pass") else 1

    if args.command == "model-smoke":
        model_config = load_model_config_with_overrides(
            env_path=args.env,
            config_path=args.config,
            provider=args.provider,
            model=args.model,
            base_url=args.base_url,
        )
        try:
            provider = ModelProvider(model_config, timeout=args.timeout)
            status = ProviderSmokeRunner(provider, timeout=args.timeout, max_retries=args.max_retries).run_all()
        except ModelConfigError as exc:
            status = ProviderSmokeRunner(_UninitializedProvider(model_config), timeout=args.timeout).doctor()
            status.details = str(exc).splitlines()[0]
        safe = redact_value(status.to_dict(), [model_config.api_key])
        print(json.dumps(safe, indent=2, sort_keys=True))
        return 0 if status.status == "ready" and status.connection == "pass" and status.tool_calling.supported == "supported" else 1

    if args.command == "binary":
        binary_workspace = _binary_workspace(args.workspace, args.binary_file)
        config = load_round2_config(args.config)
        api = BinaryToolAPI(binary_workspace, config=config)
        if args.binary_command == "analyze":
            result = api.analyze_binary(args.binary_file, force=args.force, allow_fallback=not args.no_fallback)
        elif args.binary_command == "functions":
            result = api.list_functions(args.binary_file)
        elif args.binary_command == "decompile":
            result = api.decompile_function(args.binary_file, args.function)
        else:
            result = {"success": False, "errors": ["unknown binary command"]}
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result.get("success") or args.binary_command == "decompile" else 1

    if args.command == "investigate":
        task_dir = Path(args.workspace) / args.task_id
        dynamic_workspace_exists = any((task_dir / name).exists() for name in ("dynamic", "surface", "taint", "hypotheses"))
        if args.autonomous or dynamic_workspace_exists:
            config = load_dynamic_config(args.config)
            result = InvestigationController(args.workspace, args.task_id, config=config).run(
                resume=args.resume,
                max_iterations=args.max_iterations,
                stop_after_iteration=args.stop_after_iteration,
            )
            print(json.dumps(result, indent=2, sort_keys=True) if args.json else _format_investigation_summary(result))
            return 0 if result.get("success") else 1
        config = load_round2_config(args.config)
        if any(
            value is not None
            for value in (
                args.max_steps,
                args.max_binary_analyses,
                args.max_decompilations_per_binary,
            )
        ):
            config = replace(
                config,
                agent=AgentSettings(
                    max_steps=args.max_steps if args.max_steps is not None else config.agent.max_steps,
                    max_binary_analyses=(
                        args.max_binary_analyses
                        if args.max_binary_analyses is not None
                        else config.agent.max_binary_analyses
                    ),
                    max_decompilations_per_binary=(
                        args.max_decompilations_per_binary
                        if args.max_decompilations_per_binary is not None
                        else config.agent.max_decompilations_per_binary
                    ),
                ),
            )

        try:
            model_config = load_model_config()
            if args.dry_run:
                result = PiAgent(
                    args.workspace,
                    args.task_id,
                    config=config,
                    binary=args.binary,
                    binary_api_workspace=args.tool_workspace,
                ).dry_run(model_config=model_config)
                print(_format_dry_run(result))
                return 0 if result["ready"] else 1
            model_config.require_credentials()
            provider = ModelProvider(model_config)
            agent = PiAgent(
                args.workspace,
                args.task_id,
                config=config,
                model=provider,
                model_info={"provider": model_config.provider, "model": model_config.model},
                binary=args.binary,
                binary_api_workspace=args.tool_workspace,
            )
            result = agent.run()
        except ModelConfigError as exc:
            print("ERROR")
            print(str(exc))
            return 1
        except ModelProviderError as exc:
            print(f"MODEL_ERROR {exc.code}: {exc}")
            return 1
        print(json.dumps(redact_value(result, [model_config.api_key]), indent=2, sort_keys=True))
        return 0 if result.get("success") else 1

    if args.command == "investigate-status":
        config = load_dynamic_config(args.config)
        controller = InvestigationController(args.workspace, args.task_id, config=config)
        state = controller.load_or_create_state().to_dict()
        summary = controller.workspace.load_investigation_artifact("summary.json") or {}
        payload = {"success": True, "state": state, "summary": summary.get("summary", {}), "provider_backed": False}
        print(json.dumps(payload, indent=2, sort_keys=True) if args.json else _format_investigation_status(payload))
        return 0

    if args.command == "investigate-resume":
        config = load_dynamic_config(args.config)
        result = InvestigationController(args.workspace, args.task_id, config=config).run(resume=True, max_iterations=args.max_iterations)
        print(json.dumps(result, indent=2, sort_keys=True) if args.json else _format_investigation_summary(result))
        return 0 if result.get("success") else 1

    if args.command == "investigate-stop":
        config = load_dynamic_config(args.config)
        state = InvestigationController(args.workspace, args.task_id, config=config).stop(args.reason)
        print(json.dumps({"success": True, "state": state, "provider_backed": False}, indent=2, sort_keys=True))
        return 0

    if args.command == "investigate-history":
        config = load_dynamic_config(args.config)
        controller = InvestigationController(args.workspace, args.task_id, config=config)
        history = controller.workspace.load_investigation_artifact("action_history.json") or []
        print(json.dumps(history, indent=2, sort_keys=True) if args.json else _format_investigation_history(history))
        return 0

    if args.command == "investigate-next":
        config = load_dynamic_config(args.config)
        action = InvestigationController(args.workspace, args.task_id, config=config).next_action()
        print(json.dumps(action, indent=2, sort_keys=True) if args.json else _format_investigation_next(action))
        return 0

    if args.command == "emulate":
        config = load_dynamic_config(args.config)
        api = DynamicToolAPI(args.workspace, args.task_id, config=config)
        prepare = api.execute("dynamic.prepare_firmware", {})
        boot = api.execute("dynamic.boot_firmware", {"timeout": args.timeout} if args.timeout else {})
        output = {"prepare": prepare, "boot": boot, "state": api.state.to_dict()}
        print(json.dumps(output, indent=2, sort_keys=True))
        return 0 if boot.get("success") else 1

    if args.command == "emulate-status":
        config = load_dynamic_config(args.config)
        workspace = DynamicWorkspace(args.workspace, args.task_id)
        state = workspace.load_state()
        if state is None:
            print(json.dumps({"success": False, "errors": ["emulation state not found"]}, indent=2))
            return 1
        print(json.dumps(state.to_dict(), indent=2, sort_keys=True))
        return 0

    if args.command == "emulate-stop":
        config = load_dynamic_config(args.config)
        api = DynamicToolAPI(args.workspace, args.task_id, config=config)
        result = api.execute("dynamic.stop_firmware", {})
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result.get("success") else 1

    if args.command == "service-profile":
        config = replace(load_dynamic_config(args.config), backend="service-qemu")
        api = DynamicToolAPI(args.workspace, args.task_id, config=config)
        result = api.execute("dynamic.reconstruct_service_startup", {"binary": args.service})
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result.get("success") else 1

    if args.command == "service-start":
        config = replace(load_dynamic_config(args.config), backend="service-qemu")
        api = DynamicToolAPI(args.workspace, args.task_id, config=config)
        profile = api.execute("dynamic.reconstruct_service_startup", {"binary": args.service})
        prepare = api.execute("dynamic.prepare_service", {"service": args.service})
        start = api.execute(
            "dynamic.start_service",
            {"service": args.service, "stability_seconds": args.stability_seconds},
        )
        ports = api.execute("dynamic.get_service_ports", {"service": args.service}) if start.get("success") else None
        http = api.execute("dynamic.probe_service_http", {"service": args.service}) if ports and ports.get("success") else None
        stop = None if args.keep_running else api.execute("dynamic.stop_service", {"service": args.service})
        output = {"profile": profile, "prepare": prepare, "start": start, "ports": ports, "http": http, "stop": stop}
        print(json.dumps(output, indent=2, sort_keys=True))
        return 0 if start.get("success") else 1

    if args.command == "service-status":
        config = replace(load_dynamic_config(args.config), backend="service-qemu")
        api = DynamicToolAPI(args.workspace, args.task_id, config=config)
        status = api.execute("dynamic.get_service_status", {"service": args.service})
        logs = api.execute("dynamic.get_service_logs", {"service": args.service, "lines": 80})
        ports = api.execute("dynamic.get_service_ports", {"service": args.service})
        print(json.dumps({"status": status, "logs": logs, "ports": ports}, indent=2, sort_keys=True))
        return 0 if status.get("success") else 1

    if args.command == "service-stop":
        config = replace(load_dynamic_config(args.config), backend="service-qemu")
        api = DynamicToolAPI(args.workspace, args.task_id, config=config)
        result = api.execute("dynamic.stop_service", {"service": args.service})
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result.get("success") else 1

    if args.command == "application-inspect":
        config = replace(load_dynamic_config(args.config), backend="service-qemu")
        api = DynamicToolAPI(args.workspace, args.task_id, config=config)
        inspect = api.execute("application.inspect_backend", {"backend": args.backend})
        profile = api.execute("application.get_launch_profile", {"backend": args.backend})
        dependencies = api.execute("application.get_dependencies", {"backend": args.backend})
        output = {"inspect": inspect, "profile": profile, "dependencies": dependencies}
        print(json.dumps(output, indent=2, sort_keys=True))
        return 0 if inspect.get("success") and profile.get("success") else 1

    if args.command == "application-start":
        config = replace(load_dynamic_config(args.config), backend="service-qemu")
        api = DynamicToolAPI(args.workspace, args.task_id, config=config)
        trace = (
            api.execute("application.trace_startup", {"backend": args.backend, "timeout_seconds": 10, "max_events": 2000})
            if args.trace
            else None
        )
        start = api.execute(
            "application.start_backend",
            {"backend": args.backend, "stability_seconds": args.stability_seconds},
        )
        logs = api.execute("application.get_backend_logs", {"backend": args.backend, "lines": 120})
        print(json.dumps({"trace": trace, "start": start, "logs": logs}, indent=2, sort_keys=True))
        return 0 if start.get("success") else 1

    if args.command == "application-endpoints":
        config = replace(load_dynamic_config(args.config), backend="service-qemu")
        api = DynamicToolAPI(args.workspace, args.task_id, config=config)
        result = api.execute("application.list_endpoints", {"backend": args.backend})
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result.get("success") else 1

    if args.command == "application-probe":
        config = replace(load_dynamic_config(args.config), backend="service-qemu")
        api = DynamicToolAPI(args.workspace, args.task_id, config=config)
        result = api.execute("application.probe_endpoint", {"backend": args.backend, "path": args.path, "method": args.method})
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result.get("success") else 1

    if args.command == "fastcgi-context":
        config = replace(load_dynamic_config(args.config), backend="service-qemu")
        api = DynamicToolAPI(args.workspace, args.task_id, config=config)
        standalone = api.execute("dynamic.get_fastcgi_runtime_context", {"backend": args.backend, "mode": "standalone", "timeout_seconds": args.timeout_seconds})
        lighttpd = api.execute("dynamic.get_fastcgi_runtime_context", {"backend": args.backend, "mode": "lighttpd", "timeout_seconds": args.timeout_seconds})
        legacy_diff = api.execute("application.compare_runtime_contexts", {"backend": args.backend})
        graph = api.execute("application.get_startup_graph", {"backend": args.backend})
        output = {"standalone": standalone, "lighttpd": lighttpd, "legacy_diff": legacy_diff, "graph": graph}
        print(json.dumps(output, indent=2, sort_keys=True))
        return 0 if standalone.get("success") and lighttpd.get("success") and legacy_diff.get("success") else 1

    if args.command == "fastcgi-harness":
        config = replace(load_dynamic_config(args.config), backend="service-qemu")
        api = DynamicToolAPI(args.workspace, args.task_id, config=config)
        plan = api.execute("application.build_fastcgi_harness", {"backend": args.backend, "endpoint": args.endpoint})
        result = api.execute(
            "application.start_fastcgi_harness",
            {"backend": args.backend, "endpoint": args.endpoint, "timeout_seconds": args.timeout_seconds},
        )
        latest = api.execute("application.get_fastcgi_result", {"backend": args.backend})
        print(json.dumps({"plan": plan, "result": result, "latest": latest}, indent=2, sort_keys=True))
        return 0 if result.get("success") else 1

    if args.command == "fastcgi-diff":
        config = replace(load_dynamic_config(args.config), backend="service-qemu")
        api = DynamicToolAPI(args.workspace, args.task_id, config=config)
        result = api.execute("dynamic.compare_fastcgi_runtime", {"backend": args.backend})
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result.get("success") else 1

    if args.command == "fastcgi-child-status":
        config = replace(load_dynamic_config(args.config), backend="service-qemu")
        api = DynamicToolAPI(args.workspace, args.task_id, config=config)
        result = api.execute("dynamic.get_fastcgi_child_failure", {"backend": args.backend, "stability_seconds": args.stability_seconds})
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result.get("success") else 1

    if args.command == "fastcgi-integration-validate":
        config = replace(load_dynamic_config(args.config), backend="service-qemu")
        api = DynamicToolAPI(args.workspace, args.task_id, config=config)
        result = api.execute(
            "dynamic.validate_fastcgi_integration",
            {"backend": args.backend, "endpoint": args.endpoint, "stability_seconds": args.stability_seconds},
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result.get("success") else 1

    if args.command == "cleanup":
        result = AnalysisPipelineController(args.workspace).cleanup(args.task_id, all_artifacts=args.all)
        print(json.dumps(result, indent=2, sort_keys=True) if args.json else _format_cleanup(result))
        return 0 if result.get("success") else 1

    if args.command == "dynamic-validate":
        config = load_dynamic_config(args.config)
        try:
            model_config = load_model_config()
            if args.dry_run:
                result = DynamicValidationAgent(
                    args.workspace,
                    args.task_id,
                    config=config,
                    hypothesis_id=args.hypothesis,
                    service=args.service,
                ).dry_run(model_config=model_config)
                print(json.dumps(result, indent=2, sort_keys=True))
                return 0 if result["ready"] else 1
            model_config.require_credentials()
            provider = ModelProvider(model_config)
            agent = DynamicValidationAgent(
                args.workspace,
                args.task_id,
                config=config,
                model=provider,
                model_info={"provider": model_config.provider, "model": model_config.model},
                hypothesis_id=args.hypothesis,
                service=args.service,
            )
            result = agent.run()
        except ModelConfigError as exc:
            print("ERROR")
            print(str(exc))
            return 1
        except ModelProviderError as exc:
            print(f"MODEL_ERROR {exc.code}: {exc}")
            return 1
        print(json.dumps(redact_value(result, [model_config.api_key]), indent=2, sort_keys=True))
        return 0 if result.get("success") else 1

    if args.command == "validate-hypothesis":
        config = replace(load_dynamic_config(args.config), backend="service-qemu")
        try:
            model_config = load_model_config()
            if args.dry_run:
                result = DynamicValidationAgent(
                    args.workspace,
                    args.task_id,
                    config=config,
                    hypothesis_id=args.hypothesis_id,
                    service=args.service,
                ).dry_run(model_config=model_config)
                print(json.dumps(result, indent=2, sort_keys=True))
                return 0 if result["ready"] else 1
            model_config.require_credentials()
            provider = ModelProvider(model_config)
            agent = DynamicValidationAgent(
                args.workspace,
                args.task_id,
                config=config,
                model=provider,
                model_info={"provider": model_config.provider, "model": model_config.model},
                hypothesis_id=args.hypothesis_id,
                service=args.service,
            )
            result = agent.run()
        except ModelConfigError as exc:
            print("ERROR")
            print(str(exc))
            return 1
        except ModelProviderError as exc:
            print(f"MODEL_ERROR {exc.code}: {exc}")
            return 1
        print(_format_validation_summary(redact_value(result, [model_config.api_key])))
        return 0 if result.get("success") else 1

    if args.command == "agent-smoke":
        dynamic_config = replace(load_dynamic_config(args.config), backend="service-qemu")
        model_config = load_model_config(args.env) if not args.model_config else load_model_config_with_overrides(env_path=args.env, config_path=args.model_config)
        try:
            provider = ModelProvider(model_config, timeout=args.timeout)
            smoke = ProviderSmokeRunner(provider, timeout=args.timeout, max_retries=args.max_retries).run_all()
            if smoke.status != "ready" or smoke.connection != "pass" or smoke.tool_calling.supported != "supported":
                output = {"success": False, "provider_backed": False, "model_status": smoke.to_dict()}
                print(json.dumps(redact_value(output, [model_config.api_key]), indent=2, sort_keys=True))
                return 1
            agent = DynamicValidationAgent(
                args.workspace,
                args.task_id,
                config=dynamic_config,
                model=provider,
                model_info={"provider": model_config.provider, "model": model_config.model},
                hypothesis_id=args.hypothesis_id,
            )
            result = agent.run()
        except ModelConfigError as exc:
            print("ERROR")
            print(str(exc))
            return 1
        except ModelProviderError as exc:
            category = classify_provider_error(exc.code, str(exc))
            print(json.dumps({"success": False, "provider_backed": False, "failure_category": category, "error": str(exc)}, indent=2, sort_keys=True))
            return 1
        print(_format_validation_summary(redact_value(result, [model_config.api_key])))
        return 0 if result.get("success") and (result.get("agent_run") or {}).get("provider_backed") else 1

    if args.command == "validation-status":
        config = replace(load_dynamic_config(args.config), backend="service-qemu")
        api = DynamicToolAPI(args.workspace, args.task_id, config=config)
        result = api.execute("dynamic.get_validation_status", {"validation_id": args.validation_id})
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result.get("success") else 1

    if args.command == "validation-report":
        root = Path(args.workspace) / args.task_id / "dynamic" / "validation" / args.validation_id
        artifacts = {}
        for name in ("plan.json", "inputs.json", "observations.json", "differential.json", "evidence.json", "verdict.json"):
            path = root / name
            if path.exists():
                artifacts[name] = json.loads(path.read_text(encoding="utf-8"))
        result = {"success": bool(artifacts), "validation_id": args.validation_id, "artifacts": artifacts}
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if artifacts else 1

    if args.command == "hypotheses":
        config = load_dynamic_config(args.config)
        state = HypothesisValidationScheduler(args.workspace, args.task_id, config=config).assess()
        if args.json:
            print(json.dumps(state, indent=2, sort_keys=True))
        else:
            print(_format_hypotheses_table(state))
        return 0 if state.get("success") else 1

    if args.command == "prioritize":
        config = load_dynamic_config(args.config)
        state = HypothesisValidationScheduler(args.workspace, args.task_id, config=config).assess()
        if args.explain:
            assessment = next((item for item in state.get("assessments", []) if item.get("hypothesis_id") == args.explain), None)
            if assessment is None:
                print(json.dumps({"success": False, "errors": [f"hypothesis not found: {args.explain}"]}, indent=2))
                return 1
            print(json.dumps(assessment, indent=2, sort_keys=True) if args.json else _format_priority_explain(assessment))
        elif args.json:
            print(json.dumps(state, indent=2, sort_keys=True))
        else:
            print(_format_priority_table(state))
        return 0 if state.get("success") else 1

    if args.command == "validation-budget":
        config = load_dynamic_config(args.config)
        state = HypothesisValidationScheduler(args.workspace, args.task_id, config=config).assess()
        budget = state.get("budget") or {}
        if args.json:
            print(json.dumps(budget, indent=2, sort_keys=True))
        else:
            print(_format_budget(budget))
        return 0

    if args.command == "validation-queue":
        config = load_dynamic_config(args.config)
        state = HypothesisValidationScheduler(args.workspace, args.task_id, config=config).assess()
        queue = state.get("queue") or {}
        if args.json:
            print(json.dumps(queue, indent=2, sort_keys=True))
        else:
            print(_format_queue(queue))
        return 0

    if args.command == "validate-next":
        config = load_dynamic_config(args.config)
        state = HypothesisValidationScheduler(args.workspace, args.task_id, config=config).execute_next_mock(verdict_status=args.mock_verdict)
        if args.json:
            print(json.dumps(state, indent=2, sort_keys=True))
        else:
            print(_format_validate_next(state))
        return 0 if state.get("success") else 1

    if args.command == "graph-build":
        config = load_dynamic_config(args.config)
        result = ComponentGraphBuilder(args.workspace, args.task_id, config=config).build()
        print(json.dumps(result, indent=2, sort_keys=True) if args.json else _format_graph_summary(result))
        return 0 if result.get("success") else 1

    if args.command == "graph-summary":
        config = load_dynamic_config(args.config)
        result = ComponentGraphBuilder(args.workspace, args.task_id, config=config).build()
        print(json.dumps(result.get("summary"), indent=2, sort_keys=True) if args.json else _format_graph_summary(result))
        return 0 if result.get("success") else 1

    if args.command == "component":
        config = load_dynamic_config(args.config)
        graph = ComponentGraphBuilder(args.workspace, args.task_id, config=config).load_or_build_graph()
        component_id = graph.resolve_component_id(args.component)
        if not component_id:
            print(json.dumps({"success": False, "errors": [f"component not found: {args.component}"]}, indent=2))
            return 1
        payload = {
            "component": graph.components[component_id].to_dict(),
            "neighbors": [item.to_dict() for item in graph.get_neighbors(component_id)],
            "relationships": [item.to_dict() for item in graph.find_relationships(source_component_id=component_id) + graph.find_relationships(target_component_id=component_id)],
        }
        print(json.dumps(payload, indent=2, sort_keys=True) if args.json else _format_component(payload))
        return 0

    if args.command == "graph-path":
        config = load_dynamic_config(args.config)
        graph = ComponentGraphBuilder(args.workspace, args.task_id, config=config).load_or_build_graph()
        paths = graph.find_paths(args.source, args.target, max_depth=args.max_depth or config.correlation.filtering.max_path_depth)
        payload = {"success": True, "paths": [item.to_dict() for item in paths[:10]], "provider_backed": False}
        print(json.dumps(payload, indent=2, sort_keys=True) if args.json else _format_graph_paths(graph, paths))
        return 0 if paths else 1

    if args.command == "correlation-context":
        config = load_dynamic_config(args.config)
        context = ComponentGraphBuilder(args.workspace, args.task_id, config=config).cross_component_context(
            args.hypothesis_id,
            max_depth=args.max_depth,
            max_nodes=args.max_nodes,
        )
        payload = {"success": True, "context": context.to_dict(), "provider_backed": False}
        print(json.dumps(payload, indent=2, sort_keys=True) if args.json else _format_correlation_context(context.to_dict()))
        return 0 if context.root_component_id else 1

    if args.command == "surface-build":
        config = load_dynamic_config(args.config)
        result = AttackSurfaceBuilder(args.workspace, args.task_id, config=config).build()
        print(json.dumps(result, indent=2, sort_keys=True) if args.json else _format_surface_summary(result.get("summary") or {}))
        return 0 if result.get("success") else 1

    if args.command == "surface-summary":
        config = load_dynamic_config(args.config)
        result = AttackSurfaceBuilder(args.workspace, args.task_id, config=config).load_or_build()
        summary = result.get("summary") or {}
        print(json.dumps(summary, indent=2, sort_keys=True) if args.json else _format_surface_summary(summary))
        return 0

    if args.command == "surface-list":
        config = load_dynamic_config(args.config)
        result = AttackSurfaceBuilder(args.workspace, args.task_id, config=config).load_or_build()
        entries = result.get("entry_points") or []
        print(json.dumps(entries, indent=2, sort_keys=True) if args.json else _format_surface_entries(entries))
        return 0

    if args.command == "surface-entry":
        config = load_dynamic_config(args.config)
        result = AttackSurfaceBuilder(args.workspace, args.task_id, config=config).load_or_build()
        context = next((item for item in result.get("entry_contexts", []) if (item.get("entry_point") or {}).get("entry_id") == args.entry_id), None)
        if context is None:
            print(json.dumps({"success": False, "errors": [f"entry point not found: {args.entry_id}"]}, indent=2))
            return 1
        print(json.dumps(context, indent=2, sort_keys=True) if args.json else _format_surface_entry_context(context))
        return 0

    if args.command == "reachable-from":
        config = load_dynamic_config(args.config)
        result = AttackSurfaceBuilder(args.workspace, args.task_id, config=config).load_or_build()
        reachability = next((item for item in result.get("reachability", []) if item.get("entry_point_id") == args.entry_id), None)
        if reachability is None:
            print(json.dumps({"success": False, "errors": [f"entry reachability not found: {args.entry_id}"]}, indent=2))
            return 1
        print(json.dumps(reachability, indent=2, sort_keys=True) if args.json else _format_reachable_from(reachability))
        return 0

    if args.command == "hypothesis-entry":
        config = load_dynamic_config(args.config)
        result = AttackSurfaceBuilder(args.workspace, args.task_id, config=config).load_or_build()
        mapping = next((item for item in result.get("hypothesis_reachability", []) if item.get("hypothesis_id") == args.hypothesis_id), None)
        if mapping is None:
            print(json.dumps({"success": False, "errors": [f"hypothesis reachability not found: {args.hypothesis_id}"]}, indent=2))
            return 1
        print(json.dumps(mapping, indent=2, sort_keys=True) if args.json else _format_hypothesis_entry(mapping))
        return 0

    if args.command == "taint-build":
        config = load_dynamic_config(args.config)
        result = TaintAnalysisBuilder(args.workspace, args.task_id, config=config).build()
        print(json.dumps(result, indent=2, sort_keys=True) if args.json else _format_taint_summary(result.get("summary") or {}))
        return 0 if result.get("success") else 1

    if args.command == "taint-summary":
        config = load_dynamic_config(args.config)
        result = TaintAnalysisBuilder(args.workspace, args.task_id, config=config).load_or_build()
        summary = result.get("summary") or {}
        print(json.dumps(summary, indent=2, sort_keys=True) if args.json else _format_taint_summary(summary))
        return 0

    if args.command == "taint-sources":
        config = load_dynamic_config(args.config)
        result = TaintAnalysisBuilder(args.workspace, args.task_id, config=config).load_or_build()
        sources = result.get("sources") or []
        print(json.dumps(sources, indent=2, sort_keys=True) if args.json else _format_taint_sources(sources))
        return 0

    if args.command == "taint-sinks":
        config = load_dynamic_config(args.config)
        result = TaintAnalysisBuilder(args.workspace, args.task_id, config=config).load_or_build()
        sinks = result.get("sinks") or []
        print(json.dumps(sinks, indent=2, sort_keys=True) if args.json else _format_taint_sinks(sinks))
        return 0

    if args.command == "taint-paths":
        config = load_dynamic_config(args.config)
        result = TaintAnalysisBuilder(args.workspace, args.task_id, config=config).load_or_build()
        paths = result.get("taint_paths") or []
        print(json.dumps(paths, indent=2, sort_keys=True) if args.json else _format_taint_paths(paths))
        return 0

    if args.command == "taint-hypothesis":
        config = load_dynamic_config(args.config)
        context = TaintAnalysisBuilder(args.workspace, args.task_id, config=config).context(hypothesis_id=args.hypothesis_id)
        payload = context.to_dict()
        print(json.dumps(payload, indent=2, sort_keys=True) if args.json else _format_taint_hypothesis(payload))
        return 0

    if args.command == "taint-path":
        config = load_dynamic_config(args.config)
        result = TaintAnalysisBuilder(args.workspace, args.task_id, config=config).load_or_build()
        path = next((item for item in result.get("taint_paths", []) if item.get("path_id") == args.path_id), None)
        if path is None:
            print(json.dumps({"success": False, "errors": [f"taint path not found: {args.path_id}"]}, indent=2))
            return 1
        print(json.dumps(path, indent=2, sort_keys=True) if args.json else _format_taint_path(path))
        return 0

    if args.command == "synthesize-hypotheses":
        config = load_dynamic_config(args.config)
        result = HypothesisSynthesizer(args.workspace, args.task_id, config=config).build()
        print(json.dumps(result, indent=2, sort_keys=True) if args.json else _format_synthesis_summary(result.get("summary") or {}))
        return 0

    if args.command == "synthesis-summary":
        config = load_dynamic_config(args.config)
        result = HypothesisSynthesizer(args.workspace, args.task_id, config=config).load_or_build()
        print(json.dumps(result.get("summary") or {}, indent=2, sort_keys=True) if args.json else _format_synthesis_summary(result.get("summary") or {}))
        return 0

    if args.command == "hypothesis-candidates":
        config = load_dynamic_config(args.config)
        result = HypothesisSynthesizer(args.workspace, args.task_id, config=config).load_or_build()
        candidates = result.get("candidates") or []
        print(json.dumps(candidates, indent=2, sort_keys=True) if args.json else _format_hypothesis_candidates(candidates))
        return 0

    if args.command == "hypothesis-candidate":
        config = load_dynamic_config(args.config)
        result = HypothesisSynthesizer(args.workspace, args.task_id, config=config).load_or_build()
        candidate = next((item for item in result.get("candidates", []) if item.get("candidate_id") == args.candidate_id), None)
        if candidate is None:
            print(json.dumps({"success": False, "errors": [f"candidate not found: {args.candidate_id}"]}, indent=2))
            return 1
        print(json.dumps(candidate, indent=2, sort_keys=True) if args.json else _format_hypothesis_candidate(candidate))
        return 0

    if args.command == "hypothesis-generated":
        config = load_dynamic_config(args.config)
        result = HypothesisSynthesizer(args.workspace, args.task_id, config=config).load_or_build()
        generated = result.get("canonical_generated") or []
        print(json.dumps(generated, indent=2, sort_keys=True) if args.json else _format_generated_hypotheses(generated))
        return 0

    if args.command == "finding-candidates":
        config = load_dynamic_config(args.config)
        result = HypothesisSynthesizer(args.workspace, args.task_id, config=config).load_or_build()
        findings = result.get("finding_candidates") or []
        print(json.dumps(findings, indent=2, sort_keys=True) if args.json else _format_finding_candidates(findings))
        return 0

    if args.command == "docker-build":
        controller = DockerController()
        try:
            version = controller.ensure_available()
            builds = []
            if args.image in {"static", "all"}:
                builds.append(controller.build_image("firmxplore:latest", "Dockerfile", "."))
            if args.image in {"dynamic", "all"}:
                builds.append(controller.build_image("firmxplore-dynamic:latest", "docker/Dockerfile.dynamic", "."))
        except DockerUnavailableError as exc:
            print(str(exc))
            return 1
        print(json.dumps({"docker": version, "builds": builds}, indent=2, sort_keys=True))
        return 0 if all(item["success"] for item in builds) else 1

    parser.print_help()
    return 1


def _binary_workspace(workspace_root: str | Path, binary_file: str | Path) -> Path:
    binary_path = Path(binary_file).resolve()
    workspace = Path(workspace_root).resolve()
    workspace.mkdir(parents=True, exist_ok=True)
    digest = sha256_file(binary_path)[:8] if binary_path.exists() else uuid.uuid4().hex[:8]
    task_dir = workspace / f"binary-{binary_path.stem}-{digest}"
    task_dir.mkdir(parents=True, exist_ok=True)
    for name in ("ghidra", "logs", "reports", "evidence", "hypotheses"):
        (task_dir / name).mkdir(parents=True, exist_ok=True)
    return task_dir


def _format_dry_run(result: dict) -> str:
    model = result.get("model") or {}
    limits = result.get("limits") or {}
    tools = result.get("tools") or []
    lines = [
        "Agent Validation",
        "",
        f"Task: {result.get('task')}",
        f"Binary: {result.get('binary') or 'not selected'}",
        "",
        "Model:",
        f"provider {'configured' if model.get('provider') else 'missing'}",
        f"model {'configured' if model.get('model') else 'missing'}",
        f"API key {'present' if model.get('api_key_present') else 'missing'}",
        "",
        f"Tools: {len(tools)} registered",
        "",
        "Limits:",
        f"steps={limits.get('steps')}",
        f"binaries={limits.get('binaries')}",
        f"decompilations={limits.get('decompilations')}",
        "",
    ]
    if result.get("errors"):
        lines.append("NOT READY")
        for error in result["errors"]:
            lines.append(f"- {error}")
    else:
        lines.append("READY")
    return "\n".join(lines)


def _format_validation_summary(result: dict) -> str:
    verdict = result.get("validation_verdict") or {}
    hypotheses = result.get("hypotheses") or []
    selected_id = result.get("hypothesis") or verdict.get("hypothesis_id")
    selected = next((item for item in hypotheses if item.get("id") == selected_id), {})
    evidence = result.get("evidence") or []
    trace = result.get("tool_trace") or []
    lines = [
        f"Hypothesis: {selected_id or 'unknown'}",
        f"Static status: {selected.get('static_status') or 'unknown'}",
        f"Dynamic validation: {verdict.get('dynamic_status') or 'not_finalized'}",
        f"Runtime: {result.get('backend')}",
        f"Requests: {sum(1 for item in evidence if item.get('type') in {'baseline_response', 'validation_request'})}",
        f"Evidence: {', '.join(item.get('id', '') for item in evidence[-8:])}",
        f"Verdict: {verdict.get('dynamic_status') or result.get('stop_reason')}",
        f"Steps: {result.get('steps')} Tool calls: {result.get('tool_calls')}",
        f"Stop reason: {result.get('stop_reason')}",
    ]
    if trace:
        lines.append("Tool order: " + " -> ".join(item.get("tool", "") for item in trace))
    return "\n".join(lines)


def _format_hypotheses_table(state: dict) -> str:
    rows = state.get("assessments") or []
    lines = ["Hypothesis  Score  Tier      Runtime              Status"]
    for item in rows:
        status = "blocked" if item.get("blocking_reasons") else "ready"
        lines.append(
            f"{item.get('hypothesis_id',''):<11} {float(item.get('priority_score', 0)):>5.1f}  "
            f"{item.get('priority_tier',''):<9} {item.get('recommended_runtime',''):<20} {status}"
        )
    lines.append("provider_backed=false real_model_validation=deferred")
    return "\n".join(lines)


def _format_priority_table(state: dict) -> str:
    lines = ["Rank  Hypothesis     Score  Runtime              Cost    Status"]
    for index, item in enumerate(state.get("assessments") or [], start=1):
        cost = (item.get("cost_estimate") or {}).get("runtime_complexity") or "unknown"
        status = "blocked" if item.get("blocking_reasons") else "ready"
        lines.append(
            f"{index:<5} {item.get('hypothesis_id',''):<13} {float(item.get('priority_score', 0)):>5.1f}  "
            f"{item.get('recommended_runtime',''):<20} {cost:<7} {status}"
        )
    lines.append(f"Stop: {state.get('stop_reason') or 'not_triggered'}")
    lines.append("Priority is validation priority, not vulnerability severity.")
    lines.append("provider_backed=false real_model_validation=deferred")
    return "\n".join(lines)


def _format_priority_explain(assessment: dict) -> str:
    lines = [
        f"Hypothesis: {assessment.get('hypothesis_id')}",
        f"Evidence quality: {float(assessment.get('static_evidence_score', 0)):.2f}",
        f"Evidence diversity: {float(assessment.get('evidence_diversity_score', 0)):.2f}",
        f"Evidence directness: {float(assessment.get('evidence_directness_score', 0)):.2f}",
        f"Runtime feasibility: {float(assessment.get('runtime_feasibility_score', 0)):.2f}",
        f"Expected information gain: {float(assessment.get('expected_information_gain', 0)):.2f}",
        f"Security relevance: {float(assessment.get('security_relevance_score', 0)):.2f}",
        f"Cost penalty basis: {float(assessment.get('validation_cost_score', 0)):.2f}",
        f"Duplicate penalty: {float(assessment.get('duplicate_penalty', 0)):.2f}",
        f"Dependency penalty: {float(assessment.get('dependency_penalty', 0)):.2f}",
        f"Prior validation penalty: {float(assessment.get('already_validated_penalty', 0)):.2f}",
        f"Safety penalty: {float(assessment.get('safety_penalty', 0)):.2f}",
        f"Final priority: {float(assessment.get('priority_score', 0)):.1f}",
        f"Tier: {assessment.get('priority_tier')}",
        f"Runtime: {assessment.get('recommended_runtime')}",
        f"Strategy: {assessment.get('recommended_strategy')}",
        "",
        "Reason:",
        str(assessment.get("assessment_reason") or ""),
    ]
    blocking = assessment.get("blocking_reasons") or []
    if blocking:
        lines.extend(["", "Blocking reasons:", *[f"- {reason}" for reason in blocking]])
    return "\n".join(lines)


def _format_budget(budget: dict) -> str:
    return "\n".join(
        [
            "Validation Budget",
            f"max_hypotheses: {budget.get('max_hypotheses')}",
            f"max_total_tool_calls: {budget.get('max_total_tool_calls')}",
            f"max_total_requests: {budget.get('max_total_requests')}",
            f"max_total_runtime_seconds: {budget.get('max_total_runtime_seconds')}",
            f"max_runtime_boots: {budget.get('max_runtime_boots')}",
            f"max_repairs: {budget.get('max_repairs')}",
            f"max_failures: {budget.get('max_failures')}",
            f"max_blocked_validations: {budget.get('max_blocked_validations')}",
        ]
    )


def _format_queue(queue: dict) -> str:
    lines = ["Pos  Hypothesis     Score  Runtime              Requests  Tools  Seconds  Status"]
    for item in queue.get("items") or []:
        lines.append(
            f"{item.get('queue_position'):<4} {item.get('hypothesis_id',''):<13} {float(item.get('priority_score', 0)):>5.1f}  "
            f"{item.get('runtime_backend',''):<20} {item.get('allocated_requests'):>8}  "
            f"{item.get('allocated_tool_calls'):>5}  {item.get('allocated_seconds'):>7}  {item.get('queue_status')}"
        )
    lines.append(f"Stop: {queue.get('stop_reason') or 'not_triggered'}")
    lines.append("provider_backed=false")
    return "\n".join(lines)


def _format_validate_next(state: dict) -> str:
    executed = state.get("executed") or {}
    lines = [
        "Deterministic scheduler mock execution",
        f"Executed: {executed.get('hypothesis_id') or 'none'}",
        f"Verdict: {executed.get('verdict_status') or 'none'}",
        f"Evidence: {executed.get('evidence_id') or 'none'}",
        f"provider_backed={str(bool(executed.get('provider_backed'))).lower()}",
        "Re-ranked queue:",
        _format_queue(state.get("queue") or {}),
    ]
    return "\n".join(lines)


def _format_graph_summary(result: dict) -> str:
    summary = result.get("summary") or {}
    lines = [
        "Component Graph Summary",
        f"Components: {summary.get('total_components', 0)}",
        f"Relationships: {summary.get('total_relationships', 0)}",
        f"Static relationships: {summary.get('static_relationships', 0)}",
        f"Dynamic relationships: {summary.get('dynamic_relationships', 0)}",
        f"Evidence correlations: {summary.get('evidence_correlations', 0)}",
        "",
        "Component types:",
    ]
    lines.extend(f"- {key}: {value}" for key, value in (summary.get("component_counts") or {}).items())
    lines.extend(["", "Relationship types:"])
    lines.extend(f"- {key}: {value}" for key, value in (summary.get("relationship_counts") or {}).items())
    paths = summary.get("high_confidence_paths") or []
    if paths:
        lines.extend(["", "Confirmed runtime path:"])
        lines.append(" -> ".join((result_component_id or "") for result_component_id in paths[0].get("component_ids", [])))
    lines.append("provider_backed=false")
    return "\n".join(lines)


def _format_component(payload: dict) -> str:
    component = payload.get("component") or {}
    lines = [
        f"Component: {component.get('component_id')}",
        f"Type: {component.get('component_type')}",
        f"Name: {component.get('name')}",
        f"Path: {component.get('path') or 'n/a'}",
        f"Confidence: {component.get('confidence')}",
        "Relationships:",
    ]
    for relationship in payload.get("relationships") or []:
        lines.append(
            f"- {relationship.get('relationship_id')}: {relationship.get('source_component_id')} "
            f"--{relationship.get('relationship_type')}--> {relationship.get('target_component_id')} "
            f"({relationship.get('status')}, {relationship.get('confidence')})"
        )
    return "\n".join(lines)


def _format_graph_paths(graph, paths: list) -> str:
    if not paths:
        return "No path found"
    lines = []
    for path in paths[:3]:
        lines.append(f"Path: {path.path_id} confidence={path.confidence} reachable={str(path.reachable).lower()}")
        for index, component_id in enumerate(path.component_ids):
            component = graph.components.get(component_id)
            lines.append(component.name if component else component_id)
            if index < len(path.relationship_ids):
                relationship = graph.relationships[path.relationship_ids[index]]
                lines.append(f"  --{relationship.relationship_type}-->")
        lines.append("Evidence: " + ", ".join(path.evidence_ids))
        lines.append("")
    return "\n".join(lines).rstrip()


def _format_correlation_context(context: dict) -> str:
    lines = [
        f"Root: {context.get('root_component_id')}",
        f"Components: {len(context.get('related_components') or [])}",
        f"Relationships: {len(context.get('relationships') or [])}",
        f"Evidence: {', '.join(context.get('evidence_ids') or [])}",
        f"Dynamic evidence: {', '.join(context.get('dynamic_evidence_ids') or [])}",
        f"Config dependencies: {', '.join(context.get('config_dependencies') or []) or 'none'}",
        f"Runtime dependencies: {', '.join(context.get('runtime_dependencies') or []) or 'none'}",
        f"Reachable services: {', '.join(context.get('reachable_services') or []) or 'none'}",
        f"Known blockers: {', '.join(context.get('known_blockers') or []) or 'none'}",
        f"Confidence: {(context.get('confidence_summary') or {}).get('average')}",
        "provider_backed=false",
    ]
    return "\n".join(lines)


def _format_surface_summary(summary: dict) -> str:
    lines = [
        "Attack Surface Summary",
        f"Entries: {summary.get('total_entries', 0)}",
        f"Runtime confirmed: {summary.get('runtime_confirmed_entries', 0)}",
        f"Network/loopback entries: {summary.get('network_entries', 0)}",
        f"Local entries: {summary.get('local_entries', 0)}",
        f"Routes: {summary.get('route_entries', 0)}",
        f"Services: {summary.get('service_entries', 0)}",
        f"Reachable hypotheses: {summary.get('reachable_hypotheses', 0)}",
        f"Blocked hypotheses: {summary.get('blocked_hypotheses', 0)}",
        f"Unknown hypotheses: {summary.get('unknown_hypotheses', 0)}",
        "",
        "Entry priority ranking:",
    ]
    for item in summary.get("entry_priority_ranking") or []:
        lines.append(
            f"- #{item.get('priority_rank')} {item.get('entry_point_id')} "
            f"score={float(item.get('priority_score', 0)):.1f} cost={item.get('validation_cost')}"
        )
    lines.extend(["", "Safety notes:"])
    lines.extend(f"- {note}" for note in summary.get("safety_notes") or [])
    lines.append("Entry priority is validation priority, not vulnerability severity.")
    lines.append("provider_backed=false real_model_validation=deferred")
    return "\n".join(lines)


def _format_surface_entries(entries: list[dict]) -> str:
    lines = ["Entry Points", "ID                                      Type          Scope          Runtime  Target"]
    for entry in entries:
        target = entry.get("path") or entry.get("service") or entry.get("name")
        lines.append(
            f"{entry.get('entry_id',''):<39} {entry.get('entry_type',''):<13} "
            f"{entry.get('exposure_scope',''):<14} {str(bool(entry.get('runtime_confirmed'))).lower():<7} {target}"
        )
    lines.append("provider_backed=false")
    return "\n".join(lines)


def _format_surface_entry_context(context: dict) -> str:
    entry = context.get("entry_point") or {}
    route = context.get("route") or {}
    handler = context.get("handler") or {}
    hypotheses = context.get("reachable_hypotheses") or []
    lines = [
        f"Entry: {entry.get('entry_id')}",
        f"Type: {entry.get('entry_type')} scope={entry.get('exposure_scope')} runtime_confirmed={str(bool(entry.get('runtime_confirmed'))).lower()}",
        f"Protocol: {entry.get('protocol') or 'unknown'} transport={entry.get('transport') or 'unknown'} port={entry.get('port') or 'unknown'}",
        f"Route: {route.get('path') or entry.get('path') or 'n/a'} methods={','.join(route.get('methods') or ['unknown'])}",
        f"Handler: {handler.get('name') or 'unknown'} path={handler.get('path') or 'n/a'}",
        f"Reachable components: {len(context.get('reachable_components') or [])}",
        f"Reachable hypotheses: {', '.join(item.get('hypothesis_id','') for item in hypotheses) or 'none'}",
        f"Evidence: {', '.join(entry.get('evidence_ids') or [])}",
        "REACHABLE != EXPLOITABLE",
        "provider_backed=false",
    ]
    return "\n".join(lines)


def _format_reachable_from(reachability: dict) -> str:
    lines = [
        f"Entry: {reachability.get('entry_point_id')}",
        f"State: {reachability.get('state')}",
        f"Runtime confirmed: {str(bool(reachability.get('runtime_confirmed'))).lower()}",
        f"Entry distance: {reachability.get('entry_distance')}",
        f"Confidence: {reachability.get('confidence')}",
        "Components:",
    ]
    lines.extend(f"- {component_id}" for component_id in reachability.get("reachable_component_ids") or [])
    blocker = reachability.get("blocking_reason")
    if blocker:
        lines.extend(["Blocking reason:", f"- {blocker}"])
    lines.append("provider_backed=false")
    return "\n".join(lines)


def _format_hypothesis_entry(mapping: dict) -> str:
    lines = [
        f"Hypothesis: {mapping.get('hypothesis_id')}",
        f"State: {mapping.get('state')}",
        f"Reachable: {str(bool(mapping.get('reachable'))).lower()}",
        f"Network exposed: {str(bool(mapping.get('network_exposed'))).lower()}",
        f"Runtime confirmed: {str(bool(mapping.get('runtime_confirmed'))).lower()}",
        f"Entry reachability score: {float(mapping.get('entry_reachability_score', 0)):.2f}",
        f"Entry distance: {mapping.get('entry_distance')}",
        f"Entries: {', '.join(mapping.get('entry_point_ids') or []) or 'none'}",
        f"Scopes: {', '.join(mapping.get('exposure_scopes') or []) or 'unknown'}",
        f"Evidence: {', '.join(mapping.get('evidence_ids') or [])}",
        "EXPOSED != VULNERABLE; REACHABLE != EXPLOITABLE",
        "provider_backed=false real_model_validation=deferred",
    ]
    if mapping.get("blocking_reason"):
        lines.insert(-2, f"Blocking reason: {mapping.get('blocking_reason')}")
    return "\n".join(lines)


def _format_taint_summary(summary: dict) -> str:
    lines = [
        "Taint Analysis Summary",
        f"Sources: {summary.get('sources', 0)}",
        f"Sinks: {summary.get('sinks', 0)}",
        f"Candidate paths: {summary.get('candidate_paths', 0)}",
        f"Supported paths: {summary.get('supported_paths', 0)}",
        f"Runtime-supported paths: {summary.get('runtime_supported_paths', 0)}",
        f"Paths with sanitizers: {summary.get('paths_with_sanitizers', 0)}",
        f"Unknown paths: {summary.get('unknown_paths', 0)}",
        f"High-priority investigation paths: {summary.get('high_priority_paths', 0)}",
        "",
        "Source types:",
    ]
    lines.extend(f"- {key}: {value}" for key, value in (summary.get("source_types") or {}).items())
    lines.extend(["", "Sink types:"])
    lines.extend(f"- {key}: {value}" for key, value in (summary.get("sink_types") or {}).items())
    lines.extend(["", "Safety notes:"])
    lines.extend(f"- {note}" for note in summary.get("safety_notes") or [])
    lines.append("provider_backed=false real_model_validation=deferred")
    return "\n".join(lines)


def _format_taint_sources(sources: list[dict]) -> str:
    lines = ["Input Sources", "ID                         Type              Entry                                  Runtime  Parameter"]
    for source in sources:
        lines.append(
            f"{source.get('source_id',''):<26} {source.get('source_type',''):<17} "
            f"{source.get('entry_point_id') or 'n/a':<38} {str(bool(source.get('runtime_confirmed'))).lower():<7} "
            f"{source.get('parameter_name') or 'n/a'}"
        )
    lines.append("provider_backed=false")
    return "\n".join(lines)


def _format_taint_sinks(sinks: list[dict]) -> str:
    lines = ["Sensitive Sinks", "ID                                      Type                Function        Relevance  Confidence"]
    for sink in sinks:
        lines.append(
            f"{sink.get('sink_id',''):<39} {sink.get('sink_type',''):<19} "
            f"{sink.get('callee_name') or sink.get('function_name') or 'n/a':<15} "
            f"{float(sink.get('security_relevance', 0)):<9.2f} {float(sink.get('confidence', 0)):.2f}"
        )
    lines.append("Sink presence is not vulnerability confirmation.")
    lines.append("provider_backed=false")
    return "\n".join(lines)


def _format_taint_paths(paths: list[dict]) -> str:
    lines = ["Taint Paths", "ID                                      State                 Confidence  Runtime  Source -> Sink"]
    for path in paths:
        lines.append(
            f"{path.get('path_id',''):<39} {path.get('path_state',''):<21} "
            f"{float(path.get('confidence', 0)):<10.2f} {str(bool(path.get('runtime_supported'))).lower():<7} "
            f"{path.get('source_id')} -> {path.get('sink_id')}"
        )
    lines.append("CALL PATH != DATA FLOW; REACHABLE SINK != EXPLOITABLE SINK")
    lines.append("provider_backed=false")
    return "\n".join(lines)


def _format_taint_hypothesis(context: dict) -> str:
    lines = [
        f"Hypothesis: {context.get('hypothesis_id')}",
        f"Conclusion: {context.get('conclusion')}",
        "",
        "Sources:",
    ]
    for source in context.get("sources") or []:
        lines.append(f"- {source.get('source_id')}: {source.get('source_type')} ({source.get('parameter_name') or 'n/a'})")
    lines.append("Sensitive sinks:")
    for sink in context.get("sinks") or []:
        lines.append(f"- {sink.get('sink_id')}: {sink.get('sink_type')} {sink.get('callee_name') or sink.get('function_name')}")
    lines.append("Paths:")
    for path in context.get("paths") or []:
        lines.append(f"- {path.get('path_id')}: {path.get('path_state')} confidence={path.get('confidence')} runtime_sink_confirmed={str(bool(path.get('runtime_sink_confirmed'))).lower()}")
    lines.extend(
        [
            f"Functions: {', '.join(context.get('functions') or []) or 'none'}",
            "SOURCE + SINK != VULNERABILITY",
            "provider_backed=false real_model_validation=deferred",
        ]
    )
    return "\n".join(lines)


def _format_taint_path(path: dict) -> str:
    lines = [
        f"Path: {path.get('path_id')}",
        f"State: {path.get('path_state')}",
        f"Evidence level: {path.get('evidence_level')}",
        f"Confidence: {path.get('confidence')}",
        f"Runtime handler/path support: {str(bool(path.get('runtime_supported'))).lower()}",
        f"Runtime sink confirmed: {str(bool(path.get('runtime_sink_confirmed'))).lower()}",
        f"Source: {path.get('source_id')}",
        f"Sink: {path.get('sink_id')}",
        f"Function chain: {' -> '.join(path.get('function_chain') or [])}",
        f"Evidence: {', '.join(path.get('evidence_ids') or [])}",
        "Validated means data-flow evidence validation, not vulnerability confirmation.",
        "provider_backed=false",
    ]
    return "\n".join(lines)


def _format_synthesis_summary(summary: dict) -> str:
    lines = [
        "Hypothesis Synthesis Summary",
        f"Candidates: {summary.get('candidate_count', 0)}",
        f"Promoted: {summary.get('promoted_count', 0)}",
        f"Deduplicated: {summary.get('deduplicated_count', 0)}",
        f"Rejected by gate: {summary.get('rejected_by_gate', 0)}",
        f"Weak/deferred candidates: {summary.get('weak_candidate_count', 0)}",
        f"Supported candidates: {summary.get('supported_count', 0)}",
        f"Runtime-supported candidates: {summary.get('runtime_supported_count', 0)}",
        f"Finding candidates: {summary.get('finding_candidate_count', 0)}",
        "",
        "Top candidates:",
    ]
    for item in summary.get("top_candidates") or []:
        lines.append(
            f"- {item.get('candidate_id')}: {item.get('hypothesis_type')} "
            f"{item.get('support_level')} confidence={item.get('confidence')}"
        )
    lines.extend(["", "Candidate != Vulnerability", "provider_backed=false real_model_validation=deferred"])
    return "\n".join(lines)


def _format_hypothesis_candidates(candidates: list[dict]) -> str:
    lines = ["Hypothesis Candidates"]
    for item in candidates:
        lines.append(
            f"- {item.get('candidate_id')}: {item.get('hypothesis_type')} "
            f"{item.get('support_level')} confidence={item.get('confidence')} title={item.get('title')}"
        )
    lines.append("Supported Hypothesis != Confirmed Exploit")
    lines.append("provider_backed=false")
    return "\n".join(lines)


def _format_hypothesis_candidate(candidate: dict) -> str:
    return "\n".join(
        [
            f"Candidate: {candidate.get('candidate_id')}",
            f"Type: {candidate.get('hypothesis_type')}",
            f"Support: {candidate.get('support_level')}",
            f"Confidence: {candidate.get('confidence')}",
            f"Claim: {candidate.get('claim')}",
            f"Sources: {', '.join(candidate.get('source_ids') or []) or 'none'}",
            f"Sinks: {', '.join(candidate.get('sink_ids') or []) or 'none'}",
            f"Paths: {', '.join(candidate.get('taint_path_ids') or []) or 'none'}",
            f"Existing overlap: {', '.join(candidate.get('existing_hypothesis_ids') or []) or 'none'}",
            f"Missing evidence: {', '.join(candidate.get('missing_evidence') or []) or 'none'}",
            f"Validation goal: {candidate.get('validation_goal')}",
            f"Strategy: {candidate.get('validation_strategy')}",
            "Candidate != Vulnerability",
            "provider_backed=false",
        ]
    )


def _format_generated_hypotheses(generated: list[dict]) -> str:
    lines = ["Generated Canonical Hypothesis Records"]
    for item in generated:
        lines.append(f"- {item.get('id')}: {item.get('status')} confidence={item.get('confidence')} derived={', '.join(item.get('derived_candidate_ids') or [])}")
    lines.append("Generated records preserve evidence gates and do not confirm exploits.")
    lines.append("provider_backed=false")
    return "\n".join(lines)


def _format_finding_candidates(findings: list[dict]) -> str:
    lines = ["Finding Candidates"]
    for item in findings:
        lines.append(
            f"- {item.get('finding_candidate_id')}: {item.get('status')} "
            f"{item.get('security_category')} confidence={item.get('confidence')} title={item.get('title')}"
        )
    lines.append("FindingCandidate != Final Finding")
    lines.append("provider_backed=false")
    return "\n".join(lines)


def _format_investigation_summary(result: dict) -> str:
    state = result.get("state") or {}
    summary = result.get("summary") or {}
    budget = result.get("budget_state") or {}
    priority = (result.get("priority") or {}).get("assessments") or []
    top = priority[0] if priority else {}
    return "\n".join(
        [
            f"Investigation: {state.get('investigation_id')}",
            f"Phase: {state.get('phase')}",
            f"Status: {state.get('status')}",
            f"Iteration: {state.get('iteration')} / {((result.get('budget') or {}).get('max_iterations') or '?')}",
            f"Top hypothesis: {top.get('hypothesis_id') or 'none'}",
            f"Budget: requests {budget.get('requests_used', 0)}/{((result.get('budget') or {}).get('max_total_requests') or 0)}, tool calls {budget.get('tool_calls_used', 0)}/{((result.get('budget') or {}).get('max_total_tool_calls') or 0)}",
            f"Hypotheses generated: {summary.get('hypotheses_generated', 0)}",
            f"Hypotheses validated: {summary.get('hypotheses_validated', 0)}",
            f"Stop reason: {state.get('stop_reason') or summary.get('stop_reason') or 'none'}",
            "Mock verdicts stay in simulation; canonical updates require real evidence guard.",
            "provider_backed=false real_model_validation=deferred",
        ]
    )


def _format_investigation_status(payload: dict) -> str:
    state = payload.get("state") or {}
    summary = payload.get("summary") or {}
    budget = state.get("budget_state") or {}
    return "\n".join(
        [
            f"Investigation: {state.get('investigation_id')}",
            f"Phase: {state.get('phase')}",
            f"Status: {state.get('status')}",
            f"Iteration: {state.get('iteration')}",
            f"Active hypothesis: {state.get('active_hypothesis_id') or 'none'}",
            f"Active validation: {state.get('active_validation_id') or 'none'}",
            f"Budget used: requests {budget.get('requests_used', 0)}, tool calls {budget.get('tool_calls_used', 0)}, validations {budget.get('validations_used', 0)}",
            f"Stop reason: {state.get('stop_reason') or summary.get('stop_reason') or 'none'}",
            "provider_backed=false",
        ]
    )


def _format_investigation_history(history: list[dict]) -> str:
    lines = ["Investigation History"]
    for item in history:
        lines.append(
            f"- Iteration {item.get('iteration')} {item.get('phase')} {item.get('action')} "
            f"target={item.get('target') or 'none'} result={item.get('result')} reason={item.get('reason')}"
        )
    lines.append("No private chain-of-thought is stored.")
    lines.append("provider_backed=false")
    return "\n".join(lines)


def _format_investigation_next(action: dict) -> str:
    return "\n".join(
        [
            f"Next action: {action.get('action')}",
            f"Target: {action.get('target') or 'none'}",
            f"Reason: {action.get('reason')}",
            "Controller must still validate budget, safety, phase, and canonical state permissions.",
            "provider_backed=false",
        ]
    )


def _format_pipeline_summary(result: dict) -> str:
    task = result.get("task") or {}
    findings = result.get("findings") or {}
    reports = result.get("report_paths") or {}
    duration = result.get("duration") or {}
    platform = result.get("platform") or {}
    lines = [
        f"FirmXplore v{__version__}",
        "",
        "FirmXplore Analysis Complete" if result.get("success") else "FirmXplore Analysis Failed",
        "",
        f"Task: {result.get('task_id') or task.get('task_id') or 'unknown'}",
        f"Firmware: {task.get('firmware_name') or 'unknown'}",
        f"Architecture: {platform.get('architecture') or platform.get('primary_architecture') or 'unknown'}",
        f"Status: {result.get('analysis_status') or result.get('status') or 'unknown'}",
        f"Findings: {findings.get('findings', 0)}",
        f"Supported: {findings.get('supported', 0)}",
        f"Candidate/Inconclusive: {findings.get('candidate_or_inconclusive', 0)}",
        f"Runtime-confirmed: {findings.get('runtime_supported', 0)}",
        f"Blocked validations: {findings.get('blocked', 0)}",
        f"Investigation iterations: {result.get('investigation_iterations', 0)}",
        f"Final stop reason: {result.get('final_stop_reason')}",
        "",
        "Reports:",
        f"HTML: {reports.get('html', 'not generated')}",
        f"Markdown: {reports.get('md', 'not generated')}",
        f"JSON: {reports.get('json', 'not generated')}",
        "",
        "Provider:",
        "deterministic",
        "provider_backed=false",
        "Real model validation: deferred",
        f"Duration: {duration.get('total', 0)}s",
    ]
    if result.get("errors"):
        lines.extend(["", "Blockers / Partial Issues:"])
        for error in result.get("errors") or []:
            lines.append(f"- {error.get('code')}: {error.get('message')}")
    return "\n".join(lines)


def _format_final_report_summary(report: dict) -> str:
    summary = report.get("summary") or {}
    metadata = report.get("metadata") or {}
    return "\n".join(
        [
            "FirmXplore Final Report",
            f"Task: {report.get('task_id') or metadata.get('task_id')}",
            f"Status: {report.get('analysis_status')}",
            f"Findings: {summary.get('findings', 0)}",
            f"Supported: {summary.get('supported', 0)}",
            f"Candidate/Inconclusive: {summary.get('candidate_or_inconclusive', 0)}",
            "HTML: reports/report.html",
            "Provider: deterministic",
            "provider_backed=false",
        ]
    )


def _format_report_regeneration(result: dict) -> str:
    reports = result.get("report_paths") or {}
    return "\n".join(
        [
            "Report regenerated",
            f"Task: {result.get('task_id')}",
            f"HTML: {reports.get('html', 'not generated')}",
            f"Markdown: {reports.get('md', 'not generated')}",
            f"JSON: {reports.get('json', 'not generated')}",
            f"Artifact manifest: {result.get('artifact_manifest')}",
            "provider_backed=false",
        ]
    )


def _format_task_status(result: dict) -> str:
    task = result.get("task") or {}
    reports = result.get("reports") or {}
    return "\n".join(
        [
            f"Task: {task.get('task_id') or 'missing'}",
            f"Pipeline phase: {result.get('pipeline_phase')}",
            f"Investigation phase: {result.get('investigation_phase')}",
            f"Findings: {result.get('findings', 0)}",
            f"Reports: {', '.join(sorted(reports.values())) if reports else 'none'}",
            f"Resume available: {str(result.get('resume_available', False)).lower()}",
            f"Blockers: {result.get('blockers') or 'none'}",
            "provider_backed=false",
        ]
    )


def _format_cleanup(result: dict) -> str:
    if not result.get("success"):
        return f"Cleanup failed: {result.get('error')}"
    if result.get("removed_task"):
        return "Cleanup complete: task directory removed"
    return "\n".join(
        [
            "Cleanup complete",
            f"Removed: {', '.join(result.get('removed') or []) or 'none'}",
            f"Canonical preserved: {str(result.get('canonical_preserved', False)).lower()}",
            "provider_backed=false",
        ]
    )


class _UninitializedProvider:
    def __init__(self, config):
        self.config = config

    def chat(self, messages, *, max_tokens=256, temperature=0.0):
        raise ModelProviderError("MODEL_CONFIG_MISSING", "provider is not initialized")


def _format_model_doctor(status: dict) -> str:
    metadata = status.get("metadata") or {}
    tool = status.get("tool_calling") or {}
    lines = [
        "FirmXplore Model Provider Check",
        "",
        f"Provider: {status.get('provider') or 'missing'}",
        f"Model: {status.get('model') or 'missing'}",
        f"Credentials: {'configured' if status.get('credentials_configured') else 'missing'}",
        f"Endpoint: {'configured' if status.get('endpoint_configured') else 'missing'}",
        f"Endpoint type: {metadata.get('endpoint_type') or 'unknown'}",
        f"Connection: {status.get('connection')}",
        f"Structured output: {status.get('structured_output')}",
        f"Tool Calling: {tool.get('supported')}",
        f"Failure category: {status.get('failure_category') or 'none'}",
        f"Status: {status.get('status')}",
    ]
    if status.get("details"):
        lines.extend(["", f"Details: {status.get('details')}"])
    return "\n".join(lines)


if __name__ == "__main__":
    sys.exit(main())
