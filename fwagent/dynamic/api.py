from __future__ import annotations

import json
import re
import socket
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from fwagent.dynamic.backend import EmulationBackend, create_backend
from fwagent.dynamic.config import DynamicConfig, load_dynamic_config
from fwagent.dynamic.correlation import ComponentGraphBuilder, ComponentGraph
from fwagent.dynamic.models import (
    CANONICAL_RUNTIME_OBSERVATION_TYPES,
    DYNAMIC_EVIDENCE_TYPES,
    VALID_DYNAMIC_HYPOTHESIS_STATUSES,
    DynamicEvidence,
    DynamicHypothesis,
    EmulationState,
)
from fwagent.dynamic.investigation import InvestigationController
from fwagent.dynamic.prioritization import HypothesisValidationScheduler
from fwagent.dynamic.surface import AttackSurfaceBuilder
from fwagent.dynamic.synthesis import HypothesisSynthesizer
from fwagent.dynamic.taint import TaintAnalysisBuilder
from fwagent.dynamic.validation import (
    BehaviorObservation,
    DynamicValidationPlan,
    SafeValidationInput,
    build_static_dynamic_context,
    compare_behavior,
    decide_verdict,
    default_safe_inputs,
    response_signature,
    validate_safe_input,
)
from fwagent.dynamic.workspace import DynamicWorkspace
from fwagent.runtime.command import CommandRunner
from fwagent.runtime.execution_policy import BLOCK_CODE, blocked_execution


HTTP_MAX_BODY_BYTES = 64 * 1024
PORT_SCAN_TARGETS = (22, 23, 53, 80, 443, 8080, 1900)
PRIVATE_NETWORK_PREFIXES = ("127.", "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.30.", "172.31.")


@dataclass
class DynamicToolSpec:
    name: str
    description: str
    arguments_schema: dict[str, dict[str, Any]]
    handler: Callable[[dict[str, Any]], dict[str, Any]]


class DynamicToolAPI:
    def __init__(
        self,
        workspace_root: str | Path,
        task_id: str,
        *,
        config: DynamicConfig | None = None,
        backend: EmulationBackend | None = None,
    ):
        self.workspace = DynamicWorkspace(workspace_root, task_id)
        self.config = config or load_dynamic_config()
        self.backend = backend or create_backend(self.config, self.workspace.task_dir)
        self.runner = CommandRunner(self.workspace.logs_dir)
        self.evidence = self.workspace.load_evidence()
        self.hypotheses = self.workspace.load_hypotheses()
        self.state = self.workspace.load_state() or EmulationState(backend=self.backend.name)
        self.tools = self._build_tools()
        self.http_requests = 0
        self.port_probes = 0
        self.log_reads = 0
        self.actions = 0
        self._seed_hypotheses_from_static()

    def execute(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        spec = self.tools.get(name)
        if spec is None:
            return {"success": False, "tool": name, "errors": [f"unknown tool: {name}"]}
        if self.actions >= self.config.validation.max_tool_calls:
            return {"success": False, "tool": name, "errors": ["max_tool_calls reached"]}
        normalized = self._normalize(spec, args)
        errors = self._validate(spec, normalized)
        if errors:
            return {"success": False, "tool": name, "errors": errors}
        self.actions += 1
        return spec.handler(normalized)

    def _build_tools(self) -> dict[str, DynamicToolSpec]:
        return {
            "dynamic.prepare_firmware": DynamicToolSpec(
                "dynamic.prepare_firmware",
                "Prepare the firmware image in the dynamic workspace.",
                {},
                self._prepare_firmware,
            ),
            "dynamic.boot_firmware": DynamicToolSpec(
                "dynamic.boot_firmware",
                "Boot the firmware with the configured emulation backend.",
                {"timeout": {"type": "number", "required": False}},
                self._boot_firmware,
            ),
            "dynamic.get_emulation_status": DynamicToolSpec(
                "dynamic.get_emulation_status",
                "Return the current emulation state.",
                {},
                self._get_emulation_status,
            ),
            "dynamic.stop_firmware": DynamicToolSpec(
                "dynamic.stop_firmware",
                "Stop the emulation and clean up runtime resources.",
                {},
                self._stop_firmware,
            ),
            "dynamic.list_processes": DynamicToolSpec(
                "dynamic.list_processes",
                "List processes observed in the emulation runtime.",
                {},
                self._list_processes,
            ),
            "dynamic.list_open_ports": DynamicToolSpec(
                "dynamic.list_open_ports",
                "List open TCP/UDP ports on the emulated network.",
                {},
                self._list_open_ports,
            ),
            "dynamic.list_services": DynamicToolSpec(
                "dynamic.list_services",
                "List services inferred from running processes.",
                {},
                self._list_services,
            ),
            "dynamic.get_runtime_logs": DynamicToolSpec(
                "dynamic.get_runtime_logs",
                "Return bounded runtime logs from the emulation backend.",
                {"lines": {"type": "number", "required": False}},
                self._get_runtime_logs,
            ),
            "dynamic.probe_http": DynamicToolSpec(
                "dynamic.probe_http",
                "Send a bounded HTTP request to an emulated service.",
                {
                    "url": {"type": "string", "required": True},
                    "method": {"type": "string", "required": False},
                },
                self._probe_http,
            ),
            "dynamic.probe_tcp": DynamicToolSpec(
                "dynamic.probe_tcp",
                "Probe TCP connectivity to a port on the emulated network.",
                {
                    "host": {"type": "string", "required": True},
                    "port": {"type": "number", "required": True},
                },
                self._probe_tcp,
            ),
            "dynamic.check_process": DynamicToolSpec(
                "dynamic.check_process",
                "Check whether a process matching a name or command is running.",
                {"query": {"type": "string", "required": True}},
                self._check_process,
            ),
            "dynamic.reconstruct_service_startup": DynamicToolSpec(
                "dynamic.reconstruct_service_startup",
                "Reconstruct firmware service startup arguments and config from the rootfs.",
                {"binary": {"type": "string", "required": True}},
                self._reconstruct_service_startup,
            ),
            "dynamic.prepare_service": DynamicToolSpec(
                "dynamic.prepare_service",
                "Prepare a controlled service runtime rootfs.",
                {"service": {"type": "string", "required": True}},
                self._prepare_service,
            ),
            "dynamic.start_service": DynamicToolSpec(
                "dynamic.start_service",
                "Start one firmware service under the controlled QEMU service backend.",
                {
                    "service": {"type": "string", "required": True},
                    "stability_seconds": {"type": "number", "required": False},
                },
                self._start_service,
            ),
            "dynamic.get_service_status": DynamicToolSpec(
                "dynamic.get_service_status",
                "Return current service runtime state.",
                {"service": {"type": "string", "required": True}},
                self._get_service_status,
            ),
            "dynamic.get_service_logs": DynamicToolSpec(
                "dynamic.get_service_logs",
                "Return bounded service stdout/stderr logs.",
                {
                    "service": {"type": "string", "required": True},
                    "lines": {"type": "number", "required": False},
                },
                self._get_service_logs,
            ),
            "dynamic.get_service_ports": DynamicToolSpec(
                "dynamic.get_service_ports",
                "Observe listening ports for a service.",
                {"service": {"type": "string", "required": True}},
                self._get_service_ports,
            ),
            "dynamic.probe_service_http": DynamicToolSpec(
                "dynamic.probe_service_http",
                "Probe the reconstructed HTTP endpoint for a running service.",
                {"service": {"type": "string", "required": True}},
                self._probe_service_http,
            ),
            "dynamic.stop_service": DynamicToolSpec(
                "dynamic.stop_service",
                "Stop one managed service runtime.",
                {"service": {"type": "string", "required": True}},
                self._stop_service,
            ),
            "dynamic.get_boot_progress": DynamicToolSpec(
                "dynamic.get_boot_progress",
                "Parse whole-system QEMU console progress into deterministic boot stages.",
                {},
                self._get_boot_progress,
            ),
            "application.inspect_backend": DynamicToolSpec(
                "application.inspect_backend",
                "Inspect a firmware application backend binary with bounded deterministic analysis.",
                {"backend": {"type": "string", "required": False}},
                self._application_inspect_backend,
            ),
            "application.get_dependencies": DynamicToolSpec(
                "application.get_dependencies",
                "Return the reconstructed dependency graph for an application backend.",
                {"backend": {"type": "string", "required": False}},
                self._application_get_dependencies,
            ),
            "application.get_launch_profile": DynamicToolSpec(
                "application.get_launch_profile",
                "Return the reconstructed FastCGI launch profile for an application backend.",
                {"backend": {"type": "string", "required": False}},
                self._application_get_launch_profile,
            ),
            "application.trace_startup": DynamicToolSpec(
                "application.trace_startup",
                "Run a bounded startup syscall trace for an application backend through the parent service.",
                {
                    "backend": {"type": "string", "required": False},
                    "timeout_seconds": {"type": "number", "required": False},
                    "max_events": {"type": "number", "required": False},
                },
                self._application_trace_startup,
            ),
            "application.start_backend": DynamicToolSpec(
                "application.start_backend",
                "Attempt original FastCGI backend startup through lighttpd without disabling the backend.",
                {
                    "backend": {"type": "string", "required": False},
                    "stability_seconds": {"type": "number", "required": False},
                },
                self._application_start_backend,
            ),
            "application.get_backend_status": DynamicToolSpec(
                "application.get_backend_status",
                "Return the latest structured application backend startup state.",
                {"backend": {"type": "string", "required": False}},
                self._application_get_backend_status,
            ),
            "application.get_backend_logs": DynamicToolSpec(
                "application.get_backend_logs",
                "Return bounded application backend startup logs.",
                {
                    "backend": {"type": "string", "required": False},
                    "lines": {"type": "number", "required": False},
                },
                self._application_get_backend_logs,
            ),
            "application.get_direct_context": DynamicToolSpec(
                "application.get_direct_context",
                "Capture direct backend execution context with bounded qemu-user trace.",
                {"backend": {"type": "string", "required": False}},
                self._application_get_direct_context,
            ),
            "application.get_fastcgi_context": DynamicToolSpec(
                "application.get_fastcgi_context",
                "Capture lighttpd FastCGI child context with bounded qemu-user trace.",
                {"backend": {"type": "string", "required": False}},
                self._application_get_fastcgi_context,
            ),
            "application.compare_runtime_contexts": DynamicToolSpec(
                "application.compare_runtime_contexts",
                "Compare direct exec context against lighttpd FastCGI child context.",
                {"backend": {"type": "string", "required": False}},
                self._application_compare_contexts,
            ),
            "application.trace_backend_startup": DynamicToolSpec(
                "application.trace_backend_startup",
                "Alias for bounded FastCGI backend startup tracing.",
                {
                    "backend": {"type": "string", "required": False},
                    "timeout_seconds": {"type": "number", "required": False},
                    "max_events": {"type": "number", "required": False},
                },
                self._application_trace_startup,
            ),
            "application.get_startup_graph": DynamicToolSpec(
                "application.get_startup_graph",
                "Return deterministic backend startup stage observations.",
                {"backend": {"type": "string", "required": False}},
                self._application_get_startup_graph,
            ),
            "application.build_fastcgi_harness": DynamicToolSpec(
                "application.build_fastcgi_harness",
                "Return the reconstructed standalone FastCGI harness plan.",
                {"backend": {"type": "string", "required": False}},
                self._application_build_fastcgi_harness,
            ),
            "application.start_fastcgi_harness": DynamicToolSpec(
                "application.start_fastcgi_harness",
                "Start a minimal standalone FastCGI harness and observe the backend.",
                {
                    "backend": {"type": "string", "required": False},
                    "endpoint": {"type": "string", "required": False},
                    "timeout_seconds": {"type": "number", "required": False},
                },
                self._application_start_fastcgi_harness,
            ),
            "application.send_fastcgi_request": DynamicToolSpec(
                "application.send_fastcgi_request",
                "Run the harness with one benign reconstructed FastCGI request.",
                {
                    "backend": {"type": "string", "required": False},
                    "endpoint": {"type": "string", "required": False},
                },
                self._application_start_fastcgi_harness,
            ),
            "application.get_fastcgi_result": DynamicToolSpec(
                "application.get_fastcgi_result",
                "Return the latest standalone FastCGI harness result.",
                {"backend": {"type": "string", "required": False}},
                self._application_get_fastcgi_result,
            ),
            "dynamic.get_fastcgi_runtime_context": DynamicToolSpec(
                "dynamic.get_fastcgi_runtime_context",
                "Return a structured standalone or lighttpd FastCGI runtime snapshot.",
                {
                    "backend": {"type": "string", "required": False},
                    "mode": {"type": "string", "required": False},
                    "timeout_seconds": {"type": "number", "required": False},
                },
                self._get_fastcgi_runtime_context,
            ),
            "dynamic.compare_fastcgi_runtime": DynamicToolSpec(
                "dynamic.compare_fastcgi_runtime",
                "Compare standalone FastCGI harness runtime against lighttpd-managed runtime.",
                {"backend": {"type": "string", "required": False}},
                self._compare_fastcgi_runtime,
            ),
            "dynamic.get_fastcgi_child_failure": DynamicToolSpec(
                "dynamic.get_fastcgi_child_failure",
                "Return evidence-driven classification for lighttpd FastCGI child failure.",
                {
                    "backend": {"type": "string", "required": False},
                    "stability_seconds": {"type": "number", "required": False},
                },
                self._get_fastcgi_child_failure,
            ),
            "dynamic.validate_fastcgi_integration": DynamicToolSpec(
                "dynamic.validate_fastcgi_integration",
                "Validate lighttpd-to-FastCGI integration with a controlled runtime parity repair.",
                {
                    "backend": {"type": "string", "required": False},
                    "endpoint": {"type": "string", "required": False},
                    "stability_seconds": {"type": "number", "required": False},
                },
                self._validate_fastcgi_integration,
            ),
            "dynamic.get_hypothesis": DynamicToolSpec(
                "dynamic.get_hypothesis",
                "Return one dynamic hypothesis with static and dynamic validation status.",
                {"hypothesis_id": {"type": "string", "required": True}},
                self._get_hypothesis,
            ),
            "dynamic.get_static_dynamic_context": DynamicToolSpec(
                "dynamic.get_static_dynamic_context",
                "Translate static evidence for a hypothesis into controlled dynamic validation context.",
                {"hypothesis_id": {"type": "string", "required": True}},
                self._get_static_dynamic_context,
            ),
            "hypothesis.list": DynamicToolSpec(
                "hypothesis.list",
                "List hypotheses with deterministic priority summaries.",
                {},
                self._hypothesis_list,
            ),
            "hypothesis.get_priority": DynamicToolSpec(
                "hypothesis.get_priority",
                "Return deterministic priority score for one hypothesis.",
                {"hypothesis_id": {"type": "string", "required": True}},
                self._hypothesis_get_priority,
            ),
            "hypothesis.get_assessment": DynamicToolSpec(
                "hypothesis.get_assessment",
                "Return full deterministic assessment for one hypothesis.",
                {"hypothesis_id": {"type": "string", "required": True}},
                self._hypothesis_get_assessment,
            ),
            "validation.get_budget": DynamicToolSpec(
                "validation.get_budget",
                "Return current deterministic validation budget.",
                {},
                self._validation_get_budget,
            ),
            "validation.get_queue": DynamicToolSpec(
                "validation.get_queue",
                "Return current deterministic validation queue.",
                {},
                self._validation_get_queue,
            ),
            "validation.request_reassessment": DynamicToolSpec(
                "validation.request_reassessment",
                "Recompute deterministic hypothesis priorities and queue.",
                {},
                self._validation_request_reassessment,
            ),
            "graph.get_component": DynamicToolSpec(
                "graph.get_component",
                "Return one firmware component from the persisted correlation graph.",
                {"component": {"type": "string", "required": True}},
                self._graph_get_component,
            ),
            "graph.get_neighbors": DynamicToolSpec(
                "graph.get_neighbors",
                "Return bounded neighbors for one firmware component.",
                {"component": {"type": "string", "required": True}},
                self._graph_get_neighbors,
            ),
            "graph.find_paths": DynamicToolSpec(
                "graph.find_paths",
                "Find bounded cross-component paths between two components.",
                {
                    "source": {"type": "string", "required": True},
                    "target": {"type": "string", "required": True},
                    "max_depth": {"type": "number", "required": False},
                },
                self._graph_find_paths,
            ),
            "graph.get_cross_component_context": DynamicToolSpec(
                "graph.get_cross_component_context",
                "Return a compressed cross-component context slice for one hypothesis.",
                {
                    "hypothesis_id": {"type": "string", "required": True},
                    "max_depth": {"type": "number", "required": False},
                    "max_nodes": {"type": "number", "required": False},
                },
                self._graph_get_cross_component_context,
            ),
            "graph.get_relationship_evidence": DynamicToolSpec(
                "graph.get_relationship_evidence",
                "Return provenance and evidence IDs for one graph relationship.",
                {"relationship_id": {"type": "string", "required": True}},
                self._graph_get_relationship_evidence,
            ),
            "graph.get_runtime_path": DynamicToolSpec(
                "graph.get_runtime_path",
                "Return high-confidence runtime-reachable component paths.",
                {},
                self._graph_get_runtime_path,
            ),
            "surface.list_entry_points": DynamicToolSpec(
                "surface.list_entry_points",
                "List discovered attack-surface entry points from persisted local evidence.",
                {},
                self._surface_list_entry_points,
            ),
            "surface.get_entry_point": DynamicToolSpec(
                "surface.get_entry_point",
                "Return one discovered entry point and context.",
                {"entry_id": {"type": "string", "required": True}},
                self._surface_get_entry_point,
            ),
            "surface.get_attack_surface_summary": DynamicToolSpec(
                "surface.get_attack_surface_summary",
                "Return non-vulnerability attack-surface summary counts.",
                {},
                self._surface_get_attack_surface_summary,
            ),
            "surface.get_reachability": DynamicToolSpec(
                "surface.get_reachability",
                "Return entry-point reachability records.",
                {"entry_id": {"type": "string", "required": False}},
                self._surface_get_reachability,
            ),
            "surface.get_entry_context": DynamicToolSpec(
                "surface.get_entry_context",
                "Return route, handler, component, and hypothesis context for one entry.",
                {"entry_id": {"type": "string", "required": True}},
                self._surface_get_entry_context,
            ),
            "surface.get_hypothesis_entries": DynamicToolSpec(
                "surface.get_hypothesis_entries",
                "Return entry-point reachability for one hypothesis.",
                {"hypothesis_id": {"type": "string", "required": True}},
                self._surface_get_hypothesis_entries,
            ),
            "surface.get_runtime_confirmed_entries": DynamicToolSpec(
                "surface.get_runtime_confirmed_entries",
                "Return runtime-confirmed entry points only.",
                {},
                self._surface_get_runtime_confirmed_entries,
            ),
            "taint.list_sources": DynamicToolSpec(
                "taint.list_sources",
                "List input source descriptors from persisted local evidence.",
                {},
                self._taint_list_sources,
            ),
            "taint.list_sinks": DynamicToolSpec(
                "taint.list_sinks",
                "List sensitive sinks from the configurable registry and static evidence.",
                {},
                self._taint_list_sinks,
            ),
            "taint.get_source": DynamicToolSpec(
                "taint.get_source",
                "Return one input source descriptor.",
                {"source_id": {"type": "string", "required": True}},
                self._taint_get_source,
            ),
            "taint.get_sink": DynamicToolSpec(
                "taint.get_sink",
                "Return one sensitive sink descriptor.",
                {"sink_id": {"type": "string", "required": True}},
                self._taint_get_sink,
            ),
            "taint.find_paths": DynamicToolSpec(
                "taint.find_paths",
                "Return bounded source-to-sink taint paths.",
                {
                    "source_id": {"type": "string", "required": False},
                    "sink_id": {"type": "string", "required": False},
                    "hypothesis_id": {"type": "string", "required": False},
                },
                self._taint_find_paths,
            ),
            "taint.get_path": DynamicToolSpec(
                "taint.get_path",
                "Return one taint path.",
                {"path_id": {"type": "string", "required": True}},
                self._taint_get_path,
            ),
            "taint.get_hypothesis_context": DynamicToolSpec(
                "taint.get_hypothesis_context",
                "Return compressed taint context for one hypothesis.",
                {"hypothesis_id": {"type": "string", "required": True}},
                self._taint_get_hypothesis_context,
            ),
            "taint.get_summary": DynamicToolSpec(
                "taint.get_summary",
                "Return taint analysis summary.",
                {},
                self._taint_get_summary,
            ),
            "hypothesis.list_candidates": DynamicToolSpec(
                "hypothesis.list_candidates",
                "List deterministic security hypothesis candidates.",
                {},
                self._hypothesis_list_candidates,
            ),
            "hypothesis.get_candidate": DynamicToolSpec(
                "hypothesis.get_candidate",
                "Return one deterministic security hypothesis candidate.",
                {"candidate_id": {"type": "string", "required": True}},
                self._hypothesis_get_candidate,
            ),
            "hypothesis.get_evidence_bundle": DynamicToolSpec(
                "hypothesis.get_evidence_bundle",
                "Return the evidence bundle for one hypothesis candidate.",
                {"candidate_id": {"type": "string", "required": True}},
                self._hypothesis_get_evidence_bundle,
            ),
            "hypothesis.get_generation_reason": DynamicToolSpec(
                "hypothesis.get_generation_reason",
                "Return deterministic generation reason for one hypothesis candidate.",
                {"candidate_id": {"type": "string", "required": True}},
                self._hypothesis_get_generation_reason,
            ),
            "hypothesis.get_missing_evidence": DynamicToolSpec(
                "hypothesis.get_missing_evidence",
                "Return missing evidence for one hypothesis candidate.",
                {"candidate_id": {"type": "string", "required": True}},
                self._hypothesis_get_missing_evidence,
            ),
            "hypothesis.list_generated": DynamicToolSpec(
                "hypothesis.list_generated",
                "List generated canonical hypothesis promotion records.",
                {},
                self._hypothesis_list_generated,
            ),
            "finding.list_candidates": DynamicToolSpec(
                "finding.list_candidates",
                "List grouped finding candidates.",
                {},
                self._finding_list_candidates,
            ),
            "finding.get_candidate": DynamicToolSpec(
                "finding.get_candidate",
                "Return one grouped finding candidate.",
                {"finding_candidate_id": {"type": "string", "required": True}},
                self._finding_get_candidate,
            ),
            "investigation.get_state": DynamicToolSpec(
                "investigation.get_state",
                "Return autonomous investigation state.",
                {},
                self._investigation_get_state,
            ),
            "investigation.get_context": DynamicToolSpec(
                "investigation.get_context",
                "Return compressed autonomous investigation context.",
                {},
                self._investigation_get_context,
            ),
            "investigation.get_budget": DynamicToolSpec(
                "investigation.get_budget",
                "Return investigation budget and usage.",
                {},
                self._investigation_get_budget,
            ),
            "investigation.get_history": DynamicToolSpec(
                "investigation.get_history",
                "Return investigation action history.",
                {},
                self._investigation_get_history,
            ),
            "investigation.get_next_action": DynamicToolSpec(
                "investigation.get_next_action",
                "Return the deterministic next investigation action proposal.",
                {},
                self._investigation_get_next_action,
            ),
            "investigation.get_iteration": DynamicToolSpec(
                "investigation.get_iteration",
                "Return one investigation iteration record.",
                {"iteration_id": {"type": "string", "required": True}},
                self._investigation_get_iteration,
            ),
            "investigation.request_reassessment": DynamicToolSpec(
                "investigation.request_reassessment",
                "Run controlled reassessment of investigation artifacts.",
                {},
                self._investigation_request_reassessment,
            ),
            "dynamic.create_validation_plan": DynamicToolSpec(
                "dynamic.create_validation_plan",
                "Create a non-destructive dynamic validation plan from a static hypothesis.",
                {
                    "hypothesis_id": {"type": "string", "required": True},
                    "validation_strategy": {"type": "string", "required": False},
                    "runtime_backend": {"type": "string", "required": False},
                    "risk_level": {"type": "string", "required": False},
                    "destructive": {"type": "boolean", "required": False},
                    "request_budget": {"type": "number", "required": False},
                },
                self._create_validation_plan,
            ),
            "dynamic.get_validation_plan": DynamicToolSpec(
                "dynamic.get_validation_plan",
                "Return a stored dynamic validation plan.",
                {"validation_id": {"type": "string", "required": True}},
                self._get_validation_plan,
            ),
            "dynamic.run_safe_validation": DynamicToolSpec(
                "dynamic.run_safe_validation",
                "Run bounded safe validation inputs against the selected local runtime.",
                {
                    "validation_id": {"type": "string", "required": True},
                    "inputs": {"type": "array", "required": False},
                },
                self._run_safe_validation,
            ),
            "dynamic.get_validation_status": DynamicToolSpec(
                "dynamic.get_validation_status",
                "Return validation verdict and artifact status.",
                {"validation_id": {"type": "string", "required": True}},
                self._get_validation_status,
            ),
            "dynamic.get_validation_observations": DynamicToolSpec(
                "dynamic.get_validation_observations",
                "Return bounded behavior observations for one validation.",
                {"validation_id": {"type": "string", "required": True}},
                self._get_validation_observations,
            ),
            "dynamic.finalize_validation": DynamicToolSpec(
                "dynamic.finalize_validation",
                "Finalize validation verdict and update the linked hypothesis dynamic status.",
                {"validation_id": {"type": "string", "required": True}},
                self._finalize_validation,
            ),
            "application.list_endpoints": DynamicToolSpec(
                "application.list_endpoints",
                "List reconstructed frontend and FastCGI-backed endpoints.",
                {"backend": {"type": "string", "required": False}},
                self._application_list_endpoints,
            ),
            "application.get_endpoint": DynamicToolSpec(
                "application.get_endpoint",
                "Return one reconstructed endpoint by path.",
                {
                    "backend": {"type": "string", "required": False},
                    "path": {"type": "string", "required": True},
                },
                self._application_get_endpoint,
            ),
            "application.probe_endpoint": DynamicToolSpec(
                "application.probe_endpoint",
                "Probe one real reconstructed endpoint with a safe local GET/HEAD request.",
                {
                    "backend": {"type": "string", "required": False},
                    "path": {"type": "string", "required": True},
                    "method": {"type": "string", "required": False},
                },
                self._application_probe_endpoint,
            ),
            "application.create_evidence": DynamicToolSpec(
                "application.create_evidence",
                "Create a DynamicEvidence entry for application backend observations.",
                {
                    "type": {"type": "string", "required": True},
                    "observation": {"type": "string", "required": True},
                    "target": {"type": "string", "required": False},
                    "metadata": {"type": "object", "required": False},
                },
                self._application_create_evidence,
            ),
            "dynamic.create_evidence": DynamicToolSpec(
                "dynamic.create_evidence",
                "Create a DynamicEvidence entry.",
                {
                    "type": {"type": "string", "required": True},
                    "observation": {"type": "string", "required": True},
                    "source_tool": {"type": "string", "required": False},
                    "confidence": {"type": "number", "required": False},
                    "target": {"type": "string", "required": False},
                    "metadata": {"type": "object", "required": False},
                },
                self._create_evidence,
            ),
            "dynamic.update_hypothesis": DynamicToolSpec(
                "dynamic.update_hypothesis",
                "Create or update a dynamic hypothesis.",
                {
                    "id": {"type": "string", "required": False},
                    "title": {"type": "string", "required": True},
                    "status": {"type": "string", "required": True},
                    "confidence": {"type": "number", "required": False},
                    "cwe": {"type": "string", "required": False},
                    "evidence_ids": {"type": "array", "required": False},
                    "missing_evidence": {"type": "array", "required": False},
                    "next_actions": {"type": "array", "required": False},
                    "static_status": {"type": "string", "required": False},
                    "dynamic_status": {"type": "string", "required": False},
                },
                self._update_hypothesis,
            ),
        }

    def _prepare_firmware(self, args: dict[str, Any]) -> dict[str, Any]:
        self.state.transition("preparing")
        result = self.workspace.prepare_firmware()
        if result["success"]:
            self.state.transition("not_started")
        else:
            self.state.errors.append({"code": "backend_error", "message": result["errors"][0]})
            self.state.transition("failed")
        self.workspace.save_state(self.state)
        return {"success": result["success"], "tool": "dynamic.prepare_firmware", "result": result}

    def _boot_firmware(self, args: dict[str, Any]) -> dict[str, Any]:
        if getattr(self.backend.boot, "execution_blocked", False):
            return {"success": False, "tool": "dynamic.boot_firmware", "result": blocked_execution("dynamic.boot_firmware")}
        firmware = self.workspace.resolve_firmware()
        if not firmware:
            return {"success": False, "tool": "dynamic.boot_firmware", "errors": ["firmware not found"]}
        self.state.transition("booting")
        self.state.boot_started_at = _now()
        self.workspace.save_state(self.state)
        timeout = int(args.get("timeout") or self.config.boot.timeout_seconds)
        result = self.backend.boot(firmware, timeout=timeout)
        if result.get("success"):
            self.state.transition("running")
            self.state.boot_completed_at = _now()
            self._auto_evidence("boot_success", "Firmware boot completed", "dynamic.boot", result)
        else:
            diagnosis = result.get("diagnosis", "backend_error")
            self.state.errors.append({"code": diagnosis, "message": "; ".join(result.get("errors", []) or ["boot failed"])})
            self.state.transition("failed")
            self._auto_evidence(
                _failure_evidence_type(diagnosis),
                f"Dynamic validation blocked: firmware boot failed with {diagnosis}",
                "dynamic.boot",
                result,
            )
        self.state.backend = self.backend.name
        self.workspace.save_state(self.state)
        self.workspace.write_log("boot.log", json.dumps(result, ensure_ascii=True, indent=2))
        return {"success": bool(result.get("success")), "tool": "dynamic.boot_firmware", "result": result}

    def _get_emulation_status(self, args: dict[str, Any]) -> dict[str, Any]:
        return {"success": True, "tool": "dynamic.get_emulation_status", "result": self.state.to_dict()}

    def _stop_firmware(self, args: dict[str, Any]) -> dict[str, Any]:
        result = self.backend.stop()
        self.state.transition("stopped")
        self.workspace.save_state(self.state)
        self.workspace.write_log("shutdown.log", json.dumps(result, ensure_ascii=True, indent=2))
        return {"success": True, "tool": "dynamic.stop_firmware", "result": result}

    def _list_processes(self, args: dict[str, Any]) -> dict[str, Any]:
        if self.state.status not in {"booting", "running"}:
            return {"success": False, "tool": "dynamic.list_processes", "errors": ["emulation not running"]}
        result = self.runner.run(["ps", "-eo", "pid,comm,args"], timeout=10)
        processes = _parse_ps(result.stdout)
        self.state.processes = processes
        self.workspace.save_state(self.state)
        return {"success": result.exit_code == 0, "tool": "dynamic.list_processes", "result": {"processes": processes[:100]}}

    def _list_open_ports(self, args: dict[str, Any]) -> dict[str, Any]:
        if self.state.status not in {"booting", "running"}:
            return {"success": False, "tool": "dynamic.list_open_ports", "errors": ["emulation not running"]}
        result = self.runner.run(["ss", "-tlnp"], timeout=10)
        if result.exit_code != 0:
            result = self.runner.run(["netstat", "-tlnp"], timeout=10)
        ports = _parse_ss_ports(result.stdout)
        self.state.open_ports = ports
        self.workspace.save_state(self.state)
        return {"success": True, "tool": "dynamic.list_open_ports", "result": {"ports": ports}}

    def _list_services(self, args: dict[str, Any]) -> dict[str, Any]:
        processes = self.state.processes or (self._list_processes({}).get("result", {}).get("processes") or [])
        services = []
        for name in ("lighttpd", "dnsmasq", "miniupnpd", "uhttpd"):
            matches = [item for item in processes if name in item.get("command", "") or name in item.get("name", "")]
            if matches:
                services.append({"name": name, "processes": matches[:5]})
        self.state.services = services
        self.workspace.save_state(self.state)
        return {"success": True, "tool": "dynamic.list_services", "result": {"services": services}}

    def _get_runtime_logs(self, args: dict[str, Any]) -> dict[str, Any]:
        if self.log_reads >= self.config.agent.max_log_reads:
            return {"success": False, "tool": "dynamic.get_runtime_logs", "errors": ["max_log_reads reached"]}
        self.log_reads += 1
        lines = int(args.get("lines") or 200)
        logs = self.backend.logs(limit=max(1, min(lines, 500)))
        return {"success": True, "tool": "dynamic.get_runtime_logs", "result": {"logs": logs}}

    def _probe_http(self, args: dict[str, Any]) -> dict[str, Any]:
        if self.http_requests >= self.config.validation.max_http_requests:
            return {"success": False, "tool": "dynamic.probe_http", "errors": ["max_http_requests reached"]}
        url = str(args["url"])
        if not _private_target(url):
            return {"success": False, "tool": "dynamic.probe_http", "errors": ["HTTP target must be a private/emulated address"]}
        method = str(args.get("method") or "GET").upper()
        if method not in {"GET", "HEAD"}:
            return {"success": False, "tool": "dynamic.probe_http", "errors": ["only GET/HEAD are allowed"]}
        self.http_requests += 1
        start = time.monotonic()
        request = urllib.request.Request(url, method=method)
        try:
            with urllib.request.urlopen(request, timeout=self.config.network.probe_timeout_seconds) as response:
                body = response.read(HTTP_MAX_BODY_BYTES)
                status = response.status
                headers = {key: value for key, value in response.headers.items()}
        except Exception as exc:  # noqa: BLE001 - probe failures are structured
            return {"success": False, "tool": "dynamic.probe_http", "errors": [f"HTTP probe failed: {exc}"]}
        body_preview = body[:2048].decode("utf-8", errors="replace")
        result = {
            "method": method,
            "url": url,
            "status": status,
            "headers": headers,
            "body_preview": body_preview,
            "body_length": len(body),
            "duration": round(time.monotonic() - start, 3),
            "network_backend": getattr(self.backend, "name", None),
            "network": getattr(self.backend, "network", None).prepare([80]) if hasattr(self.backend, "network") else None,
        }
        self._auto_evidence(
            "http_response",
            f"HTTP {method} {url} returned status {status}",
            "http_probe",
            result,
            target=url,
        )
        return {"success": True, "tool": "dynamic.probe_http", "result": result}

    def _probe_tcp(self, args: dict[str, Any]) -> dict[str, Any]:
        if self.port_probes >= self.config.agent.max_port_probes:
            return {"success": False, "tool": "dynamic.probe_tcp", "errors": ["max_port_probes reached"]}
        host = str(args["host"])
        port = int(args["port"])
        if not _private_target(host) or port not in PORT_SCAN_TARGETS:
            return {
                "success": False,
                "tool": "dynamic.probe_tcp",
                "errors": ["TCP target must be a private/emulated address and a known service port"],
            }
        self.port_probes += 1
        start = time.monotonic()
        try:
            with socket.create_connection((host, port), timeout=self.config.network.probe_timeout_seconds):
                open_port = True
        except OSError:
            open_port = False
        duration = round(time.monotonic() - start, 3)
        result = {
            "host": host,
            "port": port,
            "open": open_port,
            "duration": duration,
            "network_backend": getattr(self.backend, "name", None),
            "network": getattr(self.backend, "network", None).prepare([port]) if hasattr(self.backend, "network") else None,
        }
        self._auto_evidence(
            "port_open" if open_port else "port_closed",
            f"TCP {host}:{port} {'open' if open_port else 'closed'}",
            "tcp_probe",
            result,
            target=f"{host}:{port}",
        )
        return {"success": True, "tool": "dynamic.probe_tcp", "result": result}

    def _check_process(self, args: dict[str, Any]) -> dict[str, Any]:
        processes = self.state.processes or (self._list_processes({}).get("result", {}).get("processes") or [])
        query = str(args["query"])
        matches = [item for item in processes if query in item.get("command", "") or query in item.get("name", "")]
        result = {"query": query, "running": bool(matches), "matches": matches[:10]}
        if matches:
            self._auto_evidence("process_running", f"Process {query} is running", "process_observer", result)
        return {"success": True, "tool": "dynamic.check_process", "result": result}

    def _reconstruct_service_startup(self, args: dict[str, Any]) -> dict[str, Any]:
        if not hasattr(self.backend, "reconstruct_service_startup"):
            return {"success": False, "tool": "dynamic.reconstruct_service_startup", "errors": ["backend does not support service startup reconstruction"]}
        result = self.backend.reconstruct_service_startup(str(args["binary"]))
        return {"success": bool(result.get("success")), "tool": "dynamic.reconstruct_service_startup", "result": result}

    def _prepare_service(self, args: dict[str, Any]) -> dict[str, Any]:
        if not hasattr(self.backend, "prepare_service"):
            return {"success": False, "tool": "dynamic.prepare_service", "errors": ["backend does not support service preparation"]}
        result = self.backend.prepare_service(str(args["service"]))
        if not result.get("success") and result.get("diagnosis") == "missing_runtime_dependency":
            self._auto_evidence("runtime_dependency_missing", "Service runtime dependency is missing", "service_prepare", result, target=str(args["service"]))
        return {"success": bool(result.get("success")), "tool": "dynamic.prepare_service", "result": result}

    def _start_service(self, args: dict[str, Any]) -> dict[str, Any]:
        if not hasattr(self.backend, "start_service"):
            return {"success": False, "tool": "dynamic.start_service", "errors": ["backend does not support service start"]}
        service = str(args["service"])
        result = self.backend.start_service(service, stability_seconds=int(args.get("stability_seconds") or 5))
        if result.get("success"):
            self._auto_evidence("service_start_success", f"Firmware service {service} started under service-qemu", "service_start", result, target=service)
            self._auto_evidence("service_process_alive", f"Firmware service {service} remained alive after startup threshold", "service_start", result, target=service)
        else:
            self._auto_evidence("service_start_failure", f"Firmware service {service} failed to start", "service_start", result, target=service)
        return {"success": bool(result.get("success")), "tool": "dynamic.start_service", "result": result}

    def _get_service_status(self, args: dict[str, Any]) -> dict[str, Any]:
        if not hasattr(self.backend, "get_service_status"):
            return {"success": False, "tool": "dynamic.get_service_status", "errors": ["backend does not support service status"]}
        result = self.backend.get_service_status(str(args["service"]))
        return {"success": bool(result.get("success")), "tool": "dynamic.get_service_status", "result": result}

    def _get_service_logs(self, args: dict[str, Any]) -> dict[str, Any]:
        if not hasattr(self.backend, "get_service_logs"):
            return {"success": False, "tool": "dynamic.get_service_logs", "errors": ["backend does not support service logs"]}
        result = self.backend.get_service_logs(str(args["service"]), lines=int(args.get("lines") or 100))
        return {"success": bool(result.get("success")), "tool": "dynamic.get_service_logs", "result": result}

    def _get_service_ports(self, args: dict[str, Any]) -> dict[str, Any]:
        if not hasattr(self.backend, "get_service_ports"):
            return {"success": False, "tool": "dynamic.get_service_ports", "errors": ["backend does not support service port observation"]}
        service = str(args["service"])
        result = self.backend.get_service_ports(service)
        if result.get("success"):
            self._auto_evidence("service_port_listening", f"Firmware service {service} has a listening TCP port", "service_ports", result, target=service)
        return {"success": bool(result.get("success")), "tool": "dynamic.get_service_ports", "result": result}

    def _probe_service_http(self, args: dict[str, Any]) -> dict[str, Any]:
        if not hasattr(self.backend, "probe_service_http"):
            return {"success": False, "tool": "dynamic.probe_service_http", "errors": ["backend does not support service HTTP probing"]}
        service = str(args["service"])
        safe_input = SafeValidationInput(
            input_id=f"SAFE-SERVICE-{service}",
            protocol="http",
            method="GET",
            path="/",
            category="baseline",
            source="dynamic.probe_service_http",
        )
        errors = validate_safe_input(
            safe_input,
            max_request_bytes=self.config.validation.max_request_bytes,
            max_body_bytes=self.config.validation.max_body_bytes,
        )
        if errors:
            return {"success": False, "tool": "dynamic.probe_service_http", "errors": errors}
        try:
            result = self.backend.probe_service_http(service, safe_input.to_dict())
        except TypeError:
            result = self.backend.probe_service_http(service)
        result["safe_validation_input"] = safe_input.to_dict()
        if result.get("success"):
            self._auto_evidence("service_http_response", f"Firmware service {service} returned an HTTP response", "service_http_probe", result, target=service)
            self._auto_evidence("service_reachable", f"Firmware service {service} is reachable over HTTP", "service_http_probe", result, target=service)
        return {"success": bool(result.get("success")), "tool": "dynamic.probe_service_http", "result": result}

    def _stop_service(self, args: dict[str, Any]) -> dict[str, Any]:
        if not hasattr(self.backend, "stop_service"):
            return {"success": False, "tool": "dynamic.stop_service", "errors": ["backend does not support service stop"]}
        result = self.backend.stop_service(str(args["service"]))
        return {"success": bool(result.get("success")), "tool": "dynamic.stop_service", "result": result}

    def _get_boot_progress(self, args: dict[str, Any]) -> dict[str, Any]:
        if not hasattr(self.backend, "get_boot_progress"):
            return {"success": False, "tool": "dynamic.get_boot_progress", "errors": ["backend does not support boot progress parsing"]}
        result = self.backend.get_boot_progress()
        return {"success": bool(result.get("success")), "tool": "dynamic.get_boot_progress", "result": result}

    def _application_inspect_backend(self, args: dict[str, Any]) -> dict[str, Any]:
        if not hasattr(self.backend, "inspect_application_backend"):
            return {"success": False, "tool": "application.inspect_backend", "errors": ["backend does not support application inspection"]}
        backend = _application_backend_arg(args)
        result = self.backend.inspect_application_backend(backend)
        return {"success": bool(result.get("success")), "tool": "application.inspect_backend", "result": result}

    def _application_get_dependencies(self, args: dict[str, Any]) -> dict[str, Any]:
        if not hasattr(self.backend, "get_application_dependencies"):
            return {"success": False, "tool": "application.get_dependencies", "errors": ["backend does not support application dependency graphing"]}
        backend = _application_backend_arg(args)
        result = self.backend.get_application_dependencies(backend)
        for dependency in result.get("dependencies", []):
            if dependency.get("type") == "nvram":
                self._auto_evidence("backend_nvram_dependency", f"Application backend {backend} references NVRAM", "application_dependencies", dependency, target=backend)
            if dependency.get("type") == "unix_socket" and not dependency.get("available"):
                self._auto_evidence("backend_ipc_dependency", f"Application backend {backend} references unavailable IPC socket", "application_dependencies", dependency, target=backend)
            if dependency.get("required") and not dependency.get("available"):
                self._auto_evidence("backend_dependency_missing", f"Application backend {backend} has a missing startup dependency", "application_dependencies", dependency, target=backend)
        return {"success": bool(result.get("success")), "tool": "application.get_dependencies", "result": result}

    def _application_get_launch_profile(self, args: dict[str, Any]) -> dict[str, Any]:
        if not hasattr(self.backend, "get_fastcgi_launch_profile"):
            return {"success": False, "tool": "application.get_launch_profile", "errors": ["backend does not support FastCGI launch profile reconstruction"]}
        backend = _application_backend_arg(args)
        result = self.backend.get_fastcgi_launch_profile(backend)
        return {"success": bool(result.get("success")), "tool": "application.get_launch_profile", "result": result}

    def _application_trace_startup(self, args: dict[str, Any]) -> dict[str, Any]:
        if not hasattr(self.backend, "trace_application_startup"):
            return {"success": False, "tool": "application.trace_startup", "errors": ["backend does not support application tracing"]}
        backend = _application_backend_arg(args)
        result = self.backend.trace_application_startup(
            backend,
            timeout_seconds=int(args.get("timeout_seconds") or 10),
            max_events=int(args.get("max_events") or 2000),
        )
        return {"success": bool(result.get("success")), "tool": "application.trace_startup", "result": result}

    def _application_start_backend(self, args: dict[str, Any]) -> dict[str, Any]:
        if not hasattr(self.backend, "start_application_backend"):
            return {"success": False, "tool": "application.start_backend", "errors": ["backend does not support application startup"]}
        backend = _application_backend_arg(args)
        result = self.backend.start_application_backend(backend, stability_seconds=int(args.get("stability_seconds") or 5))
        if result.get("success"):
            self._auto_evidence("backend_start_success", f"Application backend {backend} started through original FastCGI mapping", "application_start", result, target=backend)
            if result.get("socket_ready"):
                self._auto_evidence("backend_socket_ready", f"Application backend {backend} FastCGI socket is ready", "application_start", result, target=backend)
        else:
            self._auto_evidence("backend_start_failure", f"Application backend {backend} failed through original FastCGI mapping", "application_start", result, target=backend)
        return {"success": bool(result.get("success")), "tool": "application.start_backend", "result": result}

    def _application_get_backend_status(self, args: dict[str, Any]) -> dict[str, Any]:
        backend = _application_backend_arg(args)
        path = self.workspace.dynamic_dir / "application" / backend / "startup.json"
        if not path.exists():
            return {"success": False, "tool": "application.get_backend_status", "errors": ["application startup state not found"]}
        return {"success": True, "tool": "application.get_backend_status", "result": json.loads(path.read_text(encoding="utf-8"))}

    def _application_get_backend_logs(self, args: dict[str, Any]) -> dict[str, Any]:
        backend = _application_backend_arg(args)
        lines = int(args.get("lines") or 100)
        app_dir = self.workspace.dynamic_dir / "application" / backend / "logs"
        return {
            "success": True,
            "tool": "application.get_backend_logs",
            "result": {
                "stdout": _tail(app_dir / "startup_stdout.log", lines),
                "stderr": _tail(app_dir / "startup_stderr.log", lines),
                "trace_stderr": _tail(app_dir / "trace_stderr.log", lines),
            },
        }

    def _application_get_direct_context(self, args: dict[str, Any]) -> dict[str, Any]:
        if not hasattr(self.backend, "get_direct_application_context"):
            return {"success": False, "tool": "application.get_direct_context", "errors": ["backend does not support direct context capture"]}
        backend = _application_backend_arg(args)
        result = self.backend.get_direct_application_context(backend)
        if result.get("success"):
            self._auto_evidence("fastcgi_context_difference", f"Application backend {backend} direct execution context captured for FastCGI comparison", "application_direct_context", result, target=backend)
        return {"success": bool(result.get("success")), "tool": "application.get_direct_context", "result": result}

    def _application_get_fastcgi_context(self, args: dict[str, Any]) -> dict[str, Any]:
        if not hasattr(self.backend, "get_fastcgi_application_context"):
            return {"success": False, "tool": "application.get_fastcgi_context", "errors": ["backend does not support FastCGI context capture"]}
        backend = _application_backend_arg(args)
        result = self.backend.get_fastcgi_application_context(backend, timeout_seconds=int(args.get("timeout_seconds") or 10))
        context = result.get("context") or {}
        if result.get("success"):
            self._auto_evidence("fastcgi_context_difference", f"Application backend {backend} FastCGI child context captured", "application_fastcgi_context", result, target=backend)
            if context.get("listen_socket_fd") is None:
                self._auto_evidence("fastcgi_fd_missing", f"Application backend {backend} FastCGI listener FD was not observed", "application_fastcgi_context", result, target=backend)
        return {"success": bool(result.get("success")), "tool": "application.get_fastcgi_context", "result": result}

    def _application_compare_contexts(self, args: dict[str, Any]) -> dict[str, Any]:
        if not hasattr(self.backend, "compare_application_runtime_contexts"):
            return {"success": False, "tool": "application.compare_runtime_contexts", "errors": ["backend does not support FastCGI context comparison"]}
        backend = _application_backend_arg(args)
        result = self.backend.compare_application_runtime_contexts(backend)
        if result.get("success"):
            self._auto_evidence("fastcgi_context_difference", f"Application backend {backend} direct and FastCGI contexts differ", "application_context_diff", result, target=backend)
        return {"success": bool(result.get("success")), "tool": "application.compare_runtime_contexts", "result": result}

    def _application_get_startup_graph(self, args: dict[str, Any]) -> dict[str, Any]:
        if not hasattr(self.backend, "get_application_startup_graph"):
            return {"success": False, "tool": "application.get_startup_graph", "errors": ["backend does not support startup graph extraction"]}
        backend = _application_backend_arg(args)
        result = self.backend.get_application_startup_graph(backend)
        if result.get("success"):
            failed_stages = [stage for stage in result.get("stages", []) if stage.get("entered") and not stage.get("completed")]
            if failed_stages:
                self._auto_evidence("fastcgi_init_failure", f"Application backend {backend} stopped before completing {failed_stages[0].get('name')}", "application_startup_graph", result, target=backend)
        return {"success": bool(result.get("success")), "tool": "application.get_startup_graph", "result": result}

    def _application_build_fastcgi_harness(self, args: dict[str, Any]) -> dict[str, Any]:
        if not hasattr(self.backend, "get_fastcgi_launch_profile"):
            return {"success": False, "tool": "application.build_fastcgi_harness", "errors": ["backend does not support FastCGI launch reconstruction"]}
        backend = _application_backend_arg(args)
        profile = self.backend.get_fastcgi_launch_profile(backend)
        endpoint = str(args.get("endpoint") or "/services/device_manager/")
        result = {
            "success": bool(profile.get("success")),
            "backend": backend,
            "endpoint": endpoint,
            "harness": {
                "listener_fd": 0,
                "protocol": "FastCGI responder",
                "request_method": "GET",
                "request_uri": endpoint,
                "socket_family": "AF_UNIX",
            },
            "profile": profile,
        }
        return {"success": bool(result["success"]), "tool": "application.build_fastcgi_harness", "result": result}

    def _application_start_fastcgi_harness(self, args: dict[str, Any]) -> dict[str, Any]:
        if not hasattr(self.backend, "start_fastcgi_harness"):
            return {"success": False, "tool": "application.start_fastcgi_harness", "errors": ["backend does not support standalone FastCGI harness"]}
        backend = _application_backend_arg(args)
        result = self.backend.start_fastcgi_harness(
            backend,
            endpoint=str(args.get("endpoint") or "/services/device_manager/"),
            timeout_seconds=int(args.get("timeout_seconds") or 10),
        )
        if result.get("backend_alive"):
            self._auto_evidence("fastcgi_backend_alive", f"Application backend {backend} stayed alive in standalone FastCGI harness", "application_fastcgi_harness", result, target=backend)
        if result.get("socket_ready"):
            self._auto_evidence("fastcgi_socket_ready", f"Application backend {backend} FastCGI listener socket accepted harness setup", "application_fastcgi_harness", result, target=backend)
        if result.get("request_sent"):
            self._auto_evidence("fastcgi_request_sent", f"Application backend {backend} received a benign FastCGI request frame", "application_fastcgi_harness", result, target=backend)
        if result.get("response_received"):
            self._auto_evidence("fastcgi_response_received", f"Application backend {backend} returned a FastCGI response", "application_fastcgi_harness", result, target=backend)
        if not result.get("request_sent") and not result.get("response_received"):
            evidence_type = "fastcgi_socket_failure" if result.get("socket_ready") is False else "fastcgi_init_failure"
            self._auto_evidence(evidence_type, f"Application backend {backend} did not reach FastCGI request handling in standalone harness", "application_fastcgi_harness", result, target=backend)
        return {"success": bool(result.get("success")), "tool": "application.start_fastcgi_harness", "result": result}

    def _application_get_fastcgi_result(self, args: dict[str, Any]) -> dict[str, Any]:
        backend = _application_backend_arg(args)
        path = self.workspace.dynamic_dir / "application" / backend / "harness_result.json"
        if not path.exists():
            return {"success": False, "tool": "application.get_fastcgi_result", "errors": ["FastCGI harness result not found"]}
        return {"success": True, "tool": "application.get_fastcgi_result", "result": json.loads(path.read_text(encoding="utf-8"))}

    def _get_fastcgi_runtime_context(self, args: dict[str, Any]) -> dict[str, Any]:
        if not hasattr(self.backend, "get_fastcgi_runtime_context"):
            return {"success": False, "tool": "dynamic.get_fastcgi_runtime_context", "errors": ["backend does not support FastCGI runtime snapshots"]}
        backend = _application_backend_arg(args)
        mode = str(args.get("mode") or "standalone")
        result = self.backend.get_fastcgi_runtime_context(
            backend,
            mode=mode,
            timeout_seconds=int(args.get("timeout_seconds") or 10),
        )
        if result.get("success"):
            self._auto_evidence("fastcgi_runtime_context", f"Captured {mode} FastCGI runtime context for {backend}", "fastcgi_runtime_context", result, target=backend)
        return {"success": bool(result.get("success")), "tool": "dynamic.get_fastcgi_runtime_context", "result": result}

    def _compare_fastcgi_runtime(self, args: dict[str, Any]) -> dict[str, Any]:
        if not hasattr(self.backend, "compare_fastcgi_runtime"):
            return {"success": False, "tool": "dynamic.compare_fastcgi_runtime", "errors": ["backend does not support FastCGI runtime diffing"]}
        backend = _application_backend_arg(args)
        result = self.backend.compare_fastcgi_runtime(backend)
        if result.get("success"):
            self._auto_evidence("fastcgi_runtime_difference", f"Compared standalone and lighttpd FastCGI runtime for {backend}", "fastcgi_runtime_diff", result, target=backend)
        return {"success": bool(result.get("success")), "tool": "dynamic.compare_fastcgi_runtime", "result": result}

    def _get_fastcgi_child_failure(self, args: dict[str, Any]) -> dict[str, Any]:
        if not hasattr(self.backend, "get_fastcgi_child_failure"):
            return {"success": False, "tool": "dynamic.get_fastcgi_child_failure", "errors": ["backend does not support FastCGI child failure classification"]}
        backend = _application_backend_arg(args)
        result = self.backend.get_fastcgi_child_failure(backend, stability_seconds=int(args.get("stability_seconds") or 5))
        classification = result.get("classification") or {}
        if result.get("success"):
            self._auto_evidence("fastcgi_child_exit", f"Classified FastCGI child failure for {backend}: {classification.get('category')}", "fastcgi_child_failure", result, target=backend)
            if classification.get("category") != "unknown":
                self._auto_evidence("fastcgi_exit_code_explained", f"FastCGI child exit classification recorded for {backend}", "fastcgi_child_failure", result, target=backend)
        return {"success": bool(result.get("success")), "tool": "dynamic.get_fastcgi_child_failure", "result": result}

    def _validate_fastcgi_integration(self, args: dict[str, Any]) -> dict[str, Any]:
        if not hasattr(self.backend, "validate_fastcgi_integration"):
            return {"success": False, "tool": "dynamic.validate_fastcgi_integration", "errors": ["backend does not support FastCGI integration validation"]}
        backend = _application_backend_arg(args)
        result = self.backend.validate_fastcgi_integration(
            backend,
            endpoint=str(args.get("endpoint") or "/services/device_manager/"),
            stability_seconds=int(args.get("stability_seconds") or 3),
        )
        if result.get("backend_child", {}).get("alive_after_startup"):
            self._auto_evidence("fastcgi_child_started", f"FastCGI child for {backend} survived controlled runtime startup", "fastcgi_integration", result, target=backend)
        if result.get("probe"):
            self._auto_evidence("fastcgi_request_received", f"lighttpd forwarded a local HTTP request to {backend}", "fastcgi_integration", result, target=backend)
        if result.get("application_response_reached"):
            self._auto_evidence("fastcgi_application_response", f"{backend} returned an application-level FastCGI response through lighttpd", "fastcgi_integration", result, target=backend)
        if result.get("success"):
            self._auto_evidence("fastcgi_integration_reachable", f"lighttpd to {backend} FastCGI integration is reachable", "fastcgi_integration", result, target=backend)
        else:
            self._auto_evidence("fastcgi_validation_blocked", f"FastCGI integration validation is blocked for {backend}", "fastcgi_integration", result, target=backend)
        return {"success": bool(result.get("success")), "tool": "dynamic.validate_fastcgi_integration", "result": result}

    def _get_hypothesis(self, args: dict[str, Any]) -> dict[str, Any]:
        hypothesis_id = str(args["hypothesis_id"])
        hypothesis = self._lookup_hypothesis(hypothesis_id)
        if hypothesis is None:
            return {"success": False, "tool": "dynamic.get_hypothesis", "errors": [f"hypothesis not found: {hypothesis_id}"]}
        return {"success": True, "tool": "dynamic.get_hypothesis", "result": {"hypothesis": hypothesis.to_dict()}}

    def _get_static_dynamic_context(self, args: dict[str, Any]) -> dict[str, Any]:
        hypothesis_id = str(args["hypothesis_id"])
        hypothesis = self._lookup_hypothesis(hypothesis_id)
        if hypothesis is None:
            return {"success": False, "tool": "dynamic.get_static_dynamic_context", "errors": [f"hypothesis not found: {hypothesis_id}"]}
        static_evidence = self._static_evidence_for(hypothesis)
        context = build_static_dynamic_context(hypothesis.to_dict(), static_evidence, self._static_report())
        return {
            "success": True,
            "tool": "dynamic.get_static_dynamic_context",
            "result": {
                "hypothesis_id": hypothesis_id,
                "static_evidence": static_evidence[:20],
                "context": context.to_dict(),
            },
        }

    def _prioritization_state(self) -> dict[str, Any]:
        return HypothesisValidationScheduler(
            self.workspace.workspace_root,
            self.workspace.task_id,
            config=self.config,
        ).assess()

    def _hypothesis_list(self, args: dict[str, Any]) -> dict[str, Any]:
        state = self._prioritization_state()
        assessments = state.get("assessments") or []
        rows = [
            {
                "hypothesis_id": item.get("hypothesis_id"),
                "priority_score": item.get("priority_score"),
                "priority_tier": item.get("priority_tier"),
                "runtime": item.get("recommended_runtime"),
                "strategy": item.get("recommended_strategy"),
                "blocking_reasons": item.get("blocking_reasons") or [],
            }
            for item in assessments
        ]
        return {"success": True, "tool": "hypothesis.list", "result": {"hypotheses": rows, "provider_backed": False}}

    def _hypothesis_get_priority(self, args: dict[str, Any]) -> dict[str, Any]:
        hypothesis_id = str(args["hypothesis_id"])
        state = self._prioritization_state()
        assessment = next((item for item in state.get("assessments", []) if item.get("hypothesis_id") == hypothesis_id), None)
        if assessment is None:
            return {"success": False, "tool": "hypothesis.get_priority", "errors": [f"hypothesis not found: {hypothesis_id}"]}
        return {
            "success": True,
            "tool": "hypothesis.get_priority",
            "result": {
                "hypothesis_id": hypothesis_id,
                "priority_score": assessment.get("priority_score"),
                "priority_tier": assessment.get("priority_tier"),
                "reason": assessment.get("assessment_reason"),
                "provider_backed": False,
            },
        }

    def _hypothesis_get_assessment(self, args: dict[str, Any]) -> dict[str, Any]:
        hypothesis_id = str(args["hypothesis_id"])
        state = self._prioritization_state()
        assessment = next((item for item in state.get("assessments", []) if item.get("hypothesis_id") == hypothesis_id), None)
        if assessment is None:
            return {"success": False, "tool": "hypothesis.get_assessment", "errors": [f"hypothesis not found: {hypothesis_id}"]}
        return {"success": True, "tool": "hypothesis.get_assessment", "result": {"assessment": assessment, "provider_backed": False}}

    def _validation_get_budget(self, args: dict[str, Any]) -> dict[str, Any]:
        state = self._prioritization_state()
        return {"success": True, "tool": "validation.get_budget", "result": {"budget": state.get("budget"), "provider_backed": False}}

    def _validation_get_queue(self, args: dict[str, Any]) -> dict[str, Any]:
        state = self._prioritization_state()
        return {"success": True, "tool": "validation.get_queue", "result": {"queue": state.get("queue"), "provider_backed": False}}

    def _validation_request_reassessment(self, args: dict[str, Any]) -> dict[str, Any]:
        state = self._prioritization_state()
        return {
            "success": True,
            "tool": "validation.request_reassessment",
            "result": {
                "assessment_count": len(state.get("assessments", [])),
                "queue_count": len((state.get("queue") or {}).get("items") or []),
                "stop_reason": state.get("stop_reason"),
                "provider_backed": False,
            },
        }

    def _component_graph(self) -> ComponentGraph:
        return ComponentGraphBuilder(self.workspace.workspace_root, self.workspace.task_id, config=self.config).load_or_build_graph()

    def _graph_get_component(self, args: dict[str, Any]) -> dict[str, Any]:
        graph = self._component_graph()
        component_id = graph.resolve_component_id(str(args["component"]))
        if not component_id:
            return {"success": False, "tool": "graph.get_component", "errors": [f"component not found: {args['component']}"]}
        return {"success": True, "tool": "graph.get_component", "result": {"component": graph.components[component_id].to_dict()}}

    def _graph_get_neighbors(self, args: dict[str, Any]) -> dict[str, Any]:
        graph = self._component_graph()
        component_id = graph.resolve_component_id(str(args["component"]))
        if not component_id:
            return {"success": False, "tool": "graph.get_neighbors", "errors": [f"component not found: {args['component']}"]}
        relationships = graph.find_relationships(source_component_id=component_id) + graph.find_relationships(target_component_id=component_id)
        return {
            "success": True,
            "tool": "graph.get_neighbors",
            "result": {
                "component_id": component_id,
                "neighbors": [item.to_dict() for item in graph.get_neighbors(component_id)[: self.config.correlation.filtering.max_context_nodes]],
                "relationships": [item.to_dict() for item in relationships[: self.config.correlation.filtering.max_context_nodes]],
            },
        }

    def _graph_find_paths(self, args: dict[str, Any]) -> dict[str, Any]:
        graph = self._component_graph()
        paths = graph.find_paths(
            str(args["source"]),
            str(args["target"]),
            max_depth=int(args.get("max_depth") or self.config.correlation.filtering.max_path_depth),
        )
        return {"success": True, "tool": "graph.find_paths", "result": {"paths": [item.to_dict() for item in paths[:10]]}}

    def _graph_get_cross_component_context(self, args: dict[str, Any]) -> dict[str, Any]:
        context = ComponentGraphBuilder(self.workspace.workspace_root, self.workspace.task_id, config=self.config).cross_component_context(
            str(args["hypothesis_id"]),
            max_depth=int(args.get("max_depth") or self.config.correlation.filtering.max_path_depth),
            max_nodes=int(args.get("max_nodes") or self.config.correlation.filtering.max_context_nodes),
        )
        return {"success": True, "tool": "graph.get_cross_component_context", "result": {"context": context.to_dict(), "provider_backed": False}}

    def _graph_get_relationship_evidence(self, args: dict[str, Any]) -> dict[str, Any]:
        graph = self._component_graph()
        relationship = graph.relationships.get(str(args["relationship_id"]))
        if relationship is None:
            return {"success": False, "tool": "graph.get_relationship_evidence", "errors": [f"relationship not found: {args['relationship_id']}"]}
        return {
            "success": True,
            "tool": "graph.get_relationship_evidence",
            "result": {
                "relationship": relationship.to_dict(),
                "evidence_ids": relationship.evidence_ids,
                "provenance": relationship.provenance,
                "execution_mode": relationship.execution_mode,
            },
        }

    def _graph_get_runtime_path(self, args: dict[str, Any]) -> dict[str, Any]:
        graph = self._component_graph()
        paths = graph.find_paths("lighttpd", "application response", max_depth=self.config.correlation.filtering.max_path_depth)
        return {
            "success": True,
            "tool": "graph.get_runtime_path",
            "result": {"paths": [item.to_dict() for item in paths if item.reachable][:10], "provider_backed": False},
        }

    def _attack_surface(self) -> dict[str, Any]:
        return AttackSurfaceBuilder(self.workspace.workspace_root, self.workspace.task_id, config=self.config).load_or_build()

    def _surface_list_entry_points(self, args: dict[str, Any]) -> dict[str, Any]:
        surface = self._attack_surface()
        return {"success": True, "tool": "surface.list_entry_points", "result": {"entry_points": surface.get("entry_points", []), "provider_backed": False}}

    def _surface_get_entry_point(self, args: dict[str, Any]) -> dict[str, Any]:
        surface = self._attack_surface()
        entry_id = str(args["entry_id"])
        entry = next((item for item in surface.get("entry_points", []) if item.get("entry_id") == entry_id), None)
        if entry is None:
            return {"success": False, "tool": "surface.get_entry_point", "errors": [f"entry point not found: {entry_id}"]}
        return {"success": True, "tool": "surface.get_entry_point", "result": {"entry_point": entry, "provider_backed": False}}

    def _surface_get_attack_surface_summary(self, args: dict[str, Any]) -> dict[str, Any]:
        surface = self._attack_surface()
        return {"success": True, "tool": "surface.get_attack_surface_summary", "result": {"summary": surface.get("summary", {}), "provider_backed": False}}

    def _surface_get_reachability(self, args: dict[str, Any]) -> dict[str, Any]:
        surface = self._attack_surface()
        entry_id = args.get("entry_id")
        items = surface.get("reachability", [])
        if entry_id:
            items = [item for item in items if item.get("entry_point_id") == str(entry_id)]
        return {"success": True, "tool": "surface.get_reachability", "result": {"reachability": items, "provider_backed": False}}

    def _surface_get_entry_context(self, args: dict[str, Any]) -> dict[str, Any]:
        surface = self._attack_surface()
        entry_id = str(args["entry_id"])
        context = next((item for item in surface.get("entry_contexts", []) if (item.get("entry_point") or {}).get("entry_id") == entry_id), None)
        if context is None:
            return {"success": False, "tool": "surface.get_entry_context", "errors": [f"entry context not found: {entry_id}"]}
        return {"success": True, "tool": "surface.get_entry_context", "result": {"context": context, "provider_backed": False}}

    def _surface_get_hypothesis_entries(self, args: dict[str, Any]) -> dict[str, Any]:
        surface = self._attack_surface()
        hypothesis_id = str(args["hypothesis_id"])
        entries = [item for item in surface.get("hypothesis_reachability", []) if item.get("hypothesis_id") == hypothesis_id]
        if not entries:
            return {"success": False, "tool": "surface.get_hypothesis_entries", "errors": [f"hypothesis reachability not found: {hypothesis_id}"]}
        return {"success": True, "tool": "surface.get_hypothesis_entries", "result": {"hypothesis_reachability": entries, "provider_backed": False}}

    def _surface_get_runtime_confirmed_entries(self, args: dict[str, Any]) -> dict[str, Any]:
        surface = self._attack_surface()
        entries = [item for item in surface.get("entry_points", []) if item.get("runtime_confirmed")]
        return {"success": True, "tool": "surface.get_runtime_confirmed_entries", "result": {"entry_points": entries, "provider_backed": False}}

    def _taint(self) -> dict[str, Any]:
        return TaintAnalysisBuilder(self.workspace.workspace_root, self.workspace.task_id, config=self.config).load_or_build()

    def _taint_list_sources(self, args: dict[str, Any]) -> dict[str, Any]:
        payload = self._taint()
        return {"success": True, "tool": "taint.list_sources", "result": {"sources": payload.get("sources", []), "provider_backed": False}}

    def _taint_list_sinks(self, args: dict[str, Any]) -> dict[str, Any]:
        payload = self._taint()
        return {"success": True, "tool": "taint.list_sinks", "result": {"sinks": payload.get("sinks", []), "provider_backed": False}}

    def _taint_get_source(self, args: dict[str, Any]) -> dict[str, Any]:
        payload = self._taint()
        source_id = str(args["source_id"])
        source = next((item for item in payload.get("sources", []) if item.get("source_id") == source_id), None)
        if source is None:
            return {"success": False, "tool": "taint.get_source", "errors": [f"source not found: {source_id}"]}
        return {"success": True, "tool": "taint.get_source", "result": {"source": source, "provider_backed": False}}

    def _taint_get_sink(self, args: dict[str, Any]) -> dict[str, Any]:
        payload = self._taint()
        sink_id = str(args["sink_id"])
        sink = next((item for item in payload.get("sinks", []) if item.get("sink_id") == sink_id), None)
        if sink is None:
            return {"success": False, "tool": "taint.get_sink", "errors": [f"sink not found: {sink_id}"]}
        return {"success": True, "tool": "taint.get_sink", "result": {"sink": sink, "provider_backed": False}}

    def _taint_find_paths(self, args: dict[str, Any]) -> dict[str, Any]:
        payload = self._taint()
        paths = payload.get("taint_paths", [])
        if args.get("source_id"):
            paths = [item for item in paths if item.get("source_id") == str(args["source_id"])]
        if args.get("sink_id"):
            paths = [item for item in paths if item.get("sink_id") == str(args["sink_id"])]
        if args.get("hypothesis_id"):
            paths = [item for item in paths if str(args["hypothesis_id"]) in item.get("hypothesis_ids", [])]
        return {"success": True, "tool": "taint.find_paths", "result": {"paths": paths, "provider_backed": False}}

    def _taint_get_path(self, args: dict[str, Any]) -> dict[str, Any]:
        payload = self._taint()
        path_id = str(args["path_id"])
        path = next((item for item in payload.get("taint_paths", []) if item.get("path_id") == path_id), None)
        if path is None:
            return {"success": False, "tool": "taint.get_path", "errors": [f"path not found: {path_id}"]}
        return {"success": True, "tool": "taint.get_path", "result": {"path": path, "provider_backed": False}}

    def _taint_get_hypothesis_context(self, args: dict[str, Any]) -> dict[str, Any]:
        context = TaintAnalysisBuilder(self.workspace.workspace_root, self.workspace.task_id, config=self.config).context(hypothesis_id=str(args["hypothesis_id"]))
        return {"success": True, "tool": "taint.get_hypothesis_context", "result": {"context": context.to_dict(), "provider_backed": False}}

    def _taint_get_summary(self, args: dict[str, Any]) -> dict[str, Any]:
        payload = self._taint()
        return {"success": True, "tool": "taint.get_summary", "result": {"summary": payload.get("summary", {}), "provider_backed": False}}

    def _synthesis(self) -> dict[str, Any]:
        return HypothesisSynthesizer(self.workspace.workspace_root, self.workspace.task_id, config=self.config).load_or_build()

    def _hypothesis_list_candidates(self, args: dict[str, Any]) -> dict[str, Any]:
        payload = self._synthesis()
        return {"success": True, "tool": "hypothesis.list_candidates", "result": {"candidates": payload.get("candidates", []), "provider_backed": False}}

    def _hypothesis_get_candidate(self, args: dict[str, Any]) -> dict[str, Any]:
        candidate_id = str(args["candidate_id"])
        candidate = next((item for item in self._synthesis().get("candidates", []) if item.get("candidate_id") == candidate_id), None)
        if candidate is None:
            return {"success": False, "tool": "hypothesis.get_candidate", "errors": [f"candidate not found: {candidate_id}"]}
        return {"success": True, "tool": "hypothesis.get_candidate", "result": {"candidate": candidate, "provider_backed": False}}

    def _hypothesis_get_evidence_bundle(self, args: dict[str, Any]) -> dict[str, Any]:
        candidate_id = str(args["candidate_id"])
        bundle = next((item for item in self._synthesis().get("evidence_bundles", []) if item.get("candidate_id") == candidate_id), None)
        if bundle is None:
            return {"success": False, "tool": "hypothesis.get_evidence_bundle", "errors": [f"evidence bundle not found: {candidate_id}"]}
        return {"success": True, "tool": "hypothesis.get_evidence_bundle", "result": {"evidence_bundle": bundle, "provider_backed": False}}

    def _hypothesis_get_generation_reason(self, args: dict[str, Any]) -> dict[str, Any]:
        candidate_id = str(args["candidate_id"])
        candidate = next((item for item in self._synthesis().get("candidates", []) if item.get("candidate_id") == candidate_id), None)
        if candidate is None:
            return {"success": False, "tool": "hypothesis.get_generation_reason", "errors": [f"candidate not found: {candidate_id}"]}
        return {
            "success": True,
            "tool": "hypothesis.get_generation_reason",
            "result": {"candidate_id": candidate_id, "generation_reason": candidate.get("generation_reason"), "provider_backed": False},
        }

    def _hypothesis_get_missing_evidence(self, args: dict[str, Any]) -> dict[str, Any]:
        candidate_id = str(args["candidate_id"])
        candidate = next((item for item in self._synthesis().get("candidates", []) if item.get("candidate_id") == candidate_id), None)
        if candidate is None:
            return {"success": False, "tool": "hypothesis.get_missing_evidence", "errors": [f"candidate not found: {candidate_id}"]}
        return {
            "success": True,
            "tool": "hypothesis.get_missing_evidence",
            "result": {"candidate_id": candidate_id, "missing_evidence": candidate.get("missing_evidence", []), "provider_backed": False},
        }

    def _hypothesis_list_generated(self, args: dict[str, Any]) -> dict[str, Any]:
        payload = self._synthesis()
        return {"success": True, "tool": "hypothesis.list_generated", "result": {"generated": payload.get("canonical_generated", []), "provider_backed": False}}

    def _finding_list_candidates(self, args: dict[str, Any]) -> dict[str, Any]:
        payload = self._synthesis()
        return {"success": True, "tool": "finding.list_candidates", "result": {"finding_candidates": payload.get("finding_candidates", []), "provider_backed": False}}

    def _finding_get_candidate(self, args: dict[str, Any]) -> dict[str, Any]:
        finding_id = str(args["finding_candidate_id"])
        finding = next((item for item in self._synthesis().get("finding_candidates", []) if item.get("finding_candidate_id") == finding_id), None)
        if finding is None:
            return {"success": False, "tool": "finding.get_candidate", "errors": [f"finding candidate not found: {finding_id}"]}
        return {"success": True, "tool": "finding.get_candidate", "result": {"finding_candidate": finding, "provider_backed": False}}

    def _investigation_controller(self) -> InvestigationController:
        return InvestigationController(self.workspace.workspace_root, self.workspace.task_id, config=self.config)

    def _investigation_get_state(self, args: dict[str, Any]) -> dict[str, Any]:
        controller = self._investigation_controller()
        state = controller.load_or_create_state()
        return {"success": True, "tool": "investigation.get_state", "result": {"state": state.to_dict(), "provider_backed": False}}

    def _investigation_get_context(self, args: dict[str, Any]) -> dict[str, Any]:
        controller = self._investigation_controller()
        return {"success": True, "tool": "investigation.get_context", "result": {"context": controller.context().to_dict(), "provider_backed": False}}

    def _investigation_get_budget(self, args: dict[str, Any]) -> dict[str, Any]:
        controller = self._investigation_controller()
        return {
            "success": True,
            "tool": "investigation.get_budget",
            "result": {"budget": controller.budget.to_dict(), "budget_state": controller.load_budget_state().to_dict(), "provider_backed": False},
        }

    def _investigation_get_history(self, args: dict[str, Any]) -> dict[str, Any]:
        history = self.workspace.load_investigation_artifact("action_history.json") or []
        return {"success": True, "tool": "investigation.get_history", "result": {"history": history, "provider_backed": False}}

    def _investigation_get_next_action(self, args: dict[str, Any]) -> dict[str, Any]:
        action = self._investigation_controller().next_action()
        return {"success": True, "tool": "investigation.get_next_action", "result": {"action": action, "provider_backed": False}}

    def _investigation_get_iteration(self, args: dict[str, Any]) -> dict[str, Any]:
        iteration_id = str(args["iteration_id"])
        iterations = self.workspace.load_investigation_artifact("iterations.json") or []
        iteration = next((item for item in iterations if item.get("iteration_id") == iteration_id), None)
        if iteration is None:
            return {"success": False, "tool": "investigation.get_iteration", "errors": [f"iteration not found: {iteration_id}"]}
        return {"success": True, "tool": "investigation.get_iteration", "result": {"iteration": iteration, "provider_backed": False}}

    def _investigation_request_reassessment(self, args: dict[str, Any]) -> dict[str, Any]:
        summary = self._investigation_controller().run(max_iterations=1)
        return {"success": True, "tool": "investigation.request_reassessment", "result": summary}

    def _create_validation_plan(self, args: dict[str, Any]) -> dict[str, Any]:
        if args.get("destructive"):
            return {"success": False, "tool": "dynamic.create_validation_plan", "errors": ["destructive validation is forbidden"]}
        if str(args.get("risk_level") or "low") not in {"low", "moderate"}:
            return {"success": False, "tool": "dynamic.create_validation_plan", "errors": ["risk_level must be low or moderate"]}
        hypothesis_id = str(args["hypothesis_id"])
        hypothesis = self._lookup_hypothesis(hypothesis_id)
        if hypothesis is None:
            return {"success": False, "tool": "dynamic.create_validation_plan", "errors": [f"hypothesis not found: {hypothesis_id}"]}
        static_evidence = self._static_evidence_for(hypothesis)
        context = build_static_dynamic_context(hypothesis.to_dict(), static_evidence, self._static_report())
        strategy = str(args.get("validation_strategy") or ("input_behavior_difference" if context.runtime_backend == "fastcgi-integration" else "handler_reachability"))
        runtime_backend = str(args.get("runtime_backend") or context.runtime_backend)
        validation_id = f"DV-{len(list(self.workspace.validation_dir.glob('DV-*'))) + 1:04d}"
        plan = DynamicValidationPlan(
            validation_id=validation_id,
            hypothesis_id=hypothesis_id,
            target_binary=context.target_binary,
            target_service=context.candidate_service,
            target_function=context.candidate_functions[0] if context.candidate_functions else None,
            runtime_backend=runtime_backend,
            validation_goal=str(hypothesis.title),
            validation_strategy=strategy,
            required_evidence=["runtime_ready", "baseline_response", "validation_request"],
            expected_observations=list(getattr(hypothesis, "next_actions", []) or ["application response or bounded behavior difference"]),
            contradictory_observations=["endpoint unreachable", "handler not reached"],
            preconditions=["local Docker/service-qemu runtime", "loopback-only target"],
            request_budget=int(args.get("request_budget") or min(self.config.validation.max_requests, 3)),
            step_budget=self.config.validation.max_steps,
            timeout_seconds=self.config.validation.timeout_seconds,
            risk_level=str(args.get("risk_level") or "low"),
            destructive=False,
            relevant_evidence_ids=context.relevant_evidence_ids,
            known_endpoint=context.known_endpoint,
            known_protocol=context.known_protocol,
            out_of_scope=["exploitation", "persistence", "remote target probing", "credential access", "shell spawning"],
        )
        self.workspace.save_validation_artifact(validation_id, "plan.json", plan.to_dict())
        inputs = [item.to_dict() for item in default_safe_inputs(plan, max_inputs=min(plan.request_budget, self.config.validation.max_requests))]
        self.workspace.save_validation_artifact(validation_id, "inputs.json", inputs)
        self.workspace.save_validation_artifact(validation_id, "context.json", context.to_dict())
        evidence = self._create_evidence(
            {
                "type": "validation_plan_created",
                "observation": f"Created dynamic validation plan {validation_id} for {hypothesis_id}",
                "source_tool": "dynamic.create_validation_plan",
                "confidence": 0.9,
                "target": hypothesis_id,
                "metadata": {"validation_id": validation_id, "hypothesis_id": hypothesis_id, "context": context.to_dict()},
            }
        )
        hypothesis.dynamic_status = "validation_planned"
        hypothesis.status = hypothesis.static_status or hypothesis.status
        self.workspace.save_hypotheses(self.hypotheses)
        return {
            "success": True,
            "tool": "dynamic.create_validation_plan",
            "result": {
                "plan": plan.to_dict(),
                "inputs": inputs,
                "context": context.to_dict(),
                "evidence_id": evidence.get("result", {}).get("id"),
            },
        }

    def _get_validation_plan(self, args: dict[str, Any]) -> dict[str, Any]:
        validation_id = str(args["validation_id"])
        plan = self.workspace.load_validation_artifact(validation_id, "plan.json")
        if plan is None:
            return {"success": False, "tool": "dynamic.get_validation_plan", "errors": [f"validation plan not found: {validation_id}"]}
        return {"success": True, "tool": "dynamic.get_validation_plan", "result": {"plan": plan}}

    def _run_safe_validation(self, args: dict[str, Any]) -> dict[str, Any]:
        validation_id = str(args["validation_id"])
        plan_data = self.workspace.load_validation_artifact(validation_id, "plan.json")
        if plan_data is None:
            return {"success": False, "tool": "dynamic.run_safe_validation", "errors": [f"validation plan not found: {validation_id}"]}
        plan = DynamicValidationPlan(**plan_data)
        raw_inputs = args.get("inputs") or self.workspace.load_validation_artifact(validation_id, "inputs.json") or []
        safe_inputs: list[SafeValidationInput] = []
        errors: list[str] = []
        if len(raw_inputs) > min(plan.request_budget, self.config.validation.max_requests):
            errors.append("request budget reached")
        for raw in raw_inputs[: min(plan.request_budget, self.config.validation.max_requests)]:
            try:
                item = SafeValidationInput(**raw)
            except (TypeError, ValueError) as exc:
                errors.append(str(exc))
                continue
            errors.extend(validate_safe_input(item, max_request_bytes=self.config.validation.max_request_bytes, max_body_bytes=self.config.validation.max_body_bytes))
            safe_inputs.append(item)
        if errors:
            return {"success": False, "tool": "dynamic.run_safe_validation", "errors": errors}
        hypothesis = self._lookup_hypothesis(plan.hypothesis_id)
        if hypothesis is not None:
            hypothesis.dynamic_status = "validation_running"
            self.workspace.save_hypotheses(self.hypotheses)
        blocked = False
        runtime_result: dict[str, Any]
        if plan.runtime_backend == "fastcgi-integration" and hasattr(self.backend, "validate_fastcgi_integration"):
            runtime_result = self.backend.validate_fastcgi_integration(
                "device_manager",
                endpoint=plan.known_endpoint or "/services/device_manager/",
                stability_seconds=2,
                safe_inputs=[item.to_dict() for item in safe_inputs],
                max_response_preview=self.config.validation.max_response_preview,
            )
        elif plan.runtime_backend == "process-stdin":
            runtime_result = {
                "success": False,
                "diagnosis": "validation_inconclusive",
                "runtime_backend": "process-stdin",
                "request_observations": [
                    {
                        "input_id": item.input_id,
                        "probe": None,
                        "errors": ["process stdin runtime execution is intentionally not automated in Round 4"],
                        "backend_alive_after": None,
                        "lighttpd_alive_after": None,
                    }
                    for item in safe_inputs
                ],
            }
            blocked = True
        else:
            runtime_result = {"success": False, "diagnosis": "unsupported_runtime_backend", "errors": [f"unsupported runtime backend: {plan.runtime_backend}"]}
            blocked = True
        observations = self._observations_from_runtime(plan, safe_inputs, runtime_result)
        differentials = [compare_behavior(observations[0], item) for item in observations[1:]] if observations else []
        self.workspace.save_validation_artifact(validation_id, "observations.json", [item.to_dict() for item in observations])
        self.workspace.save_validation_artifact(validation_id, "differential.json", [item.to_dict() for item in differentials])
        self.workspace.save_validation_artifact(validation_id, "runtime.json", runtime_result)
        evidence_ids = self._evidence_for_validation(plan, observations, differentials, runtime_result, blocked=blocked)
        verdict = decide_verdict(plan, observations, differentials, blocked=blocked or not runtime_result.get("success"), evidence_ids=evidence_ids)
        self.workspace.save_validation_artifact(validation_id, "verdict.json", verdict.to_dict())
        self.workspace.save_validation_artifact(validation_id, "evidence.json", {"evidence_ids": evidence_ids})
        return {
            "success": bool(runtime_result.get("success")) and verdict.dynamic_status != "validation_blocked",
            "tool": "dynamic.run_safe_validation",
            "result": {
                "validation_id": validation_id,
                "runtime": runtime_result,
                "observations": [item.to_dict() for item in observations],
                "differentials": [item.to_dict() for item in differentials],
                "evidence_ids": evidence_ids,
                "verdict": verdict.to_dict(),
            },
        }

    def _get_validation_status(self, args: dict[str, Any]) -> dict[str, Any]:
        validation_id = str(args["validation_id"])
        verdict = self.workspace.load_validation_artifact(validation_id, "verdict.json")
        plan = self.workspace.load_validation_artifact(validation_id, "plan.json")
        if plan is None:
            return {"success": False, "tool": "dynamic.get_validation_status", "errors": [f"validation not found: {validation_id}"]}
        return {"success": True, "tool": "dynamic.get_validation_status", "result": {"validation_id": validation_id, "plan": plan, "verdict": verdict}}

    def _get_validation_observations(self, args: dict[str, Any]) -> dict[str, Any]:
        validation_id = str(args["validation_id"])
        observations = self.workspace.load_validation_artifact(validation_id, "observations.json")
        if observations is None:
            return {"success": False, "tool": "dynamic.get_validation_observations", "errors": [f"observations not found: {validation_id}"]}
        return {"success": True, "tool": "dynamic.get_validation_observations", "result": {"validation_id": validation_id, "observations": observations}}

    def _finalize_validation(self, args: dict[str, Any]) -> dict[str, Any]:
        validation_id = str(args["validation_id"])
        verdict_data = self.workspace.load_validation_artifact(validation_id, "verdict.json")
        plan_data = self.workspace.load_validation_artifact(validation_id, "plan.json")
        if verdict_data is None or plan_data is None:
            return {"success": False, "tool": "dynamic.finalize_validation", "errors": [f"validation verdict not found: {validation_id}"]}
        hypothesis = self._lookup_hypothesis(str(plan_data["hypothesis_id"]))
        if hypothesis is None:
            return {"success": False, "tool": "dynamic.finalize_validation", "errors": [f"hypothesis not found: {plan_data['hypothesis_id']}"]}
        hypothesis.dynamic_status = str(verdict_data["dynamic_status"])
        hypothesis.status = str(verdict_data["dynamic_status"])
        hypothesis.confidence = float(verdict_data["dynamic_confidence"])
        hypothesis.evidence_ids = list(dict.fromkeys([*hypothesis.evidence_ids, *verdict_data.get("evidence_ids", [])]))
        hypothesis.missing_evidence = list(verdict_data.get("missing_observations", []))
        hypothesis.next_actions = []
        self.workspace.save_hypotheses(self.hypotheses)
        if verdict_data["dynamic_status"] == "dynamically_supported":
            evidence_type = "validation_supported"
        elif verdict_data["dynamic_status"] == "dynamically_rejected":
            evidence_type = "validation_rejected"
        elif verdict_data["dynamic_status"] == "validation_blocked" and verdict_data.get("stop_reason") == "safety_stop":
            evidence_type = "validation_safety_stop"
        else:
            evidence_type = str(verdict_data["dynamic_status"])
        final_evidence = self._create_evidence(
            {
                "type": evidence_type,
                "observation": f"Validation {validation_id} finalized with {verdict_data['dynamic_status']}",
                "source_tool": "dynamic.finalize_validation",
                "confidence": verdict_data["dynamic_confidence"],
                "target": hypothesis.id,
                "metadata": {"validation_id": validation_id, "hypothesis_id": hypothesis.id, "verdict": verdict_data},
            }
        )
        return {"success": True, "tool": "dynamic.finalize_validation", "result": {"hypothesis": hypothesis.to_dict(), "evidence_id": final_evidence.get("result", {}).get("id")}}

    def _application_list_endpoints(self, args: dict[str, Any]) -> dict[str, Any]:
        if not hasattr(self.backend, "list_application_endpoints"):
            return {"success": False, "tool": "application.list_endpoints", "errors": ["backend does not support endpoint reconstruction"]}
        backend = _application_backend_arg(args)
        result = self.backend.list_application_endpoints(backend)
        for endpoint in result.get("endpoints", [])[:50]:
            self._auto_evidence("endpoint_discovered", f"Application endpoint reconstructed: {endpoint.get('path')}", "application_endpoints", endpoint, target=endpoint.get("path"))
        for link in result.get("links", [])[:50]:
            self._auto_evidence("endpoint_backend_link", f"Endpoint {link.get('endpoint')} routes to {backend}", "application_endpoints", link, target=link.get("endpoint"))
        return {"success": bool(result.get("success")), "tool": "application.list_endpoints", "result": result}

    def _application_get_endpoint(self, args: dict[str, Any]) -> dict[str, Any]:
        backend = _application_backend_arg(args)
        listed = self._application_list_endpoints({"backend": backend})
        path = str(args["path"])
        for endpoint in listed.get("result", {}).get("endpoints", []):
            if endpoint.get("path") == path:
                return {"success": True, "tool": "application.get_endpoint", "result": endpoint}
        return {"success": False, "tool": "application.get_endpoint", "errors": [f"endpoint not found: {path}"]}

    def _application_probe_endpoint(self, args: dict[str, Any]) -> dict[str, Any]:
        if not hasattr(self.backend, "probe_application_endpoint"):
            return {"success": False, "tool": "application.probe_endpoint", "errors": ["backend does not support endpoint probing"]}
        backend = _application_backend_arg(args)
        result = self.backend.probe_application_endpoint(backend, str(args["path"]), method=str(args.get("method") or "GET"))
        if result.get("success"):
            self._auto_evidence("application_endpoint_reachable", f"Application endpoint {args['path']} returned a backend response", "application_probe", result, target=str(args["path"]))
            self._auto_evidence("endpoint_reachable", f"Endpoint {args['path']} is reachable", "application_probe", result, target=str(args["path"]))
        return {"success": bool(result.get("success")), "tool": "application.probe_endpoint", "result": result}

    def _application_create_evidence(self, args: dict[str, Any]) -> dict[str, Any]:
        payload = {
            "type": str(args["type"]),
            "observation": str(args["observation"]),
            "source_tool": "application_api",
            "confidence": 0.85,
            "target": args.get("target"),
            "metadata": args.get("metadata") or {},
        }
        return self._create_evidence(payload)

    def _create_evidence(
        self,
        args: dict[str, Any],
        *,
        canonical_runtime_observation: bool = False,
    ) -> dict[str, Any]:
        evidence_type = str(args["type"])
        if evidence_type not in DYNAMIC_EVIDENCE_TYPES:
            return {"success": False, "tool": "dynamic.create_evidence", "errors": [f"invalid evidence type: {evidence_type}"]}
        canonical = canonical_runtime_observation and evidence_type in CANONICAL_RUNTIME_OBSERVATION_TYPES
        evidence = DynamicEvidence(
            id=f"DE-{len(self.evidence) + 1:04d}",
            type=evidence_type,
            target=args.get("target"),
            observation=str(args["observation"]),
            source_tool=str(args.get("source_tool") or "dynamic_api"),
            confidence=_clamp(args.get("confidence"), 0.8),
            metadata=args.get("metadata") or {},
            provenance="real_runtime_observation" if canonical else "runtime_status_record",
            runtime_observation_real=canonical,
        )
        self.evidence.append(evidence)
        self.workspace.save_evidence(self.evidence)
        return {"success": True, "tool": "dynamic.create_evidence", "result": {"id": evidence.id}}

    def _update_hypothesis(self, args: dict[str, Any]) -> dict[str, Any]:
        status = str(args["status"])
        if status not in VALID_DYNAMIC_HYPOTHESIS_STATUSES:
            return {"success": False, "tool": "dynamic.update_hypothesis", "errors": [f"invalid status: {status}"]}
        hypothesis_id = args.get("id")
        hypothesis = next((item for item in self.hypotheses if item.id == hypothesis_id), None)
        if hypothesis is None:
            hypothesis = DynamicHypothesis(
                id=hypothesis_id or f"H-{len(self.hypotheses) + 1:04d}",
                title=str(args["title"]),
                status=status,
                confidence=_clamp(args.get("confidence"), 0.5),
                cwe=args.get("cwe"),
                evidence_ids=list(args.get("evidence_ids") or []),
                missing_evidence=list(args.get("missing_evidence") or []),
                next_actions=list(args.get("next_actions") or []),
                static_status=args.get("static_status"),
                dynamic_status=args.get("dynamic_status"),
            )
            self.hypotheses.append(hypothesis)
        else:
            hypothesis.status = status
            hypothesis.confidence = _clamp(args.get("confidence"), hypothesis.confidence)
            if "cwe" in args:
                hypothesis.cwe = args.get("cwe")
            if "evidence_ids" in args:
                hypothesis.evidence_ids = list(args["evidence_ids"])
            if "missing_evidence" in args:
                hypothesis.missing_evidence = list(args["missing_evidence"])
            if "next_actions" in args:
                hypothesis.next_actions = list(args["next_actions"])
            if "static_status" in args:
                hypothesis.static_status = args.get("static_status")
            if "dynamic_status" in args:
                hypothesis.dynamic_status = args.get("dynamic_status")
        self.workspace.save_hypotheses(self.hypotheses)
        return {"success": True, "tool": "dynamic.update_hypothesis", "result": {"id": hypothesis.id}}

    def _auto_evidence(
        self,
        evidence_type: str,
        observation: str,
        source_tool: str,
        result: dict[str, Any],
        *,
        target: str | None = None,
    ) -> None:
        if result.get("error_code") == BLOCK_CODE:
            # An execution policy refusal is not a runtime attempt/observation.
            return
        if evidence_type not in DYNAMIC_EVIDENCE_TYPES:
            return
        runtime_observation_real = _is_real_runtime_observation(evidence_type, result)
        self.evidence.append(
            DynamicEvidence(
                id=f"DE-{len(self.evidence) + 1:04d}",
                type=evidence_type,
                target=target,
                observation=observation,
                source_tool=source_tool,
                confidence=0.9,
                metadata={"result_summary": json.dumps(_compact(result), ensure_ascii=True)[:1000]},
                provenance="real_runtime_observation" if runtime_observation_real else "real_runtime_attempt",
                runtime_observation_real=runtime_observation_real,
            )
        )
        self.workspace.save_evidence(self.evidence)

    def _seed_hypotheses_from_static(self) -> None:
        if self.hypotheses:
            return
        static_path = self.workspace.task_dir / "hypotheses" / "hypotheses.json"
        if not static_path.exists():
            return
        try:
            static = json.loads(static_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return
        for item in static:
            status = item.get("status", "candidate")
            if status not in VALID_DYNAMIC_HYPOTHESIS_STATUSES:
                status = "candidate"
            self.hypotheses.append(
                DynamicHypothesis(
                    id=str(item.get("id") or f"H-{len(self.hypotheses) + 1:04d}"),
                    title=str(item.get("title") or "Dynamic validation hypothesis"),
                    status=status,
                    confidence=float(item.get("confidence", 0.5)),
                    cwe=item.get("cwe"),
                    evidence_ids=list(item.get("evidence_ids") or []),
                    missing_evidence=list(item.get("missing_evidence") or []),
                    next_actions=list(item.get("next_actions") or []),
                    static_status=str(item.get("status") or "candidate"),
                    dynamic_status="not_tested",
                )
            )
        self.workspace.save_hypotheses(self.hypotheses)

    def _lookup_hypothesis(self, hypothesis_id: str) -> DynamicHypothesis | None:
        return next((item for item in self.hypotheses if item.id == hypothesis_id), None)

    def _static_report(self) -> dict[str, Any]:
        try:
            return self.workspace.load_report()
        except Exception:  # noqa: BLE001 - missing reports are handled by bridge defaults
            return {}

    def _static_evidence_for(self, hypothesis: DynamicHypothesis) -> list[dict[str, Any]]:
        report = self._static_report()
        evidence: list[dict[str, Any]] = []
        for key in ("evidence", "security_candidates"):
            items = report.get(key)
            if isinstance(items, list):
                evidence.extend(item for item in items if isinstance(item, dict))
        static_path = self.workspace.task_dir / "evidence" / "evidence.json"
        if static_path.exists():
            try:
                items = json.loads(static_path.read_text(encoding="utf-8"))
                if isinstance(items, list):
                    evidence.extend(item for item in items if isinstance(item, dict))
            except json.JSONDecodeError:
                pass
        if hypothesis.evidence_ids:
            selected = [item for item in evidence if str(item.get("id")) in set(hypothesis.evidence_ids)]
            if selected:
                return selected
        return evidence[:50]

    def _observations_from_runtime(
        self,
        plan: DynamicValidationPlan,
        safe_inputs: list[SafeValidationInput],
        runtime_result: dict[str, Any],
    ) -> list[BehaviorObservation]:
        by_input = {item.input_id: item for item in safe_inputs}
        raw_observations = runtime_result.get("request_observations") or []
        if not raw_observations and runtime_result.get("probe"):
            raw_observations = [{"input_id": safe_inputs[0].input_id if safe_inputs else "VI-0001", "probe": runtime_result.get("probe")}]
        observations: list[BehaviorObservation] = []
        for index, raw in enumerate(raw_observations, start=1):
            input_id = str(raw.get("input_id") or f"VI-{index:04d}")
            probe = raw.get("probe") or {}
            signature = response_signature(probe, max_preview=self.config.validation.max_response_preview).to_dict() if probe else None
            errors = raw.get("errors") or []
            duration_ms = int(float((probe or {}).get("duration") or 0) * 1000)
            process_alive_after = raw.get("backend_alive_after")
            service_alive_after = raw.get("lighttpd_alive_after")
            observations.append(
                BehaviorObservation(
                    observation_id=f"BO-{index:04d}",
                    validation_id=plan.validation_id,
                    input_id=input_id,
                    http_status=probe.get("status") if probe else None,
                    response_signature=signature,
                    response_length=len(str((probe or {}).get("body_preview") or "")),
                    process_alive_before=bool(runtime_result.get("backend_child", {}).get("alive_after_startup")) if runtime_result.get("backend_child") else None,
                    process_alive_after=process_alive_after if process_alive_after is not None else None,
                    service_state="running" if service_alive_after else "stopped" if service_alive_after is False else None,
                    runtime_error="; ".join(errors)[:500] if errors else None,
                    log_signature=_log_signature(runtime_result.get("logs") or {}),
                    duration_ms=duration_ms,
                    side_effect_detected=False,
                    notes=f"{(by_input.get(input_id) or SafeValidationInput(input_id=input_id)).category} validation input observed",
                )
            )
        return observations

    def _evidence_for_validation(
        self,
        plan: DynamicValidationPlan,
        observations: list[BehaviorObservation],
        differentials: list[Any],
        runtime_result: dict[str, Any],
        *,
        blocked: bool = False,
    ) -> list[str]:
        evidence_ids: list[str] = []

        def add(evidence_type: str, observation: str, metadata: dict[str, Any], confidence: float = 0.85) -> None:
            created = self._create_evidence(
                {
                    "type": evidence_type,
                    "observation": observation,
                    "source_tool": "dynamic.run_safe_validation",
                    "confidence": confidence,
                    "target": plan.hypothesis_id,
                    "metadata": {"validation_id": plan.validation_id, "hypothesis_id": plan.hypothesis_id, **metadata},
                },
                canonical_runtime_observation=not blocked,
            )
            evidence_id = created.get("result", {}).get("id")
            if evidence_id:
                evidence_ids.append(evidence_id)

        if blocked:
            add("validation_blocked", f"Runtime {plan.runtime_backend} blocked validation {plan.validation_id}", {"runtime": runtime_result}, 0.75)
        elif runtime_result.get("success"):
            add("runtime_ready", f"Runtime {plan.runtime_backend} was ready for validation {plan.validation_id}", {"runtime": runtime_result.get("diagnosis")}, 0.9)
        for item in observations:
            evidence_type = "baseline_response" if item.input_id.endswith("0001") else "validation_request"
            add(evidence_type, f"Observed response for {item.input_id} during validation {plan.validation_id}", {"input_id": item.input_id, "observation": item.to_dict()}, 0.85)
            signature = item.response_signature or {}
            if item.http_status is not None and (signature.get("known_error") or signature.get("body_hash")):
                add("application_response", f"Application-level response observed for {item.input_id}", {"input_id": item.input_id, "response_signature": signature}, 0.85)
                if plan.runtime_backend == "fastcgi-integration":
                    add("handler_reached", f"FastCGI handler path reached for {item.input_id}", {"input_id": item.input_id}, 0.75)
        for item in differentials:
            if item.relevance in {"medium", "high"}:
                add("behavior_difference", f"Behavior differential observed in validation {plan.validation_id}: {item.relevance}", {"differential": item.to_dict()}, 0.8)
        return evidence_ids

    def _normalize(self, spec: DynamicToolSpec, args: Any) -> dict[str, Any]:
        if not isinstance(args, dict):
            return {}
        normalized = dict(args)
        if "url" in normalized and "host" not in normalized:
            normalized["host"] = _host_from_url(str(normalized["url"]))
        return normalized

    def _validate(self, spec: DynamicToolSpec, args: dict[str, Any]) -> list[str]:
        errors = []
        for name, meta in spec.arguments_schema.items():
            if meta.get("required") and name not in args:
                errors.append(f"missing argument: {name}")
            elif name in args and meta.get("type") == "string" and not isinstance(args[name], str):
                errors.append(f"argument {name} must be a string")
            elif name in args and meta.get("type") == "number" and not isinstance(args[name], (int, float)):
                errors.append(f"argument {name} must be a number")
            elif name in args and meta.get("type") == "array" and not isinstance(args[name], list):
                errors.append(f"argument {name} must be an array")
            elif name in args and meta.get("type") == "boolean" and not isinstance(args[name], bool):
                errors.append(f"argument {name} must be a boolean")
        return errors


def _parse_ps(output: str) -> list[dict[str, Any]]:
    processes = []
    for line in output.splitlines()[1:]:
        parts = line.strip().split(None, 2)
        if len(parts) < 2:
            continue
        processes.append({"pid": parts[0], "name": parts[1], "command": parts[2] if len(parts) > 2 else parts[1]})
    return processes


def _parse_ss_ports(output: str) -> list[int]:
    ports: set[int] = set()
    for line in output.splitlines():
        for token in line.split():
            if ":" not in token:
                continue
            candidate = token.rsplit(":", 1)[-1]
            if candidate.isdigit():
                ports.add(int(candidate))
    return sorted(ports)


def _private_target(value: str) -> bool:
    host = _host_from_url(value) if "://" in value else value
    return any(host.startswith(prefix) for prefix in PRIVATE_NETWORK_PREFIXES) or host in {"localhost", "0.0.0.0"}


def _host_from_url(value: str) -> str:
    match = re.match(r"^https?://([^:/]+)", value)
    if match:
        return match.group(1)
    return value


def _compact(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _compact(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_compact(item) for item in value[:20]]
    if isinstance(value, str) and len(value) > 500:
        return value[:500] + "..."
    return value


def _log_signature(logs: dict[str, Any]) -> str | None:
    if not logs:
        return None
    text = json.dumps(logs, ensure_ascii=True, sort_keys=True)
    if not text or text == "{}":
        return None
    import hashlib

    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:16]


def _failure_evidence_type(diagnosis: Any) -> str:
    if str(diagnosis) in {
        "image_build_failure",
        "kernel_boot_failure",
        "rootfs_mount_failure",
        "init_failure",
        "device_dependency_failure",
        "service_start_failure",
        "network_failure",
        "boot_timeout",
        "timeout",
        "backend_error",
        "unsupported_architecture",
    }:
        return "validation_blocked"
    return "boot_failure"


def _clamp(value: Any, default: float) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return default
    return max(0.0, min(1.0, parsed))


def _is_real_runtime_observation(evidence_type: str, result: dict[str, Any]) -> bool:
    if evidence_type in {
        "fastcgi_validation_blocked",
        "fastcgi_validation_inconclusive",
        "fastcgi_context_difference",
        "fastcgi_runtime_context",
        "fastcgi_runtime_difference",
        "fastcgi_exit_code_explained",
        "validation_blocked",
        "validation_inconclusive",
        "validation_rejected",
        "validation_safety_stop",
        "entry_validation_blocked",
        "entry_validation_inconclusive",
        "taint_validation_blocked",
        "taint_validation_inconclusive",
    }:
        return False
    if result.get("runtime_environment_blocked") or result.get("diagnosis") == "RUNTIME_ENVIRONMENT_BLOCKED":
        return False
    if result.get("success") is False:
        return False
    return evidence_type in CANONICAL_RUNTIME_OBSERVATION_TYPES


def _application_backend_arg(args: dict[str, Any]) -> str:
    return str(args.get("backend") or "device_manager")


def _tail(path: Path, lines: int) -> list[str]:
    if not path.exists():
        return []
    return path.read_text(encoding="utf-8", errors="replace").splitlines()[-lines:]


def _now() -> str:
    import datetime

    return datetime.datetime.now(datetime.timezone.utc).isoformat()
