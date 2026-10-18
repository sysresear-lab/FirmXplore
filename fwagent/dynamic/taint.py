from __future__ import annotations

import hashlib
import json
import logging
import re
from collections import Counter, deque
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fwagent.dynamic.config import DynamicConfig
from fwagent.dynamic.correlation import CanonicalStateGuard, ComponentGraphBuilder
from fwagent.dynamic.models import DynamicEvidence
from fwagent.dynamic.surface import AttackSurfaceBuilder
from fwagent.dynamic.static_audit import GhidraEvidenceIndex
from fwagent.dynamic.static_evidence import EvidenceValidationError, rootfs_relative_path
from fwagent.dynamic.workspace import DynamicWorkspace

logger = logging.getLogger(__name__)

# 无攻击面入口时的静态污点源兜底（P1）：从 Ghidra 证据里识别
# "接收外部输入"的函数调用，直接标记为污点源，避免 56 sink / 0 source 的断链。
_READ_FUNCS = (
    "recv", "recvfrom", "recvmsg", "read", "fread", "fgets",
    "gets", "getenv", "getchar",
)


SOURCE_TYPES = {
    "http_parameter",
    "http_header",
    "http_body",
    "soap_action",
    "cgi_parameter",
    "fastcgi_parameter",
    "tcp_stream",
    "udp_datagram",
    "stdin",
    "file_input",
    "ipc_message",
    "environment",
    "config_input",
    "device_input",
    "unknown",
}

SINK_TYPES = {
    "command_execution",
    "process_execution",
    "unsafe_copy",
    "formatted_output",
    "memory_copy",
    "file_write",
    "file_open",
    "path_operation",
    "authentication_decision",
    "authorization_decision",
    "nvram_write",
    "network_connect",
    "dynamic_load",
    "deserialization",
    "memory_allocation",
    "unknown",
}

TRANSFORM_TYPES = {
    "copy",
    "concatenate",
    "format",
    "decode",
    "parse",
    "split",
    "normalize",
    "convert",
    "store_then_load",
    "unknown",
}

SANITIZER_TYPES = {
    "length_check",
    "bounds_check",
    "allowlist",
    "denylist",
    "encoding",
    "escaping",
    "canonicalization",
    "type_validation",
    "range_validation",
    "authentication_check",
    "authorization_check",
    "copy_with_limit",
    "unknown",
}

SANITIZER_EFFECTIVENESS = {
    "proven_effective",
    "possibly_effective",
    "unknown_effectiveness",
    "bypassed_by_flow",
    "not_applicable",
}

TAINT_STATES = {
    "source",
    "propagated",
    "sanitized",
    "partially_sanitized",
    "sink_argument",
    "unknown",
    "stopped",
}

TAINT_EDGE_TYPES = {
    "callgraph_edge",
    "passes_to",
    "returns_to",
    "copied_to",
    "formatted_into",
    "parsed_into",
    "validated_by",
    "flows_to",
    "calls_with",
    "runtime_correlated",
}

PATH_STATES = {
    "candidate",
    "statically_supported",
    "runtime_supported",
    "validated",
    "blocked",
    "contradicted",
    "unknown",
}

EVIDENCE_LEVELS = {
    "L0_source_sink_exist": 0,
    "L1_same_component": 1,
    "L2_reachable_call_chain": 2,
    "L3_argument_propagation": 3,
    "L4_runtime_handler_support": 4,
    "L5_runtime_sink_observation": 5,
}


@dataclass
class InputSourceDescriptor:
    source_id: str
    source_type: str
    entry_point_id: str | None = None
    component_id: str | None = None
    function_name: str | None = None
    parameter_name: str | None = None
    parameter_index: int | None = None
    protocol: str | None = None
    origin: str = "unknown"
    runtime_confirmed: bool = False
    evidence_ids: list[str] = field(default_factory=list)
    confidence: float = 0.5
    provenance: str = "real_static_analysis"
    execution_mode: str = "real"
    provider_backed: bool = False
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def __post_init__(self) -> None:
        if self.source_type not in SOURCE_TYPES:
            raise ValueError(f"invalid source_type: {self.source_type}")
        self.confidence = _clamp01(self.confidence)
        self.evidence_ids = sorted(set(self.evidence_ids))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SensitiveSink:
    sink_id: str
    sink_type: str
    component_id: str | None = None
    binary_path: str | None = None
    function_name: str | None = None
    callee_name: str | None = None
    address: str | None = None
    argument_index: int | None = None
    operation: str = ""
    evidence_ids: list[str] = field(default_factory=list)
    confidence: float = 0.5
    security_relevance: float = 0.5
    provenance: str = "real_static_analysis"
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def __post_init__(self) -> None:
        if self.sink_type not in SINK_TYPES:
            raise ValueError(f"invalid sink_type: {self.sink_type}")
        self.confidence = _clamp01(self.confidence)
        self.security_relevance = _clamp01(self.security_relevance)
        self.evidence_ids = sorted(set(self.evidence_ids))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SinkCandidate:
    candidate_name: str
    reason: str
    evidence: list[str] = field(default_factory=list)
    confidence: float = 0.4

    def __post_init__(self) -> None:
        self.confidence = _clamp01(self.confidence)
        self.evidence = sorted(set(self.evidence))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SanitizerDescriptor:
    transform_id: str
    transform_type: str
    function_name: str | None = None
    component_id: str | None = None
    operation: str = ""
    input_argument: str | None = None
    output_argument: str | None = None
    evidence_ids: list[str] = field(default_factory=list)
    confidence: float = 0.4
    effectiveness: str = "unknown_effectiveness"

    def __post_init__(self) -> None:
        if self.transform_type not in SANITIZER_TYPES:
            raise ValueError(f"invalid sanitizer type: {self.transform_type}")
        if self.effectiveness not in SANITIZER_EFFECTIVENESS:
            raise ValueError(f"invalid sanitizer effectiveness: {self.effectiveness}")
        self.confidence = _clamp01(self.confidence)
        self.evidence_ids = sorted(set(self.evidence_ids))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DataTransformation:
    transform_id: str
    transform_type: str
    source_value: str | None = None
    destination_value: str | None = None
    function: str | None = None
    evidence: list[str] = field(default_factory=list)
    confidence: float = 0.5

    def __post_init__(self) -> None:
        if self.transform_type not in TRANSFORM_TYPES:
            raise ValueError(f"invalid transform type: {self.transform_type}")
        self.confidence = _clamp01(self.confidence)
        self.evidence = sorted(set(self.evidence))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TaintFact:
    fact_id: str
    source_id: str | None = None
    component_id: str | None = None
    function_name: str | None = None
    location: str | None = None
    variable: str | None = None
    parameter_index: int | None = None
    taint_state: str = "unknown"
    evidence_ids: list[str] = field(default_factory=list)
    confidence: float = 0.5
    provenance: str = "real_static_analysis"

    def __post_init__(self) -> None:
        if self.taint_state not in TAINT_STATES:
            raise ValueError(f"invalid taint state: {self.taint_state}")
        self.confidence = _clamp01(self.confidence)
        self.evidence_ids = sorted(set(self.evidence_ids))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TaintEdge:
    edge_id: str
    source_node_id: str
    target_node_id: str
    edge_type: str
    evidence_ids: list[str] = field(default_factory=list)
    confidence: float = 0.5

    def __post_init__(self) -> None:
        if self.edge_type not in TAINT_EDGE_TYPES:
            raise ValueError(f"invalid taint edge type: {self.edge_type}")
        self.confidence = _clamp01(self.confidence)
        self.evidence_ids = sorted(set(self.evidence_ids))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TaintGraph:
    nodes: list[dict[str, Any]] = field(default_factory=list)
    edges: list[TaintEdge] = field(default_factory=list)

    def add_node(self, node_id: str, node_type: str, label: str, **metadata: Any) -> None:
        if any(item.get("node_id") == node_id for item in self.nodes):
            return
        self.nodes.append({"node_id": node_id, "node_type": node_type, "label": label, "metadata": metadata})

    def add_edge(self, edge: TaintEdge) -> None:
        if any(item.edge_id == edge.edge_id for item in self.edges):
            return
        self.edges.append(edge)

    def to_dict(self) -> dict[str, Any]:
        return {"nodes": self.nodes, "edges": [item.to_dict() for item in self.edges]}


@dataclass
class TaintPath:
    path_id: str
    source_id: str
    sink_id: str
    component_ids: list[str]
    function_chain: list[str]
    taint_edges: list[str]
    sanitizers: list[str]
    transformations: list[str]
    evidence_ids: list[str]
    confidence: float
    path_state: str
    interprocedural: bool
    runtime_supported: bool
    entry_point_id: str | None = None
    hypothesis_ids: list[str] = field(default_factory=list)
    evidence_level: str = "L0_source_sink_exist"
    runtime_sink_confirmed: bool = False

    def __post_init__(self) -> None:
        if self.path_state not in PATH_STATES:
            raise ValueError(f"invalid path_state: {self.path_state}")
        if self.evidence_level not in EVIDENCE_LEVELS:
            raise ValueError(f"invalid evidence_level: {self.evidence_level}")
        self.confidence = _clamp01(self.confidence)
        self.component_ids = sorted(set(self.component_ids))
        self.taint_edges = sorted(set(self.taint_edges))
        self.sanitizers = sorted(set(self.sanitizers))
        self.transformations = sorted(set(self.transformations))
        self.evidence_ids = sorted(set(self.evidence_ids))
        self.hypothesis_ids = sorted(set(self.hypothesis_ids))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DataFlowEvidence:
    evidence_id: str
    source_id: str | None
    sink_id: str | None
    function: str | None
    observation_type: str
    decompile_excerpt_summary: str
    argument_mapping: dict[str, Any] = field(default_factory=dict)
    call_chain: list[str] = field(default_factory=list)
    confidence: float = 0.5
    artifact_reference: str | None = None
    provenance: str = "real_static_analysis"
    evidence_level: str = "L0_source_sink_exist"
    analysis_status: str | None = None
    static_evidence: list[dict[str, Any]] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.evidence_level not in EVIDENCE_LEVELS:
            raise ValueError(f"invalid evidence_level: {self.evidence_level}")
        self.confidence = _clamp01(self.confidence)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SourceSinkHypothesisLink:
    hypothesis_id: str
    source_ids: list[str]
    sink_ids: list[str]
    taint_path_ids: list[str]
    relationship: str
    confidence: float
    runtime_supported: bool
    reason: str

    def __post_init__(self) -> None:
        self.confidence = _clamp01(self.confidence)
        self.source_ids = sorted(set(self.source_ids))
        self.sink_ids = sorted(set(self.sink_ids))
        self.taint_path_ids = sorted(set(self.taint_path_ids))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SensitiveFunctionCatalog:
    binary: str
    functions: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class InputSourceCatalog:
    entry_point_id: str
    service: str | None
    backend_component_id: str | None
    sources: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TaintAnalysisSummary:
    sources: int
    sinks: int
    candidate_paths: int
    supported_paths: int
    runtime_supported_paths: int
    paths_with_sanitizers: int
    unknown_paths: int
    high_priority_paths: int
    source_types: dict[str, int]
    sink_types: dict[str, int]
    safety_notes: list[str]
    # P1-2：路径质量统计——让读者一眼区分合成路径与真实数据流
    # argument_mapped_paths: 带参数级映射（argument_mapping 非空）的路径数
    # decompile_backed_paths: 证据引用了反编译产物的路径数
    # callgraph_synthetic_paths: 由 callgraph 链合成（TP-GEN-）的路径数
    argument_mapped_paths: int = 0
    decompile_backed_paths: int = 0
    callgraph_synthetic_paths: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TaintContext:
    hypothesis_id: str | None
    entry_id: str | None
    component_id: str | None
    sources: list[dict[str, Any]]
    sinks: list[dict[str, Any]]
    paths: list[dict[str, Any]]
    sanitizers: list[dict[str, Any]]
    functions: list[str]
    conclusion: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class SensitiveSinkRegistry:
    def __init__(self, registry: dict[str, list[str]] | None = None):
        self.registry = registry or self.default_registry()
        self.aliases = {
            "__GI_system": "system",
            "__libc_system": "system",
            "__isoc99_scanf": "scanf",
            "__GI_memcpy": "memcpy",
            "system@plt": "system",
            "popen@plt": "popen",
            "gets@plt": "gets",
            "strcpy@plt": "strcpy",
            "sprintf@plt": "sprintf",
        }

    @staticmethod
    def default_registry() -> dict[str, list[str]]:
        return {
            "command_execution": ["system", "popen"],
            "process_execution": ["execl", "execle", "execlp", "execv", "execve", "execvp"],
            "unsafe_copy": ["strcpy", "strcat", "sprintf", "vsprintf", "gets"],
            "memory_copy": ["memcpy", "memmove", "strncpy", "snprintf"],
            "file_write": ["fopen", "open", "write", "fwrite"],
            "dynamic_load": ["dlopen"],
            "authentication_decision": ["strcmp", "strncmp", "crypt"],
            "nvram_write": ["nvram_set", "nvram_commit"],
        }

    def normalize_symbol(self, symbol: str) -> str:
        normalized = str(symbol or "").strip()
        normalized = self.aliases.get(normalized, normalized)
        normalized = normalized.split("@@", 1)[0]
        normalized = normalized[:-4] if normalized.endswith("@plt") else normalized
        normalized = re.sub(r"^_+", "", normalized)
        return self.aliases.get(normalized, normalized)

    def sink_type_for(self, symbol: str) -> str | None:
        normalized = self.normalize_symbol(symbol)
        for sink_type, names in self.registry.items():
            if normalized in {self.normalize_symbol(name) for name in names}:
                return sink_type
        return None

    def is_sink(self, symbol: str) -> bool:
        return self.sink_type_for(symbol) is not None

    def resolve_wrapper_candidate(self, function_name: str, decompile_text: str) -> SinkCandidate | None:
        lowered = decompile_text.lower()
        for sink_type, names in self.registry.items():
            for name in names:
                if re.search(rf"\b{re.escape(name.lower())}\s*\(", lowered):
                    return SinkCandidate(
                        candidate_name=function_name,
                        reason=f"wrapper candidate calls {name}; candidate sink type {sink_type}",
                        evidence=[name],
                        confidence=0.58,
                    )
        return None

    def to_dict(self) -> dict[str, Any]:
        return {key: list(value) for key, value in self.registry.items()}


class StaticDataFlowBridge:
    def __init__(self, config: DynamicConfig, registry: SensitiveSinkRegistry | None = None):
        self.config = config
        self.registry = registry or SensitiveSinkRegistry()

    def audit_exported_candidate(self, task_dir: str | Path, *, task_id: str, path_id: str) -> dict[str, Any]:
        """Read saved evidence without constructing a builder or mutating a task.

        The legacy text/regex bridge is deliberately not used to invent missing
        SSA, callsites or argument mappings for v1 Ghidra exports.
        """
        return GhidraEvidenceIndex(task_dir, task_id=task_id).audit_candidate(path_id)

    def analyze_same_function_flow(
        self,
        *,
        source_id: str,
        sink_id: str,
        function_name: str,
        source_variable: str,
        sink_name: str,
        decompile_text: str,
    ) -> DataFlowEvidence | None:
        aliases = self.local_aliases(decompile_text, source_variable)
        aliases.add(source_variable)
        sink_call = self._call_arguments(decompile_text, sink_name)
        if not sink_call:
            return None
        tainted_arguments = [arg for arg in sink_call if any(_token_equal(alias, arg) for alias in aliases)]
        if not tainted_arguments:
            return None
        return DataFlowEvidence(
            evidence_id=f"DFE-{_slug(function_name)}-{_slug(sink_name)}",
            source_id=source_id,
            sink_id=sink_id,
            function=function_name,
            observation_type="direct_argument_flow",
            decompile_excerpt_summary=f"{source_variable} reaches {sink_name} argument in {function_name}",
            argument_mapping={"source_variable": source_variable, "sink_arguments": tainted_arguments},
            confidence=self.config.taint.confidence.direct_argument,
            evidence_level="L3_argument_propagation",
        )

    def local_aliases(self, decompile_text: str, source_variable: str) -> set[str]:
        aliases = set()
        pattern = re.compile(rf"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*{re.escape(source_variable)}\b")
        aliases.update(match.group(1) for match in pattern.finditer(decompile_text))
        copy_pattern = re.compile(rf"\b(?:strcpy|memcpy|strncpy)\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*,\s*{re.escape(source_variable)}\b")
        aliases.update(match.group(1) for match in copy_pattern.finditer(decompile_text))
        return aliases

    def return_value_propagation(self, decompile_text: str, source_variable: str) -> list[DataTransformation]:
        transforms = []
        pattern = re.compile(rf"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\s*\([^;]*\b{re.escape(source_variable)}\b[^;]*\)")
        for index, match in enumerate(pattern.finditer(decompile_text), start=1):
            transforms.append(
                DataTransformation(
                    transform_id=f"TR-return-{index:04d}",
                    transform_type="parse",
                    source_value=source_variable,
                    destination_value=match.group(1),
                    function=match.group(2),
                    evidence=[match.group(0)[:120]],
                    confidence=self.config.taint.confidence.return_propagation,
                )
            )
        return transforms

    def formatting_propagation(self, decompile_text: str, source_variable: str) -> list[DataTransformation]:
        transforms = []
        pattern = re.compile(rf"\b(snprintf|sprintf)\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*,[^;]*\b{re.escape(source_variable)}\b[^;]*\)")
        for index, match in enumerate(pattern.finditer(decompile_text), start=1):
            transforms.append(
                DataTransformation(
                    transform_id=f"TR-format-{index:04d}",
                    transform_type="format",
                    source_value=source_variable,
                    destination_value=match.group(2),
                    function=match.group(1),
                    evidence=[match.group(0)[:120]],
                    confidence=0.72,
                )
            )
        return transforms

    def detect_sanitizers(self, decompile_text: str, function_name: str, source_variable: str) -> list[SanitizerDescriptor]:
        sanitizers = []
        checks = [
            ("length_check", rf"if\s*\([^)]*(strlen\s*\(\s*{re.escape(source_variable)}\s*\)|{re.escape(source_variable)}_len|len)[^)]*(<|<=|>|>=)"),
            ("allowlist", rf"if\s*\([^)]*(strcmp|strncmp|memcmp)\s*\([^)]*{re.escape(source_variable)}"),
            ("range_validation", rf"if\s*\([^)]*{re.escape(source_variable)}[^)]*(<|<=|>|>=)[^)]*\)"),
        ]
        for index, (transform_type, pattern) in enumerate(checks, start=1):
            if re.search(pattern, decompile_text, flags=re.IGNORECASE):
                sanitizers.append(
                    SanitizerDescriptor(
                        transform_id=f"SAN-{_slug(function_name)}-{index:04d}",
                        transform_type=transform_type,
                        function_name=function_name,
                        operation=f"{transform_type} involving {source_variable}",
                        input_argument=source_variable,
                        confidence=0.62,
                        effectiveness="unknown_effectiveness",
                    )
                )
        return sanitizers

    def map_argument(self, caller_text: str, callee_name: str, argument_name: str) -> dict[str, Any]:
        args = self._call_arguments(caller_text, callee_name)
        for index, arg in enumerate(args):
            if _token_equal(argument_name, arg):
                return {"mapped": True, "callee": callee_name, "caller_argument": argument_name, "callee_parameter_index": index}
        return {"mapped": False, "callee": callee_name, "reason": "argument mapping unknown"}

    def bounded_call_chain(self, callgraph: list[dict[str, Any]], source_function: str, sink_function: str, max_depth: int) -> list[str]:
        adjacency: dict[str, list[str]] = {}
        for edge in callgraph:
            caller = str(edge.get("caller") or "")
            callee = str(edge.get("callee") or "")
            if caller and callee:
                adjacency.setdefault(caller, []).append(callee)
        queue = deque([(source_function, [source_function])])
        while queue:
            current, chain = queue.popleft()
            if len(chain) - 1 >= max_depth:
                continue
            for callee in adjacency.get(current, []):
                if callee in chain:
                    continue
                next_chain = chain + [callee]
                if callee == sink_function:
                    return next_chain
                queue.append((callee, next_chain))
        return []

    def _call_arguments(self, decompile_text: str, function_name: str) -> list[str]:
        match = re.search(rf"\b{re.escape(function_name)}\s*\(([^;]*)\)", decompile_text)
        if not match:
            return []
        return [_strip_expr(item) for item in _split_args(match.group(1))]


class TaintAnalysisBuilder:
    def __init__(self, workspace_root: str | Path, task_id: str, *, config: DynamicConfig):
        self.workspace = DynamicWorkspace(workspace_root, task_id)
        self.config = config
        self.registry = SensitiveSinkRegistry()
        self.bridge = StaticDataFlowBridge(config, self.registry)
        self.surface = AttackSurfaceBuilder(workspace_root, task_id, config=config).load_or_build()
        self.graph = ComponentGraphBuilder(workspace_root, task_id, config=config).load_or_build_graph()
        self.hypotheses = self.workspace.load_hypotheses()
        self.dynamic_evidence = self.workspace.load_evidence()

    def build(self) -> dict[str, Any]:
        sources = self._discover_sources()[: self.config.taint.max_sources]
        sinks = self._discover_sinks()[: self.config.taint.max_sinks]
        sanitizers = self._discover_sanitizers()
        transformations = self._discover_transformations()
        facts = self._build_facts(sources, sinks)
        paths, data_flow_evidence, graph = self._build_paths(sources, sinks, sanitizers, transformations)
        links = self._link_hypotheses(sources, sinks, paths)
        source_catalog = self._source_catalog(sources)
        sink_catalog = self._sink_catalog(sinks)
        summary = self._summary(sources, sinks, paths, sanitizers, data_flow_evidence)
        contexts = self._contexts(sources, sinks, paths, sanitizers, links)
        payload = {
            "success": True,
            "provider_backed": False,
            "real_model_validation": "deferred",
            "sources": [item.to_dict() for item in sources],
            "sinks": [item.to_dict() for item in sinks],
            "sink_catalog": [item.to_dict() for item in sink_catalog],
            "source_catalog": [item.to_dict() for item in source_catalog],
            "taint_facts": [item.to_dict() for item in facts],
            "taint_graph": graph.to_dict(),
            "taint_paths": [item.to_dict() for item in paths[: self.config.taint.max_paths]],
            "sanitizers": [item.to_dict() for item in sanitizers],
            "transformations": [item.to_dict() for item in transformations],
            "data_flow_evidence": [item.to_dict() for item in data_flow_evidence],
            "hypothesis_links": [item.to_dict() for item in links],
            "summary": summary.to_dict(),
            "contexts": [item.to_dict() for item in contexts],
        }
        payload["summary"]["static_evidence_diagnostics"] = getattr(self, "_static_evidence_diagnostics", [])
        self._persist(payload)
        return payload

    def load_or_build(self) -> dict[str, Any]:
        summary = self.workspace.load_taint_artifact("summary.json")
        sources = self.workspace.load_taint_artifact("sources.json")
        if summary and sources:
            return {
                "success": True,
                "provider_backed": False,
                "real_model_validation": "deferred",
                "sources": sources,
                "sinks": self.workspace.load_taint_artifact("sinks.json") or [],
                "sink_catalog": self.workspace.load_taint_artifact("sink_catalog.json") or [],
                "source_catalog": self.workspace.load_taint_artifact("source_catalog.json") or [],
                "taint_facts": self.workspace.load_taint_artifact("taint_facts.json") or [],
                "taint_graph": self.workspace.load_taint_artifact("taint_graph.json") or {"nodes": [], "edges": []},
                "taint_paths": self.workspace.load_taint_artifact("taint_paths.json") or [],
                "sanitizers": self.workspace.load_taint_artifact("sanitizers.json") or [],
                "transformations": self.workspace.load_taint_artifact("transformations.json") or [],
                "data_flow_evidence": self.workspace.load_taint_artifact("data_flow_evidence.json") or [],
                "hypothesis_links": self.workspace.load_taint_artifact("hypothesis_links.json") or [],
                "summary": summary,
                "contexts": self.workspace.load_taint_artifact("contexts.json") or [],
            }
        return self.build()

    def context(self, *, hypothesis_id: str | None = None, entry_id: str | None = None, component_id: str | None = None) -> TaintContext:
        payload = self.load_or_build()
        sources = payload.get("sources", [])
        sinks = payload.get("sinks", [])
        paths = payload.get("taint_paths", [])
        if hypothesis_id:
            paths = [item for item in paths if hypothesis_id in item.get("hypothesis_ids", [])]
            source_ids = {item.get("source_id") for item in paths}
            sink_ids = {item.get("sink_id") for item in paths}
            sources = [item for item in sources if item.get("source_id") in source_ids]
            sinks = [item for item in sinks if item.get("sink_id") in sink_ids]
        if entry_id:
            sources = [item for item in sources if item.get("entry_point_id") == entry_id]
            source_ids = {item.get("source_id") for item in sources}
            paths = [item for item in paths if item.get("source_id") in source_ids]
        if component_id:
            sinks = [item for item in sinks if item.get("component_id") == component_id]
            paths = [item for item in paths if component_id in item.get("component_ids", [])]
        conclusion = "candidate_or_unknown"
        if any(item.get("path_state") in {"statically_supported", "runtime_supported", "validated"} for item in paths):
            conclusion = "supported_data_flow_without_vulnerability_confirmation"
        elif not paths:
            conclusion = "no_sufficiently_supported_sink_path"
        return TaintContext(
            hypothesis_id=hypothesis_id,
            entry_id=entry_id,
            component_id=component_id,
            sources=sources[: self.config.taint.max_sources],
            sinks=sinks[: self.config.taint.max_sinks],
            paths=paths[: self.config.taint.max_paths],
            sanitizers=payload.get("sanitizers", [])[:8],
            functions=sorted({fn for path in paths for fn in path.get("function_chain", [])})[: self.config.taint.max_function_candidates],
            conclusion=conclusion,
        )

    def mock_add_taint_path(self, path_name: str) -> dict[str, Any]:
        state = self.workspace.load_taint_artifact("mock_taint_state.json") or {"mock_paths": []}
        state.setdefault("mock_paths", []).append(
            {
                "name": path_name,
                "provenance": "mock_agent",
                "execution_mode": "mock",
                "canonical_update_allowed": False,
                "provider_backed": False,
            }
        )
        self.workspace.save_taint_artifact("mock_taint_state.json", state)
        return {"success": True, "canonical_update_allowed": False, "provider_backed": False}

    def incremental_update_from_dynamic_evidence(self, evidence: DynamicEvidence) -> dict[str, Any]:
        allowed = CanonicalStateGuard.can_update_canonical(
            execution_mode=evidence.execution_mode,
            runtime_observation_real=evidence.runtime_observation_real,
            synthetic=evidence.provenance in {"mock_agent", "simulation", "fixture"},
        )
        if not allowed:
            self.workspace.save_taint_artifact(
                "mock_taint_state.json",
                {
                    "accepted": False,
                    "reason": "mock/simulation taint evidence cannot mutate canonical hypotheses",
                    "evidence": evidence.to_dict(),
                    "provider_backed": False,
                },
            )
            return {"success": True, "canonical_update_allowed": False, "provider_backed": False}
        result = self.build()
        return {"success": True, "canonical_update_allowed": True, "summary": result["summary"], "provider_backed": False}

    def _discover_sources(self) -> list[InputSourceDescriptor]:
        entries = {item["entry_id"]: item for item in self.surface.get("entry_points", [])}
        sources: list[InputSourceDescriptor] = []
        for entry in entries.values():
            entry_id = str(entry.get("entry_id") or "")
            protocol = str(entry.get("protocol") or entry.get("entry_type") or "").lower()
            entry_type = str(entry.get("entry_type") or "").lower()
            if entry_id in {"EP-HTTPS-lighttpd-device-manager", "EP-LOOPBACK-FCGI-44171", "EP-STDIN-ret2text"}:
                continue
            if protocol not in {"http", "https", "fastcgi", "tcp", "udp"} and "http" not in entry_id.lower():
                continue
            # P0-2(c)：component_id 为 null 时回退到 handler_component_id；
            # P0-2(d)：CGI/脚本入口区分"HTTP 请求参数"与"原始 TCP 流"
            # （spec 中的 http_param 在 SOURCE_TYPES 枚举里对应 cgi_parameter / http_parameter）。
            if entry_type == "cgi":
                source_type = "cgi_parameter"
            elif entry_type == "http_route":
                source_type = "http_parameter"
            else:
                source_type = "tcp_stream" if protocol in {"http", "https", "tcp", "fastcgi"} else "udp_datagram" if protocol == "udp" else "unknown"
            handler_component_id = entry.get("handler_component_id") or entry.get("component_id")
            sources.append(
                InputSourceDescriptor(
                    source_id=f"SRC-{_slug(entry_id)}-REQUEST",
                    source_type=source_type,
                    entry_point_id=entry_id,
                    component_id=handler_component_id,
                    function_name=str(entry.get("name") or "request handler"),
                    parameter_name="request",
                    protocol=entry.get("protocol"),
                    origin="network_or_service_entry",
                    runtime_confirmed=bool(entry.get("runtime_confirmed")),
                    evidence_ids=entry.get("evidence_ids", []),
                    confidence=float(entry.get("confidence", 0.55)),
                    provenance="real_runtime_observation" if entry.get("runtime_confirmed") else "real_static_analysis",
                )
            )
        fastcgi_entry = entries.get("EP-HTTPS-lighttpd-device-manager")
        if fastcgi_entry:
            for source_id, source_type, parameter_name, origin, confidence in (
                ("SRC-FCGI-SOAP-ACTION", "soap_action", "SOAPAction", "http_header_or_body", 0.82),
                ("SRC-FCGI-HTTP-BODY", "http_body", "body", "http_request_body", 0.78),
                ("SRC-FCGI-REQUEST-URI", "fastcgi_parameter", "REQUEST_URI", "fastcgi_environment", 0.70),
            ):
                sources.append(
                    InputSourceDescriptor(
                        source_id=source_id,
                        source_type=source_type,
                        entry_point_id=fastcgi_entry["entry_id"],
                        component_id=fastcgi_entry.get("handler_component_id") or fastcgi_entry.get("component_id"),
                        function_name="device_manager.fcgi request handler",
                        parameter_name=parameter_name,
                        protocol=fastcgi_entry.get("protocol"),
                        origin=origin,
                        runtime_confirmed=bool(fastcgi_entry.get("runtime_confirmed")),
                        evidence_ids=fastcgi_entry.get("evidence_ids", []),
                        confidence=confidence,
                        provenance="real_runtime_observation" if fastcgi_entry.get("runtime_confirmed") else "real_static_analysis",
                    )
                )
        loopback_entry = entries.get("EP-LOOPBACK-FCGI-44171")
        if loopback_entry:
            sources.append(
                InputSourceDescriptor(
                    source_id="SRC-FCGI-IPC-MESSAGE",
                    source_type="ipc_message",
                    entry_point_id=loopback_entry["entry_id"],
                    component_id=loopback_entry.get("component_id"),
                    function_name="FastCGI request loop",
                    protocol="fastcgi",
                    origin="loopback_fastcgi_ipc",
                    runtime_confirmed=True,
                    evidence_ids=loopback_entry.get("evidence_ids", []),
                    confidence=0.76,
                    provenance="real_runtime_observation",
                )
            )
        report = self._load_report()
        firmware_name = str((report.get("firmware") or {}).get("filename") or "").lower()
        ret_entry = entries.get("EP-STDIN-ret2text") if not firmware_name or "ret2text" in firmware_name else None
        if ret_entry:
            sources.append(
                InputSourceDescriptor(
                    source_id="SRC-RET2TEXT-STDIN",
                    source_type="stdin",
                    entry_point_id=ret_entry["entry_id"],
                    component_id=ret_entry.get("component_id"),
                    function_name="main",
                    parameter_name="stdin",
                    protocol="stdin",
                    origin="local_process_stdin",
                    runtime_confirmed=False,
                    evidence_ids=ret_entry.get("evidence_ids", []),
                    confidence=ret_entry.get("confidence", 0.5),
                    provenance="real_static_analysis",
                )
            )
        if not sources:
            fallback = self._static_source_fallback()
            if fallback:
                logger.warning(
                    "no attack surface entries; using %d static callgraph sources as taint sources",
                    len(fallback),
                )
            sources.extend(fallback)
        return sources

    def _static_source_fallback(self) -> list[InputSourceDescriptor]:
        """攻击面为空时的兜底污点源：从 Ghidra 证据标记外部输入接收点。

        evidence id 形如 SE-GHIDRA-sbin-httpd-recv，末段即函数名；
        与 _READ_FUNCS 匹配的调用点视为外部输入 source。
        """
        sources: list[InputSourceDescriptor] = []
        evidence_path = self.workspace.task_dir / "ghidra" / "evidence.json"
        if not evidence_path.exists():
            return sources
        try:
            records = json.loads(evidence_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return sources
        if isinstance(records, dict):
            records = records.get("evidence") or []

        for item in records:
            if not isinstance(item, dict):
                continue
            ev_id = str(item.get("id") or "")
            binary = str((item.get("metadata") or {}).get("binary") or "")
            if not ev_id or not binary:
                continue
            func = ev_id.rsplit("-", 1)[-1].lower()
            if not any(rf == func or func.startswith(rf) for rf in _READ_FUNCS):
                continue
            binary_name = Path(binary).name
            sources.append(
                InputSourceDescriptor(
                    source_id=f"SRC-STATIC-{_slug(ev_id)}",
                    source_type="tcp_stream",
                    entry_point_id=None,
                    component_id=self.graph.resolve_component_id(binary_name) if self.graph else None,
                    function_name=func,
                    parameter_name="request",
                    protocol="tcp",
                    origin=f"static_callgraph: {binary_name}",
                    runtime_confirmed=False,
                    evidence_ids=[ev_id],
                    confidence=0.55,
                    provenance="real_static_analysis",
                )
            )
        return sources

    def _discover_sinks(self) -> list[SensitiveSink]:
        sinks: list[SensitiveSink] = []
        report = self._load_report()
        for binary in report.get("binaries", []) if isinstance(report.get("binaries"), list) else []:
            path = str(binary.get("path") or "")
            if not path:
                continue
            component_id = self.graph.resolve_component_id(path) or self.graph.resolve_component_id(Path(path).name)
            for symbol in binary.get("dangerous_symbols", [])[: self.config.taint.max_sinks]:
                sink_type = self.registry.sink_type_for(str(symbol))
                if not sink_type:
                    continue
                sink_prefix = "FCGI" if "device_manager" in path or path.endswith(".fcgi") else _slug(Path(path).name)
                sinks.append(
                    SensitiveSink(
                        sink_id=f"SINK-{sink_prefix}-{_slug(sink_type)}-{_slug(symbol)}",
                        sink_type=sink_type,
                        component_id=component_id,
                        binary_path=path,
                        function_name=self.registry.normalize_symbol(str(symbol)),
                        callee_name=self.registry.normalize_symbol(str(symbol)),
                        # The registry identifies an API, not observed call arguments.
                        argument_index=None,
                        operation=f"imported or referenced {symbol}",
                        evidence_ids=[f"BIN:{path}"],
                        confidence=0.62,
                        security_relevance=_sink_relevance(sink_type),
                    )
                )
        firmware_name = str((report.get("firmware") or {}).get("filename") or "").lower()
        ret_component = self.graph.resolve_component_id("ret2text") if not firmware_name or "ret2text" in firmware_name else None
        ret_evidence = sorted({evidence_id for hypothesis in self.hypotheses if "ret2text" in (hypothesis.id + hypothesis.title).lower() for evidence_id in hypothesis.evidence_ids})
        if ret_component:
            sinks.append(
                SensitiveSink(
                    sink_id="SINK-RET2TEXT-main-gets",
                    sink_type="unsafe_copy",
                    component_id=ret_component,
                    binary_path="ret2text",
                    function_name="main",
                    callee_name="gets",
                    argument_index=0,
                    operation="unsafe input primitive gets(stdin-buffer)",
                    evidence_ids=ret_evidence or ["SE-RET2TEXT-0001"],
                    confidence=0.86,
                    security_relevance=0.84,
                )
            )
            sinks.append(
                SensitiveSink(
                    sink_id="SINK-RET2TEXT-secure-system",
                    sink_type="command_execution",
                    component_id=ret_component,
                    binary_path="ret2text",
                    function_name="secure",
                    callee_name="system",
                    argument_index=0,
                    operation="secure function contains command execution sink",
                    evidence_ids=ret_evidence or ["SE-RET2TEXT-0002"],
                    confidence=0.74,
                    security_relevance=0.95,
                )
            )
        return _unique_sinks(sinks)

    def _discover_sanitizers(self) -> list[SanitizerDescriptor]:
        return []

    def _discover_transformations(self) -> list[DataTransformation]:
        return []

    def _build_facts(self, sources: list[InputSourceDescriptor], sinks: list[SensitiveSink]) -> list[TaintFact]:
        facts = []
        for source in sources:
            facts.append(
                TaintFact(
                    fact_id=f"TF-{source.source_id}",
                    source_id=source.source_id,
                    component_id=source.component_id,
                    function_name=source.function_name,
                    variable=source.parameter_name,
                    taint_state="source",
                    evidence_ids=source.evidence_ids,
                    confidence=source.confidence,
                    provenance=source.provenance,
                )
            )
        for sink in sinks:
            facts.append(
                TaintFact(
                    fact_id=f"TF-{sink.sink_id}",
                    component_id=sink.component_id,
                    function_name=sink.function_name,
                    variable=sink.callee_name,
                    parameter_index=sink.argument_index,
                    taint_state="sink_argument",
                    evidence_ids=sink.evidence_ids,
                    confidence=sink.confidence,
                    provenance=sink.provenance,
                )
            )
        return facts

    def _build_paths(
        self,
        sources: list[InputSourceDescriptor],
        sinks: list[SensitiveSink],
        sanitizers: list[SanitizerDescriptor],
        transformations: list[DataTransformation],
    ) -> tuple[list[TaintPath], list[DataFlowEvidence], TaintGraph]:
        paths: list[TaintPath] = []
        data_flow_evidence: list[DataFlowEvidence] = []
        graph = TaintGraph()
        for source in sources:
            graph.add_node(source.source_id, "source", source.source_type, entry_point_id=source.entry_point_id)
        for sink in sinks:
            graph.add_node(sink.sink_id, "sink", sink.callee_name or sink.function_name or sink.sink_type, sink_type=sink.sink_type)
        ret_source = next((item for item in sources if item.source_id == "SRC-RET2TEXT-STDIN"), None)
        ret_gets = next((item for item in sinks if item.sink_id == "SINK-RET2TEXT-main-gets"), None)
        if ret_source and ret_gets:
            edge_id = "TE-RET2TEXT-STDIN-main-gets"
            graph.add_node("FN-ret2text-main", "function", "main")
            graph.add_edge(TaintEdge(edge_id, ret_source.source_id, ret_gets.sink_id, "calls_with", sorted(set(ret_source.evidence_ids + ret_gets.evidence_ids)), 0.86))
            evidence = DataFlowEvidence(
                evidence_id="DFE-RET2TEXT-main-gets",
                source_id=ret_source.source_id,
                sink_id=ret_gets.sink_id,
                function="main",
                observation_type="direct_unsafe_input_primitive",
                decompile_excerpt_summary="stdin reaches gets in main; unsafe input primitive recorded without exploit construction",
                argument_mapping={"source": "stdin", "sink": "gets argument 0"},
                call_chain=["main", "gets"],
                confidence=0.86,
                artifact_reference="ret2text static evidence",
                evidence_level="L3_argument_propagation",
            )
            data_flow_evidence.append(evidence)
            paths.append(
                TaintPath(
                    path_id="TP-RET2TEXT-STDIN-GETS",
                    source_id=ret_source.source_id,
                    sink_id=ret_gets.sink_id,
                    component_ids=[ret_source.component_id or "", ret_gets.component_id or ""],
                    function_chain=["main", "gets"],
                    taint_edges=[edge_id],
                    sanitizers=[],
                    transformations=[],
                    evidence_ids=sorted(set(ret_source.evidence_ids + ret_gets.evidence_ids)),
                    confidence=0.81,
                    path_state="statically_supported",
                    interprocedural=False,
                    runtime_supported=False,
                    entry_point_id=ret_source.entry_point_id,
                    hypothesis_ids=["H-RET2TEXT-0001"],
                    evidence_level="L3_argument_propagation",
                    runtime_sink_confirmed=False,
                )
            )
        # ------------------------------------------------------------------
        # 通用 L2 路径合成：在 Ghidra callgraph 中搜索
        # "外部输入接收点 → 危险函数" 的可达调用链（深度受限）。
        # 打通 通用source → 通用sink → 假设 → 发现 的完整链路，
        # 不再依赖 ret2text / FastCGI 硬编码特例。
        # ------------------------------------------------------------------
        paths.extend(self._generic_callgraph_paths(sources, sinks, graph, data_flow_evidence))
        fcgi_sources = [item for item in sources if item.source_id.startswith("SRC-FCGI")]
        fcgi_sinks = [item for item in sinks if item.sink_id.startswith("SINK-FCGI")]
        runtime_handler_ids = [evidence.id for evidence in self.dynamic_evidence if evidence.type in {"handler_reached", "fastcgi_application_response", "application_response"}]
        for source in fcgi_sources:
            graph.add_node("FN-device-manager-handler", "function", "device_manager.fcgi request handler")
            graph.add_edge(TaintEdge(f"TE-{source.source_id}-handler", source.source_id, "FN-device-manager-handler", "runtime_correlated", source.evidence_ids, source.confidence))
            for sink in fcgi_sinks[: max(1, self.config.taint.max_paths // max(1, len(fcgi_sources)))]:
                evidence_id = f"DFE-{_slug(source.source_id)}-{_slug(sink.sink_id)}"
                confidence = round(
                    min(source.confidence, sink.confidence, self.config.taint.confidence.same_component_candidate)
                    + (self.config.taint.confidence.runtime_handler if source.runtime_confirmed else 0.0),
                    3,
                )
                evidence = DataFlowEvidence(
                    evidence_id=evidence_id,
                    source_id=source.source_id,
                    sink_id=sink.sink_id,
                    function=source.function_name,
                    observation_type="same_component_candidate",
                    decompile_excerpt_summary="source and sink are in the runtime-confirmed FastCGI component; argument flow remains unresolved",
                    argument_mapping={"mapped": False, "reason": "no argument-level data-flow evidence"},
                    call_chain=["lighttpd", "device_manager.fcgi request handler", sink.function_name or sink.callee_name or "sink"],
                    confidence=confidence,
                    artifact_reference=sink.binary_path,
                    evidence_level="L1_same_component",
                )
                data_flow_evidence.append(evidence)
                edge_id = f"TE-{_slug(source.source_id)}-{_slug(sink.sink_id)}"
                graph.add_edge(TaintEdge(edge_id, "FN-device-manager-handler", sink.sink_id, "flows_to", sorted(set(source.evidence_ids + sink.evidence_ids + runtime_handler_ids)), confidence))
                paths.append(
                    TaintPath(
                        path_id=f"TP-{_slug(source.source_id)}-{_slug(sink.sink_id)}",
                        source_id=source.source_id,
                        sink_id=sink.sink_id,
                        component_ids=[source.component_id or "", sink.component_id or ""],
                        function_chain=["lighttpd", "device_manager.fcgi request handler", sink.function_name or sink.callee_name or "sink"],
                        taint_edges=[edge_id],
                        sanitizers=[item.transform_id for item in sanitizers if item.component_id == sink.component_id],
                        transformations=[item.transform_id for item in transformations],
                        evidence_ids=sorted(set(source.evidence_ids + sink.evidence_ids + runtime_handler_ids)),
                        confidence=confidence,
                        path_state="candidate",
                        interprocedural=True,
                        runtime_supported=False,
                        entry_point_id=source.entry_point_id,
                        hypothesis_ids=["H-FCGI-0001"],
                        evidence_level="L1_same_component",
                        runtime_sink_confirmed=False,
                    )
                )
        paths = self._cap_generic_paths(paths)
        return paths[: self.config.taint.max_paths], data_flow_evidence, graph

    def _cap_generic_paths(self, paths: list[TaintPath]) -> list[TaintPath]:
        """通用路径的防洪水截断：每个 sink 只保留置信度最高的一条来源。"""
        best_by_sink: dict[str, TaintPath] = {}
        fixed: list[TaintPath] = []
        for path in paths:
            if path.path_id.startswith("TP-GEN-"):
                sink_id = path.sink_id
                current = best_by_sink.get(sink_id)
                if current is None or path.confidence > current.confidence:
                    best_by_sink[sink_id] = path
            else:
                fixed.append(path)
        generics = sorted(best_by_sink.values(), key=lambda p: p.confidence, reverse=True)
        return fixed + generics

    def _generic_callgraph_paths(
        self,
        sources: list[InputSourceDescriptor],
        sinks: list[SensitiveSink],
        graph: TaintGraph,
        data_flow_evidence: list[DataFlowEvidence],
    ) -> list[TaintPath]:
        """Address-keyed call relationships; receiver controllability is unknown.

        Paths stay L2 candidates. Neither a receiver label nor a call relation
        establishes source values reaching the dangerous sink argument.
        """
        callgraphs = self._load_callgraphs()
        generated: list[TaintPath] = []
        for sink in sinks:
            if not sink.callee_name or not sink.binary_path:
                continue
            export = callgraphs.binary(sink.binary_path)
            if export is None:
                continue
            chain_edges = export.receiver_chain(sink.callee_name, max_depth=4)
            if not chain_edges:
                continue
            binary_name = self._path_basename(sink.binary_path)
            source = self._source_for_binary(sources, sink.component_id, export.identity.rootfs_path)
            if source is None:
                callgraphs.diagnostics.append(f"{export.identity.rootfs_path}: no source with an exact binary path identity")
                continue
            best_chain = [edge.observation["caller"] for edge in chain_edges] + [chain_edges[-1].observation["callee"]]
            confidence = round(min(source.confidence, sink.confidence) * 0.75, 3)
            src_tag = _slug(source.source_id)[:24]
            edge_id = f"TE-GEN-{src_tag}-{_slug(sink.sink_id)}"
            graph.add_edge(TaintEdge(edge_id, source.source_id, sink.sink_id, "callgraph_edge", sorted(set(source.evidence_ids + sink.evidence_ids)), confidence))
            path_id = f"TP-GEN-{src_tag}-{_slug(sink.sink_id)}"
            flow_key = hashlib.sha256((export.identity.identity_id + path_id).encode()).hexdigest()[:16]
            evidence = DataFlowEvidence(
                evidence_id=f"DFE-{_slug(path_id)[:48]}-{flow_key}",
                source_id=source.source_id,
                sink_id=sink.sink_id,
                function=" -> ".join(best_chain[:4]),
                observation_type="callgraph_reachable_input_to_sink",
                decompile_excerpt_summary=(
                    f"receiver-labelled caller {best_chain[0]} reaches {sink.callee_name} in {export.identity.rootfs_path} "
                    f"via {' -> '.join(best_chain[:5])}; callchain-level evidence, arguments unverified"
                ),
                argument_mapping={},
                call_chain=best_chain,
                confidence=confidence,
                artifact_reference=f"ghidra callgraph: {binary_name}",
                evidence_level="L2_reachable_call_chain",
                analysis_status="callgraph_only",
                static_evidence=[edge.to_dict() for edge in chain_edges],
                limitations=["Source controllability, callsite arguments, parameter propagation and mitigation coverage unverified"],
            )
            data_flow_evidence.append(evidence)
            generated.append(
                TaintPath(
                    path_id=path_id,
                    source_id=source.source_id,
                    sink_id=sink.sink_id,
                    component_ids=[source.component_id or sink.component_id or "", sink.component_id or ""],
                    function_chain=best_chain,
                    taint_edges=[edge_id],
                    sanitizers=[],
                    transformations=[],
                    evidence_ids=sorted(set(source.evidence_ids + sink.evidence_ids)),
                    confidence=confidence,
                    path_state="candidate",
                    interprocedural=len(best_chain) > 2,
                    runtime_supported=False,
                    entry_point_id=source.entry_point_id,
                    evidence_level="L2_reachable_call_chain",
                    runtime_sink_confirmed=False,
                )
            )
        self._static_evidence_diagnostics = list(callgraphs.diagnostics) + [message for export in callgraphs.binaries for message in export.diagnostics]
        return generated

    @staticmethod
    def _path_basename(path_str: str) -> str:
        """跨平台取文件名：Windows 反斜杠路径在 POSIX Path 下不会被切分。"""
        normalized = str(path_str).replace("\\", "/")
        return Path(normalized).name

    def _sink_binary_name(self, sink: SensitiveSink) -> str | None:
        if sink.binary_path:
            return self._path_basename(sink.binary_path)
        return None

    def _network_entry_callers(self, adjacency: dict[str, set[str]]) -> set[str]:
        """调用了外部输入接收函数（recv/read/...）的 caller 集合。"""
        callers: set[str] = set()
        for caller, callees in adjacency.items():
            for callee in callees:
                low = callee.lower()
                if any(low == rf or low.startswith(rf) for rf in _READ_FUNCS):
                    callers.add(caller)
                    break
        return callers

    def _source_for_binary(
        self, sources: list[InputSourceDescriptor], component_id: str | None, binary_path: str
    ) -> InputSourceDescriptor | None:
        """Bind explicit component file/service metadata; basename is insufficient."""
        target = rootfs_relative_path(binary_path)
        best: InputSourceDescriptor | None = None
        for source in sources:
            if source.source_id.startswith("SRC-RET2TEXT") or not source.component_id:
                continue
            component = self.graph.components.get(source.component_id)
            path = (component.path or component.metadata.get("binary")) if component else None
            try:
                same = rootfs_relative_path(path) == target
            except EvidenceValidationError:
                same = False
            if not same:
                continue
            if best is None or source.confidence > best.confidence:
                best = source
        return best

    @staticmethod
    def _component_binary_token(component_id: str) -> str:
        return component_id.rstrip("/").split("-")[-1].lower() if component_id else ""

    def _load_callgraphs(self) -> GhidraEvidenceIndex:
        return GhidraEvidenceIndex(self.workspace.task_dir, task_id=self.workspace.task_id)

    @staticmethod
    def _callgraph_chain(adjacency: dict[str, set[str]], start: str, goal: str, *, max_depth: int) -> list[str] | None:
        """BFS：start 函数到 goal 函数的调用链；找不到返回 None。"""
        if start == goal:
            return [start]
        from collections import deque as _deque

        queue = _deque([[start]])
        seen = {start}
        while queue:
            chain = queue.popleft()
            if len(chain) > max_depth:
                continue
            for callee in adjacency.get(chain[-1], ()):
                nxt = chain + [callee]
                if callee == goal:
                    return nxt
                if callee not in seen:
                    seen.add(callee)
                    queue.append(nxt)
        return None

    def _link_hypotheses(
        self,
        sources: list[InputSourceDescriptor],
        sinks: list[SensitiveSink],
        paths: list[TaintPath],
    ) -> list[SourceSinkHypothesisLink]:
        links = []
        fcgi_paths = [item for item in paths if "H-FCGI-0001" in item.hypothesis_ids]
        if any(hypothesis.id == "H-FCGI-0001" for hypothesis in self.hypotheses):
            links.append(
                SourceSinkHypothesisLink(
                    hypothesis_id="H-FCGI-0001",
                    source_ids=[item.source_id for item in sources if item.source_id.startswith("SRC-FCGI")],
                    sink_ids=[item.sink_id for item in sinks if item.sink_id.startswith("SINK-FCGI")],
                    taint_path_ids=[item.path_id for item in fcgi_paths],
                    relationship="candidate_source_sink_context",
                    confidence=max((item.confidence for item in fcgi_paths), default=0.0),
                    runtime_supported=False,
                    reason="runtime-confirmed handler with same-component sensitive sinks, but argument-level source-to-sink data flow is unresolved",
                )
            )
        ret_paths = [item for item in paths if "H-RET2TEXT-0001" in item.hypothesis_ids]
        if any(hypothesis.id == "H-RET2TEXT-0001" for hypothesis in self.hypotheses):
            links.append(
                SourceSinkHypothesisLink(
                    hypothesis_id="H-RET2TEXT-0001",
                    source_ids=[item.source_id for item in sources if item.source_id == "SRC-RET2TEXT-STDIN"],
                    sink_ids=[item.sink_id for item in sinks if item.sink_id.startswith("SINK-RET2TEXT")],
                    taint_path_ids=[item.path_id for item in ret_paths],
                    relationship="supported_unsafe_input_path_without_command_exploit",
                    confidence=max((item.confidence for item in ret_paths), default=0.0),
                    runtime_supported=False,
                    reason="stdin to gets is supported; secure/system is separate and no stdin-to-system data-flow path is created",
                )
            )
        return links

    def _source_catalog(self, sources: list[InputSourceDescriptor]) -> list[InputSourceCatalog]:
        by_entry: dict[str, list[InputSourceDescriptor]] = {}
        for source in sources:
            by_entry.setdefault(source.entry_point_id or "unknown", []).append(source)
        entries = {item["entry_id"]: item for item in self.surface.get("entry_points", [])}
        return [
            InputSourceCatalog(
                entry_point_id=entry_id,
                service=(entries.get(entry_id) or {}).get("service"),
                backend_component_id=(entries.get(entry_id) or {}).get("handler_component_id"),
                sources=[item.to_dict() for item in items],
            )
            for entry_id, items in sorted(by_entry.items())
        ]

    def _sink_catalog(self, sinks: list[SensitiveSink]) -> list[SensitiveFunctionCatalog]:
        by_binary: dict[str, list[SensitiveSink]] = {}
        for sink in sinks:
            by_binary.setdefault(sink.binary_path or "unknown", []).append(sink)
        return [
            SensitiveFunctionCatalog(
                binary=binary,
                functions=[
                    {
                        "function": item.function_name,
                        "callee": item.callee_name,
                        "sink_type": item.sink_type,
                        "references": item.evidence_ids,
                        "callers": [],
                        "confidence": item.confidence,
                    }
                    for item in items
                ],
            )
            for binary, items in sorted(by_binary.items())
        ]

    def _summary(
        self,
        sources: list[InputSourceDescriptor],
        sinks: list[SensitiveSink],
        paths: list[TaintPath],
        sanitizers: list[SanitizerDescriptor],
        data_flow_evidence: list[DataFlowEvidence] | None = None,
    ) -> TaintAnalysisSummary:
        dfe_by_path: dict[str, dict[str, Any]] = {}
        for item in data_flow_evidence or []:
            for path_id in [p for p in [item.path_id] if p] if hasattr(item, "path_id") else []:
                dfe_by_path[path_id] = item.to_dict()
        # DataFlowEvidence 没有 path_id 字段时按 source_id+sink_id 关联
        for item in data_flow_evidence or []:
            dfe_by_path.setdefault(f"{item.source_id}|{item.sink_id}", item.to_dict())
        mapped_path_ids = {
            dfe.get("source_id", "")
            for dfe in dfe_by_path.values()
            if dfe.get("argument_mapping")
        }
        return TaintAnalysisSummary(
            sources=len(sources),
            sinks=len(sinks),
            candidate_paths=sum(1 for path in paths if path.path_state == "candidate"),
            supported_paths=sum(1 for path in paths if path.path_state in {"statically_supported", "runtime_supported", "validated"}),
            runtime_supported_paths=sum(1 for path in paths if path.runtime_supported),
            paths_with_sanitizers=sum(1 for path in paths if path.sanitizers),
            unknown_paths=sum(1 for path in paths if path.path_state == "unknown"),
            high_priority_paths=sum(1 for path in paths if path.confidence >= 0.75 and path.sink_id),
            source_types=dict(sorted(Counter(source.source_type for source in sources).items())),
            sink_types=dict(sorted(Counter(sink.sink_type for sink in sinks).items())),
            argument_mapped_paths=sum(
                1 for path in paths
                if any(
                    dfe.get("source_id") == path.source_id and dfe.get("sink_id") == path.sink_id and dfe.get("argument_mapping")
                    for dfe in dfe_by_path.values()
                )
            ),
            decompile_backed_paths=sum(
                1 for path in paths
                if any("decompile" in str(ev_id).lower() for ev_id in path.evidence_ids)
            ),
            callgraph_synthetic_paths=sum(1 for path in paths if path.path_id.startswith("TP-GEN-")),
            safety_notes=[
                "SOURCE + SINK != VULNERABILITY",
                "CALL PATH != DATA FLOW",
                "REACHABLE SINK != EXPLOITABLE SINK",
                "SANITIZER UNKNOWN != SANITIZER ABSENT",
                "Sink relevance is not CVSS, exploitability, or real-world impact.",
            ],
        )

    def _contexts(
        self,
        sources: list[InputSourceDescriptor],
        sinks: list[SensitiveSink],
        paths: list[TaintPath],
        sanitizers: list[SanitizerDescriptor],
        links: list[SourceSinkHypothesisLink],
    ) -> list[TaintContext]:
        contexts = []
        for link in links:
            link_sources = [source.to_dict() for source in sources if source.source_id in set(link.source_ids)]
            link_sinks = [sink.to_dict() for sink in sinks if sink.sink_id in set(link.sink_ids)]
            link_paths = [path.to_dict() for path in paths if path.path_id in set(link.taint_path_ids)]
            contexts.append(
                TaintContext(
                    hypothesis_id=link.hypothesis_id,
                    entry_id=link_sources[0].get("entry_point_id") if link_sources else None,
                    component_id=link_sinks[0].get("component_id") if link_sinks else None,
                    sources=link_sources,
                    sinks=link_sinks,
                    paths=link_paths,
                    sanitizers=[item.to_dict() for item in sanitizers],
                    functions=sorted({fn for path in link_paths for fn in path.get("function_chain", [])}),
                    conclusion="supported_data_flow_without_vulnerability_confirmation" if any(path.get("path_state") == "statically_supported" for path in link_paths) else "candidate_or_unknown",
                )
            )
        return contexts

    def _persist(self, payload: dict[str, Any]) -> None:
        self.workspace.save_taint_artifact("sources.json", payload["sources"])
        self.workspace.save_taint_artifact("sinks.json", payload["sinks"])
        self.workspace.save_taint_artifact("sink_catalog.json", payload["sink_catalog"])
        self.workspace.save_taint_artifact("source_catalog.json", payload["source_catalog"])
        self.workspace.save_taint_artifact("taint_facts.json", payload["taint_facts"])
        self.workspace.save_taint_artifact("taint_graph.json", payload["taint_graph"])
        self.workspace.save_taint_artifact("taint_paths.json", payload["taint_paths"])
        self.workspace.save_taint_artifact("sanitizers.json", payload["sanitizers"])
        self.workspace.save_taint_artifact("transformations.json", payload["transformations"])
        self.workspace.save_taint_artifact("data_flow_evidence.json", payload["data_flow_evidence"])
        self.workspace.save_taint_artifact("hypothesis_links.json", payload["hypothesis_links"])
        self.workspace.save_taint_artifact("summary.json", payload["summary"])
        self.workspace.save_taint_artifact("contexts.json", payload["contexts"])
        self.workspace.save_taint_artifact("taint_analysis.json", payload)

    def _load_report(self) -> dict[str, Any]:
        try:
            return self.workspace.load_report()
        except FileNotFoundError:
            return {}


def _unique_sinks(sinks: list[SensitiveSink]) -> list[SensitiveSink]:
    # Preserve legacy IDs when unambiguous; disambiguate every conflicting path
    # deterministically before deduplication, rather than dropping a same-name ELF.
    paths: dict[str, set[str]] = {}
    slugs: dict[str, set[tuple[str, str | None]]] = {}
    for sink in sinks:
        path = rootfs_relative_path(sink.binary_path) if sink.binary_path else None
        if sink.binary_path:
            paths.setdefault(sink.sink_id, set()).add(path)
        slugs.setdefault(_slug(sink.sink_id), set()).add((sink.sink_id, path))
    by_id = {}
    for sink in sinks:
        if (sink.binary_path and len(paths[sink.sink_id]) > 1) or len(slugs[_slug(sink.sink_id)]) > 1:
            material = f"{rootfs_relative_path(sink.binary_path) if sink.binary_path else ''}\0{sink.sink_id}"
            suffix = hashlib.sha256(material.encode()).hexdigest()[:16]
            sink = replace(sink, sink_id=sink.sink_id[:60] + "-" + suffix)
        by_id.setdefault(sink.sink_id, sink)
    return list(by_id.values())


def _sink_relevance(sink_type: str) -> float:
    return {
        "command_execution": 0.95,
        "process_execution": 0.93,
        "unsafe_copy": 0.84,
        "memory_copy": 0.68,
        "formatted_output": 0.70,
        "file_write": 0.62,
        "file_open": 0.55,
        "authentication_decision": 0.82,
        "authorization_decision": 0.82,
        "nvram_write": 0.76,
        "dynamic_load": 0.78,
    }.get(sink_type, 0.5)


def _slug(value: str) -> str:
    normalized = "".join(ch.lower() if ch.isalnum() else "-" for ch in str(value))
    return "-".join(part for part in normalized.split("-") if part)[:80] or "unknown"


def _strip_expr(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip().strip("()"))


def _split_args(value: str) -> list[str]:
    args = []
    depth = 0
    current = []
    for ch in value:
        if ch == "," and depth == 0:
            args.append("".join(current).strip())
            current = []
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        current.append(ch)
    if current:
        args.append("".join(current).strip())
    return args


def _token_equal(left: str, right: str) -> bool:
    tokens = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", right))
    return left in tokens or left == right


def _clamp01(value: float) -> float:
    return round(max(0.0, min(1.0, float(value))), 3)
