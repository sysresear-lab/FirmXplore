"""Bounded, read-only assessment of existing Ghidra v1 exports.

This reader does not decompile, execute, generate canonical task artifacts or
promote findings. v1 supplies call relationships, not parameter propagation.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from fwagent.dynamic.static_evidence import (
    BinaryIdentity, EvidenceValidationError, JsonEvidenceStore, StaticEvidence,
    entry_key, rootfs_relative_path, validate_evidence_bundle,
)


RECEIVER_SYMBOLS = {"recv", "recvfrom", "recvmsg", "read", "fread", "fgets", "gets", "getenv", "getchar"}
MINIMUM_EXPORT_REQUIREMENTS = [
    "callsite instruction address, instruction kind, caller entry and resolved callee identity",
    "calling convention, actual argument indices/values and callee parameter mapping",
    "SSA or p-code value IDs, definitions/uses, memory alias and buffer/length relationships",
    "source output values/buffers and sink argument values connected by explicit def-use edges",
    "basic blocks, branch conditions and check/sanitizer coverage for the propagated values",
]


@dataclass
class ExportBinary:
    identity: BinaryIdentity
    identity_reference: dict[str, str]
    path_reference: dict[str, str]
    collections: dict[str, tuple[dict[str, str], list[Any]]]
    diagnostics: list[str] = field(default_factory=list)

    def rows(self, kind: str) -> list[tuple[dict[str, str], dict[str, Any]]]:
        base, rows = self.collections.get(kind, ({}, []))
        result = []
        for index, row in enumerate(rows):
            if not isinstance(row, dict):
                self.diagnostics.append(f"{base.get('source_artifact')}#{base.get('source_json_pointer')}/{index}: expected an object")
                continue
            reference = {**base, "source_json_pointer": base["source_json_pointer"] + f"/{index}"}
            result.append((reference, row))
        return result

    def call_edges(self) -> list[StaticEvidence]:
        edges = []
        for reference, row in self.rows("callgraph"):
            try:
                if not all(isinstance(row.get(key), str) and row[key] for key in ("caller", "callee", "caller_address", "callee_address")):
                    raise EvidenceValidationError("caller/callee names and entry addresses required")
                entry_key(row["caller_address"])
                entry_key(row["callee_address"])
                edges.append(StaticEvidence(
                    "dataflow_edge", self.identity, **reference, function_entry=row["caller_address"],
                    function_name=row["caller"], target_function_entry=row["callee_address"],
                    edge_kind="callgraph_edge", status="observed" if self.identity.sha256 else "partial",
                    observation={"caller": row["caller"], "callee": row["callee"],
                                 "caller_function_id": self.identity.function_id(row["caller_address"]),
                                 "callee_function_id": self.identity.function_id(row["callee_address"])},
                    limitations=["Function entry addresses are not callsite addresses",
                                 "Call relation does not establish argument propagation"],
                ))
            except EvidenceValidationError as exc:
                self.diagnostics.append(f"{reference['source_artifact']}#{reference['source_json_pointer']}: {exc}")
        return edges

    def named_chain(self, names: list[str]) -> list[StaticEvidence]:
        """Resolve legacy display names only when a unique address chain exists."""
        candidates: list[list[StaticEvidence]] = [[]]
        edges = self.call_edges()
        for caller, callee in zip(names, names[1:]):
            matching = [edge for edge in edges if edge.observation["caller"] == caller and edge.observation["callee"] == callee]
            extended: dict[tuple[str, ...], list[StaticEvidence]] = {}
            for chain in candidates:
                for edge in matching:
                    if chain and entry_key(chain[-1].target_function_entry) != entry_key(edge.function_entry):
                        continue
                    next_chain = chain + [edge]
                    key = tuple(entry_key(item.function_entry) for item in next_chain) + (entry_key(edge.target_function_entry),)
                    extended.setdefault(key, next_chain)
            candidates = list(extended.values())
        if len(candidates) != 1 or not candidates[0]:
            self.diagnostics.append("legacy function chain is missing or ambiguous at function-entry level")
            return []
        return candidates[0]

    def receiver_chain(self, sink_symbol: str, *, max_depth: int = 4) -> list[StaticEvidence]:
        """Search by entry addresses, never merge same-named function bodies."""
        edges = self.call_edges()
        adjacency: dict[str, list[StaticEvidence]] = {}
        starts = set()
        for edge in edges:
            caller = entry_key(edge.function_entry)
            adjacency.setdefault(caller, []).append(edge)
            if edge.observation["callee"].split("@", 1)[0] in RECEIVER_SYMBOLS:
                starts.add(caller)
        queue = deque((start, []) for start in sorted(starts))
        seen = set(starts)
        while queue:
            current, chain = queue.popleft()
            if len(chain) >= max_depth:
                continue
            for edge in sorted(adjacency.get(current, []), key=lambda item: (entry_key(item.target_function_entry), item.evidence_id)):
                if edge.observation["callee"].split("@", 1)[0] == sink_symbol:
                    return chain + [edge]
                target = entry_key(edge.target_function_entry)
                if target not in seen:
                    seen.add(target)
                    queue.append((target, chain + [edge]))
        return []


class GhidraEvidenceIndex:
    def __init__(self, task_dir: str | Path, *, task_id: str):
        self.store = JsonEvidenceStore(task_dir, task_id=task_id)
        self.task_id = task_id
        self.binaries: list[ExportBinary] = []
        self.diagnostics: list[str] = []
        self._load()

    def _load(self) -> None:
        artifact = "ghidra/analysis_summary.json"
        try:
            summary, digest = self.store.read(artifact)
            if not isinstance(summary, dict) or not isinstance(summary.get("analyses"), list):
                raise EvidenceValidationError("analysis_summary.analyses: expected a list")
        except EvidenceValidationError as exc:
            self.diagnostics.append(str(exc))
            return
        for index, analysis in enumerate(summary["analyses"]):
            prefix = f"/analyses/{index}"
            try:
                if not isinstance(analysis, dict) or not isinstance(analysis.get("target"), dict):
                    raise EvidenceValidationError("target.path required; a host basename is not a rootfs identity")
                path = rootfs_relative_path(analysis["target"].get("path"))
                result = analysis.get("result")
                if not isinstance(result, dict) or not isinstance(result.get("summary"), dict):
                    raise EvidenceValidationError("result.summary: unavailable")
                identity = BinaryIdentity.from_export(path, result["summary"], task_id=self.task_id,
                    hash_origin=f"{artifact}#{prefix}/result/summary/sha256",
                    path_origin=f"{artifact}#{prefix}/target/path")
                reference = {"source_artifact": artifact, "source_artifact_sha256": digest}
                collections = {}
                for kind in ("callgraph", "functions", "imports"):
                    rows = result.get(kind)
                    if not isinstance(rows, list):
                        self.diagnostics.append(f"{artifact}#{prefix}/result/{kind}: expected a list")
                        rows = []
                    collections[kind] = ({**reference, "source_json_pointer": prefix + "/result/" + kind}, rows)
                # Embedded exports are valid evidence too. Prefer saved raw exports
                # only when their actual contents agree with the embedded data.
                metadata = result.get("metadata")
                output = metadata.get("output_dir") if isinstance(metadata, dict) else None
                if isinstance(output, str) and "/ghidra/outputs/" in output.replace("\\", "/"):
                    suffix = output.replace("\\", "/").split("/ghidra/outputs/", 1)[1]
                    for kind in collections:
                        relative = f"ghidra/outputs/{suffix}/{kind}.json"
                        try:
                            saved, saved_digest = self.store.read(relative)
                            if saved != collections[kind][1]:
                                raise EvidenceValidationError("raw export differs from analysis_summary; using embedded record")
                            collections[kind] = ({"source_artifact": relative, "source_artifact_sha256": saved_digest,
                                                  "source_json_pointer": ""}, saved)
                        except EvidenceValidationError as exc:
                            self.diagnostics.append(f"{relative}: {exc}")
                self.binaries.append(ExportBinary(identity,
                    {**reference, "source_json_pointer": prefix + "/result/summary"},
                    {**reference, "source_json_pointer": prefix + "/target"}, collections))
            except EvidenceValidationError as exc:
                self.diagnostics.append(f"{artifact}#{prefix}: {exc}")

    def binary(self, path: str) -> ExportBinary | None:
        try:
            relative = rootfs_relative_path(path)
        except EvidenceValidationError as exc:
            self.diagnostics.append(str(exc))
            return None
        matches = [item for item in self.binaries if item.identity.rootfs_path == relative]
        if len(matches) != 1:
            self.diagnostics.append(f"binary {relative}: unavailable or ambiguous export identity ({len(matches)} records)")
            return None
        return matches[0]

    def audit_candidate(self, path_id: str) -> dict[str, Any]:
        """Read actual saved objects and report gaps; never edit a finding."""
        paths, _ = self.store.read("taint/taint_paths.json")
        sources, _ = self.store.read("taint/sources.json")
        sinks, _ = self.store.read("taint/sinks.json")
        findings, _ = self.store.read("findings/findings.json")
        if not all(isinstance(value, list) and all(isinstance(row, dict) for row in value) for value in (paths, sources, sinks)):
            raise EvidenceValidationError("saved paths/sources/sinks: expected object lists")
        if not isinstance(findings, dict) or not isinstance(findings.get("findings"), list) or not all(isinstance(row, dict) for row in findings["findings"]):
            raise EvidenceValidationError("findings.findings: expected an object list")
        def unique(rows: list[dict[str, Any]], key: str, value: Any) -> tuple[int, dict[str, Any]]:
            matches = [(index, row) for index, row in enumerate(rows) if row.get(key) == value]
            if len(matches) != 1:
                raise EvidenceValidationError(f"{key} {value!r}: missing or ambiguous saved reference")
            return matches[0]
        path_index, path = unique(paths, "path_id", path_id)
        source_index, source = unique(sources, "source_id", path.get("source_id"))
        sink_index, sink = unique(sinks, "sink_id", path.get("sink_id"))
        matching_findings = [(index, row) for index, row in enumerate(findings["findings"])
                             if isinstance(row.get("taint_path_ids"), list) and path_id in row["taint_path_ids"]]
        export = self.binary(sink.get("binary_path"))
        result: dict[str, Any] = {
            "path_id": path_id, "original_path_state": path.get("path_state"),
            "original_evidence_level": path.get("evidence_level"),
            "original_source": source, "original_sink": sink,
            "original_findings": [row for _, row in matching_findings],
            "original_references": {
                "path": self.store.reference("taint/taint_paths.json", f"/{path_index}")[0],
                "source": self.store.reference("taint/sources.json", f"/{source_index}")[0],
                "sink": self.store.reference("taint/sinks.json", f"/{sink_index}")[0],
                "findings": [self.store.reference("findings/findings.json", f"/findings/{index}")[0] for index, _ in matching_findings],
            },
            "status": "insufficient_export", "parameter_flow_supported": False,
            "proved_parameter_chain": [], "finding_mutation": False,
            "evidence": [], "missing_export_fields": list(MINIMUM_EXPORT_REQUIREMENTS),
            "mitigation_assessment": {"status": "unavailable", "observed_checks": [],
                "limitations": ["Empty legacy sanitizer lists do not prove absence of validation or sanitization",
                                "No check instructions, branch conditions or value coverage exported"]},
        }
        if export is None:
            result.update(binary_identity=None, callgraph_status="unavailable", diagnostics=list(self.diagnostics))
            return result
        identity = export.identity
        result["binary_identity"] = identity.to_dict()
        result["identity_references"] = {"binary_metadata": export.identity_reference, "rootfs_path": export.path_reference}
        names = path.get("function_chain")
        if not isinstance(names, list) or not all(isinstance(name, str) and name for name in names):
            raise EvidenceValidationError("function_chain: expected nonempty function names")
        chain = export.named_chain(names)
        result["callgraph_status"] = "callgraph_only" if chain else "unavailable"
        records: dict[str, StaticEvidence] = {edge.evidence_id: edge for edge in chain}
        receiver_edges = [edge for edge in export.call_edges() if chain
                          and entry_key(edge.function_entry) == entry_key(chain[0].function_entry)
                          and edge.observation["callee"].split("@", 1)[0] in RECEIVER_SYMBOLS]
        source_ref = result["original_references"]["source"]
        original_source = StaticEvidence("source", identity, **source_ref, status="unavailable",
            observation={"legacy_source_id": source.get("source_id"), "legacy_function_name": source.get("function_name"),
                         "input_origin": "unknown", "external_controllability": "unknown"},
            limitations=["Entry descriptor is not a located receiver call; CGI dispatch/socket input origin unverified"])
        records[original_source.evidence_id] = original_source
        for edge in receiver_edges:
            receiver = StaticEvidence("source", identity, source_artifact=edge.source_artifact,
                source_artifact_sha256=edge.source_artifact_sha256, source_json_pointer=edge.source_json_pointer,
                function_entry=edge.function_entry, function_name=edge.function_name, target_function_entry=edge.target_function_entry,
                status="partial", observation={"receiver_symbol": edge.observation["callee"],
                    "input_origin": "unknown", "external_controllability": "unknown"},
                limitations=["Receiver name and call relation observed; socket/FD, output buffer and controllability unavailable"])
            records[receiver.evidence_id] = receiver
        result["receiver_symbols"] = sorted({edge.observation["callee"] for edge in receiver_edges})
        result["source_assessment"] = {
            "status": "source_unverified", "external_controllability": "unknown",
            "api_observations": [{"symbol": edge.observation["callee"],
                "category": ("environment_access_api" if edge.observation["callee"] == "getenv" else
                             "network_receive_api" if edge.observation["callee"] in {"recv", "recvfrom", "recvmsg"} else
                             "generic_read_api"),
                "reference": {key: getattr(edge, key) for key in ("source_artifact", "source_artifact_sha256", "source_json_pointer")}}
                for edge in receiver_edges],
            "limitations": ["API category is not proof of an external peer, environment variable, stream identity or attacker control"],
        }
        for edge in chain:
            callsite = StaticEvidence("callsite", identity, source_artifact=edge.source_artifact,
                source_artifact_sha256=edge.source_artifact_sha256, source_json_pointer=edge.source_json_pointer,
                function_entry=edge.function_entry, target_function_entry=edge.target_function_entry, status="unavailable",
                observation={"caller": edge.observation["caller"], "callee": edge.observation["callee"]},
                limitations=["Export has function entry addresses only; call instruction address unavailable"])
            records[callsite.evidence_id] = callsite
        sink_ref = result["original_references"]["sink"]
        parameter = StaticEvidence("parameter", identity, **sink_ref, status="unavailable",
            observation={"legacy_argument_index": sink.get("argument_index"), "sink_symbol": sink.get("callee_name")},
            limitations=["Legacy registry argument_index is not an observed actual argument; index and role remain unknown"])
        records[parameter.evidence_id] = parameter
        if chain:
            edge = chain[-1]
            imports = [row for _, row in export.rows("imports") if row.get("name") == sink.get("callee_name")]
            exact_sink = edge.observation["callee"] == sink.get("callee_name")
            result["sink_assessment"] = {"status": "sink_unverified", "exact_callee_label": exact_sink,
                "exact_import_symbol_observed": bool(imports), "dangerous_parameter_index": None,
                "dangerous_parameter_role": None, "limitations": ["External thunk binding and actual argument semantics unavailable"]}
            sink_evidence = StaticEvidence("sink", identity, source_artifact=edge.source_artifact,
                source_artifact_sha256=edge.source_artifact_sha256, source_json_pointer=edge.source_json_pointer,
                function_entry=edge.function_entry, function_name=edge.function_name, target_function_entry=edge.target_function_entry,
                status="partial", observation={"callee": edge.observation["callee"], "exact_import_symbol_observed": bool(imports),
                                               "matches_legacy_sink_label": exact_sink},
                limitations=["Exact callee label observed; thunk-to-external binding and dangerous argument remain unverified"])
            records[sink_evidence.evidence_id] = sink_evidence
        result["function_references"] = []
        symbols = set(result["receiver_symbols"]) | {sink.get("callee_name")}
        result["symbol_references"] = [{**reference, "symbol": row.get("name")}
            for reference, row in export.rows("imports") if isinstance(row.get("name"), str) and row["name"] in symbols]
        entries = {entry_key(edge.function_entry) for edge in chain} | {entry_key(edge.target_function_entry) for edge in chain}
        for reference, function in export.rows("functions"):
            try:
                if entry_key(function.get("address")) in entries:
                    result["function_references"].append({**reference, "function_id": identity.function_id(function["address"]),
                                                          "entry": function["address"], "name": function.get("name")})
            except EvidenceValidationError as exc:
                export.diagnostics.append(str(exc))
        result["evidence"] = [record.to_dict() for record in records.values()]
        result["diagnostics"] = list(self.diagnostics) + list(export.diagnostics) + validate_evidence_bundle(list(records.values()), self.store)
        result["reason"] = "Call relationships located; no exported callsite arguments, buffer/value def-use or mitigation coverage"
        return result
