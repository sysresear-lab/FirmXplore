"""Offline contract, graph identity and saved-candidate regressions."""
from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from fwagent.dynamic.config import DynamicConfig
from fwagent.dynamic.correlation import ComponentGraph, FirmwareComponent
from fwagent.dynamic.static_audit import GhidraEvidenceIndex
from fwagent.dynamic.static_evidence import (
    BinaryIdentity, EvidenceValidationError, JsonEvidenceStore, StaticEvidence, validate_evidence_bundle,
)
from fwagent.dynamic.taint import (
    InputSourceDescriptor, SensitiveSink, StaticDataFlowBridge, TaintAnalysisBuilder, TaintGraph, _unique_sinks,
)
from fwagent.dynamic.workspace import DynamicWorkspace


ROOT = Path(__file__).resolve().parents[2]
TASK = ROOT / "docs/diagnostics/phase3-20261016T173500Z-c02c78/task"
AUDIT = ROOT / "docs/diagnostics/phase4-20261016T181745Z-6e5429/paths_audit.json"


class StaticEvidenceTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.workspace = DynamicWorkspace(temp.name, "export-fixture")
        self.task = self.workspace.task_dir
        self.store = JsonEvidenceStore(self.task)
        self.identity = BinaryIdentity.from_export("/bin/same", {"sha256": "a" * 64},
                                                  task_id="export-fixture", hash_origin="summary.json#/sha256")
        self.write("summary.json", {"sha256": "a" * 64})

    def write(self, relative, value):
        path = self.task / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def edge(self, caller="start", callee="system", caller_entry="00401000", callee_entry="00402000"):
        return {"caller": caller, "callee": callee, "caller_address": caller_entry, "callee_address": callee_entry}

    def export(self, path="/bin/same", edges=None, digest="a" * 64):
        edges = [self.edge("start", "recvfrom", "00401000", "00403000"), self.edge()] if edges is None else edges
        return {"target": {"path": path}, "binary": "/host/rootfs" + path,
                "result": {"summary": {"sha256": digest}, "callgraph": edges,
                           "functions": [], "imports": [{"name": "recvfrom"}, {"name": "system"}]}}

    def write_exports(self, *exports):
        self.write("ghidra/analysis_summary.json", {"analyses": list(exports)})

    def record(self, kind="dataflow_edge", status="observed", **kwargs):
        self.write("edges.json", [self.edge()])
        reference, _ = self.store.reference("edges.json", "/0")
        return StaticEvidence(kind, self.identity, **reference, function_entry="00401000",
                              target_function_entry="00402000", status=status, **kwargs)

    def test_callgraph_contract_does_not_acquire_parameters_or_callsites(self):
        edge = self.record(edge_kind="callgraph_edge")
        self.assertEqual(validate_evidence_bundle([edge], self.store), [])
        self.assertIsNone(edge.parameter_index)
        self.assertIsNone(edge.callsite_address)
        self.assertIsNone(edge.input_value)
        self.assertEqual(edge.to_dict()["field_status"]["parameter_index"], "unavailable")

    def test_all_five_evidence_kinds_round_trip_without_losing_references(self):
        for kind in ("source", "sink", "callsite", "parameter", "dataflow_edge"):
            with self.subTest(kind=kind):
                kwargs = {"edge_kind": "callgraph_edge"} if kind == "dataflow_edge" else {}
                item = self.record(kind, "partial", limitations=["arguments unavailable"], **kwargs)
                saved = json.loads(json.dumps(item.to_dict()))
                self.assertEqual(StaticEvidence.from_dict(saved).to_dict(), saved)
                self.assertEqual(validate_evidence_bundle([StaticEvidence.from_dict(saved)], self.store), [])

    def test_callgraph_cannot_be_relabeled_as_parameter_flow(self):
        item = self.record(edge_kind="intra_procedural_flow", status="partial", limitations=["not exported"])
        self.assertTrue(any("cannot be relabeled" in message for message in validate_evidence_bundle([item], self.store)))

    def test_interprocedural_flow_requires_matching_argument_mapping(self):
        raw = {"function_entry": "00401000", "target_function_entry": "00402000", "edge_kind": "inter_procedural_flow",
               "callsite_address": "00401010", "input_value": "ssa:a", "output_value": "ssa:b"}
        self.write("flows.json", [raw])
        reference, _ = self.store.reference("flows.json", "/0")
        edge = StaticEvidence("dataflow_edge", self.identity, **reference, **raw, status="observed")
        self.assertTrue(any("argument_mapping required" in message for message in validate_evidence_bundle([edge], self.store)))

    def test_missing_and_invalid_references_have_diagnostics(self):
        good = self.record(edge_kind="callgraph_edge")
        for field, value, expected in (("source_json_pointer", "/500", "does not resolve"),
                                        ("source_artifact", "missing.json", "FileNotFoundError"),
                                        ("source_artifact_sha256", "b" * 64, "content does not match")):
            with self.subTest(field=field):
                data = good.to_dict()
                data.pop("evidence_id")
                data[field] = value
                changed = StaticEvidence.from_dict(data)
                self.assertTrue(any(expected in message for message in validate_evidence_bundle([changed], self.store)))
        good.related_evidence_ids = ["missing-evidence"]
        self.assertTrue(any("missing evidence" in message for message in validate_evidence_bundle([good], self.store)))

    def test_wrong_field_types_do_not_default_to_argument_zero(self):
        fields = ({"parameter_index": True}, {"parameter_index": "0"}, {"parameter_index": -1},
                  {"callsite_address": []}, {"observation": []}, {"status": []}, {"edge_kind": []})
        for kwargs in fields:
            with self.subTest(kwargs=kwargs), self.assertRaises(EvidenceValidationError):
                StaticEvidence("parameter", self.identity, limitations=["unknown"], **kwargs)
        with self.assertRaisesRegex(EvidenceValidationError, "required"):
            StaticEvidence("parameter", self.identity, status="observed")

    def test_reference_cannot_substitute_function_or_parameter(self):
        reference, _ = self.store.reference("summary.json", "")
        forged = StaticEvidence("parameter", self.identity, **reference, status="partial",
                                parameter_index=0, limitations=["no parameter export"])
        self.assertTrue(any("parameter_index" in message for message in validate_evidence_bundle([forged], self.store)))

    def test_same_basename_exports_are_selected_by_exact_path(self):
        self.write_exports(self.export("/bin/same"), self.export("/sbin/same", digest="b" * 64))
        index = GhidraEvidenceIndex(self.task, task_id="export-fixture")
        first, second = index.binary("/bin/same"), index.binary("/sbin/same")
        self.assertNotEqual(first.identity.identity_id, second.identity.identity_id)
        self.assertNotEqual(first.identity.function_id("00401000"), second.identity.function_id("00401000"))
        self.assertIsNone(index.binary("same"))
        self.assertTrue(any("unavailable" in message for message in index.diagnostics))

    def test_same_function_names_do_not_join_different_entries(self):
        edges = [self.edge("start", "recvfrom", "00401000", "00403000"),
                 self.edge("start", "helper", "00401000", "00404000"),
                 self.edge("helper", "system", "00405000", "00402000")]
        self.write_exports(self.export(edges=edges))
        export = GhidraEvidenceIndex(self.task, task_id="export-fixture").binary("/bin/same")
        self.assertEqual(export.receiver_chain("system"), [])
        self.assertEqual(export.named_chain(["start", "helper", "system"]), [])

    def test_missing_addresses_never_become_synthetic_function_entries(self):
        self.write_exports(self.export(edges=[{"caller": "start", "callee": "system"}]))
        export = GhidraEvidenceIndex(self.task, task_id="export-fixture").binary("/bin/same")
        self.assertEqual(export.call_edges(), [])
        self.assertTrue(any("entry addresses required" in message for message in export.diagnostics))

    def test_receiver_names_are_exact_and_do_not_prove_controllability(self):
        for symbol in ("myrecvfrom", "readdir64", "fread_hook"):
            self.write_exports(self.export(edges=[self.edge("start", symbol, "00401000", "00403000"), self.edge()]))
            export = GhidraEvidenceIndex(self.task, task_id="export-fixture").binary("/bin/same")
            self.assertEqual(export.receiver_chain("system"), [])

    def test_missing_raw_export_falls_back_to_real_embedded_pointer(self):
        export = self.export()
        export["result"]["metadata"] = {"output_dir": "/saved/task/ghidra/outputs/missing"}
        self.write_exports(export)
        index = GhidraEvidenceIndex(self.task, task_id="export-fixture")
        binary = index.binary("/bin/same")
        edge = binary.receiver_chain("system")[0]
        self.assertEqual(edge.source_artifact, "ghidra/analysis_summary.json")
        self.assertEqual(self.store.resolve(edge.to_dict())["callee"], "system")
        self.assertTrue(any("FileNotFoundError" in message for message in index.diagnostics))

    def test_malformed_export_records_are_isolated_with_diagnostics(self):
        good = self.export()
        self.write_exports(None, {"target": None}, good)
        index = GhidraEvidenceIndex(self.task, task_id="export-fixture")
        self.assertEqual(len(index.binaries), 1)
        self.assertEqual(len(index.diagnostics), 2)
        self.assertTrue(index.binary("/bin/same").receiver_chain("system"))

    def test_generic_analyzer_does_not_borrow_same_basename_callgraph(self):
        self.write_exports(self.export("/bin/same", edges=[]), self.export("/sbin/same", digest="b" * 64))
        builder = TaintAnalysisBuilder.__new__(TaintAnalysisBuilder)
        builder.workspace, builder.config, builder.graph = self.workspace, DynamicConfig(), ComponentGraph()
        sources, sinks = [], []
        for tag, path in (("A", "/bin/same"), ("B", "/sbin/same")):
            builder.graph.add_component(FirmwareComponent(tag, "binary", "same", path=path))
            sources.append(InputSourceDescriptor("SRC-" + tag, "unknown", component_id=tag))
            sinks.append(SensitiveSink("SINK-same-system", "command_execution", binary_path=path, component_id=tag, callee_name="system"))
        distinct = _unique_sinks(sinks)
        self.assertEqual(len(distinct), 2)
        self.assertNotEqual(distinct[0].sink_id, distinct[1].sink_id)
        graph, evidence = TaintGraph(), []
        paths = builder._generic_callgraph_paths(sources, distinct, graph, evidence)
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0].source_id, "SRC-B")
        self.assertEqual(paths[0].evidence_level, "L2_reachable_call_chain")
        self.assertEqual(paths[0].path_state, "candidate")
        self.assertEqual(evidence[0].analysis_status, "callgraph_only")
        self.assertEqual(evidence[0].argument_mapping, {})
        self.assertEqual({item["edge_kind"] for item in evidence[0].static_evidence}, {"callgraph_edge"})
        self.assertEqual(graph.edges[0].edge_type, "callgraph_edge")

    def test_sink_disambiguation_is_stable_without_changing_legacy_objects(self):
        original = SensitiveSink("SINK-legacy-system", "command_execution", binary_path="/bin/same")
        self.assertEqual(_unique_sinks([original])[0].sink_id, original.sink_id)
        other = SensitiveSink(original.sink_id, "command_execution", binary_path="/sbin/same")
        first = _unique_sinks([original, other])
        second = _unique_sinks([other, original])
        self.assertEqual({item.sink_id for item in first}, {item.sink_id for item in second})
        self.assertEqual([item.sink_id for item in _unique_sinks(first)], [item.sink_id for item in first])
        self.assertEqual(original.sink_id, "SINK-legacy-system")
        self.assertEqual(other.sink_id, original.sink_id)

    def test_same_basename_positive_paths_have_distinct_evidence_ids(self):
        self.write_exports(self.export("/bin/same"), self.export("/sbin/same", digest="b" * 64))
        builder = TaintAnalysisBuilder.__new__(TaintAnalysisBuilder)
        builder.workspace, builder.config, builder.graph = self.workspace, DynamicConfig(), ComponentGraph()
        sources, sinks = [], []
        for tag, path in (("A", "/bin/same"), ("B", "/sbin/same")):
            builder.graph.add_component(FirmwareComponent(tag, "binary", "same", path=path))
            sources.append(InputSourceDescriptor("SRC-" + tag, "unknown", component_id=tag))
            sinks.append(SensitiveSink("SINK-same-system", "command_execution", binary_path=path, component_id=tag, callee_name="system"))
        evidence = []
        paths = builder._generic_callgraph_paths(sources, _unique_sinks(sinks), TaintGraph(), evidence)
        self.assertEqual(len({path.path_id for path in paths}), 2)
        self.assertEqual(len({record.evidence_id for record in evidence}), 2)
        self.assertEqual(len({item["binary_identity"]["identity_id"] for record in evidence for item in record.static_evidence}), 2)

    def test_long_same_basename_does_not_collapse_different_sink_apis(self):
        from fwagent.dynamic.taint import _slug
        name = "long-daemon-" * 10
        sinks = [SensitiveSink(f"SINK-{name}-{api}", "command_execution", binary_path=f"/{directory}/{name}", callee_name=api)
                 for directory in ("bin", "sbin") for api in ("system", "popen")]
        distinct = _unique_sinks(sinks)
        self.assertEqual(len(distinct), 4)
        self.assertEqual(len({_slug(sink.sink_id) for sink in distinct}), 4)
        self.assertEqual({sink.sink_id for sink in _unique_sinks(list(reversed(sinks)))}, {sink.sink_id for sink in distinct})

    def test_binary_hash_origin_is_verified_against_existing_json(self):
        edge = self.record(edge_kind="callgraph_edge")
        self.write("summary.json", {"sha256": "b" * 64})
        self.assertTrue(any("identity does not match" in message for message in validate_evidence_bundle([edge], self.store)))

    def test_generic_sink_registry_does_not_invent_argument_index(self):
        from unittest.mock import patch
        builder = TaintAnalysisBuilder.__new__(TaintAnalysisBuilder)
        builder.config, builder.graph, builder.hypotheses = DynamicConfig(), ComponentGraph(), []
        builder.graph.add_component(FirmwareComponent("B", "binary", "same", path="/bin/same"))
        from fwagent.dynamic.taint import SensitiveSinkRegistry
        builder.registry = SensitiveSinkRegistry()
        with patch.object(builder, "_load_report", return_value={"binaries": [{"path": "/bin/same", "dangerous_symbols": ["system"]}]}):
            sink, = builder._discover_sinks()
        self.assertIsNone(sink.argument_index)

    def test_malformed_saved_references_have_explicit_errors(self):
        self.write_exports(self.export())
        self.write("taint/taint_paths.json", {"wrong": []})
        self.write("taint/sources.json", [])
        self.write("taint/sinks.json", [])
        self.write("findings/findings.json", {"findings": []})
        index = GhidraEvidenceIndex(self.task, task_id="export-fixture")
        with self.assertRaisesRegex(EvidenceValidationError, "expected object lists"):
            index.audit_candidate("missing")


class HistoricalCandidateTests(unittest.TestCase):
    def test_three_candidates_remain_unpromoted_and_saved_files_unchanged(self):
        protected = [p for phase in ("phase3-20261016T173500Z-c02c78", "phase4-20261016T181745Z-6e5429", "phase5-20261016T183843Z")
                     for p in (ROOT / "docs/diagnostics" / phase).rglob("*") if p.is_file()]
        before = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in protected}
        saved = json.loads(AUDIT.read_text(encoding="utf-8"))
        paths = json.loads((TASK / "taint/taint_paths.json").read_text(encoding="utf-8"))
        findings = json.loads((TASK / "findings/findings.json").read_text(encoding="utf-8"))
        self.assertEqual(len(paths), 32)
        self.assertEqual(len(findings["findings"]), 14)
        bridge = StaticDataFlowBridge(DynamicConfig())
        for label in ("P16", "P28", "P01"):
            with self.subTest(label=label):
                row, = [row for row in saved if row["label"] == label]
                result = bridge.audit_exported_candidate(TASK, task_id="accept-20261016T173500Z-c02c78", path_id=row["path"]["path_id"])
                self.assertEqual(result["path_id"], row["path"]["path_id"])
                self.assertEqual(result["status"], "insufficient_export")
                self.assertEqual(result["callgraph_status"], "callgraph_only")
                self.assertFalse(result["parameter_flow_supported"])
                self.assertFalse(result["finding_mutation"])
                self.assertEqual(result["proved_parameter_chain"], [])
                self.assertTrue(result["original_findings"])
                self.assertTrue(all(item["status"] == "candidate" for item in result["original_findings"]))
                self.assertTrue(result["binary_identity"]["sha256"])
                self.assertEqual(result["binary_identity"]["local_file_status"], "unavailable")
                self.assertEqual(result["diagnostics"], [])
                for item in result["evidence"]:
                    reread = StaticEvidence.from_dict(json.loads(json.dumps(item)))
                    self.assertEqual(reread.to_dict(), item)
                    if item["evidence_type"] in {"parameter", "callsite"}:
                        self.assertIsNone(item["parameter_index"])
                        self.assertIsNone(item["callsite_address"])
                self.assertEqual(result["mitigation_assessment"]["status"], "unavailable")
        self.assertEqual(before, {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in protected})
        self.assertEqual(json.loads((TASK / "findings/findings.json").read_text(encoding="utf-8")), findings)


if __name__ == "__main__":
    unittest.main()
