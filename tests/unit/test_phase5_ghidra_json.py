"""Ghidra artifact failures are offline inputs, never negative network proof."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fwagent.dynamic.config import DynamicConfig
from fwagent.dynamic.correlation import ComponentGraph
from fwagent.dynamic.surface import AttackSurfaceBuilder
from fwagent.dynamic.workspace import DynamicWorkspace


class GhidraJsonToleranceTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.workspace = DynamicWorkspace(Path(temp.name), "json-fixture")
        self.builder = AttackSurfaceBuilder.__new__(AttackSurfaceBuilder)
        self.builder.workspace = self.workspace
        self.builder.graph = ComponentGraph()
        self.builder.config = DynamicConfig()
        self.builder.hypotheses = []
        self.builder.dynamic_evidence = []
        self.write("analysis_summary.json", {"analyses": []})
        self.write("evidence.json", [])

    def write(self, filename, payload):
        path = self.workspace.task_dir / "ghidra" / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def analysis(self, binary="/lib/valid.so", imports=None):
        return {"binary": binary, "result": {"imports": [{"name": "recvfrom"}] if imports is None else imports}}

    def evidence(self, binary="/lib/fallback.so", symbol="recvmsg", evidence_id="E-valid"):
        return {"id": evidence_id, "metadata": {"binary": binary, "function": symbol}}

    def assert_diagnostic(self, artifact, pointer=None):
        status = self.builder._ghidra_input_status
        self.assertNotEqual(status["status"], "complete")
        self.assertTrue(any(item["artifact"] == "ghidra/" + artifact
                            and (pointer is None or item["json_pointer"] == pointer)
                            for item in status["diagnostics"]), status)

    def check_bad_file(self, filename):
        # The independent, healthy source must survive every file failure.
        if filename == "analysis_summary.json":
            self.write("evidence.json", [self.evidence()])
            expected = "fallback.so"
        else:
            self.write("analysis_summary.json", {"analyses": [self.analysis()]})
            expected = "valid.so"
        path = self.workspace.task_dir / "ghidra" / filename
        for label, content in (("missing", None), ("json", b"{"), ("utf8", b"\xff"),
                               ("null", b"null"), ("string", b'"wrong"'), ("number", b"42")):
            with self.subTest(filename=filename, failure=label):
                if content is None:
                    path.unlink(missing_ok=True)
                else:
                    path.write_bytes(content)
                with self.assertLogs("fwagent.dynamic.surface", level="WARNING") as logs:
                    entries = self.builder._network_callers_from_ghidra()
                self.assertEqual([entry.service for entry in entries], [expected])
                self.assert_diagnostic(filename, "")
                self.assertIn(filename, "\n".join(logs.output))
                entry, = entries
                self.assertEqual(entry.evidence_level, "api_symbol_observed")
                self.assertEqual(entry.classification_status, "unconfirmed")
                self.assertEqual(entry.exposure_scope, "unknown")
                self.assertFalse(entry.runtime_confirmed)
                self.assertIsNone(entry.protocol)

    def test_summary_missing_json_encoding_and_top_level_failures(self):
        self.check_bad_file("analysis_summary.json")
        self.write("analysis_summary.json", [])
        self.builder._network_callers_from_ghidra()
        self.assert_diagnostic("analysis_summary.json", "")

    def test_evidence_missing_json_encoding_and_top_level_failures(self):
        self.check_bad_file("evidence.json")

    def test_both_files_unreadable_are_unknown_not_verified_empty(self):
        original = Path.read_text
        for error in (PermissionError("fixture denied"), OSError("fixture read failed")):
            with self.subTest(error=type(error).__name__):
                def read(path, *args, **kwargs):
                    if path.parent.name == "ghidra":
                        raise error
                    return original(path, *args, **kwargs)
                with patch.object(Path, "read_text", read):
                    self.assertEqual(self.builder._network_callers_from_ghidra(), [])
                self.assertEqual(self.builder._ghidra_input_status["status"], "unknown")
                self.assertEqual(len(self.builder._ghidra_input_status["diagnostics"]), 2)
                self.assertTrue(all(type(error).__name__ in item["reason"] for item in self.builder._ghidra_input_status["diagnostics"]))

    def test_collection_shapes_are_validated_for_both_files(self):
        for filename, key in (("analysis_summary.json", "analyses"), ("evidence.json", "evidence")):
            for value in (None, False, 12, "wrong", {}, {"0": self.analysis()}):
                with self.subTest(filename=filename, value=value):
                    self.write(filename, {key: value})
                    self.assertEqual(self.builder._network_callers_from_ghidra(), [])
                    self.assert_diagnostic(filename, "/" + key)
            self.write(filename, {})
            self.builder._network_callers_from_ghidra()
            self.assert_diagnostic(filename, "/" + key)
            self.write(filename, {key: []})

    def test_bad_analyses_and_nested_fields_do_not_drop_valid_records(self):
        bad = [None, False, 3, "wrong", [], {}, {"binary": ["/bad"]}, {"binary": "/"}]
        for result in (None, False, 3, "wrong", [], {}, {"imports": None}, {"imports": {}}, {"imports": "recv"}):
            bad.append({"binary": "/lib/bad.so", "result": result})
        self.write("analysis_summary.json", {"analyses": [self.analysis("/first"), *bad, self.analysis("/last")]})
        entries = self.builder._network_callers_from_ghidra()
        self.assertEqual([entry.service for entry in entries], ["first", "last"])
        self.assertEqual(len(self.builder._ghidra_input_status["diagnostics"]), len(bad))
        self.assert_diagnostic("analysis_summary.json", "/analyses/1")
        self.assertEqual(entries[-1].api_matches[0]["json_pointer"], f"/analyses/{len(bad) + 1}/result/imports/0")

    def test_bad_imports_preserve_other_exact_symbols(self):
        self.write("analysis_summary.json", {"analyses": [self.analysis(imports=[
            {"name": "recvfrom"}, None, "recv", {"name": ["socket"]}, {}, {"name": ""},
            {"name": "pthread_mutex_lock"}, {"name": "fread"}, {"name": "readdir64"}, {"name": "socket"},
        ])]})
        entry, = self.builder._network_callers_from_ghidra()
        self.assertEqual([item["api"] for item in entry.api_matches], ["recvfrom", "socket"])
        self.assert_diagnostic("analysis_summary.json", "/analyses/0/result/imports/1")

    def test_bad_evidence_records_preserve_siblings_and_wrapped_pointers(self):
        bad = [None, False, 2, "wrong", [], {}, {"metadata": []}, {"metadata": {"binary": []}},
               self.evidence(symbol=["recv"]), self.evidence(evidence_id=[]), self.evidence(binary="/")]
        for wrapped in (False, True):
            with self.subTest(wrapped=wrapped):
                records = [self.evidence("/first"), *bad, self.evidence("/last")]
                self.write("evidence.json", {"evidence": records} if wrapped else records)
                entries = self.builder._network_callers_from_ghidra()
                self.assertEqual([entry.service for entry in entries], ["first", "last"])
                prefix = "/evidence" if wrapped else ""
                self.assert_diagnostic("evidence.json", prefix + "/1")
                self.assertEqual(entries[0].api_matches[0]["json_pointer"], prefix + "/0/metadata")

    def test_summary_failure_does_not_make_id_only_records_network_evidence(self):
        (self.workspace.task_dir / "ghidra/analysis_summary.json").write_text("{", encoding="utf-8")
        records = [self.evidence("/id-only", symbol="", evidence_id="SE-GHIDRA-id-only-recvfrom")]
        records.extend(self.evidence("/" + symbol, symbol=symbol) for symbol in ("pthread_mutex_lock", "fread", "readdir64"))
        self.write("evidence.json", records)
        self.assertEqual(self.builder._network_callers_from_ghidra(), [])
        self.assert_diagnostic("analysis_summary.json")
        self.assert_diagnostic("evidence.json", "/0/metadata")

    def test_incomplete_imports_allow_explicit_fallback_without_promotion(self):
        self.write("analysis_summary.json", {"analyses": [{"binary": "/lib/fallback.so", "result": None}]})
        self.write("evidence.json", [self.evidence()])
        entry, = self.builder._network_callers_from_ghidra()
        self.assertEqual(entry.evidence_level, "api_symbol_observed")
        self.assertFalse(entry.runtime_confirmed)
        self.assertIsNone(entry.transport)
        self.assertEqual(entry.api_matches[0]["artifact"], "ghidra/evidence.json")

    def test_valid_summary_keeps_precedence_over_fallback(self):
        self.write("analysis_summary.json", {"analyses": [self.analysis("/lib/fallback.so", imports=[{"name": "fread"}])]})
        self.write("evidence.json", [self.evidence()])
        self.assertEqual(self.builder._network_callers_from_ghidra(), [])
        self.assertEqual(self.builder._ghidra_input_status["status"], "complete")

    def test_old_candidates_survive_missing_or_incomplete_imports_idempotently(self):
        old = {"entry_id": "EP-BINARY-legacy", "service": "legacy", "entry_type": "tcp_service", "evidence_ids": ["OLD"]}
        for analyses in (None, [], [None], [{"binary": "/legacy", "result": None}],
                         [self.analysis("/legacy", imports=[None])],
                         [self.analysis("/legacy", imports=[]), {"binary": "/legacy", "result": None}]):
            with self.subTest(analyses=analyses):
                self.write("analysis_summary.json", {"analyses": analyses})
                self.workspace.save_surface_artifact("entry_points.json", [old])
                first, = self.builder._network_callers_from_ghidra()
                self.workspace.save_surface_artifact("entry_points.json", [first.to_dict()])
                second, = self.builder._network_callers_from_ghidra()
                self.assertEqual(first.evidence_details, second.evidence_details)
                self.assertEqual(second.entry_id, old["entry_id"])
                self.assertEqual(second.evidence_ids, ["OLD"])
                self.assertEqual(second.entry_type, "binary_candidate")
                self.assertEqual(second.evidence_level, "heuristic_only")
                self.assertEqual(second.classification_status, "unconfirmed")
                self.assertEqual(second.api_matches, [])
                self.assertIn("unverified", second.unresolved_reason)

    def test_file_failures_retain_legacy_candidate_and_valid_candidate(self):
        old = {"entry_id": "EP-BINARY-legacy", "service": "legacy", "evidence_ids": ["OLD"]}
        self.workspace.save_surface_artifact("entry_points.json", [old])
        self.write("evidence.json", [self.evidence()])
        path = self.workspace.task_dir / "ghidra/analysis_summary.json"
        for content in (None, b"{", b"null"):
            with self.subTest(content=content):
                if content is None:
                    path.unlink(missing_ok=True)
                else:
                    path.write_bytes(content)
                entries = {entry.service: entry for entry in self.builder._network_callers_from_ghidra()}
                self.assertEqual(set(entries), {"legacy", "fallback.so"})
                self.assertEqual(entries["legacy"].classification_status, "unconfirmed")
                self.assertEqual(entries["fallback.so"].evidence_level, "api_symbol_observed")

    def test_build_persists_unknown_inputs_even_without_candidates(self):
        for filename in ("analysis_summary.json", "evidence.json"):
            (self.workspace.task_dir / "ghidra" / filename).unlink()
        with patch.object(self.builder, "_discover_entries", return_value=[]), patch.object(self.builder, "_load_report", return_value={}):
            payload = self.builder.build()
        self.assertTrue(payload["success"])
        self.assertEqual(payload["entry_points"], [])
        status = payload["summary"]["ghidra_input_status"]
        self.assertEqual(status["status"], "unknown")
        self.assertEqual(len(status["diagnostics"]), 2)
        for artifact in ("attack_surface_summary.json", "attack_surface_map.json"):
            saved = self.workspace.load_surface_artifact(artifact)
            self.assertEqual((saved.get("summary") or saved)["ghidra_input_status"], status)
        self.assertEqual(self.builder.load_or_build()["summary"]["ghidra_input_status"], status)

    def test_unexpected_programming_errors_are_not_swallowed(self):
        self.write("analysis_summary.json", {"analyses": [self.analysis()]})
        with patch("fwagent.dynamic.surface._network_api", side_effect=RuntimeError("programming defect")):
            with self.assertRaisesRegex(RuntimeError, "programming defect"):
                self.builder._network_callers_from_ghidra()


if __name__ == "__main__":
    unittest.main()
