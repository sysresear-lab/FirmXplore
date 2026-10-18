"""Offline regressions: saved JSON is input only; all generators write to temp."""
from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fwagent.dynamic.config import DynamicConfig
from fwagent.dynamic.correlation import ComponentGraph, FirmwareComponent
from fwagent.dynamic.surface import AttackSurfaceBuilder, EntryPoint, _network_api
from fwagent.dynamic.surface_contract import surface_counts, surface_summary
from fwagent.dynamic.workspace import DynamicWorkspace
from fwagent.pipeline.product import AnalysisPipelineController, PipelineStageResult, V01_PIPELINE_STAGES, _items_processed
from fwagent.reporting.final_report import ReportGenerator

ROOT = Path(__file__).resolve().parents[2]
SNAPSHOT = ROOT / "docs/diagnostics/phase3-20261016T173500Z-c02c78/task"
AUDIT = ROOT / "docs/diagnostics/phase4-20261016T181745Z-6e5429"


class SurfaceContractTests(unittest.TestCase):
    def test_legacy_numeric_keys(self):
        for key in ("total_entries", "entry_points", "total_entry_points", "candidate_entries_total"):
            with self.subTest(key=key):
                counts = surface_counts({key: 27, "runtime_confirmed_entries": 0})
                self.assertEqual(counts["candidate_entries_total"], 27)
                self.assertEqual(counts["runtime_confirmed_entries"], 0)
                self.assertEqual(counts["count_status"], "summary_only")
                self.assertIsNone(counts["api_inferred_candidates"])

    def test_empty_is_different_from_missing(self):
        self.assertIsNone(surface_counts()["candidate_entries_total"])
        self.assertEqual(surface_counts(entries=[])["candidate_entries_total"], 0)
        self.assertEqual(surface_counts(entries=[])["runtime_confirmed_entries"], 0)
        self.assertIsNone(surface_counts({"total_entries": "27"})["candidate_entries_total"])
        self.assertIsNone(surface_counts({"total_entries": True})["candidate_entries_total"])

    def test_unknown_level_and_missing_flags_are_not_promoted(self):
        entries = [{"evidence_level": "future_level"}, {}]
        counts = surface_counts(entries=entries)
        self.assertEqual(counts["unknown_evidence_candidates"], 2)
        self.assertEqual(counts["runtime_confirmed_entries"], 0)
        self.assertEqual(counts["api_inferred_candidates"], 0)
        with self.assertRaises(ValueError):
            EntryPoint("X", "cgi", "test", evidence_level="future_level")

    def test_list_wins_but_conflicting_declaration_is_preserved(self):
        summary = surface_summary({"total_entries": 0, "entry_points": 8}, [{}, {}])
        self.assertEqual(summary["candidate_entries_total"], 2)
        self.assertEqual(summary["total_entries"], 0)
        self.assertEqual(summary["entry_points"], 8)
        self.assertEqual(summary["count_disagreements"], {"total_entries": 0, "entry_points": 8})
        self.assertEqual(surface_counts({"api_inferred_candidates": 9}, [{}])["count_disagreements"], {"api_inferred_candidates": 9})

    def test_network_symbol_matching(self):
        for name in ("pthread_setspecific", "pthread_mutex_lock", "fread", "readdir64", "read", "select", "myrecvfrom", "socketpair", "Recv"):
            with self.subTest(name=name):
                self.assertIsNone(_network_api(name))
        for name in ("recv", "recvfrom", "recvmsg", "accept", "listen", "bind", "socket"):
            self.assertEqual(_network_api(name), name)
        self.assertEqual(_network_api("recvfrom@@GLIBC_2.0"), "recvfrom")
        self.assertEqual(_network_api("__libc_recvfrom"), "recvfrom")

    def test_runtime_level_requires_explicit_runtime_flag(self):
        with self.assertRaises(ValueError):
            EntryPoint("R", "service_port", "test", evidence_level="runtime_confirmed")
        entry = EntryPoint("R", "service_port", "test", runtime_confirmed=True)
        self.assertEqual(entry.evidence_level, "runtime_confirmed")
        self.assertEqual(surface_counts(entries=[entry.to_dict()])["runtime_confirmed_entries"], 1)


class SurfaceGenerationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.workspace = DynamicWorkspace(self.root, "offline-fixture")
        self.task = self.workspace.task_dir
        self.builder = AttackSurfaceBuilder.__new__(AttackSurfaceBuilder)
        self.builder.workspace = self.workspace
        self.builder.config = DynamicConfig()
        self.builder.graph = ComponentGraph()
        self.controller = AnalysisPipelineController(self.root, config=DynamicConfig())

    def write(self, relative, value):
        path = self.task / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")

    def network_fixture(self, names):
        self.write("ghidra/analysis_summary.json", {"analyses": [{"binary": "/lib/test.so", "result": {"imports": [{"name": name} for name in names]}}]})

    def test_thread_and_file_symbols_do_not_create_network_candidates(self):
        self.network_fixture(["pthread_setspecific", "pthread_mutex_lock", "fread", "readdir64"])
        self.assertEqual(self.builder._network_callers_from_ghidra(), [])

    def test_exact_api_has_reference_but_no_tcp_claim(self):
        self.network_fixture(["recvfrom", "socket", "read"])
        entry, = self.builder._network_callers_from_ghidra()
        self.assertEqual(entry.entry_type, "network_capability_candidate")
        self.assertEqual(entry.evidence_level, "api_symbol_observed")
        self.assertEqual({item["api"] for item in entry.api_matches}, {"recvfrom", "socket"})
        self.assertEqual(entry.api_matches[0]["json_pointer"], "/analyses/0/result/imports/0")
        self.assertIsNone(entry.protocol)
        self.assertIsNone(entry.transport)
        self.assertIsNone(entry.port)
        self.assertIsNone(entry.authentication_known)
        self.assertEqual(entry.exposure_scope, "unknown")
        self.assertFalse(entry.runtime_confirmed)

    def test_fallback_requires_symbol_metadata_not_id_substring(self):
        self.write("ghidra/evidence.json", [
            {"id": "SE-GHIDRA-test-pthread_mutex_lock", "metadata": {"binary": "/test"}},
            {"id": "E-recv", "metadata": {"binary": "/lib/valid.so", "function": "recv"}},
        ])
        entries = self.builder._network_callers_from_ghidra()
        self.assertEqual([item.service for item in entries], ["valid.so"])
        self.assertEqual(entries[0].api_matches[0]["artifact"], "ghidra/evidence.json")

    def historical_fixture(self):
        # Copy saved JSON only. Never construct a builder/generator in SNAPSHOT.
        for name in ("ghidra/analysis_summary.json", "surface/entry_points.json"):
            self.write(name, json.loads((SNAPSHOT / name).read_text(encoding="utf-8")))
        graph = json.loads((SNAPSHOT / "correlation/component_graph.json").read_text(encoding="utf-8"))
        for item in graph["components"]:
            self.builder.graph.add_component(FirmwareComponent(**item))
        metadata = json.loads((AUDIT / "entry_file_metadata.json").read_text(encoding="utf-8"))
        rootfs = self.task / "synthetic-rootfs"
        aliases = {}
        for item in metadata:
            path = rootfs / item["rootfs_path"].lstrip("/")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"synthetic placeholder; never execute")
            if item["type"] == "symlink":
                aliases[path] = item["link_target"]
        original = Path.lstat

        def lstat(path):
            return SimpleNamespace(st_mode=stat.S_IFLNK | 0o777) if path in aliases else original(path)

        # OS-independent metadata fixture based on the saved Linux probe.
        with patch.object(Path, "lstat", lstat), patch("fwagent.dynamic.surface.os.readlink", side_effect=lambda path: aliases[path]), patch("fwagent.dynamic.surface.read_prefix", side_effect=AssertionError("CGI content must not be read")):
            web = self.builder._web_route_entries(rootfs)
        entries = web + self.builder._network_callers_from_ghidra()
        return entries, aliases

    def test_historical_27_objects_and_evidence_breakdown(self):
        entries, _ = self.historical_fixture()
        counts = surface_counts(entries=[item.to_dict() for item in entries], routes=[])
        for key, expected in {"candidate_entries_total": 27, "file_or_symlink_candidates": 15, "api_inferred_candidates": 11, "heuristic_candidates": 1, "runtime_confirmed_entries": 0, "route_mappings_total": 0, "http_route_candidates": 14}.items():
            self.assertEqual(counts[key], expected, key)
        old = json.loads((SNAPSHOT / "surface/entry_points.json").read_text(encoding="utf-8"))
        self.assertEqual({item.entry_id for item in entries}, {item["entry_id"] for item in old})
        self.assertFalse(any(item.entry_type == "tcp_service" for item in entries))
        libgcc = next(item for item in entries if item.service == "libgcc_s.so.1")
        self.assertEqual(libgcc.entry_type, "binary_candidate")
        self.assertEqual(libgcc.classification_status, "unsupported")
        self.assertEqual(libgcc.api_matches, [])
        self.assertEqual(libgcc.evidence_details["previous_entry"]["entry_type"], "tcp_service")

    def test_new_summary_coverage_and_reports_share_all_counts(self):
        entries, _ = self.historical_fixture()
        summary = self.builder._summarize(entries, [], [], []).to_dict()
        self.assertEqual(summary["candidate_entries_total"], 27)
        self.assertEqual(summary["total_entries"], 27)
        self.write("surface/entry_points.json", [item.to_dict() for item in entries])
        self.write("surface/attack_surface_summary.json", summary)
        self.write("surface/routes.json", [])
        generator = ReportGenerator(self.root, self.workspace.task_id)
        model = generator.build_model()
        payload = json.loads(generator.generate_json(model).read_text(encoding="utf-8"))
        for key in ("candidate_entries_total", "file_or_symlink_candidates", "api_inferred_candidates", "heuristic_candidates", "runtime_confirmed_entries"):
            self.assertEqual(payload["attack_surface"]["summary"][key], summary[key])
            self.assertEqual(payload["coverage"][key], summary[key])
        md = generator.generate_markdown(model).read_text(encoding="utf-8")
        html = generator.generate_html(model).read_text(encoding="utf-8")
        for label, value in (("Candidate entries", 27), ("Runtime confirmed entries", 0), ("File/symlink candidates", 15), ("API inferred candidates", 11), ("Heuristic candidates", 1), ("Route mappings", 0), ("Static http_route candidates", 14)):
            self.assertIn(f"{label}: `{value}`", md)
            self.assertIn(f"{label}: <code>{value}</code>", html)
        for entry in entries:
            self.assertIn(entry.entry_id, md)
            self.assertIn(entry.entry_id, html)

    def test_removed_network_classification_is_idempotently_retained(self):
        self.network_fixture(["pthread_mutex_lock"])
        previous = {"entry_id": "EP-BINARY-test-so", "entry_type": "tcp_service", "service": "test.so", "evidence_ids": ["OLD"]}
        self.write("surface/entry_points.json", [previous])
        first = self.builder._network_callers_from_ghidra()[0]
        self.write("surface/entry_points.json", [first.to_dict()])
        second = self.builder._network_callers_from_ghidra()[0]
        self.assertEqual(first.evidence_details, second.evidence_details)
        self.assertEqual(second.entry_id, previous["entry_id"])
        self.assertEqual(second.evidence_ids, ["OLD"])

    def test_all_14_cgi_aliases_retained_without_dispatch_assertion(self):
        entries, aliases = self.historical_fixture()
        scripts = [item for item in entries if item.symlink_target]
        self.assertEqual(len(scripts), 14)
        self.assertEqual(len(aliases), 14)
        self.assertEqual({item.candidate_file_entity for item in scripts}, {"/htdocs/cgibin"})
        self.assertEqual({item.candidate_handler_component_id for item in scripts}, {"C-BINARY-htdocs-cgibin"})
        for item in scripts:
            self.assertEqual(item.symlink_target, "/htdocs/cgibin")
            self.assertIsNone(item.url_path)
            self.assertIsNone(item.component_id)
            self.assertIsNone(item.handler_component_id)
            self.assertFalse(item.handler_dispatch_confirmed)
        seama = next(item for item in scripts if item.filesystem_path.endswith("seama.cgi"))
        self.assertIn("unconfirmed", seama.unresolved_reason)
        self.assertEqual(self.builder._resolve_route_component(Path("seama.cgi"), "htdocs/web/seama.cgi", {}), (None, None))

    def test_file_input_descriptions_do_not_claim_http_urls_or_known_exposure(self):
        entries, _ = self.historical_fixture()
        inputs = self.builder._describe_inputs(entries)
        file_inputs = [item for item in inputs if item.source_type in {"cgi", "http_route"}]
        self.assertEqual(len(file_inputs), 15)
        for item in file_inputs:
            self.assertIn("URL mapping and handler dispatch unconfirmed", item.description)
            self.assertNotIn("on TCP", item.description)
            self.assertIsNone(item.network_exposed)

    def test_file_or_api_identity_does_not_prove_entry_reachability(self):
        entries, _ = self.historical_fixture()
        reachability = self.builder._build_reachability(entries)
        self.assertEqual(len(reachability), 27)
        self.assertTrue(all(item.state in {"candidate", "entry_unknown"} for item in reachability))
        self.assertFalse(any(item.runtime_confirmed for item in reachability))

    def test_metadata_only_special_reparse_permission_semantics(self):
        rootfs = self.task
        path = rootfs / "test.cgi"
        for mode, kind in ((stat.S_IFIFO, "special"), (stat.S_IFCHR, "special"), (stat.S_IFSOCK, "special"), (stat.S_IFDIR, "special")):
            with patch.object(Path, "lstat", return_value=SimpleNamespace(st_mode=mode)), patch("builtins.open", side_effect=AssertionError("content read")):
                facts = self.builder._route_file_facts(path, rootfs)
            self.assertEqual(facts["file_kind"], kind)
            self.assertIsNone(facts["candidate_file_entity"])
        with patch.object(Path, "lstat", return_value=SimpleNamespace(st_mode=stat.S_IFREG, st_file_attributes=0x400)):
            self.assertEqual(self.builder._route_file_facts(path, rootfs)["file_kind"], "reparse_point")
        with patch.object(Path, "lstat", side_effect=PermissionError("denied")):
            self.assertIn("PermissionError", self.builder._route_file_facts(path, rootfs)["error"])

    @unittest.skipUnless(os.name == "posix", "requires POSIX temporary symlinks/FIFO")
    def test_real_temporary_symlink_and_fifo_metadata_only(self):
        target = self.task / "cgibin"
        target.write_bytes(b"ordinary placeholder")
        link = self.task / "alias.cgi"
        link.symlink_to("/cgibin")
        fifo = self.task / "fifo.cgi"
        os.mkfifo(fifo)
        with patch("builtins.open", side_effect=AssertionError("content read")):
            self.assertEqual(self.builder._route_file_facts(link, self.task)["candidate_file_entity"], "/cgibin")
            self.assertEqual(self.builder._route_file_facts(fifo, self.task)["file_kind"], "special")

    def test_processed_known_empty_unknown_and_not_executed(self):
        for payload, expected, status in (({"entry_points": [{}] * 27}, 27, "observed_list"), ({"entry_points": []}, 0, "observed_list"), ({"success": True}, None, "unknown")):
            stages = {"ATTACK_SURFACE": PipelineStageResult("ATTACK_SURFACE")}
            self.controller._run_stage(stages, "ATTACK_SURFACE", {}, lambda: payload, False, "fixture")
            self.assertEqual(stages["ATTACK_SURFACE"].items_processed, expected)
            self.assertEqual(stages["ATTACK_SURFACE"].item_count_status, status)
        stage = PipelineStageResult("ATTACK_SURFACE")
        self.assertIsNone(stage.items_processed)
        self.assertEqual(stage.item_count_status, "not_executed")
        self.assertEqual(_items_processed({"summary": {"total_entries": 27}}), 27)

    def test_saved_legacy_list_coverage_and_all_report_formats(self):
        entries = json.loads((SNAPSHOT / "surface/entry_points.json").read_text(encoding="utf-8"))
        summary = json.loads((SNAPSHOT / "surface/attack_surface_summary.json").read_text(encoding="utf-8"))
        self.write("surface/entry_points.json", entries)
        self.write("surface/attack_surface_summary.json", summary)
        self.write("surface/routes.json", [])
        stages = {name: PipelineStageResult(name) for name in V01_PIPELINE_STAGES}
        coverage = self.controller._coverage_metrics(self.workspace.task_id, stages)
        self.assertEqual(coverage["surface_entries"], 27)
        self.assertEqual(coverage["runtime_confirmed_entries"], 0)
        self.write("pipeline_stages.json", {"coverage": {"surface_entries": 0}, "stages": [{"stage": "ATTACK_SURFACE", "status": "completed", "items_processed": 0}]})
        generator = ReportGenerator(self.root, self.workspace.task_id)
        model = generator.build_model()
        self.assertEqual(model.coverage["surface_entries"], 27)
        self.assertEqual(model.pipeline_stages[0]["items_processed"], 27)
        self.assertEqual(model.pipeline_stages[0]["original_items_processed"], 0)
        self.assertEqual(model.attack_surface_summary["unknown_evidence_candidates"], 27)
        for path in (generator.generate_markdown(model), generator.generate_html(model)):
            text = path.read_text(encoding="utf-8")
            self.assertIn("Candidate entries", text)
            self.assertIn("Runtime confirmed entries", text)
            self.assertIn("27", text)
            self.assertIn("not establish reachable services", text)
        payload = json.loads(generator.generate_json(model).read_text(encoding="utf-8"))
        self.assertEqual(len(payload["attack_surface"]["entries"]), 27)
        self.assertEqual(payload["attack_surface"]["summary"]["candidate_entries_total"], 27)
        self.assertEqual(payload["attack_surface"]["summary"]["runtime_confirmed_entries"], 0)
        self.assertEqual(payload["attack_surface"]["summary"]["route_mappings_total"], 0)
        self.assertEqual(payload["attack_surface"]["summary"]["http_route_candidates"], 14)

    def test_missing_surface_report_is_unknown_not_empty_success(self):
        generator = ReportGenerator(self.root, self.workspace.task_id)
        model = generator.build_model()
        self.assertIsNone(model.attack_surface_summary["candidate_entries_total"])
        self.assertIn("Candidate entries: `unknown`", generator.generate_markdown(model).read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
