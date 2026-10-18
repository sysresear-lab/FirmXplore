from __future__ import annotations

import json
import hashlib
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from fwagent.pipeline.product import AnalysisPipelineController
from fwagent.pipeline.product import PipelineStageResult, V01_PIPELINE_STAGES
from fwagent.runtime.ghidra import EXPORT_SCRIPTS, ExportValidationError, GhidraRuntime
from fwagent.tools.ghidra_api import BinaryToolAPI
from fwagent.config import GhidraSettings, Round2Config
from fwagent.models import CommandResult
from tests.unit.test_v01_integration import FakeGhidraAPI, base_report, write_json


def export_files(output, binary):
    payload = {key: [] for key in EXPORT_SCRIPTS}
    payload["summary"] = {"function_count": 0, "sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                          "language": "ARM:LE:32:v7", "analysis_timed_out": False}
    for key, (_, name) in EXPORT_SCRIPTS.items():
        write_json(output / name, payload[key])
    return payload


class GhidraBatchTests(unittest.TestCase):
    def test_required_exports_and_valid_empty_results(self):
        cases = ("valid_empty", "missing_functions", "bad_json", "wrong_schema", "count_mismatch", "wrong_target", "internal_timeout")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                binary = root / "binary"
                binary.write_bytes(b"\x7fELF" + b"\0" * 60)
                runtime = GhidraRuntime(root / "workspace", settings=GhidraSettings(home=root / "missing"))
                output = runtime.output_dir / "controlled"
                export_files(output, binary)
                if case == "missing_functions":
                    (output / "functions.json").unlink()  # only a temporary synthetic export
                elif case == "bad_json":
                    (output / "functions.json").write_text("{")
                elif case == "wrong_schema":
                    write_json(output / "strings.json", {})
                elif case in {"count_mismatch", "wrong_target", "internal_timeout"}:
                    summary = json.loads((output / "summary.json").read_text())
                    field, value = {"count_mismatch": ("function_count", 1), "wrong_target": ("sha256", "0" * 64), "internal_timeout": ("analysis_timed_out", True)}[case]
                    summary[field] = value
                    write_json(output / "summary.json", summary)
                command_result = CommandResult([], 0, "", "", 0.01)
                result = runtime._finish_export(binary, output, command_result, time.monotonic(), backend="host_ghidra", image=None)
                self.assertEqual(result.success, case == "valid_empty")
                if case != "valid_empty":
                    expected = {"missing_functions": "GHIDRA_OUTPUT_MISSING", "bad_json": "GHIDRA_JSON_INVALID", "wrong_schema": "GHIDRA_OUTPUT_INVALID", "count_mismatch": "GHIDRA_OUTPUT_INVALID", "wrong_target": "GHIDRA_TARGET_MISMATCH", "internal_timeout": "GHIDRA_TIMEOUT"}[case]
                    self.assertEqual(result.result["metadata"]["error_code"], expected)

    def test_command_failure_and_timeout_are_not_missing_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            runtime = GhidraRuntime(root)
            binary = root / "binary"
            binary.write_bytes(b"controlled")
            for command, code in ((CommandResult([], 1, "", "controlled error", 0.1), "GHIDRA_ANALYSIS_FAILED"), (CommandResult([], None, "", "", 0.1, timed_out=True), "GHIDRA_TIMEOUT")):
                result = runtime._finish_export(binary, root / "no-output", command, time.monotonic(), backend="host_ghidra", image=None)
                self.assertFalse(result.success)
                self.assertEqual(result.result["metadata"]["error_code"], code)

    def test_real_api_parse_failure_then_valid_second_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            task = base / "new"
            write_json(task / "reports/analysis.json", base_report())
            api = BinaryToolAPI(task, config=Round2Config(ghidra=GhidraSettings(home=base / "missing")))
            targets = []
            for name in ("first", "second"):
                binary = task / name
                binary.write_bytes(b"\x7fELF" + name.encode())
                output = api.runtime.output_dir / name
                export_files(output, binary)
                if name == "first":
                    (output / "functions.json").write_text("{")
                targets.append({"path": "/" + name, "host_path": str(binary), "exists": True})
            api.runtime.check_environment = lambda: {"success": True}
            api.runtime.ghidra_version = lambda: "controlled"
            api.runtime._project_name = lambda binary: binary.name
            api.runtime.build_export_command = lambda *args: ["controlled-no-tool"]
            with patch.object(api.runtime.runner, "run", return_value=CommandResult([], 0, "", "", 0.01)), patch("fwagent.pipeline.product.BinaryToolAPI", return_value=api):
                summary = AnalysisPipelineController(base)._run_ghidra_stage("new", targets)
            self.assertEqual(summary["real_completed"], 1)
            self.assertEqual(summary["items_failed"], 1)
            self.assertEqual(summary["analyses"][0]["error_code"], "GHIDRA_JSON_INVALID")
            self.assertTrue(summary["analyses"][1]["success"])
            self.assertFalse(summary["success"])

    def test_bad_cache_remains_failure_and_is_not_deleted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / "binary"
            binary.write_bytes(b"\x7fELF")
            api = BinaryToolAPI(root / "workspace", config=Round2Config(ghidra=GhidraSettings(home=root / "missing")))
            cache = api._cache_path(binary)
            cache.write_text("{")
            result = api.analyze_binary(binary)
            self.assertFalse(result["success"])
            self.assertEqual(result["result"]["metadata"]["error_code"], "GHIDRA_CACHE_INVALID")
            self.assertEqual(cache.read_text(), "{")

    def test_generic_failure_cannot_default_to_completed(self):
        with tempfile.TemporaryDirectory() as tmp:
            controller = AnalysisPipelineController(tmp)
            for value in ({"success": False}, {"success": False, "stage_status": "completed"}, {"success": False, "blocking_reason": "not available"}):
                stages = {name: PipelineStageResult(name) for name in V01_PIPELINE_STAGES}
                controller._run_stage(stages, "GHIDRA_ANALYSIS", {}, lambda: value, False, "controlled")
                self.assertNotEqual(stages["GHIDRA_ANALYSIS"].status, "completed")

    def test_explicit_failure_counts_are_not_double_counted_as_skips(self):
        with tempfile.TemporaryDirectory() as tmp:
            controller = AnalysisPipelineController(tmp)
            stages = {name: PipelineStageResult(name) for name in V01_PIPELINE_STAGES}
            value = {"success": False, "stage_status": "blocked", "items_processed": 2,
                     "items_succeeded": 0, "items_failed": 2, "items_skipped": 0}
            controller._run_stage(stages, "GHIDRA_ANALYSIS", {}, lambda: value, False, "controlled")
            result = stages["GHIDRA_ANALYSIS"]
            self.assertEqual(result.items_failed, 2)
            self.assertEqual(result.items_skipped, 0)
            self.assertEqual(result.items_succeeded + result.items_failed + result.items_skipped, result.items_processed)

    def test_all_targets_failed_is_not_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_json(root / "new/reports/analysis.json", base_report())
            with patch("fwagent.pipeline.product.BinaryToolAPI", return_value=FakeGhidraAPI("failed")):
                result = AnalysisPipelineController(root)._run_ghidra_stage("new", [{"path": "/a", "host_path": "a", "exists": True}])
            self.assertFalse(result["success"])
            self.assertEqual(result["items_failed"], 1)
            self.assertTrue(result["execution_completed"])
    def test_corrupt_first_target_does_not_drop_second(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            task = base / "new-task"
            write_json(task / "reports/analysis.json", base_report())
            api = FakeGhidraAPI("real")
            real_call = api.analyze_binary

            def run(binary, **kwargs):
                if binary == "first":
                    raise json.JSONDecodeError("partial functions export", "{", 1)
                return real_call(binary, **kwargs)

            api.analyze_binary = run
            with patch("fwagent.pipeline.product.BinaryToolAPI", return_value=api):
                summary = AnalysisPipelineController(base)._run_ghidra_stage("new-task", [
                    {"path": "/usr/sbin/dnsmasq", "host_path": "first", "exists": True},
                    {"path": "/usr/sbin/uhttpd", "host_path": "second", "exists": True},
                ])
            self.assertEqual(summary["real_completed"], 1)
            self.assertEqual(summary["failed_binary_count"], 1)
            self.assertEqual(summary["stage_status"], "partial")
            self.assertEqual(summary["analyses"][0]["error_code"], "GHIDRA_JSON_INVALID")
            self.assertTrue(summary["analyses"][1]["success"])
            for record in summary["analyses"]:
                self.assertTrue(record["started_at"])
                self.assertTrue(record["finished_at"])
                self.assertGreaterEqual(record["duration"], 0)
            checkpoint = json.loads((task / "ghidra/target_status.json").read_text())
            self.assertTrue(checkpoint["batch_complete"])
            self.assertEqual(len(checkpoint["analyses"]), 2)
            self.assertEqual([item["status"] for item in checkpoint["analyses"]], ["failed", "completed"])

    def test_timeout_and_missing_target_are_distinct(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            write_json(base / "new/reports/analysis.json", base_report())
            with patch("fwagent.pipeline.product.BinaryToolAPI") as factory:
                factory.return_value.analyze_binary.side_effect = TimeoutError("controlled timeout")
                result = AnalysisPipelineController(base)._run_ghidra_stage("new", [
                    {"path": "/a", "host_path": "a", "exists": True},
                    {"path": "/missing", "exists": False},
                ])
            self.assertEqual(result["analyses"][0]["execution_status"], "timed_out")
            self.assertEqual(result["analyses"][1]["execution_status"], "skipped")
            self.assertEqual(result["items_failed"], 1)
            self.assertEqual(result["items_skipped"], 1)
            self.assertFalse(result["success"])


if __name__ == "__main__":
    unittest.main()
