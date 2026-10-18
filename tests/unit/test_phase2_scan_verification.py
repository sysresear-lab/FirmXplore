from __future__ import annotations

import json
import multiprocessing
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from fwagent.pipeline.product import AnalysisPipelineController, AnalysisTask
from fwagent.runtime.scanning import ScanWorkerError, _scan_child, process_token, recover_interrupted_scan, run_bounded_scan, scan_budget
from fwagent.dynamic.application import _collect_lighttpd_config
from fwagent.dynamic.surface import AttackSurfaceBuilder
from fwagent.tools.architecture import parse_elf_header
from fwagent.tools.common import read_prefix
from fwagent.tools.ghidra_api import BinaryToolAPI
from tests.unit.test_scan_safety import _block_with_child, _pid_running


def exit_abnormally():
    os._exit(9)


def scan_parent(base):
    base = Path(base)
    controller = AnalysisPipelineController(base.parent)
    task = AnalysisTask(base.name, "controlled.bin", "0" * 64, "controlled.bin", str(base), status="running", pipeline_phase="static_analysis")
    controller._save_task(task)
    (base / "state.json").write_text('{"status":"created"}')
    with scan_budget(20, event_path=base / "scan_events.jsonl"):
        run_bounded_scan("blocking", _block_with_child, str(base / "pids.json"))


class Phase2ScanVerificationTests(unittest.TestCase):
    def test_unreleased_start_gate_has_a_hard_deadline(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "never-written.pickle"
            ctx = multiprocessing.get_context("spawn")
            gate = ctx.Event()  # Keep the POSIX semaphore alive until spawn has attached.
            process = ctx.Process(target=_scan_child, args=(exit_abnormally, (), {}, str(output), time.monotonic() + 0.5, None, gate, os.getpid(), process_token(os.getpid())))
            process.start()
            try:
                process.join(3)
                self.assertFalse(process.is_alive(), "closed gate left an orphan worker")
                self.assertEqual(process.exitcode, 0, "callback must not run before gate release")
                self.assertFalse(output.exists())
            finally:
                if process.is_alive():
                    process.kill()
                    process.join(3)
                process.close()

    def test_corrupt_elf_is_not_a_normal_empty_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "truncated"
            path.write_bytes(b"\x7fELF")
            self.assertEqual(read_prefix(path), b"\x7fELF")
            with self.assertRaisesRegex(ValueError, "truncated ELF"):
                parse_elf_header(path)

    def test_binary_tool_special_input_does_not_launch_tools(self):
        with tempfile.TemporaryDirectory() as tmp:
            api = BinaryToolAPI(Path(tmp))
            with patch("fwagent.tools.ghidra_api.is_regular_file", return_value=False), patch.object(api.runtime, "check_environment") as environment:
                self.assertFalse(api.analyze_binary("controlled-device")["success"])
                self.assertFalse(api.decompile_function("controlled-device", "f")["success"])
                environment.assert_not_called()

    def test_worker_abnormal_exit_persists_failure(self):
        with tempfile.TemporaryDirectory() as tmp, scan_budget(5, event_path=Path(tmp) / "scan_events.jsonl"):
            with self.assertRaises(ScanWorkerError):
                run_bounded_scan("abnormal", exit_abnormally)
            self.assertEqual(json.loads((Path(tmp) / "scan_events.state.json").read_text())["status"], "failed")

    def test_dead_parent_is_reconciled_on_status_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "new-task"
            process = subprocess.Popen([sys.executable, "-B", "-c", "import sys; from tests.unit.test_phase2_scan_verification import scan_parent; scan_parent(sys.argv[1])", str(base)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                deadline = time.monotonic() + 10
                while not (base / "pids.json").exists() and time.monotonic() < deadline:
                    time.sleep(0.05)
                self.assertTrue((base / "pids.json").exists())
                pids = json.loads((base / "pids.json").read_text())
                process.terminate()
                process.wait(timeout=5)
                controller = AnalysisPipelineController(base.parent)
                task = controller.load_task(base.name)
                self.assertEqual(task.status, "paused")
                self.assertEqual(task.error["code"], "SCAN_OWNER_EXITED")
                self.assertEqual(json.loads((base / "state.json").read_text())["status"], "interrupted")
                deadline = time.monotonic() + 3
                while any(_pid_running(pid) for pid in pids) and time.monotonic() < deadline:
                    time.sleep(0.05)
                self.assertTrue(all(not _pid_running(pid) for pid in pids))
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)

    def test_unknown_or_alive_owner_is_not_marked_dead(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            path = base / "scan_events.state.json"
            original = '{"status":"running","owner_pid":123,"owner_token":"birth-token"}'
            path.write_text(original)
            for value in (None, "birth-token"):
                with patch("fwagent.runtime.scanning.process_token", return_value=value):
                    self.assertFalse(recover_interrupted_scan(base))
                self.assertEqual(path.read_text(), original)

    def test_explicit_config_and_script_paths_do_not_open_devices(self):
        info = SimpleNamespace(st_mode=stat.S_IFCHR)
        builder = object.__new__(AttackSurfaceBuilder)
        builder.graph = None
        with patch.object(Path, "stat", return_value=info), patch("fwagent.tools.common.os.open") as opened:
            lines = []
            _collect_lighttpd_config(Path("rootfs"), "/etc/controlled.conf", set(), lines)
            self.assertEqual(lines, [])
            self.assertEqual(builder._resolve_route_component(Path("device.cgi"), "/cgi/device.cgi", {}), (None, None))
            opened.assert_not_called()


if __name__ == "__main__":
    unittest.main()
