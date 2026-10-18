from __future__ import annotations

import hashlib
import io
import json
import multiprocessing
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from fwagent.pipeline.analyzer import _run_step, analyze_firmware
from fwagent.pipeline.product import AnalysisPipelineController, validate_rootfs_candidate
from fwagent.runtime.scanning import ScanTimeoutError, run_bounded_scan, scan_budget, scan_timeout
from fwagent.tools.architecture import identify_architecture, parse_elf_header
from fwagent.tools.common import extract_ascii_strings, is_elf, is_regular_file, iter_files, read_prefix, safe_read_text, sha256_file
from fwagent.tools.extractor import _is_squashfs_image, extract_firmware
from fwagent.tools.filesystem import inventory_filesystem


def _raise_permission():
    raise PermissionError("controlled scan permission error")


def _block_with_child(pid_file):
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    Path(pid_file).write_text(json.dumps([os.getpid(), child.pid]))
    time.sleep(60)


def _pid_running(pid):
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes as w
        api = ctypes.WinDLL("kernel32", use_last_error=True)
        api.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
        api.OpenProcess.restype = w.HANDLE
        api.WaitForSingleObject.argtypes = [w.HANDLE, w.DWORD]
        api.CloseHandle.argtypes = [w.HANDLE]
        handle = api.OpenProcess(0x100000, False, pid)
        if not handle:
            error = ctypes.get_last_error()
            if error == 87:  # PID no longer exists, not an access-denied false positive.
                return False
            raise ctypes.WinError(error)
        try:
            return api.WaitForSingleObject(handle, 0) == 258
        finally:
            api.CloseHandle(handle)
    try:
        os.kill(pid, 0)
        proc = Path(f"/proc/{pid}/stat")
        return not proc.exists() or proc.read_text().split(")", 1)[1].split()[0] != "Z"
    except ProcessLookupError:
        return False


def deadline_probe(base):
    """Invoked under an outer subprocess timeout, never the unittest runner itself."""
    base = Path(base)
    try:
        with scan_budget(2, event_path=base / "scan_events.jsonl"):
            run_bounded_scan("controlled_block", _block_with_child, str(base / "pids.json"))
    except ScanTimeoutError:
        pids = json.loads((base / "pids.json").read_text())
        assert all(not _pid_running(pid) for pid in pids), pids
        assert not multiprocessing.active_children()
        print("worker_and_tool_reaped")
        return
    raise AssertionError("blocking worker did not time out")


def fifo_probe(base):
    """Real FIFO with no writer; any accidental blocking open trips the outer timeout."""
    base = Path(base)
    fifo = base / "console"
    os.mkfifo(fifo)
    (base / "normal").write_bytes(b"\x7fELF" + b"\0" * 60)
    with patch("fwagent.tools.common.os.open", wraps=os.open) as opened:
        assert read_prefix(fifo) == b""
        assert safe_read_text(fifo) == ""
        assert extract_ascii_strings(fifo) == []
        assert not _is_squashfs_image(fifo)
        assert parse_elf_header(fifo) is None
        assert not opened.called
    assert list(iter_files(base)) == [base / "normal"]
    assert inventory_filesystem(base)["elf_files"] == 1
    assert fifo.exists()  # never delete/replace the firmware's special nodes
    # Race an ordinary pathname into a FIFO after prechecks, just before os.open.
    raced = base / "race"
    raced.write_bytes(b"ordinary")
    original_open = os.open

    def replace_before_open(path, flags):
        raced.unlink()
        os.mkfifo(raced)
        return original_open(path, flags)

    with patch("fwagent.tools.common.os.open", side_effect=replace_before_open):
        assert read_prefix(raced) == b""
    print("fifo_skipped_and_open_race_rejected")


class ScanSafetyTests(unittest.TestCase):
    def test_regular_files_and_empty_reads(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            file = root / "data"
            file.write_bytes(b"hello\0world")
            empty = root / "empty"
            empty.touch()
            self.assertEqual(set(iter_files(root)), {file, empty})
            self.assertEqual(read_prefix(file, 5), b"hello")
            self.assertEqual(safe_read_text(file), "hello\0world")
            self.assertEqual(extract_ascii_strings(file), ["hello", "world"])
            self.assertEqual(sha256_file(file), hashlib.sha256(file.read_bytes()).hexdigest())
            self.assertEqual(read_prefix(empty), b"")
            self.assertFalse(is_regular_file(root))
            self.assertEqual(read_prefix(root), b"")

    def test_special_metadata_never_opens_device_contents(self):
        for mode in (stat.S_IFCHR, stat.S_IFBLK, stat.S_IFIFO, stat.S_IFSOCK, stat.S_IFDIR, stat.S_IFLNK):
            with self.subTest(mode=mode), patch.object(Path, "stat", return_value=SimpleNamespace(st_mode=mode)), patch("fwagent.tools.common.os.open") as opened:
                self.assertFalse(is_regular_file(Path("controlled-node")))
                self.assertEqual(read_prefix(Path("controlled-node")), b"")
                opened.assert_not_called()

    def test_reparse_metadata_is_not_regular(self):
        info = SimpleNamespace(st_mode=stat.S_IFREG, st_file_attributes=0x400)
        with patch.object(Path, "stat", return_value=info), patch("fwagent.tools.common.os.open") as opened:
            self.assertEqual(safe_read_text(Path("reparse")), "")
            opened.assert_not_called()

    def test_non_regular_extraction_input_never_reaches_external_tools(self):
        with tempfile.TemporaryDirectory() as tmp, patch("fwagent.tools.extractor.is_regular_file", return_value=False), patch("fwagent.tools.extractor._external_extractors") as tools:
            result = extract_firmware(Path(tmp) / "controlled-device", Path(tmp) / "output")
            self.assertFalse(result["success"])
            self.assertEqual(result["errors"][0]["error_type"], "NonRegularFileError")
            tools.assert_not_called()

    @unittest.skipUnless(os.name == "nt", "Windows device namespace test")
    def test_windows_special_namespace_never_opens(self):
        with patch("fwagent.tools.common.os.open") as opened:
            for value in ("NUL", "CON.txt", r"\\.\pipe\controlled", r"\\?\GLOBALROOT\Device\controlled"):
                self.assertEqual(read_prefix(Path(value)), b"")
            opened.assert_not_called()
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp).resolve() / "ordinary"
            file.write_bytes(b"extended ordinary path")
            self.assertEqual(read_prefix(Path("\\\\?\\" + str(file))), b"extended ordinary path")

    def test_descriptor_type_and_identity_checked_before_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "normal"
            file.write_bytes(b"ordinary")
            info = file.stat()
            device = SimpleNamespace(st_mode=stat.S_IFCHR, st_dev=info.st_dev, st_ino=info.st_ino)
            with patch("fwagent.tools.common.os.fstat", return_value=device), patch("fwagent.tools.common.os.fdopen") as reader:
                self.assertEqual(read_prefix(file), b"")
                reader.assert_not_called()
            replaced = SimpleNamespace(st_mode=stat.S_IFREG, st_dev=info.st_dev, st_ino=info.st_ino + 1)
            with patch("fwagent.tools.common.os.fstat", return_value=replaced), patch("fwagent.tools.common.os.fdopen") as reader:
                self.assertEqual(read_prefix(file), b"")
                reader.assert_not_called()

    def test_many_ordinary_files_survive_special_neighbor(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            for i in range(250):
                (root / f"file-{i}").write_bytes(b"ordinary")
            special = root / "console"
            special.touch()
            original = Path.stat

            def metadata(path, *args, **kwargs):
                if path == special:
                    return SimpleNamespace(st_mode=stat.S_IFCHR)
                return original(path, *args, **kwargs)

            with patch.object(Path, "stat", metadata):
                self.assertEqual(len(list(iter_files(root))), 250)
                inventory = inventory_filesystem(root)
            self.assertEqual(inventory["total_files"], 250)
            self.assertEqual(inventory["special_files_skipped"], 1)
            self.assertTrue(special.exists())

    def test_arm_and_big_endian_mips_headers_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name, machine, encoding, endian in (("arm", 40, 1, "little"), ("mips", 8, 2, "big")):
                header = bytearray(64)
                header[:4] = b"\x7fELF"
                header[4:6] = bytes((1, encoding))
                header[18:20] = machine.to_bytes(2, endian)
                path = root / name
                path.write_bytes(header)
                self.assertTrue(is_elf(path))
                self.assertEqual(parse_elf_header(path), {"architecture": name, "endianness": endian, "bitness": 32})
                self.assertEqual(identify_architecture(root, ["/" + name])["primary_architecture"], name)

    def test_permission_error_is_not_an_empty_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "ordinary"
            file.touch()
            with patch("fwagent.tools.common.os.open", side_effect=PermissionError("denied")):
                for reader in (read_prefix, safe_read_text, extract_ascii_strings):
                    with self.assertRaises(PermissionError):
                        reader(file)
            errors, timings = [], {}
            self.assertEqual(_run_step("permission", timings, errors, _raise_permission, default=[]), [])
            self.assertEqual(errors[0]["error_type"], "PermissionError")
            clean_errors = []
            self.assertEqual(_run_step("empty", {}, clean_errors, lambda: [], default=None), [])
            self.assertEqual(clean_errors, [])

    def test_metadata_permission_error_is_not_empty_inventory(self):
        with patch.object(Path, "stat", side_effect=PermissionError("metadata denied")):
            with self.assertRaises(PermissionError):
                list(iter_files(Path("unreadable-root")))
            with self.assertRaises(PermissionError):
                inventory_filesystem("unreadable-root")

    def test_synthetic_archive_records_substages_and_completed_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "controlled.tar"
            with tarfile.open(source, "w") as archive:
                for name, data in (("etc/config.conf", b"x=y\n"), ("bin/app", b"\x7fELF" + b"\0" * 60)):
                    member = tarfile.TarInfo(name)
                    member.size = len(data)
                    archive.addfile(member, io.BytesIO(data))
            before = hashlib.sha256(source.read_bytes()).digest()
            report, path = analyze_firmware(source, workspace=root / "workspace", task_id="synthetic", scan_timeout=10)
            self.assertEqual(report["base_scan_status"], "completed")
            task = path.parent.parent
            state = json.loads((task / "scan_events.state.json").read_text())
            self.assertEqual(state["status"], "completed")
            events = [json.loads(line) for line in (task / "scan_events.jsonl").read_text().splitlines()]
            for stage in ("firmware", "extractor", "filesystem", "architecture", "services", "web", "secrets", "binaries"):
                self.assertTrue(any(e["stage"] == stage and e["event"] == "start" for e in events), stage)
                self.assertTrue(any(e["stage"] == stage and e["event"] == "end" and "duration" in e for e in events), stage)
            self.assertTrue(any(e["event"] == "read_start" for e in events))
            self.assertEqual(hashlib.sha256(source.read_bytes()).digest(), before)

    def test_diagnostic_write_failure_does_not_mask_scan_failure(self):
        with tempfile.TemporaryDirectory() as tmp, scan_budget(5, event_path=Path(tmp) / "events.jsonl"):
            errors = []
            with patch.object(Path, "open", side_effect=OSError("log disk unavailable")), self.assertLogs("fwagent.runtime.scanning", level="WARNING"):
                _run_step("permission", {}, errors, _raise_permission, default=None)
            self.assertEqual(errors[0]["error_type"], "PermissionError")

    @unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux FIFO; not verified on Windows")
    def test_linux_fifo_under_hard_outer_timeout(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run([sys.executable, "-B", "-c", "import sys; from tests.unit.test_scan_safety import fifo_probe; fifo_probe(sys.argv[1])", tmp], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("fifo_skipped", result.stdout)

    def test_worker_and_descendant_really_end_after_deadline(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run([sys.executable, "-B", "-c", "import sys; from tests.unit.test_scan_safety import deadline_probe; deadline_probe(sys.argv[1])", tmp], capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("worker_and_tool_reaped", result.stdout)
            state = json.loads((Path(tmp) / "scan_events.state.json").read_text())
            self.assertEqual(state["status"], "timed_out")
            events = [json.loads(line) for line in (Path(tmp) / "scan_events.jsonl").read_text().splitlines()]
            self.assertEqual(events[0]["event"], "start")
            self.assertTrue(any(e.get("error_type") == "ScanTimeoutError" for e in events))

    def test_worker_preserves_permission_exception_and_failure_state(self):
        with tempfile.TemporaryDirectory() as tmp, scan_budget(5, event_path=Path(tmp) / "events.jsonl"):
            with self.assertRaises(PermissionError):
                run_bounded_scan("permission", _raise_permission)
            self.assertEqual(json.loads((Path(tmp) / "events.state.json").read_text())["status"], "failed")

    def test_shared_budget_is_not_reset_between_steps(self):
        with tempfile.TemporaryDirectory() as tmp, scan_budget(2, event_path=Path(tmp) / "events.jsonl"):
            run_bounded_scan("first", time.sleep, 0.1)
            with self.assertRaises(ScanTimeoutError):
                run_bounded_scan("second", time.sleep, 5)
            starts = [json.loads(line) for line in (Path(tmp) / "events.jsonl").read_text().splitlines() if json.loads(line)["event"] == "start"]
            self.assertLess(starts[1]["remaining_seconds"], starts[0]["remaining_seconds"])

    def test_timeout_configuration_has_finite_upper_bound(self):
        for value in (0, -1, float("inf"), float("nan"), 3601):
            with self.assertRaises(ValueError):
                scan_timeout(value)
        with patch.dict(os.environ, {"FWAGENT_SCAN_TIMEOUT_SECONDS": "12"}):
            self.assertEqual(scan_timeout(), 12)

    def test_controller_reports_base_scan_timeout_distinctly(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "firmware.bin"
            source.write_bytes(b"controlled-input")
            controller = AnalysisPipelineController(root / "workspace")
            with patch.object(controller, "_environment_stage", return_value={"success": True}):
                result = controller.analyze(source, task_id="new-timeout-task", scan_timeout=0.001, progress=False)
            self.assertFalse(result["success"])
            self.assertEqual(result["scan_status"], "timed_out")
            self.assertEqual(result["error"]["code"], "BASE_SCAN_TIMEOUT")


if __name__ == "__main__":
    unittest.main()
