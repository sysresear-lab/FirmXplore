from __future__ import annotations

import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from fwagent.pipeline.analyzer import analyze_firmware
from fwagent.pipeline.context import WorkspaceStateError, create_workspace
from fwagent.pipeline.product import AnalysisPipelineController


def firmware(base):
    source = base / "controlled.tar"
    with tarfile.open(source, "w") as archive:
        for name, data in (("etc/config.conf", b"x=y\n"), ("bin/app", b"\x7fELF" + b"\0" * 60)):
            member = tarfile.TarInfo(name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    return source


class ResumeTests(unittest.TestCase):
    def test_invalid_resume_metadata_is_rejected_without_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = firmware(base)
            context = create_workspace(source, base / "workspace", "invalid")
            path = context.task_dir / "state.json"
            path.write_text("[]")
            result = AnalysisPipelineController(base / "workspace").analyze(source, task_id="invalid", resume=True, progress=False)
            self.assertEqual(result["error"]["code"], "RESUME_STATE_INVALID")
            self.assertEqual(path.read_text(), "[]")
    def test_complete_base_report_is_reused_without_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = firmware(base)
            first, path = analyze_firmware(source, workspace=base / "workspace", task_id="base")
            original = path.read_bytes()
            second, same_path = analyze_firmware(source, workspace=base / "workspace", task_id="base", resume=True)
            self.assertEqual(same_path, path)
            self.assertEqual(second["firmware"]["sha256"], first["firmware"]["sha256"])
            self.assertEqual(path.read_bytes(), original)

    def test_new_workspace_and_explicit_duplicate_policy(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = firmware(base)
            context = create_workspace(source, base / "workspace", "new")
            self.assertEqual(context.input_firmware.read_bytes(), source.read_bytes())
            with self.assertRaises(WorkspaceStateError):
                create_workspace(source, base / "workspace", "new")

    def test_resume_without_report_preserves_all_partial_artifacts(self):
        for partial in ("directory_only", "inventory_finished", "partial_analysis"):
            with self.subTest(partial=partial), tempfile.TemporaryDirectory() as tmp:
                base = Path(tmp)
                source = firmware(base)
                context = create_workspace(source, base / "workspace", "resume")
                marker = context.extracted_dir / "original-partial"
                marker.write_bytes(b"preserve existing extracted bytes")
                artifact = context.artifacts_dir / (partial + ".json")
                artifact.write_text('{"keep":true}')
                if partial == "inventory_finished":
                    (context.artifacts_dir / "inventory.json").write_text('{"files":1}')
                report, path = analyze_firmware(source, workspace=base / "workspace", task_id="resume", resume=True)
                self.assertTrue(path.exists())
                self.assertEqual(report["filesystem"]["elf_files"], 1)
                self.assertIn("scan_attempts", report["extraction"]["rootfs"])
                self.assertEqual(marker.read_bytes(), b"preserve existing extracted bytes")
                self.assertEqual(artifact.read_text(), '{"keep":true}')

    def test_hash_mismatch_does_not_change_existing_task(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = firmware(base)
            context = create_workspace(source, base / "workspace", "resume")
            original = (context.task_dir / "state.json").read_bytes()
            other = base / "different.bin"
            other.write_bytes(b"different firmware")
            controller = AnalysisPipelineController(base / "workspace")
            result = controller.analyze(other, task_id="resume", resume=True, progress=False)
            self.assertEqual(result["error"]["code"], "RESUME_STATE_INVALID")
            self.assertEqual((context.task_dir / "state.json").read_bytes(), original)

    def test_completed_controller_resume_is_idempotent_and_duplicate_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = firmware(base)
            controller = AnalysisPipelineController(base / "workspace")
            with patch.object(controller, "_environment_stage", return_value={"success": True}):
                first = controller.analyze(source, task_id="completed", fast=True, progress=False)
            self.assertTrue(first["success"])
            report = base / "workspace/completed/reports/report.json"
            original = report.read_bytes()
            resumed = controller.analyze(source, task_id="completed", resume=True, fast=True, progress=False)
            self.assertTrue(resumed["resume_reused_complete"])
            self.assertEqual(report.read_bytes(), original)
            duplicate = controller.analyze(source, task_id="completed", progress=False)
            self.assertEqual(duplicate["error"]["code"], "TASK_EXISTS")

    def test_controller_resumes_pre_report_workspace(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = firmware(base)
            context = create_workspace(source, base / "workspace", "early")
            controller = AnalysisPipelineController(base / "workspace")
            with patch.object(controller, "_environment_stage", return_value={"success": True}):
                result = controller.analyze(source, task_id="early", resume=True, fast=True, progress=False)
            self.assertTrue(result["success"], result)
            self.assertEqual(result["task_id"], "early")
            self.assertTrue((context.task_dir / "reports/analysis.json").exists())

    def test_original_upload_missing_can_reuse_verified_stored_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = firmware(base)
            controller = AnalysisPipelineController(base / "workspace")
            with patch.object(controller, "_environment_stage", return_value={"success": True}):
                first = controller.analyze(source, task_id="stored", fast=True, progress=False)
            self.assertTrue(first["success"])
            source.unlink()  # controlled temporary upload, not a historical artifact
            resumed = controller.analyze(source, task_id="stored", resume=True, fast=True, progress=False)
            self.assertTrue(resumed["resume_reused_complete"])


if __name__ == "__main__":
    unittest.main()
