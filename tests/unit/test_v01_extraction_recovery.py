from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fwagent.models import CommandResult
from fwagent.pipeline.product import (
    AnalysisPipelineController,
    PipelineStageResult,
    V01_PIPELINE_STAGES,
    normalize_extraction_path,
    score_rootfs_candidate,
    select_canonical_rootfs_candidate,
    validate_rootfs_candidate,
    _validate_rootfs_candidate,
)
from fwagent.reporting.final_report import ReportGenerator
from fwagent.tools.architecture import identify_architecture
from fwagent.tools.extractor import _post_process_embedded_files


REAL_TPLINK_ROOTFS = Path(
    "workspace/deepseek-firmware-02/docker-extract-01/"
    "_tpra_sr20v1_us-up-ver1-2-1-P522_20180518-rel77140_2018-05-21_08.42.04.bin.extracted/"
    "squashfs-root"
)


def fake_arm_elf(payload: bytes = b"") -> bytes:
    header = bytearray(64)
    header[0:4] = b"\x7fELF"
    header[4] = 1
    header[5] = 1
    header[16:18] = (2).to_bytes(2, "little")
    header[18:20] = (40).to_bytes(2, "little")
    return bytes(header) + payload


def make_rootfs(root: Path, *, elf_count: int = 2, files: int = 8, web: bool = True) -> Path:
    for directory in ("bin", "etc", "usr/sbin", "sbin", "lib"):
        (root / directory).mkdir(parents=True, exist_ok=True)
    (root / "etc" / "passwd").write_text("root:x:0:0:root:/root:/bin/sh\n", encoding="utf-8")
    (root / "etc" / "init.d").mkdir(parents=True, exist_ok=True)
    (root / "etc" / "init.d" / "S80httpd").write_text("/usr/sbin/httpd\n", encoding="utf-8")
    if web:
        (root / "www").mkdir(parents=True, exist_ok=True)
        (root / "www" / "index.html").write_text("<html></html>", encoding="utf-8")
    names = ["httpd", "dnsmasq", "uhttpd", "miniupnpd"]
    for index in range(elf_count):
        (root / "usr" / "sbin" / names[index % len(names)]).write_bytes(fake_arm_elf(b"HTTP/1.1\x00system\x00/bin/sh\x00"))
    for index in range(files):
        (root / "etc" / f"config{index}.conf").write_text("x=y\n", encoding="utf-8")
    return root


def write_analysis(task: Path, *, rootfs: str | None = None, candidates: list[str] | None = None) -> None:
    payload = {
        "firmware": {"filename": "firmware.bin", "sha256": "abc"},
        "extraction": {"success": bool(rootfs), "extractor": "none", "rootfs": rootfs, "rootfs_candidates": candidates or []},
        "platform": {},
        "filesystem": {},
        "services": [],
        "web": {},
        "binaries": [],
        "priority_binaries": [],
        "security_candidates": [],
        "errors": [],
    }
    (task / "reports").mkdir(parents=True, exist_ok=True)
    (task / "reports" / "analysis.json").write_text(json.dumps(payload) + "\n", encoding="utf-8")


def stages() -> dict[str, PipelineStageResult]:
    return {name: PipelineStageResult(name, status="pending") for name in V01_PIPELINE_STAGES}


class ExtractionRecoveryTests(unittest.TestCase):
    def test_sasquatch_recovers_when_unsquashfs_fails(self) -> None:
        class FakeRunner:
            def __init__(self) -> None:
                self.commands: list[list[str]] = []

            def run(self, command, **_) -> CommandResult:
                self.commands.append(command)
                if command[0] == "sasquatch":
                    target = Path(command[3])
                    (target / "etc").mkdir(parents=True)
                    (target / "etc" / "passwd").write_text("root:x:0:0:root:/root:/bin/sh\n", encoding="utf-8")
                    return CommandResult(command=list(command), exit_code=0, stdout="ok", stderr="", duration=0.01)
                return CommandResult(command=list(command), exit_code=1, stdout="", stderr="lzma failed", duration=0.01)

        with tempfile.TemporaryDirectory() as tmp:
            extract_dir = Path(tmp)
            (extract_dir / "legacy.squashfs").write_bytes(b"qshs" + b"\x00" * 64)
            errors: list[dict] = []
            runner = FakeRunner()

            with patch("fwagent.tools.extractor.shutil.which", return_value="/usr/bin/tool"):
                extracted = _post_process_embedded_files(extract_dir, runner, 1, errors)

            self.assertEqual(extracted, 1)
            self.assertEqual([command[0] for command in runner.commands], ["unsquashfs", "sasquatch"])
            self.assertEqual(errors[0]["tool"], "unsquashfs")

    def test_primary_no_rootfs_triggers_docker_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            task = root / "t"
            fallback = make_rootfs(task / "docker-extract" / "_fw.extracted" / "squashfs-root")
            write_analysis(task)
            controller = AnalysisPipelineController(root)
            with patch.object(controller, "_docker_extract_rootfs", return_value={"success": True, "rootfs": str(fallback), "method": "docker-binwalk", "validation": validate_rootfs_candidate(fallback)}):
                artifact = controller._ensure_canonical_rootfs("t", root / "firmware.bin", stages(), {}, [], timeout=1)
            self.assertEqual(artifact.source, "docker")

    def test_docker_binwalk_success_selected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            task = Path(tmp) / "t"
            rootfs = make_rootfs(task / "docker-extract" / "nested" / "squashfs-root")
            self.assertEqual(select_canonical_rootfs_candidate([rootfs], task_dir=task)["host_path"], rootfs.resolve())

    def test_nested_squashfs_root_discovered_by_scoring(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            task = Path(tmp) / "t"
            nested = make_rootfs(task / "docker-extract" / "_firmware.bin.extracted" / "squashfs-root")
            selected = select_canonical_rootfs_candidate([task / "docker-extract", nested], task_dir=task)
            self.assertEqual(selected["host_path"], nested.resolve())

    def test_empty_candidate_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            empty = Path(tmp) / "empty"
            empty.mkdir()
            self.assertFalse(validate_rootfs_candidate(empty)["valid"])

    def test_non_rootfs_directory_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / "logs"
            directory.mkdir()
            (directory / "log.txt").write_text("x", encoding="utf-8")
            self.assertFalse(validate_rootfs_candidate(directory)["valid"])

    def test_multiple_candidate_scoring_prefers_richer_rootfs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            task = Path(tmp) / "t"
            weak = make_rootfs(task / "weak", elf_count=1, files=1)
            strong = make_rootfs(task / "strong", elf_count=3, files=20)
            selected = select_canonical_rootfs_candidate([weak, strong], task_dir=task)
            self.assertEqual(selected["host_path"], strong.resolve())

    def test_canonical_rootfs_selected_from_primary_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            task = Path(tmp) / "t"
            rootfs = make_rootfs(task / "extracted" / "squashfs-root")
            write_analysis(task, rootfs=str(rootfs))
            artifact = AnalysisPipelineController(tmp)._ensure_canonical_rootfs("t", Path(tmp) / "firmware.bin", stages(), {}, [], timeout=1)
            self.assertTrue(artifact.validated)

    def test_rootfs_json_generated(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            task = Path(tmp) / "t"
            rootfs = make_rootfs(task / "rootfs")
            controller = AnalysisPipelineController(tmp)
            controller.import_extracted_rootfs("t", rootfs)
            self.assertTrue((task / "artifacts" / "rootfs.json").exists())

    def test_extraction_json_generated(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            task = Path(tmp) / "t"
            rootfs = make_rootfs(task / "rootfs")
            AnalysisPipelineController(tmp).import_extracted_rootfs("t", rootfs)
            self.assertTrue((task / "artifacts" / "extraction.json").exists())

    def test_host_container_path_separated(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            task = Path(tmp) / "t"
            artifact = AnalysisPipelineController(tmp).import_extracted_rootfs("t", make_rootfs(task / "rootfs"))
            self.assertNotEqual(artifact.host_path, artifact.container_path)
            self.assertIn("/repo/workspace/t/", artifact.container_path)

    def test_host_safe_view_recorded_separately(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            task = Path(tmp) / "t"
            rootfs = make_rootfs(task / "rootfs")
            host_safe = make_rootfs(task / "host-safe-rootfs")

            artifact = AnalysisPipelineController(tmp).import_extracted_rootfs("t", rootfs, host_safe_view=host_safe)

            self.assertEqual(artifact.canonical_linux_rootfs, str(rootfs.resolve()))
            self.assertEqual(artifact.host_safe_view, str(host_safe.resolve()))
            self.assertFalse(artifact.linux_semantics_preserved)
            self.assertEqual(artifact.semantic_fidelity, "host-safe-view")

    def test_windows_drive_path_normalized(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            task = Path(tmp) / "t"
            rootfs = make_rootfs(task / "rootfs")
            self.assertEqual(normalize_extraction_path(str(rootfs), task_dir=task), rootfs.resolve())

    def test_container_path_not_mistaken_for_host_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            task = Path(tmp) / "t"
            mapped = normalize_extraction_path("/repo/workspace/t/docker-extract/squashfs-root", task_dir=task)
            self.assertEqual(mapped.resolve(), (task / "docker-extract" / "squashfs-root").resolve())

    def test_symlink_error_does_not_abort_scan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rootfs = make_rootfs(Path(tmp) / "rootfs")
            with patch("fwagent.pipeline.product._safe_walk", return_value=[(str(rootfs), [], ["badlink"])]), patch.object(Path, "is_symlink", side_effect=OSError("bad link")):
                # In-process unit for injected stat errors; public worker isolation is tested separately.
                result = _validate_rootfs_candidate(rootfs)
            self.assertFalse(result["valid"])

    def test_broken_symlink_skipped_when_supported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rootfs = make_rootfs(Path(tmp) / "rootfs")
            try:
                (rootfs / "bad").symlink_to(rootfs / "missing")
            except OSError:
                self.skipTest("symlink unavailable on this Windows host")
            self.assertTrue(validate_rootfs_candidate(rootfs)["valid"])

    def test_inventory_consumes_canonical_rootfs_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            task = Path(tmp) / "t"
            canonical = make_rootfs(task / "canonical", elf_count=1)
            decoy = make_rootfs(task / "decoy", elf_count=4)
            artifact = AnalysisPipelineController(tmp).import_extracted_rootfs("t", canonical)
            report = json.loads((task / "reports" / "analysis.json").read_text(encoding="utf-8"))
            report["extraction"]["rootfs_candidates"] = [str(decoy)]
            (task / "reports" / "analysis.json").write_text(json.dumps(report) + "\n", encoding="utf-8")
            AnalysisPipelineController(tmp)._refresh_inventory_for_canonical_rootfs("t", artifact)
            refreshed = json.loads((task / "reports" / "analysis.json").read_text(encoding="utf-8"))
            self.assertEqual(refreshed["extraction"]["rootfs"], str(canonical.resolve()))

    def test_file_count_positive(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.assertGreater(validate_rootfs_candidate(make_rootfs(Path(tmp) / "rootfs"))["file_count"], 0)

    def test_elf_magic_detection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.assertGreater(validate_rootfs_candidate(make_rootfs(Path(tmp) / "rootfs", elf_count=1))["elf_count"], 0)

    def test_architecture_detection_arm(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rootfs = make_rootfs(Path(tmp) / "rootfs", elf_count=1)
            result = identify_architecture(rootfs, ["/usr/sbin/httpd"])
            self.assertEqual(result["primary_architecture"], "arm")

    def test_rootfs_exists_zero_files_invalid_partial(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rootfs = Path(tmp) / "rootfs"
            (rootfs / "etc").mkdir(parents=True)
            self.assertFalse(validate_rootfs_candidate(rootfs)["valid"])

    @unittest.skipUnless(REAL_TPLINK_ROOTFS.exists(), "historical TP-Link rootfs artifact missing")
    def test_current_firmware_fixture_rootfs_finds_elf(self) -> None:
        self.assertGreater(validate_rootfs_candidate(REAL_TPLINK_ROOTFS)["elf_count"], 100)

    def test_elf_inventory_to_target_selection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            task = Path(tmp) / "t"
            controller = AnalysisPipelineController(tmp)
            artifact = controller.import_extracted_rootfs("t", make_rootfs(task / "rootfs", elf_count=2))
            controller._refresh_inventory_for_canonical_rootfs("t", artifact)
            targets = controller._select_static_targets("t")
            self.assertGreater(len(targets), 0)

    def test_selected_targets_positive(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            task = Path(tmp) / "t"
            controller = AnalysisPipelineController(tmp)
            artifact = controller.import_extracted_rootfs("t", make_rootfs(task / "rootfs"))
            controller._refresh_inventory_for_canonical_rootfs("t", artifact)
            self.assertGreater(json.loads((task / "reports" / "analysis.json").read_text())["priority_binaries"][0]["score"], 0)

    def test_ghidra_scheduling_positive(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            task = Path(tmp) / "t"
            controller = AnalysisPipelineController(tmp)
            artifact = controller.import_extracted_rootfs("t", make_rootfs(task / "rootfs"))
            controller._refresh_inventory_for_canonical_rootfs("t", artifact)
            controller._select_static_targets("t")
            targets = json.loads((task / "ghidra" / "targets.json").read_text(encoding="utf-8"))
            self.assertGreater(targets["selected_static_targets"], 0)

    def test_ghidra_permission_block_differs_from_no_targets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            task = Path(tmp) / "t"
            write_analysis(task)
            controller = AnalysisPipelineController(tmp)
            with patch.object(controller, "_docker_extract_rootfs", return_value={"success": False, "error_code": "DOCKER_PERMISSION_DENIED", "error": "permission denied"}):
                local_stages = stages()
                controller._ensure_canonical_rootfs("t", Path(tmp) / "firmware.bin", local_stages, {}, [], timeout=1)
            self.assertEqual(local_stages["EXTRACTION"].status, "blocked")

    def test_cross_task_contamination_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            task = Path(tmp) / "t"
            other = make_rootfs(Path(tmp) / "other" / "rootfs")
            write_analysis(task, candidates=[str(other)])
            selected = select_canonical_rootfs_candidate([f"/repo/workspace/other/rootfs"], task_dir=task)
            self.assertIsNone(selected)

    def test_explicit_imported_artifact_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            artifact = AnalysisPipelineController(tmp).import_extracted_rootfs("t", make_rootfs(Path(tmp) / "other" / "rootfs"))
            self.assertEqual(artifact.source, "imported")

    def test_imported_artifact_provenance_recorded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            task = Path(tmp) / "t"
            AnalysisPipelineController(tmp).import_extracted_rootfs("t", make_rootfs(Path(tmp) / "other" / "rootfs"))
            payload = json.loads((task / "artifacts" / "extraction.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["attempts"][0]["status"], "imported_artifact")

    def test_extraction_failure_still_generates_stage_result(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            task = Path(tmp) / "t"
            write_analysis(task)
            controller = AnalysisPipelineController(tmp)
            local_stages = stages()
            with patch.object(controller, "_docker_extract_rootfs", return_value={"success": False, "error": "no rootfs"}):
                self.assertIsNone(controller._ensure_canonical_rootfs("t", Path(tmp) / "firmware.bin", local_stages, {}, [], timeout=1))
            self.assertIn(local_stages["EXTRACTION"].status, {"partial", "blocked"})

    def test_report_shows_extraction_method(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            task = Path(tmp) / "t"
            controller = AnalysisPipelineController(tmp)
            artifact = controller.import_extracted_rootfs("t", make_rootfs(task / "rootfs"))
            controller._refresh_inventory_for_canonical_rootfs("t", artifact)
            controller._write_pipeline_artifacts("t", stages(), "STATIC_ONLY_COMPLETED")
            text = ReportGenerator(tmp, "t").generate_markdown(ReportGenerator(tmp, "t").build_model({"findings": []})).read_text(encoding="utf-8")
            self.assertIn("Extraction mode", text)

    def test_report_shows_canonical_rootfs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            task = Path(tmp) / "t"
            controller = AnalysisPipelineController(tmp)
            artifact = controller.import_extracted_rootfs("t", make_rootfs(task / "rootfs"))
            controller._refresh_inventory_for_canonical_rootfs("t", artifact)
            controller._write_pipeline_artifacts("t", stages(), "STATIC_ONLY_COMPLETED")
            text = ReportGenerator(tmp, "t").generate_markdown(ReportGenerator(tmp, "t").build_model({"findings": []})).read_text(encoding="utf-8")
            self.assertIn("Canonical rootfs", text)

    def test_report_differentiates_extraction_blocked_vs_ghidra_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            task = Path(tmp) / "t"
            write_analysis(task)
            local_stages = stages()
            local_stages["EXTRACTION"].status = "blocked"
            local_stages["GHIDRA_ANALYSIS"].status = "pending"
            AnalysisPipelineController(tmp)._write_pipeline_artifacts("t", local_stages, "PARTIAL")
            payload = json.loads((task / "pipeline_stages.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["coverage"]["stage_extraction"], "blocked")

    def test_no_downstream_fake_zero_complete_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            firmware = Path(tmp) / "fw.bin"
            firmware.write_bytes(b"abc")
            result = AnalysisPipelineController(tmp).analyze(firmware, task_id="t", progress=False)
            statuses = {item["stage"]: item["status"] for item in result["stage_results"]}
            self.assertNotEqual(statuses["ROOTFS_INVENTORY"], "completed")
            self.assertNotEqual(statuses["GHIDRA_ANALYSIS"], "completed")

    def test_docker_permission_classification(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            task = Path(tmp) / "t"
            write_analysis(task)
            controller = AnalysisPipelineController(tmp)
            with patch.object(controller, "_docker_extract_rootfs", return_value={"success": False, "error_code": "DOCKER_PERMISSION_DENIED", "error": "permission denied"}):
                errors = []
                controller._ensure_canonical_rootfs("t", Path(tmp) / "fw.bin", stages(), {}, errors, timeout=1)
            self.assertEqual(errors[0]["code"], "DOCKER_PERMISSION_DENIED")

    def test_docker_extract_uses_argv_for_parenthesized_names(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            firmware = Path(tmp) / "SR20(US).zip"
            firmware.write_bytes(b"PK")
            completed = unittest.mock.Mock(returncode=0, stdout="", stderr="")
            controller = AnalysisPipelineController(tmp)

            with patch("fwagent.pipeline.product.shutil.which", return_value="docker"), patch("fwagent.pipeline.product.subprocess.run", return_value=completed) as run, patch("fwagent.pipeline.product.find_rootfs_candidates", return_value=[]):
                controller._docker_extract_rootfs("t", firmware, timeout=1)

            command = run.call_args.args[0]
            self.assertNotIn("-lc", command)
            self.assertIn("binwalk", command)
            self.assertIn("/input/SR20(US).zip", command)

    def test_embedded_firmware_fallback_selected_after_archive_extract(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            task = Path(tmp) / "t"
            write_analysis(task)
            embedded = task / "extracted" / "SR20(US).bin"
            embedded.parent.mkdir(parents=True)
            embedded.write_bytes(b"x" * (1024 * 1024 + 1))
            rootfs = make_rootfs(task / "docker-extract" / "_SR20.extracted" / "squashfs-root")
            controller = AnalysisPipelineController(tmp)

            with patch.object(
                controller,
                "_docker_extract_rootfs",
                side_effect=[
                    {"success": False, "error_code": "ROOTFS_NOT_FOUND", "error": "archive wrapper produced no rootfs"},
                    {"success": True, "rootfs": str(rootfs), "method": "docker-binwalk", "validation": validate_rootfs_candidate(rootfs), "exit_code": 0},
                ],
            ):
                artifact = controller._ensure_canonical_rootfs("t", Path(tmp) / "SR20(US).zip", stages(), {}, [], timeout=1)

            self.assertIsNotNone(artifact)
            self.assertEqual(artifact.extraction_method, "embedded-docker-binwalk")

    def test_score_prefers_markers_and_elf(self) -> None:
        self.assertGreater(score_rootfs_candidate(markers=["etc", "bin", "usr"], file_count=10, elf_count=2), score_rootfs_candidate(markers=["etc"], file_count=10, elf_count=0))


if __name__ == "__main__":
    unittest.main()
