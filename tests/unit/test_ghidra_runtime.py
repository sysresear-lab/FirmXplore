from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fwagent.config import GhidraSettings
from fwagent.models import CommandResult
from fwagent.runtime.ghidra import GhidraRuntime


class FakeRunner:
    def __init__(self, result: CommandResult):
        self.result = result
        self.commands: list[list[str]] = []

    def run(self, command: list[str], *, timeout: int | None = None, cwd: Path | None = None, env: dict[str, str] | None = None) -> CommandResult:
        self.commands.append(command)
        return self.result


class GhidraRuntimeTests(unittest.TestCase):
    def test_builds_headless_export_command(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            home = base / "ghidra"
            support = home / "support"
            scripts = base / "scripts"
            support.mkdir(parents=True)
            scripts.mkdir()
            (support / "analyzeHeadless").write_text("#!/bin/sh\n", encoding="utf-8")
            binary = base / "sample"
            binary.write_bytes(b"\x7fELF" + b"\x00" * 60)
            runtime = GhidraRuntime(
                base / "workspace",
                settings=GhidraSettings(home=home, project_dir=base / "projects", script_dir=scripts),
            )

            command = runtime.build_export_command(binary, "proj", base / "out")

            self.assertEqual(command[0], str(support / "analyzeHeadless"))
            self.assertIn("-import", command)
            self.assertIn("ExportBinarySummary.java", command)
            self.assertIn("-deleteProject", command)

    def test_cache_key_is_stable_for_same_binary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            binary = base / "sample"
            binary.write_bytes(b"\x7fELF" + b"\x00" * 60)
            runtime = GhidraRuntime(base / "workspace", settings=GhidraSettings(home=base / "missing"))

            self.assertEqual(runtime.cache_key(binary), runtime.cache_key(binary))

    def test_default_cache_key_version_invalidates_old_fallbacks(self) -> None:
        self.assertEqual(GhidraSettings().config_version, "0.1-ghidra12-strings")

    def test_container_environment_check_reports_dockerized_ghidra(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runner = FakeRunner(
                CommandResult(
                    command=[],
                    exit_code=0,
                    stdout='openjdk version "21.0.8"\nGHIDRA_HOME=/opt/ghidra\nANALYZE_HEADLESS=/opt/ghidra/support/analyzeHeadless\nGhidra 12.1.3\n',
                    stderr="",
                    duration=0.2,
                )
            )
            runtime = GhidraRuntime(
                Path(tmp),
                settings=GhidraSettings(home=Path("missing-ghidra"), docker_image="firmxplore:latest"),
                runner=runner,
            )

            # FakeRunner does not execute Docker; CLI discovery belongs to this
            # fixture too, rather than depending on Docker installed on the host.
            with patch("fwagent.runtime.ghidra.shutil.which", return_value="controlled-docker"):
                result = runtime.check_container_environment()

            self.assertTrue(result["success"])
            self.assertEqual(result["result"]["image"], "firmxplore:latest")
            self.assertEqual(result["result"]["java_version"], "21.0.8")
            self.assertEqual(result["result"]["ghidra_version"], "12.1.3")
            self.assertEqual(result["result"]["analyze_headless"], "/opt/ghidra/support/analyzeHeadless")
            self.assertIn("--network", runner.commands[0])


if __name__ == "__main__":
    unittest.main()

