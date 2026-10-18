from __future__ import annotations

import time
import os
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from fwagent.runtime.command import CommandRunner
from fwagent.tools.common import is_regular_file, is_scan_directory


@dataclass
class ImageBuildResult:
    success: bool
    output_path: Path | None
    filesystem_type: str
    image_size_mb: int
    builder: str
    duration: float
    errors: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "output_path": str(self.output_path) if self.output_path else None,
            "filesystem_type": self.filesystem_type,
            "image_size_mb": self.image_size_mb,
            "builder": self.builder,
            "duration": self.duration,
            "errors": self.errors,
            "metadata": self.metadata,
        }


class FirmwareImageBuilder:
    name = "base"

    def build(
        self,
        rootfs: str | Path,
        output_path: str | Path,
        *,
        size_mb: int = 256,
    ) -> ImageBuildResult:
        raise NotImplementedError


class LoopImageBuilder(FirmwareImageBuilder):
    name = "loop"

    def __init__(self, runner: CommandRunner | None = None):
        self.runner = runner or CommandRunner(Path("workspace") / "dynamic" / "logs")

    def build(self, rootfs, output_path, *, size_mb=256) -> ImageBuildResult:
        return ImageBuildResult(
            success=False,
            output_path=Path(output_path),
            filesystem_type="ext4",
            image_size_mb=size_mb,
            builder=self.name,
            duration=0.0,
            errors=["loop device workflow requires /dev/loop*; use UserspaceImageBuilder on Docker Desktop"],
        )


class UserspaceImageBuilder(FirmwareImageBuilder):
    name = "userspace"

    def __init__(self, runner: CommandRunner | None = None):
        self.runner = runner or CommandRunner(Path("workspace") / "dynamic" / "logs")

    def build(
        self,
        rootfs: str | Path,
        output_path: str | Path,
        *,
        size_mb: int = 256,
    ) -> ImageBuildResult:
        start = time.monotonic()
        commands = []
        output = None
        def failed(message):
            return ImageBuildResult(
                False, output, "ext2", size_mb, self.name, round(time.monotonic() - start, 3),
                [message[:2000]], {"commands": commands},
            )
        try:
            if type(size_mb) is not int or size_mb <= 0:
                return failed("image size must be a positive integer")
            root, output = Path(rootfs).absolute(), Path(output_path).absolute()
            if not is_scan_directory(root):
                return failed("rootfs must be an ordinary directory")
            # Never remove an existing user image, including a dangling link.
            if output.exists() or output.is_symlink():
                return failed("image output already exists; choose a fresh path")
            # Local staging preserves Linux semantics when rootfs is on a bind
            # mount. TemporaryDirectory owns this unique tree, never a global
            # /tmp/rootfs_build shared with other users/runs.
            with tempfile.TemporaryDirectory(prefix="firmxplore-rootfs-") as temporary:
                staging = Path(temporary)
                stage = staging / "rootfs"
                stage.mkdir()
                copy_command = ["cp", "-a", "--", str(root) + os.sep + ".", str(stage) + os.sep]
                commands.append(copy_command)
                copied = self.runner.run(copy_command, timeout=600)
                if copied.exit_code != 0 or getattr(copied, "timed_out", False):
                    return failed("rootfs copy failed: " + str(copied.stderr or copied.stdout or "no diagnostic"))
                image = staging / "image.ext2"
                command = ["mke2fs", "-t", "ext2", "-F", "-d", str(stage), str(image), f"{size_mb}M"]
                commands.append(command)
                result = self.runner.run(command, timeout=300)
                if result.exit_code != 0 or getattr(result, "timed_out", False) or not is_regular_file(image):
                    return failed("mke2fs failed: " + str(result.stderr or result.stdout or "output missing"))
                output.parent.mkdir(parents=True, exist_ok=True)
                # Exclusive publish also rejects an output created while the
                # copy/build was running. No original output is overwritten.
                with image.open("rb") as source, output.open("xb") as destination:
                    shutil.copyfileobj(source, destination)
        except (OSError, ValueError, TypeError) as exc:
            return failed(f"image build failed: {type(exc).__name__}: {exc}")
        return ImageBuildResult(
            success=True,
            output_path=output,
            filesystem_type="ext2",
            image_size_mb=size_mb,
            builder=self.name,
            duration=round(time.monotonic() - start, 3),
            errors=[],
            metadata={
                "command": command,
                "commands": commands,
                "rootfs": str(root),
                "exit_code": result.exit_code,
            },
        )
