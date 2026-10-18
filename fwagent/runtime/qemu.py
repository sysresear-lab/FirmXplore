from __future__ import annotations

from fwagent.runtime.execution_policy import deny_unisolated_execution

import os
import shutil
from pathlib import Path
from typing import Any

from fwagent.dynamic.models import EmulationState
from fwagent.runtime.command import CommandRunner


class QemuRuntime:
    def __init__(self, workspace: str | Path, *, runner: CommandRunner | None = None):
        self.workspace = Path(workspace).resolve()
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.runner = runner or CommandRunner(self.workspace / "logs")
        self.logs_path = self.workspace / "logs" / "qemu.log"

    def check_environment(self) -> dict[str, Any]:
        checks: dict[str, Any] = {}
        for name in ("qemu-system-arm", "qemu-system-mips", "qemu-arm-static", "qemu-mips-static"):
            checks[name] = shutil.which(name) is not None
        checks["dev_net_tun"] = Path("/dev/net/tun").exists()
        checks["kvm"] = Path("/dev/kvm").exists()
        return {
            "success": all(value for key, value in checks.items() if key != "kvm"),
            "checks": checks,
            "warnings": ["KVM unavailable; software emulation only"] if not checks["kvm"] else [],
        }

    @deny_unisolated_execution
    def start(self, firmware_path: str | Path, *, arch: str = "arm") -> dict[str, Any]:
        environment = self.check_environment()
        if not environment["success"]:
            return {"success": False, "errors": ["QEMU environment unavailable"], "checks": environment["checks"]}
        return {
            "success": False,
            "errors": ["QEMU whole-firmware boot requires kernel/rootfs configuration; use FirmAE backend"],
            "diagnosis": "unsupported_architecture" if arch not in {"arm", "mips", "mipsel"} else "missing_kernel_rootfs",
        }

    def stop(self) -> dict[str, Any]:
        return {"success": True, "stopped": True}

    def status(self) -> EmulationState:
        return EmulationState(backend="qemu", status="stopped", errors=[])

    def logs(self, limit: int = 200) -> list[str]:
        if not self.logs_path.exists():
            return []
        lines = self.logs_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        return lines[-limit:]
