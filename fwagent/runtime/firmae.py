from __future__ import annotations

from fwagent.runtime.execution_policy import deny_unisolated_execution

import os
import shutil
import time
from pathlib import Path
from typing import Any

from fwagent.dynamic.models import EmulationState
from fwagent.runtime.command import CommandRunner


class FirmAERuntime:
    def __init__(self, workspace: str | Path, *, home: str | Path | None = None, runner: CommandRunner | None = None):
        self.workspace = Path(workspace).resolve()
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.home = Path(home or os.environ.get("FIRMAE_HOME", "/opt/FirmAE")).resolve()
        self.runner = runner or CommandRunner(self.workspace / "logs")
        self.run_script = self.home / "run.sh"
        self.logs_path = self.workspace / "logs" / "firmae.log"

    def check_environment(self) -> dict[str, Any]:
        checks = {
            "firmae_run_script": self.run_script.exists(),
            "qemu_system_arm": shutil.which("qemu-system-arm") is not None,
            "qemu_system_mips": shutil.which("qemu-system-mips") is not None,
            "binwalk": shutil.which("binwalk") is not None,
            "unsquashfs": shutil.which("unsquashfs") is not None,
            "sasquatch": shutil.which("sasquatch") is not None,
            "dev_net_tun": Path("/dev/net/tun").exists(),
        }
        warnings = []
        if not checks["dev_net_tun"]:
            warnings.append("/dev/net/tun unavailable; TUN/TAP emulation may fail")
        return {"success": all(value for key, value in checks.items() if key != "dev_net_tun"), "checks": checks, "warnings": warnings}

    def prepare(self, firmware_path: str | Path) -> dict[str, Any]:
        source = Path(firmware_path)
        if not source.exists():
            return {"success": False, "errors": ["firmware not found"]}
        target_dir = self.workspace / "input"
        target_dir.mkdir(parents=True, exist_ok=True)
        target = target_dir / source.name
        if not target.exists():
            import shutil

            shutil.copy2(source, target)
        return {"success": True, "firmware": str(source), "prepared": str(target)}

    @deny_unisolated_execution
    def boot(self, firmware_path: str | Path, *, timeout: int = 300, brand: str = "router") -> dict[str, Any]:
        environment = self.check_environment()
        if not environment["success"]:
            return {
                "success": False,
                "errors": ["FirmAE environment unavailable"],
                "checks": environment["checks"],
                "diagnosis": "backend_error",
            }
        setup_errors = self._ensure_postgres()
        if setup_errors:
            return {
                "success": False,
                "errors": setup_errors,
                "diagnosis": "backend_error",
            }
        prepared = self.prepare(firmware_path)
        if not prepared["success"]:
            return {"success": False, "errors": prepared["errors"], "diagnosis": "backend_error"}
        command = [str(self.run_script), "-r", brand, prepared["prepared"]]
        start = time.monotonic()
        env = dict(os.environ)
        env["PYTHONPATH"] = "/usr/lib/python3/dist-packages"
        env["USER"] = os.environ.get("USER", "root")
        result = self.runner.run(command, timeout=timeout + 30, cwd=self.home, env=env)
        duration = round(time.monotonic() - start, 3)
        with self.logs_path.open("a", encoding="utf-8") as handle:
            handle.write(_as_text(result.stdout)[-8000:])
            handle.write(_as_text(result.stderr)[-8000:])
        if result.timed_out:
            return {
                "success": False,
                "errors": ["FirmAE boot timed out"],
                "diagnosis": "timeout",
                "duration": duration,
            }
        stdout = _as_text(result.stdout)
        stderr = _as_text(result.stderr)
        output = f"{stdout}\n{stderr}"
        if result.exit_code != 0 or "extractor.py failed" in output or "failed!" in output:
            output = (stderr or stdout or "")[:2000]
            failure_marker = "extractor.py failed" in output
            return {
                "success": False,
                "errors": [output[:2000] if output else "FirmAE boot failed"],
                "diagnosis": "extractor_failure" if failure_marker else (
                    "kernel_boot_failure" if "kernel" in output.lower() else "backend_error"
                ),
                "exit_code": result.exit_code,
                "duration": duration,
            }
        return {"success": True, "duration": duration}

    def _ensure_postgres(self) -> list[str]:
        errors: list[str] = []
        start = self.runner.run(["pg_ctlcluster", "17", "main", "start"], timeout=30)
        if start.exit_code != 0:
            errors.append((start.stderr or start.stdout or "postgres start failed")[:500])

        role = self.runner.run(
            ["su", "postgres", "-c", "psql -tAc \"SELECT 1 FROM pg_roles WHERE rolname='firmadyne'\""],
            timeout=10,
        )
        if "1" not in role.stdout:
            created = self.runner.run(
                ["su", "postgres", "-c", "psql -c \"CREATE USER firmadyne WITH PASSWORD 'firmadyne';\""],
                timeout=10,
            )
            if created.exit_code != 0:
                errors.append((created.stderr or created.stdout or "create user failed")[:500])

        database = self.runner.run(
            ["su", "postgres", "-c", "psql -tAc \"SELECT 1 FROM pg_database WHERE datname='firmware'\""],
            timeout=10,
        )
        if "1" not in database.stdout:
            created = self.runner.run(
                ["su", "postgres", "-c", "createdb -O firmadyne firmware"],
                timeout=10,
            )
            if created.exit_code != 0:
                errors.append((created.stderr or created.stdout or "create database failed")[:500])
            schema = self.home / "database" / "schema"
            loaded = self.runner.run(
                ["su", "postgres", "-c", f"psql -d firmware -f {schema}"],
                timeout=60,
            )
            if loaded.exit_code != 0:
                errors.append((loaded.stderr or loaded.stdout or "schema load failed")[:500])
        return errors

    def stop(self) -> dict[str, Any]:
        result = self.runner.run(["pkill", "-f", "run.sh"], timeout=10)
        return {"success": True, "stopped": True, "pkill_exit": result.exit_code}

    def status(self) -> EmulationState:
        return EmulationState(backend="firmae", status="stopped", errors=[])

    def logs(self, limit: int = 200) -> list[str]:
        if not self.logs_path.exists():
            return []
        lines = self.logs_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        return lines[-limit:]


def _as_text(value) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value or "")
