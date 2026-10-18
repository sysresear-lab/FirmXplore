from __future__ import annotations

import json
import subprocess
import threading
import time
from pathlib import Path

from fwagent.models import CommandResult
from fwagent.runtime.execution_policy import BLOCK_CODE, BLOCK_REASON, command_requires_isolation


class CommandRunner:
    def __init__(self, logs_dir: Path, default_timeout: int = 60, output_limit: int = 4 * 1024 * 1024):
        if type(output_limit) is not int or output_limit < 1:
            raise ValueError("output_limit must be a positive byte count")
        self.output_limit = output_limit
        self.logs_dir = logs_dir
        self.default_timeout = default_timeout
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        self.trace_path = self.logs_dir / "commands.jsonl"

    def run(
        self,
        command: list[str],
        *,
        timeout: int | None = None,
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
    ) -> CommandResult:
        start = time.monotonic()
        effective_timeout = timeout or self.default_timeout
        if command_requires_isolation(command):
            result = CommandResult(
                command=command, exit_code=126, stdout="",
                stderr=f"{BLOCK_CODE}: {BLOCK_REASON}",
                duration=time.monotonic() - start, timed_out=False,
            )
            self._log_result(result, cwd)
            return result
        try:
            process = subprocess.Popen(
                command,
                cwd=str(cwd) if cwd else None,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                env=env,
            )
            buffers = [bytearray(), bytearray()]
            overflow = threading.Event()
            read_errors = []
            def drain(stream, destination):
                try:
                    while True:
                        data = stream.read1(8192)
                        if not data:
                            break
                        room = self.output_limit - len(destination)
                        destination.extend(data[:room])
                        if len(data) > room:
                            overflow.set()
                            try:
                                process.kill()
                            except OSError:
                                pass
                            break
                except OSError as exc:
                    read_errors.append(type(exc).__name__)
            threads = [threading.Thread(target=drain, args=(stream, buffer), daemon=True)
                       for stream, buffer in zip((process.stdout, process.stderr), buffers)]
            for thread in threads:
                thread.start()
            timed_out = False
            try:
                process.wait(timeout=effective_timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                process.kill()
                process.wait(timeout=5)
            for thread in threads:
                thread.join(timeout=1)
            incomplete = any(thread.is_alive() for thread in threads)
            if not incomplete:
                process.stdout.close()
                process.stderr.close()
            stdout, stderr = (bytes(buffer).decode("utf-8", errors="replace") for buffer in buffers)
            failed_output = overflow.is_set() or incomplete or bool(read_errors)
            if failed_output:
                stderr += "\nCOMMAND_OUTPUT_LIMIT_OR_READ_FAILURE: output unavailable or exceeded byte budget"
            result = CommandResult(
                command=command,
                exit_code=None if timed_out or failed_output else process.returncode,
                stdout=stdout,
                stderr=stderr,
                duration=time.monotonic() - start,
                timed_out=timed_out,
            )
        except FileNotFoundError as exc:
            result = CommandResult(
                command=command,
                exit_code=None,
                stdout="",
                stderr=str(exc),
                duration=time.monotonic() - start,
                timed_out=False,
            )
        except subprocess.TimeoutExpired as exc:
            result = CommandResult(
                command=command,
                exit_code=None,
                stdout=exc.stdout or "",
                stderr=exc.stderr or "",
                duration=time.monotonic() - start,
                timed_out=True,
            )
        self._log_result(result, cwd)
        return result

    def _log_result(self, result: CommandResult, cwd: Path | None) -> None:
        record = result.to_dict()
        record["cwd"] = str(cwd) if cwd else None
        record["stdout"] = _as_text(record.get("stdout"))[:4000]
        record["stderr"] = _as_text(record.get("stderr"))[:4000]
        with self.trace_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=True) + "\n")


def _as_text(value) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value or "")
