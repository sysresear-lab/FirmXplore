"""Run bounded isolated emulation for every successfully extracted corpus item."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
from pathlib import Path
import subprocess
import sys
import time


def run_one(workspace: Path, task_id: str, timeout: int) -> dict:
    log = workspace / "emulation-logs" / f"{task_id}.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    command = [sys.executable, "-m", "fwagent.cli", "emulate", task_id,
               "--workspace", str(workspace), "--backend", "isolated-qemu",
               "--timeout", str(timeout)]
    started = time.monotonic()
    try:
        completed = subprocess.run(command, capture_output=True, text=True,
                                   timeout=timeout + 120)
        log.write_text(completed.stdout + completed.stderr, encoding="utf-8")
        payload = {}
        for line in reversed(completed.stdout.splitlines()):
            try:
                payload = json.loads(line)
                break
            except json.JSONDecodeError:
                continue
        result_path = workspace / task_id / "dynamic" / "isolated" / "result.json"
        if result_path.is_file():
            payload = json.loads(result_path.read_text(encoding="utf-8"))
        return {"task_id": task_id, "exit_code": completed.returncode,
                "duration_seconds": round(time.monotonic() - started, 3),
                "result": payload, "log": str(log.relative_to(workspace))}
    except subprocess.TimeoutExpired as exc:
        log.write_text((exc.stdout or "") + (exc.stderr or ""), encoding="utf-8")
        return {"task_id": task_id, "exit_code": None, "timed_out": True,
                "duration_seconds": round(time.monotonic() - started, 3),
                "log": str(log.relative_to(workspace))}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=1, choices=(1, 2))
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--only", action="append")
    args = parser.parse_args()
    workspace = args.workspace.resolve()
    extraction = json.loads((workspace / "extract_summary.json").read_text(encoding="utf-8"))
    task_ids = [run["task_id"] for run in extraction.get("runs", [])
                if run.get("worker", {}).get("extraction_success") is True]
    if args.only:
        wanted = set(args.only)
        unknown = wanted - set(task_ids)
        if unknown:
            parser.error("unknown or unextracted task ids: " + ", ".join(sorted(unknown)))
        task_ids = [task_id for task_id in task_ids if task_id in wanted]
    outcomes: list[dict] = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        pending = [pool.submit(run_one, workspace, task_id, args.timeout) for task_id in task_ids]
        for future in as_completed(pending):
            outcome = future.result()
            outcomes.append(outcome)
            outcomes.sort(key=lambda item: item["task_id"])
            summary = {
                "scheduled": len(task_ids),
                "completed": len(outcomes),
                "boot_succeeded": sum(item.get("result", {}).get("success") is True for item in outcomes),
                "endpoint_observed": sum(bool(item.get("result", {}).get("response_observed")) for item in outcomes),
                "runs": outcomes,
            }
            (workspace / "emulation_summary.json").write_text(
                json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
            print(json.dumps({"task_id": outcome["task_id"],
                              "exit_code": outcome.get("exit_code"),
                              "success": outcome.get("result", {}).get("success"),
                              "duration_seconds": outcome["duration_seconds"]}), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
