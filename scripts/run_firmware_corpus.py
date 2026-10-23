"""Inventory and execute the authorized local firmware corpus in isolated workers."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def slug(value: str) -> str:
    value = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return value[:48] or "firmware"


def inventory(source: Path) -> tuple[list[dict], list[dict]]:
    files = sorted(p for p in source.rglob("*") if p.is_file())
    records = []
    for path in files:
        relative = path.relative_to(source)
        digest = sha256(path)
        parts = relative.parts
        vendor = parts[0] if len(parts) > 1 else "unknown"
        model = parts[1] if len(parts) > 2 else path.stem
        records.append({"relative_path": relative.as_posix(), "source_path": str(path.resolve()),
                        "vendor": vendor, "model": model, "filename": path.name,
                        "bytes": path.stat().st_size, "sha256": digest})
    first = {}
    unique = []
    for record in records:
        if record["sha256"] in first:
            record["duplicate_of"] = first[record["sha256"]]["relative_path"]
            continue
        first[record["sha256"]] = record
        record["task_id"] = f"{slug(record['vendor'])}-{slug(record['model'])}-{record['sha256'][:12]}"
        unique.append(record)
    return records, unique


def docker_command(record: dict, output: Path, repo: Path, mode: str) -> list[str]:
    return ["docker", "run", "--rm", "--network", "none", "--ipc", "none",
        "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--memory", "6g", "--memory-swap", "6g", "--cpus", "4", "--pids-limit", "512",
        "--tmpfs", "/work:rw,exec,nosuid,nodev,size=6g,mode=1777",
        "--tmpfs", "/tmp:rw,exec,nosuid,nodev,size=512m,mode=1777",
        "--tmpfs", "/dev/shm:rw,nosuid,nodev,noexec,size=64m,mode=1777",
        "--tmpfs", "/home/nobody:rw,nosuid,nodev,size=64m,mode=700",
        "--mount", f"type=bind,source={record['source_path']},target=/input/firmware,readonly",
        "--mount", f"type=bind,source={repo},target=/src,readonly",
        "--mount", f"type=bind,source={output},target=/out",
        "--env", "PYTHONPATH=/src", "--env", "GHIDRA_HOME=/opt/ghidra",
        "--env", "HOME=/work/home", "--env", "XDG_CONFIG_HOME=/work/config",
        "--workdir", "/src", "--entrypoint", "python", "firmxplore:latest",
        "-B", "/src/scripts/corpus_worker.py", "--task-id", record["task_id"],
        "--name", record["filename"], "--vendor", record["vendor"], "--model", record["model"],
        "--mode", mode]


def execute(record: dict, output: Path, repo: Path, mode: str, timeout: int) -> dict:
    log = output / "logs" / f"{record['task_id']}.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    command = docker_command(record, output, repo, mode)
    lock_dir = output / "locks"
    lock_dir.mkdir(parents=True, exist_ok=True)
    lock = lock_dir / f"{record['task_id']}.lock"
    token = f"{os.getpid()}:{uuid.uuid4().hex}"
    while True:
        try:
            descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(token)
            break
        except FileExistsError:
            try:
                owner = int(lock.read_text(encoding="utf-8").split(":", 1)[0])
                os.kill(owner, 0)
            except (OSError, ValueError):
                try:
                    lock.unlink()
                except FileNotFoundError:
                    pass
                continue
            if time.monotonic() - started >= timeout:
                return {**record, "exit_code": None, "timed_out": True,
                        "error": "task lock wait timed out",
                        "duration_seconds": round(time.monotonic() - started, 3),
                        "log": str(log.relative_to(output))}
            time.sleep(2)
    try:
        with log.open("wb") as stream:
            completed = subprocess.run(command, cwd=repo, stdout=stream, stderr=subprocess.STDOUT, timeout=timeout)
        result_path = output / record["task_id"] / "corpus_result.json"
        worker = json.loads(result_path.read_text(encoding="utf-8")) if result_path.is_file() else {}
        return {**record, "exit_code": completed.returncode,
                "duration_seconds": round(time.monotonic() - started, 3), "worker": worker,
                "log": str(log.relative_to(output))}
    except subprocess.TimeoutExpired:
        return {**record, "exit_code": None, "timed_out": True,
                "duration_seconds": round(time.monotonic() - started, 3), "log": str(log.relative_to(output))}
    finally:
        try:
            if lock.read_text(encoding="utf-8") == token:
                lock.unlink()
        except FileNotFoundError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--mode", choices=("inventory", "extract", "static"), default="inventory")
    parser.add_argument("--workers", type=int, default=2, choices=range(1, 5))
    parser.add_argument("--timeout", type=int, default=3600)
    parser.add_argument("--only", action="append", help="Task id to execute; may be repeated")
    parser.add_argument("--successful-extractions-only", action="store_true",
        help="Execute only inputs already marked as successfully extracted in extract_summary.json")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parent.parent
    source, output = args.source.resolve(), args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    records, unique = inventory(source)
    manifest = {"created_at": datetime.now(timezone.utc).isoformat(), "source": str(source),
                "file_count": len(records), "unique_sha256_count": len(unique),
                "duplicate_count": len(records)-len(unique), "files": records}
    (output / "corpus_manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    if args.mode == "inventory":
        print(json.dumps({k: manifest[k] for k in ("file_count", "unique_sha256_count", "duplicate_count")}))
        return 0
    if args.only:
        wanted = set(args.only)
        unique = [record for record in unique if record["task_id"] in wanted]
        missing = wanted - {record["task_id"] for record in unique}
        if missing:
            parser.error("unknown task ids: " + ", ".join(sorted(missing)))
    if args.successful_extractions_only:
        extraction_summary = output / "extract_summary.json"
        if not extraction_summary.is_file():
            parser.error("--successful-extractions-only requires extract_summary.json in the output directory")
        prior = json.loads(extraction_summary.read_text(encoding="utf-8"))
        successful = {run["task_id"] for run in prior.get("runs", [])
                      if run.get("worker", {}).get("extraction_success") is True}
        unique = [record for record in unique if record["task_id"] in successful]
    outcomes = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        pending = [pool.submit(execute, record, output, repo, args.mode, args.timeout) for record in unique]
        for future in as_completed(pending):
            outcome = future.result()
            outcomes.append(outcome)
            outcomes.sort(key=lambda item: item["relative_path"])
            summary = {"mode": args.mode, "scheduled": len(unique), "completed": len(outcomes),
                       "successful_extractions": sum(x.get("worker", {}).get("extraction_success") is True for x in outcomes),
                       "static_completed": sum(x.get("worker", {}).get("static_completed") is True for x in outcomes),
                       "runs": outcomes}
            (output / f"{args.mode}_summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
            print(json.dumps({"task_id":outcome["task_id"], "exit_code":outcome.get("exit_code"),
                              "status":outcome.get("worker",{}).get("status"),
                              "duration_seconds":outcome["duration_seconds"]}), flush=True)
    return 0 if all(x.get("exit_code") in (0, 2) for x in outcomes) else 1


if __name__ == "__main__":
    raise SystemExit(main())
