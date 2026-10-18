from __future__ import annotations

import json
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fwagent.models import WorkspaceContext
from fwagent.tools.common import is_regular_file, safe_is_dir, sha256_file


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class WorkspaceStateError(ValueError):
    pass


def validate_workspace_input(task_dir: Path, firmware_path: Path, task_id: str) -> Path | None:
    expected = sha256_file(firmware_path)
    identified = False
    for name in ("task.json", "state.json"):
        path = task_dir / name
        if not path.exists():
            continue
        state = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(state, dict):
            raise WorkspaceStateError("workspace metadata must be an object")
        if state.get("task_id") != task_id:
            raise WorkspaceStateError("workspace task id mismatch")
        stored_hash = state.get("input_hash") or state.get("input_sha256")
        if stored_hash:
            if stored_hash != expected:
                raise WorkspaceStateError("resume input hash mismatch")
            identified = True
    files = list((task_dir / "input").iterdir()) if (task_dir / "input").exists() else []
    if files:
        if len(files) != 1 or not is_regular_file(files[0]) or sha256_file(files[0]) != expected:
            raise WorkspaceStateError("stored firmware does not match resume input")
        return files[0]
    if not identified:
        raise WorkspaceStateError("existing workspace has no verifiable input identity")
    return None


def _ensure_directory(path: Path) -> None:
    try:
        path.stat(follow_symlinks=False)
    except FileNotFoundError:
        path.mkdir(parents=True)
        return
    if not safe_is_dir(path):
        raise WorkspaceStateError(f"workspace path is not an ordinary directory: {path}")


def create_workspace(firmware_path: Path, workspace_root: Path, task_id: str | None = None, *, resume: bool = False) -> WorkspaceContext:
    workspace_root = workspace_root.resolve()
    workspace_root.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    task_id = task_id or f"{stamp}-{uuid.uuid4().hex[:8]}"
    task_dir = workspace_root / task_id

    existing = any((task_dir / name).exists() for name in ("input", "extracted", "state.json"))
    if existing and not resume:
        raise WorkspaceStateError("workspace already initialized; use explicit resume")
    stored_input = validate_workspace_input(task_dir, firmware_path, task_id) if resume else None
    previous = json.loads((task_dir / "state.json").read_text(encoding="utf-8")) if resume and (task_dir / "state.json").exists() else {}
    input_dir = task_dir / "input"
    extracted_dir = task_dir / "scan_attempts" / uuid.uuid4().hex[:12] / "extracted" if resume else task_dir / "extracted"
    artifacts_dir = task_dir / "artifacts"
    logs_dir = task_dir / "logs"
    reports_dir = task_dir / "reports"
    ghidra_dir = task_dir / "ghidra"
    evidence_dir = task_dir / "evidence"
    hypotheses_dir = task_dir / "hypotheses"
    for directory in (input_dir, extracted_dir, artifacts_dir, logs_dir, reports_dir, ghidra_dir, evidence_dir, hypotheses_dir):
        _ensure_directory(directory)
    for name in ("binaries", "configs", "web"):
        _ensure_directory(artifacts_dir / name)

    input_firmware = stored_input or input_dir / firmware_path.name
    if stored_input is None:
        shutil.copy2(firmware_path, input_firmware)

    created_at = previous.get("created_at") or utc_now_iso()
    context = WorkspaceContext(
        task_id=task_id,
        task_dir=task_dir,
        input_dir=input_dir,
        extracted_dir=extracted_dir,
        artifacts_dir=artifacts_dir,
        logs_dir=logs_dir,
        reports_dir=reports_dir,
        input_firmware=input_firmware,
        created_at=created_at,
    )
    save_state(context, "created")
    return context


def save_state(context: WorkspaceContext, status: str) -> None:
    state = {
        "task_id": context.task_id,
        "created_at": context.created_at,
        "status": status,
        "input_firmware": str(context.input_firmware),
        "reports_dir": str(context.reports_dir),
        "input_sha256": sha256_file(context.input_firmware),
        "extracted_dir": str(context.extracted_dir),
    }
    path = context.task_dir / "state.json"
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)
