"""Bounded local scan workers; no threads are left reading after a timeout."""
from __future__ import annotations

import contextlib
import contextvars
import json
import logging
import math
import multiprocessing
import os
import pickle
import signal
import tempfile
import time
import threading
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_SCAN_TIMEOUT = 300.0
MAX_SCAN_TIMEOUT = 3600.0
_budget = contextvars.ContextVar("scan_budget", default=None)
_worker = False
_owner_pid = None
_owner_token = None
logger = logging.getLogger(__name__)


def process_token(pid: int) -> str | None:
    """Empty means dead, None means unknown; birth identity prevents PID reuse."""
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes as w
        api = ctypes.WinDLL("kernel32", use_last_error=True)
        api.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
        api.OpenProcess.restype = w.HANDLE
        api.WaitForSingleObject.argtypes = [w.HANDLE, w.DWORD]
        api.GetProcessTimes.argtypes = [w.HANDLE, *([ctypes.POINTER(w.FILETIME)] * 4)]
        api.CloseHandle.argtypes = [w.HANDLE]
        handle = api.OpenProcess(0x101000, False, pid)
        if not handle:
            return "" if ctypes.get_last_error() == 87 else None
        try:
            if api.WaitForSingleObject(handle, 0) == 0:
                return ""
            times = [w.FILETIME() for _ in range(4)]
            if not api.GetProcessTimes(handle, *(ctypes.byref(t) for t in times)):
                return None
            return f"{times[0].dwHighDateTime}:{times[0].dwLowDateTime}"
        finally:
            api.CloseHandle(handle)
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        return "" if fields[0] == "Z" else fields[19]
    except FileNotFoundError:
        return "" if Path("/proc").exists() else None
    except (OSError, IndexError):
        return None


def recover_interrupted_scan(task_dir: Path) -> bool:
    """Reconcile only leased scans with a provably dead/replaced owner on next read."""
    path = task_dir / "scan_events.state.json"
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
        pid, token = state.get("owner_pid"), state.get("owner_token")
        if not isinstance(pid, int) or not token:
            return False
        current = process_token(pid)
        if current is None or current == token:
            return False
        state.update(status="interrupted", event="owner_exited", error_type="ScanOwnerExited")
        temporary = path.with_suffix(".recovery.tmp")
        temporary.write_text(json.dumps(state) + "\n", encoding="utf-8")
        temporary.replace(path)
        low = task_dir / "state.json"
        if low.exists():
            payload = json.loads(low.read_text(encoding="utf-8"))
            payload["status"] = "interrupted"
            temporary = low.with_suffix(".recovery.tmp")
            temporary.write_text(json.dumps(payload) + "\n", encoding="utf-8")
            temporary.replace(low)
        return True
    except (OSError, ValueError):
        return False


def scan_owner_active(task_dir: Path) -> bool:
    try:
        state = json.loads((task_dir / "scan_events.state.json").read_text(encoding="utf-8"))
        return bool(state.get("owner_token") and process_token(state["owner_pid"]) == state["owner_token"])
    except (OSError, ValueError, KeyError):
        return False


class ScanTimeoutError(TimeoutError):
    pass


class ScanWorkerError(RuntimeError):
    pass


def scan_timeout(value: float | None = None) -> float:
    seconds = float(value if value is not None else os.environ.get("FWAGENT_SCAN_TIMEOUT_SECONDS", DEFAULT_SCAN_TIMEOUT))
    if not math.isfinite(seconds) or not 0 < seconds <= MAX_SCAN_TIMEOUT:
        raise ValueError(f"scan timeout must be greater than 0 and at most {MAX_SCAN_TIMEOUT:g} seconds")
    return seconds


def remaining_scan_seconds() -> float:
    current = _budget.get()
    remaining = current[0] - time.monotonic() if current else scan_timeout()
    if remaining <= 0:
        raise ScanTimeoutError("base scan deadline exceeded")
    return remaining


@contextlib.contextmanager
def scan_budget(seconds: float | None = None, *, event_path: Path | None = None):
    parent = _budget.get()
    deadline = parent[0] if parent and seconds is None else time.monotonic() + scan_timeout(seconds)
    if parent:
        deadline = min(deadline, parent[0])
        event_path = event_path or parent[1]
    token = _budget.set((deadline, event_path))
    try:
        yield
    finally:
        _budget.reset(token)


def scan_event(stage: str, event: str, **fields) -> None:
    """Best effort diagnostics must never replace an original scan exception."""
    owner = _owner_pid or os.getpid()
    record = {"timestamp": datetime.now(timezone.utc).isoformat(), "stage": stage, "event": event, "pid": os.getpid(),
              "owner_pid": owner, "owner_token": _owner_token if _worker else process_token(owner), **fields}
    current = _budget.get()
    if not current or current[1] is None:
        logger.info("scan %s", record)
        return
    path = current[1]
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=True) + "\n")
        if event in {"start", "end", "error"}:
            state = {**record, "status": fields.get("status", "running")}
            temporary = path.with_name(f"{path.stem}.{os.getpid()}.tmp")
            temporary.write_text(json.dumps(state, ensure_ascii=True) + "\n", encoding="utf-8")
            temporary.replace(path.with_suffix(".state.json"))
    except OSError as exc:
        logger.warning("cannot write scan event %s: %s", path, exc)


class _SkipHandler(logging.Handler):
    def emit(self, record):
        scan_event("files", getattr(record, "scan_event", "skipped"), reason=record.getMessage())


def _scan_child(callback, args, kwargs, output: str, deadline: float, event_path, gate, owner_pid: int, owner_token) -> None:
    global _worker, _owner_pid, _owner_token
    _owner_pid = owner_pid
    _owner_token = owner_token
    if os.name != "nt":
        os.setsid()
    # Windows parent assigns the job before any scan/tool runs. A parent can
    # disappear before assignment; the closed gate must not leave an orphan.
    while not gate.wait(0.2):
        current_owner = process_token(owner_pid)
        if time.monotonic() >= deadline or (owner_token and current_owner is not None and current_owner != owner_token):
            return
    _worker = True
    _budget.set((deadline, event_path))
    if os.name != "nt":
        def watch_parent():
            while os.getppid() == owner_pid:
                time.sleep(0.2)
            scan_event("worker", "error", status="interrupted", error_type="ScanOwnerExited")
            os.killpg(os.getpid(), signal.SIGKILL)
        threading.Thread(target=watch_parent, daemon=True).start()
    skips = logging.getLogger("fwagent.scan.files")
    skips.addHandler(_SkipHandler())
    skips.setLevel(logging.INFO)
    skips.propagate = False
    try:
        result = {"ok": True, "value": callback(*args, **kwargs)}
    except BaseException as exc:
        try:
            pickle.dumps(exc)
        except Exception:
            exc = ScanWorkerError(f"{type(exc).__name__}: {exc}")
        result = {"ok": False, "error": exc}
    # Parent reads only after this process exits: no full-pipe/join deadlock.
    with open(output, "wb") as handle:
        pickle.dump(result, handle)


class _WindowsJob:
    """Kill-on-close job owns both the scan process and its local tool children."""
    def __init__(self, pid: int):
        import ctypes
        from ctypes import wintypes as w

        class Basic(ctypes.Structure):
            _fields_ = [("process_time", ctypes.c_longlong), ("job_time", ctypes.c_longlong), ("flags", w.DWORD),
                        ("min_working_set", ctypes.c_size_t), ("max_working_set", ctypes.c_size_t),
                        ("active_processes", w.DWORD), ("affinity", ctypes.c_size_t),
                        ("priority", w.DWORD), ("scheduling", w.DWORD)]

        class Extended(ctypes.Structure):
            _fields_ = [("basic", Basic), ("io", ctypes.c_ulonglong * 6),
                        ("process_memory", ctypes.c_size_t), ("job_memory", ctypes.c_size_t),
                        ("peak_process_memory", ctypes.c_size_t), ("peak_job_memory", ctypes.c_size_t)]

        self.api = ctypes.WinDLL("kernel32", use_last_error=True)
        self.api.CreateJobObjectW.argtypes = [w.LPVOID, w.LPCWSTR]
        self.api.CreateJobObjectW.restype = w.HANDLE
        self.api.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
        self.api.OpenProcess.restype = w.HANDLE
        self.api.SetInformationJobObject.argtypes = [w.HANDLE, ctypes.c_int, w.LPVOID, w.DWORD]
        self.api.AssignProcessToJobObject.argtypes = [w.HANDLE, w.HANDLE]
        self.api.CloseHandle.argtypes = [w.HANDLE]
        self.handle = self.api.CreateJobObjectW(None, None)
        process = self.api.OpenProcess(0x0101, False, pid)  # SET_QUOTA | TERMINATE
        try:
            limits = Extended()
            limits.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            if not self.handle or not process or not self.api.SetInformationJobObject(self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)) or not self.api.AssignProcessToJobObject(self.handle, process):
                raise ctypes.WinError(ctypes.get_last_error())
        except BaseException:
            self.close()
            raise
        finally:
            if process:
                self.api.CloseHandle(process)

    def close(self):
        if self.handle:
            self.api.CloseHandle(self.handle)
            self.handle = None


def _stop_worker(process, job) -> None:
    if job:
        job.close()
    elif os.name != "nt":
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            if process.is_alive():
                process.kill()  # child may not have called setsid yet
    elif process.is_alive():
        process.kill()  # assignment failed; gate prevented tool creation
    process.join(5)
    if process.is_alive():
        raise ScanWorkerError(f"scan worker {process.pid} could not be reaped")


def run_bounded_scan(stage: str, callback, *args, **kwargs):
    """One remaining budget for the batch, never a fresh timeout per ELF."""
    if _worker:
        started = time.monotonic()
        status = "failed"
        scan_event(stage, "start", status="running")
        try:
            value = callback(*args, **kwargs)
            status = "completed"
            return value
        except BaseException as exc:
            scan_event(stage, "error", status=status, error_type=type(exc).__name__, error=str(exc))
            raise
        finally:
            scan_event(stage, "end", status=status, duration=round(time.monotonic() - started, 3))
    if _budget.get() is None:
        with scan_budget():
            return run_bounded_scan(stage, callback, *args, **kwargs)
    deadline, event_path = _budget.get()
    started = time.monotonic()
    scan_event(stage, "start", remaining_seconds=max(0, deadline - started))
    if started >= deadline:
        scan_event(stage, "end", status="timed_out", duration=0)
        raise ScanTimeoutError(f"base scan deadline exceeded before {stage}")
    status = "failed"
    process = None
    job = None
    stopped = False
    try:
        with tempfile.TemporaryDirectory(prefix="firmxplore-scan-") as tmp:
            output = str(Path(tmp) / "result.pickle")
            ctx = multiprocessing.get_context("spawn")
            gate = ctx.Event()
            process = ctx.Process(target=_scan_child, args=(callback, args, kwargs, output, deadline, event_path, gate, os.getpid(), process_token(os.getpid())))
            process.start()
            if os.name == "nt":
                job = _WindowsJob(process.pid)
            scan_event(stage, "worker_started", worker_pid=process.pid)
            gate.set()
            process.join(max(0, deadline - time.monotonic()))
            if process.is_alive():
                _stop_worker(process, job)
                stopped = True
                status = "timed_out"
                raise ScanTimeoutError(f"base scan deadline exceeded in {stage}; worker {process.pid} terminated and reaped")
            if process.exitcode == 0 and not Path(output).exists() and time.monotonic() >= deadline:
                status = "timed_out"
                raise ScanTimeoutError(f"base scan deadline exceeded before {stage} worker started")
            if process.exitcode != 0 or not Path(output).exists():
                raise ScanWorkerError(f"scan worker exited without result: stage={stage} exit={process.exitcode}")
            with open(output, "rb") as handle:
                result = pickle.load(handle)  # private parent-created temp dir, not firmware input
            if not result["ok"]:
                raise result["error"]
            value = result["value"]
            status = value[0].get("base_scan_status", "completed") if isinstance(value, tuple) and value and isinstance(value[0], dict) else "completed"
            return value
    except BaseException as exc:
        scan_event(stage, "error", status=status, error_type=type(exc).__name__, error=str(exc))
        raise
    finally:
        if process is not None and process.pid is not None:
            if not stopped:
                _stop_worker(process, job)
            process.close()
        scan_event(stage, "end", status=status, duration=round(time.monotonic() - started, 3))
