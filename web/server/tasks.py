"""任务执行与实时状态推送。

fwagent 适配层：
- fwagent 的分析入口是同步阻塞函数
  `AnalysisPipelineController(workspace).analyze(firmware, task_id=..., ...)`，
  会运行数分钟到数十分钟。这里在独立子进程中运行它（web/server/runner.py）：
  * 可暂停/恢复——终止子进程即可中断，配合 fwagent 的 analyze(resume=True) 续跑；
  * 日志可观测——子进程 stdout/stderr 重定向到 workspace/{task_id}/web_console.log；
  * 不阻塞事件循环，也不会拖垮 Web 服务本身。
- fwagent 没有进度回调，因此由一个 watcher 线程轮询
  workspace/{task_id}/task.json（fwagent 写入的 pipeline_phase/status）、
  web_console.log 和 logs/commands.jsonl，换算出 stage + progress，
  再通过 EventHub 推给 SSE 订阅者。如果未来 fwagent 提供回调接口，
  只需替换 `run_analysis` 里的更新点。
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy.orm import Session

from . import config, security
from .database import SessionLocal
from .models import Task, TaskCredential
from .schemas import StreamEvent
from .task_config import is_current_snapshot, validate_task_config

logger = logging.getLogger("firmxplore.web")

# ---------------------------------------------------------------------------
# fwagent pipeline_phase -> (展示名, 进度百分比)
# phase 值来自 fwagent/pipeline/product.py 中 _phase() 的写入。
# ---------------------------------------------------------------------------
PHASE_MAP: dict[str, tuple[str, float]] = {
    "task_create": ("task create", 3),
    "static_analysis": ("static analysis", 25),
    "investigation_prepare": ("correlation & hypotheses", 50),
    "investigation": ("investigation", 65),
    "finding_finalize": ("finalizing findings", 85),
    "report_generation": ("report generation", 93),
    "completed": ("completed", 100),
    "failed": ("failed", 100),
    "interrupted": ("paused", 100),
}

# fwagent 的 task.json status -> Web 展示状态
STATUS_MAP = {"completed": "success", "partial": "success", "failed": "failed", "paused": "paused"}

MAX_LOG_LINES = 300


class EventHub:
    """每个任务一个订阅者集合，向 SSE 端点分发实时事件。

    watcher 运行在工作线程里，publish() 会被线程调用，
    因此用 loop.call_soon_threadsafe 把事件投递回事件循环。
    """

    def __init__(self) -> None:
        self._subscribers: dict[str, set[asyncio.Queue]] = {}
        self._loop: asyncio.AbstractEventLoop | None = None
        self._lock = threading.Lock()

    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        """在启动时绑定主事件循环（main.py 的 startup 钩子里调用）。"""
        self._loop = loop

    def subscribe(self, task_id: str) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=256)
        with self._lock:
            self._subscribers.setdefault(task_id, set()).add(queue)
        return queue

    def unsubscribe(self, task_id: str, queue: asyncio.Queue) -> None:
        with self._lock:
            self._subscribers.get(task_id, set()).discard(queue)

    def publish(self, task_id: str, event: StreamEvent) -> None:
        """线程安全：工作线程和事件循环都可调用。"""
        self.publish_raw(task_id, "status", event.model_dump_json())

    def publish_raw(self, task_id: str, event_name: str, data: str) -> None:
        """通用事件分发：data 为已序列化的 JSON 字符串。"""
        with self._lock:
            queues = list(self._subscribers.get(task_id, ()))
        loop = self._loop
        if not queues or loop is None or loop.is_closed():
            return
        for queue in queues:
            try:
                loop.call_soon_threadsafe(self._put_nowait, queue, (event_name, data))
            except RuntimeError:
                pass  # 事件循环已关闭

    @staticmethod
    def _put_nowait(queue: asyncio.Queue, item: tuple[str, str]) -> None:
        try:
            queue.put_nowait(item)
        except asyncio.QueueFull:
            pass  # 慢消费者：丢弃，SSE 端点的心跳后会带全量快照兜底


event_hub = EventHub()

# 运行中的分析子进程注册表（task_id -> Popen），stop/resume 通过它操作进程
_processes: dict[str, subprocess.Popen] = {}
_stop_requested: set[str] = set()
_processes_lock = threading.Lock()


def _db_update(task_id: str, **fields) -> None:
    """在独立会话中更新任务行（工作线程/事件循环均可调用）。"""
    db: Session = SessionLocal()
    try:
        task = db.get(Task, task_id)
        if task is None:
            return
        for key, value in fields.items():
            setattr(task, key, value)
        task.updated_at = datetime.now(timezone.utc)
        db.commit()
    except Exception:  # noqa: BLE001
        db.rollback()
        logger.exception("failed to update task %s", task_id)
    finally:
        db.close()


def _snapshot_event(task_id: str, status: str, stage: str, progress: float,
                    log_lines: list[str], error: str | None) -> StreamEvent:
    return StreamEvent(
        task_id=task_id, status=status, stage=stage, progress=progress,
        log_lines=log_lines, error=error,
        timestamp=datetime.now(timezone.utc),
    )


def _format_commands_jsonl(path: Path, limit: int = 30) -> list[str]:
    """把 fwagent CommandRunner 的 commands.jsonl 转成可读日志行。

    每行是一条 JSON 记录（命令、返回码、stdout 摘要），
    这里只取命令与返回码，避免大段 stdout 刷屏。
    """
    lines: list[str] = []
    try:
        raw = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    for entry in raw[-limit:]:
        try:
            record = json.loads(entry)
        except json.JSONDecodeError:
            continue
        cmd = str(record.get("command", ""))[:160]
        returncode = record.get("returncode")
        marker = "ok" if returncode == 0 else f"exit={returncode}"
        lines.append(f"[cmd] {cmd} ({marker})")
    return lines


def _collect_logs(task_dir: Path) -> list[str]:
    """汇总日志：web_console.log（子进程进度输出）优先，其次 commands.jsonl。"""
    lines: list[str] = []
    console = task_dir / "web_console.log"
    if console.exists():
        try:
            lines.extend(console.read_text(encoding="utf-8", errors="replace").splitlines()[-MAX_LOG_LINES:])
        except OSError:
            pass
    commands = task_dir / "logs" / "commands.jsonl"
    if commands.exists():
        lines.extend(_format_commands_jsonl(commands))
    return lines[-MAX_LOG_LINES:]


def _fwagent_state(task_dir: Path) -> dict:
    """读取 fwagent 写入的 task.json（不存在/损坏时返回空 dict）。"""
    path = task_dir / "task.json"
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _report_paths(task_dir: Path) -> dict[str, str]:
    """从 fwagent 的 task.json.report_paths 读取报告索引，兜底扫描 reports/ 目录。"""
    state = _fwagent_state(task_dir)
    paths = state.get("report_paths") or {}
    if paths:
        return {k: str(v) for k, v in paths.items()}
    reports = task_dir / "reports"
    found: dict[str, str] = {}
    if reports.is_dir():
        mapping = {"json": "report.json", "md": "report.md", "html": "report.html"}
        for fmt, name in mapping.items():
            if (reports / name).exists():
                found[fmt] = f"reports/{name}"
    return found


def _watch_progress(task_id: str, task_dir: Path, process: subprocess.Popen, stop: threading.Event) -> None:
    """独立线程：轮询子进程存活 + fwagent 状态 + 日志 + 图文件，直到进程退出或 stop 置位。"""
    last_payload = None
    graph_path = task_dir / "correlation" / "component_graph.json"
    last_graph_sig: tuple[float, int] | None = None
    while not stop.wait(config.PROGRESS_POLL_INTERVAL):
        if process.poll() is not None:
            return  # 子进程已退出，由 run_analysis 收尾
        state = _fwagent_state(task_dir)
        phase = str(state.get("pipeline_phase") or "task_create")
        stage, progress = PHASE_MAP.get(phase, (phase, 10))
        log_lines = _collect_logs(task_dir)
        event = _snapshot_event(task_id, "running", stage, progress, log_lines, None)
        if event.model_dump_json() != last_payload:
            last_payload = event.model_dump_json()
            _db_update(task_id, status="running", stage=stage, progress=progress)
            event_hub.publish(task_id, event)

        # 实时拓扑：correlation/component_graph.json 一旦写出或被改写，
        # 立即推送 graph 事件，前端据此重新拉取并渲染拓扑图
        sig: tuple[float, int] | None = None
        try:
            if graph_path.exists():
                st = graph_path.stat()
                sig = (st.st_mtime, st.st_size)
        except OSError:
            sig = None
        if sig != last_graph_sig:
            last_graph_sig = sig
            if sig is not None:
                try:
                    data = json.loads(graph_path.read_text(encoding="utf-8"))
                    counts = {"nodes": len(data.get("components") or []),
                              "edges": len(data.get("relationships") or [])}
                    event_hub.publish_raw(task_id, "graph", json.dumps(counts))
                except (OSError, json.JSONDecodeError):
                    pass


async def run_analysis(task_id: str, *, resume: bool = False) -> None:
    """asyncio 任务入口（POST /api/analyze 与 /resume 都走这里）。

    编排：写 spec -> 启动 runner 子进程 -> watcher 线程跟踪 -> 收尾回写 DB。
    """
    db: Session = SessionLocal()
    try:
        task = db.get(Task, task_id)
        if task is None:
            return
        if task.owner_id is None or not is_current_snapshot(task.config_json):
            logger.warning("refusing quarantined legacy task %s", task_id)
            return
        cfg = dict(task.config_json or {})
        credential = db.get(TaskCredential, task_id)
        api_key = ""
        if not cfg["deterministic"] and credential is not None:
            if credential.owner_id != task.owner_id:
                raise ValueError("task credential owner mismatch")
            api_key = security.decrypt(credential.ciphertext)
            if api_key is None:
                raise ValueError("task credential cannot be decrypted; reconfigure a new task")
        firmware_path = task.upload_path or ""
        task.status = "running"
        task.stage = "resuming" if resume else PHASE_MAP["task_create"][0]
        db.commit()
    finally:
        db.close()

    task_dir = config.WORKSPACE_ROOT / task_id
    task_dir.mkdir(parents=True, exist_ok=True)
    options = cfg.get("options") or {}

    # Public spec only. The secret travels once over stdin, never an artifact,
    # command-line argument or an inherited parent model configuration.
    spec = {
        "task_id": task_id,
        "firmware_path": firmware_path,
        "workspace": str(config.WORKSPACE_ROOT),
        "log_path": str(task_dir / "web_console.log"),
        "resume": resume,
        "cfg": {k: v for k, v in cfg.items() if k != "options"},
        "options": options,
    }
    spec_path = config.UPLOAD_ROOT / f"{task_id}.spec.json"
    spec_path.parent.mkdir(parents=True, exist_ok=True)
    spec_path.write_text(json.dumps(spec, ensure_ascii=False), encoding="utf-8")

    started = time.monotonic()
    with _processes_lock:
        _stop_requested.discard(task_id)

    def _launch() -> subprocess.Popen:
        process = subprocess.Popen(
            [sys.executable, "-m", "web.server.runner", str(spec_path)],
            cwd=str(config.PROJECT_ROOT),
            stdout=subprocess.DEVNULL,  # 子进程内部已重定向到 web_console.log
            stderr=subprocess.DEVNULL,
            stdin=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            env={key: value for key, value in os.environ.items() if key.upper() in {
                "PATH", "PYTHONPATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "TEMP", "TMP",
                "HOME", "USERPROFILE", "LANG", "LC_ALL", "PYTHONDONTWRITEBYTECODE",
            }},
        )
        try:
            process.stdin.write(json.dumps({"api_key": api_key}) + "\n")
            process.stdin.close()
        except (OSError, ValueError):
            process.kill()
            process.wait(timeout=5)
            raise RuntimeError("runner credential handoff failed") from None
        return process

    process = await asyncio.to_thread(_launch)
    with _processes_lock:
        _processes[task_id] = process

    stop = threading.Event()
    watcher = threading.Thread(target=_watch_progress, args=(task_id, task_dir, process, stop), daemon=True)
    watcher.start()

    status, error = "failed", None
    try:
        # 等待子进程结束（to_thread 不阻塞事件循环）
        returncode = await asyncio.to_thread(process.wait)
        with _processes_lock:
            _processes.pop(task_id, None)

        if task_id in _stop_requested:
            # 用户主动暂停：保留工作区，等待 /resume 续跑
            status = "paused"
            error = None
        else:
            # fwagent 把最终状态写进 task.json；进程码非 0 且无状态记录时视为失败
            fw_status = str(
                _fwagent_state(task_dir).get("status")
                or ("failed" if returncode != 0 else "completed")
            )
            status = STATUS_MAP.get(fw_status, "failed")
            if status == "failed" and returncode != 0:
                crash = _last_console_error(task_dir)
                error = crash or f"分析进程异常退出（exit code {returncode}）"
    except Exception as exc:  # noqa: BLE001
        logger.exception("task %s crashed", task_id)
        error = f"{type(exc).__name__}: {exc}"
        status = "failed"
    finally:
        stop.set()
        watcher.join(timeout=5)
        with _processes_lock:
            _processes.pop(task_id, None)
        spec_path.unlink(missing_ok=True)

    duration = round(time.monotonic() - started, 1)
    report_paths = _report_paths(task_dir) if status in ("success", "failed", "paused") else {}
    # fwagent status=partial 表示部分阶段受阻但报告已生成，Web 层同样视为 success
    final_stage = {
        "success": PHASE_MAP["completed"][0],
        "paused": "paused (resumable)",
        "failed": "failed",
    }[status]
    _db_update(
        task_id, status=status, stage=final_stage, progress=100.0,
        report_paths=report_paths, error=error, duration_seconds=duration,
    )
    event_hub.publish(task_id, _snapshot_event(task_id, status, final_stage, 100.0, _collect_logs(task_dir), error))


def _last_console_error(task_dir: Path) -> str | None:
    """从 web_console.log 尾部找一条像错误的行，给前端展示。"""
    console = task_dir / "web_console.log"
    if not console.exists():
        return None
    try:
        lines = console.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    for line in reversed(lines[-50:]):
        text = line.strip()
        if text and ("ERROR" in text.upper() or "Traceback" in text or text.startswith("ANALYSIS_CRASHED")):
            return text[:500]
    return None


def stop_analysis(task_id: str) -> bool:
    """暂停任务：请求置位 + 终止子进程。进程退出后 run_analysis 会标记 paused。"""
    with _processes_lock:
        _stop_requested.add(task_id)
        process = _processes.get(task_id)
    if process is None or process.poll() is not None:
        with _processes_lock:
            _stop_requested.discard(task_id)
        return False
    try:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
    except OSError:
        logger.exception("failed to terminate task %s", task_id)
    return True


def is_running(task_id: str) -> bool:
    with _processes_lock:
        process = _processes.get(task_id)
    return process is not None and process.poll() is None


def create_task_row(filename: str, upload_path: Path, cfg: dict, file_size: int, *, owner_id: str, api_key: str | None = None) -> str:
    cfg = validate_task_config(cfg)
    if not isinstance(owner_id, str) or not owner_id:
        raise ValueError("task owner required")
    if api_key is not None and (not isinstance(api_key, str) or len(api_key) > 512):
        raise ValueError("invalid private credential type or length")
    task_id = uuid.uuid4().hex[:12]
    db: Session = SessionLocal()
    try:
        db.add(Task(
            id=task_id, owner_id=owner_id, filename=filename, status="pending", stage="queued", progress=0,
            config_json=cfg, upload_path=str(upload_path),
            workspace_path=str(config.WORKSPACE_ROOT / task_id), file_size=file_size,
        ))
        if api_key and not cfg["deterministic"]:
            db.add(TaskCredential(task_id=task_id, owner_id=owner_id, ciphertext=security.encrypt(api_key)))
        db.commit()
    finally:
        db.close()
    return task_id


def delete_task_files(task: Task) -> None:
    """删除任务的上传文件与工作区目录。"""
    for path_str in (task.upload_path, task.workspace_path):
        if not path_str:
            continue
        path = Path(path_str)
        # 只允许删除 workspace / uploads 约定目录内的内容，防止误删
        try:
            if str(config.WORKSPACE_ROOT) in str(path.resolve()) and path.is_dir():
                import shutil
                shutil.rmtree(path, ignore_errors=True)
        except OSError:
            logger.warning("cleanup skipped for %s", path)
