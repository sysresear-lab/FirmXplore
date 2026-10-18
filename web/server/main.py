"""FirmXplore Web 后端入口。

启动方式（开发）：
    uvicorn web.server.main:app --reload --port 8000

生产：
    uvicorn web.server.main:app --host 127.0.0.1 --port 8000 --workers 1
    注意：SSE、asyncio 任务队列都基于进程内状态，请保持 --workers 1，
    多 worker 部署需把任务队列与事件分发移到 Redis 等外部组件。
"""
from __future__ import annotations

import asyncio
import json
import logging
import mimetypes
import shutil
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from sse_starlette.sse import EventSourceResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from fwagent.tools.bounded_io import read_beneath

from . import config, security, tasks
from .database import SessionLocal, get_db, init_db
from .models import AppConfig, Task, TaskCredential
from .task_config import is_current_snapshot, validate_endpoint
from .schemas import (
    AnalyzeResponse,
    ArtifactInfo,
    ArtifactListResponse,
    ConfigStatus,
    ConfigUpdate,
    GraphEdge,
    GraphNode,
    GraphResponse,
    TaskOut,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("firmxplore.web")

app = FastAPI(title="FirmXplore Console", version="0.1.0")


@app.middleware("http")
async def authenticate_web(request: Request, call_next):
    # Protect static pages too: a browser establishes Basic auth before fetching
    # APIs, EventSource streams or direct downloads. No token in URLs/cookies.
    if request.method != "OPTIONS":
        try:
            security.require_principal(request)
        except HTTPException as exc:
            return JSONResponse({"detail": exc.detail}, status_code=exc.status_code, headers=exc.headers)
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    return response

app.add_middleware(
    CORSMiddleware,
    allow_origins=config.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 单机并发闸门：同时运行的分析任务数由 WEB_MAX_CONCURRENT_TASKS 控制
_run_semaphore: asyncio.Semaphore | None = None
_running: set[str] = set()  # 进程内正在执行的任务 id，避免重复提交


@app.on_event("startup")
async def startup() -> None:
    global _run_semaphore
    init_db()
    tasks.event_hub.bind_loop(asyncio.get_running_loop())
    _run_semaphore = asyncio.Semaphore(config.MAX_CONCURRENT_TASKS)
    # 上次服务退出时可能遗留 running/pending 记录（子进程已死），标记为失败
    db: Session = SessionLocal()
    try:
        orphans = db.scalars(select(Task).where(Task.owner_id.is_not(None), Task.status.in_(["running", "pending"]))).all()
        for task in orphans:
            if not is_current_snapshot(task.config_json):
                continue
            task.status = "failed"
            task.error = "服务重启导致任务中断，请重新提交"
        db.commit()
        if orphans:
            logger.warning("marked %d orphaned tasks as failed", len(orphans))
    finally:
        db.close()
    if config.RETENTION_DAYS > 0:
        asyncio.create_task(_cleanup_loop())


# ---------------------------------------------------------------------------
# 配置管理
# ---------------------------------------------------------------------------

_CONFIG_KEYS = ("model_provider", "model_name", "base_url", "deterministic")


def _load_config(db: Session, principal: str) -> dict:
    prefix = principal + ":"
    keys = [prefix + name for name in (*_CONFIG_KEYS, "api_key")]
    rows = {row.key[len(prefix):]: row.value for row in db.scalars(select(AppConfig).where(AppConfig.key.in_(keys)))}
    api_key = security.decrypt(rows["api_key"]) if rows.get("api_key") else None
    cfg = {key: rows.get(key, "") for key in _CONFIG_KEYS}
    cfg["deterministic"] = cfg["deterministic"] in ("1", "true", "True", "")
    cfg["api_key"] = api_key
    if cfg["deterministic"]:
        cfg["model_provider"] = "deterministic"
    return cfg


@app.post("/api/config")
def save_config(body: ConfigUpdate, db: Session = Depends(get_db), principal: str = Depends(security.require_principal)) -> ConfigStatus:
    """保存 provider 配置。api_key 为 None 表示保留旧值；空字符串表示清除。"""
    values: dict[str, str] = {
        "model_provider": "deterministic" if body.deterministic else body.model_provider,
        "model_name": body.model_name,
        "base_url": body.base_url,
        "deterministic": "1" if body.deterministic else "0",
    }
    if not body.deterministic and not body.model_provider:
        raise HTTPException(400, "非确定性模式必须填写 model_provider")
    try:
        validate_endpoint(body.base_url)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None
    previous = _load_config(db, principal)
    if previous.get("api_key") and body.base_url != previous["base_url"] and body.api_key is None:
        raise HTTPException(400, "Changing the model endpoint requires explicitly replacing or clearing its key")
    if body.api_key is not None:
        values["api_key"] = security.encrypt(body.api_key) if body.api_key else ""
    for key, value in values.items():
        scoped_key = principal + ":" + key
        row = db.get(AppConfig, scoped_key)
        if row is None:
            db.add(AppConfig(key=scoped_key, value=value))
        else:
            row.value = value
    db.commit()
    return _config_status(_load_config(db, principal))


def _config_status(cfg: dict) -> ConfigStatus:
    return ConfigStatus(
        model_provider=cfg["model_provider"],
        model_name=cfg["model_name"],
        base_url=cfg["base_url"],
        api_key_set=bool(cfg.get("api_key")),
        deterministic=bool(cfg["deterministic"]),
    )


@app.get("/api/config")
def get_config(db: Session = Depends(get_db), principal: str = Depends(security.require_principal)) -> ConfigStatus:
    """配置状态：绝不返回 API Key 明文。"""
    return _config_status(_load_config(db, principal))


# ---------------------------------------------------------------------------
# 上传与启动分析
# ---------------------------------------------------------------------------

@app.post("/api/analyze")
async def start_analysis(
    file: UploadFile = File(...),
    static_only: bool = Form(False),
    fast: bool = Form(False),
    no_dynamic: bool = Form(False),
    timeout: int = Form(600),
    use_saved_config: bool = Form(True),
    db: Session = Depends(get_db), principal: str = Depends(security.require_principal),
) -> AnalyzeResponse:
    """上传固件并立即返回 task_id，分析在后台执行。"""
    if file.filename is None or not Path(file.filename).suffix.lower() in config.ALLOWED_EXTENSIONS:
        raise HTTPException(400, f"不支持的文件类型，允许：{', '.join(sorted(config.ALLOWED_EXTENSIONS))}")

    # 排队上限：pending/running 任务过多时直接拒绝，避免磁盘被上传文件堆满
    queued = db.scalar(select(func.count(Task.id)).where(Task.status.in_(["pending", "running"]))) or 0
    if queued >= 20:
        raise HTTPException(503, "排队任务过多，请等待现有任务完成后再提交")

    # 读取并落盘上传文件（限制大小，防止内存/磁盘被撑爆）
    max_bytes = config.MAX_UPLOAD_SIZE_MB * 1024 * 1024
    upload_path = config.UPLOAD_ROOT / f"{uuid.uuid4().hex[:8]}_{Path(file.filename).name}"
    size = 0
    try:
        with upload_path.open("wb") as out:
            while chunk := await file.read(1024 * 1024):
                size += len(chunk)
                if size > max_bytes:
                    raise HTTPException(413, f"文件超过 {config.MAX_UPLOAD_SIZE_MB}MB 限制")
                out.write(chunk)
    except HTTPException:
        upload_path.unlink(missing_ok=True)
        raise

    # 配置快照（剔除 API Key），任务详情页据此展示用户当时的选择
    if use_saved_config:
        saved = _load_config(db, principal)
        cfg = {k: saved.get(k) for k in ("model_provider", "model_name", "base_url", "deterministic")}
        api_key = saved.get("api_key") if not cfg["deterministic"] else None
    else:
        cfg = {"model_provider": "deterministic", "model_name": "", "base_url": "", "deterministic": True}
        api_key = None
    cfg["options"] = {"static_only": static_only, "fast": fast, "no_dynamic": no_dynamic, "timeout": timeout}

    task_id = tasks.create_task_row(file.filename, upload_path, cfg, size, owner_id=principal, api_key=api_key)
    # 并发闸门包裹实际的执行协程；_execute 是任务真正排队启动的地方
    asyncio.create_task(_execute(task_id))
    return AnalyzeResponse(task_id=task_id)


async def _execute(task_id: str, *, resume: bool = False) -> None:
    """获取并发闸门后调用 tasks.run_analysis。"""
    async with _run_semaphore:
        _running.add(task_id)
        try:
            await tasks.run_analysis(task_id, resume=resume)
        finally:
            _running.discard(task_id)


# ---------------------------------------------------------------------------
# 任务列表 / 详情 / 删除
# ---------------------------------------------------------------------------

@app.get("/api/tasks")
def list_tasks(status: str | None = None, db: Session = Depends(get_db), principal: str = Depends(security.require_principal)) -> list[TaskOut]:
    query = select(Task).where(Task.owner_id == principal).order_by(Task.created_at.desc())
    if status:
        query = query.where(Task.status == status)
    return [TaskOut.model_validate(t) for t in db.scalars(query) if is_current_snapshot(t.config_json)]


def _get_task_or_404(db: Session, task_id: str, principal: str) -> Task:
    task = db.get(Task, task_id)
    if task is None or task.owner_id != principal:
        raise HTTPException(404, "任务不存在")
    if not is_current_snapshot(task.config_json):
        raise HTTPException(409, "Legacy/private task snapshot is quarantined; create a new task with current credentials")
    return task


@app.get("/api/tasks/{task_id}")
def get_task(task_id: str, db: Session = Depends(get_db), principal: str = Depends(security.require_principal)) -> TaskOut:
    return TaskOut.model_validate(_get_task_or_404(db, task_id, principal))


@app.delete("/api/tasks/{task_id}")
def delete_task(task_id: str, db: Session = Depends(get_db), principal: str = Depends(security.require_principal)) -> dict:
    task = _get_task_or_404(db, task_id, principal)
    if task.status in ("pending", "running") or tasks.is_running(task_id):
        raise HTTPException(409, "任务正在运行，请先暂停再删除")
    tasks.delete_task_files(task)
    credential = db.get(TaskCredential, task_id)
    if credential is not None:
        db.delete(credential)
    db.delete(task)
    db.commit()
    return {"deleted": task_id}


# ---------------------------------------------------------------------------
# 暂停 / 恢复
# ---------------------------------------------------------------------------

@app.post("/api/tasks/{task_id}/stop")
def stop_task(task_id: str, db: Session = Depends(get_db), principal: str = Depends(security.require_principal)) -> dict:
    """暂停任务：终止分析子进程，保留工作区，之后可通过 /resume 续跑。"""
    _get_task_or_404(db, task_id, principal)
    if not tasks.stop_analysis(task_id):
        raise HTTPException(409, "任务当前没有在运行的进程")
    return {"stopped": task_id}


@app.post("/api/tasks/{task_id}/resume")
async def resume_task(task_id: str, db: Session = Depends(get_db), principal: str = Depends(security.require_principal)):
    """恢复已暂停的任务：用 fwagent 的 analyze(resume=True) 在子进程中续跑。"""
    task = _get_task_or_404(db, task_id, principal)
    if task.status != "paused":
        raise HTTPException(409, f"仅已暂停的任务可以恢复（当前：{task.status}）")
    if tasks.is_running(task_id):
        raise HTTPException(409, "任务已在运行中")
    if _run_semaphore is None:
        raise HTTPException(503, "服务尚未就绪")
    asyncio.create_task(_execute(task_id, resume=True))
    return {"resumed": task_id}


# ---------------------------------------------------------------------------
# SSE 实时推送
# ---------------------------------------------------------------------------

@app.get("/api/tasks/{task_id}/stream")
async def stream_task(task_id: str, db: Session = Depends(get_db), principal: str = Depends(security.require_principal)):
    """SSE 流：先推送一次当前全量快照，之后转发 EventHub 的增量事件。

    watcher 每 2s 才轮询一次，订阅后立即发快照可让前端秒级渲染首帧。
    """
    task = _get_task_or_404(db, task_id, principal)
    queue = tasks.event_hub.subscribe(task_id)

    async def generator():
        try:
            snapshot = tasks._snapshot_event(  # noqa: SLF001 初始快照复用内部构造器
                task_id, task.status, task.stage, task.progress,
                tasks._collect_logs(config.WORKSPACE_ROOT / task_id), task.error,
            )
            yield {"event": "status", "data": snapshot.model_dump_json()}
            while True:
                try:
                    # 队列元素为 (事件名, JSON负载) 元组：status=任务状态，graph=拓扑图更新信号
                    event_name, data = await asyncio.wait_for(queue.get(), timeout=15)
                    yield {"event": event_name, "data": data}
                except asyncio.TimeoutError:
                    # 心跳：防止中间代理断开空闲连接
                    yield {"comment": "keep-alive"}
        finally:
            tasks.event_hub.unsubscribe(task_id, queue)

    return EventSourceResponse(generator())


# ---------------------------------------------------------------------------
# 报告
# ---------------------------------------------------------------------------

_REPORT_FILES = {"json": "report.json", "md": "report.md", "html": "report.html"}


@app.get("/api/tasks/{task_id}/report")
def get_report(task_id: str, format: str = "json", db: Session = Depends(get_db), principal: str = Depends(security.require_principal)):
    """返回报告内容。json 解析后返回结构化 JSON；md 返回纯文本；html 以附件下载。"""
    if format not in _REPORT_FILES:
        raise HTTPException(400, "format 仅支持 json|md|html")
    task = _get_task_or_404(db, task_id, principal)
    relative = "reports/" + _REPORT_FILES[format]
    data = _public_artifact_bytes(task_id, relative)
    if format == "json":
        try:
            return JSONResponse(json.loads(data))
        except json.JSONDecodeError:
            raise HTTPException(500, "JSON 报告解析失败")
    if format == "md":
        return PlainTextResponse(data.decode("utf-8"), media_type="text/markdown; charset=utf-8")
    # HTML 以附件方式下载，避免在主站域内执行报告中的任意脚本
    return _attachment(data, f"{task.filename}.report.html", "text/html")


# ---------------------------------------------------------------------------
# 产物浏览与下载
# ---------------------------------------------------------------------------

MAX_ARTIFACTS = 2000
# 产物列表中跳过的中间目录（体积大且对用户无意义）
_SKIPPED_DIRS = {"extracted"}

# A closed export surface: never offer input, logs, spec, environment, private
# configuration or arbitrary files from a task directory for download.
PUBLIC_ARTIFACTS = {
    "reports/report.json", "reports/report.md", "reports/report.html", "reports/analysis.json",
    "pipeline_stages.json", "artifacts/extraction.json", "artifacts/rootfs.json",
    "correlation/component_graph.json", "correlation/summary.json",
    "surface/entry_points.json", "surface/attack_surface_summary.json", "surface/routes.json",
    "taint/summary.json", "taint/taint_paths.json", "findings/findings.json",
}


def _public_artifact_path(task_id: str, relative: str) -> Path:
    if relative not in PUBLIC_ARTIFACTS:
        raise HTTPException(403, "This file is not a public task artifact")
    task_dir = config.WORKSPACE_ROOT / task_id
    current = task_dir
    for part in ("", *relative.split("/")):
        if part:
            current /= part
        try:
            info = current.lstat()
        except FileNotFoundError:
            raise HTTPException(404, "产物尚未生成") from None
        if current.is_symlink() or getattr(info, "st_file_attributes", 0) & 0x400:
            raise HTTPException(403, "Linked task artifacts are not public")
    if not current.resolve().is_relative_to(task_dir.resolve()) or not current.is_file():
        raise HTTPException(404, "文件不存在")
    return current


def _public_artifact_bytes(task_id: str, relative: str) -> bytes:
    _public_artifact_path(task_id, relative)
    try:return read_beneath(config.WORKSPACE_ROOT / task_id, relative, limit=16*1024*1024)
    except FileNotFoundError:raise HTTPException(404, "产物尚未生成") from None
    except (OSError, ValueError):raise HTTPException(403, "Artifact is linked, changed or exceeds the export budget") from None


def _attachment(data: bytes, filename: str, media_type: str | None = None):
    return Response(data, media_type=media_type or "application/octet-stream", headers={
        "Content-Disposition": "attachment; filename*=utf-8''" + quote(filename, safe=""),
        "X-Content-Type-Options": "nosniff",
    })


@app.get("/api/tasks/{task_id}/artifacts")
def list_artifacts(task_id: str, db: Session = Depends(get_db), principal: str = Depends(security.require_principal)) -> ArtifactListResponse:
    _get_task_or_404(db, task_id, principal)
    task_dir = config.WORKSPACE_ROOT / task_id
    if not task_dir.is_dir():
        return ArtifactListResponse(task_id=task_id, artifacts=[], truncated=False)

    artifacts: list[ArtifactInfo] = []
    truncated = False
    for relative in sorted(PUBLIC_ARTIFACTS):
        try:
            path = _public_artifact_path(task_id, relative)
        except HTTPException:
            continue
        rel = path.relative_to(task_dir).as_posix()
        if any(part in _SKIPPED_DIRS for part in path.relative_to(task_dir).parts):
            continue
        if len(artifacts) >= MAX_ARTIFACTS:
            truncated = True
            break
        stat = path.stat()
        artifacts.append(ArtifactInfo(
            path=rel, size=stat.st_size,
            modified_at=datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc),
        ))
    return ArtifactListResponse(task_id=task_id, artifacts=artifacts, truncated=truncated)


@app.get("/api/tasks/{task_id}/artifacts/{artifact_path:path}")
def download_artifact(task_id: str, artifact_path: str, db: Session = Depends(get_db), principal: str = Depends(security.require_principal)):
    """下载产物文件。路径拼接后必须仍位于任务目录内（防目录穿越）。"""
    _get_task_or_404(db, task_id, principal)
    return _attachment(_public_artifact_bytes(task_id, artifact_path), Path(artifact_path).name)


# ---------------------------------------------------------------------------
# 组件关联拓扑图
# ---------------------------------------------------------------------------

@app.get("/api/tasks/{task_id}/graph")
def get_graph(task_id: str, db: Session = Depends(get_db), principal: str = Depends(security.require_principal)) -> GraphResponse:
    """返回组件关联图（correlation 阶段产物）。

    数据源：workspace/{task_id}/correlation/component_graph.json，
    由 fwagent 的 ComponentGraphBuilder 生成；未生成时返回 404，
    前端据此显示"拓扑图尚未生成"。
    """
    _get_task_or_404(db, task_id, principal)
    graph_file = _public_artifact_path(task_id, "correlation/component_graph.json")
    if not graph_file.exists():
        raise HTTPException(404, "拓扑图尚未生成（关联分析阶段完成后可用）")
    try:
        data = json.loads(_public_artifact_bytes(task_id, "correlation/component_graph.json"))
    except (OSError, json.JSONDecodeError):
        raise HTTPException(500, "拓扑图数据解析失败")

    nodes = [
        GraphNode(
            id=c["component_id"],
            name=c.get("name") or c["component_id"],
            type=c.get("component_type") or "unknown",
            path=c.get("path"),
            confidence=float(c.get("confidence", 0.7)),
        )
        for c in data.get("components", [])
    ]
    known_ids = {n.id for n in nodes}
    edges = [
        GraphEdge(
            id=r.get("relationship_id") or f"{r['source_component_id']}->{r['target_component_id']}",
            source=r["source_component_id"],
            target=r["target_component_id"],
            type=r.get("relationship_type") or "related",
            confidence=float(r.get("confidence", 0.5)),
            static_or_dynamic=r.get("static_or_dynamic") or "static",
        )
        for r in data.get("relationships", [])
        if r.get("source_component_id") in known_ids and r.get("target_component_id") in known_ids
    ]
    summary: dict = {}
    summary_file = config.WORKSPACE_ROOT / task_id / "correlation" / "summary.json"
    if summary_file.exists():
        try:
            summary = json.loads(_public_artifact_bytes(task_id, "correlation/summary.json"))
        except (OSError, json.JSONDecodeError):
            pass
    return GraphResponse(task_id=task_id, nodes=nodes, edges=edges, summary=summary)


@app.get("/api/tasks/{task_id}/model-usage")
def get_model_usage(task_id: str, db: Session = Depends(get_db), principal: str = Depends(security.require_principal)) -> dict:
    """模型调用的 token 消耗记录（web_model_usage.jsonl，由 ModelProvider 追加）。

    用于核对 DeepSeek 后台额度：每行是一次 model.chat 的 usage 快照。
    """
    _get_task_or_404(db, task_id, principal)
    usage_file = config.WORKSPACE_ROOT / task_id / "web_model_usage.jsonl"
    if not usage_file.exists():
        return {"task_id": task_id, "calls": [], "totals": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0, "calls": 0}}
    calls = []
    try:
        for line in read_beneath(config.WORKSPACE_ROOT / task_id, "web_model_usage.jsonl", limit=8*1024*1024).decode("utf-8").splitlines():
            if line.strip():
                calls.append(json.loads(line))
    except (OSError, json.JSONDecodeError):
        raise HTTPException(500, "model usage log parse failed")
    totals = {
        "prompt_tokens": sum(c.get("prompt_tokens") or 0 for c in calls),
        "completion_tokens": sum(c.get("completion_tokens") or 0 for c in calls),
        "total_tokens": sum(c.get("total_tokens") or 0 for c in calls),
        "calls": len(calls),
    }
    return {"task_id": task_id, "calls": calls[-50:], "totals": totals}


# ---------------------------------------------------------------------------
# 定期清理
# ---------------------------------------------------------------------------

async def _cleanup_loop() -> None:
    """每小时清理超过保留期的终态任务（DB 行 + 工作区 + 上传文件）。"""
    while True:
        await asyncio.sleep(3600)
        try:
            cutoff = datetime.now(timezone.utc) - timedelta(days=config.RETENTION_DAYS)
            db: Session = SessionLocal()
            try:
                stale = db.scalars(select(Task).where(
                    Task.created_at < cutoff,
                    Task.owner_id.is_not(None),
                    Task.status.in_(["success", "failed"]),
                )).all()
                for task in stale:
                    if not is_current_snapshot(task.config_json):
                        continue
                    tasks.delete_task_files(task)
                    credential = db.get(TaskCredential, task.id)
                    if credential is not None:
                        db.delete(credential)
                    db.delete(task)
                db.commit()
                if stale:
                    logger.info("cleaned %d expired tasks", len(stale))
            finally:
                db.close()
        except Exception:  # noqa: BLE001
            logger.exception("cleanup loop error")


# ---------------------------------------------------------------------------
# 前端静态资源（生产模式：Vite 构建产物由 FastAPI 直接托管）
# ---------------------------------------------------------------------------

_frontend_dist = Path(__file__).resolve().parents[1] / "frontend" / "dist"
if _frontend_dist.is_dir():
    # Vite 的带 hash 资源文件挂载在 /assets；API 路由注册在先，优先级更高。
    # 其余所有 GET 请求走 SPA fallback：命中真实文件则直接返回，否则回退
    # index.html 交给 React Router 处理（保证 /new、/tasks/{id} 刷新不 404）。
    app.mount("/assets", StaticFiles(directory=_frontend_dist / "assets"), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def spa_fallback(full_path: str):
        try:
            data = read_beneath(_frontend_dist, full_path or "index.html", limit=16*1024*1024)
            media_type = mimetypes.guess_type(full_path or "index.html")[0]
        except FileNotFoundError:
            data = read_beneath(_frontend_dist, "index.html", limit=16*1024*1024)
            media_type = "text/html"
        except (OSError, ValueError):
            raise HTTPException(403, "Static path is outside the frontend root or cannot be read safely") from None
        return Response(data, media_type=media_type, headers={"X-Content-Type-Options": "nosniff"})
