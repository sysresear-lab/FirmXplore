"""数据库表模型。

tasks 表：Web 层的任务登记表。fwagent 自己会在 workspace/{task_id}/task.json
里保存分析状态，本表负责 Web 展示层的状态、进度、配置快照与报告索引。
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Task(Base):
    __tablename__ = "tasks"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    filename: Mapped[str] = mapped_column(String(512), nullable=False)
    # Null means legacy/unclaimed: never exposed or automatically adopted.
    owner_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)

    # pending -> running -> success / failed
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True, nullable=False)
    stage: Mapped[str] = mapped_column(String(128), default="排队中", nullable=False)
    progress: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)

    # 用户提交时的配置快照（已剔除 API Key，只记录 provider/model/base_url 等非敏感项）
    config_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    # fwagent 报告路径（相对 workspace/{task_id} 的 reports/ 下文件名索引）
    report_paths: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    # 本地文件位置，删除任务时用于清理
    upload_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    workspace_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)

    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    # 运行时长（秒），成功/失败后回填
    duration_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)
    file_size: Mapped[int | None] = mapped_column(Integer, nullable=True)


class AppConfig(Base):
    """单行键值表，存放 provider 配置。

    API_KEY 加密后存放于 key='api_key'（Fernet），
    GET /api/config 永远只返回 api_key_set 布尔位。
    """
    __tablename__ = "app_config"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str | None] = mapped_column(Text, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


class TaskCredential(Base):
    """Private encrypted per-task credential; never part of TaskOut or artifacts."""
    __tablename__ = "task_credentials"
    task_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    owner_id: Mapped[str] = mapped_column(String(32), nullable=False)
    ciphertext: Mapped[str] = mapped_column(Text, nullable=False)
