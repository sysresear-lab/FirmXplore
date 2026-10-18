"""Pydantic 请求/响应模型（API 对外契约）。

原则：任何响应都不包含 API Key 明文，只返回 api_key_set 布尔位。
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .task_config import public_task_config


class ConfigUpdate(BaseModel):
    """POST /api/config 请求体。

    deterministic=True 表示确定性分析模式，不需要 API Key，
    后端将 MODEL_PROVIDER 置为 deterministic 且不注入凭证。
    api_key 为 None 时表示"不修改已保存的 Key"。
    """
    model_provider: str = Field(default="deterministic", max_length=64)
    model_name: str = Field(default="", max_length=128)
    base_url: str = Field(default="", max_length=512)
    api_key: str | None = Field(default=None, max_length=512)
    deterministic: bool = True


class ConfigStatus(BaseModel):
    """GET /api/config 响应体：只暴露非敏感信息。"""
    model_provider: str
    model_name: str
    base_url: str
    api_key_set: bool
    deterministic: bool


class TaskOut(BaseModel):
    """任务列表/详情条目。"""
    model_config = ConfigDict(from_attributes=True)

    id: str
    filename: str
    status: Literal["pending", "running", "paused", "success", "failed"]
    stage: str
    progress: float
    created_at: datetime
    updated_at: datetime
    config_json: dict[str, Any] | None = None
    report_paths: dict[str, Any] | None = None
    error: str | None = None
    duration_seconds: float | None = None
    file_size: int | None = None

    @field_validator("config_json", mode="before")
    @classmethod
    def public_snapshot(cls, value):
        return public_task_config(value)


class AnalyzeResponse(BaseModel):
    task_id: str


class ArtifactInfo(BaseModel):
    """产物条目：相对任务目录的路径 + 元信息。"""
    path: str
    size: int
    modified_at: datetime | None = None


class ArtifactListResponse(BaseModel):
    task_id: str
    artifacts: list[ArtifactInfo]
    truncated: bool = False


class StreamEvent(BaseModel):
    """SSE 事件负载（data 字段的 JSON 结构）。"""
    task_id: str
    status: str
    stage: str
    progress: float
    log_lines: list[str] = []
    error: str | None = None
    timestamp: datetime


class GraphNode(BaseModel):
    """拓扑图节点：来自 correlation/component_graph.json 的 FirmwareComponent。"""
    id: str
    name: str
    type: str
    path: str | None = None
    confidence: float = 0.7


class GraphEdge(BaseModel):
    """拓扑图边：来自 ComponentRelationship。"""
    id: str
    source: str
    target: str
    type: str
    confidence: float = 0.5
    static_or_dynamic: str = "static"


class GraphResponse(BaseModel):
    task_id: str
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    summary: dict[str, Any] = {}
