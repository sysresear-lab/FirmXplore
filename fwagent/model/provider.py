from __future__ import annotations

import http.client
import json
import logging
import re
import socket
import time
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fwagent.model.config import ModelConfig
from fwagent.model.redaction import redact_text

logger = logging.getLogger(__name__)


class ModelProviderError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class ModelProvider:
    """OpenAI 兼容 chat-completions 客户端。

    网络健壮性（P0-1）：
    - 连接超时 / 读超时分离（http.client 直连）：连接 10s，读 120s，
      长补全不会被连接超时误杀；
    - 对瞬态错误（连接重置、远端断开 RemoteDisconnected、超时、HTTP 5xx/429）
      做指数退避重试（最多 3 次，间隔 1s/2s/4s）；4xx 认证/参数错误不重试；
    - 上下文保护：估算 messages token 数（字符数/4 近似），超过
      context_tokens * max_context_ratio 时从最旧的对话轮次开始裁剪；
    - 每次尝试（success/retry/failed）都写入 usage 日志（含 error_message），
      便于对账 provider 后台额度与排查断连。
    """

    MAX_RETRIES = 3
    BACKOFF_SECONDS = (1.0, 2.0, 4.0)
    RETRYABLE_CODES = {
        "MODEL_CONNECTION_TIMEOUT",
        "MODEL_CONNECTION_ERROR",
        "MODEL_RATE_LIMITED",
    }
    # 近似 token 估算：1 token ≈ 4 字符（对混合英文的 JSON 对话足够保守）
    CHARS_PER_TOKEN = 4

    def __init__(
        self,
        config: ModelConfig,
        *,
        timeout: int = 30,
        usage_log_path: str | Path | None = None,
        connect_timeout: float = 10.0,
        read_timeout: float = 120.0,
        context_tokens: int = 65536,
        max_context_ratio: float = 0.6,
    ):
        config.require_credentials()
        self.config = config
        self.timeout = timeout  # 兼容旧签名；实际读超时用 read_timeout
        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout
        self.context_tokens = context_tokens
        self.max_context_tokens = int(context_tokens * max_context_ratio)
        self.usage_log_path = Path(usage_log_path) if usage_log_path else None

    # ------------------------------------------------------------------
    # 对外入口
    # ------------------------------------------------------------------
    def chat(self, messages: list[dict[str, Any]], *, max_tokens: int = 256, temperature: float = 0.0, max_attempts: int | None = None) -> dict[str, Any]:
        messages = self._trim_messages(messages)
        payload = {
            "model": self.config.model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "stream": False,
        }
        body = json.dumps(payload).encode("utf-8")
        start = time.monotonic()
        last_error: ModelProviderError | None = None

        attempts = 1 + self.MAX_RETRIES if max_attempts is None else min(1 + self.MAX_RETRIES, max(1, max_attempts))
        for attempt in range(attempts):
            try:
                data = self._post_chat(body)
                duration = round(time.monotonic() - start, 3)
                result = self._parse_chat_response(data, duration)
                self._log_usage(usage=data.get("usage"), duration=duration, status="success", attempt=attempt + 1)
                result["request_attempts"] = attempt + 1
                return result
            except ModelProviderError as exc:
                last_error = exc
                retryable = self._is_retryable(exc)
                exhausted = attempt + 1 >= attempts
                exc.attempts_used = attempt + 1
                self._log_usage(
                    usage=None,
                    duration=round(time.monotonic() - start, 3),
                    status="failed" if (exhausted or not retryable) else "retry",
                    error_message=str(exc),
                    attempt=attempt + 1,
                )
                if not retryable or exhausted:
                    raise
                delay = self.BACKOFF_SECONDS[min(attempt, len(self.BACKOFF_SECONDS) - 1)]
                logger.warning(
                    "transient model request failure (attempt %d/%d, retry in %.1fs): %s",
                    attempt + 1,
                    attempts,
                    delay,
                    exc,
                )
                time.sleep(delay)
        raise last_error or ModelProviderError("MODEL_CONNECTION_ERROR", "request failed")  # pragma: no cover

    # ------------------------------------------------------------------
    # HTTP 层：连接超时与读超时分离
    # ------------------------------------------------------------------
    def _post_chat(self, body: bytes) -> dict[str, Any]:
        """POST /chat/completions 并解析 JSON。

        用 http.client 直连而不是 urllib：建连用 connect_timeout，
        发出请求后把同一 socket 的读超时改为 read_timeout。
        urllib 的单一 timeout 无法区分两者——长补全会在读阶段被连接超时误杀。
        """
        endpoint = self._endpoint()
        url = urllib.parse.urlsplit(endpoint)
        path = url.path or "/"
        if url.query:
            path += "?" + url.query
        conn_cls = http.client.HTTPSConnection if url.scheme == "https" else http.client.HTTPConnection
        conn = conn_cls(url.hostname, url.port, timeout=self.connect_timeout)
        try:
            conn.request(
                "POST",
                path,
                body=body,
                headers={
                    "Authorization": f"Bearer {self.config.api_key}",
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "Connection": "close",
                },
            )
            if conn.sock is None:
                raise ModelProviderError("MODEL_CONNECTION_ERROR", "connection was not established")
            conn.sock.settimeout(self.read_timeout)
            response = conn.getresponse()
            raw = response.read().decode("utf-8", errors="replace")
            if response.status >= 400:
                raise ModelProviderError(
                    _classify_status(response.status, raw),
                    redact_text(f"{response.status}: {raw[:500]}", [self.config.api_key]),
                )
            try:
                return json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ModelProviderError("MODEL_RESPONSE_INVALID", "response was not valid JSON") from exc
        except ModelProviderError:
            raise
        except (http.client.RemoteDisconnected, ConnectionError, socket.timeout, TimeoutError, OSError) as exc:
            code = "MODEL_CONNECTION_TIMEOUT" if isinstance(exc, (socket.timeout, TimeoutError)) else "MODEL_CONNECTION_ERROR"
            raise ModelProviderError(
                code,
                redact_text(f"{type(exc).__name__}: {exc}"[:300], [self.config.api_key]),
            ) from exc
        finally:
            conn.close()

    def _parse_chat_response(self, data: dict[str, Any], duration: float) -> dict[str, Any]:
        choices = data.get("choices") or []
        first = choices[0] if choices else {}
        message = first.get("message") or {}
        content = message.get("content") or first.get("text") or ""
        return {
            "success": True,
            "content": content,
            "finish_reason": first.get("finish_reason"),
            "model": data.get("model"),
            "usage": data.get("usage"),
            "duration": duration,
        }

    # ------------------------------------------------------------------
    # 上下文保护
    # ------------------------------------------------------------------
    def _estimate_tokens(self, messages: list[dict[str, Any]]) -> int:
        return sum(len(str(item.get("content") or "")) for item in messages) // self.CHARS_PER_TOKEN

    def _trim_messages(self, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """超过上下文预算时从最旧的轮次开始裁剪（保留 system 首条与最后一条）。

        本 agent 的消息结构是 system + (assistant 动作 / user 工具结果) 交替，
        从 messages[1] 开始逐条丢弃即等价于裁剪最旧的 tool_call/tool_result 对。
        """
        trimmed = list(messages)
        inserted_marker = False
        while len(trimmed) > 2 and self._estimate_tokens(trimmed) > self.max_context_tokens:
            del trimmed[1]
            if not inserted_marker:
                trimmed.insert(1, {
                    "role": "user",
                    "content": "[earlier context trimmed to fit the context window; base later steps on recent tool results]",
                })
                inserted_marker = True
        return trimmed

    def _is_retryable(self, exc: ModelProviderError) -> bool:
        if exc.code in self.RETRYABLE_CODES:
            return True
        # HTTP 5xx 通用码（MODEL_REQUEST_INVALID 携带状态码前缀）视为瞬态
        head = str(exc).split(":", 1)[0]
        return bool(re.search(r"\b5\d\d\b", head))

    # ------------------------------------------------------------------
    # usage 日志
    # ------------------------------------------------------------------
    def _log_usage(
        self,
        *,
        usage: dict[str, Any] | None,
        duration: float,
        status: str,
        error_message: str | None = None,
        attempt: int | None = None,
    ) -> None:
        """把每次尝试的消耗/结果状态追加到 JSONL 文件（路径由构造方传入）。"""
        if not self.usage_log_path:
            return
        usage = usage or {}
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "provider": self.config.provider,
            "model": self.config.model,
            "endpoint": self._endpoint(),
            "status": status,
            "attempt": attempt,
            "prompt_tokens": usage.get("prompt_tokens"),
            "completion_tokens": usage.get("completion_tokens"),
            "total_tokens": usage.get("total_tokens"),
            "duration": duration,
            "error_message": error_message,
        }
        try:
            self.usage_log_path.parent.mkdir(parents=True, exist_ok=True)
            with self.usage_log_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, ensure_ascii=True) + "\n")
        except OSError:
            logger.warning("failed to write model usage log", exc_info=True)

    def smoke_test(self, *, max_tokens: int = 64) -> dict[str, Any]:
        result = self.chat(
            [{"role": "user", "content": "Reply with the single word: ok"}],
            max_tokens=max_tokens,
        )
        return {
            "success": True,
            "provider": self.config.provider,
            "model": result["model"] or self.config.model,
            "response": redact_text(result["content"][:120], [self.config.api_key]),
            "duration": result["duration"],
        }

    def _endpoint(self) -> str:
        base = (self.config.base_url or "").rstrip("/")
        if base.endswith("/chat/completions"):
            return base
        return f"{base}/chat/completions"


def _classify_status(status: int, body: str) -> str:
    lowered = body.lower()
    if status in (401, 403):
        return "MODEL_AUTH_FAILED"
    if status == 429:
        return "MODEL_RATE_LIMITED"
    if status == 404:
        return "MODEL_NOT_FOUND"
    if status == 400 and "model" in lowered:
        return "MODEL_NOT_FOUND"
    return "MODEL_REQUEST_INVALID"
