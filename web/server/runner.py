"""分析子进程入口：python -m web.server.runner <spec.json>

为什么用子进程而不是线程：
1. 可暂停——直接 terminate 子进程即可中断 fwagent 的同步流水线；
2. 可恢复——fwagent 的 analyze(resume=True) 支持续跑已有任务；
3. 可观测——子进程的 stdout/stderr（fwagent 的 [N/15] 进度输出）重定向到
   web_console.log，由主进程的 watcher 实时采集并推送给前端。

spec.json 结构：
{
  "task_id": "...",
  "firmware_path": "...",
  "workspace": "...",
  "log_path": "...",
  "resume": false,
  "cfg": {"model_provider": ..., ...},
  "options": {"static_only": false, "fast": false, "no_dynamic": false, "timeout": 600}
}
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path


def _apply_model_config(cfg: dict) -> None:
    """与主进程 tasks._apply_model_config 相同的约定：fwagent 读 MODEL_* 环境变量。"""
    for name in ("MODEL_PROVIDER", "MODEL_NAME", "MODEL_BASE_URL", "MODEL_API_KEY",
                 "FWAGENT_MODEL_PROVIDER", "FWAGENT_MODEL_NAME", "FWAGENT_MODEL_BASE_URL", "FWAGENT_MODEL_API_KEY"):
        os.environ.pop(name, None)
    if cfg.get("deterministic") or cfg.get("model_provider") in ("", "deterministic"):
        os.environ["MODEL_PROVIDER"] = "deterministic"
        os.environ.pop("MODEL_API_KEY", None)
        return
    os.environ["MODEL_PROVIDER"] = cfg["model_provider"]
    if cfg.get("model_name"):
        os.environ["MODEL_NAME"] = cfg["model_name"]
    if cfg.get("base_url"):
        os.environ["MODEL_BASE_URL"] = cfg["base_url"]
    if cfg.get("api_key"):
        os.environ["MODEL_API_KEY"] = cfg["api_key"]


def _read_private_key(stream) -> str:
    raw = stream.readline(4097)
    if len(raw) > 4096:
        raise ValueError("invalid runner credential handoff")
    try:
        value = json.loads(raw)
        key = value["api_key"]
        if set(value) != {"api_key"} or not isinstance(key, str) or len(key) > 512:
            raise ValueError
        return key
    except (ValueError, TypeError, KeyError):
        raise ValueError("invalid runner credential handoff") from None


class _RedactedLog:
    def __init__(self, handle, secret: str):
        self.handle, self.secret = handle, secret

    def write(self, text):
        return self.handle.write(text.replace(self.secret, "[REDACTED]") if self.secret else text)

    def flush(self):
        self.handle.flush()


def main() -> None:
    spec_path = Path(sys.argv[1])
    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    from .task_config import validate_task_config
    spec["cfg"] = validate_task_config({**spec["cfg"], "options": spec.get("options") or {}})
    api_key = _read_private_key(sys.stdin)
    # Only this in-memory copy carries a private field.
    spec["cfg"]["api_key"] = api_key

    log_path = Path(spec["log_path"])
    # stdout/stderr 全部进日志文件：进度行、警告、异常堆栈都会实时出现在前端日志面板
    log_handle = log_path.open("w", encoding="utf-8", buffering=1)  # 行缓冲
    sys.stdout = _RedactedLog(log_handle, api_key)
    sys.stderr = sys.stdout
    os.dup2(log_handle.fileno(), 1)
    os.dup2(log_handle.fileno(), 2)

    from fwagent.pipeline.product import AnalysisPipelineController

    _apply_model_config(spec["cfg"])
    options = spec.get("options") or {}
    exit_code = 0
    try:
        controller = AnalysisPipelineController(spec["workspace"])
        summary = controller.analyze(
            spec["firmware_path"],
            task_id=spec["task_id"],
            resume=bool(spec.get("resume")),
            report_formats={"json", "md", "html"},
            static_only=bool(options.get("static_only")),
            fast=bool(options.get("fast")),
            no_dynamic=bool(options.get("no_dynamic")),
            timeout=int(options.get("timeout") or 600),
        )
        exit_code = int(summary.get("exit_code", 1))
        # 确定性流水线结束后：若配置了模型凭证，追加 fwagent 官方的
        # provider-backed 静态调查（PiAgent），模型按 max_steps 驱动 Ghidra 工具链。
        # 注意：analyze 主流程本身是纯确定性的（fwagent 设计如此，从不调用模型 API），
        # 这是 Web 界面里唯一会消耗模型 token 的环节。
        # 注意：analyze 的 exit_code 在部分阶段受阻时也会是 1（success 仍为 True），
        # 因此用 success 标志而不是 exit_code 判断是否进入模型调查。
        if summary.get("success"):
            _run_model_investigation(spec)
    except Exception as exc:  # noqa: BLE001
        print(f"ANALYSIS_CRASHED: {type(exc).__name__}: {exc}")
        exit_code = 1
    finally:
        log_handle.flush()

    sys.exit(exit_code)


def _model_ready(cfg: dict) -> bool:
    """是否具备调用模型的条件：非确定性模式且四项凭证齐全（fwagent require_credentials 的要求）。"""
    if cfg.get("deterministic") or cfg.get("model_provider") in ("", "deterministic"):
        return False
    return all(str(cfg.get(k) or "").strip() for k in ("model_provider", "model_name", "api_key", "base_url"))


def _private_model_config(cfg: dict):
    """A Web task has one credential authority; never consult shared files/env."""
    from fwagent.model.config import ModelConfig
    from .task_config import validate_endpoint
    if not _model_ready(cfg):
        raise ValueError("task model credentials are incomplete")
    validate_endpoint(cfg["base_url"])
    result = ModelConfig(provider=cfg["model_provider"], model=cfg["model_name"],
                         api_key=cfg["api_key"], base_url=cfg["base_url"])
    result.require_credentials()
    return result


def _remap_to_current_env(path_str: str, workspace_root: str) -> str | None:
    """把其他环境产生的 workspace 绝对路径重映射到当前环境。

    例：任务在 Windows 宿主机创建（rootfs=D:\\...\\workspace\\<id>\\...），
    拿到容器里续跑/调查时挂载点是 /work/workspace/<id>/...。
    以 spec 里的 workspace 根为锚点做相对拼接，而不是硬编码 /work。
    """
    s = path_str.replace("\\", "/")
    anchor = str(Path(workspace_root).resolve())
    idx = s.find(anchor)
    if idx >= 0:
        return str(Path(workspace_root) / s[idx + len(anchor):].lstrip("/"))
    # 兜底：任意 ".../workspace/..." 子串
    generic = s.find("workspace/")
    if generic >= 0:
        return str(Path(workspace_root) / s[generic + len("workspace/"):])
    return None


def _fix_rootfs_paths(spec: dict) -> None:
    """修正 analysis.json 中指向其他环境的 rootfs 路径（P0-2 环境对齐）。

    PiAgent 的 sanity check 和工具都依赖 analysis.json 里的 rootfs 绝对路径，
    跨环境时该路径不存在会导致 priority_binary_exists=False 而拒绝调查。
    仅当重映射后的路径真实存在时才写回，避免破坏有效任务。
    """
    workspace = spec["workspace"]
    analysis_path = Path(workspace) / spec["task_id"] / "reports" / "analysis.json"
    if not analysis_path.exists():
        return
    try:
        data = json.loads(analysis_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    rootfs = str((data.get("extraction") or {}).get("rootfs") or "")
    if not rootfs or Path(rootfs).exists():
        return  # 路径有效或缺失，无需处理
    remapped = _remap_to_current_env(rootfs, workspace)
    if remapped and Path(remapped).exists():
        data["extraction"]["rootfs"] = remapped
        try:
            analysis_path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
            print(f"[model] remapped rootfs: {rootfs} -> {remapped}")
        except OSError as exc:
            print(f"[model] failed to write remapped analysis.json: {exc}")
    else:
        print(f"[model] rootfs path not usable in this environment: {rootfs}")


def _run_model_investigation(spec: dict) -> None:
    """provider-backed 静态调查（等价 CLI: firmxplore investigate <task_id>）。

    PiAgent 会调用 model.chat（消耗 API token），驱动 Ghidra 分析/反编译工具，
    产出 evidence/、hypotheses/、reports/investigation.json。失败只记录日志，
    不影响已完成的确定性分析结果。
    环境对齐（P0-2）：
    - 先修正跨环境的 rootfs 路径，避免 sanity check 的 priority_binary_exists 失败；
    - Ghidra 工具 API 不可用时（如宿主机无 /opt/ghidra）以降级模式重试：
      模型调查循环照常运行（token 照常消耗），Ghidra 工具调用逐个失败返回。
    """
    cfg = spec["cfg"]
    if not _model_ready(cfg):
        print("[model] incomplete credentials (provider/model/api_key/base_url all required) - skipping model investigation")
        return
    _fix_rootfs_paths(spec)
    print(f"[model] starting model investigation: provider={cfg['model_provider']} model={cfg['model_name']}")
    task_dir = Path(spec["workspace"]) / spec["task_id"]
    try:
        from fwagent.investigation.agent import PiAgent
        from fwagent.model.provider import ModelProvider
        from fwagent.model.redaction import redact_value

        class PrivateModelProvider(ModelProvider):
            def chat(self, *args, **kwargs):
                return redact_value(super().chat(*args, **kwargs), [self.config.api_key])

        model_config = _private_model_config(cfg)
        provider = PrivateModelProvider(model_config, timeout=60, usage_log_path=task_dir / "web_model_usage.jsonl")
        model_info = {"provider": model_config.provider, "model": model_config.model}

        def _build(require_ghidra: bool) -> PiAgent:
            return PiAgent(
                spec["workspace"],
                spec["task_id"],
                model=provider,
                model_info=model_info,
                require_ghidra=require_ghidra,
            )

        result = _build(require_ghidra=True).run()
        errors = " ".join(str(e) for e in (result.get("errors") or []))
        if not result.get("success") and "ghidra_tool_api_callable" in errors:
            # Ghidra sanity check 失败 → 降级重试：模型循环照跑，Ghidra 工具逐个失败
            print("[model] ghidra sanity check failed; retrying in degraded mode (no Ghidra tools)")
            result = _build(require_ghidra=False).run()
        _report_investigation_result(result)
    except Exception as exc:  # noqa: BLE001
        print(f"[model] MODEL_ERROR: {type(exc).__name__}: {exc}")
        print("[model] deterministic results unaffected; check provider/base_url/api_key/model config")
        return

    # 模型调查成功后重新生成报告，把 model_investigation 段落写入 report.json（P3）
    if isinstance(result, dict) and result.get("success"):
        try:
            from fwagent.pipeline.product import AnalysisPipelineController

            regen = AnalysisPipelineController(spec["workspace"]).regenerate_report(
                spec["task_id"], report_formats={"json", "md", "html"}
            )
            print(f"[model] report regenerated with model_investigation: success={regen.get('success')}")
        except Exception as exc:  # noqa: BLE001
            print(f"[model] report regeneration failed (investigation results kept on disk): {exc}")


def _report_investigation_result(result: dict) -> None:
    if result.get("success"):
        print(
            f"[model] investigation finished: steps={result.get('steps')}, "
            f"stop_reason={result.get('stop_reason')}, "
            f"evidence={len(result.get('evidence') or [])}, "
            f"hypotheses={len(result.get('hypotheses') or [])}"
        )
        if result.get("degraded"):
            print("[model] note: ran in degraded mode (Ghidra tools unavailable)")
    else:
        print(f"[model] investigation not run: {result.get('errors')}")


if __name__ == "__main__":
    main()
