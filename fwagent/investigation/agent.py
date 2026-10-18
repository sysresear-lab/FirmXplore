from __future__ import annotations

import json
import hashlib
import logging
import time
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from fwagent.config import Round2Config, load_round2_config
from fwagent.model.config import CONFIGURED_MESSAGE, ModelConfig, ModelConfigError
from fwagent.model.provider import ModelProvider
from fwagent.models import Evidence, Hypothesis
from fwagent.tools.ghidra_api import BinaryToolAPI, DANGEROUS_NAMES

logger = logging.getLogger(__name__)

VALID_HYPOTHESIS_STATUSES = {"candidate", "investigating", "supported", "rejected"}

SYSTEM_PROMPT = """You are performing static security investigation of IoT firmware.

Your task is not to immediately declare vulnerabilities.

You must:
1. inspect available structured evidence
2. identify security-relevant investigation targets
3. select the smallest useful next tool action
4. collect evidence
5. update hypotheses
6. explicitly track missing evidence
7. stop when evidence is insufficient or investigation limits are reached

Important: presence of system(), strcpy(), sprintf(), memcpy(), etc. does NOT by
itself confirm a vulnerability. You must inspect callers, references, and context
before creating a supported hypothesis.

Decompilation guidance (P2-1): decompilation runs on demand, so symbol-level
evidence alone is shallow. For every network_binary or cgi entry point you
investigate, call ghidra.decompile_function on at least 1-2 key functions
(the external-input receiver and the dangerous-call site) BEFORE creating or
promoting a hypothesis. Record the decompiled evidence with evidence.create;
a hypothesis whose evidence only cites import/symbol summaries is weaker than
one backed by decompiled call sites.

Allowed tools:
{tools}

For every security-relevant observation, create an evidence entry. Track your
current best explanation with hypothesis.create and update it with
hypothesis.update. Hypothesis status is limited to candidate, investigating,
supported, or rejected. supported requires at least two consistent evidence
items. Never use confirmed or exploitable.

You must never call shell, bash, subprocess, docker, analyzeHeadless directly, or
arbitrary scripts. Only the structured tools above are available.

Return ONLY a JSON object with this shape:
{{"reason": "short action rationale", "tool": "tool.name", "arguments": {{...}}, "stop": false}}

Set stop to true when evidence is insufficient, the hypothesis is resolved, or
no useful next action exists. Keep reason short; do not include private
chain-of-thought."""


class StaticInvestigator:
    def __init__(self, workspace_root: str | Path, task_id: str, *, config: Round2Config | None = None):
        self.workspace_root = Path(workspace_root).resolve()
        self.task_id = task_id
        self.task_dir = self.workspace_root / task_id
        self.config = config or load_round2_config()
        self.evidence_dir = self.task_dir / "evidence"
        self.hypotheses_dir = self.task_dir / "hypotheses"
        self.reports_dir = self.task_dir / "reports"
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.hypotheses_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.binary_tools = BinaryToolAPI(self.task_dir, config=self.config)
        self.evidence: list[Evidence] = []
        self.hypotheses: list[Hypothesis] = []
        self.tool_sequence: list[dict[str, Any]] = []
        self.steps = 0

    def run(self) -> dict[str, Any]:
        report = self._load_round1_report()
        selected = self._select_binaries(report)
        stop_reason = "completed"
        for item in selected:
            if self.steps >= self.config.agent.max_steps:
                stop_reason = "max_steps_reached"
                break
            binary_path = self._resolve_binary(report, item["path"])
            if not binary_path or not binary_path.exists():
                self._record_sequence("firmware.resolve_binary", item.get("path"), False, ["binary not found"])
                continue
            analysis = self._call_tool("ghidra.analyze_binary", lambda: self.binary_tools.analyze_binary(binary_path))
            if not analysis.get("success"):
                continue
            self._create_evidence_from_analysis(item["path"], analysis.get("result", {}))
            if self.steps >= self.config.agent.max_steps:
                stop_reason = "max_steps_reached"
                break
        self._create_hypotheses()
        output = {
            "task_id": self.task_id,
            "status": "complete",
            "stop_reason": stop_reason,
            "steps": self.steps,
            "selected_binaries": selected,
            "tool_sequence": self.tool_sequence,
            "evidence": [item.to_dict() for item in self.evidence],
            "hypotheses": [item.to_dict() for item in self.hypotheses],
        }
        self._save_json(self.evidence_dir / "evidence.json", output["evidence"])
        self._save_json(self.hypotheses_dir / "hypotheses.json", output["hypotheses"])
        self._save_json(self.reports_dir / "investigation.json", output)
        return output

    def _call_tool(self, name: str, callback):
        if self.steps >= self.config.agent.max_steps:
            return {"success": False, "errors": ["max_steps_reached"]}
        self.steps += 1
        result = callback()
        self.tool_sequence.append(
            {
                "step": self.steps,
                "tool": name,
                "success": bool(result.get("success")),
                "binary": result.get("binary"),
                "warnings": result.get("warnings", []),
                "errors": result.get("errors", []),
            }
        )
        return result

    def _create_evidence_from_analysis(self, report_binary_path: str, result: dict[str, Any]) -> None:
        summary = result.get("summary", {})
        imports = result.get("imports", [])
        strings = result.get("strings", [])
        functions = result.get("functions", [])
        dangerous_imports = [item.get("name") for item in imports if item.get("name") in DANGEROUS_NAMES or item.get("dangerous")]
        for name in sorted(set(filter(None, dangerous_imports))):
            self._add_evidence(
                type_="function_call",
                binary=report_binary_path,
                function=None,
                address=None,
                description=f"Binary imports or references {name}()",
                source_tool="ghidra.analyze_binary",
                confidence=1.0 if summary.get("analyzer") == "ghidra" else 0.8,
                metadata={"symbol": name},
            )
        interesting_values = [item.get("value", "") if isinstance(item, dict) else str(item) for item in strings]
        for token in ("/bin/sh", "HTTP", "GET ", "POST ", "cgi"):
            if any(token in value for value in interesting_values):
                self._add_evidence(
                    type_="interesting_string",
                    binary=report_binary_path,
                    function=None,
                    address=None,
                    description=f"Binary contains string marker {token.strip()}",
                    source_tool="ghidra.analyze_binary",
                    confidence=0.8,
                    metadata={"marker": token.strip()},
                )
        if functions:
            self._add_evidence(
                type_="function_inventory",
                binary=report_binary_path,
                function=None,
                address=None,
                description=f"Discovered {len(functions)} functions",
                source_tool="ghidra.analyze_binary",
                confidence=0.9,
                metadata={"function_count": len(functions)},
            )

    def _create_hypotheses(self) -> None:
        by_binary: dict[str, list[Evidence]] = {}
        for item in self.evidence:
            if item.binary:
                by_binary.setdefault(item.binary, []).append(item)
        for binary, evidence in by_binary.items():
            has_command_sink = any(item.metadata.get("symbol") in {"system", "popen", "execv", "execve"} for item in evidence)
            has_web_marker = any(item.metadata.get("marker") in {"HTTP", "GET", "POST", "cgi"} for item in evidence)
            if has_command_sink and has_web_marker:
                related_ids = [item.id for item in evidence if item.type in {"function_call", "interesting_string"}]
                self.hypotheses.append(
                    Hypothesis(
                        id=self._next_hypothesis_id(),
                        title=f"Potential web-to-command execution path in {binary}",
                        cwe="CWE-78",
                        status="investigating",
                        confidence=0.45,
                        evidence_ids=related_ids,
                        missing_evidence=[
                            "Identify caller function that connects external input to command sink",
                            "Decompile the caller and inspect dataflow statically",
                            "Dynamic confirmation is out of scope for Round 2",
                        ],
                        next_actions=[
                            "ghidra.find_function_references for command sink",
                            "ghidra.decompile_function on candidate caller",
                        ],
                    )
                )
        if not self.hypotheses:
            self.hypotheses.append(
                Hypothesis(
                    id=self._next_hypothesis_id(),
                    title="No sufficiently supported static security hypothesis found",
                    cwe=None,
                    status="rejected",
                    confidence=0.5,
                    evidence_ids=[item.id for item in self.evidence[:10]],
                    missing_evidence=["More caller/callee or decompilation evidence would be required"],
                    next_actions=[],
                )
            )

    def _add_evidence(
        self,
        *,
        type_: str,
        binary: str | None,
        function: str | None,
        address: str | None,
        description: str,
        source_tool: str,
        confidence: float,
        metadata: dict[str, Any],
    ) -> None:
        self.evidence.append(
            Evidence(
                id=self._next_evidence_id(),
                type=type_,
                binary=binary,
                function=function,
                address=address,
                description=description,
                source_tool=source_tool,
                confidence=confidence,
                metadata=metadata,
            )
        )

    def _select_binaries(self, report: dict[str, Any]) -> list[dict[str, Any]]:
        priority = report.get("priority_binaries", [])
        selected = [
            item
            for item in priority
            if item.get("score", 0) >= self.config.ghidra.minimum_priority_score
        ]
        if not selected:
            selected = priority
        return selected[: min(3, self.config.agent.max_binary_analyses)]

    def _resolve_binary(self, report: dict[str, Any], binary_path: str) -> Path | None:
        if not binary_path:
            return None
        rootfs = report.get("extraction", {}).get("rootfs")
        if not rootfs:
            return None
        if binary_path.startswith("/"):
            return Path(rootfs) / binary_path.lstrip("/")
        return Path(binary_path)

    def _load_round1_report(self) -> dict[str, Any]:
        path = self.reports_dir / "analysis.json"
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)

    def _next_evidence_id(self) -> str:
        return f"E-{len(self.evidence) + 1:04d}"

    def _next_hypothesis_id(self) -> str:
        return f"H-{len(self.hypotheses) + 1:04d}"

    def _record_sequence(self, tool: str, binary: str | None, success: bool, errors: list[str]) -> None:
        self.steps += 1
        self.tool_sequence.append(
            {
                "step": self.steps,
                "tool": tool,
                "success": success,
                "binary": binary,
                "warnings": [],
                "errors": errors,
            }
        )

    def _save_json(self, path: Path, data: Any) -> None:
        with path.open("w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
            handle.write("\n")


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    arguments_schema: dict[str, dict[str, Any]]
    handler: Callable[[dict[str, Any]], dict[str, Any]]


class PiAgent:
    def __init__(
        self,
        workspace_root: str | Path,
        task_id: str,
        *,
        config: Round2Config | None = None,
        model: Any = None,
        model_info: dict[str, str] | None = None,
        binary: str | None = None,
        max_steps: int | None = None,
        max_binary_analyses: int | None = None,
        max_decompilations_per_binary: int | None = None,
        binary_api_workspace: str | Path | None = None,
        require_ghidra: bool = True,
    ):
        self.workspace_root = Path(workspace_root).resolve()
        self.task_id = task_id
        self.task_dir = self.workspace_root / task_id
        self.config = config or load_round2_config()
        agent = self.config.agent
        self.max_steps = max_steps if max_steps is not None else agent.max_steps
        self.max_binary_analyses = max_binary_analyses if max_binary_analyses is not None else agent.max_binary_analyses
        self.max_decompilations_per_binary = (
            max_decompilations_per_binary
            if max_decompilations_per_binary is not None
            else agent.max_decompilations_per_binary
        )

        self.evidence_dir = self.task_dir / "evidence"
        self.hypotheses_dir = self.task_dir / "hypotheses"
        self.reports_dir = self.task_dir / "reports"
        self.agent_dir = self.task_dir / "agent"
        for directory in (self.evidence_dir, self.hypotheses_dir, self.reports_dir, self.agent_dir):
            directory.mkdir(parents=True, exist_ok=True)

        self.model = model
        self.model_info = dict(model_info or {})
        self.binary = binary
        self.binary_tools = BinaryToolAPI(
            binary_api_workspace or self.task_dir,
            config=self.config,
        )
        self.tools = self._build_tools()
        self.evidence: list[Evidence] = []
        self._trusted_evidence: dict[str, str] = {}
        self.hypotheses: list[Hypothesis] = []
        self.tool_trace: list[dict[str, Any]] = []
        self.steps = 0
        self.model_calls = 0
        self.budget_used = 0
        self.parse_errors = 0
        self.model_trace: list[dict[str, Any]] = []
        self.stop_reason = "completed"
        self.model_error: str | None = None
        self.report: dict[str, Any] | None = None
        self.report_error: str | None = None
        self.binaries_seen: set[str] = set()
        self.decompilation_counts: dict[str, int] = defaultdict(int)
        self.sanity_checks: dict[str, bool] = {}
        # 降级模式：Ghidra 工具 API 不可用时仍允许模型驱动的调查循环
        # （Ghidra 工具调用会在运行时逐个失败，模型收到失败结果后继续推理）。
        # require_ghidra=False 时 sanity check 不再因 Ghidra 缺失而拒绝运行。
        self.require_ghidra = require_ghidra
        self.degraded = False
        # P0-1：provider 瞬态错误容错参数与错误记录
        self.max_consecutive_model_failures = 3
        self.model_errors: list[str] = []

        try:
            self.report = self._load_report()
        except Exception as exc:  # noqa: BLE001 - report loading must not abort construction
            self.report_error = str(exc)

    def run(self) -> dict[str, Any]:
        checks = self.sanity_check()
        self.sanity_checks = checks
        if self.report is None:
            return {
                "success": False,
                "status": "invalid",
                "errors": [self.report_error or "analysis.json unavailable"],
                "sanity_checks": checks,
            }
        failed = [name for name, ok in checks.items() if not ok]
        if failed:
            return {
                "success": False,
                "status": "invalid",
                "errors": [f"sanity check failed: {name}" for name in failed],
                "sanity_checks": checks,
            }
        if self.model is None:
            raise ModelConfigError(CONFIGURED_MESSAGE)

        self._run_loop()
        self._finalize_hypotheses()
        output = self._summary()
        self._save_outputs(output)
        return output

    def dry_run(self, model_config: ModelConfig | None = None) -> dict[str, Any]:
        checks = self.sanity_check()
        errors = [f"sanity check failed: {name}" for name, ok in checks.items() if not ok]
        selected = self._selected_binary()
        if not selected:
            errors.append("no priority binary available")
        model_info: dict[str, Any] = {
            "provider": None,
            "model": None,
            "base_url": None,
            "api_key_present": False,
        }
        if model_config is not None:
            model_info = model_config.safe_dict()
            try:
                model_config.require_credentials()
            except ModelConfigError as exc:
                errors.append(str(exc).splitlines()[0])
        else:
            errors.append("model configuration not available")
        return {
            "ready": not errors,
            "task": self.task_id,
            "binary": selected,
            "model": model_info,
            "tools": [spec.name for spec in self.tools.values()],
            "limits": {
                "steps": self.max_steps,
                "binaries": self.max_binary_analyses,
                "decompilations": self.max_decompilations_per_binary,
            },
            "errors": errors,
            "sanity_checks": checks,
        }

    def sanity_check(self) -> dict[str, bool]:
        report_exists = (self.task_dir / "reports" / "analysis.json").exists()
        binary = self._resolve_binary(self._selected_binary() or "")
        environment = self.binary_tools.runtime.check_environment()
        ghidra_ok = bool(environment.get("success"))
        if not ghidra_ok and not self.require_ghidra:
            # 降级：记录状态但不阻塞模型调查（模型调用比工具执行更重要）
            self.degraded = True
            logger.warning(
                "ghidra tool api unavailable; running PiAgent in degraded mode (model loop only)"
            )
            ghidra_ok = True
        return {
            "workspace_exists": self.task_dir.exists(),
            "analysis_json_exists": report_exists,
            "priority_binary_exists": bool(binary and binary.exists()),
            "ghidra_tool_api_callable": ghidra_ok,
        }

    def _run_loop(self) -> None:
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": SYSTEM_PROMPT.format(tools=self._tool_descriptions())},
            {"role": "user", "content": self._initial_prompt()},
        ]
        malformed = 0
        # P0-1：provider 层的瞬态错误（断连/超时/5xx）不再终止整个调查——
        # 记入 model_errors 并继续下一轮；连续 max_consecutive_model_failures
        # 次失败才判定 model_error 终止。
        consecutive_failures = 0
        while self.budget_used < self.max_steps:
            remaining = self.max_steps - self.budget_used
            self.model_calls += 1
            self.budget_used += 1
            request = {"call": self.model_calls, "budget_used": self.budget_used, "request_attempts": 1, "status": "running"}
            self.model_trace.append(request)
            try:
                if isinstance(self.model, ModelProvider):
                    response = self.model.chat(messages, max_tokens=800, max_attempts=remaining)
                else:
                    response = self.model.chat(messages, max_tokens=800)
                attempts = min(remaining, max(1, int(response.get("request_attempts", 1)))) if isinstance(response, dict) else 1
                self.budget_used += attempts - 1
                request.update(request_attempts=attempts, budget_used=self.budget_used, status="returned")
            except Exception as exc:  # noqa: BLE001 - 模型失败先容错再终止
                attempts = min(remaining, max(1, int(getattr(exc, "attempts_used", 1))))
                self.budget_used += attempts - 1
                request.update(request_attempts=attempts, budget_used=self.budget_used, status="model_error", error=str(exc))
                self.model_errors.append(str(exc))
                consecutive_failures += 1
                if consecutive_failures >= self.max_consecutive_model_failures:
                    self.stop_reason = "model_error"
                    self.model_error = str(exc)
                    break
                logger.warning(
                    "transient model failure (%d/%d consecutive): %s",
                    consecutive_failures,
                    self.max_consecutive_model_failures,
                    exc,
                )
                continue
            if not isinstance(response, dict):
                response = {"success": True, "content": None}
            if not response.get("success"):
                request["status"] = "model_error"
                self.model_errors.append(str(response.get("error") or "model request failed"))
                consecutive_failures += 1
                if consecutive_failures >= self.max_consecutive_model_failures:
                    self.stop_reason = "model_error"
                    self.model_error = str(response.get("error") or "model request failed")
                    break
                continue
            consecutive_failures = 0

            action = self._parse_action(response.get("content", ""))
            if action is None:
                malformed += 1
                self.parse_errors += 1
                request["status"] = "invalid_model_output"
                messages.append(
                    {
                        "role": "user",
                        "content": (
                            "Your previous response was not valid JSON. Return ONLY a JSON object "
                            "with keys: reason, tool, arguments, stop."
                        ),
                    }
                )
                if malformed >= 2:
                    self.stop_reason = "invalid_model_output"
                    break
                continue

            request["status"] = "valid_action"
            if action.get("stop"):
                self.stop_reason = "model_stopped"
                break

            tool_name = str(action.get("tool") or "")
            args = action.get("arguments") or {}
            reason = str(action.get("reason") or "")
            spec = self.tools.get(tool_name)
            if spec is None:
                self._record_trace(
                    tool_name,
                    args,
                    {"success": False, "errors": [f"unknown tool: {tool_name}"]},
                    0.0,
                    reason,
                )
                messages.append({"role": "user", "content": f"Unknown tool {tool_name}. Retry with an allowed tool."})
                continue

            validation = self._validate_call(spec, args)
            if validation["errors"]:
                self._record_trace(tool_name, args, {"success": False, "errors": validation["errors"]}, 0.0, reason)
                messages.append({"role": "user", "content": "Invalid arguments: " + "; ".join(validation["errors"])})
                continue

            normalized = validation["arguments"]
            limit_error = self._check_limits(tool_name, normalized)
            if limit_error:
                self._record_trace(tool_name, normalized, {"success": False, "errors": [limit_error]}, 0.0, reason)
                messages.append({"role": "user", "content": limit_error})
                continue

            start = time.monotonic()
            try:
                result = spec.handler(normalized)
            except Exception as exc:  # noqa: BLE001 - tool execution failures stay in trace
                result = {"success": False, "errors": [f"tool execution failed: {exc}"]}
            duration = round(time.monotonic() - start, 3)
            self._record_trace(tool_name, normalized, result, duration, reason)
            self._auto_record_evidence(tool_name, normalized, result)
            messages.append(
                {
                    "role": "assistant",
                    "content": json.dumps(
                        {"tool": tool_name, "arguments": normalized, "reason": reason},
                        ensure_ascii=True,
                    ),
                }
            )
            messages.append({"role": "user", "content": f"Tool result:\n{self._compact_result(result)}"})
            if self._stop_after_tool():
                break
        else:
            self.stop_reason = "max_steps_reached"

    def _finalize_hypotheses(self) -> None:
        for item in self.hypotheses:
            if item.status == "supported" and self._evidence_error(item.evidence_ids, supported=True):
                item.status = "investigating"
                item.missing_evidence.append("Supported status rejected: current tool evidence provenance is insufficient")
        if not self.hypotheses:
            dangerous = [
                item
                for item in self.evidence
                if item.type in {"dangerous_function_reference", "function_reference"}
                and item.metadata.get("symbol") in DANGEROUS_NAMES
            ]
            if dangerous:
                binary = dangerous[0].binary or "firmware binary"
                self.hypotheses.append(
                    Hypothesis(
                        id=self._next_hypothesis_id(),
                        title=f"Potential command execution path in {binary}",
                        cwe="CWE-78",
                        status="investigating",
                        confidence=0.4,
                        evidence_ids=[item.id for item in dangerous],
                        missing_evidence=[
                            "Identify caller function that connects external input to command sink",
                            "Decompile the caller and inspect dataflow statically",
                            "Dynamic confirmation is out of scope for Round 2",
                        ],
                        next_actions=[
                            "ghidra.find_function_references for command sink",
                            "ghidra.decompile_function on candidate caller",
                        ],
                    )
                )
            else:
                self.hypotheses.append(
                    Hypothesis(
                        id="H-0001",
                        title="No sufficiently supported security hypothesis found",
                        cwe=None,
                        status="rejected",
                        confidence=0.5,
                        evidence_ids=[item.id for item in self.evidence[:10]],
                        missing_evidence=["Caller/callee and decompilation evidence would be required"],
                        next_actions=[],
                    )
                )

    def _auto_record_evidence(self, tool_name: str, args: dict[str, Any], result: dict[str, Any]) -> None:
        if not result.get("success"):
            return
        binary = args.get("binary")
        data = result.get("result")
        if tool_name == "ghidra.get_binary_summary":
            summary = data.get("summary", {}) if isinstance(data, dict) else {}
            function_count = summary.get("function_count")
            if function_count:
                self._add_auto_evidence(
                    type_="binary_summary",
                    binary=binary,
                    function=None,
                    address=None,
                    description=f"Ghidra summary: {function_count} functions, {summary.get('language')}",
                    source_tool="ghidra",
                    confidence=0.9,
                    metadata={
                        "function_count": function_count,
                        "language": summary.get("language"),
                        "analyzer": summary.get("analyzer"),
                    },
                )
            imports = data.get("imports", []) if isinstance(data, dict) else []
            dangerous = [item.get("name") for item in imports if item.get("dangerous") or item.get("name") in DANGEROUS_NAMES]
            for name in sorted(set(filter(None, dangerous))):
                self._add_auto_evidence(
                    type_="dangerous_function_reference",
                    binary=binary,
                    function=None,
                    address=None,
                    description=f"Binary imports or references {name}()",
                    source_tool="ghidra",
                    confidence=0.8,
                    metadata={"symbol": name},
                )
        elif tool_name == "ghidra.search_functions":
            matches = data.get("functions", []) if isinstance(data, dict) else []
            for item in matches[:10]:
                name = item.get("name", "")
                if name in DANGEROUS_NAMES or any(token in name.lower() for token in ("cgi", "fastcgi", "exec", "system")):
                    self._add_auto_evidence(
                        type_="function_reference",
                        binary=binary,
                        function=name,
                        address=item.get("address"),
                        description=f"Function {name} matched security query {args.get('query')}",
                        source_tool="ghidra",
                        confidence=0.7,
                        metadata={"symbol": name, "query": args.get("query")},
                    )
        elif tool_name in {"ghidra.get_callers", "ghidra.get_callees", "ghidra.find_function_references", "ghidra.find_references"}:
            key = {
                "ghidra.get_callers": "callers",
                "ghidra.get_callees": "callees",
                "ghidra.find_function_references": "references",
                "ghidra.find_references": "references",
            }[tool_name]
            edges = data.get(key, []) if isinstance(data, dict) else []
            for edge in edges[:10]:
                self._add_auto_evidence(
                    type_="callgraph_reference",
                    binary=binary,
                    function=None,
                    address=edge.get("caller_address") or edge.get("callee_address"),
                    description=f"Callgraph {tool_name} for {args.get('function') or args.get('address')}",
                    source_tool="ghidra",
                    confidence=0.7,
                    metadata={"edge": edge},
                )
        elif tool_name == "ghidra.find_string":
            strings = data.get("strings", []) if isinstance(data, dict) else []
            for item in strings[:10]:
                self._add_auto_evidence(
                    type_="interesting_string",
                    binary=binary,
                    function=None,
                    address=None,
                    description=f"String matches {args.get('query')}",
                    source_tool="ghidra",
                    confidence=0.7,
                    metadata={"query": args.get("query"), "value": str(item.get("value", ""))[:200]},
                )
        elif tool_name == "ghidra.decompile_function":
            if not isinstance(data,dict) or not isinstance(data.get('decompiled_code'),str) or not data['decompiled_code'].strip():
                return
            name = (data.get("name") if isinstance(data, dict) else None) or args.get("function")
            self._add_auto_evidence(
                type_="decompilation",
                binary=binary,
                function=name,
                address=None,
                description=f"Decompiled {name}",
                source_tool="ghidra",
                confidence=0.9,
                metadata={"function": name, "success": bool(result.get("success"))},
            )

    def _add_auto_evidence(
        self,
        *,
        type_: str,
        binary: str | None,
        function: str | None,
        address: str | None,
        description: str,
        source_tool: str,
        confidence: float,
        metadata: dict[str, Any],
    ) -> None:
        for item in self.evidence:
            if item.id in self._trusted_evidence and item.type == type_ and item.binary == binary and item.description == description:
                return
        self.evidence.append(
            Evidence(
                id=self._next_evidence_id(),
                type=type_,
                binary=binary,
                function=function,
                address=address,
                description=description,
                source_tool=source_tool,
                confidence=confidence,
                metadata=metadata,
            )
        )
        item = self.evidence[-1]
        self._trusted_evidence[item.id] = self._evidence_fingerprint(item)

    def _summary(self) -> dict[str, Any]:
        supported = any(item.status == "supported" and not self._evidence_error(item.evidence_ids, supported=True) for item in self.hypotheses)
        last_error = bool(self.model_trace and self.model_trace[-1]["status"] in {"invalid_model_output", "model_error"})
        all_tools_failed = bool(self.tool_trace) and not any(item["success"] for item in self.tool_trace)
        failed = self.stop_reason in {"invalid_model_output", "model_error"} or (self.stop_reason == "max_steps_reached" and (last_error or all_tools_failed or self.max_steps <= 0))
        return {
            "success": not failed,
            "status": "failed" if failed else "complete",
            "errors": ["model protocol/request budget failed: " + self.stop_reason] if failed else [],
            "model_calls": self.model_calls,
            "budget_used": self.budget_used,
            "budget_limit": self.max_steps,
            "parse_errors": self.parse_errors,
            "model_trace": self.model_trace,
            "task_id": self.task_id,
            "model": self.model_info,
            "target": self._selected_binary(),
            "steps": self.steps,
            "tool_calls": len(self.tool_trace),
            "evidence_count": len(self.evidence),
            "hypothesis_count": len(self.hypotheses),
            "stop_reason": self.stop_reason,
            "model_error": self.model_error,
            "model_errors": list(self.model_errors),
            "degraded": self.degraded,
            "result": (
                "SUPPORTED STATIC HYPOTHESIS"
                if supported
                else "No sufficiently supported security hypothesis found."
            ),
            "sanity_checks": self.sanity_checks,
            "evidence": [item.to_dict() for item in self.evidence],
            "hypotheses": [item.to_dict() for item in self.hypotheses],
        }

    def _save_outputs(self, output: dict[str, Any]) -> None:
        self._save_json(self.evidence_dir / "evidence.json", output["evidence"])
        self._save_json(self.hypotheses_dir / "hypotheses.json", output["hypotheses"])
        self._save_json(self.agent_dir / "tool_trace.json", self.tool_trace)
        self._save_json(self.agent_dir / "model_trace.json", self.model_trace)
        self._save_json(self.reports_dir / "investigation.json", output)

    def _build_tools(self) -> dict[str, ToolSpec]:
        return {
            "firmware.get_summary": ToolSpec(
                "firmware.get_summary",
                "Return firmware metadata, architecture, services, web surface, and priority binaries.",
                {},
                self._tool_firmware_summary,
            ),
            "firmware.get_priority_binaries": ToolSpec(
                "firmware.get_priority_binaries",
                "Return the priority binary list with scores.",
                {},
                self._tool_firmware_priority,
            ),
            "ghidra.get_binary_summary": ToolSpec(
                "ghidra.get_binary_summary",
                "Return the structured Ghidra/static summary for one binary.",
                {"binary": {"type": "string", "required": True}},
                self._tool_get_binary_summary,
            ),
            "ghidra.list_functions": ToolSpec(
                "ghidra.list_functions",
                "List functions for one binary.",
                {"binary": {"type": "string", "required": True}},
                self._tool_list_functions,
            ),
            "ghidra.search_functions": ToolSpec(
                "ghidra.search_functions",
                "Search functions by name substring.",
                {"binary": {"type": "string", "required": True}, "query": {"type": "string", "required": True}},
                self._tool_search_functions,
            ),
            "ghidra.find_string": ToolSpec(
                "ghidra.find_string",
                "Find strings containing a substring.",
                {"binary": {"type": "string", "required": True}, "query": {"type": "string", "required": True}},
                self._tool_find_string,
            ),
            "ghidra.find_references": ToolSpec(
                "ghidra.find_references",
                "Find callgraph references by address.",
                {"binary": {"type": "string", "required": True}, "address": {"type": "string", "required": True}},
                self._tool_find_references,
            ),
            "ghidra.find_function_references": ToolSpec(
                "ghidra.find_function_references",
                "Find callgraph references by function name.",
                {"binary": {"type": "string", "required": True}, "function": {"type": "string", "required": True}},
                self._tool_find_function_references,
            ),
            "ghidra.get_callers": ToolSpec(
                "ghidra.get_callers",
                "Return callers of a function.",
                {"binary": {"type": "string", "required": True}, "function": {"type": "string", "required": True}},
                self._tool_get_callers,
            ),
            "ghidra.get_callees": ToolSpec(
                "ghidra.get_callees",
                "Return callees of a function.",
                {"binary": {"type": "string", "required": True}, "function": {"type": "string", "required": True}},
                self._tool_get_callees,
            ),
            "ghidra.decompile_function": ToolSpec(
                "ghidra.decompile_function",
                "Decompile or disassemble one function.",
                {"binary": {"type": "string", "required": True}, "function": {"type": "string", "required": True}},
                self._tool_decompile_function,
            ),
            "evidence.create": ToolSpec(
                "evidence.create",
                "Create an evidence entry for an observation.",
                {
                    "type": {"type": "string", "required": True},
                    "binary": {"type": "string", "required": False},
                    "function": {"type": "string", "required": False},
                    "address": {"type": "string", "required": False},
                    "description": {"type": "string", "required": True},
                    "source_tool": {"type": "string", "required": False},
                    "confidence": {"type": "number", "required": False},
                    "metadata": {"type": "object", "required": False},
                },
                self._tool_evidence_create,
            ),
            "hypothesis.create": ToolSpec(
                "hypothesis.create",
                "Create a hypothesis with status candidate/investigating/supported/rejected.",
                {
                    "title": {"type": "string", "required": True},
                    "cwe": {"type": "string", "required": False},
                    "status": {"type": "string", "required": False},
                    "confidence": {"type": "number", "required": False},
                    "evidence_ids": {"type": "array", "required": False},
                    "missing_evidence": {"type": "array", "required": False},
                    "next_actions": {"type": "array", "required": False},
                },
                self._tool_hypothesis_create,
            ),
            "hypothesis.update": ToolSpec(
                "hypothesis.update",
                "Update an existing hypothesis.",
                {
                    "id": {"type": "string", "required": True},
                    "title": {"type": "string", "required": False},
                    "cwe": {"type": "string", "required": False},
                    "status": {"type": "string", "required": False},
                    "confidence": {"type": "number", "required": False},
                    "evidence_ids": {"type": "array", "required": False},
                    "missing_evidence": {"type": "array", "required": False},
                    "next_actions": {"type": "array", "required": False},
                },
                self._tool_hypothesis_update,
            ),
        }

    def _tool_firmware_summary(self, args: dict[str, Any]) -> dict[str, Any]:
        return {"success": True, "tool": "firmware.get_summary", "result": self._state_summary()}

    def _tool_firmware_priority(self, args: dict[str, Any]) -> dict[str, Any]:
        priority = (self.report or {}).get("priority_binaries") or []
        return {
            "success": True,
            "tool": "firmware.get_priority_binaries",
            "result": [
                {
                    "path": item.get("path"),
                    "score": item.get("score"),
                    "reasons": item.get("reasons", [])[:5],
                }
                for item in priority[:20]
            ],
        }

    def _tool_get_binary_summary(self, args: dict[str, Any]) -> dict[str, Any]:
        binary = self._require_binary(args)
        if not binary:
            return {"success": False, "tool": "ghidra.get_binary_summary", "errors": ["binary not found"]}
        return self.binary_tools.get_binary_summary(binary)

    def _tool_list_functions(self, args: dict[str, Any]) -> dict[str, Any]:
        binary = self._require_binary(args)
        if not binary:
            return {"success": False, "tool": "ghidra.list_functions", "errors": ["binary not found"]}
        return self.binary_tools.list_functions(binary)

    def _tool_search_functions(self, args: dict[str, Any]) -> dict[str, Any]:
        binary = self._require_binary(args)
        if not binary:
            return {"success": False, "tool": "ghidra.search_functions", "errors": ["binary not found"]}
        return self.binary_tools.search_functions(binary, args["query"])

    def _tool_find_string(self, args: dict[str, Any]) -> dict[str, Any]:
        binary = self._require_binary(args)
        if not binary:
            return {"success": False, "tool": "ghidra.find_string", "errors": ["binary not found"]}
        return self.binary_tools.find_string(binary, args["query"])

    def _tool_find_references(self, args: dict[str, Any]) -> dict[str, Any]:
        binary = self._require_binary(args)
        if not binary:
            return {"success": False, "tool": "ghidra.find_references", "errors": ["binary not found"]}
        return self.binary_tools.find_references(binary, args["address"])

    def _tool_find_function_references(self, args: dict[str, Any]) -> dict[str, Any]:
        binary = self._require_binary(args)
        if not binary:
            return {"success": False, "tool": "ghidra.find_function_references", "errors": ["binary not found"]}
        return self.binary_tools.find_function_references(binary, args["function"])

    def _tool_get_callers(self, args: dict[str, Any]) -> dict[str, Any]:
        binary = self._require_binary(args)
        if not binary:
            return {"success": False, "tool": "ghidra.get_callers", "errors": ["binary not found"]}
        return self.binary_tools.get_callers(binary, args["function"])

    def _tool_get_callees(self, args: dict[str, Any]) -> dict[str, Any]:
        binary = self._require_binary(args)
        if not binary:
            return {"success": False, "tool": "ghidra.get_callees", "errors": ["binary not found"]}
        return self.binary_tools.get_callees(binary, args["function"])

    def _tool_decompile_function(self, args: dict[str, Any]) -> dict[str, Any]:
        binary = self._require_binary(args)
        if not binary:
            return {"success": False, "tool": "ghidra.decompile_function", "errors": ["binary not found"]}
        return self.binary_tools.decompile_function(binary, args["function"])

    def _tool_evidence_create(self, args: dict[str, Any]) -> dict[str, Any]:
        evidence = Evidence(
            id=self._next_evidence_id(),
            type=str(args["type"]),
            binary=args.get("binary"),
            function=args.get("function"),
            address=args.get("address"),
            description=str(args["description"]),
            source_tool=str(args.get("source_tool") or "pi_agent"),
            confidence=_clamp_float(args.get("confidence"), 0.8),
            metadata=args.get("metadata") or {},
        )
        self.evidence.append(evidence)
        return {"success": True, "tool": "evidence.create", "result": {"id": evidence.id}}

    def _tool_hypothesis_create(self, args: dict[str, Any]) -> dict[str, Any]:
        status = str(args.get("status") or "candidate")
        if status not in VALID_HYPOTHESIS_STATUSES:
            return {
                "success": False,
                "tool": "hypothesis.create",
                "errors": [f"invalid hypothesis status: {status}"],
            }
        evidence_ids = args.get("evidence_ids", [])
        error = self._evidence_error(evidence_ids, supported=status == "supported")
        if error:
            return {
                "success": False,
                "tool": "hypothesis.create",
                "errors": [error],
            }
        hypothesis = Hypothesis(
            id=self._next_hypothesis_id(),
            title=str(args["title"]),
            cwe=args.get("cwe"),
            status=status,
            confidence=_clamp_float(args.get("confidence"), 0.5),
            evidence_ids=evidence_ids,
            missing_evidence=list(args.get("missing_evidence") or []),
            next_actions=list(args.get("next_actions") or []),
        )
        self.hypotheses.append(hypothesis)
        return {"success": True, "tool": "hypothesis.create", "result": {"id": hypothesis.id}}

    def _tool_hypothesis_update(self, args: dict[str, Any]) -> dict[str, Any]:
        hypothesis = next((item for item in self.hypotheses if item.id == args["id"]), None)
        if hypothesis is None:
            return {"success": False, "tool": "hypothesis.update", "errors": [f"unknown hypothesis: {args['id']}"]}
        status = args.get("status", hypothesis.status)
        if not isinstance(status, str) or status not in VALID_HYPOTHESIS_STATUSES:
            return {"success": False, "tool": "hypothesis.update", "errors": ["invalid hypothesis status"]}
        error = self._evidence_error(args.get("evidence_ids", hypothesis.evidence_ids), supported=status == "supported")
        if error:
            return {"success": False, "tool": "hypothesis.update", "errors": [error]}
        if "title" in args:
            hypothesis.title = str(args["title"])
        if "cwe" in args:
            hypothesis.cwe = args.get("cwe")
        if "status" in args:
            status = str(args["status"])
            if status not in VALID_HYPOTHESIS_STATUSES:
                return {
                    "success": False,
                    "tool": "hypothesis.update",
                    "errors": [f"invalid hypothesis status: {status}"],
                }
            hypothesis.status = status
        if "confidence" in args:
            hypothesis.confidence = _clamp_float(args["confidence"], hypothesis.confidence)
        if "evidence_ids" in args:
            hypothesis.evidence_ids = list(args["evidence_ids"])
        if "missing_evidence" in args:
            hypothesis.missing_evidence = list(args["missing_evidence"])
        if "next_actions" in args:
            hypothesis.next_actions = list(args["next_actions"])
        return {"success": True, "tool": "hypothesis.update", "result": {"id": hypothesis.id}}

    def _validate_call(self, spec: ToolSpec, args: Any) -> dict[str, Any]:
        if not isinstance(args, dict):
            return {"arguments": {}, "errors": ["arguments must be an object"]}
        normalized = self._normalize_arguments(spec, dict(args))
        errors: list[str] = []
        for name, meta in spec.arguments_schema.items():
            if meta.get("required") and name not in normalized:
                errors.append(f"missing argument: {name}")
                continue
            if name not in normalized:
                continue
            value = normalized[name]
            if meta.get("type") == "string" and not isinstance(value, str):
                errors.append(f"argument {name} must be a string")
            if meta.get("type") == "array" and not isinstance(value, list):
                errors.append(f"argument {name} must be an array")
            if meta.get("type") == "object" and not isinstance(value, dict):
                errors.append(f"argument {name} must be an object")
        return {"arguments": normalized, "errors": errors}

    def _normalize_arguments(self, spec: ToolSpec, args: dict[str, Any]) -> dict[str, Any]:
        normalized = dict(args)
        if spec.name.startswith("ghidra."):
            if "binary" not in normalized and "path" in normalized:
                normalized["binary"] = normalized.pop("path")
            if "query" not in normalized and "substring" in normalized:
                normalized["query"] = normalized.pop("substring")
            if "function" not in normalized and "function_name" in normalized:
                normalized["function"] = normalized.pop("function_name")
            if "function" not in normalized and "callee" in normalized:
                normalized["function"] = normalized.pop("callee")
        if spec.name == "evidence.create":
            if "type" not in normalized and "evidence_type" in normalized:
                normalized["type"] = normalized.pop("evidence_type")
            if "description" not in normalized and "observation" in normalized:
                normalized["description"] = normalized.pop("observation")
            if "source_tool" not in normalized and "source" in normalized:
                normalized["source_tool"] = normalized.pop("source")
            if "function" not in normalized and "artifact" in normalized:
                normalized["function"] = normalized.pop("artifact")
            if "type" not in normalized:
                normalized["type"] = "function_observation" if "function" in normalized else "observation"
        if "confidence" in normalized and isinstance(normalized["confidence"], str):
            normalized["confidence"] = _confidence_from_label(normalized["confidence"])
        return normalized

    def _check_limits(self, tool_name: str, args: dict[str, Any]) -> str | None:
        if not tool_name.startswith("ghidra."):
            return None
        binary = self._resolve_binary(args.get("binary") or "")
        if not binary:
            return "binary not found"
        key = str(binary)
        if key not in self.binaries_seen:
            if len(self.binaries_seen) >= self.max_binary_analyses:
                return f"max_binary_analyses reached ({self.max_binary_analyses})"
            self.binaries_seen.add(key)
        if tool_name == "ghidra.decompile_function":
            if self.decompilation_counts[key] >= self.max_decompilations_per_binary:
                return f"max_decompilations_per_binary reached ({self.max_decompilations_per_binary})"
            self.decompilation_counts[key] += 1
        return None

    def _record_trace(
        self,
        tool: str,
        arguments: dict[str, Any],
        result: dict[str, Any],
        duration: float,
        reason: str,
    ) -> None:
        self.steps += 1
        self.tool_trace.append(
            {
                "step": self.steps,
                "tool": tool,
                "arguments": arguments,
                "reason": reason[:500],
                "success": bool(result.get("success")),
                "result_summary": self._result_summary(result),
                "duration": duration,
            }
        )

    def _result_summary(self, result: dict[str, Any]) -> str:
        if not result.get("success"):
            return "; ".join(result.get("errors", []) or ["failed"])[:500]
        data = result.get("result")
        if isinstance(data, list):
            return f"success; {len(data)} items"
        if isinstance(data, dict) and data:
            return json.dumps(data, ensure_ascii=True)[:800]
        return str(data or "success")[:300]

    def _stop_after_tool(self) -> bool:
        if any(item.status == "supported" and not self._evidence_error(item.evidence_ids, supported=True) for item in self.hypotheses):
            self.stop_reason = "hypothesis_supported"
            return True
        return False

    @staticmethod
    def _evidence_fingerprint(item: Evidence) -> str:
        import hashlib
        data=item.to_dict().copy();data.pop('id',None)
        return hashlib.sha256(json.dumps(data,sort_keys=True,ensure_ascii=True,allow_nan=False).encode()).hexdigest()

    def _evidence_error(self, ids: Any, *, supported: bool) -> str | None:
        if not isinstance(ids,list) or not all(isinstance(key,str) and key for key in ids) or len(set(ids)) != len(ids):
            return "evidence_ids must contain unique existing IDs"
        records={item.id:item for item in self.evidence}
        if any(key not in records for key in ids):
            return "evidence_ids contains an unknown current-run ID"
        if supported:
            trusted=getattr(self,'_trusted_evidence',{})
            if len(ids)<2 or any(key not in trusted or trusted[key] != self._evidence_fingerprint(records[key]) for key in ids):
                return "supported requires at least two distinct unmodified current-run tool evidence items; model assertions are insufficient"
            if len({trusted[key] for key in ids})<2:
                return "supported requires distinct tool observations"
        return None

    def _selected_binary(self) -> str | None:
        if self.binary:
            return self.binary
        priority = (self.report or {}).get("priority_binaries") or []
        if priority:
            return priority[0].get("path")
        return None

    def _resolve_binary(self, binary: str) -> Path | None:
        from fwagent.dynamic.guest_paths import guest_parts, guest_path
        from fwagent.tools.bounded_io import read_beneath
        if not isinstance(binary, str) or not binary:
            return None
        rootfs = (self.report or {}).get("extraction", {}).get("rootfs")
        try:
            if not rootfs:return None
            relative = "/".join(guest_parts(binary))
            assets = {}
            for item in [*(self.report.get("binaries") or []), *(self.report.get("priority_binaries") or [])]:
                if not isinstance(item, dict) or not isinstance(item.get("path"), str):continue
                try:assets["/".join(guest_parts(item["path"]))] = item
                except ValueError:continue
            if relative not in assets:return None
            configured = getattr(getattr(getattr(self, "config", None), "ghidra", None), "max_binary_size_mb", 64)
            limit = min(64*1024*1024, max(1, int(configured))*1024*1024)
            data = read_beneath(rootfs, relative, limit=limit)
            if not data.startswith(b"\x7fELF"):return None
            digest = hashlib.sha256(data).hexdigest()
            expected = assets[relative].get("sha256")
            if expected is not None and expected != digest:return None
            # External/static tools consume a private snapshot, never reopen a
            # model-selected rootfs/host path after the boundary check.
            directory = guest_path(self.task_dir, "/agent/asset-snapshots")
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            total = count = 0
            for path in directory.iterdir():
                count += 1
                if count > 64 or path.is_symlink():return None
                total += path.lstat().st_size
            name = hashlib.sha256((relative + "\0" + digest).encode()).hexdigest() + ".elf"
            target = directory / name
            if target.exists():
                if read_beneath(directory, name, limit=limit) != data:return None
            else:
                if total + len(data) > 128*1024*1024:return None
                with target.open("xb") as handle:handle.write(data)
            return target
        except (OSError, ValueError, TypeError, AttributeError):
            return None

    def _require_binary(self, args: dict[str, Any]) -> Path | None:
        return self._resolve_binary(args.get("binary") or "")

    def _state_summary(self) -> dict[str, Any]:
        report = self.report or {}
        firmware = report.get("firmware") or {}
        platform = report.get("platform") or {}
        web = report.get("web") or {}
        return {
            "firmware": {
                "filename": firmware.get("filename"),
                "sha256": firmware.get("sha256"),
                "formats": firmware.get("formats") or [],
            },
            "architecture": platform.get("architecture"),
            "services": [
                {"name": item.get("name"), "category": item.get("category"), "confidence": item.get("confidence")}
                for item in (report.get("services") or [])[:10]
            ],
            "web": {
                "roots": web.get("roots", []),
                "cgi": web.get("cgi", []),
                "candidate_backend_binaries": web.get("candidate_backend_binaries", [])[:10],
            },
            "priority_binaries": [
                {
                    "path": item.get("path"),
                    "score": item.get("score"),
                    "reasons": item.get("reasons", [])[:5],
                }
                for item in (report.get("priority_binaries") or [])[:10]
            ],
        }

    def _initial_prompt(self) -> str:
        selected = self._selected_binary() or "unknown"
        state = json.dumps(self._state_summary(), ensure_ascii=True, indent=2)
        return f"Task: {self.task_id}\n\nExisting Round 1/2 state:\n{state[:30000]}\n\nSelected target binary: {selected}"

    def _load_report(self) -> dict[str, Any]:
        path = self.reports_dir / "analysis.json"
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)

    def _next_evidence_id(self) -> str:
        return f"E-{len(self.evidence) + 1:04d}"

    def _next_hypothesis_id(self) -> str:
        return f"H-{len(self.hypotheses) + 1:04d}"

    def _tool_descriptions(self) -> str:
        return "\n".join(f"- {spec.name}: {spec.description}" for spec in self.tools.values())

    def _parse_action(self, content: str) -> dict[str, Any] | None:
        if not isinstance(content, str):
            return None
        text = content.strip()
        if text.startswith("```") and text.endswith("```"):
            text = "\n".join(text.splitlines()[1:-1])
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            return None
        if not isinstance(data, dict) or not isinstance(data.get("stop"), bool):
            return None
        if "reason" in data and not isinstance(data["reason"], str):
            return None
        if not data["stop"] and (not isinstance(data.get("tool"), str) or not data["tool"] or not isinstance(data.get("arguments"), dict)):
            return None
        return data

    def _compact_result(self, result: dict[str, Any]) -> str:
        compact = _compact_value(result)
        return _truncate_text(json.dumps(compact, ensure_ascii=True), 12000)

    def _save_json(self, path: Path, data: Any) -> None:
        with path.open("w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
            handle.write("\n")


def _compact_value(value: Any) -> Any:
    if isinstance(value, dict):
        compact: dict[str, Any] = {}
        for key, item in value.items():
            if key == "functions" and isinstance(item, list) and len(item) > 200:
                compact[key] = _compact_value(item[:200]) + [{"truncated": True, "count": len(item)}]
            else:
                compact[key] = _compact_value(item)
        return compact
    if isinstance(value, list):
        return [_compact_value(item) for item in value[:300]]
    if isinstance(value, str) and len(value) > 4000:
        return value[:4000] + "..."
    return value


def _truncate_text(value: str, limit: int) -> str:
    return value if len(value) <= limit else value[:limit] + "..."


def _clamp_float(value: Any, default: float) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return default
    return max(0.0, min(1.0, parsed))


def _confidence_from_label(value: str) -> float:
    lowered = value.strip().lower()
    if lowered in {"high", "confident", "strong"}:
        return 0.8
    if lowered in {"medium", "med", "moderate"}:
        return 0.6
    if lowered in {"low", "weak"}:
        return 0.4
    return _clamp_float(value, 0.5)
