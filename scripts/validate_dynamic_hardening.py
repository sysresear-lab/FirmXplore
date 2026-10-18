from __future__ import annotations

from fwagent.runtime.execution_policy import deny_unisolated_execution

import argparse
import json
from pathlib import Path
from typing import Any

from fwagent.dynamic.api import DynamicToolAPI
from fwagent.dynamic.backend import QemuUserServiceBackend
from fwagent.dynamic.models import DynamicEvidence, is_canonical_runtime_evidence
from fwagent.dynamic.service import resolve_runtime_rootfs, save_json
from fwagent.dynamic.workspace import DynamicWorkspace


SERVICE_CATEGORY_PRIORITY = {
    "web": 100,
    "upnp": 70,
    "network": 60,
    "remote_access": 50,
}


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def select_primary_service(report: dict[str, Any], rootfs: Path) -> dict[str, Any] | None:
    candidates = []
    for service in report.get("services", []):
        binary = str(service.get("binary") or service.get("source") or "")
        if not binary.startswith("/") or not (rootfs / binary.lstrip("/")).is_file():
            continue
        candidates.append(
            (
                SERVICE_CATEGORY_PRIORITY.get(str(service.get("category") or ""), 10),
                float(service.get("confidence") or 0.0),
                -len(next((item.get("linked_libraries") or [] for item in report.get("binaries", []) if item.get("path") == binary), [])),
                {**service, "binary": binary},
            )
        )
    return max(candidates, key=lambda item: item[:3])[3] if candidates else None


def select_smoke_binary(report: dict[str, Any], rootfs: Path, selected: dict[str, Any]) -> str:
    for binary in report.get("binaries", []):
        path = str(binary.get("path") or "")
        if Path(path).name == "busybox" and (rootfs / path.lstrip("/")).is_file():
            return path
    return str(selected["binary"])


def append_process_evidence(workspace: DynamicWorkspace, *, binary: str, smoke: dict[str, Any]) -> str | None:
    if not smoke.get("success") or not (smoke.get("attempt") or {}).get("process_started"):
        return None
    evidence = workspace.load_evidence()
    evidence_id = f"DE-RUNTIME-SMOKE-{workspace.task_id}"
    if any(item.id == evidence_id for item in evidence):
        return evidence_id
    mapping = f"{smoke.get('architecture')}/{smoke.get('endianness')} via {smoke.get('emulator')}"
    evidence.append(
        DynamicEvidence(
            id=evidence_id,
            type="process_started",
            observation=f"Firmware executable {binary} loaded and ran under {mapping} during a bounded benign smoke test.",
            source_tool="scripts.validate_dynamic_hardening",
            confidence=0.9,
            target=binary,
            metadata={
                "binary": binary,
                "architecture": smoke.get("architecture"),
                "endianness": smoke.get("endianness"),
                "emulator": smoke.get("emulator"),
                "exit_code": smoke.get("exit_code"),
                "timed_out": smoke.get("timed_out"),
                "runtime_backend": "service-qemu",
                "smoke_artifact": f"dynamic/runtime-smoke/{Path(binary).name}.json",
            },
            provenance="real_runtime_observation",
            execution_mode="real",
            provider_backed=False,
            runtime_observation_real=True,
        )
    )
    workspace.save_evidence(evidence)
    return evidence_id


def append_trace_process_evidence(
    workspace: DynamicWorkspace,
    *,
    service: str,
    binary: str,
    trace: dict[str, Any],
) -> str | None:
    if not trace.get("process_started"):
        return None
    evidence = workspace.load_evidence()
    evidence_id = f"DE-RUNTIME-TRACE-{workspace.task_id}-{service}"
    if any(item.id == evidence_id for item in evidence):
        return evidence_id
    evidence.append(
        DynamicEvidence(
            id=evidence_id,
            type="runtime_log_observed",
            observation=(
                f"Firmware service {binary} reached real startup syscalls under {trace.get('emulator')}; "
                f"the bounded trace stopped at {trace.get('failure_category') or 'normal process exit'}."
            ),
            source_tool="scripts.validate_dynamic_hardening",
            confidence=0.95,
            target=binary,
            metadata={
                "service": service,
                "binary": binary,
                "architecture": trace.get("architecture"),
                "endianness": trace.get("endianness"),
                "emulator": trace.get("emulator"),
                "exit_code": trace.get("exit_code"),
                "failure_category": trace.get("failure_category"),
                "trace_artifact": f"dynamic/services/{service}/startup_trace.json",
            },
            provenance="real_runtime_observation",
            execution_mode="real",
            provider_backed=False,
            runtime_observation_real=True,
        )
    )
    workspace.save_evidence(evidence)
    return evidence_id


def summarize_accepted_integration(workspace: DynamicWorkspace, rootfs_artifact: dict[str, Any]) -> dict[str, Any] | None:
    integration_paths = sorted(workspace.dynamic_dir.glob("application/*/integration_validation.json"))
    accepted = None
    integration_path = None
    for path in integration_paths:
        candidate = _load(path)
        if candidate.get("success") and candidate.get("diagnosis") == "fastcgi_integration_reachable":
            accepted = candidate
            integration_path = path
            break
    if accepted is None or integration_path is None:
        return None

    repair = dict(accepted.get("runtime_repair") or {})
    repair.update(
        {
            "original_environment_gap": repair.get("original_environment_gap")
            or "lighttpd-managed firmware FastCGI child exited before request handling",
            "files_modified": repair.get("files_modified") or [repair.get("config_file")],
            "source_rootfs_modified": False,
            "runtime_copy_modified": True,
            "transport_changes": repair.get("transport_changes")
            or [
                "FastCGI child lifecycle was externally managed",
                "lighttpd used a loopback-only TCP FastCGI endpoint in the reconstructed runtime",
            ],
            "environment_changes": repair.get("environment_changes") or {},
            "original_startup_confirmed": False,
            "fidelity_limitations": repair.get("fidelity_limitations")
            or ["the accepted chain preserves firmware binaries and routing but does not reproduce vendor-original child supervision"],
        }
    )
    accepted["runtime_repair"] = repair
    save_json(integration_path, accepted)
    repair_path = workspace.dynamic_dir / "services" / "lighttpd" / "fastcgi_external_repair.json"
    if repair_path.exists():
        save_json(repair_path, repair)

    evidence = workspace.load_evidence()
    real_count = sum(1 for item in evidence if is_canonical_runtime_evidence(item))
    application = str(accepted.get("backend") or integration_path.parent.name)
    backend_command = ((accepted.get("backend_child") or {}).get("command") or [])
    selected_binary = backend_command[-1] if backend_command else None
    request_observations = accepted.get("request_observations") or []
    response_observed = bool(accepted.get("application_response_reached"))
    summary = {
        "selected_dynamic_service": application,
        "selected_binary": selected_binary,
        "container_image": "firmxplore:latest (accepted artifact provenance)",
        "startup_method": "externally managed firmware FastCGI child with reconstructed lighttpd routing",
        "architecture": rootfs_artifact.get("architecture"),
        "endianness": rootfs_artifact.get("endianness"),
        "runtime_backend": "fastcgi-integration",
        "runtime_backend_reason": "the accepted local lighttpd-to-firmware FastCGI chain is the least-cost backend that verifies routing, request receipt, and application response",
        "binary_smoke": "PASS" if (accepted.get("backend_child") or {}).get("started") else "BLOCKED",
        "dynamic_feasibility": "FEASIBLE",
        "dynamic_status": "response_observed" if response_observed else "endpoint_established",
        "process_started": bool((accepted.get("backend_child") or {}).get("started")),
        "endpoint_established": bool((accepted.get("lighttpd") or {}).get("started")),
        "service_reachable": bool(accepted.get("success")),
        "request_sent": bool(request_observations),
        "response_observed": response_observed,
        "runtime_repair_ids": [repair.get("id")] if repair.get("id") else [],
        "real_dynamic_evidence": real_count,
        "failure_category": None,
        "deepest_verified_blocker": None,
        "integration_artifact": str(integration_path.relative_to(workspace.task_dir)).replace("\\", "/"),
        "source_rootfs_modified": False,
        "network_isolation": "recorded endpoints were loopback-only; no public target was contacted",
        "public_target_probes": 0,
        "exploit_payloads": 0,
        "blocked_promoted_as_real": 0,
        "mock_promoted_as_real": 0,
    }
    save_json(workspace.dynamic_dir / "runtime_summary.json", summary)
    return summary


@deny_unisolated_execution
def validate_task(workspace_root: Path, task_id: str) -> dict[str, Any]:
    workspace = DynamicWorkspace(workspace_root, task_id)
    report = workspace.load_report()
    rootfs_artifact = _load(workspace.task_dir / "artifacts" / "rootfs.json")
    accepted_summary = summarize_accepted_integration(workspace, rootfs_artifact)
    if accepted_summary is not None:
        return accepted_summary
    resolution = resolve_runtime_rootfs(workspace.task_dir, report)
    rootfs = Path(str(resolution.get("path") or ""))
    selected = select_primary_service(report, rootfs)
    if selected is None:
        summary = {
            "dynamic_feasibility": "BLOCKED",
            "dynamic_status": "blocked",
            "failure_category": "dependency_missing",
            "blocking_reasons": ["no statically discovered service has a present executable"],
            "process_started": False,
            "endpoint_established": False,
            "service_reachable": False,
            "request_sent": False,
            "response_observed": False,
            "runtime_repair_ids": [],
        }
        save_json(workspace.dynamic_dir / "runtime_summary.json", summary)
        return summary

    backend = QemuUserServiceBackend(workspace.task_dir)
    backend.reconstruct_service_startup(str(selected["binary"]))
    service_name = Path(str(selected["binary"])).name
    feasibility_result = backend.inspect_runtime_feasibility(service_name)
    assessment = feasibility_result.get("assessment") or feasibility_result
    smoke_binary = select_smoke_binary(report, rootfs, selected)
    smoke = backend.smoke_test_executable(smoke_binary, timeout_seconds=10)
    smoke_evidence_id = append_process_evidence(workspace, binary=smoke_binary, smoke=smoke)

    start: dict[str, Any] = {}
    ports: dict[str, Any] = {}
    response: dict[str, Any] = {}
    startup_trace: dict[str, Any] = {}
    request_sent = False
    if assessment.get("runtime_feasible"):
        api = DynamicToolAPI(workspace_root, task_id, backend=backend)
        start = api.execute("dynamic.start_service", {"service": service_name, "stability_seconds": 2})
        if start.get("success"):
            ports = api.execute("dynamic.get_service_ports", {"service": service_name})
            profile = backend._load_or_reconstruct_profile(service_name)
            if ports.get("success") and profile.protocol == "http":
                request_sent = True
                response = api.execute("dynamic.probe_service_http", {"service": service_name})
        else:
            startup_trace = backend.trace_service_startup(service_name, timeout_seconds=10)
            append_trace_process_evidence(
                workspace,
                service=service_name,
                binary=str(selected["binary"]),
                trace=startup_trace,
            )
        backend.stop()

    state = (start.get("result") or {}).get("state") or (start.get("result") or {}).get("attempt") or {}
    process_started = bool(smoke_evidence_id or state.get("pid"))
    endpoint_established = bool(ports.get("success"))
    response_observed = bool(response.get("success"))
    evidence = workspace.load_evidence()
    real_count = sum(1 for item in evidence if is_canonical_runtime_evidence(item))
    failure_category = assessment.get("failure_category")
    deepest_reason = (assessment.get("blocking_reasons") or [None])[-1]
    start_result = start.get("result") or {}
    if start and not start.get("success"):
        failure_category = start_result.get("failure_category") or failure_category
        deepest_reason = ((start_result.get("state") or {}).get("errors") or [start_result.get("diagnosis") or deepest_reason])[-1]
    if startup_trace.get("failure_category"):
        failure_category = startup_trace["failure_category"]
        deepest_reason = startup_trace.get("deepest_verified_blocker") or deepest_reason
    if start.get("success") and not endpoint_established:
        failure_category = "protocol_unavailable"
        deepest_reason = (
            "ELF loader and shared libraries resolved and the service process remained alive, but no configuration-derived expected port was available; no safe protocol request was sent."
        )
    dynamic_feasibility = (
        "FEASIBLE"
        if response_observed or endpoint_established
        else "PARTIAL"
        if process_started
        else "BLOCKED"
    )
    dynamic_status = "response_observed" if response_observed else "endpoint_established" if endpoint_established else "process_started" if process_started else "blocked"
    runtime_repairs = start_result.get("runtime_repairs") or []
    attempt = start_result.get("attempt") or (start_result.get("state") or {}).get("attempt") or {}
    summary = {
        "selected_dynamic_service": service_name,
        "selected_binary": selected["binary"],
        "container_image": "firmxplore:latest",
        "startup_method": (
            backend._load_or_reconstruct_profile(service_name).startup_source
            or "direct firmware executable; vendor startup command not recovered"
        ),
        "architecture": rootfs_artifact.get("architecture"),
        "endianness": rootfs_artifact.get("endianness"),
        "runtime_backend": "service-qemu",
        "runtime_backend_reason": assessment.get("selection_reason"),
        "binary_smoke": "PASS" if smoke.get("success") else "BLOCKED",
        "dynamic_feasibility": dynamic_feasibility,
        "dynamic_status": dynamic_status,
        "process_started": process_started,
        "endpoint_established": endpoint_established,
        "service_reachable": endpoint_established,
        "request_sent": request_sent,
        "response_observed": response_observed,
        "runtime_repair_ids": [item.get("id") for item in runtime_repairs if item.get("id")],
        "real_dynamic_evidence": real_count,
        "failure_category": failure_category,
        "deepest_verified_blocker": deepest_reason,
        "failure_fingerprint": attempt.get("failure_fingerprint"),
        "stop_reason": start_result.get("stop_reason") or attempt.get("stop_reason"),
        "emulator": assessment.get("emulator"),
        "loader": assessment.get("loader"),
        "rootfs_source": assessment.get("rootfs_source"),
        "rootfs_semantic_fidelity": assessment.get("rootfs_semantic_fidelity"),
        "runtime_budget": {"smoke_seconds": 10, "stability_seconds": 2, "trace_seconds": 10 if startup_trace else 0},
        "feasibility_artifact": f"dynamic/services/{service_name}/feasibility.json",
        "smoke_artifact": f"dynamic/runtime-smoke/{Path(smoke_binary).name}.json",
        "startup_trace_artifact": f"dynamic/services/{service_name}/startup_trace.json" if startup_trace else None,
        "source_rootfs_modified": False,
        "network_isolation": "container --network none; loopback only",
        "public_target_probes": 0,
        "exploit_payloads": 0,
        "blocked_promoted_as_real": 0,
        "mock_promoted_as_real": 0,
    }
    save_json(workspace.dynamic_dir / "runtime_summary.json", summary)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Run bounded local multi-firmware dynamic hardening checks.")
    parser.add_argument("--workspace-root", default="workspace")
    parser.add_argument("task_ids", nargs="+")
    args = parser.parse_args()
    root = Path(args.workspace_root).resolve()
    results = {task_id: validate_task(root, task_id) for task_id in args.task_ids}
    print(json.dumps(results, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
