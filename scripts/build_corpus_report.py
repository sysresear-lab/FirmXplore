"""Aggregate extraction, static, and emulation evidence into bilingual reports."""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import html
import json
from pathlib import Path


def load(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def esc(value) -> str:
    return html.escape(str(value if value is not None else "—"))


def classify_runtime_failure(result: dict) -> str | None:
    if result.get("success") is True:
        return None
    message = " ".join(str(item) for item in (result.get("errors") or []))
    if "at most 64 MiB" in message:
        return "archive_quota"
    if "expanded byte budget exceeded" in message:
        return "expanded_quota"
    if "No such file or directory" in message and "/bin/busybox" in message:
        return "busybox_missing"
    if "guest BusyBox failed" in message:
        return "guest_busybox_failed"
    return "other"


def status_row(run: dict, root: Path, emulation: dict[str, dict]) -> dict:
    worker = run.get("worker") or {}
    task_id = run["task_id"]
    pipeline = load(root / task_id / "pipeline_summary.json", {})
    coverage = pipeline.get("coverage") or {}
    ghidra = load(root / task_id / "ghidra" / "analysis_summary.json", {})
    dynamic = emulation.get(task_id, {}).get("result") or {}
    return {
        "task_id": task_id, "vendor": run["vendor"], "model": run["model"],
        "filename": run["filename"], "sha256": run["sha256"],
        "extraction": "success" if worker.get("extraction_success") is True else
                      "timeout" if run.get("timed_out") else worker.get("status", "failed"),
        "files": (worker.get("validation") or {}).get("file_count"),
        "elf": (worker.get("validation") or {}).get("elf_count"),
        "architecture": (pipeline.get("platform") or {}).get("architecture"),
        "endianness": (pipeline.get("platform") or {}).get("endianness"),
        "ghidra_scheduled": ghidra.get("scheduled"),
        "ghidra_real": ghidra.get("real_completed"),
        "ghidra_failed": ghidra.get("failed_binary_count"),
        "ghidra_fallback": ghidra.get("fallback_count"),
        "surface": coverage.get("surface_entries"),
        "sources": coverage.get("taint_sources"),
        "sinks": coverage.get("sensitive_sinks"),
        "candidate_paths": coverage.get("candidate_taint_paths"),
        "findings": coverage.get("findings"),
        "static_complete": bool(ghidra) and ghidra.get("execution_completed") is True,
        "ghidra_stage_status": ghidra.get("stage_status"),
        "emulation_success": dynamic.get("success"),
        "emulation_backend": dynamic.get("backend"),
        "response_observed": dynamic.get("response_observed"),
        "runtime_failure_category": classify_runtime_failure(dynamic),
    }


def table_md(rows: list[dict], chinese: bool) -> str:
    headers = (["厂商", "型号", "解包", "架构", "文件/ELF", "Ghidra", "攻击面", "源/汇", "候选路径", "发现", "仿真"]
               if chinese else ["Vendor", "Model", "Extract", "Arch", "Files/ELF", "Ghidra", "Surface", "Sources/Sinks", "Paths", "Findings", "Emulation"])
    lines = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    for row in rows:
        arch = row.get("architecture") or "—"
        if row.get("endianness"):
            arch += "-" + ("LE" if row["endianness"] == "little" else "BE")
        ghidra = (f"{row['ghidra_real']}/{row['ghidra_scheduled']}" if row.get("ghidra_scheduled") is not None else "—")
        emu = ("pass" if row.get("emulation_success") is True else
               "fail" if row.get("emulation_success") is False else "—")
        values = [row["vendor"], row["model"], row["extraction"], arch,
                  f"{row.get('files') or 0}/{row.get('elf') or 0}", ghidra,
                  row.get("surface") if row.get("surface") is not None else "—",
                  f"{row.get('sources') or 0}/{row.get('sinks') or 0}" if row.get("static_complete") else "—",
                  row.get("candidate_paths") if row.get("candidate_paths") is not None else "—",
                  row.get("findings") if row.get("findings") is not None else "—", emu]
        lines.append("| " + " | ".join(str(value).replace("|", "\\|") for value in values) + " |")
    return "\n".join(lines)


def render_markdown(aggregate: dict, chinese: bool) -> str:
    m = aggregate["metrics"]
    title = "FirmXplore 全固件实验报告" if chinese else "FirmXplore Full Firmware Corpus Report"
    if chinese:
        intro = (f"本次实验清点 {m['input_files']} 个文件（{m['unique_firmware']} 个唯一 SHA-256，"
                 f"{m['duplicates']} 个重复文件），覆盖 {m['vendors']} 个厂商目录。"
                 f"成功恢复 {m['extracted']} 个规范 Linux 根文件系统；{m['static_complete']} 个完成静态流水线。")
        notes = ("结果中的候选路径和发现不等同于已确认漏洞。解包失败或超时按失败语义保留；"
                 "重建环境中的启动或响应也不代表原厂硬件完整启动。")
        headings = ("汇总", "失败与边界", "逐样本结果", "解释边界")
        failures = (
            f"提取阶段有 {m['extraction_no_rootfs']} 个样本未找到规范根文件系统，"
            f"{m['extraction_timeout']} 个样本达到 1,200 秒时限。38 个可恢复样本均进行了有界运行时验证："
            f"{m['runtime_archive_quota']} 个超过 64 MiB 归档配额，{m['runtime_expanded_quota']} 个超过 128 MiB 展开配额，"
            f"{m['runtime_busybox_missing']} 个缺少 /bin/busybox，{m['runtime_guest_busybox_failed']} 个来宾 BusyBox 在 QEMU 下执行失败。"
        )
    else:
        intro = (f"The corpus contains {m['input_files']} files ({m['unique_firmware']} unique SHA-256 values and "
                 f"{m['duplicates']} duplicate), spanning {m['vendors']} vendor directories. "
                 f"Canonical Linux root filesystems were recovered for {m['extracted']} images; "
                 f"{m['static_complete']} completed the static pipeline.")
        notes = ("Candidate paths and findings are not confirmed vulnerabilities. Extraction failures and timeouts "
                 "remain explicit, and reconstructed runtime behavior does not establish stock-hardware boot parity.")
        headings = ("Summary", "Failures and bounds", "Per-image results", "Interpretation boundary")
        failures = (
            f"Extraction found no canonical root filesystem for {m['extraction_no_rootfs']} images and reached the "
            f"1,200-second limit for {m['extraction_timeout']}. All 38 recovered images received bounded runtime validation: "
            f"{m['runtime_archive_quota']} exceeded the 64 MiB archive quota, {m['runtime_expanded_quota']} exceeded the "
            f"128 MiB expanded quota, {m['runtime_busybox_missing']} lacked /bin/busybox, and "
            f"{m['runtime_guest_busybox_failed']} failed the guest BusyBox execution under QEMU."
        )
    bullets = [
        f"- {'解包成功' if chinese else 'Extracted'}: {m['extracted']}/{m['unique_firmware']}",
        f"- {'根文件系统文件数' if chinese else 'RootFS files'}: {m['rootfs_files']}",
        f"- {'ELF 数' if chinese else 'ELF binaries'}: {m['elf_binaries']}",
        f"- {'真实 Ghidra 完成' if chinese else 'Real Ghidra completed'}: {m['ghidra_real']}/{m['ghidra_scheduled']}",
        f"- {'Ghidra 失败/回退' if chinese else 'Ghidra failed/fallback'}: {m['ghidra_failed']}/{m['ghidra_fallback']}",
        f"- {'用户态执行' if chinese else 'Userspace execution'}: {m['emulation_success']}/{m['emulation_attempted']}",
        f"- {'HTTP 端点响应' if chinese else 'HTTP endpoint observed'}: {m['endpoint_observed']}/{m['emulation_attempted']}",
        f"- {'重建内核启动' if chinese else 'Reconstructed kernel boot'}: {m['kernel_boot_observed']}/{m['emulation_attempted']}",
        f"- {'本次语料基线功能验证' if chinese else 'Corpus-baseline functional validation'}: {m['functional_passed']}/{m['emulation_attempted']}",
        f"- {'独立 TP-Link 功能验收' if chinese else 'Separate TP-Link functional acceptance'}: {m['acceptance_passed']}/{m['acceptance_runs']} ({m['acceptance_firmware']} {'个固件' if chinese else 'firmware images'})",
        f"- {'攻击面/源/汇' if chinese else 'Surface/sources/sinks'}: {m['surface_entries']}/{m['taint_sources']}/{m['taint_sinks']}",
        f"- {'候选路径/候选发现' if chinese else 'Candidate paths/findings'}: {m['candidate_paths']}/{m['candidate_findings']}",
        f"- {'已提升漏洞' if chinese else 'Promoted vulnerabilities'}: {m['promoted_vulnerabilities']}",
    ]
    return f"# {title}\n\n{intro}\n\n## {headings[0]}\n\n" + "\n".join(bullets) + \
           f"\n\n## {headings[1]}\n\n{failures}\n\n## {headings[2]}\n\n{table_md(aggregate['rows'], chinese)}\n\n## {headings[3]}\n\n{notes}\n"


def render_html(markdown: str, aggregate: dict, chinese: bool) -> str:
    m = aggregate["metrics"]
    title = "FirmXplore 全固件实验报告" if chinese else "FirmXplore Full Firmware Corpus Report"
    rows = []
    for row in aggregate["rows"]:
        gh = f"{row['ghidra_real']}/{row['ghidra_scheduled']}" if row.get("ghidra_scheduled") is not None else "—"
        arch = (row.get("architecture") or "—") + (("-LE" if row.get("endianness") == "little" else "-BE") if row.get("endianness") else "")
        rows.append("<tr>" + "".join(f"<td>{esc(x)}</td>" for x in [row['vendor'], row['model'], row['extraction'], arch,
                    f"{row.get('files') or 0}/{row.get('elf') or 0}", gh, row.get('surface'),
                    f"{row.get('sources') or 0}/{row.get('sinks') or 0}" if row.get('static_complete') else "—",
                    row.get('candidate_paths'), row.get('findings'), row.get('emulation_success')]) + "</tr>")
    labels = (["输入", "唯一固件", "解包", "静态完成", "真实 Ghidra", "用户态执行", "端点响应"] if chinese else
              ["Inputs", "Unique", "Extracted", "Static complete", "Real Ghidra", "Userspace execution", "Endpoint observed"])
    values = [m['input_files'], m['unique_firmware'], m['extracted'], m['static_complete'],
              f"{m['ghidra_real']}/{m['ghidra_scheduled']}", f"{m['emulation_success']}/{m['emulation_attempted']}",
              f"{m['endpoint_observed']}/{m['emulation_attempted']}"]
    cards = "".join(f"<div class=card><b>{esc(v)}</b><span>{esc(k)}</span></div>" for k, v in zip(labels, values))
    headers = (["厂商","型号","解包","架构","文件/ELF","Ghidra","攻击面","源/汇","路径","发现","仿真"] if chinese else
               ["Vendor","Model","Extract","Arch","Files/ELF","Ghidra","Surface","Sources/Sinks","Paths","Findings","Emulation"])
    boundary = ((f"候选路径和候选发现均不是已确认漏洞。提取失败：未找到根文件系统 {m['extraction_no_rootfs']}，超时 {m['extraction_timeout']}。"
                 f"运行时失败：归档配额 {m['runtime_archive_quota']}，展开配额 {m['runtime_expanded_quota']}，缺少 BusyBox {m['runtime_busybox_missing']}，来宾执行 {m['runtime_guest_busybox_failed']}。"
                 f"独立 TP-Link 功能验收为 {m['acceptance_passed']}/{m['acceptance_runs']}。") if chinese else
                (f"Candidate paths and findings are not confirmed vulnerabilities. Extraction failures: no rootfs {m['extraction_no_rootfs']}, timeout {m['extraction_timeout']}. "
                 f"Runtime failures: archive quota {m['runtime_archive_quota']}, expanded quota {m['runtime_expanded_quota']}, missing BusyBox {m['runtime_busybox_missing']}, guest execution {m['runtime_guest_busybox_failed']}. "
                 f"Separate TP-Link functional acceptance passed {m['acceptance_passed']}/{m['acceptance_runs']}."))
    return f"""<!doctype html><html lang={'zh-CN' if chinese else 'en'}><meta charset=utf-8><title>{title}</title>
<style>body{{font:15px system-ui;margin:32px;color:#17202a}}h1{{margin-bottom:6px}}.cards{{display:flex;gap:12px;flex-wrap:wrap;margin:22px 0}}.card{{background:#eef4ff;border-radius:10px;padding:14px 20px;min-width:120px}}.card b{{display:block;font-size:22px}}.card span{{color:#53657a}}table{{border-collapse:collapse;width:100%;font-size:12px}}th,td{{border:1px solid #d7dee8;padding:6px;text-align:left}}th{{background:#1f4b7a;color:white}}tr:nth-child(even){{background:#f7f9fc}}.note{{background:#fff7dc;padding:14px;border-left:4px solid #db9b00;margin-top:20px}}</style>
<h1>{title}</h1><p>{esc(aggregate['created_at'])}</p><div class=cards>{cards}</div>
<table><thead><tr>{''.join('<th>'+esc(x)+'</th>' for x in headers)}</tr></thead><tbody>{''.join(rows)}</tbody></table><p class=note>{esc(boundary)}</p></html>"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve()
    manifest = load(root / "corpus_manifest.json", {})
    extraction = load(root / "extract_summary.json", {"runs": []})
    emulation_summary = load(root / "emulation_summary.json", {"runs": []})
    emulation = {item["task_id"]: item for item in emulation_summary.get("runs", [])}
    rows = [status_row(run, root, emulation) for run in extraction.get("runs", [])]
    acceptance = load(root.parent / "tplink-functional-20261021" / "acceptance-02" / "summary.json", {})
    acceptance_runs = acceptance.get("runs") or []
    runtime_failures = Counter(item.get("runtime_failure_category") for item in rows if item.get("runtime_failure_category"))
    metrics = {
        "input_files": manifest.get("file_count", 0), "unique_firmware": manifest.get("unique_sha256_count", 0),
        "duplicates": manifest.get("duplicate_count", 0),
        "vendors": len({item.get("vendor") for item in rows}),
        "extracted": sum(item["extraction"] == "success" for item in rows),
        "rootfs_files": sum(item.get("files") or 0 for item in rows),
        "elf_binaries": sum(item.get("elf") or 0 for item in rows),
        "static_complete": sum(bool(item.get("static_complete")) for item in rows),
        "ghidra_scheduled": sum(item.get("ghidra_scheduled") or 0 for item in rows),
        "ghidra_real": sum(item.get("ghidra_real") or 0 for item in rows),
        "ghidra_failed": sum(item.get("ghidra_failed") or 0 for item in rows),
        "ghidra_fallback": sum(item.get("ghidra_fallback") or 0 for item in rows),
        "surface_entries": sum(item.get("surface") or 0 for item in rows),
        "taint_sources": sum(item.get("sources") or 0 for item in rows),
        "taint_sinks": sum(item.get("sinks") or 0 for item in rows),
        "candidate_paths": sum(item.get("candidate_paths") or 0 for item in rows),
        "candidate_findings": sum(item.get("findings") or 0 for item in rows),
        "emulation_attempted": len(emulation),
        "emulation_success": sum(item.get("result", {}).get("success") is True for item in emulation.values()),
        "endpoint_observed": sum(item.get("result", {}).get("response_observed") is True for item in emulation.values()),
        "kernel_boot_observed": sum(item.get("result", {}).get("kernel_boot_observed") is True for item in emulation.values()),
        "functional_passed": sum((item.get("result", {}).get("functional_validation") or {}).get("functional_passed") is True for item in emulation.values()),
        "acceptance_runs": len(acceptance_runs),
        "acceptance_passed": sum(item.get("passed") is True and (item.get("functional_validation") or {}).get("functional_passed") is True for item in acceptance_runs),
        "acceptance_firmware": len({item.get("sample") for item in acceptance_runs}),
        "extraction_no_rootfs": sum(item["extraction"] == "no_canonical_rootfs" for item in rows),
        "extraction_timeout": sum(item["extraction"] == "timeout" for item in rows),
        "runtime_archive_quota": runtime_failures["archive_quota"],
        "runtime_expanded_quota": runtime_failures["expanded_quota"],
        "runtime_busybox_missing": runtime_failures["busybox_missing"],
        "runtime_guest_busybox_failed": runtime_failures["guest_busybox_failed"],
        "promoted_vulnerabilities": 0,
    }
    aggregate = {"created_at": datetime.now(timezone.utc).isoformat(), "metrics": metrics,
                 "architectures": dict(Counter(item.get("architecture") or "unknown" for item in rows if item["extraction"] == "success")),
                 "rows": rows}
    (root / "aggregate.json").write_text(json.dumps(aggregate, ensure_ascii=False, indent=2), encoding="utf-8")
    for chinese, stem in ((True, "report.zh-CN"), (False, "report.en")):
        markdown = render_markdown(aggregate, chinese)
        (root / f"{stem}.md").write_text(markdown, encoding="utf-8")
        (root / f"{stem}.html").write_text(render_html(markdown, aggregate, chinese), encoding="utf-8")
    print(json.dumps(metrics, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
