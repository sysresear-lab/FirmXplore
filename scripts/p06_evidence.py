"""Offline, opt-in P06 export. Stdlib only; never imports the product pipeline."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import time
import uuid
import sys
import re

TARGET_SHA256 = "8abdb32fee180c6765d4e953b97f1d7e16b6de67271a11d156a541ec1dc26eed"
IMAGE = "sha256:d5115efd59fd00c45e185034a28278c777e6ea35d1c9c36586d8fc191fceb7df"
SCHEMA = "firmxplore.p06_export.prototype.v1"
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from fwagent.tools.bounded_io import read_beneath


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, data: object) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2)
        handle.write("\n")


def validate_binary(path: Path) -> None:
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != TARGET_SHA256:
        raise ValueError("P06 ELF SHA-256 mismatch")
    if data[:6] != b"\x7fELF\x01\x01" or int.from_bytes(data[18:20], "little") != 8:
        raise ValueError("Expected MIPS 32-bit little-endian ELF")


def address_key(address: dict) -> tuple[str, str]:
    return address["space"], address["offset"]


def _validate_shapes(data: object) -> None:
    """Validate types before graph operations; bool is never an integer slot."""
    def obj(value):
        if not isinstance(value, dict):raise ValueError("expected object")
        return value
    def array(value):
        if not isinstance(value, list) or len(value)>100000:raise ValueError("expected bounded array")
        return value
    def text(value, nullable=False):
        if nullable and value is None:return
        if not isinstance(value,str) or not value:raise ValueError("expected nonempty string")
    def flag(value):
        if type(value) is not bool:raise ValueError("expected boolean")
    def integer(value):
        if type(value) is not int:raise ValueError("expected integer")
    def address(value):
        value=obj(value);text(value.get('space'));text(value.get('offset'))
    data=obj(data)
    for name in ('schema_version','ghidra_version','java_version','status'):text(data.get(name))
    flag(data.get('analysis_timed_out'))
    binary=obj(data.get('binary'));text(binary.get('sha256'));text(binary.get('language'))
    address(obj(data.get('function')).get('entry'))
    for name in ('instruction_state','ssa_state'):
        state=obj(data.get(name));text(state.get('status'));text(state.get('reason'))
    decompiler=obj(data.get('decompiler'))
    for name in ('completed','high_function_present','timed_out'):flag(decompiler.get(name))
    for ins in array(data.get('instructions')):
        ins=obj(ins);address(ins.get('instruction_address'));text(ins.get('bytes_hex'))
        flag(ins.get('flow_is_call'));text(ins.get('callsite_id'),True);text(ins.get('callsite_status'))
        if ins['callsite_status'] not in {'observed','partial','unavailable','not_a_call_candidate'}:raise ValueError('invalid callsite status')
        for ref in array(ins.get('references')):
            ref=obj(ref);address(ref.get('from'));address(ref.get('to'));text(ref.get('reference_type'))
            flag(ref.get('is_call'));integer(ref.get('operand_index'))
        for op in array(ins.get('raw_pcode')):
            op=obj(op);text(op.get('opcode'));text(op.get('layer'))
            for node in [*array(op.get('inputs')),op.get('output')]:
                if node is not None:
                    node=obj(node);text(node.get('def_use_status'))
                    if 'ssa_identity' not in node:raise ValueError('missing raw varnode SSA state')
    for op in array(data.get('ssa_ops')):
        op=obj(op)
        for name in ('op_id','layer','origin','opcode','instruction_link'):text(op.get(name))
        if op['instruction_link'] not in {'exact_address_in_body','unavailable'}:raise ValueError('invalid instruction link')
        address(op.get('seq_address'))
        if op.get('instruction_address') is not None:address(op['instruction_address'])
        for value in array(op.get('inputs')):text(value)
        text(op.get('output'),True)
        for actual in array(op.get('recovered_actuals')):
            actual=obj(actual);integer(actual.get('pcode_input_index'));text(actual.get('value_id'))
    for value in array(data.get('ssa_values')):
        value=obj(value);text(value.get('value_id'));text(value.get('def_op_id'),True)
        for use in array(value.get('uses_in_exported_ops')):
            use=obj(use);text(use.get('op_id'));integer(use.get('input_index'))


def validate_sidecar(data: dict) -> dict:
    """Reject broken IR and false call/argument claims; does not prove machine semantics."""
    def require(condition: bool, reason: str) -> None:
        if not condition:
            raise ValueError(reason)

    _validate_shapes(data)
    require(data.get("schema_version") == SCHEMA, "unknown prototype schema")
    require(data.get("ghidra_version") == "12.1.3", "wrong Ghidra version")
    require(str(data.get("java_version", "")).split(".")[0] == "21", "wrong Java version")
    require(data.get("binary", {}).get("sha256") == TARGET_SHA256, "wrong binary identity")
    require(data.get("binary", {}).get("language") == "MIPS:LE:32:default", "wrong language")
    require(data.get("function", {}).get("entry", {}).get("offset") == "004061f8", "wrong function entry")
    require(data.get("status") in {"observed", "partial", "unavailable"}, "invalid status")
    for section in ("instruction_state", "ssa_state"):
        require(data[section]["status"] in {"observed", "partial", "unavailable"}, "invalid section status")
        require(bool(data[section].get("reason")), "missing acquisition reason")
    instructions = data["instructions"]
    require(data['instruction_state']['status'] != 'observed' or bool(instructions), 'observed empty instruction shell')
    require(data['instruction_state']['status'] != 'unavailable' or not instructions, 'unavailable instructions carry usable records')
    insns = {address_key(i["instruction_address"]): i for i in instructions}
    require(len(insns) == len(instructions), "duplicate instruction address")
    call_ids = [i["callsite_id"] for i in instructions if i["callsite_id"] is not None]
    require(len(call_ids) == len(set(call_ids)), "duplicate callsite ID")
    for ins in instructions:
        require(bool(ins["bytes_hex"]) and len(bytes.fromhex(ins["bytes_hex"])) > 0, "missing instruction bytes")
        refs = ins["references"]
        ref_keys = [(address_key(r["from"]), address_key(r["to"]), r["reference_type"], r["operand_index"]) for r in refs]
        require(len(ref_keys) == len(set(ref_keys)), "duplicate raw reference")
        for ref in refs:
            require(address_key(ref["from"]) == address_key(ins["instruction_address"]), "reference from mismatch")
            require(type(ref["operand_index"]) is int, "invalid operand index")
        if ins["callsite_status"] == "observed":
            require(ins["flow_is_call"] and any(r["is_call"] for r in refs), "call reference/flow conflict")
            require(any(p["opcode"] in {"CALL", "CALLIND"} for p in ins["raw_pcode"]), "no raw call operation")
        for op in ins["raw_pcode"]:
            require(op["layer"] == "raw_instruction_pcode", "raw/SSA layer confusion")
            for node in [*op["inputs"], op["output"]]:
                if node is not None:
                    require(node["ssa_identity"] is None and node["def_use_status"] == "unavailable", "raw varnode presented as SSA")
    ops = {op["op_id"]: op for op in data["ssa_ops"]}
    values = {v["value_id"]: v for v in data["ssa_values"]}
    require(len(ops) == len(data["ssa_ops"]), "duplicate SSA op ID")
    require(len(values) == len(data["ssa_values"]), "duplicate SSA value ID")
    uses: dict[str, list] = {v: [] for v in values}
    outputs: dict[str, str] = {}
    for op_id, op in ops.items():
        require(op["layer"] == "decompiler_ssa" and op["origin"] == "decompiler_inference", "missing inference origin")
        for index, value in enumerate(op["inputs"]):
            require(value in values, "dangling input value")
            uses[value].append({"op_id": op_id, "input_index": index})
        if op["output"] is not None:
            require(op["output"] in values, "dangling output value")
            require(op["output"] not in outputs, "multiple SSA definitions")
            outputs[op["output"]] = op_id
        actuals = op["recovered_actuals"]
        expected = list(range(1, len(op["inputs"]))) if op["opcode"] in {"CALL", "CALLIND"} else []
        require([a["pcode_input_index"] for a in actuals] == expected, "CALL target used as argument or lost actual")
        for actual in actuals:
            require(type(actual["pcode_input_index"]) is int, "invalid actual slot")
            require(actual["value_id"] == op["inputs"][actual["pcode_input_index"]], "actual value mismatch")
        if op["instruction_link"] == "exact_address_in_body":
            key = address_key(op["instruction_address"])
            require(key in insns and key == address_key(op["seq_address"]), "bad SSA instruction link")
    complete_ssa = data["ssa_state"]["status"] == "observed"
    for value_id, value in values.items():
        require(value["uses_in_exported_ops"] == uses[value_id], "inconsistent SSA uses")
        definition = value["def_op_id"]
        if definition in ops:
            require(ops[definition]["output"] == value_id, "inconsistent SSA definition")
        elif definition is not None:
            require(not complete_ssa, "dangling definition in complete export")
        if value_id in outputs:
            require(definition == outputs[value_id], "output/definition mismatch")
    if complete_ssa:
        require(bool(ops) and bool(values), "observed empty SSA shell")
        require(data["decompiler"]["completed"] and data["decompiler"]["high_function_present"] and not data["decompiler"]["timed_out"], "false HighFunction success")
    if data["ssa_state"]["status"] == "unavailable":
        require(not ops and not values, "unavailable SSA must not carry usable records")
    if data["status"] == "observed":
        require(data["instruction_state"]["status"] == "observed" and complete_ssa and not data.get("analysis_timed_out", True) and not data.get("failure"), "false complete status")
    return {"instructions": len(instructions), "call_candidates": len(call_ids),
            "observed_callsites": sum(i["callsite_status"] == "observed" for i in instructions),
            "ssa_ops": len(ops), "ssa_values": len(values),
            "ssa_calls": sum(op["opcode"] in {"CALL", "CALLIND"} for op in ops.values()),
            "parameter_flow_supported": False}


def docker_command(binary: Path, out: Path, image: str, name: str) -> list[str]:
    if not isinstance(image,str) or re.fullmatch(r'(?:sha256:|[^\s@]+@sha256:)[0-9a-f]{64}',image) is None:
        raise ValueError('P06 image must be an immutable SHA-256 image ID or repository digest; mutable tags are rejected')
    # All paths are arguments, never shell-interpolated. Only the new output directory is writable.
    bootstrap = r'''python -B - <<'PY'
import glob, hashlib, json, pathlib, subprocess
paths=['/opt/ghidra/Ghidra/application.properties',
 '/opt/ghidra/Ghidra/Features/Decompiler/lib/Decompiler.jar',
 '/opt/ghidra/Ghidra/Features/Decompiler/lib/Decompiler-src.zip',
 '/opt/ghidra/Ghidra/Framework/SoftwareModeling/lib/SoftwareModeling.jar',
 '/opt/ghidra/Ghidra/Framework/SoftwareModeling/lib/SoftwareModeling-src.zip',
 '/scripts/ExportTargetEvidence.java']
paths += sorted(glob.glob('/opt/ghidra/Ghidra/Processors/MIPS/data/languages/*.cspec'))
env={'files':{p:hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest() for p in paths},
 'application_properties':pathlib.Path(paths[0]).read_text(),
 'java_version':subprocess.run(['java','-version'],capture_output=True,text=True).stderr}
with open('/out/environment.json','x') as f: json.dump(env,f,indent=2)
assert 'application.version=12.1.3' in env['application_properties']
assert 'version "21.' in env['java_version']
PY
test $? -eq 0 || exit 20
exec /opt/ghidra/support/analyzeHeadless /out/projects p06 -import /input/cgibin -scriptPath /scripts -analysisTimeoutPerFile 120 -postScript ExportTargetEvidence.java /out/target_evidence.json -deleteProject -log /out/headless.log -scriptlog /out/script.log
'''
    return ["docker", "run", "--name", name, "--pull=never", "--rm", "--network=none", "--read-only",
            "--cap-drop=ALL", "--security-opt=no-new-privileges", "--memory=8g", "--cpus=4", "--pids-limit=512",
            "--tmpfs", "/tmp:rw,exec,size=2g", "--tmpfs", "/root:rw,size=512m",
            "--mount", f"type=bind,source={binary},target=/input/cgibin,readonly",
            "--mount", f"type=bind,source={out / 'script-source'},target=/scripts,readonly",
            "--mount", f"type=bind,source={out},target=/out",
            "--env", "MAXMEM=4G", "--entrypoint", "/bin/sh", image, "-c", bootstrap]


def run(binary: Path, out: Path, image: str = IMAGE) -> int:
    binary, out = binary.resolve(strict=True), out.resolve()
    validate_binary(binary)
    container_name = "firmxplore-p06-" + uuid.uuid4().hex
    command = docker_command(binary, out, image, container_name)
    out.mkdir(parents=True, exist_ok=False, mode=0o700)
    start = time.monotonic()
    report: dict = {"status": "unavailable", "parameter_flow_supported": False}
    try:
        (out / "projects").mkdir()
        (out / "script-source").mkdir()
        script = ROOT / "ghidra_scripts/ExportTargetEvidence.java"
        shutil.copyfile(script, out / "script-source/ExportTargetEvidence.java")
        write_json(out / "descriptor.json", {"binary_sha256": digest(binary), "binary_path": str(binary),
            "target_entry": "004061f8", "script_sha256": digest(script), "image": image,
            "analysis_timeout_seconds": 120, "command": command, "schema": SCHEMA})
        with (out / "runner.log").open("xb") as log:
            result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=300, check=False)
        report["process_exit_code"] = result.returncode
        if result.returncode != 0:
            raise RuntimeError("headless process failed; see runner.log")
        sidecar = out / "target_evidence.json"
        sidecar_bytes = read_beneath(out, sidecar.name, limit=20*1024*1024)
        data = json.loads(sidecar_bytes.decode("utf-8"))
        report["counts"] = validate_sidecar(data)
        if read_beneath(out, sidecar.name, limit=20*1024*1024) != sidecar_bytes:
            raise ValueError("sidecar changed during validation")
        report["status"] = data["status"]
        report["instruction_state"], report["ssa_state"] = data["instruction_state"], data["ssa_state"]
        sidecar_sha256 = hashlib.sha256(sidecar_bytes).hexdigest()
        report["sidecar"] = {"path": sidecar.name, "sha256": sidecar_sha256, "bytes": len(sidecar_bytes)}
        refs = [{"path": sidecar.name, "sha256": sidecar_sha256, "json_pointer": f"/{section}/{index}"}
                for section in ("instructions", "ssa_ops", "ssa_values") for index in range(len(data[section]))]
        write_json(out / "evidence_index.json", {"scope": "Acquired records, not proof of parameter flow", "references": refs})
    except subprocess.TimeoutExpired as exc:
        # This name is random for this run and is never taken from external input.
        report["error"] = {"type": type(exc).__name__, "message": str(exc)}
        try:
            cleanup = subprocess.run(["docker", "stop", "--time", "5", container_name], capture_output=True, timeout=30, check=False)
            report["error"]["container_stop_exit_code"] = cleanup.returncode
        except (OSError, subprocess.TimeoutExpired) as cleanup_error:
            report["error"]["container_stop_error"] = str(cleanup_error)
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, AttributeError, UnicodeError) as exc:
        report["status"] = "unavailable"
        report["error"] = {"type": type(exc).__name__, "message": str(exc)}
    report["elapsed_seconds"] = round(time.monotonic() - start, 3)
    report["files"] = []
    # One unreadable/replaced artifact must not prevent a terminal manifest.
    try:
        for index, p in enumerate(out.rglob("*")):
            if index >= 4096:raise ValueError("output inventory entry budget exceeded")
            if p.is_dir():continue
            relative=p.relative_to(out).as_posix()
            raw=read_beneath(out,relative,limit=64*1024*1024)
            if relative == report.get('sidecar',{}).get('path') and hashlib.sha256(raw).hexdigest() != report['sidecar']['sha256']:
                raise ValueError('validated sidecar changed before manifest inventory')
            report["files"].append({"path":relative,"sha256":hashlib.sha256(raw).hexdigest(),"bytes":len(raw)})
    except (OSError,ValueError,RuntimeError) as exc:
        report["status"]="unavailable"
        report["inventory_error"]={"type":type(exc).__name__,"message":str(exc)}
    write_json(out / "manifest.json", report)
    print(json.dumps({"directory": str(out), "status": report["status"], "counts": report.get("counts"), "error": report.get("error")}, ensure_ascii=False))
    return 0 if report["status"] == "observed" else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True, help="Must not already exist")
    args = parser.parse_args()
    return run(args.binary, args.out)


if __name__ == "__main__":
    raise SystemExit(main())
