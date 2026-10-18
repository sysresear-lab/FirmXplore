"""Synthetic contract/runner tests; fixtures are not observations from Ghidra."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[2] / "scripts/p06_evidence.py"
SPEC = importlib.util.spec_from_file_location("p06_evidence", SCRIPT)
p06 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(p06)


def fixture():
    address = {"space": "ram", "offset": "00406534"}
    values = [{"value_id": f"v{i}", "def_op_id": None, "uses_in_exported_ops": [{"op_id": "op", "input_index": i}]} for i in range(2)]
    return {"schema_version": p06.SCHEMA, "ghidra_version": "12.1.3", "java_version": "21.0.12.1",
        "binary": {"sha256": p06.TARGET_SHA256, "language": "MIPS:LE:32:default"},
        "function": {"entry": {"space": "ram", "offset": "004061f8"}},
        "status": "observed", "analysis_timed_out": False,
        "instruction_state": {"status": "observed", "reason": "synthetic fixture"},
        "ssa_state": {"status": "observed", "reason": "synthetic fixture"},
        "decompiler": {"completed": True, "high_function_present": True, "timed_out": False},
        "instructions": [{"instruction_address": address, "bytes_hex": "09f82003", "flow_is_call": True,
            "callsite_id": "c", "callsite_status": "observed",
            "references": [{"from": address, "to": {"space": "ram", "offset": "0041faa0"}, "reference_type": "COMPUTED_CALL", "is_call": True, "operand_index": -1}],
            "raw_pcode": [{"opcode": "CALLIND", "layer": "raw_instruction_pcode", "inputs": [], "output": None}]}],
        "ssa_ops": [{"op_id": "op", "layer": "decompiler_ssa", "origin": "decompiler_inference", "opcode": "CALLIND",
            "seq_address": address, "inputs": ["v0", "v1"], "output": None,
            "recovered_actuals": [{"pcode_input_index": 1, "value_id": "v1"}],
            "instruction_link": "exact_address_in_body", "instruction_address": address}], "ssa_values": values}


class ContractTests(unittest.TestCase):
    def test_synthetic_valid_without_flow_claim(self):
        result = p06.validate_sidecar(fixture())
        self.assertEqual(result["observed_callsites"], 1)
        self.assertFalse(result["parameter_flow_supported"])

    def test_negative_mutations(self):
        mutations = {
            "identity": lambda d: d["binary"].update(sha256="0" * 64),
            "version": lambda d: d.update(ghidra_version="11.3.2"),
            "java": lambda d: d.update(java_version="17.0"),
            "entry": lambda d: d["function"]["entry"].update(offset="0040d730"),
            "duplicate_instruction": lambda d: d["instructions"].append(copy.deepcopy(d["instructions"][0])),
            "duplicate_reference": lambda d: d["instructions"][0]["references"].append(copy.deepcopy(d["instructions"][0]["references"][0])),
            "ordinary_reference": lambda d: d["instructions"][0]["references"][0].update(is_call=False),
            "branch_not_call": lambda d: d["instructions"][0]["raw_pcode"][0].update(opcode="BRANCHIND"),
            "reference_from": lambda d: d["instructions"][0]["references"][0].update(**{"from": {"space": "ram", "offset": "004061f8"}}),
            "boolean_operand": lambda d: d["instructions"][0]["references"][0].update(operand_index=True),
            "duplicate_op": lambda d: d["ssa_ops"].append(copy.deepcopy(d["ssa_ops"][0])),
            "duplicate_value": lambda d: d["ssa_values"].append(copy.deepcopy(d["ssa_values"][0])),
            "dangling_input": lambda d: d["ssa_ops"][0]["inputs"].append("missing"),
            "dangling_output": lambda d: d["ssa_ops"][0].update(output="missing"),
            "dangling_def": lambda d: d["ssa_values"][0].update(def_op_id="missing"),
            "wrong_def_output": lambda d: d["ssa_values"][0].update(def_op_id="op"),
            "wrong_use": lambda d: d["ssa_values"][0].update(uses_in_exported_ops=[]),
            "target_as_argument": lambda d: d["ssa_ops"][0]["recovered_actuals"][0].update(pcode_input_index=0),
            "boolean_actual": lambda d: d["ssa_ops"][0]["recovered_actuals"][0].update(pcode_input_index=True),
            "wrong_actual_value": lambda d: d["ssa_ops"][0]["recovered_actuals"][0].update(value_id="v0"),
            "bad_instruction_link": lambda d: d["ssa_ops"][0].update(instruction_address={"space": "ram", "offset": "004061f8"}),
            "false_highfunction": lambda d: d["decompiler"].update(high_function_present=False),
            "decompile_timeout": lambda d: d["decompiler"].update(timed_out=True),
            "analysis_timeout": lambda d: d.update(analysis_timed_out=True),
            "unavailable_with_records": lambda d: d["ssa_state"].update(status="unavailable"),
            "unexplained_failure": lambda d: d["ssa_state"].update(reason=""),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                data = fixture()
                mutate(data)
                with self.assertRaises(ValueError):
                    p06.validate_sidecar(data)

    def test_partial_is_not_promoted(self):
        data = fixture()
        data["status"] = "partial"
        data["ssa_state"] = {"status": "unavailable", "reason": "HighFunction_null (synthetic)"}
        data["ssa_ops"], data["ssa_values"] = [], []
        self.assertEqual(p06.validate_sidecar(data)["ssa_ops"], 0)

    def test_raw_is_not_ssa(self):
        data = fixture()
        data["instructions"][0]["raw_pcode"][0]["inputs"] = [{"ssa_identity": "v1", "def_use_status": "observed"}]
        with self.assertRaisesRegex(ValueError, "raw varnode"):
            p06.validate_sidecar(data)

    def test_repeated_storage_does_not_merge_ssa_ids(self):
        data = fixture()
        for value in data["ssa_values"]:
            value["storage"] = {"space": "register", "offset": "10"}
        self.assertEqual(p06.validate_sidecar(data)["ssa_values"], 2)

    def test_callsite_ids_distinguish_instructions(self):
        data = fixture()
        ins = copy.deepcopy(data["instructions"][0])
        ins["instruction_address"] = {"space": "ram", "offset": "004065c4"}
        ins["references"][0]["from"] = ins["instruction_address"]
        ins["callsite_id"] = "c2"
        data["instructions"].append(ins)
        self.assertEqual(p06.validate_sidecar(data)["observed_callsites"], 2)
        ins["callsite_id"] = "c"
        with self.assertRaisesRegex(ValueError, "duplicate callsite"):
            p06.validate_sidecar(data)


class RunnerTests(unittest.TestCase):
    def test_isolated_command(self):
        cmd = p06.docker_command(Path("/sample/cgibin"), Path("/new/output"), p06.IMAGE, "owned-test")
        for option in ["--network=none", "--pull=never", "--read-only", "--cap-drop=ALL"]:
            self.assertIn(option, cmd)
        self.assertIn(f"type=bind,source={Path('/sample/cgibin')},target=/input/cgibin,readonly", cmd)
        self.assertIn("ExportTargetEvidence.java", cmd[-1])
        self.assertNotIn("ExportCallGraph.java", cmd[-1])
        self.assertNotIn("firmxplore-phase3", str(cmd))

    def test_wrong_binary_does_not_create_output(self):
        with tempfile.TemporaryDirectory() as temp:
            binary, out = Path(temp) / "input", Path(temp) / "out"
            binary.write_bytes(b"untrusted")
            with self.assertRaises(ValueError):
                p06.run(binary, out)
            self.assertFalse(out.exists())

    def test_existing_output_is_preserved(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(p06, "validate_binary"):
            binary, out = Path(temp) / "input", Path(temp) / "out"
            binary.write_bytes(b"fixture")
            out.mkdir()
            (out / "keep").write_bytes(b"keep")
            with self.assertRaises(FileExistsError):
                p06.run(binary, out)
            self.assertEqual((out / "keep").read_bytes(), b"keep")

    def test_failed_process_manifest_has_no_success_shell(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(p06, "validate_binary"), patch.object(p06.subprocess, "run", return_value=subprocess.CompletedProcess([], 2)):
            binary, out = Path(temp) / "input", Path(temp) / "out"
            binary.write_bytes(b"fixture")
            self.assertEqual(p06.run(binary, out), 1)
            report = json.loads((out / "manifest.json").read_text())
            self.assertEqual(report["status"], "unavailable")
            self.assertFalse(report["parameter_flow_supported"])
            self.assertNotIn("sidecar", report)

    def test_timeout_stops_only_owned_container(self):
        failure = subprocess.TimeoutExpired("synthetic docker run", 300)
        with tempfile.TemporaryDirectory() as temp, patch.object(p06, "validate_binary"), patch.object(p06.subprocess, "run", side_effect=[failure, subprocess.CompletedProcess([], 0)]) as execute:
            binary, out = Path(temp) / "input", Path(temp) / "out"
            binary.write_bytes(b"fixture")
            self.assertEqual(p06.run(binary, out), 1)
            run_args, stop_args = execute.call_args_list[0].args[0], execute.call_args_list[1].args[0]
            self.assertEqual(stop_args[:4], ["docker", "stop", "--time", "5"])
            self.assertEqual(stop_args[-1], run_args[run_args.index("--name") + 1])

    def test_timeout_cleanup_failure_is_recorded(self):
        failures = [subprocess.TimeoutExpired("synthetic run", 300), subprocess.TimeoutExpired("synthetic cleanup", 30)]
        with tempfile.TemporaryDirectory() as temp, patch.object(p06, "validate_binary"), patch.object(p06.subprocess, "run", side_effect=failures):
            binary, out = Path(temp) / "input", Path(temp) / "out"
            binary.write_bytes(b"fixture")
            self.assertEqual(p06.run(binary, out), 1)
            report = json.loads((out / "manifest.json").read_text())
            self.assertIn("container_stop_error", report["error"])

    def test_synthetic_success_creates_resolvable_reference_index(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(p06, "validate_binary"):
            binary, out = Path(temp) / "input", Path(temp) / "out"
            binary.write_bytes(b"fixture")
            def execute(*args, **kwargs):
                p06.write_json(out / "target_evidence.json", fixture())
                return subprocess.CompletedProcess([], 0)
            with patch.object(p06.subprocess, "run", side_effect=execute):
                self.assertEqual(p06.run(binary, out), 0)
            data = json.loads((out / "target_evidence.json").read_text())
            refs = json.loads((out / "evidence_index.json").read_text())["references"]
            self.assertEqual(len(refs), 4)
            for ref in refs:
                self.assertEqual(ref["sha256"], p06.digest(out / ref["path"]))
                _, section, index = ref["json_pointer"].split("/")
                self.assertIsInstance(data[section][int(index)], dict)


if __name__ == "__main__":
    unittest.main()
