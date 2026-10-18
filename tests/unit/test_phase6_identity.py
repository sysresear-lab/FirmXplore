"""Identity tests run before the identity layer is integrated into taint analysis."""
import json
import tempfile
import unittest
from pathlib import Path

from fwagent.dynamic.static_evidence import (
    BinaryIdentity, EvidenceValidationError, JsonEvidenceStore, json_pointer, rootfs_relative_path,
)


class StaticIdentityTests(unittest.TestCase):
    def identity(self, path="/usr/sbin/daemon", digest=None):
        return BinaryIdentity.from_export(path, {"sha256": digest, "language": "MIPS:LE:32:default"},
                                          task_id="export-task", hash_origin="ghidra/summary.json#/sha256")

    def test_same_basename_in_different_directories_stays_distinct(self):
        first, second = self.identity("/bin/daemon", "a" * 64), self.identity("/usr/bin/daemon", "a" * 64)
        self.assertNotEqual(first.identity_id, second.identity_id)
        self.assertNotEqual(first.function_id("00401000"), second.function_id("00401000"))

    def test_function_identity_uses_binary_and_entry_not_name(self):
        first, second = self.identity(digest="a" * 64), self.identity(digest="b" * 64)
        self.assertNotEqual(first.function_id("00401000"), second.function_id("00401000"))
        self.assertNotEqual(first.function_id("00401000"), first.function_id("00402000"))
        self.assertEqual(first.function_id("00401000"), first.function_id("0x401000"))

    def test_missing_hash_and_entry_are_not_invented(self):
        identity = self.identity()
        self.assertIsNone(identity.sha256)
        self.assertIsNone(identity.sha256_origin)
        self.assertIsNone(identity.function_id(None))
        self.assertEqual(identity.to_dict()["status"], "partial")
        self.assertEqual(identity.to_dict()["field_status"]["sha256"], "unavailable")
        self.assertIsNone(identity.ghidra_project)
        self.assertEqual(identity.local_file_status, "unavailable")
        self.assertTrue(identity.limitations)

    def test_unhashed_identity_has_explicit_task_scope(self):
        first = self.identity()
        second = BinaryIdentity("usr/sbin/daemon", "another-task")
        self.assertNotEqual(first.identity_id, second.identity_id)

    def test_only_exported_language_supplies_architecture(self):
        identity = self.identity()
        self.assertEqual((identity.architecture, identity.bitness, identity.endianness), ("MIPS", 32, "little"))
        other = BinaryIdentity.from_export("/daemon", {}, task_id="task", hash_origin="summary.json")
        self.assertIsNone(other.architecture)
        self.assertIsNone(other.bitness)
        self.assertIsNone(other.endianness)

    def test_rootfs_path_normalization_is_safe_and_stable(self):
        self.assertEqual(rootfs_relative_path("/usr/./bin/../sbin/daemon"), "usr/sbin/daemon")
        for path in ("../../daemon", "/../daemon", "C:\\daemon", "", "/", None):
            with self.subTest(path=path), self.assertRaises(EvidenceValidationError):
                rootfs_relative_path(path)

    def test_serialized_identity_round_trip_preserves_key_and_states(self):
        identity = self.identity(digest="b" * 64)
        saved = json.loads(json.dumps(identity.to_dict()))
        self.assertEqual(BinaryIdentity.from_dict(saved).to_dict(), saved)
        saved["identity_id"] = "forged"
        with self.assertRaisesRegex(EvidenceValidationError, "inconsistent"):
            BinaryIdentity.from_dict(saved)

    def test_bad_identity_field_types_are_rejected(self):
        for fields in ({"sha256": []}, {"bitness": True}, {"export_task_id": None}, {"endianness": "unknown"}):
            data = {"rootfs_path": "/bin/x", "export_task_id": "task", **fields}
            with self.subTest(fields=fields), self.assertRaises(EvidenceValidationError):
                BinaryIdentity(**data)

    def test_json_pointer_requires_real_target_and_valid_escapes(self):
        value = {"a/b": {"~key": [None, {"address": "00401000"}]}}
        self.assertIsNone(json_pointer(value, "/a~1b/~0key/0"))
        self.assertEqual(json_pointer(value, "/a~1b/~0key/1/address"), "00401000")
        for pointer in ("missing", "/absent", "/a~2b", "/a~1b/~0key/01", "/a~1b/~0key/-1", None):
            with self.subTest(pointer=pointer), self.assertRaises(EvidenceValidationError):
                json_pointer(value, pointer)

    def test_missing_corrupt_or_changed_export_has_explicit_diagnostic(self):
        with tempfile.TemporaryDirectory() as directory:
            store = JsonEvidenceStore(directory)
            with self.assertRaisesRegex(EvidenceValidationError, "FileNotFoundError"):
                store.reference("missing.json", "")
            path = Path(directory) / "export.json"
            path.write_text('{"address":"00401000"}', encoding="utf-8")
            reference, value = store.reference("export.json", "/address")
            self.assertEqual(store.resolve(reference), value)
            path.write_text('{"address":"00402000"}', encoding="utf-8")
            with self.assertRaisesRegex(EvidenceValidationError, "content does not match"):
                store.resolve(reference)
            path.write_text("{", encoding="utf-8")
            with self.assertRaisesRegex(EvidenceValidationError, "JSONDecodeError"):
                store.reference("export.json", "")
            with self.assertRaisesRegex(EvidenceValidationError, "inside the task"):
                store.reference("../outside.json", "")


if __name__ == "__main__":
    unittest.main()
