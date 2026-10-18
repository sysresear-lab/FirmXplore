"""FXSA-002: harmless paths/markers only; POSIX writes use real directory FDs."""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from fwagent.dynamic import guest_paths
from fwagent.dynamic.guest_paths import GuestPathError, GuestRoot, SecurePathUnavailable, create_private_root, guest_parts, guest_path
from fwagent.dynamic.service import _materialize_directory, _remove_inaccessible_path, prepare_service_rootfs, reconstruct_service_startup
from fwagent.dynamic.application import resolve_lighttpd_config

POSIX = guest_paths._SECURE_WRITES


class GuestPathTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.source = self.base / "source"
        (self.source / "etc/lighttpd").mkdir(parents=True)
        (self.source / "usr/sbin").mkdir(parents=True)
        (self.source / "usr/sbin/lighttpd").write_bytes(b"ordinary placeholder, not executed")
        self.config = self.source / "etc/lighttpd/lighttpd.conf"
        self.config.write_text('server.errorlog = "/var/log/server.log"\nserver.pid-file = "/var/run/service.pid"\n')

    def test_normal_posix_guest_names_resolve_inside_root(self):
        for value in ("/etc/lighttpd/lighttpd.conf", "etc/lighttpd/lighttpd.conf", "/etc/./lighttpd/lighttpd.conf"):
            self.assertEqual(guest_path(self.source, value), self.config)
        self.assertEqual(guest_parts('/var/log/a \'";--literal'), ("var", "log", 'a \'";--literal'))
        profile = reconstruct_service_startup(self.source, "lighttpd")
        self.assertIn("/var/log", profile.writable_paths)

    def test_host_traversal_names_and_wrong_types_rejected(self):
        for value in (None, True, 1, [], "", "/../outside", "a/../../outside", "C:/host", "C:host", "//server/share", r"\\server\share", r"\\?\C:\host", r"etc\..\outside", "x\0y"):
            with self.subTest(value=value), self.assertRaises(GuestPathError): guest_path(self.source, value)

    def test_original_log_path_escape_regression_before_any_write(self):
        self.config.write_text('server.errorlog = "/../outside-runtime/probe.log"\n')
        target = self.base / "runtime"
        with self.assertRaises(GuestPathError): reconstruct_service_startup(self.source, "lighttpd")
        profile = reconstruct_service_startup(self.source, "other")
        profile.writable_paths = ["/../outside-runtime"]
        with self.assertRaises(GuestPathError): prepare_service_rootfs(self.source, target, profile)
        self.assertFalse(target.exists()); self.assertFalse((self.base / "outside-runtime").exists())

    def test_include_cannot_escape_to_sibling_marker(self):
        marker = self.base / "outside.txt";marker.write_text("PRIVATE_TEST_MARKER")
        self.config.write_text('include "/../outside.txt"\n')
        with self.assertRaises(GuestPathError):resolve_lighttpd_config(self.source)
        self.assertEqual(marker.read_text(), "PRIVATE_TEST_MARKER")

    def test_reparse_metadata_rejected_without_following(self):
        original = Path.lstat
        def metadata(p, *args, **kwargs):
            return SimpleNamespace(st_mode=stat.S_IFDIR, st_file_attributes=0x400) if p == self.source / "etc" else original(p, *args, **kwargs)
        with patch.object(Path, "lstat", metadata), self.assertRaises(GuestPathError):guest_path(self.source, "/etc/lighttpd/lighttpd.conf")

    def test_unsupported_writes_fail_before_creating_output(self):
        profile = reconstruct_service_startup(self.source, "lighttpd")
        target = self.base / "new-parent/runtime"
        with patch.object(guest_paths, "_SECURE_WRITES", False), self.assertRaises(SecurePathUnavailable):
            prepare_service_rootfs(self.source, target, profile)
        self.assertFalse(target.parent.exists())

    def test_removal_helper_never_removes_conflicting_data(self):
        marker = self.base / "keep.txt";marker.write_text("keep")
        with self.assertRaises(GuestPathError):_remove_inaccessible_path(marker)
        self.assertEqual(marker.read_text(), "keep")

    @unittest.skipUnless(POSIX, "secure directory descriptor writes require POSIX")
    def test_fresh_runtime_copy_normal_paths_and_source_preserved(self):
        profile = reconstruct_service_startup(self.source, "lighttpd")
        before = self.config.read_bytes(); target = self.base / "new-parent/runtime"
        result = prepare_service_rootfs(self.source, target, profile)
        self.assertTrue(result["success"]); self.assertFalse(result["reused"])
        self.assertTrue((target / "var/run").is_dir())
        self.assertEqual(self.config.read_bytes(), before)
        self.assertEqual((target / "etc/lighttpd/lighttpd.conf").read_bytes(), before)
        self.assertEqual(target.stat().st_mode & 0o777, 0o700)
        self.assertTrue(json.loads((target / ".firmxplore-runtime-copy.json").read_text())["complete"])

    @unittest.skipUnless(POSIX, "secure directory descriptor writes require POSIX")
    def test_existing_runtime_or_forged_marker_is_not_adopted(self):
        target = self.base / "runtime";target.mkdir()
        (target / "keep").write_text("keep")
        (target / ".firmxplore-runtime-copy.json").write_text('{"complete":true}')
        profile = reconstruct_service_startup(self.source, "lighttpd")
        with self.assertRaises(FileExistsError):prepare_service_rootfs(self.source, target, profile)
        self.assertEqual((target / "keep").read_text(), "keep")

    @unittest.skipUnless(POSIX, "real symlink/no-follow race test requires POSIX")
    def test_linked_writable_parent_never_reaches_outside_marker(self):
        outside = self.base / "outside";outside.mkdir();(outside / "keep").write_text("keep")
        (self.source / "var").symlink_to(outside, target_is_directory=True)
        profile = reconstruct_service_startup(self.source, "lighttpd")
        with self.assertRaises(GuestPathError):prepare_service_rootfs(self.source, self.base / "runtime", profile)
        self.assertEqual(list(p.name for p in outside.iterdir()), ["keep"])

    @unittest.skipUnless(POSIX, "real symlink/no-follow race test requires POSIX")
    def test_directory_swap_between_validation_and_open_is_rejected(self):
        root = self.base / "runtime";create_private_root(root);(root / "var").mkdir()
        outside = self.base / "outside";outside.mkdir();(outside / "keep").write_text("keep")
        original = os.open; swapped = False
        def race(path, flags, *args, **kwargs):
            nonlocal swapped
            if path == "var" and kwargs.get("dir_fd") is not None and not swapped:
                swapped = True
                (root / "var").rename(root / "parked")
                (root / "var").symlink_to(outside, target_is_directory=True)
            return original(path, flags, *args, **kwargs)
        with GuestRoot(root) as owned, patch.object(os, "open", side_effect=race):
            with self.assertRaises(OSError):owned.mkdir("/var/new")
        self.assertTrue(swapped)
        self.assertEqual([p.name for p in outside.iterdir()], ["keep"])

    @unittest.skipUnless(POSIX, "secure directory descriptor writes require POSIX")
    def test_exclusive_file_writes_and_conflicting_directory_data_preserved(self):
        root = self.base / "runtime";create_private_root(root)
        with GuestRoot(root) as owned:
            owned.write_new("/etc/new.conf", b"safe")
            with self.assertRaises(FileExistsError):owned.write_new("/etc/new.conf", b"replace")
            with self.assertRaises(OSError):owned.mkdir("/etc/new.conf/child")
        self.assertEqual((root / "etc/new.conf").read_bytes(), b"safe")
        with self.assertRaises(GuestPathError):_materialize_directory(root, root / "../outside")

    @unittest.skipUnless(POSIX, "secure directory descriptor writes require POSIX")
    def test_copy_failure_does_not_write_complete_marker(self):
        profile = reconstruct_service_startup(self.source, "lighttpd")
        with patch("fwagent.dynamic.service.shutil.copytree", side_effect=OSError("controlled copy failure")):
            with self.assertRaises(OSError):prepare_service_rootfs(self.source, self.base / "runtime", profile)
        self.assertFalse((self.base / "runtime/.firmxplore-runtime-copy.json").exists())
        self.assertTrue(self.config.exists())


if __name__ == "__main__":unittest.main()
