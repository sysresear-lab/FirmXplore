from __future__ import annotations

import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from fwagent.dynamic.isolated_docker import IsolatedDockerBackend, seccomp_profile
from fwagent.dynamic.isolated_worker import ensure_runtime_directory, unpack, vm_observations
from scripts.validate_kernel_elf import validate
from fwagent.models import CommandResult


class IsolatedEmulationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)

    def archive(self, members):
        source = self.base/'canonical-rootfs.tar.gz'
        with tarfile.open(source, 'w:gz') as archive:
            for name, data in members:
                info = tarfile.TarInfo(name)
                info.size = len(data)
                info.mode = 0o4755
                archive.addfile(info, io.BytesIO(data))
        return source

    def test_archive_traversal_is_rejected_without_outside_writes(self):
        source = self.archive([('rootfs/../../outside', b'bad')])
        with self.assertRaises(ValueError):
            unpack(source, self.base/'root')
        self.assertFalse((self.base/'outside').exists())

    def test_actual_expanded_byte_quota_is_enforced(self):
        source = self.archive([('rootfs/a', b'12345')])
        with patch('fwagent.dynamic.isolated_worker.MAX_BYTES', 4), self.assertRaises(ValueError):
            unpack(source, self.base/'root')

    def test_regular_member_above_legacy_two_mib_limit_is_accepted(self):
        payload = b'x' * (2 * 1024 * 1024 + 1)
        source = self.archive([('rootfs/usr/bin/vendor-service', payload)])
        result = unpack(source, self.base/'root')
        self.assertEqual(result['expanded_bytes'], len(payload))
        self.assertEqual((self.base/'root/usr/bin/vendor-service').stat().st_size, len(payload))

    def test_duplicate_regular_member_cannot_replace_prior_output(self):
        source = self.archive([('rootfs/a', b'first'), ('rootfs/a', b'second')])
        with self.assertRaises(ValueError):
            unpack(source, self.base/'root')
        self.assertEqual((self.base/'root/a').read_bytes(), b'first')

    def test_special_files_are_not_created_on_host(self):
        source = self.base/'canonical-rootfs.tar.gz'
        with tarfile.open(source, 'w:gz') as archive:
            info = tarfile.TarInfo('rootfs/dev/mem')
            info.type = tarfile.CHRTYPE
            info.devmajor = 1
            info.devminor = 1
            archive.addfile(info)
        result = unpack(source, self.base/'root')
        self.assertEqual(result['skipped_special_entries'], 1)
        self.assertFalse((self.base/'root/dev/mem').exists())

    @unittest.skipIf(os.name == 'nt', 'POSIX link semantics are verified in the real Linux worker')
    def test_absolute_guest_link_is_confined(self):
        source = self.base/'canonical-rootfs.tar.gz'
        with tarfile.open(source, 'w:gz') as archive:
            info = tarfile.TarInfo('rootfs/var')
            info.type = tarfile.SYMTYPE
            info.linkname = '/tmp'
            archive.addfile(info)
        unpack(source, self.base/'root')
        self.assertEqual((self.base/'root/var').resolve(), self.base/'root/tmp')

    @unittest.skipIf(os.name == 'nt', 'POSIX link semantics are verified in the real Linux worker')
    def test_runtime_directory_follows_confined_broken_symlink(self):
        root = self.base/'root'
        root.mkdir()
        (root/'var').symlink_to('tmp')
        ensure_runtime_directory(root, 'var/run')
        self.assertTrue((root/'tmp/run').is_dir())

    def test_profile_cannot_create_mounts_or_namespaces(self):
        profile = seccomp_profile()
        self.assertEqual(profile['defaultAction'], 'SCMP_ACT_ERRNO')
        allowed = {n for r in profile['syscalls'] if r['action'] == 'SCMP_ACT_ALLOW' for n in r['names']}
        self.assertFalse(allowed & {'mount', 'umount2', 'unshare', 'setns', 'bpf', 'keyctl', 'init_module', 'finit_module', 'kexec_load', 'reboot'})
        self.assertNotIn('clone3', allowed)
        self.assertIn('SCMP_ARCH_X86', profile['architectures'])
        clone = next(rule for rule in profile['syscalls'] if rule['names'] == ['clone'])
        self.assertEqual(clone['args'][0]['valueTwo'], 0)

    def test_vm_command_echoes_cannot_claim_guest_execution(self):
        result = vm_observations('[kernel] argv: echo FIRMXPLORE_VM_INIT_READY\n[kernel] argv: echo FIRMXPLORE_VM_VENDOR_BUSYBOX_OK\n')
        self.assertFalse(result['kernel_boot_observed'])
        self.assertFalse(result['vendor_binary_observed'])

    def test_http_connect_failure_is_not_a_response(self):
        result = vm_observations('FIRMXPLORE_VM_HTTP_BEGIN\nConnecting to 127.0.0.1\nConnection refused\nFIRMXPLORE_VM_HTTP_END\n')
        self.assertFalse(result['response_observed'])

    def test_actual_http_error_response_counts_as_reachability(self):
        result = vm_observations('FIRMXPLORE_VM_HTTP_UPNP_BEGIN\r\nConnecting to 127.0.0.1:1900\r\n  HTTP/1.1 404 Not Found\r\nFIRMXPLORE_VM_HTTP_UPNP_END\r\n')
        self.assertTrue(result['response_observed'])
        self.assertEqual(result['http_responses'][0]['status'], 404)
        self.assertEqual(result['http_responses'][0]['url'], 'http://127.0.0.1:1900/')

    def test_vendor_process_with_startup_argument_is_observed(self):
        result = vm_observations('   57 0         0:00 /usr/bin/httpd -r\r\n')
        self.assertTrue(result['httpd_process_observed'])
        self.assertFalse(result['response_observed'])

    def test_kernel_validator_rejects_truncated_load_segment(self):
        import struct
        data = bytearray(88)
        data[:6] = b'\x7fELF\x01\x01'
        struct.pack_into('<I', data, 28, 52)
        struct.pack_into('<HH', data, 42, 32, 1)
        struct.pack_into('<8I', data, 52, 1, 84, 0x80000000, 0, 4, 4, 7, 4096)
        source = self.base/'kernel'
        source.write_bytes(data)
        self.assertEqual(validate(source)['bytes'], 88)
        source.write_bytes(data[:-1])
        with self.assertRaisesRegex(ValueError, 'truncated segment'):
            validate(source)

    def test_cleanup_runs_when_attached_worker_fails(self):
        self.archive([('rootfs/file', b'payload')])
        calls = []
        settings = {'Config': {'User': '65534:65534'}, 'Mounts': [{'Type': 'bind', 'RW': False}],
                    'HostConfig': {'NetworkMode': 'none', 'ReadonlyRootfs': True, 'Privileged': False,
                                   'CapDrop': ['ALL'], 'CapAdd': None, 'IpcMode': 'none', 'AutoRemove': True, 'Memory': 512*1024*1024}}
        class Runner:
            def run(self, command, **kwargs):
                calls.append(command)
                output, error, code = '', '', 0
                if command[1:3] == ['image', 'inspect']:
                    output = 'sha256:fixture'
                elif command[1] == 'inspect':
                    output = json.dumps([settings])
                elif command[1] == 'start':
                    error, code = 'worker failed', 1
                return CommandResult(command, code, output, error, 0, False)
        result = IsolatedDockerBackend(self.base, runner=Runner()).boot(timeout=20)
        self.assertFalse(result['success'])
        self.assertTrue(result['cleanup_succeeded'])
        summary = json.loads((self.base/'dynamic/runtime_summary.json').read_text())
        self.assertEqual(summary['dynamic_status'], 'runtime_failed')
        self.assertFalse(summary['endpoint_established'])
        self.assertEqual(calls[-1][:3], ['docker', 'rm', '-f'])
        create = next(c for c in calls if c[1] == 'create')
        self.assertIn('--read-only', create)
        self.assertEqual(create[create.index('--network')+1], 'none')
        self.assertNotIn('--privileged', create)
        self.assertNotIn('--functional',create)


if __name__ == '__main__':
    unittest.main()
