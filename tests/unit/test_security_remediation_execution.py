"""FXSA-003 tests never run a guest, QEMU, a shell or a network service."""
from __future__ import annotations

import ast
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from fwagent.dynamic.backend import QemuUserServiceBackend, FirmAEBackend, FirmAECompatBackend, QEMUBackend, DockerQemuBackend
from fwagent.dynamic.api import DynamicToolAPI
from fwagent.dynamic.fastcgi_harness import encode_params, parse_fastcgi_response, run_fastcgi_harness
from fwagent.dynamic.service import reconstruct_service_startup
from fwagent.runtime.command import CommandRunner
from fwagent.runtime.firmae import FirmAERuntime
from fwagent.runtime.qemu import QemuRuntime
from fwagent.runtime.execution_policy import BLOCK_CODE, command_requires_isolation
from scripts.validate_dynamic_hardening import validate_task


ENTRIES = {
    'boot', 'smoke_test_executable', 'trace_service_startup', 'start_service',
    'trace_application_startup', 'get_direct_application_context',
    'get_fastcgi_application_context', 'compare_application_runtime_contexts',
    'start_fastcgi_harness', 'get_fastcgi_runtime_context', 'compare_fastcgi_runtime',
    'get_fastcgi_child_failure', 'validate_fastcgi_integration', 'start_application_backend',
}


class ExecutionPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)

    def assertBlocked(self, result):
        self.assertFalse(result['success'])
        self.assertEqual(result['error_code'], BLOCK_CODE)
        for name in ('process_started', 'backend_started', 'request_sent', 'runtime_observation_real', 'isolation_verified'):
            self.assertIs(result[name], False)
        self.assertIn('static-only', result['errors'][0])

    def test_every_execution_entry_blocks_before_any_instance_access(self):
        backend = object.__new__(QemuUserServiceBackend)
        with patch('subprocess.Popen', side_effect=AssertionError('no child')), patch('socket.socket', side_effect=AssertionError('no socket')):
            for name in ENTRIES:
                for value in ('/usr/bin/ordinary', None, [], '../outside', '--trusted'):
                    with self.subTest(entry=name, value=value):
                        self.assertBlocked(getattr(backend, name)(value))
        self.assertEqual(list(self.base.iterdir()), [])

    def test_injected_runner_and_environment_do_not_bypass_lock(self):
        backend = object.__new__(QemuUserServiceBackend)
        backend.runner = SimpleNamespace(run=lambda *a, **k: self.fail('runner invoked'))
        with patch.dict(os.environ, {'FIRMXPLORE_ALLOW_UNSAFE': '1', 'FWAGENT_TRUSTED_FIRMWARE': 'true'}):
            self.assertBlocked(backend.boot('/fake-firmware', trusted=True, isolated=True))

    def test_auto_fallback_and_direct_whole_system_entry_points_cannot_bypass_lock(self):
        for cls, name in ((FirmAEBackend, 'boot'), (FirmAECompatBackend, 'boot'), (QEMUBackend, 'boot'), (DockerQemuBackend, 'boot'), (FirmAERuntime, 'boot'), (QemuRuntime, 'start')):
            with self.subTest(cls=cls.__name__):self.assertBlocked(getattr(object.__new__(cls), name)('/ordinary-fixture'))

    def test_standalone_harness_leaves_existing_socket_marker_untouched(self):
        marker = self.base / 'fwagent-fastcgi.sock';marker.write_text('keep')
        with patch('subprocess.Popen', side_effect=AssertionError('no child')), patch('socket.socket', side_effect=AssertionError('no socket')):
            self.assertBlocked(run_fastcgi_harness(['ordinary'], runtime_dir=self.base))
        self.assertEqual(marker.read_text(), 'keep')

    def test_hardening_script_does_not_rewrite_historical_diagnostics(self):
        task = self.base / 'previous';task.mkdir()
        marker = task / 'runtime_summary.json';marker.write_text('HISTORICAL_TEST_MARKER')
        self.assertBlocked(validate_task(self.base, 'previous'))
        self.assertEqual(marker.read_text(), 'HISTORICAL_TEST_MARKER')
        self.assertEqual(set(task.iterdir()), {marker})

    def test_dynamic_api_does_not_create_runtime_evidence_or_rewrite_boot_state(self):
        backend = object.__new__(QemuUserServiceBackend)
        api = DynamicToolAPI(self.base, 'new-fixture', backend=backend)
        before = {p: p.read_bytes() for p in self.base.rglob('*') if p.is_file()}
        for name, args in [('dynamic.boot_firmware', {}), ('dynamic.start_service', {'service': 'lighttpd'})]:
            result = api.execute(name, args)
            self.assertFalse(result['success']);self.assertBlocked(result['result'])
        self.assertEqual(api.evidence, [])
        self.assertEqual({p: p.read_bytes() for p in self.base.rglob('*') if p.is_file()}, before)

    def test_direct_runner_rejects_user_mode_and_wrapper_paths(self):
        runner = CommandRunner(self.base / 'logs')
        commands = [
            ['qemu-arm-static', '-L', '/root', '/bin/ordinary'],
            ['/usr/bin/qemu-mipsel', '/bin/ordinary'],
            [r'C:\tools\QEMU-AARCH64.EXE', '/ordinary'],
            ['qemu-riscv64', '/ordinary'], ['qemu-arm-static', '--version', '/ordinary'],
            ['qemu-system-arm', '-kernel', '/ordinary'],
            ['proot', '-R', '/root', '/ordinary'], ['chroot', '/root', '/ordinary'],
            ['env', 'X=1', 'qemu-arm-static', '/ordinary'],
            ['sh', '-c', 'qemu-mips-static /ordinary'],
        ]
        with patch('fwagent.runtime.command.subprocess.run', side_effect=AssertionError('no process')):
            for command in commands:
                with self.subTest(command=command):
                    result = runner.run(command)
                    self.assertEqual(result.exit_code, 126);self.assertIn(BLOCK_CODE, result.stderr)
        records = [json.loads(line) for line in runner.trace_path.read_text().splitlines()]
        self.assertEqual(len(records), len(commands))

    def test_host_static_tools_and_version_only_queries_remain_available(self):
        runner = CommandRunner(self.base / 'logs')
        for command in (['readelf', '-h', '/root/qemu-arm-static'], ['file', '/ordinary'], ['qemu-arm-static', '--version']):
            with self.subTest(command=command), patch('fwagent.runtime.command.subprocess.run', return_value=SimpleNamespace(returncode=0, stdout='STATIC_FIXTURE', stderr='')) as fake:
                self.assertEqual(runner.run(command).exit_code, 0)
                fake.assert_called_once();self.assertFalse(fake.call_args.kwargs['shell'])

    def test_static_reconstruction_and_protocol_parsing_do_not_require_execution(self):
        root = self.base / 'root';(root / 'usr/sbin').mkdir(parents=True)
        (root / 'usr/sbin/lighttpd').write_bytes(b'non executable static fixture')
        (root / 'etc/lighttpd').mkdir(parents=True)
        (root / 'etc/lighttpd/lighttpd.conf').write_text('server.port = 8081\n')
        with patch('subprocess.Popen', side_effect=AssertionError('static-only')):
            profile = reconstruct_service_startup(root, '/usr/sbin/lighttpd')
            self.assertEqual(profile.service, 'lighttpd')
            self.assertIsInstance(encode_params({'REQUEST_METHOD': 'GET'}), bytes)
            self.assertEqual(parse_fastcgi_response(b'')['stdout'], '')

    def test_source_inventory_covers_every_process_launch_in_user_backend(self):
        import fwagent.dynamic.backend as module
        tree = ast.parse(Path(module.__file__).read_text(encoding='utf-8'))
        cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'QemuUserServiceBackend')
        launch_methods = set()
        for method in cls.body:
            if not isinstance(method, ast.FunctionDef):continue
            for node in ast.walk(method):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    if node.func.attr == 'Popen' or (node.func.attr == 'run' and isinstance(node.func.value, ast.Attribute) and node.func.value.attr == 'runner'):
                        launch_methods.add(method.name)
        self.assertTrue(launch_methods)
        self.assertTrue(launch_methods <= ENTRIES, launch_methods - ENTRIES)
        for name in ENTRIES:self.assertTrue(getattr(QemuUserServiceBackend, name).execution_blocked)


if __name__ == '__main__':unittest.main()
