from pathlib import Path
import unittest


class DebugExecutionLockTests(unittest.TestCase):
    def test_debug_boot_script_has_no_runtime_commands(self):
        source=(Path(__file__).resolve().parents[2]/'scripts/firmae_boot_debug.sh').read_text(encoding='utf-8')
        lines=[line.strip() for line in source.splitlines() if line.strip() and not line.lstrip().startswith('#')]
        self.assertEqual(len(lines),2)
        self.assertTrue(lines[0].startswith("printf '%s\\n' 'UNISOLATED_FIRMWARE_EXECUTION_BLOCKED:"))
        self.assertEqual(lines[1],'exit 126')
        self.assertNotIn('./run.sh',source)
        self.assertNotIn('pg_ctlcluster',source)
