from pathlib import Path
import sys,tempfile,unittest
from fwagent.runtime.command import CommandRunner


class CommandOutputBudgetTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);self.root=Path(tmp.name)
    def test_normal_success_and_failure(self):
        runner=CommandRunner(self.root,output_limit=1024)
        good=runner.run([sys.executable,'-B','-c','print("ordinary")'])
        bad=runner.run([sys.executable,'-B','-c','import sys;sys.exit(7)'])
        self.assertEqual(good.exit_code,0);self.assertEqual(good.stdout.strip(),'ordinary');self.assertEqual(bad.exit_code,7)
    def test_output_overflow_is_bounded_and_failed(self):
        runner=CommandRunner(self.root,output_limit=1024)
        result=runner.run([sys.executable,'-B','-c','import sys;sys.stdout.write("x"*100000)'])
        self.assertIsNone(result.exit_code);self.assertLessEqual(len(result.stdout.encode()),1024)
        self.assertIn('OUTPUT_LIMIT',result.stderr)
    def test_timeout_and_type(self):
        result=CommandRunner(self.root).run([sys.executable,'-B','-c','import time;time.sleep(5)'],timeout=0.05)
        self.assertTrue(result.timed_out);self.assertIsNone(result.exit_code)
        with self.assertRaises(ValueError):CommandRunner(self.root,output_limit=True)
