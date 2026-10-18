from pathlib import Path
import json,subprocess,tempfile,unittest
from unittest.mock import patch
from tests.unit.test_p06_evidence import p06,fixture


class TerminalManifestTests(unittest.TestCase):
    def test_malformed_nested_documents_get_failed_terminal_manifest(self):
        for malformed in ([],{'binary':[]},dict(fixture(),ssa_ops=[None]),dict(fixture(),decompiler=3)):
            with self.subTest(data=malformed),tempfile.TemporaryDirectory() as tmp,patch.object(p06,'validate_binary'):
                root=Path(tmp);binary=root/'input';binary.write_bytes(b'fixture');out=root/'out'
                def execute(*a,**k):
                    p06.write_json(out/'target_evidence.json',malformed)
                    return subprocess.CompletedProcess([],0)
                with patch.object(p06.subprocess,'run',side_effect=execute):self.assertEqual(p06.run(binary,out),1)
                report=json.loads((out/'manifest.json').read_text());self.assertEqual(report['status'],'unavailable');self.assertIn('error',report)
    def test_setup_and_inventory_failure_preserve_terminal_result(self):
        with tempfile.TemporaryDirectory() as tmp,patch.object(p06,'validate_binary'),patch.object(p06.shutil,'copyfile',side_effect=OSError('synthetic denied')):
            root=Path(tmp);binary=root/'input';binary.write_bytes(b'fixture');out=root/'out'
            self.assertEqual(p06.run(binary,out),1);self.assertTrue((out/'manifest.json').is_file())
