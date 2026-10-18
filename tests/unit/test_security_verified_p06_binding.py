from pathlib import Path
import hashlib,json,subprocess,tempfile,unittest
from unittest.mock import patch
from tests.unit.test_p06_evidence import p06,fixture


class ValidatedBytesBindingTests(unittest.TestCase):
    def test_hashes_are_the_validated_bytes_and_replacement_fails(self):
        for replace in (False,True):
            with self.subTest(replace=replace),tempfile.TemporaryDirectory() as tmp,patch.object(p06,'validate_binary'):
                root=Path(tmp);binary=root/'input';binary.write_bytes(b'fixture');out=root/'out';raw=json.dumps(fixture()).encode()
                def execute(*a,**k):
                    (out/'target_evidence.json').write_bytes(raw);return subprocess.CompletedProcess([],0)
                validate=p06.validate_sidecar
                def validate_then_replace(data):
                    result=validate(data)
                    if replace:(out/'target_evidence.json').write_text('{"invalid":true}')
                    return result
                with patch.object(p06.subprocess,'run',side_effect=execute),patch.object(p06,'validate_sidecar',side_effect=validate_then_replace):
                    code=p06.run(binary,out)
                report=json.loads((out/'manifest.json').read_text())
                if replace:
                    self.assertEqual(code,1);self.assertEqual(report['status'],'unavailable');self.assertNotIn('sidecar',report)
                else:
                    self.assertEqual(code,0);self.assertEqual(report['sidecar']['sha256'],hashlib.sha256(raw).hexdigest())
