from pathlib import Path
import os,tempfile,unittest
from unittest.mock import patch
from tests.unit import test_security_remediation_web as fixtures
from web.server import main,config
from fwagent.tools import bounded_io


class SafeFileExportTests(unittest.TestCase):
    def test_registered_spa_route_cannot_read_same_prefix_sibling(self):
        case=fixtures.WebCredentialTests();case.setUp()
        try:
            root=case.base/'dist';root.mkdir();(root/'index.html').write_text('ordinary index')
            sibling=case.base/'dist-sibling';sibling.mkdir();(sibling/'marker.txt').write_text('KEEP_PRIVATE')
            if not hasattr(main,'spa_fallback'):self.skipTest('SPA not registered without frontend build')
            with patch.object(main,'_frontend_dist',root):
                self.assertEqual(case.get('/..%2Fdist-sibling%2Fmarker.txt').status_code,403)
                self.assertEqual(case.get('/ordinary/missing/route').text,'ordinary index')
        finally:case.doCleanups()

    def test_artifact_response_contains_bounded_bytes_and_is_an_attachment(self):
        case=fixtures.WebCredentialTests();case.setUp()
        try:
            root=config.WORKSPACE_ROOT/case.tid;(root/'reports').mkdir(parents=True)
            (root/'reports/report.json').write_text('{"ordinary":true}')
            response=case.get(f'/api/tasks/{case.tid}/artifacts/reports/report.json')
            self.assertEqual(response.status_code,200);self.assertEqual(response.json(),{'ordinary':True})
            self.assertTrue(response.headers['content-disposition'].startswith('attachment;'))
            self.assertEqual(response.headers['x-content-type-options'],'nosniff')
        finally:case.doCleanups()

    def test_bounded_reader_normal_and_failure_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'ordinary').write_bytes(b'12345')
            self.assertEqual(bounded_io.read_beneath(root,'ordinary',limit=5),b'12345')
            for relative,limit in (('../outside',5),('ordinary',4),('ordinary',True),('C:/outside',5)):
                with self.subTest(relative=relative,limit=limit),self.assertRaises((ValueError,OSError)):
                    bounded_io.read_beneath(root,relative,limit=limit)
            if os.name=='nt':
                with patch.object(bounded_io,'_windows_final_path',return_value=str(root.parent/'outside')),self.assertRaises(ValueError):
                    bounded_io.read_beneath(root,'ordinary',limit=5)
