from pathlib import Path
import gzip,io,tarfile,tempfile,unittest,zipfile
from unittest.mock import patch
from fwagent.tools import extractor as ex


class ArchiveQuotaTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);self.root=Path(tmp.name)
        self.out=self.root/'out';self.out.mkdir()
    def archive(self,names):
        p=self.root/'data.zip'
        with zipfile.ZipFile(p,'w') as z:
            for name,data in names:z.writestr(name,data)
        return p
    def test_normal_zip_tar_and_gzip(self):
        p=self.archive([('etc/test',b'ok')]);self.assertTrue(ex._stdlib_extract(p,self.out)['success'])
        self.assertEqual((self.out/'etc/test').read_bytes(),b'ok')
        p=self.root/'plain.gz';p.write_bytes(gzip.compress(b'hello'))
        self.assertTrue(ex._stdlib_extract(p,self.out)['success']);self.assertEqual((self.out/'plain').read_bytes(),b'hello')
        data=io.BytesIO()
        with tarfile.open(fileobj=data,mode='w') as t:
            m=tarfile.TarInfo('tar/test');m.size=2;t.addfile(m,io.BytesIO(b'ok'))
        p=self.root/'data.tar.gz';p.write_bytes(gzip.compress(data.getvalue()))
        self.assertTrue(ex._stdlib_extract(p,self.out)['success']);self.assertEqual((self.out/'tar/test').read_bytes(),b'ok')
    def test_preflight_member_bytes_depth_and_input(self):
        for limits in (ex.ExtractionLimits(members=1),ex.ExtractionLimits(file_bytes=1),ex.ExtractionLimits(total_bytes=2),ex.ExtractionLimits(depth=1),ex.ExtractionLimits(input_bytes=1),ex.ExtractionLimits(metadata_bytes=1)):
            p=self.archive([('a/x',b'xx'),('b/y',b'yy')])
            with self.subTest(limits=limits),patch.object(ex,'ExtractionLimits',return_value=limits):
                self.assertFalse(ex._stdlib_extract(p,self.out)['success']);self.assertEqual(list(self.out.iterdir()),[])
    def test_traversal_and_no_overwrite(self):
        marker=self.root/'marker';marker.write_bytes(b'preserve')
        for name in ('../marker','/marker','C:/marker'):
            self.assertFalse(ex._stdlib_extract(self.archive([(name,b'new')]),self.out)['success'])
        (self.out/'existing').write_bytes(b'keep')
        self.assertFalse(ex._stdlib_extract(self.archive([('existing',b'new')]),self.out)['success'])
        self.assertEqual(marker.read_bytes(),b'preserve');self.assertEqual((self.out/'existing').read_bytes(),b'keep')
    def test_decoded_bytes_and_actual_copy_limit(self):
        p=self.root/'data.gz';p.write_bytes(gzip.compress(b'x'*128))
        with patch.object(ex,'ExtractionLimits',return_value=ex.ExtractionLimits(total_bytes=16)):
            self.assertFalse(ex._stdlib_extract(p,self.out)['success'])
        budget=ex._ExtractionBudget(self.out,ex.ExtractionLimits(total_bytes=4))
        output=io.BytesIO()
        with self.assertRaises(ex.ExtractionQuotaError):budget.copy(io.BytesIO(b'12345'),output)
        self.assertEqual(output.getvalue(),b'')
    def test_partial_files_do_not_make_failure_success_and_no_external_fallback(self):
        p=self.root/'input';p.write_bytes(b'plain')
        (self.out/'partial').write_bytes(b'old')
        with patch.object(ex,'find_rootfs_candidates',return_value=[]):
            result=ex.extract_firmware(p,self.out)
        self.assertFalse(result['success']);self.assertEqual(ex._external_extractors(p,self.out),[]);self.assertEqual(ex._squashfs_extractors(),[])
