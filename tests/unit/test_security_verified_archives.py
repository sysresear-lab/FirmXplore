from pathlib import Path
import io,tarfile,tempfile,unittest
from unittest.mock import patch
from fwagent.tools import extractor


class TarFilterCompatibilityTests(unittest.TestCase):
    def test_normal_supported_tar_and_unsupported_api(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);data=io.BytesIO()
            with tarfile.open(fileobj=data,mode='w') as archive:
                item=tarfile.TarInfo('ordinary.txt');item.size=4;archive.addfile(item,io.BytesIO(b'data'))
            data.seek(0)
            with tarfile.open(fileobj=data,mode='r:') as archive:
                extractor._safe_extract_tar(archive,root)
            self.assertEqual((root/'ordinary.txt').read_bytes(),b'data')
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(tarfile,'data_filter',None),self.assertRaises(tarfile.TarError):extractor._safe_extract_tar([],Path(tmp))
