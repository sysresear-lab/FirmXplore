from pathlib import Path
import tempfile,unittest
from unittest.mock import patch
from fwagent.pipeline.analyzer import _select_rootfs
from fwagent.pipeline.product import AnalysisPipelineController
from fwagent.tools.extractor import extract_firmware


class FailedExtractionSelectionTests(unittest.TestCase):
    def test_failed_or_ambiguous_extraction_never_promotes_partial_candidate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);candidate=root/'out';candidate.mkdir();(candidate/'marker').write_bytes(b'preserve')
            for value in (False,None,'true',1):self.assertIsNone(_select_rootfs({'success':value,'rootfs_candidates':[str(candidate)]}))
            self.assertEqual(_select_rootfs({'success':True,'rootfs_candidates':[str(candidate)]}),str(candidate))
            source=root/'input';source.write_bytes(b'unsupported')
            result=extract_firmware(source,candidate)
            self.assertFalse(result['success']);self.assertEqual(result['rootfs_candidates'],[]);self.assertEqual((candidate/'marker').read_bytes(),b'preserve')
    def test_product_recovery_does_not_adopt_failed_extraction(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);controller=object.__new__(AnalysisPipelineController);controller.workspace_root=root
            for success in (False,True):
                report={'extraction':{'success':success,'rootfs':'ordinary-root','rootfs_candidates':['ordinary-candidate']}}
                with patch('fwagent.pipeline.product.load_analysis_json',return_value=report),patch('fwagent.pipeline.product.select_canonical_rootfs_candidate',side_effect=StopIteration) as select:
                    with self.assertRaises(StopIteration):controller._ensure_canonical_rootfs('new-task',root/'input',{}, {},[],timeout=1)
                self.assertEqual(select.call_args.args[0],['ordinary-root','ordinary-candidate'] if success else [])
