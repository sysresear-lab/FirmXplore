from pathlib import Path
from types import SimpleNamespace
import hashlib,tempfile,unittest
from fwagent.investigation.agent import PiAgent
from fwagent.tools.ghidra_api import BinaryToolAPI


class ModelAssetBoundaryTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);self.base=Path(tmp.name)
        self.root=self.base/'root';(self.root/'bin').mkdir(parents=True)
        self.binary=self.root/'bin/app';self.binary.write_bytes(b'\x7fELF'+b'\0'*60)
        self.agent=object.__new__(PiAgent);self.agent.task_dir=self.base/'task'
        self.agent.report={'extraction':{'rootfs':str(self.root)},'priority_binaries':[{'path':'/bin/app'}]}
    def test_registered_elf_is_copied_to_a_private_bounded_snapshot(self):
        resolved=self.agent._resolve_binary('/bin/app')
        self.assertIsNotNone(resolved);self.assertNotEqual(resolved,self.binary)
        self.assertEqual(resolved.read_bytes(),self.binary.read_bytes())
        self.binary.write_bytes(b'changed source')
        self.assertEqual(resolved.read_bytes(),b'\x7fELF'+b'\0'*60)
    def test_host_traversal_unknown_asset_and_non_elf_rejected(self):
        outside=self.base/'outside.txt';outside.write_text('PRIVATE_DUMMY_MARKER')
        for value in (str(outside),'/../outside.txt','../outside.txt',r'C:\outside','/bin/unknown',None,True):
            with self.subTest(value=value):self.assertIsNone(self.agent._resolve_binary(value))
        self.binary.write_text('NON_ELF_MARKER');self.assertIsNone(self.agent._resolve_binary('/bin/app'))
    def test_registered_hash_mismatch_rejected(self):
        self.agent.report['priority_binaries'][0]['sha256']='0'*64
        self.assertIsNone(self.agent._resolve_binary('/bin/app'))
    def test_direct_non_elf_fallback_does_not_read_strings(self):
        self.binary.write_text('NON_ELF_PRIVATE_MARKER')
        api=object.__new__(BinaryToolAPI)
        with self.assertRaises(ValueError):api._fallback_analyze(self.binary)
        result=api.analyze_binary(self.binary)
        self.assertFalse(result['success']);self.assertNotIn('NON_ELF_PRIVATE_MARKER',str(result))
