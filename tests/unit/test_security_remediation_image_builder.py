"""FXSA-004: fake tools only, no shell, payload, mke2fs or firmware execution."""
from __future__ import annotations
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from fwagent.dynamic.compat.image_builder import UserspaceImageBuilder


class FakeRunner:
    def __init__(self, *, copy_exit=0, copy_timeout=False, image_exit=0, emit=True):
        self.calls=[];self.copy_exit=copy_exit;self.copy_timeout=copy_timeout;self.image_exit=image_exit;self.emit=emit
    def run(self, command, **kwargs):
        self.calls.append((command,kwargs))
        if command[0]=='cp':return SimpleNamespace(exit_code=self.copy_exit,timed_out=self.copy_timeout,stderr='controlled copy diagnostic',stdout='')
        if self.emit and self.image_exit==0:Path(command[-2]).write_bytes(b'SYNTHETIC_IMAGE_NOT_BOOTABLE')
        return SimpleNamespace(exit_code=self.image_exit,timed_out=False,stderr='controlled image diagnostic',stdout='')


class ImageBuilderSecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name)
    def build(self,name='rootfs',**kwargs):
        root=self.base/name;root.mkdir(exist_ok=True);(root/'marker').write_text('ordinary data')
        tool=FakeRunner(**kwargs);out=self.base/'image.ext2'
        return UserspaceImageBuilder(tool).build(root,out,size_mb=1),tool,root,out
    def test_normal_copy_and_publish_contract(self):
        result,tool,root,out=self.build()
        self.assertTrue(result.success)
        self.assertEqual(out.read_bytes(),b'SYNTHETIC_IMAGE_NOT_BOOTABLE')
        self.assertEqual([c[0][0] for c in tool.calls],['cp','mke2fs'])
        self.assertEqual(tool.calls[0][0][1:3],['-a','--'])
        self.assertFalse(Path(tool.calls[1][0][-2]).exists())
        self.assertEqual((root/'marker').read_text(),'ordinary data')
    def test_metacharacters_remain_one_literal_argv_operand(self):
        # These are literal filenames, not executable payloads.
        names=['root with spaces',"root'quote",'root;literal','-leading-hyphen','root&literal']
        if os.name!='nt':names+=['root"quote','root|literal']
        for index,name in enumerate(names):
            root=self.base/name;root.mkdir();tool=FakeRunner()
            result=UserspaceImageBuilder(tool).build(root,self.base/f'image-{index}',size_mb=1)
            self.assertTrue(result.success)
            self.assertEqual(tool.calls[0][0][3],str(root.absolute())+os.sep+'.')
            self.assertEqual(len(tool.calls[0][0]),5)
            self.assertFalse(any(c[0][0] in {'sh','bash','cmd','powershell'} for c in tool.calls))
    def test_copy_failure_and_timeout_do_not_continue(self):
        for options in ({'copy_exit':2},{'copy_timeout':True}):
            result,tool,root,out=self.build(**options)
            self.assertFalse(result.success);self.assertFalse(out.exists())
            self.assertEqual(len(tool.calls),1)
            self.assertIn('copy failed',result.errors[0])
    def test_image_failure_or_missing_output_explicit(self):
        for options in ({'image_exit':2},{'emit':False}):
            result,tool,root,out=self.build(**options)
            self.assertFalse(result.success);self.assertFalse(out.exists())
            self.assertIn('mke2fs failed',result.errors[0])
    def test_existing_image_never_removed_or_overwritten(self):
        root=self.base/'root';root.mkdir();out=self.base/'image';out.write_bytes(b'USER_MARKER')
        tool=FakeRunner();result=UserspaceImageBuilder(tool).build(root,out,size_mb=1)
        self.assertFalse(result.success);self.assertEqual(out.read_bytes(),b'USER_MARKER');self.assertEqual(tool.calls,[])
    def test_output_created_during_build_preserved(self):
        root=self.base/'root';root.mkdir();out=self.base/'image';tool=FakeRunner()
        original=tool.run
        def execute(command,**kwargs):
            result=original(command,**kwargs)
            if command[0]=='mke2fs':out.write_bytes(b'RACED_USER_MARKER')
            return result
        tool.run=execute
        result=UserspaceImageBuilder(tool).build(root,out,size_mb=1)
        self.assertFalse(result.success);self.assertEqual(out.read_bytes(),b'RACED_USER_MARKER')
    def test_each_build_uses_distinct_owned_staging(self):
        root=self.base/'root';root.mkdir();tool=FakeRunner()
        for i in range(2):self.assertTrue(UserspaceImageBuilder(tool).build(root,self.base/f'image-{i}',size_mb=1).success)
        copies=[c[0][-1] for c in tool.calls if c[0][0]=='cp']
        self.assertEqual(len(set(copies)),2)
    def test_invalid_types_size_and_missing_root_rejected_without_tools(self):
        for source,size in ((None,1),('missing',1),(self.base,True),(self.base,0),(self.base,'1')):
            tool=FakeRunner();result=UserspaceImageBuilder(tool).build(source,self.base/'out',size_mb=size)
            self.assertFalse(result.success);self.assertEqual(tool.calls,[])


if __name__=='__main__':unittest.main()
