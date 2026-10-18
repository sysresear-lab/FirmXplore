from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import Mock, patch
from fwagent.dynamic.backend import QemuUserServiceBackend
from fwagent.dynamic.guest_paths import GuestPathError, SecurePathUnavailable, _SECURE_WRITES


class ServiceArtifactBoundaryTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);self.base=Path(tmp.name)
        self.backend=object.__new__(QemuUserServiceBackend)
        self.backend.workspace=SimpleNamespace(dynamic_dir=self.base/'task/dynamic')

    def test_invalid_service_rejected_before_rootfs_or_directory_access(self):
        self.backend._rootfs=Mock(side_effect=AssertionError('must reject before I/O'))
        for value in (str(self.base/'outside'),'../outside','/absolute',r'C:\outside','a/b',None,[],True,'.','..'):
            with self.subTest(value=value),self.assertRaises(GuestPathError):self.backend.prepare_service(value)
        self.assertFalse((self.base/'task').exists());self.assertFalse((self.base/'outside').exists())

    def test_artifact_helpers_reject_paths_but_accept_identifiers(self):
        for helper in (self.backend._service_dir,self.backend._application_dir):
            for value in ('../outside',str(self.base/'outside'),'/absolute',r'a\b'):
                with self.subTest(helper=helper.__name__,value=value),self.assertRaises(GuestPathError):helper(value)
            if not _SECURE_WRITES:
                with self.assertRaises(SecurePathUnavailable):helper('lighttpd-v1.conf')
                self.assertFalse((self.base/'task').exists())
                continue
            (self.base/'task/dynamic').mkdir(parents=True,exist_ok=True)
            target=helper('lighttpd-v1.conf');self.assertTrue(target.is_dir())
            self.assertTrue(target.resolve().is_relative_to((self.base/'task/dynamic').resolve()))

    def test_existing_reparse_parent_not_followed(self):
        import stat
        original=Path.lstat;anchor=self.base/'task/dynamic'
        anchor.mkdir(parents=True)
        def metadata(p,*a,**k):
            if p==anchor:return SimpleNamespace(st_mode=stat.S_IFDIR,st_file_attributes=0x400)
            return original(p,*a,**k)
        with patch.object(Path,'lstat',metadata),self.assertRaises(GuestPathError):self.backend._service_dir('lighttpd')
        self.assertFalse((anchor/'services').exists())
