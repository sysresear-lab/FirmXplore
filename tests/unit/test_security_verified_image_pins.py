from pathlib import Path
import unittest
from tests.unit.test_p06_evidence import p06


class ImmutableImageTests(unittest.TestCase):
    def test_existing_fixed_id_and_repository_digest_require_no_pull(self):
        for image in (p06.IMAGE,'local/worker@sha256:'+'a'*64):
            cmd=p06.docker_command(Path('/sample'),Path('/new'),image,'owned-test')
            self.assertIn('--pull=never',cmd);self.assertIn(image,cmd)
    def test_mutable_malformed_and_wrong_types_rejected(self):
        for image in ('worker:latest','worker:1.0','sha256:short','sha256:'+'a'*63,None,True):
            with self.subTest(image=image),self.assertRaises(ValueError):p06.docker_command(Path('/sample'),Path('/new'),image,'owned-test')
