from pathlib import Path
import os,tempfile,unittest
from unittest.mock import patch
from cryptography.fernet import Fernet
from web.server import security


class FernetKeyContractTests(unittest.TestCase):
    def test_canonical_environment_key_roundtrip_and_legacy_alias(self):
        key=Fernet.generate_key()
        for name in ('FIRMXPLORE_SECRET_KEY','WEB_SECRET_KEY'):
            with patch.dict(os.environ,{name:key.decode()},clear=True):
                actual=security._load_or_create_key();self.assertEqual(actual,key)
                self.assertEqual(Fernet(actual).decrypt(Fernet(key).encrypt(b'dummy secret')),b'dummy secret')
    def test_malformed_keys_fail_without_truncation_or_fallback(self):
        for value in ('','short','x'*32,'x'*43,'x'*44,'x'*64,'非ASCII'):
            with self.subTest(value=value),patch.dict(os.environ,{'FIRMXPLORE_SECRET_KEY':value,'WEB_SECRET_KEY':Fernet.generate_key().decode()},clear=True),self.assertRaises(ValueError):security._load_or_create_key()
    def test_new_file_valid_file_and_invalid_existing_are_preserved(self):
        with tempfile.TemporaryDirectory() as tmp,patch.dict(os.environ,{},clear=True):
            path=Path(tmp)/'dummy.key'
            with patch.object(security.config,'SECRET_KEY_FILE',path):
                key=security._load_or_create_key();self.assertEqual(security._load_or_create_key(),key)
                path.write_bytes(b'invalid existing');before=path.read_bytes()
                with self.assertRaises(ValueError):security._load_or_create_key()
                self.assertEqual(path.read_bytes(),before)
