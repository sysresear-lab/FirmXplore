"""Post-review fixes; dummy credentials, isolated DB and in-process HTTP only."""
import asyncio
import datetime
import os
from unittest.mock import patch
import unittest

from tests.unit.test_security_remediation_web import WebCredentialTests, cfg, DUMMY_KEY
from web.server import main, config, runner
from web.server.models import Task, TaskCredential


class CredentialAuthorityTests(unittest.TestCase):
    def test_private_config_ignores_all_shared_model_sources(self):
        from fwagent.model import config as model_config
        private = {**cfg(), 'api_key': DUMMY_KEY}
        with patch.dict(os.environ, {'FWAGENT_MODEL_API_KEY': 'SHARED_DUMMY', 'FWAGENT_MODEL_BASE_URL': 'https://other.invalid'}), patch.object(model_config, 'load_dotenv', side_effect=AssertionError('no shared dotenv')), patch.object(model_config, '_load_model_file_config', side_effect=AssertionError('no shared config')):
            actual = runner._private_model_config(private)
        self.assertEqual(actual.api_key, DUMMY_KEY)
        self.assertEqual(actual.base_url, private['base_url'])

    def test_missing_or_unsafe_private_config_fails(self):
        for change in ({'api_key': ''}, {'base_url': 'https://user:password@invalid.example'}, {'deterministic': True}):
            with self.subTest(change=change), self.assertRaises(ValueError):runner._private_model_config({**cfg(), 'api_key': DUMMY_KEY, **change})


class CredentialRetentionTests(unittest.TestCase):
    def test_expired_task_and_credential_deleted_together(self):
        case = WebCredentialTests();case.setUp()
        try:
            with case.Session() as db:
                row = db.get(Task, case.tid);row.status = 'success'
                row.created_at = datetime.datetime.now(datetime.timezone.utc)-datetime.timedelta(days=30);db.commit()
            count = 0
            async def sleep(_):
                nonlocal count
                count += 1
                if count > 1:raise asyncio.CancelledError
            with patch.object(config, 'RETENTION_DAYS', 7), patch.object(main.tasks, 'delete_task_files') as files, patch.object(main.asyncio, 'sleep', sleep):
                try:asyncio.run(main._cleanup_loop())
                except asyncio.CancelledError:pass
            files.assert_called_once()
            with case.Session() as db:
                self.assertIsNone(db.get(Task, case.tid));self.assertIsNone(db.get(TaskCredential, case.tid))
        finally:case.doCleanups()
