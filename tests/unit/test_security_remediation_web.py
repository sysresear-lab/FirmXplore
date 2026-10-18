"""FXSA-001 regressions. Isolated DB, dummy keys, in-process HTTP, fake runner."""
from __future__ import annotations

import asyncio
import base64
import io
import json
import os
from pathlib import Path
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import sessionmaker

from web.server import config, database, main, runner, security, tasks
from web.server.models import AppConfig, Task, TaskCredential
from web.server.schemas import TaskOut
from web.server.task_config import is_current_snapshot, public_task_config, validate_task_config

ALICE_TOKEN = "A" * 40
BOB_TOKEN = "B" * 40
DUMMY_KEY = "DUMMY_MODEL_SECRET_FOR_LOCAL_TEST_ONLY"


def cfg():
    return {"model_provider": "synthetic", "model_name": "fixture", "base_url": "https://invalid.example/v1",
            "deterministic": False, "options": {"static_only": True, "fast": False, "no_dynamic": True, "timeout": 10}}


class WebCredentialTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.engine = create_engine("sqlite:///" + (self.base / "web.db").as_posix(), connect_args={"check_same_thread": False})
        self.addCleanup(self.engine.dispose)
        self.Session = sessionmaker(bind=self.engine)
        self.patches = [
            patch.object(database, "engine", self.engine), patch.object(database, "SessionLocal", self.Session),
            patch.object(tasks, "SessionLocal", self.Session), patch.object(main, "SessionLocal", self.Session),
            patch.object(config, "WORKSPACE_ROOT", self.base / "workspace"),
            patch.object(config, "UPLOAD_ROOT", self.base / "uploads"),
            patch.object(config, "RETENTION_DAYS", 0), patch.object(security, "_fernet", Fernet(Fernet.generate_key())),
            patch.dict(os.environ, {"FIRMXPLORE_WEB_USERS": json.dumps({"alice": ALICE_TOKEN, "bob": BOB_TOKEN})}),
        ]
        for p in self.patches:
            p.start(); self.addCleanup(p.stop)
        database.init_db()
        self.client = TestClient(main.app)
        self.addCleanup(self.client.close)
        self.alice = {"Authorization": "Bearer " + ALICE_TOKEN}
        self.bob = {"Authorization": "Bearer " + BOB_TOKEN}
        self.tid = tasks.create_task_row("fixture.bin", self.base / "fixture.bin", cfg(), 3, owner_id="alice", api_key=DUMMY_KEY)

    def get(self, path, **kwargs):
        return self.client.get(path, headers=kwargs.pop("headers", self.alice), **kwargs)

    def test_anonymous_wrong_and_missing_configuration_fail_closed(self):
        self.assertEqual(self.client.get("/api/tasks").status_code, 401)
        self.assertEqual(self.get("/api/tasks", headers={"Authorization": "Bearer wrong"}).status_code, 401)
        with patch.dict(os.environ, {"FIRMXPLORE_WEB_USERS": ""}):
            self.assertEqual(self.get("/api/tasks").status_code, 503)
        with patch.dict(os.environ, {"FIRMXPLORE_WEB_USERS": '{"alice":"short"}'}):
            self.assertEqual(self.get("/api/tasks").status_code, 503)

    def test_basic_browser_and_bearer_auth(self):
        credential = base64.b64encode(("alice:" + ALICE_TOKEN).encode()).decode()
        for headers in (self.alice, {"Authorization": "Basic " + credential}):
            r = self.get("/api/tasks", headers=headers)
            self.assertEqual(r.status_code, 200)
            self.assertEqual(len(r.json()), 1)
            self.assertEqual(r.headers["cache-control"], "no-store")
        self.assertEqual(self.get("/api/tasks", headers={"Authorization": "Basic !!!"}).status_code, 401)

    def test_snapshot_db_and_list_detail_never_contain_key(self):
        with self.Session() as db:
            row = db.get(Task, self.tid)
            private = db.get(TaskCredential, self.tid)
            self.assertNotIn(DUMMY_KEY, json.dumps(row.config_json))
            self.assertNotIn(DUMMY_KEY, private.ciphertext)
            self.assertEqual(security.decrypt(private.ciphertext), DUMMY_KEY)
        for path in ("/api/tasks", "/api/tasks/" + self.tid):
            response = self.get(path)
            self.assertEqual(response.status_code, 200)
            self.assertNotIn(DUMMY_KEY, response.text)
            self.assertNotIn('"api_key"', response.text)

    def test_other_principal_cannot_read_mutate_stream_or_download(self):
        self.assertEqual(self.get("/api/tasks", headers=self.bob).json(), [])
        for suffix in ("", "/report", "/artifacts", "/artifacts/reports/report.json", "/stream", "/graph", "/model-usage"):
            self.assertEqual(self.get("/api/tasks/" + self.tid + suffix, headers=self.bob).status_code, 404, suffix)
        for suffix in ("/stop", "/resume"):
            self.assertEqual(self.client.post("/api/tasks/" + self.tid + suffix, headers=self.bob).status_code, 404)
        self.assertEqual(self.client.delete("/api/tasks/" + self.tid, headers=self.bob).status_code, 404)

    def test_legacy_tasks_are_quarantined_without_rewriting_them(self):
        legacy = {"api_key": DUMMY_KEY, "options": {"api_key": DUMMY_KEY}}
        with self.Session() as db:
            db.add(Task(id="legacy", filename="old.bin", owner_id=None, config_json=legacy))
            db.add(AppConfig(key="api_key", value="unclaimed encrypted legacy data"))
            db.commit()
        self.assertEqual(self.get("/api/tasks/legacy").status_code, 404)
        self.assertEqual(len(self.get("/api/tasks").json()), 1)
        self.assertFalse(self.get("/api/config").json()["api_key_set"])
        with self.Session() as db:
            row = db.get(Task, "legacy")
            self.assertEqual(row.config_json, legacy)
            row.owner_id = "alice"; db.commit()
        self.assertEqual(self.get("/api/tasks/legacy").status_code, 409)
        self.assertEqual(asyncio.run(tasks.run_analysis("legacy")), None)
        with self.Session() as db:
            row = db.get(Task, "legacy")
            self.assertEqual(row.config_json, legacy)
            output = TaskOut.model_validate(row).model_dump_json()
            self.assertNotIn(DUMMY_KEY, output)

    def test_task_config_rejects_private_fields_and_wrong_types(self):
        for mutate in (lambda d: d.update(api_key=DUMMY_KEY), lambda d: d.update(deterministic=1),
                       lambda d: d["options"].update(api_key=DUMMY_KEY), lambda d: d["options"].update(timeout=True),
                       lambda d: d.update(snapshot_version=True), lambda d: d.update(base_url="https://user:password@invalid.example")):
            data = cfg(); mutate(data)
            with self.subTest(data=data), self.assertRaises(ValueError):
                validate_task_config(data)
        self.assertTrue(is_current_snapshot(validate_task_config(cfg())))

    def test_config_and_encrypted_keys_are_per_principal(self):
        body = {k: v for k, v in cfg().items() if k != "options"};body["api_key"] = DUMMY_KEY
        self.assertEqual(self.client.post("/api/config", json=body, headers=self.alice).status_code, 200)
        self.assertTrue(self.get("/api/config").json()["api_key_set"])
        self.assertFalse(self.get("/api/config", headers=self.bob).json()["api_key_set"])
        body.update(base_url="https://other.invalid.example", api_key=None)
        self.assertEqual(self.client.post("/api/config", json=body, headers=self.alice).status_code, 400)
        with self.Session() as db:
            self.assertNotIn(DUMMY_KEY, db.get(AppConfig, "alice:api_key").value)

    def test_cross_site_state_changes_rejected(self):
        r = self.client.post("/api/tasks/" + self.tid + "/stop", headers={**self.alice, "Origin": "https://untrusted.invalid"})
        self.assertEqual(r.status_code, 403)

    def test_upload_passes_key_separately_and_does_not_start_analysis(self):
        body = {k: v for k, v in cfg().items() if k != "options"};body["api_key"] = DUMMY_KEY
        self.client.post("/api/config", json=body, headers=self.alice)
        with patch.object(main, "_execute", new=AsyncMock()):
            response = self.client.post("/api/analyze", headers=self.alice, files={"file": ("safe.bin", b"data")}, data={"static_only": "true"})
        self.assertEqual(response.status_code, 200)
        with self.Session() as db:
            tid = response.json()["task_id"]
            self.assertEqual(db.get(Task, tid).owner_id, "alice")
            self.assertNotIn(DUMMY_KEY, json.dumps(db.get(Task, tid).config_json))
            self.assertEqual(security.decrypt(db.get(TaskCredential, tid).ciphertext), DUMMY_KEY)

    def test_download_allowlist_and_path_boundary(self):
        root = config.WORKSPACE_ROOT / self.tid
        (root / "reports").mkdir(parents=True)
        (root / "reports/report.json").write_text('{"safe":true}')
        (root / "spec.json").write_text(DUMMY_KEY)
        self.assertEqual(self.get(f"/api/tasks/{self.tid}/artifacts/reports/report.json").status_code, 200)
        self.assertEqual(self.get(f"/api/tasks/{self.tid}/artifacts/spec.json").status_code, 403)
        artifacts = self.get(f"/api/tasks/{self.tid}/artifacts").json()["artifacts"]
        self.assertEqual([a["path"] for a in artifacts], ["reports/report.json"])
        for rel in ("../private.txt", "reports/../../spec.json", "C:/private", "reports\\report.json"):
            with self.subTest(rel=rel), self.assertRaises(Exception):
                main._public_artifact_path(self.tid, rel)

    def test_linked_public_artifact_is_rejected(self):
        root = config.WORKSPACE_ROOT / self.tid
        (root / "reports").mkdir(parents=True)
        target = root / "reports/report.json"; target.write_text("{}")
        original = Path.lstat
        def metadata(p, *args, **kwargs):
            return SimpleNamespace(st_mode=original(p).st_mode, st_file_attributes=0x400) if p == target else original(p, *args, **kwargs)
        with patch.object(Path, "lstat", metadata):
            self.assertEqual(self.get(f"/api/tasks/{self.tid}/artifacts/reports/report.json").status_code, 403)

    def test_runner_handoff_is_stdin_only(self):
        captured = {}
        class Pipe:
            def write(self, data): captured["stdin"] = data
            def close(self): pass
        class FakeProcess:
            stdin = Pipe()
            def wait(self, **kwargs): return 0
        def launch(argv, **kwargs):
            captured.update(argv=argv, kwargs=kwargs, spec=Path(argv[-1]).read_text(encoding="utf-8"))
            return FakeProcess()
        thread = SimpleNamespace(start=lambda: None, join=lambda **kwargs: None)
        with patch.object(tasks.subprocess, "Popen", side_effect=launch), patch.object(tasks, "threading", SimpleNamespace(Thread=lambda **kwargs: thread, Event=threading.Event)), patch.object(tasks, "_collect_logs", return_value=[]), patch.object(tasks, "_fwagent_state", return_value={"status": "completed"}):
            asyncio.run(tasks.run_analysis(self.tid))
        self.assertEqual(json.loads(captured["stdin"])["api_key"], DUMMY_KEY)
        self.assertNotIn(DUMMY_KEY, captured["spec"])
        self.assertNotIn(DUMMY_KEY, json.dumps(captured["argv"]))
        self.assertNotIn("FIRMXPLORE_WEB_USERS", captured["kwargs"]["env"])
        self.assertNotIn("MODEL_API_KEY", captured["kwargs"]["env"])

    def test_runner_input_and_log_redaction(self):
        self.assertEqual(runner._read_private_key(io.StringIO(json.dumps({"api_key": DUMMY_KEY}) + "\n")), DUMMY_KEY)
        for raw in ('[]', '{"api_key":false}', '{"api_key":"x","extra":1}', 'x' * 4097):
            with self.assertRaises(ValueError): runner._read_private_key(io.StringIO(raw))
        stream = io.StringIO(); runner._RedactedLog(stream, DUMMY_KEY).write("error " + DUMMY_KEY)
        self.assertNotIn(DUMMY_KEY, stream.getvalue())
        with patch.dict(os.environ, {"MODEL_API_KEY": DUMMY_KEY, "FWAGENT_MODEL_API_KEY": DUMMY_KEY}):
            runner._apply_model_config({"deterministic": True})
            self.assertNotIn("MODEL_API_KEY", os.environ)
            self.assertNotIn("FWAGENT_MODEL_API_KEY", os.environ)

    def test_owner_can_stop_resume_and_delete_own_task(self):
        with patch.object(tasks, "stop_analysis", return_value=True):
            self.assertEqual(self.client.post(f"/api/tasks/{self.tid}/stop", headers=self.alice).status_code, 200)
        with self.Session() as db:
            db.get(Task, self.tid).status = "paused"; db.commit()
        with patch.object(main, "_run_semaphore", asyncio.Semaphore(1)), patch.object(main, "_execute", new=AsyncMock()):
            self.assertEqual(self.client.post(f"/api/tasks/{self.tid}/resume", headers=self.alice).status_code, 200)
        with patch.object(tasks, "delete_task_files") as delete:
            self.assertEqual(self.client.delete(f"/api/tasks/{self.tid}", headers=self.alice).status_code, 200)
            delete.assert_called_once()
        with self.Session() as db:
            self.assertIsNone(db.get(TaskCredential, self.tid))

    def test_private_credential_owner_mismatch_blocks_launch(self):
        with self.Session() as db:
            db.get(TaskCredential, self.tid).owner_id = "bob"; db.commit()
        with patch.object(tasks.subprocess, "Popen") as launch:
            with self.assertRaisesRegex(ValueError, "owner mismatch"):
                asyncio.run(tasks.run_analysis(self.tid))
            launch.assert_not_called()

    def test_additive_legacy_schema_migration_does_not_change_rows(self):
        old = create_engine("sqlite:///" + (self.base / "legacy.db").as_posix())
        self.addCleanup(old.dispose)
        with old.begin() as c:
            c.execute(text("CREATE TABLE tasks (id VARCHAR(64) PRIMARY KEY, config_json JSON)"))
            c.execute(text("INSERT INTO tasks (id,config_json) VALUES ('old',:cfg)"), {"cfg": json.dumps({"api_key": DUMMY_KEY})})
        with patch.object(database, "engine", old): database.init_db()
        with old.connect() as c:
            row = c.execute(text("SELECT config_json,owner_id FROM tasks WHERE id='old'")).one()
            self.assertEqual(json.loads(row[0]), {"api_key": DUMMY_KEY})
            self.assertIsNone(row[1])


if __name__ == "__main__":
    unittest.main()
