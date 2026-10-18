from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fwagent.model.config import ModelConfig
from fwagent.model.provider import ModelProvider, ModelProviderError
from tests.unit import test_pi_agent as fixtures


class RawModel:
    def __init__(self, content):
        self.content = content
        self.calls = 0

    def chat(self, *args, **kwargs):
        self.calls += 1
        return {"success": True, "content": self.content}


class PiBudgetTests(unittest.TestCase):
    def agent(self, root, model, limit):
        agent = fixtures.PiAgentTests()._make_agent(root, "new", [], max_steps=limit)
        agent.model = model
        return agent

    def test_continuously_malformed_json_has_strict_request_limit(self):
        for limit in (1, 2, 5):
            with self.subTest(limit=limit), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                model = RawModel("{")
                result = self.agent(root, model, limit).run()
                self.assertLessEqual(model.calls, limit)
                self.assertEqual(result["budget_used"], model.calls)
                self.assertEqual(result["parse_errors"], model.calls)
                self.assertFalse(result["success"])
                self.assertTrue(result["errors"])
                self.assertTrue((root / "new/agent/model_trace.json").exists())

    def test_wrong_json_shape_and_missing_fields_are_bounded(self):
        for value in ({}, [], [{"stop": True}], {"stop": "yes"}, {"stop": False}, {"stop": False, "tool": "x", "arguments": []}):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as tmp:
                model = RawModel(json.dumps(value))
                result = self.agent(Path(tmp), model, 3).run()
                self.assertFalse(result["success"])
                self.assertLessEqual(model.calls, 3)
                self.assertEqual(result["stop_reason"], "invalid_model_output")

    def test_unknown_tool_retries_consume_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            model = RawModel('{"stop":false,"tool":"not_a_tool","arguments":{}}')
            result = self.agent(Path(tmp), model, 3).run()
            self.assertEqual(model.calls, 3)
            self.assertEqual(result["budget_used"], 3)
            self.assertEqual(result["steps"], 3)
            self.assertTrue(all(not row["success"] for row in json.loads((Path(tmp) / "new/agent/tool_trace.json").read_text())))

    def test_normal_tool_step_behavior_is_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            agent = fixtures.PiAgentTests()._make_agent(Path(tmp), "new", [
                {"stop": False, "tool": "firmware.get_summary", "arguments": {}},
                {"stop": True},
            ], max_steps=3)
            result = agent.run()
            self.assertTrue(result["success"])
            self.assertEqual(result["steps"], 1)
            self.assertEqual(result["model_calls"], 2)
            self.assertEqual(result["budget_used"], 2)

    def test_provider_internal_retries_are_charged_and_capped(self):
        with tempfile.TemporaryDirectory() as tmp:
            provider = ModelProvider(ModelConfig(provider="openai", model="controlled", api_key="test-only", base_url="https://invalid.example"))
            agent = self.agent(Path(tmp), provider, 2)
            with patch.object(provider, "_post_chat", side_effect=ModelProviderError("MODEL_CONNECTION_ERROR", "controlled disconnected")) as request, patch("fwagent.model.provider.time.sleep"):
                result = agent.run()
            self.assertEqual(request.call_count, 2)
            self.assertEqual(result["model_calls"], 1)
            self.assertEqual(result["budget_used"], 2)
            self.assertFalse(result["success"])
            self.assertEqual(result["model_trace"][0]["request_attempts"], 2)

    def test_one_parse_failure_then_valid_stop_can_recover_within_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            agent = self.agent(Path(tmp), RawModel("{"), 3)
            with patch.object(agent.model, "chat", side_effect=[{"success": True, "content": "{"}, {"success": True, "content": '{"stop":true}'}]):
                result = agent.run()
            self.assertTrue(result["success"])
            self.assertEqual(result["budget_used"], 2)
            self.assertEqual(result["parse_errors"], 1)

    def test_recovered_parse_error_does_not_discard_a_successful_last_tool(self):
        with tempfile.TemporaryDirectory() as tmp:
            agent = self.agent(Path(tmp), RawModel("{"), 2)
            with patch.object(agent.model, "chat", side_effect=[{"success": True, "content": "{"}, {"success": True, "content": '{"stop":false,"tool":"firmware.get_summary","arguments":{}}'}]):
                result = agent.run()
            self.assertTrue(result["success"])
            self.assertEqual(result["steps"], 1)
            self.assertEqual(result["budget_used"], 2)


if __name__ == "__main__":
    unittest.main()
