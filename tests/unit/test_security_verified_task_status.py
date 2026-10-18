from pathlib import Path
from types import SimpleNamespace
import json,tempfile,unittest
from unittest.mock import Mock,patch
from fwagent.pipeline.product import AnalysisPipelineController


class ReportTaskStatusTests(unittest.TestCase):
    def test_generation_preserves_failed_blocked_and_completed_task_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);directory=root/'task';(directory/'findings').mkdir(parents=True)
            (directory/'findings/findings.json').write_text('[]')
            controller=object.__new__(AnalysisPipelineController);controller.workspace_root=root
            for status in ('failed','blocked','completed','paused'):
                task=SimpleNamespace(status=status,pipeline_phase='static_analysis',error={'code':'original'},report_paths={})
                controller.load_task=Mock(return_value=task);controller._save_task=Mock()
                generator=Mock();generator.generate_all.return_value={'json':'reports/report.json'};generator.write_artifact_manifest.return_value=directory/'manifest.json'
                with patch('fwagent.pipeline.product.ReportGenerator',return_value=generator):result=controller.regenerate_report('task')
                self.assertTrue(result['success']);self.assertEqual(result['report_generation_status'],'completed')
                self.assertEqual(task.status,status);self.assertEqual(task.pipeline_phase,'static_analysis');self.assertEqual(task.error,{'code':'original'})
    def test_generation_failure_does_not_save_task(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'task/findings').mkdir(parents=True);(root/'task/findings/findings.json').write_text('[]')
            controller=object.__new__(AnalysisPipelineController);controller.workspace_root=root;controller._save_task=Mock()
            with patch('fwagent.pipeline.product.ReportGenerator',side_effect=ValueError('synthetic report failure')),self.assertRaises(ValueError):controller.regenerate_report('task')
            controller._save_task.assert_not_called()
