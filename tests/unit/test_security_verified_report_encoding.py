from pathlib import Path
import tempfile,unittest
from unittest.mock import patch
from fwagent.reporting.final_report import AnalysisReport,ReportGenerator


class ReportLiteralEncodingTests(unittest.TestCase):
    def test_normal_content_and_inert_html_markers_are_encoded(self):
        marker='<b>DUMMY_LITERAL</b>'
        model=AnalysisReport(metadata={'task_id':'ordinary task'},firmware_summary={'filename':marker},investigation_summary={},attack_surface_summary={},component_summary={},findings=[{'finding_id':'F-TEST','title':'ordinary title','confidence':marker}],rejected_hypotheses=[],inconclusive_hypotheses=[],blocked_items=[],runtime_repairs=[],evidence_summary={'total':marker,'dynamic':marker},timeline=[],remaining_problems=[],provider_status={},artifact_index=[])
        with tempfile.TemporaryDirectory() as tmp:
            generator=ReportGenerator(Path(tmp),'new-task')
            with patch.object(generator,'_surface_metrics',return_value=[('count',marker)]):
                html=generator.generate_html(model).read_text();markdown=generator.generate_markdown(model).read_text()
            self.assertIn('ordinary title',html);self.assertIn('ordinary task',markdown)
            self.assertNotIn(marker,html);self.assertNotIn(marker,markdown)
            self.assertIn('&lt;b&gt;DUMMY_LITERAL&lt;/b&gt;',html);self.assertIn('&lt;b&gt;DUMMY_LITERAL&lt;/b&gt;',markdown)
