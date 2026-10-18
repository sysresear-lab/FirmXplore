import unittest
from fwagent.investigation.agent import PiAgent


class HypothesisProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.agent=object.__new__(PiAgent);self.agent.evidence=[];self.agent.hypotheses=[];self.agent._trusted_evidence={};self.agent.stop_reason='completed'
    def automatic(self,description):
        self.agent._add_auto_evidence(type_='function_reference',binary='/bin/app',function=description,address='00401000',description=description,source_tool='ghidra',confidence=.7,metadata={})
        return self.agent.evidence[-1].id
    def create(self,ids):return self.agent._tool_hypothesis_create({'title':'synthetic hypothesis','status':'supported','evidence_ids':ids})
    def test_unknown_duplicate_and_model_assertions_rejected(self):
        self.assertFalse(self.create(['missing','other'])['success'])
        a=self.automatic('one');self.assertFalse(self.create([a,a])['success'])
        self.agent._tool_evidence_create({'type':'observation','description':'model assertion','source_tool':'ghidra'})
        self.assertFalse(self.create([a,self.agent.evidence[-1].id])['success']);self.assertFalse(self.agent._stop_after_tool())
    def test_normal_update_and_stop_revalidate_all_fields(self):
        a=self.automatic('one');b=self.automatic('two');self.assertTrue(self.create([a,b])['success'])
        hypothesis=self.agent.hypotheses[0];self.assertTrue(self.agent._stop_after_tool())
        result=self.agent._tool_hypothesis_update({'id':hypothesis.id,'title':'must not mutate','evidence_ids':[]})
        self.assertFalse(result['success']);self.assertEqual(hypothesis.title,'synthetic hypothesis');self.assertEqual(hypothesis.evidence_ids,[a,b])
        self.agent.evidence[0].description='changed after acceptance';self.assertFalse(self.agent._stop_after_tool())
        self.agent._finalize_hypotheses();self.assertEqual(hypothesis.status,'investigating')
