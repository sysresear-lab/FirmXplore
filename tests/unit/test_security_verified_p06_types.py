import unittest
from tests.unit.test_p06_evidence import p06,fixture


class StrictEvidenceTypesTests(unittest.TestCase):
    def test_normal_and_rejected_type_mutations(self):
        self.assertEqual(p06.validate_sidecar(fixture())['instructions'],1)
        changes=[lambda d:d.update(analysis_timed_out=0),
                 lambda d:d['decompiler'].update(completed='true'),
                 lambda d:d['instructions'][0].update(flow_is_call='true'),
                 lambda d:d['instructions'][0]['references'][0].update(is_call='true'),
                 lambda d:d['ssa_values'][0]['uses_in_exported_ops'][0].update(input_index=False),
                 lambda d:d.update(instructions=[]),
                 lambda d:d.update(binary=[]),lambda d:d.update(ssa_ops=[None]),
                 lambda d:d['instructions'][0].update(raw_pcode={}),
                 lambda d:d['ssa_state'].update(status=[])]
        for change in changes:
            with self.subTest(change=change):
                data=fixture();change(data)
                with self.assertRaises(ValueError):p06.validate_sidecar(data)
