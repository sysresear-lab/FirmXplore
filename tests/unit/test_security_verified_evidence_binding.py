from pathlib import Path
import json,tempfile,unittest
from fwagent.dynamic.static_evidence import BinaryIdentity,JsonEvidenceStore,StaticEvidence,validate_evidence_bundle


class ExportIdentityBindingTests(unittest.TestCase):
    def test_normal_and_cross_binary_task_and_pointer_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);store=JsonEvidenceStore(root,task_id='task-a');artifact='exports.json'
            document={'task_id':'task-a','analyses':[{'target':{'path':'/bin/'+name},'result':{'summary':{'sha256':digest*64},'functions':[{'name':'same','address':'00401000'}]}} for name,digest in [('a','a'),('b','b')]]}
            (root/artifact).write_text(json.dumps(document))
            identity=BinaryIdentity.from_export('/bin/a',{'sha256':'a'*64},task_id='task-a',hash_origin=artifact+'#/analyses/0/result/summary/sha256',path_origin=artifact+'#/analyses/0/target/path')
            ref,_=store.reference(artifact,'/analyses/0/result/functions/0')
            record=StaticEvidence('source',identity,**ref,function_entry='00401000',status='observed')
            self.assertEqual(validate_evidence_bundle([record],store),[])
            badref,_=store.reference(artifact,'/analyses/1/result/functions/0')
            bad=StaticEvidence('source',identity,**badref,function_entry='00401000',status='observed')
            self.assertTrue(validate_evidence_bundle([bad],store))
            self.assertTrue(validate_evidence_bundle([record],JsonEvidenceStore(root,task_id='task-b')))
            record.binary_identity.rootfs_path_origin=artifact+'#/analyses/1/target/path'
            self.assertTrue(validate_evidence_bundle([record],store))
