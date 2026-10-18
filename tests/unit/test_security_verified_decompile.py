from pathlib import Path
import json,tempfile,unittest
from unittest.mock import Mock,patch
from fwagent.models import CommandResult
from fwagent.runtime.ghidra import GhidraRuntime
from fwagent.investigation.agent import PiAgent


class DecompileContractTests(unittest.TestCase):
    def test_normal_empty_missing_function_and_timed_out_results(self):
        ordinary={'status':'observed','completed':True,'timed_out':False,'name':'main','address':'00401000','decompiled_code':'int main(){return 0;}'}
        for change,expected in (({},True),({'decompiled_code':''},False),({'address':''},False),({'completed':False},False),({'timed_out':True},False),({'status':'unavailable'},False)):
            with self.subTest(change=change),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);runtime=GhidraRuntime(root,runner=Mock());payload=dict(ordinary,**change)
                def command(*args):
                    output=args[-1];output.write_text(json.dumps(payload));return ['fake-headless']
                runtime.runner.run.return_value=CommandResult([],0,'','',0)
                with patch.object(runtime,'build_decompile_command',side_effect=command):result=runtime.decompile_function(root/'dummy.elf','main')
                self.assertEqual(result.success,expected)
    def test_empty_success_shell_never_records_decompilation_evidence(self):
        agent=object.__new__(PiAgent);agent.evidence=[];agent._trusted_evidence={}
        agent._auto_record_evidence('ghidra.decompile_function',{'binary':'/bin/app','function':'main'},{'success':True,'result':{'name':'main','decompiled_code':''}})
        self.assertEqual(agent.evidence,[])
        agent._auto_record_evidence('ghidra.decompile_function',{'binary':'/bin/app','function':'main'},{'success':True,'result':{'name':'main','decompiled_code':'int main(){}'}})
        self.assertEqual(len(agent.evidence),1)
