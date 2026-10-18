from pathlib import Path
import tempfile,unittest
from unittest.mock import Mock,patch
from fwagent.runtime.ghidra import GhidraRuntime
from fwagent.pipeline.product import AnalysisPipelineController


class ContainerClosureTests(unittest.TestCase):
    def test_all_ordinary_container_entrypoints_fail_before_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);runner=Mock();runtime=GhidraRuntime(root,runner=runner)
            check=runtime.check_container_environment();export=runtime.export_binary_containerized(root/'ordinary.elf')
            controller=AnalysisPipelineController(root)
            with patch('fwagent.pipeline.product.subprocess.run') as execute:
                result=controller._docker_extract_rootfs('new-task',root/'ordinary.img',timeout=1)
            self.assertFalse(check['success']);self.assertFalse(export.success);self.assertFalse(result['success'])
            self.assertIn('BLOCKED',result['error_code']);execute.assert_not_called();runner.run.assert_not_called()
            self.assertFalse((root/'new-task').exists())
    def test_host_static_command_building_remains_available(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);runtime=GhidraRuntime(root,runner=Mock())
            with patch.object(runtime,'analyze_headless_path',return_value=root/'fake-headless'):
                cmd=runtime.build_export_command(root/'ordinary.elf','test',root/'outputs')
            self.assertIn('-import',cmd);self.assertNotIn('docker',cmd)
