from pathlib import Path
import tempfile,unittest
from unittest.mock import patch
from fwagent.dynamic import application as app


class IncludeBudgetTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);self.root=Path(tmp.name)
        (self.root/'etc/conf.d').mkdir(parents=True)
    def write(self,name,text):p=self.root/name;p.write_text(text,encoding='utf-8');return p
    def test_normal_glob_and_alias_cycle(self):
        self.write('etc/main.conf','include "/etc/conf.d/*.conf"\n')
        self.write('etc/conf.d/a.conf','include "/etc/./main.conf"\nserver.port = 80\n')
        result=app.resolve_lighttpd_config(self.root,'/etc/main.conf')
        self.assertEqual(len(result['sources']),2);self.assertIn('server.port = 80',result['effective_text'])
    def test_depth_file_and_total_byte_limits_are_enforced(self):
        for i in range(4):self.write(f'etc/{i}.conf',(f'include "/etc/{i+1}.conf"\n' if i<3 else '# ordinary\n'))
        for name,value in [('MAX_INCLUDE_DEPTH',2),('MAX_INCLUDE_FILES',2),('MAX_INCLUDE_TOTAL_BYTES',32)]:
            with self.subTest(limit=name),patch.object(app,name,value),self.assertRaises(ValueError):app.resolve_lighttpd_config(self.root,'/etc/0.conf')
    def test_single_file_and_line_limits_are_enforced(self):
        self.write('etc/main.conf','# harmless\n'*4)
        for name,value in [('MAX_INCLUDE_FILE_BYTES',8),('MAX_INCLUDE_LINES',2)]:
            with patch.object(app,name,value),self.assertRaises(ValueError):app.resolve_lighttpd_config(self.root,'/etc/main.conf')
    def test_traversal_and_recursive_patterns_rejected(self):
        for value in ('/../outside','/etc/**/a.conf','/etc/*/*.conf'):
            with self.subTest(value=value),self.assertRaises(ValueError):app._resolve_include_pattern(self.root,value)
    def test_enumeration_budget_stops_before_unbounded_collection(self):
        for i in range(4):self.write(f'etc/conf.d/{i}.conf','# tiny\n')
        with patch.object(app,'MAX_INCLUDE_ENUMERATED',2),self.assertRaises(ValueError):app._resolve_include_pattern(self.root,'/etc/conf.d/*.conf')
