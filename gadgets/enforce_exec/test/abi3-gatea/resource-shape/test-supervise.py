#!/usr/bin/env python3
"""Puremock processes/IDs only. Never calls bpftool, BPF or the real runner."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import time
import unittest

spec = importlib.util.spec_from_file_location('supervise', Path(__file__).with_name('supervise.py'))
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)


class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.out = Path(self.tmp.name)
        self.stub = self.out / 'fake-bpftool'
        self.stub.write_text('''#!/usr/bin/env python3
import os, pathlib, sys, time
assert sys.argv[1] in ['map','prog'] and sys.argv[2:4] == ['show','id']
assert os.environ['LC_ALL'] == 'C'
root=pathlib.Path(__file__).parent
mode=(root/'mode').read_text()
with (root/'queries').open('a') as f: f.write(' '.join(sys.argv[1:])+'\\n')
if mode=='hang': time.sleep(5)
if mode=='permission':
 print('Error: Operation not permitted',file=sys.stderr);sys.exit(255)
if mode=='present': sys.exit(0)
kind='map ' if sys.argv[1]=='map' else ''
print('Error: get '+kind+'by id ('+sys.argv[4]+'): No such file or directory',file=sys.stderr)
sys.exit(255)
''')
        self.stub.chmod(0o755)
        (self.out/'mode').write_text('absent')
        self.child = self.out/'child.py'

    def run_case(self, ending, complete=True, timeout=3, cleanup_timeout=2):
        self.child.write_text('import os, signal, sys, time\nprint("LOAD_BEGIN",flush=True)\n'
                             + ('print("PROGRAM_ID 99 shape",flush=True)\n'
                                'for i in range(1,13): print("MAP_ID",i,"map"+str(i),flush=True)\n'
                                'print("OWNERSHIP_COMPLETE 12 1",flush=True)\n' if complete else '')
                             + ending+'\n')
        return s.supervise([sys.executable,str(self.child)],self.out,timeout=timeout,
                           grace=0.05,cleanup_timeout=cleanup_timeout,bpftool=str(self.stub))

    def test_success(self):
        self.assertEqual(self.run_case('sys.exit(0)'),0)
        self.assertEqual(len((self.out/'queries').read_text().splitlines()),13)

    def test_assertion_failure_still_joins(self):
        self.assertEqual(self.run_case('assert False'),1)
        self.assertEqual((self.out/'cleanup-status').read_text(),'0\n')
        self.assertEqual(len((self.out/'queries').read_text().splitlines()),13)

    def test_failure_not_masked_by_cleanup_failure(self):
        (self.out/'mode').write_text('permission')
        self.assertEqual(self.run_case('sys.exit(42)'),42)
        self.assertEqual((self.out/'cleanup-status').read_text(),'1\n')

    def test_success_cannot_mask_cleanup_failure(self):
        (self.out/'mode').write_text('permission')
        self.assertEqual(self.run_case('sys.exit(0)'),1)
        self.assertEqual((self.out/'runner-status').read_text(),'0\n')

    def test_term_ignored_timeout_kill_flush_and_join(self):
        start=time.monotonic()
        self.assertEqual(self.run_case('signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(10)',timeout=0.2),124)
        self.assertLess(time.monotonic()-start,4)
        self.assertEqual((self.out/'cleanup-status').read_text(),'0\n')
        self.assertIn('MAP_ID 12 map12', (self.out/'runner.log').read_text())
        self.assertEqual(len((self.out/'queries').read_text().splitlines()),13)

    def test_partial_load_is_not_absence_proof(self):
        self.assertEqual(self.run_case('sys.exit(7)',complete=False),7)
        self.assertEqual((self.out/'cleanup-status').read_text(),'1\n')
        self.assertIn('UNPROVEN',(self.out/'ownership-status').read_text())

    def test_cleanup_timeout_is_bounded(self):
        (self.out/'mode').write_text('hang')
        start=time.monotonic()
        self.assertEqual(self.run_case('sys.exit(0)',cleanup_timeout=0.1),1)
        self.assertLess(time.monotonic()-start,2)

    def test_exact_map_classifier(self):
        expected='Error: get map by id (12): No such file or directory\n'
        self.assertTrue(s.map_absent(255,'',expected,'12'))
        for status,out,err in [(1,'',expected),(255,expected,''),(255,'','Error: missing file: No such file or directory\n'),(255,'',expected.replace('(12)','(13)')),(255,'',expected+'extra\n'),(255,'','Error: get map by id (12): Operation not permitted\n')]:
            self.assertFalse(s.map_absent(status,out,err,'12'))

    def test_partial_malformed_duplicate_ownership(self):
        for text in ['MAP_ID 0 bad\n', 'MAP_ID 1 x\nMAP_ID 1 x\n','MAP_ID 4294967296 x\n','MAP_ID 1 x trailing\n']:
            self.assertFalse(s.ownership(text)[1])

    def test_c_runner_unbuffers_before_load(self):
        source=Path(__file__).with_name('runner.c').read_text()
        self.assertLess(source.index('setvbuf(stdout,NULL,_IONBF,0)'),source.index('bpf_object__load(obj)'))
        self.assertLess(source.index('OWNERSHIP_COMPLETE 12 1'),source.index('storage();cycles();'))
        self.assertLess(source.index('rs_program_type_valid(obj)'),source.index('puts("LOAD_BEGIN")'))
        self.assertNotIn('bpf_program__set_type',source)
        self.assertNotIn('bpf_program__set_flags',source)


if __name__=='__main__':
    unittest.main()
