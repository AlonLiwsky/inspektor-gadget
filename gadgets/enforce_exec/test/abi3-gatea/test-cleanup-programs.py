#!/usr/bin/env python3
"""Unprivileged cleanup-join regressions; bpftool is always a local stub."""
import importlib.util
import os
import subprocess
from pathlib import Path
import tempfile
import time
import unittest

HERE = Path(__file__).resolve().parent


class CleanupTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('cleanup_programs', HERE / 'cleanup-programs.py')
        self.helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.helper)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.out = Path(self.tmp.name)
        self.stub = self.out / 'bpftool'
        self.stub.write_text('''#!/usr/bin/env python3
import os, pathlib, sys, time
assert sys.argv[1:4] == ['prog', 'show', 'id']
assert os.environ['LC_ALL'] == 'C'
root = pathlib.Path(__file__).parent
ident = sys.argv[4]
p = root / ('calls-' + ident)
n = int(p.read_text()) if p.exists() else 0
p.write_text(str(n + 1))
mode = (root / ('mode-' + ident)).read_text()
if mode == 'hang': time.sleep(3)
if mode == 'present' or (mode == 'delayed' and n < 2):
    print(ident + ': test')
    sys.exit(0)
if mode == 'permission':
    print('Error: get by id (' + ident + '): Operation not permitted', file=sys.stderr)
elif mode == 'misleading':
    print('Error: cannot open /missing: No such file or directory', file=sys.stderr)
elif mode in ('wrong-status', 'old-status'):
    print('Error: get by id (' + ident + '): No such file or directory', file=sys.stdout if mode == 'wrong-stream' else sys.stderr)
    sys.exit(1 if mode == 'old-status' else 2)
else:
    print('Error: get by id (' + ident + '): No such file or directory', file=sys.stdout if mode == 'wrong-stream' else sys.stderr)
sys.exit(255)
''')
        self.stub.chmod(0o755)

    def run_join(self, modes, timeout=0.6):
        for ident, mode in modes.items():
            (self.out / ('mode-' + ident)).write_text(mode)
        (self.out / 'runner.log').write_text(''.join('PROGRAM_ID ' + ident + ' test_program\n' for ident in modes))
        return self.helper.join(self.out, timeout=timeout, interval=0.02, bpftool=str(self.stub))

    def test_immediate_absent(self):
        self.assertEqual(self.run_join({'113': 'absent'}), 0)

    def test_delayed_and_mixed_ids(self):
        self.assertEqual(self.run_join({'113': 'absent', '115': 'delayed'}), 0)
        self.assertEqual((self.out / 'calls-113').read_text(), '1')
        self.assertEqual((self.out / 'calls-115').read_text(), '3')

    def test_actual_initial_records_and_other_family_formats(self):
        # Exact records copied from original-initial/proof/original-initial/runner.log
        # SHA256 745b4908b5846f09786d5ece115828cd4395af0e51b3aad659cd0c7068a5fdcb.
        initial = """PROGRAM_ID 113 ga_alloc
PROGRAM_ID 114 ga_later
PROGRAM_ID 115 ga_new
PROGRAM_ID 116 ga_failed
PROGRAM_ID 117 ga_free
PROGRAM_ID 118 ga_command
"""
        # Other-family IDs are synthetic, not claims of observed guest execution.
        # Names and three-field format come from each family's BPF/runner source.
        for sub, bpf in (('', 'fixture.bpf.c'), ('ingress', 'ingress.bpf.c'),
                         ('publication', 'publication.bpf.c')):
            runner = (HERE / sub / 'runner.c').read_text()
            self.assertIn('PROGRAM_ID %u %s', runner)
            if not sub:
                records = initial
            else:
                import re
                names = re.findall(r'BPF_PROG\((\w+)', (HERE / sub / bpf).read_text())
                self.assertTrue(names)
                records = ''.join(f'PROGRAM_ID {200 + n} {name}\n' for n, name in enumerate(names))
            ids = [line.split()[1] for line in records.splitlines()]
            for ident in ids:
                (self.out / ('mode-' + ident)).write_text('absent')
            (self.out / 'runner.log').write_text(records)
            self.assertEqual(self.helper.join(self.out, bpftool=str(self.stub)), 0)
            for ident in ids:
                self.assertTrue((self.out / ('calls-' + ident)).exists())

    def test_present_deadline(self):
        started = time.monotonic()
        self.assertEqual(self.run_join({'115': 'present'}, timeout=0.15), 1)
        self.assertLess(time.monotonic() - started, 0.8)

    def test_query_timeout(self):
        started = time.monotonic()
        self.assertEqual(self.run_join({'115': 'hang'}, timeout=0.15), 1)
        self.assertLess(time.monotonic() - started, 0.8)

    def test_query_errors(self):
        for mode in ('permission', 'misleading', 'wrong-status', 'old-status', 'wrong-stream'):
            with self.subTest(mode=mode):
                self.assertEqual(self.run_join({'115': mode}), 1)

    def test_invalid_ids_no_queries(self):
        for ident in ('0', '-1', '01', '4294967296', 'x', '1 extra', ''):
            with self.subTest(ident=ident):
                self.assertEqual(self.run_join({'113': 'absent', ident: 'absent'}), 1)
                self.assertFalse((self.out / 'calls-113').exists())

    def test_missing_tool(self):
        (self.out / 'runner.log').write_text('PROGRAM_ID 115 ga_new\n')
        self.assertEqual(self.helper.join(self.out, bpftool=str(self.out / 'missing')), 1)

    def test_no_ids_on_early_failure(self):
        (self.out / 'runner.log').write_text('runner failed before loading\n')
        self.assertEqual(self.helper.join(self.out, bpftool=str(self.out / 'missing')), 0)

    def test_wrappers_preserve_status_and_refuse_without_consent(self):
        for sub in ('', 'ingress', 'publication'):
            wrapper = HERE / sub / 'run-disposable.sh'
            source = wrapper.read_text()
            cleanup = source[source.index('\ncleanup() {'):source.index('trap cleanup EXIT')]
            for runner_status, helper_status, expected in ((0, 0, 0), (0, 1, 1), (42, 0, 42), (42, 1, 42)):
                with self.subTest(sub=sub, runner=runner_status, helper=helper_status):
                    (self.out / 'runner.log').write_text('')
                    script = ('set -euo pipefail\n'
                              'out=$1; cg=$1/nonexistent; here=$2\n'
                              f'python3() {{ return {helper_status}; }}\n'
                              + cleanup + f'trap cleanup EXIT\nexit {runner_status}\n')
                    result = subprocess.run(['bash', '-c', script, '_', str(self.out), str(wrapper.parent)],
                                            capture_output=True, text=True, timeout=2)
                    self.assertEqual(result.returncode, expected, result.stderr)
            env = dict(os.environ)
            env.pop('IG_ABI3_GATE_A_DISPOSABLE', None)
            evidence = self.out / 'must-not-exist'
            result = subprocess.run(['bash', str(wrapper), '/missing-build', str(evidence)],
                                    env=env, capture_output=True, text=True, timeout=2)
            self.assertEqual(result.returncode, 2)
            self.assertIn('Refusing:', result.stderr)
            self.assertFalse(evidence.exists())
            self.assertIn('cleanup-programs.py', next(line for line in source.splitlines()
                                                     if line.startswith('  sha256sum ')))


if __name__ == '__main__':
    unittest.main()
