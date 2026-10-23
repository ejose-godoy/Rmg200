"""REACH-09: comparativo de KASAN natural e autoteste oficial de pilha, VM-only."""
from pathlib import Path
import ast
import subprocess
import unittest

ROOT=Path(__file__).resolve().parents[1]

class Reach09StackKasan(unittest.TestCase):
    def test_guest_syntax_only(self):
        subprocess.run(["gcc","-O2","-pthread","-Wall","-Wextra","-Werror",
                        "-fsyntax-only",str(ROOT/"initramfs/reach09_init.c")],check=True)

    def test_runner_bash_syntax(self):
        subprocess.run(["bash","-n",str(ROOT/"scripts/run-reach09.sh")],check=True)

    def test_guest_scopes_selftest_after_child(self):
        guest=(ROOT/"initramfs/reach09_init.c").read_text()
        self.assertIn('reach01_vm=1',guest)
        self.assertIn('getpid() != 1',guest)
        self.assertIn('setresuid(10000, 10000, 10000)',guest)
        self.assertIn('REACH08_GUEST_SYSCALL_RETURNED=1',guest)
        self.assertIn('REACH09_VM_ONLY=1',guest)
        self.assertIn('REACH09_NO_SYNTHETIC_DANGLING_DEREFERENCE=1',guest)
        self.assertIn('REACH06_NO_PRIVILEGE_ESCALATION_OBSERVED=1',guest)
        self.assertIn('KASAN_POSITIVE_CONTROL_BEGIN=1',guest)
        self.assertIn('KASAN_POSITIVE_CONTROL_END=1',guest)
        self.assertIn('SYS_init_module',guest)
        self.assertIn('WIFEXITED(status) && WEXITSTATUS(status) == 0',guest)
        self.assertIn('reach09_official_control()',guest)
        self.assertLess(guest.index('waitpid(child, &status, 0)'),guest.index('reach09_official_control()'))

    def test_official_stack_bounds_selftest_and_kasan_config(self):
        runner=(ROOT/"scripts/run-reach09.sh").read_text()
        self.assertIn("CONFIG_KASAN_STACK=1",runner)
        self.assertIn('CONFIG_TEST_KASAN=m',runner)
        self.assertIn('lib/test_kasan.ko',runner)
        self.assertIn('scripts/instrument-reach08.py "$SRC/kernel/locking/rtmutex.c" "$SRC/kernel/futex.c"',runner)
        self.assertIn('initramfs/reach09_init.c',runner)
        self.assertIn("REACH09_KASAN_STACK_POSITIVE_CONTROL=PASS",runner)
        self.assertIn("REACH09_FUTEX_PHASE_KASAN_REPORTS=",runner)
        self.assertIn("REACH09_SELFTEST_PHASE_KASAN_REPORTS=",runner)
        self.assertIn("REACH09_SELFTEST_STACK_OOB_REPORT=",runner)
        self.assertIn('REACH09_STACK_USE_AFTER_RETURN_PROOF=NOT_ESTABLISHED',runner)
        self.assertIn('REACH09_STACK_USE_AFTER_RETURN=NOT_DEMONSTRATED',runner)
        self.assertIn('REACH09_EXPLOIT_NOT_ATTEMPTED=1',runner)
        self.assertIn('MOTOROLA_REAL_DEVICE_TEST=NOT_PERFORMED',runner)
        self.assertIn('KASAN_DETECTION=',runner) if 'KASAN_DETECTION=' in runner else None

    def test_no_false_attribution_of_kasan(self):
        runner=(ROOT/"scripts/run-reach09.sh").read_text()
        self.assertIn("before=log[:i]",runner)
        self.assertIn("selftest=log[i:j]",runner)
        self.assertIn("pre_reports=before.count('BUG: KASAN:')",runner)
        self.assertIn("control_reports=selftest.count('BUG: KASAN:')",runner)
        self.assertIn("out-of-bounds on stack",runner)
        self.assertIn("BUG: KASAN: stack-out-of-bounds",runner)
        self.assertIn("if pre_reports:",runner)
        self.assertIn("if control_reports<2",runner)
        self.assertNotIn("REACH09_UAF=CONFIRMED",runner)
        self.assertIn("REACH08_RETURN_FIELD_EQ_LOCAL_WAITER=$eq",runner)

    def test_workflow_isolated_and_no_sensitive_data(self):
        wf=(ROOT/".github/workflows/arm64-reach09.yml").read_text()
        self.assertIn('branches: [reach09-20261021]',wf)
        self.assertIn('variant: [unpatched, corrected]',wf)
        self.assertIn('fail-fast: false',wf)
        self.assertIn('contents: read',wf)
        self.assertIn('persist-credentials: false',wf)
        self.assertIn('run: bash scripts/run-reach09.sh',wf)
        self.assertNotIn('secrets.',wf)
        self.assertNotIn('pull_request_target:',wf)

if __name__=="__main__":
    unittest.main()
