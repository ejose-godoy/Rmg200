"""REACH-08: prova de tempo de vida do waiter sem UAF artificial, QEMU-only."""
from pathlib import Path
import ast
import hashlib
import shutil
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
RT_HASH="70f96efb8e45b97b977957e3ecb93a4e63fcaf4e2b7d915d20316f3c4e6263b9"
FUTEX_HASH="fccba7fa429150ce1065d6a2357c2bcd50546e7659005fe9b5956bff38662a33"

class Reach08Lifecycle(unittest.TestCase):
    def test_guest_compilation_only(self):
        subprocess.run(["gcc","-O2","-pthread","-Wall","-Wextra","-Werror",
                        "-fsyntax-only",str(ROOT/"initramfs/reach08_init.c")],check=True)

    def test_bash_and_patcher_syntax(self):
        subprocess.run(["bash","-n",str(ROOT/"scripts/run-reach08.sh")],check=True)
        p=ROOT/"scripts/instrument-reach08.py"
        ast.parse(p.read_text())

    def test_vm_only_and_evidence(self):
        guest=(ROOT/"initramfs/reach08_init.c").read_text()
        for marker in [
            'reach01_vm=1',
            'getpid() != 1',
            'setresuid(10000, 10000, 10000)',
            'getuid() != 10000 || geteuid() != 10000',
            'REACH08_GUEST_SYSCALL_RETURNED=1',
            'REACH08_NO_FORCED_UAF=1',
            'REACH07_SCHED_SYSCALL_COMPLETED=1',
            'sched_setscheduler(target, SCHED_BATCH, &sp)',
        ]:
            self.assertIn(marker,guest)

    def test_patcher_checks_both_originals(self):
        script=(ROOT/"scripts/instrument-reach08.py").read_text()
        for marker in [
            RT_HASH,FUTEX_HASH,'REACH08_REFUSED_FUTEX_SOURCE_HASH',
            'REACH05_REFUSED_SOURCE_HASH',
            'REACH08_REFUSED_LIFETIME_ANCHORS',
            'READ_ONCE(current->pi_blocked_on) == &rt_waiter',
            'READ_ONCE(current->pi_blocked_on) == NULL',
            'REACH08_WAITER_STACK_OBJECT_INITIALIZED=1',
            'REACH08_WAITER_STACK_SCOPE_ABOUT_TO_END=1',
            'REACH07_ADJUST_PI_WAITING_FIELD_NON_NULL=1',
        ]:
            self.assertIn(marker,script)
        self.assertNotIn('probe_kernel_read(',script)
        self.assertNotIn('kasan_check_read(',script)
        self.assertNotIn('%px',script)

    def test_runner_records_pointer_comparison_and_event_order(self):
        runner=(ROOT/"scripts/run-reach08.sh").read_text()
        for marker in [
            'scripts/instrument-reach08.py "$SRC/kernel/locking/rtmutex.c" "$SRC/kernel/futex.c"',
            'initramfs/reach08_init.c',
            'REACH08_RETURN_FIELD_EQ_LOCAL_WAITER=$eq',
            'REACH08_RETURN_FIELD_NULL=$nil',
            'REACH08_GUEST_SYSCALL_RETURNED=1',
            'REACH08_STACK_OBJECT_OUT_OF_SCOPE_AFTER_RETURN=YES',
            'REACH08_UAF_KASAN_PROOF=NOT_YET_DEMONSTRATED',
            'REACH08_SERIAL_ORDER=PASS',
            'REACH08_ROOT_ESCALATION=NOT_DEMONSTRATED',
            'MOTOROLA_REAL_DEVICE_TEST=NOT_PERFORMED',
            '-accel tcg',
        ]:
            self.assertIn(marker,runner)
        self.assertIn('unpatched) eq=1; nil=0',runner)
        self.assertIn('corrected) eq=0; nil=1',runner)

    def test_workflow_isolated(self):
        wf=(ROOT/".github/workflows/arm64-reach08.yml").read_text()
        self.assertIn('branches: [reach08-20261021]',wf)
        self.assertIn('variant: [unpatched, corrected]',wf)
        self.assertIn('fail-fast: false',wf)
        self.assertIn('contents: read',wf)
        self.assertIn('persist-credentials: false',wf)
        self.assertNotIn('secrets.',wf)
        self.assertNotIn('pull_request_target:',wf)
        self.assertIn('run: bash scripts/run-reach08.sh',wf)

    def test_verified_source_application_both_modes(self):
        rt=ROOT.parent/"reach02_precheck"/"source_rtmutex.c"
        futex=ROOT/"work/reach08-futex-original.c"
        if not rt.exists() or not futex.exists():
            self.skipTest("Public sources checked by CI during build, not bundled")
        self.assertEqual(hashlib.sha256(rt.read_bytes()).hexdigest(),RT_HASH)
        self.assertEqual(hashlib.sha256(futex.read_bytes()).hexdigest(),FUTEX_HASH)
        for mode in ["unpatched","corrected"]:
            with tempfile.TemporaryDirectory(dir=ROOT/"work") as tmp:
                a,b=Path(tmp)/"rtmutex.c",Path(tmp)/"futex.c"
                shutil.copyfile(rt,a)
                shutil.copyfile(futex,b)
                out=subprocess.run(["python3",str(ROOT/"scripts/instrument-reach08.py"),
                                    str(a),str(b),mode],capture_output=True,text=True)
                self.assertEqual(out.returncode,0,out.stderr)
                patched=b.read_text()
                self.assertEqual(patched.count('REACH08_RETURN_FIELD_EQ_LOCAL_WAITER'),1)
                self.assertEqual(patched.count('REACH08_WAITER_STACK_SCOPE_ABOUT_TO_END'),1)
                self.assertEqual(patched.count('READ_ONCE(current->pi_blocked_on) == &rt_waiter'),1)
                self.assertIn('REACH05_WAITER_PI_BLOCKED_ON_EQ_WAITER',a.read_text())
                self.assertIn('REACH07_ADJUST_PI_WAITING_FIELD_NON_NULL',a.read_text())

if __name__=="__main__":
    unittest.main()
