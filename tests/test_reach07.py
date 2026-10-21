"""REACH-07 — guardas do teste comparativo exclusivamente QEMU."""
from pathlib import Path
import ast
import hashlib
import shutil
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
SOURCE_SHA="70f96efb8e45b97b977957e3ecb93a4e63fcaf4e2b7d915d20316f3c4e6263b9"

class Reach07VMOnly(unittest.TestCase):
    def test_guest_syntax_no_execution(self):
        subprocess.run(["gcc","-O2","-pthread","-Wall","-Wextra","-Werror",
                        "-fsyntax-only",str(ROOT/"initramfs/reach07_init.c")],check=True)
    def test_script_syntax(self):
        subprocess.run(["bash","-n",str(ROOT/"scripts/run-reach07.sh")],check=True)
        p=ROOT/"scripts/instrument-reach07.py"
        ast.parse(p.read_text())
    def test_vm_identity_and_scheduler_only(self):
        src=(ROOT/"initramfs/reach07_init.c").read_text()
        self.assertIn('getpid() != 1',src)
        self.assertIn('reach01_vm=1',src)
        self.assertIn('setresuid(10000, 10000, 10000)',src)
        self.assertIn('getuid() != 10000 || geteuid() != 10000',src)
        self.assertIn('sched_setscheduler(target, SCHED_BATCH, &sp)',src)
        self.assertIn('reach07_waiter_returned',src)
        self.assertIn('reach07_sched_done',src)
        self.assertIn('REACH07_SCHED_SYSCALL_COMPLETED=1',src)
        self.assertIn('REACH07_NO_ARTIFICIAL_DEREFERENCE=1',src)
        self.assertIn('REACH06_NO_PRIVILEGE_ESCALATION_OBSERVED=1',src)
    def test_no_synthetic_kernel_uaf(self):
        src=(ROOT/"scripts/instrument-reach07.py").read_text()
        self.assertIn(SOURCE_SHA,src)
        self.assertIn('REACH05_REFUSED_SOURCE_HASH',src)
        self.assertIn('sched_src.count(before) != 1',src)
        self.assertIn('REACH07_ADJUST_PI_WAITING_FIELD_NON_NULL=1',src)
        self.assertIn('next_lock = waiter->lock;',src)
        self.assertIn('READ_ONCE(waiter->task->pi_blocked_on)',src)
        self.assertNotIn('kasan_check_read(',src)
        self.assertNotIn('probe_kernel_read(',src)
        self.assertNotIn('%px',src)
    def test_vm_matrix_and_criteria(self):
        w=(ROOT/".github/workflows/arm64-reach07.yml").read_text()
        self.assertIn('branches: [reach07-20261020]',w)
        self.assertIn('variant: [unpatched, corrected]',w)
        self.assertIn('contents: read',w)
        self.assertIn('persist-credentials: false',w)
        self.assertNotIn('secrets.',w)
        self.assertNotIn('pull_request_target:',w)
        r=(ROOT/"scripts/run-reach07.sh").read_text()
        self.assertIn('initramfs/reach07_init.c',r)
        self.assertIn('scripts/instrument-reach07.py',r)
        self.assertIn('REACH07_SCHED_SET_BATCH_RET=0 ERRNO=0',r)
        self.assertIn('REACH07_UNPATCHED_NATURAL_SCHED_SINK=',r)
        self.assertIn('KASAN_DETECTION=NOT_OBSERVED',r)
        self.assertIn('REACH07_ROOT_ESCALATION=NOT_DEMONSTRATED',r)
        self.assertIn('MOTOROLA_REAL_DEVICE_TEST=NOT_PERFORMED',r)
        self.assertIn('-accel tcg',r)
        self.assertIn('reach01_vm=1',r)
    def test_patcher_pinned_source(self):
        p=ROOT.parent/"reach02_precheck"/"source_rtmutex.c"
        if not p.exists():
            self.skipTest("Reference is fetched and SHA checked by CI runner")
        self.assertEqual(hashlib.sha256(p.read_bytes()).hexdigest(),SOURCE_SHA)
        scratch_root=ROOT/"work"
        scratch_root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch_root) as tmp:
            for v in ("unpatched","corrected"):
                dest=Path(tmp)/("rtmutex-"+v+".c")
                shutil.copyfile(p,dest)
                result=subprocess.run(["python3",str(ROOT/"scripts/instrument-reach07.py"),
                                       str(dest),v],capture_output=True,text=True)
                self.assertEqual(result.returncode,0,result.stderr)
                body=dest.read_text()
                self.assertEqual(body.count('REACH07_ADJUST_PI_WAITING_FIELD_NON_NULL'),1)
                self.assertEqual(body.count('READ_ONCE(waiter->task->pi_blocked_on)'),1)
                self.assertEqual(body.count('REACH05_WAITER_PI_BLOCKED_ON_EQ_WAITER'),1)

if __name__=="__main__":
    unittest.main()
