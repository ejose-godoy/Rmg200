"""REACH-05: verificacao estatica de ensaio QEMU com medida de estado residual."""
from pathlib import Path
import hashlib
import shutil
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
SOURCE_HASH="70f96efb8e45b97b977957e3ecb93a4e63fcaf4e2b7d915d20316f3c4e6263b9"

class Reach05Guards(unittest.TestCase):
    def test_bash_syntax(self):
        subprocess.run(["bash","-n",str(ROOT/"scripts/run-reach05.sh")],check=True)
    def test_patcher_source_guards(self):
        s=(ROOT/"scripts/instrument-reach05.py").read_text()
        compile(s,"instrument-reach05.py","exec")
        self.assertIn(SOURCE_HASH,s)
        self.assertIn("REACH05_REFUSED_SOURCE_HASH",s)
        self.assertIn("READ_ONCE(waiter->task->pi_blocked_on)",s)
        self.assertIn("remaining == waiter",s)
        self.assertIn("remaining == NULL",s)
        self.assertIn("if (waiter->task && waiter->task != current)",s)
        self.assertIn("REACH05_WAITER_PI_BLOCKED_ON_NULL",s)
        self.assertIn("REACH05_WAITER_PI_BLOCKED_ON_EQ_WAITER",s)
        self.assertNotIn("%px",s)
    def test_ci_matrix_and_isolation(self):
        w=(ROOT/".github/workflows/arm64-reach05.yml").read_text()
        self.assertIn("branches: [reach05-20261020]",w)
        self.assertIn("variant: [unpatched, corrected]",w)
        self.assertIn("fail-fast: false",w)
        self.assertIn("contents: read",w)
        self.assertIn("persist-credentials: false",w)
        self.assertNotIn("secrets.",w)
        self.assertNotIn("pull_request_target:",w)
        r=(ROOT/"scripts/run-reach05.sh").read_text()
        self.assertIn("reach01_vm=1",r)
        self.assertIn("REACH01_GUEST_UID=10000 EUID=10000",r)
        self.assertIn("initramfs/reach01_init.c",r)
        self.assertIn("REACH05_VARIANT",r)
        self.assertIn("REACH05_TASKS_DIFFER=1",r)
        self.assertIn('expected_remaining=1',r)
        self.assertIn('expected_remaining=0',r)
        self.assertIn('expected_null=0',r)
        self.assertIn('expected_null=1',r)
        self.assertIn("REACH05_CONTROL=PASS",r)
        self.assertIn("MOTOROLA_REAL_DEVICE_TEST=NOT_PERFORMED",r)
        self.assertIn("ROOT_ESCALATION=NOT_PERFORMED",r)
    def test_baseline_guest_unchanged(self):
        x=(ROOT/"initramfs/reach01_init.c").read_text()
        self.assertIn("getuid() != 10000",x)
        self.assertIn("REACH01_NO_ROOT_NO_UAF_PROBE=1",x)
    def test_source_patch_is_pure_and_fail_closed(self):
        # Only run integration check when pinned public source is present:
        # pre-existing local cache in permitted laboratory, not included in repository.
        p=ROOT.parents[0]/"reach02_precheck"/"source_rtmutex.c"
        if not p.exists():
            self.skipTest("Original reference not vendored; CI preflight checks it during build")
        self.assertEqual(hashlib.sha256(p.read_bytes()).hexdigest(),SOURCE_HASH)
        base=ROOT/"work"
        base.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=base) as scratch:
            for variant in ("unpatched","corrected"):
                dest=Path(scratch)/("rtmutex-"+variant+".c")
                shutil.copyfile(p,dest)
                result=subprocess.run(["python3",str(ROOT/"scripts/instrument-reach05.py"),
                                       str(dest),variant],text=True,capture_output=True)
                self.assertEqual(result.returncode,0,result.stderr)
                data=dest.read_text()
                self.assertIn('remaining = READ_ONCE(waiter->task->pi_blocked_on);',data)
                self.assertEqual(data.count("REACH05_WAITER_PI_BLOCKED_ON_NULL"),1)
                self.assertEqual(data.count("REACH05_WAITER_PI_BLOCKED_ON_EQ_WAITER"),1)
                if variant=="corrected":
                    self.assertIn("waiter_task->pi_blocked_on = NULL;",data)
                else:
                    self.assertIn("current->pi_blocked_on = NULL;",data)

if __name__=="__main__":
    unittest.main()
