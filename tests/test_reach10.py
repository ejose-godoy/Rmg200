"""REACH-10: diagnostico explicito do KASAN shadow apos o rollback Futex (VM)."""
from pathlib import Path
import ast
import hashlib
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
RT_SHA = "70f96efb8e45b97b977957e3ecb93a4e63fcaf4e2b7d915d20316f3c4e6263b9"
FUTEX_SHA = "fccba7fa429150ce1065d6a2357c2bcd50546e7659005fe9b5956bff38662a33"

class Reach10MemoryShadow(unittest.TestCase):
    def test_runner_shell_syntax(self):
        subprocess.run(["bash","-n",str(ROOT/"scripts/run-reach10.sh")],check=True)

    def test_patcher_python_syntax(self):
        ast.parse((ROOT/"scripts/instrument-reach10.py").read_text())

    def test_pinned_public_sources_and_explicit_probe(self):
        s=(ROOT/"scripts/instrument-reach10.py").read_text()
        self.assertIn(RT_SHA,s)
        self.assertIn(FUTEX_SHA,s)
        self.assertIn("REACH05_REFUSED_SOURCE_HASH",s)
        self.assertIn("REACH08_REFUSED_FUTEX_SOURCE_HASH",s)
        self.assertIn("REACH10_REFUSED_SHADOW_CHECK_ANCHOR",s)
        self.assertIn("__kasan_check_read(waiter, sizeof(*waiter))",s)
        self.assertIn("#include <linux/kasan-checks.h>",s)
        self.assertIn('if mode == "unpatched":',s)
        self.assertIn('REACH10_EXPLICIT_SHADOW_QUERY_BEGIN=1',s)
        self.assertIn('REACH10_KASAN_SHADOW_READABLE=%d',s)
        self.assertIn('REACH10_EXPLICIT_SHADOW_QUERY_END=1',s)
        self.assertIn('This is NOT a natural kernel access',s)
        self.assertNotIn("kasan_poison_shadow(",s)
        self.assertNotIn("kasan_unpoison_shadow(",s)

    def test_guest_baseline_unchanged_and_unprivileged(self):
        guest=(ROOT/"initramfs/reach08_init.c").read_text()
        self.assertIn('reach01_vm=1',guest)
        self.assertIn('getpid() != 1',guest)
        self.assertIn('setresuid(10000, 10000, 10000)',guest)
        self.assertIn('REACH06_NO_PRIVILEGE_ESCALATION_OBSERVED=1',guest)
        self.assertIn('REACH08_GUEST_SYSCALL_RETURNED=1',guest)
        self.assertIn('REACH07_SCHED_SYSCALL_COMPLETED=1',guest)

    def test_runner_distinguishes_explicit_from_natural(self):
        r=(ROOT/"scripts/run-reach10.sh").read_text()
        self.assertIn('CONFIG_KASAN_STACK=1',r)
        self.assertIn('scripts/instrument-reach10.py',r)
        self.assertIn('initramfs/reach08_init.c',r)
        self.assertIn('REACH10_SHADOW_SYMBOL_AUDIT=PASS',r)
        self.assertIn(' U __kasan_check_read$',r)
        self.assertIn('REACH10_KASAN_SHADOW_READABLE=[01]',r)
        self.assertIn('REACH10_EXPLICIT_SHADOW_QUERY=NO_WAITER',r)
        self.assertIn('REACH10_SHADOW_QUERY_IS_ARTIFICIAL=YES',r)
        self.assertIn('REACH10_ORGANIC_UAF_PROOF=NOT_ESTABLISHED',r)
        self.assertIn('REACH10_STACK_UAR_KASAN_CAPABILITY=NOT_PROVEN_BY_QUERY',r)
        self.assertIn('REACH10_ROOT_ESCALATION=NOT_DEMONSTRATED',r)
        self.assertIn('MOTOROLA_REAL_DEVICE_TEST=NOT_PERFORMED',r)
        self.assertIn('-accel tcg',r)
        self.assertNotIn('scripts/instrument-reach09.py',r)

    def test_workflow_two_vm_variant_only(self):
        w=(ROOT/".github/workflows/arm64-reach10.yml").read_text()
        self.assertIn('branches: [reach10-20261021]',w)
        self.assertIn('variant: [unpatched, corrected]',w)
        self.assertIn('fail-fast: false',w)
        self.assertIn('contents: read',w)
        self.assertIn('persist-credentials: false',w)
        self.assertNotIn('secrets.',w)
        self.assertNotIn('pull_request_target:',w)
        self.assertIn('run: bash scripts/run-reach10.sh',w)

    def test_real_source_patch_both_modes(self):
        a=ROOT.parent/"reach02_precheck"/"source_rtmutex.c"
        b=ROOT/"work/reach08-futex-original.c"
        if not a.exists() or not b.exists():
            self.skipTest("CI retrieves public source and validates hashes")
        self.assertEqual(hashlib.sha256(a.read_bytes()).hexdigest(),RT_SHA)
        self.assertEqual(hashlib.sha256(b.read_bytes()).hexdigest(),FUTEX_SHA)
        work=ROOT/"work"
        work.mkdir(exist_ok=True)
        for variant in ("unpatched","corrected"):
            with tempfile.TemporaryDirectory(dir=work) as tmp:
                rt=Path(tmp)/"rtmutex.c"; ft=Path(tmp)/"futex.c"
                shutil.copyfile(a,rt);shutil.copyfile(b,ft)
                out=subprocess.run(["python3",str(ROOT/"scripts/instrument-reach10.py"),
                                   str(rt),str(ft),variant],capture_output=True,text=True)
                self.assertEqual(out.returncode,0,out.stderr)
                patched=rt.read_text()
                self.assertEqual(patched.count("__kasan_check_read(waiter, sizeof(*waiter))"),
                                 1 if variant=="unpatched" else 0)
                self.assertEqual(patched.count("#include <linux/kasan-checks.h>"),
                                 1 if variant=="unpatched" else 0)
                self.assertIn("REACH05_WAITER_PI_BLOCKED_ON_EQ_WAITER",patched)
                self.assertIn("REACH07_ADJUST_PI_WAITING_FIELD_NON_NULL",patched)
                self.assertIn("REACH08_RETURN_FIELD_EQ_LOCAL_WAITER",ft.read_text())

if __name__=="__main__":
    unittest.main()
