"""REACH-06: isolamento QEMU e verificacao de fronteira de UID real."""
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]

class Reach06Controls(unittest.TestCase):
    def test_guest_compiles_without_running(self):
        # No executable and no syscalls from host: compiler syntax only.
        subprocess.run(["gcc", "-O2", "-pthread", "-Wall", "-Wextra", "-Werror",
                        "-fsyntax-only",str(ROOT/"initramfs/reach06_init.c")], check=True)

    def test_bash_syntax(self):
        subprocess.run(["bash","-n",str(ROOT/"scripts/run-reach06.sh")],check=True)

    def test_hardened_uid_boundary(self):
        src=(ROOT/"initramfs/reach06_init.c").read_text()
        self.assertIn("reach06_uid_boundary(\"BEFORE\")",src)
        self.assertIn("reach06_uid_boundary(\"AFTER\")",src)
        self.assertIn("setresuid(0, 0, 0)",src)
        self.assertIn("if (ret != -1 || error != EPERM)",src)
        self.assertIn("getresuid(&ruid, &euid, &suid)",src)
        self.assertIn("getuid() != 10000 || geteuid() != 10000",src)
        self.assertIn("setresuid(10000, 10000, 10000)",src)
        self.assertIn("setresgid(10000, 10000, 10000)",src)
        self.assertIn('REACH06_EXPLOIT_NOT_ATTEMPTED=1',src)
        self.assertIn('REACH06_PID1_ROOT_IS_NOT_AN_EXPLOIT=1',src)
        self.assertIn('reach01_vm=1',src)
        self.assertIn('getpid() != 1',src)
        self.assertIn('REACH01_GUEST_EDEADLK=1',src)

    def test_two_public_qemu_variants_and_marker_fail_closed(self):
        runner=(ROOT/"scripts/run-reach06.sh").read_text()
        self.assertIn('REACH06_VARIANT',runner)
        self.assertIn('scripts/instrument-reach05.py',runner)
        self.assertIn('initramfs/reach06_init.c',runner)
        self.assertIn('REACH06_PRECHECK_UID_BOUNDARY=PASS',runner)
        self.assertIn('REACH06_POSTCHECK_UID_BOUNDARY=PASS',runner)
        self.assertIn('REACH06_BEFORE_SETRESUID0_RET=-1 ERRNO=1',runner)
        self.assertIn('REACH06_AFTER_SETRESUID0_RET=-1 ERRNO=1',runner)
        self.assertIn('REACH06_UID10000_TO_ROOT=NOT_OBSERVED',runner)
        self.assertIn('REACH06_INITIAL_ROOT_PID1=BASELINE_ONLY',runner)
        self.assertIn('REACH06_ROOT_EXPLOIT=NOT_ATTEMPTED',runner)
        self.assertIn('REACH05_WAITER_PI_BLOCKED_ON_EQ_WAITER',runner)
        self.assertIn('REACH05_WAITER_PI_BLOCKED_ON_NULL',runner)
        self.assertIn('MOTOROLA_REAL_DEVICE_TEST=NOT_PERFORMED',runner)
        self.assertIn('-accel tcg',runner)
        self.assertIn('reach01_vm=1',runner)

    def test_workflow_isolated_from_phone_and_repo_main(self):
        w=(ROOT/".github/workflows/arm64-reach06.yml").read_text()
        self.assertIn('branches: [reach06-20261020]',w)
        self.assertIn('variant: [unpatched, corrected]',w)
        self.assertIn('fail-fast: false',w)
        self.assertIn('contents: read',w)
        self.assertIn('persist-credentials: false',w)
        self.assertNotIn('secrets.',w)
        self.assertNotIn('pull_request_target:',w)
        self.assertIn('run: bash scripts/run-reach06.sh',w)
        self.assertNotIn('scripts/instrument-reach06.py',w)

if __name__=="__main__":
    unittest.main()
