"""REACH-11: single QEMU workflow, actual provisioned root vs no kernel exploit."""
from pathlib import Path
import subprocess
import unittest

ROOT=Path(__file__).resolve().parents[1]

class Reach11VirtualRoot(unittest.TestCase):
    def test_guest_compiles_without_running(self):
        subprocess.run(["gcc","-O2","-pthread","-Wall","-Wextra","-Werror",
                        "-fsyntax-only",str(ROOT/"initramfs/reach11_init.c")],check=True)

    def test_runner_syntax(self):
        subprocess.run(["bash","-n",str(ROOT/"scripts/run-reach11.sh")],check=True)

    def test_drops_and_checks_unprivileged_uid(self):
        s=(ROOT/"initramfs/reach11_init.c").read_text()
        for v in ["setresuid(10000, 10000, 10000)","setresgid(10000, 10000, 10000)",
                  "REACH06_%s_SETRESUID0_RET", 'reach06_uid_boundary("BEFORE")',
                  'reach06_uid_boundary("AFTER")',
                  "REACH11_UID10000_TO_UID0_BY_EXPLOIT=NOT_OBTAINED",
                  "REACH06_NO_PRIVILEGE_ESCALATION_OBSERVED=1"]:
            self.assertIn(v,s)

    def test_root_control_is_real_kernel_privilege_but_not_exploit(self):
        s=(ROOT/"initramfs/reach11_init.c").read_text()
        for v in ["reach11_provisioned_root_test(int stage)",
                  "getresuid(&r,&e,&s)", "getpid()!=1",
                  'mount("tmpfs","/reach11-rootcheck","tmpfs"',
                  'umount("/reach11-rootcheck")',
                  "REACH11_ROOT_ORIGIN=PROVISIONED_PID1_NOT_EXPLOIT",
                  "REACH11_FIRST_BOOT_ROOT=PASS", "REACH11_SECOND_BOOT=PASS"]:
            self.assertIn(v,s)
        self.assertNotIn("setresuid(0, 0, 0);\n    puts(\"REACH11_FIRST_BOOT_ROOT",s)

    def test_guest_only_qemu_mode(self):
        s=(ROOT/"initramfs/reach11_init.c").read_text()
        for v in ["reach01_vm=1","rdinit=/init","reach11_stage=1","reach11_stage=2",
                  'getpid() != 1', "REACH11_VM_ONLY=1"]:
            self.assertIn(v,s)
        self.assertIn('"/reach11-firstboot-marker"',s)

    def test_runner_requires_existing_differential(self):
        r=(ROOT/"scripts/run-reach11.sh").read_text()
        for v in [
            'scripts/instrument-reach08.py',
            "REACH05_CLEARED_TARGET=WAITER_TASK", "REACH05_CLEARED_TARGET=CURRENT",
            "REACH05_WAITER_PI_BLOCKED_ON_NULL", "REACH01_GUEST_EDEADLK=1",
            "REACH08_SERIAL_ORDER=PASS","REACH06_AFTER_SETRESUID0_RET=-1 ERRNO=1"]:
            self.assertIn(v,r)

    def test_two_independent_guest_boots(self):
        r=(ROOT/"scripts/run-reach11.sh").read_text()
        for v in ["reach11_stage=1","reach11_stage=2",
                  "reports/qemu-serial.log","reports/qemu-second-boot.log",
                  "REACH11_FIRST_BOOT_ROOT=PASS", "REACH11_SECOND_BOOT=PASS",
                  "REACH11_STAGE2_ROOTFS_STARTS_CLEAN=PASS",
                  "REACH11_FRESH_BOOT_MARKER_ABSENT=PASS",
                  "REACH11_ROOT_VIA_GHOSTLOCK=NOT_DEMONSTRATED",
                  "REACH11_UNPRIVILEGED_TO_ROOT_ESCALATION=NOT_OBTAINED",
                  "REACH11_MOTOROLA_ROOT=NOT_OBTAINED"]:
            self.assertIn(v,r)
        self.assertIn("-accel tcg",r)
        self.assertIn("MOTOROLA_REAL_DEVICE_TEST=NOT_PERFORMED",r)

    def test_readonly_ci_and_matrix(self):
        w=(ROOT/".github/workflows/arm64-reach11.yml").read_text()
        self.assertIn("branches: [reach11-20261021]",w)
        self.assertIn("variant: [unpatched, corrected]",w)
        self.assertIn("fail-fast: false",w)
        self.assertIn("contents: read",w)
        self.assertIn("persist-credentials: false",w)
        self.assertIn("run: bash scripts/run-reach11.sh",w)
        self.assertNotIn("secrets.",w)
        self.assertNotIn("pull_request_target:",w)

if __name__=="__main__":
    unittest.main()
