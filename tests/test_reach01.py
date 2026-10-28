"""QA local do REACH-01: nunca executa syscalls Futex no celular."""
import pathlib
import shutil
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class Reach01Isolation(unittest.TestCase):
    def test_bash_scripts_syntax(self):
        subprocess.run(["bash", "-n", str(ROOT / "scripts/run-reach01.sh")],
                       check=True)

    def test_compiler_syntax_only(self):
        cc = shutil.which("cc")
        if not cc:
            self.skipTest("sem compilador C local")
        subprocess.run([cc, "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                        "-pthread", "-fsyntax-only",
                        str(ROOT / "initramfs/reach01_init.c")], check=True)

    def test_unprivileged_vm_guard_and_no_probe(self):
        src = (ROOT / "initramfs/reach01_init.c").read_text()
        self.assertIn('getpid() != 1', src)
        self.assertIn('reach01_vm=1', src)
        self.assertIn('setresuid(10000, 10000, 10000)', src)
        self.assertIn('geteuid() != 10000', src)
        self.assertIn('REACH01_NO_ROOT_NO_UAF_PROBE=1', src)
        self.assertNotIn('futex_UAF_probe', src)

    def test_only_public_kernel_is_instrumented(self):
        patcher = (ROOT / "scripts/instrument-reach01.py").read_text()
        self.assertIn(
            "70f96efb8e45b97b977957e3ecb93a4e63fcaf4e2b7d915d20316f3c4e6263b9",
            patcher)
        self.assertIn("REACH01_REFUSED_SOURCE_SHA_MISMATCH", patcher)
        self.assertIn("REACH01_KERNEL_ROLLBACK_EDEADLK", patcher)
        runner = (ROOT / "scripts/run-reach01.sh").read_text()
        self.assertIn("34b5f809f17e66d5011086a3d90802989e667f75", runner)
        self.assertIn("-accel tcg", runner)
        self.assertIn("reach01_vm=1", runner)
        self.assertIn("initramfs/reach01_init.c", runner)
        self.assertIn("MOTOROLA_REACHABILITY=NOT_PERFORMED", runner)
        self.assertIn("ROOT_ESCALATION=NOT_PERFORMED", runner)
        self.assertNotIn("boot_global_XPENG_", runner)

    def test_workflow_own_branch_and_readonly(self):
        workflow = (ROOT / ".github/workflows/arm64-reach01.yml").read_text()
        self.assertIn("branches: [reach01-20261019]", workflow)
        self.assertIn("contents: read", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertNotIn("secrets.", workflow)
        self.assertNotIn("pull_request_target:", workflow)


if __name__ == "__main__":
    unittest.main(verbosity=2)
