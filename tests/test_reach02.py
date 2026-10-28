"""REACH-02: guardas estaticas sem Futex, QEMU ou execucao no dispositivo."""
from pathlib import Path
import shutil
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]


class Reach02Safety(unittest.TestCase):
    def test_shell_syntax(self):
        subprocess.run(["bash", "-n", str(ROOT / "scripts/run-reach02.sh")], check=True)

    def test_python_patcher_syntax(self):
        script = ROOT / "scripts/instrument-reach02.py"
        source = script.read_text()
        compile(source, str(script), "exec")
        self.assertIn("REACH02_REFUSED_SOURCE_HASH", source)
        self.assertIn("waiter->task", source)
        self.assertIn("REACH02_TASKS_DIFFER=", source)
        self.assertIn("REACH02_CLEARED_TARGET=", source)
        self.assertIn("70f96efb8e45b97b977957e3ecb93a4e63fcaf4e2b7d915d20316f3c4e6263b9", source)

    def test_vm_and_unprivileged_guard_reused(self):
        src = (ROOT / "initramfs/reach01_init.c").read_text()
        runner = (ROOT / "scripts/run-reach02.sh").read_text()
        self.assertIn('setresuid(10000, 10000, 10000)', src)
        self.assertIn("getuid() != 10000", src)
        self.assertIn("reach01_vm=1", src)
        self.assertIn("reach01_vm=1", runner)
        self.assertIn("-accel tcg", runner)
        self.assertIn("initramfs/reach01_init.c", runner)
        self.assertIn("MOTOROLA_REACHABILITY=NOT_PERFORMED", runner)
        self.assertIn("ROOT_ESCALATION=NOT_PERFORMED", runner)
        self.assertIn("REACH02_TASKS_DIFFER=1", runner)
        self.assertIn("REACH02_CONTROL=PASS", runner)
        self.assertIn("REACH02_VARIANT", runner)

    def test_matrix_has_independent_guest_jobs(self):
        yaml = (ROOT / ".github/workflows/arm64-reach02.yml").read_text()
        self.assertIn("branches: [reach02-20261020]", yaml)
        self.assertIn("matrix:", yaml)
        self.assertIn("variant: [unpatched, corrected]", yaml)
        self.assertIn("REACH02_VARIANT:", yaml)
        self.assertIn("fail-fast: false", yaml)
        self.assertIn("permissions:", yaml)
        self.assertIn("contents: read", yaml)
        self.assertIn("persist-credentials: false", yaml)
        self.assertNotIn("secrets.", yaml)
        self.assertNotIn("pull_request_target:", yaml)

    def test_existing_baseline_unmodified(self):
        source = (ROOT / "scripts/run-lab.sh").read_text()
        self.assertIn("GHOSTLOCK_TRIGGER=NOT_PERFORMED", source)
        self.assertIn("KASAN_SELFTEST_DONE", source)


if __name__ == "__main__":
    unittest.main()
