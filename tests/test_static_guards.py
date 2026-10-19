"""Verificacoes locais sem acesso a GitHub, Motorola ou kernel em execucao."""
import pathlib
import re
import subprocess
import unittest
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]


class LabStaticGuards(unittest.TestCase):
    def test_shell_scripts_parse(self):
        for script in ("scripts/preflight.sh", "scripts/run-lab.sh"):
            subprocess.run(["bash", "-n", str(ROOT / script)], check=True)

    def test_preflight_clean(self):
        subprocess.run(["bash", str(ROOT / "scripts/preflight.sh")], check=True)

    def test_workflow_is_manual_and_nonprivileged(self):
        txt = (ROOT / ".github/workflows/arm64-kasan-lab.yml").read_text()
        self.assertIn("workflow_dispatch:", txt)
        self.assertIn("push:", txt)
        self.assertIn("branches: [main]", txt)
        self.assertIn("runs-on: ubuntu-24.04-arm", txt)
        self.assertIn("contents: read", txt)
        self.assertNotIn("pull_request_target:", txt)
        self.assertNotIn("secrets.", txt)
        self.assertIn("persist-credentials: false", txt)

    def test_source_is_pinned_and_moto_image_is_absent(self):
        text = (ROOT / "scripts/run-lab.sh").read_text()
        self.assertIn("SOURCE_TAG=\"android12-5.4.147_r00\"", text)
        self.assertIn("SOURCE_COMMIT=\"34b5f809f17e66d5011086a3d90802989e667f75\"", text)
        banned_extensions = {".img", ".elf", ".dtb", ".bin", ".pem", ".key"}
        for f in ROOT.rglob("*"):
            if f.is_file():
                self.assertNotIn(f.suffix.lower(), banned_extensions, str(f))
                self.assertNotIn("boot_a", f.name.lower())

    def test_arm64_qemu_is_emulated(self):
        txt = (ROOT / "scripts/run-lab.sh").read_text()
        self.assertIn("-accel tcg", txt)
        self.assertIn("-M virt", txt)
        self.assertIn("-e KASAN_GENERIC", txt)
        self.assertIn("-e KASAN_OUTLINE", txt)
        self.assertIn("KASAN_LAB_INIT_OK", txt)
        self.assertIn("GHOSTLOCK_TRIGGER=NOT_PERFORMED", txt)
        self.assertIn("CONFIG_TEST_KASAN=m", txt)
        self.assertIn("lib/test_kasan.ko", txt)
        self.assertIn("KASAN_SELFTEST_DONE", txt)


if __name__ == "__main__":
    unittest.main(verbosity=2)
