import unittest,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
class Reach14(unittest.TestCase):
 def test_c_syntax(self):subprocess.run(["gcc","-fsyntax-only","-Wall","-Wextra","-Werror",str(ROOT/"initramfs/reach14_init.c")],check=True)
 def test_shell(self):subprocess.run(["bash","-n",str(ROOT/"scripts/run-reach14.sh")],check=True)
 def test_patcher_syntax(self):subprocess.run(["python3","-m","py_compile",str(ROOT/"scripts/reach14_binder_patch.py")],check=True)
 def test_no_device(self):
  t=(ROOT/"scripts/run-reach14.sh").read_text()
  assert "android.googlesource.com/kernel/common" in t
  assert "REACH14_PHYSICAL_MOTOROLA=NOT_TOUCHED" in t
  assert "KASAN" in t and "ANDROID_BINDER_IPC" in t
 def test_privilege_and_no_race(self):
  t=(ROOT/"initramfs/reach14_init.c").read_text()
  assert "setresuid(10000,10000,10000)" in t
  assert "REACH14_VM_CHMOD_IS_NOT_ANDROID_POLICY" in t
  assert "REACH14_NO_RACE=1" in t
  assert "BINDER_WRITE_READ" in t
  assert "struct binder_write_read bwr={0}" in t
