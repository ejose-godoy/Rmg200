"""QEMU-only benign Binder reference lifecycle; never trigger BadSpin UAF."""
from pathlib import Path
import subprocess
import unittest
ROOT=Path(__file__).resolve().parents[1]

class Reach15(unittest.TestCase):
 def test_guest_compiles(self):
  subprocess.run(["gcc","-fsyntax-only","-Wall","-Wextra","-Werror",str(ROOT/"initramfs/reach15_init.c")],check=True)
 def test_runner_shell(self):
  subprocess.run(["bash","-n",str(ROOT/"scripts/run-reach15.sh")],check=True)
 def test_patcher_syntax(self):
  subprocess.run(["python3","-m","py_compile",str(ROOT/"scripts/reach15_binder_instrument.py")],check=True)
 def test_normal_four_command_cycle_only(self):
  g=(ROOT/"initramfs/reach15_init.c").read_text()
  assert all(x in g for x in ["BC_INCREFS","BC_ACQUIRE","BC_RELEASE","BC_DECREFS",
                              "BINDER_SET_CONTEXT_MGR","BINDER_WRITE_READ",
                              "REACH15_NO_RACE=1","REACH15_NO_EXPLOIT=1",
                              "REACH15_CLIENT_UID=10000"])
  assert all(x not in g for x in ["BC_TRANSACTION","BC_REPLY","fork_bomb","mprotect","setresuid(0,"])
 def test_ordered_client_manager_lifetime(self):
  g=(ROOT/"initramfs/reach15_init.c").read_text()
  assert "if(read(quit_fd,&done,1)!=1 || done!='Q')" in g
  assert 'send_command(fd,BC_INCREFS,"INCREFS")' in g
  assert 'send_command(fd,BC_ACQUIRE,"ACQUIRE")' in g
  assert 'send_command(fd,BC_RELEASE,"RELEASE")' in g
  assert 'send_command(fd,BC_DECREFS,"DECREFS")' in g
  assert g.index('send_command(fd,BC_INCREFS,')<g.index('send_command(fd,BC_ACQUIRE,')<g.index('send_command(fd,BC_RELEASE,')<g.index('send_command(fd,BC_DECREFS,')
  assert g.index('waitpid(ch,&cs,0)')<g.index('write(quit[1],"Q",1)')<g.index('waitpid(mgr,&ms,0)')
 def test_instrument_normal_ref_creation_cleanup(self):
  s=(ROOT/"scripts/reach15_binder_instrument.py").read_text()
  assert "24055ff221e7ccd5be536ac7a82998a5aa1f154f" in s
  assert 'if (!ret && new_ref && ref == new_ref)' in s
  assert 'REACH15_REF_CREATED_NORMAL=1' in s
  assert 'REACH15_REF_CLEANUP_NORMAL=1' in s
  assert 'binder_cleanup_ref_olocked(new_ref)' in s
 def test_matrix_safe_env_and_expected_markers(self):
  s=(ROOT/"scripts/run-reach15.sh").read_text()
  w=(ROOT/".github/workflows/arm64-reach15.yml").read_text()
  for marker in ["REACH15_VARIANT","REACH15_QEMU_ONLY=1",
                 "REACH15_REF_CREATED_NORMAL=1","REACH15_REF_CLEANUP_NORMAL=1",
                 "REACH15_NO_RACE=1","REACH15_NO_EXPLOIT=1",
                 "REACH15_ROOT=NOT_OBTAINED","REACH15_PHYSICAL_MOTOROLA=NOT_TOUCHED"]:
   assert marker in s
  assert "loglevel=7" in s
  assert "CONFIG_KASAN=y" in s
  assert "qemu-system-aarch64" in s
  assert "reach15-20261021" in w
  assert "variant: [unpatched, corrected]" in w
  assert "persist-credentials: false" in w
  assert "contents: read" in w
  assert "secrets." not in w

if __name__=="__main__":
 unittest.main()
