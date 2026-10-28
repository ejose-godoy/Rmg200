#!/usr/bin/env python3
"""Apply published minimal Binder ref failure cleanup ONLY to GitHub Actions QEMU source."""
from pathlib import Path
import sys,hashlib
p=Path(sys.argv[1]); variant=sys.argv[2]
assert variant in ("unpatched","corrected")
data=p.read_bytes()
expected="24055ff221e7ccd5be536ac7a82998a5aa1f154f" # Git blob SHA-1, checked with git hash-object
import subprocess
real=subprocess.check_output(["git","hash-object",str(p)],text=True).strip()
assert real==expected,(real,expected)
src=data.decode()
old="""\t*rdata = ref->data;
\tbinder_proc_unlock(proc);
\tif (new_ref && ref != new_ref)"""
new="""\t*rdata = ref->data;
\tif (ret && ref == new_ref) {
\t\tbinder_cleanup_ref_olocked(new_ref);
\t\tref = NULL;
\t}
\tbinder_proc_unlock(proc);
\tif (new_ref && ref != new_ref)"""
assert src.count(old)==1
if variant=="corrected":
  src=src.replace(old,new)
  p.write_text(src)
  assert new in p.read_text()
else:assert old in src
print("REACH14_VARIANT="+variant)
print("REACH14_BUGFIX_PRESENT="+str(variant=="corrected").upper())
print("REACH14_SOURCE_SHA256="+hashlib.sha256(p.read_bytes()).hexdigest())
