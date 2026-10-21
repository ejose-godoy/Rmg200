#!/usr/bin/env python3
"""REACH-15: source-pinned instrumentation for normal Binder ref lifecycle QEMU only."""
from pathlib import Path
import sys,subprocess,hashlib
p=Path(sys.argv[1]);variant=sys.argv[2]
assert variant in ("unpatched","corrected")
blob=subprocess.check_output(["git","hash-object",str(p)],text=True).strip()
assert blob=="24055ff221e7ccd5be536ac7a82998a5aa1f154f",blob
s=p.read_text()
vuln='''\t*rdata = ref->data;
\tbinder_proc_unlock(proc);
\tif (new_ref && ref != new_ref)'''
fixed='''\t*rdata = ref->data;
\tif (ret && ref == new_ref) {
\t\tbinder_cleanup_ref_olocked(new_ref);
\t\tref = NULL;
\t}
\tbinder_proc_unlock(proc);
\tif (new_ref && ref != new_ref)'''
assert s.count(vuln)==1
if variant=="corrected":s=s.replace(vuln,fixed)
inc='''\tret = binder_inc_ref_olocked(ref, strong, target_list);
\t*rdata = ref->data;
'''
assert s.count(inc)==1
s=s.replace(inc,inc+'''\tif (!ret && new_ref && ref == new_ref)
\t\tpr_info("REACH15_REF_CREATED_NORMAL=1\\n");
''',1)
cleanup='''static void binder_cleanup_ref_olocked(struct binder_ref *ref)
{
\tbool delete_node = false;
'''
assert s.count(cleanup)==1
s=s.replace(cleanup,cleanup+'''\tpr_info("REACH15_REF_CLEANUP_NORMAL=1\\n");
''',1)
assert s.count('REACH15_REF_CREATED_NORMAL=1')==1
assert s.count('REACH15_REF_CLEANUP_NORMAL=1')==1
p.write_text(s)
print("REACH15_VARIANT="+variant)
print("REACH15_BADSPIN_FIX_PRESENT="+str(variant=="corrected").upper())
print("REACH15_SOURCE_SHA256="+hashlib.sha256(p.read_bytes()).hexdigest())
