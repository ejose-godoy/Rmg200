#!/usr/bin/env python3
"""Instrumentacao SOMENTE do kernel Android Common em QEMU, nunca do Motorola.
Falha fechada: valida SHA-256 da fonte pública fixada antes de qualquer mudança.
"""
import hashlib
import pathlib
import sys

if len(sys.argv) != 2:
    raise SystemExit("usage: instrument-reach01.py <rtmutex.c PUBLICO>")
p = pathlib.Path(sys.argv[1])
data = p.read_bytes()
expected = "70f96efb8e45b97b977957e3ecb93a4e63fcaf4e2b7d915d20316f3c4e6263b9"
actual = hashlib.sha256(data).hexdigest()
if actual != expected:
    raise SystemExit(f"REACH01_REFUSED_SOURCE_SHA_MISMATCH expected={expected} observed={actual}")

old = b"\tif (unlikely(ret))\n\t\tremove_waiter(lock, waiter);\n"
new = (b"\tif (unlikely(ret)) {\n"
       b"\t\tif (ret == -EDEADLK)\n"
       b"\t\t\tpr_info(\"REACH01_KERNEL_ROLLBACK_EDEADLK=1\\n\");\n"
       b"\t\tremove_waiter(lock, waiter);\n"
       b"\t}\n")
if data.count(old) != 1:
    raise SystemExit(f"REACH01_REFUSED_ANCHOR_COUNT={data.count(old)}")
newdata = data.replace(old, new, 1)
if newdata.count(b"REACH01_KERNEL_ROLLBACK_EDEADLK") != 1:
    raise SystemExit("REACH01_INVALID_PATCH")
p.write_bytes(newdata)
print(f"REACH01_SOURCE_ORIGINAL_SHA256={actual}", flush=True)
print(f"REACH01_SOURCE_INSTRUMENTED_SHA256={hashlib.sha256(newdata).hexdigest()}", flush=True)
print("REACH01_SOURCE_EDIT_SCOPE=QEMU_PUBLIC_ANDROID_COMMON_ONLY", flush=True)
