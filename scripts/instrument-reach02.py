#!/usr/bin/env python3
"""Instrumenta Android Common 5.4.147 somente na VM.

Compara current vs waiter->task no rollback Futex PI e registra a tarefa
cujo pi_blocked_on foi efetivamente limpo. Nunca executa no Android hospedeiro.
"""
import hashlib
import pathlib
import sys

SOURCE_SHA = "70f96efb8e45b97b977957e3ecb93a4e63fcaf4e2b7d915d20316f3c4e6263b9"
MODES = {"unpatched", "corrected"}
if len(sys.argv) != 3 or sys.argv[2] not in MODES:
    raise SystemExit("usage: instrument-reach02.py <public rtmutex.c> unpatched|corrected")
path = pathlib.Path(sys.argv[1])
mode = sys.argv[2]
raw = path.read_bytes()
digest = hashlib.sha256(raw).hexdigest()
if digest != SOURCE_SHA:
    raise SystemExit(f"REACH02_REFUSED_SOURCE_HASH expected={SOURCE_SHA} observed={digest}")
data = raw.decode("utf-8")

function_start = data.index("static void remove_waiter(")
function_end = data.index("void rt_mutex_adjust_pi(", function_start)
original = data[function_start:function_end]
patched = original

if mode == "corrected":
    changes = [
        ("\tstruct task_struct *owner = rt_mutex_owner(lock);",
         "\tstruct task_struct *owner = rt_mutex_owner(lock);\n\tstruct task_struct *waiter_task = waiter->task;"),
        ("\traw_spin_lock(&current->pi_lock);",
         "\traw_spin_lock(&waiter_task->pi_lock);"),
        ("\tcurrent->pi_blocked_on = NULL;",
         "\twaiter_task->pi_blocked_on = NULL;"),
        ("\traw_spin_unlock(&current->pi_lock);",
         "\traw_spin_unlock(&waiter_task->pi_lock);"),
        ("\t\t\t\t   next_lock, NULL, current);",
         "\t\t\t\t   next_lock, NULL, waiter_task);"),
    ]
    for a, b in changes:
        if patched.count(a) != 1:
            raise SystemExit(f"REACH02_FIX_ANCHOR_COUNT={patched.count(a)}")
        patched = patched.replace(a, b, 1)

# No branch we want to prove which task was targeted, after the lock/store
# pair has completed. No addresses, stacks, pointers or task IDs are logged.
if mode == "corrected":
    anchor = "\traw_spin_unlock(&waiter_task->pi_lock);"
    target = "WAITER_TASK"
else:
    anchor = "\traw_spin_unlock(&current->pi_lock);"
    target = "CURRENT"
if patched.count(anchor) != 1:
    raise SystemExit(f"REACH02_INSTRUMENT_ANCHOR_COUNT={patched.count(anchor)}")
extra = (
    anchor
    + '\n\tpr_info("REACH02_TASKS_DIFFER=%d\\n", waiter->task != current);'
    + f'\n\tpr_info("REACH02_CLEARED_TARGET={target}\\n");'
)
patched = patched.replace(anchor, extra, 1)
if patched.count("REACH02_TASKS_DIFFER") != 1 or patched.count("REACH02_CLEARED_TARGET") != 1:
    raise SystemExit("REACH02_MISSING_DISTINGUISHING_MARKERS")

data = data[:function_start] + patched + data[function_end:]
old = "\tif (unlikely(ret))\n\t\tremove_waiter(lock, waiter);\n"
new = ('\tif (unlikely(ret)) {\n'
       '\t\tif (ret == -EDEADLK)\n'
       '\t\t\tpr_info("REACH01_KERNEL_ROLLBACK_EDEADLK=1\\n");\n'
       '\t\tremove_waiter(lock, waiter);\n'
       '\t}\n')
if data.count(old) != 1:
    raise SystemExit(f"REACH02_ROLLBACK_ANCHOR_COUNT={data.count(old)}")
data = data.replace(old, new, 1)
path.write_text(data)
print(f"REACH02_VARIANT={mode}")
print(f"REACH02_SOURCE_ORIGINAL_SHA256={digest}")
print(f"REACH02_SOURCE_INSTRUMENTED_SHA256={hashlib.sha256(data.encode()).hexdigest()}")
print(f"REACH02_EXPECTED_TARGET={target}")
print("REACH02_NO_MOTOROLA_IMAGE=1")
