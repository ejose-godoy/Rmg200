#!/usr/bin/env python3
"""Instrumenta Android Common 5.4.147 somente na VM.

Inspeciona por READ_ONCE o estado residual de pi_blocked_on em waiter->task
apos remover o waiter, sem dereferenciar o ponteiro residual. Nunca executa no Android hospedeiro.
"""
import hashlib
import pathlib
import sys

SOURCE_SHA = "70f96efb8e45b97b977957e3ecb93a4e63fcaf4e2b7d915d20316f3c4e6263b9"
MODES = {"unpatched", "corrected"}
if len(sys.argv) != 4 or sys.argv[3] not in MODES:
    raise SystemExit("usage: instrument-reach10.py <public rtmutex.c> <public futex.c> unpatched|corrected")
path = pathlib.Path(sys.argv[1])
mode = sys.argv[3]
raw = path.read_bytes()
digest = hashlib.sha256(raw).hexdigest()
if digest != SOURCE_SHA:
    raise SystemExit(f"REACH05_REFUSED_SOURCE_HASH expected={SOURCE_SHA} observed={digest}")
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
            raise SystemExit(f"REACH05_FIX_ANCHOR_COUNT={patched.count(a)}")
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
    raise SystemExit(f"REACH05_INSTRUMENT_ANCHOR_COUNT={patched.count(anchor)}")
extra = (
    anchor
    + '\n\tpr_info("REACH05_TASKS_DIFFER=%d\\n", waiter->task != current);'
    + f'\n\tpr_info("REACH05_CLEARED_TARGET={target}\\n");'
    + '\n\tif (waiter->task && waiter->task != current) {'
    + '\n\t\tstruct rt_mutex_waiter *remaining;'
    + '\n\t\tremaining = READ_ONCE(waiter->task->pi_blocked_on);'
    + '\n\t\tpr_info("REACH05_WAITER_PI_BLOCKED_ON_EQ_WAITER=%d\\n",'
    + '\n\t\t\tremaining == waiter);'
    + '\n\t\tpr_info("REACH05_WAITER_PI_BLOCKED_ON_NULL=%d\\n",'
    + '\n\t\t\tremaining == NULL);'
    + '\n\t}'
)
patched = patched.replace(anchor, extra, 1)
if patched.count("REACH05_TASKS_DIFFER") != 1 or patched.count("REACH05_CLEARED_TARGET") != 1 or patched.count("REACH05_WAITER_PI_BLOCKED_ON_EQ_WAITER") != 1 or patched.count("REACH05_WAITER_PI_BLOCKED_ON_NULL") != 1:
    raise SystemExit("REACH05_MISSING_DISTINGUISHING_MARKERS")

data = data[:function_start] + patched + data[function_end:]

# Instrument *only* the existing scheduler path. Do not introduce any
# synthetic dereference of the stale waiter.
sched_start = data.index("void rt_mutex_adjust_pi(")
sched_end = data.index("void rt_mutex_init_waiter(", sched_start)
sched_src = data[sched_start:sched_end]
before = "\tnext_lock = waiter->lock;"
if sched_src.count(before) != 1:
    raise SystemExit("REACH07_SCHED_SINK_ANCHOR_COUNT_FAILURE")
after = ('\tpr_info("REACH07_ADJUST_PI_WAITING_FIELD_NON_NULL=1\\n");'
         + '\n' + before)
sched_src = sched_src.replace(before, after, 1)
# REACH-10: one explicit diagnostic query of KASAN shadow memory.
# This is NOT a natural kernel access and MUST NOT be classified as a
# spontaneous UAF or proof of exploitation.
if mode == "unpatched":
    old_anchor = '\tpr_info("REACH07_ADJUST_PI_WAITING_FIELD_NON_NULL=1\\n");'
    if sched_src.count(old_anchor) != 1:
        raise SystemExit("REACH10_REFUSED_SHADOW_CHECK_ANCHOR")
    shadow_probe = (
        old_anchor
        + '\n\tpr_info("REACH10_EXPLICIT_SHADOW_QUERY_BEGIN=1\\n");'
        + '\n\tpr_info("REACH10_KASAN_SHADOW_READABLE=%d\\n",'
        + '\n\t\t__kasan_check_read(waiter, sizeof(*waiter)));'
        + '\n\tpr_info("REACH10_EXPLICIT_SHADOW_QUERY_END=1\\n");'
    )
    sched_src = sched_src.replace(old_anchor, shadow_probe, 1)
else:
    if "REACH10_EXPLICIT_SHADOW_QUERY_BEGIN" in sched_src:
        raise SystemExit("REACH10_CORRECTED_SHOULD_HAVE_NO_PROBE")
data = data[:sched_start] + sched_src + data[sched_end:]
if mode == "unpatched":
    include_anchor = "#include <linux/spinlock.h>"
    if data.count(include_anchor) != 1:
        raise SystemExit("REACH10_HEADER_ANCHOR_COUNT")
    data = data.replace(include_anchor, include_anchor + "\n#include <linux/kasan-checks.h>", 1)
old = "\tif (unlikely(ret))\n\t\tremove_waiter(lock, waiter);\n"
new = ('\tif (unlikely(ret)) {\n'
       '\t\tif (ret == -EDEADLK)\n'
       '\t\t\tpr_info("REACH01_KERNEL_ROLLBACK_EDEADLK=1\\n");\n'
       '\t\tremove_waiter(lock, waiter);\n'
       '\t}\n')
if data.count(old) != 1:
    raise SystemExit(f"REACH05_ROLLBACK_ANCHOR_COUNT={data.count(old)}")
data = data.replace(old, new, 1)
# Require both public source hashes and all unique anchors BEFORE mutating either.
futex_path = pathlib.Path(sys.argv[2])
futex_raw = futex_path.read_bytes()
FUTEX_SOURCE_SHA = "fccba7fa429150ce1065d6a2357c2bcd50546e7659005fe9b5956bff38662a33"
futex_digest = hashlib.sha256(futex_raw).hexdigest()
if futex_digest != FUTEX_SOURCE_SHA:
    raise SystemExit(f"REACH08_REFUSED_FUTEX_SOURCE_HASH expected={FUTEX_SOURCE_SHA} observed={futex_digest}")
futex_text = futex_raw.decode("utf-8")
func_a = futex_text.index("static int futex_wait_requeue_pi(")
func_b = futex_text.index("/*\n * Support for robust futexes:", func_a)
fragment = futex_text[func_a:func_b]
init_anchor = "\trt_mutex_init_waiter(&rt_waiter);"
end_anchor = "\treturn ret;\n}\n"
if fragment.count(init_anchor) != 1 or fragment.count(end_anchor) != 1:
    raise SystemExit(f"REACH08_REFUSED_LIFETIME_ANCHORS init={fragment.count(init_anchor)} end={fragment.count(end_anchor)}")
fragment = fragment.replace(init_anchor,
  init_anchor + '\n\tpr_info("REACH08_WAITER_STACK_OBJECT_INITIALIZED=1\\n");', 1)
before_return = (
    '\tpr_info("REACH08_RETURN_FIELD_EQ_LOCAL_WAITER=%d\\n",\n'
    '\t\tREAD_ONCE(current->pi_blocked_on) == &rt_waiter);\n'
    '\tpr_info("REACH08_RETURN_FIELD_NULL=%d\\n",\n'
    '\t\tREAD_ONCE(current->pi_blocked_on) == NULL);\n'
    '\tpr_info("REACH08_WAITER_STACK_SCOPE_ABOUT_TO_END=1\\n");\n'
    + end_anchor
)
fragment = fragment.replace(end_anchor, before_return, 1)
futex_text = futex_text[:func_a] + fragment + futex_text[func_b:]
if futex_text.count("REACH08_RETURN_FIELD_EQ_LOCAL_WAITER") != 1:
    raise SystemExit("REACH08_REFUSED_NONUNIQUE_MARKER")
path.write_text(data)
futex_path.write_text(futex_text)
print(f"REACH10_FUTEX_SOURCE_ORIGINAL_SHA256={futex_digest}")
print(f"REACH10_FUTEX_SOURCE_INSTRUMENTED_SHA256={hashlib.sha256(futex_text.encode()).hexdigest()}")
print("REACH08_NO_SYNTHETIC_POINTER_DEREFERENCE=1")
print(f"REACH10_VARIANT={mode}")
print(f"REACH10_RTMUTEX_SOURCE_ORIGINAL_SHA256={digest}")
print(f"REACH10_RTMUTEX_SOURCE_INSTRUMENTED_SHA256={hashlib.sha256(data.encode()).hexdigest()}")
print(f"REACH08_EXPECTED_TARGET={target}")
print("REACH10_NO_MOTOROLA_IMAGE=1")
