#!/usr/bin/env python3
"""Abstract RT-mutex waiter/task invariant model; not a kernel exploit."""
from dataclasses import dataclass

@dataclass
class Task:
    name: str
    pi_blocked_on: object = None

@dataclass
class Waiter:
    task: Task

def check():
    a, b = Task("A"), Task("B")
    waiter = Waiter(a)
    a.pi_blocked_on = waiter
    assert waiter.task is a

    # Legacy abstract model clears actor B, leaving A's pointer unchanged.
    b.pi_blocked_on = None
    assert a.pi_blocked_on is waiter

    # Corrected abstract model clears the task associated with the waiter.
    waiter.task.pi_blocked_on = None
    assert a.pi_blocked_on is None
    print("PASS: abstract identity invariants")
    print("MODEL ONLY: no QEMU, KASAN, futex, or kernel execution")

if __name__ == "__main__":
    check()
