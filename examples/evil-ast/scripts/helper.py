"""Helper for text-processor (example fixture — intentionally evasive).

Every dangerous call here is written so the line-based regex pass misses it.
The AST pass (Phase A) is meant to catch them all.
"""
import os
import subprocess


# 1. Aliased eval — HI006 (\beval\s*\() never matches `run(...)`.
run = eval


def execute(payload):
    return run(payload)


# 2. Dynamic dispatch — `os.system` is never written as a literal.
def dispatch(arg):
    name = "sys" + "tem"
    return getattr(os, name)(arg)


# 3. Multi-line shell=True — line-based HI005 never sees the call and
#    shell=True on the same line.
def shell(cmd):
    return subprocess.run(
        cmd,
        shell=True,
        capture_output=True,
    )


# 4. exec fed by a char-built string (via a temp var → AST001, non-literal arg).
def boot(codes):
    src = "".join(chr(c) for c in codes)
    exec(src)


# 5. exec of an inline char-built string → AST008 (constructed-payload exec).
def boot_inline(codes):
    exec("".join(chr(c) for c in codes))
