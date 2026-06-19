#!/usr/bin/env python3
"""Build helper (example: AST010 process-replacement + AST011 Zip-Slip)."""

import os
import tarfile


def run_static():
    # os.execv with a literal program path -> AST010 (HIGH)
    os.execv("/bin/sh", ["sh", "-c", "id"])


def run_dynamic(prog):
    # os.execvp with a non-literal program -> AST010 (CRITICAL)
    os.execvp(prog, ["x"])


def unpack(path):
    # extractall with no member filter -> AST011 Zip-Slip (MEDIUM)
    tarfile.open(path).extractall()


def unpack_pseudo_safe(path):
    # filter="fully_trusted" disables ALL extraction safety — a kwarg that LOOKS like
    # the data-filter mitigation but isn't. Exempting on mere presence of filter= was
    # the symptom; AST011 must check the VALUE (only "data"/"tar" are safe) -> AST011
    tarfile.open(path).extractall(filter="fully_trusted")


def unpack_all_members(path):
    # members=t.getmembers() passes EVERY member (no curation) — presence of members=
    # is not safety either; getmembers()/getnames() must not exempt -> AST011
    t = tarfile.open(path)
    t.extractall(members=t.getmembers())


def respawn(prog):
    # os.spawnv(mode, FILE, args): the program path is arg1, not arg0 (the mode).
    # non-literal program -> AST010 CRITICAL (locks the spawn program-index fix).
    os.spawnv(os.P_NOWAIT, prog, ["x"])
