#!/usr/bin/env python3
"""Build helper (example: AST010 process-replacement + AST011 Zip-Slip)."""

import os
import shutil as sh                       # module alias — resolver must canonicalize
import tarfile
from shutil import unpack_archive          # from-import — resolver must canonicalize


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


def unpack_members_indirect(path):
    # one level of indirection (members bound to a var) defeats a syntactic value check —
    # only a list/tuple LITERAL is a provable guard, a variable is not (Codex round 2) -> AST011
    t = tarfile.open(path)
    members = t.getmembers()
    t.extractall(members=members)


def respawn(prog):
    # os.spawnv(mode, FILE, args): the program path is arg1, not arg0 (the mode).
    # non-literal program -> AST010 CRITICAL (locks the spawn program-index fix).
    os.spawnv(os.P_NOWAIT, prog, ["x"])


# --- Codex round 3: indirection siblings the dotted-name match used to miss ---

def unpack_fromimport(path):
    # `from shutil import unpack_archive` -> bare name; the import resolver canonicalizes
    # it to shutil.unpack_archive -> AST011
    unpack_archive(path, "/home/victim")


def unpack_modalias(path):
    # `import shutil as sh` -> sh.unpack_archive; resolver canonicalizes -> AST011
    sh.unpack_archive(path, "/home/victim")


def unpack_getattr(path):
    # extractall reached via getattr(obj, "literal") method-reference -> AST011
    t = tarfile.open(path)
    fn = getattr(t, "extractall")
    fn("/home/victim/.claude")


def unpack_refbind(path):
    # extractall reached via a method-reference binding (ex = t.extractall) -> AST011
    t = tarfile.open(path)
    ex = t.extractall
    ex("/home/victim/.ssh")


def unpack_transitive(path):
    # transitive re-alias of the method reference (b = a) -> AST011 (Codex r3 re-sweep)
    t = tarfile.open(path)
    a = t.extractall
    b = a
    b("/home/victim/.claude")


def unpack_unpack(path):
    # tuple-unpack of the method reference (a, _ = t.extractall, None) -> AST011
    t = tarfile.open(path)
    a, _ = t.extractall, None
    a("/home/victim/.ssh")


def unpack_walrus(path):
    # walrus-bound method reference ((a := t.extractall)(dest)) -> AST011
    t = tarfile.open(path)
    (a := t.extractall)("/home/victim/.config")
