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


def unpack_classmethod(path):
    # tarfile.TarFile.open is the alternative-constructor classmethod tarfile.open delegates
    # to — its result is a real archive, so the provenance gate must accept it -> AST011 (r4)
    tarfile.TarFile.open(path).extractall()


def unpack_modulealias(path):
    # `z = zipfile` — a MODULE bound by plain assignment; _canon must resolve the head so
    # z.ZipFile is a provable archive opener -> AST011 (round 4 re-verify head-resolution)
    import zipfile
    z = zipfile
    z.ZipFile(path).extractall("/srv/victim3")


def unpack_rebind(path):
    # extractall, THEN rebind the archive name to None — a rebind AFTER the use must not
    # clear the provenance -> AST011 (round-4 audit FN)
    archive = tarfile.open(path)
    archive.extractall("/srv/victim4")
    archive = None


def unpack_ternary(path, cond):
    # an IfExp/ternary arm yields a live archive on the cond-true path -> AST011 (audit pass 3)
    a = tarfile.open(path) if cond else None
    a.extractall("/srv/victim5")


def unpack_tryexcept(path):
    # a try-open with a None fallback in the EXCEPT handler — a sibling-branch rebind must NOT
    # mask the try-body archive (the success path keeps it live) -> AST011 (audit pass 3 #4)
    try:
        a = tarfile.open(path)
    except OSError:
        a = None
    a.extractall("/srv/victim6")


def unpack_listed(path):
    # an archive opened inside a list literal, extracted via a for-target over it -> AST011
    archives = [tarfile.open(path)]
    for a in archives:
        a.extractall("/srv/victim7")


def unpack_methodref_rebind(path, safe):
    # a method-ref `ex = t.extractall` is CALLED, then ex is rebound to a safe callable — the
    # position-aware method-ref timeline catches the call (a final-state map missed it) -> AST011
    t = tarfile.open(path)
    ex = t.extractall
    ex("/srv/victim8")
    ex = safe


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


# --- round-6 sweep: the archive timeline reaches form-coverage parity with the others ---

def unpack_annassign(path):
    # ANNOTATED archive binding `arch: object = tarfile.open(p)` — the archive provenance
    # timeline now records AnnAssign (it was the one value-timeline the #3 reset fix missed),
    # so the receiver is a provable archive -> AST011 (round-6 sweep R6-1 FN).
    arch: object = tarfile.open(path)
    arch.extractall("/srv/victim9")


def unpack_seq_methodref(path):
    # a for-target over a LITERAL list holding a method-REF (not an opener call) — seq_ref
    # resolves ex to the archive's extractall (mirrors seqarch) -> AST011 (round-6 sweep R6-3).
    t = tarfile.open(path)
    for ex in [t.extractall]:
        ex("/srv/victim10")


def unpack_getattr_opener(path):
    # the archive OPENER reached via an INLINE getattr(tarfile,"open") — _func_canon resolves
    # the inline-getattr opener so the receiver is a provable archive -> AST011 (round-6 sweep).
    getattr(tarfile, "open")(path).extractall("/srv/victim11")


def unpack_annassign_noval(path):
    # a BARE `t: object` (annotation, NO value) does NOT unbind t at runtime -> the archive
    # provenance is preserved -> AST011 (round-6 CONFIRM sweep C23: a reset on a bare annotation
    # was an FN regression — the no-value AnnAssign must be a no-op, lock-step with __file__).
    t = tarfile.open(path)
    t: object
    t.extractall("/srv/victim12")


def unpack_methodref_annassign_noval(path):
    # bare `ex: object` preserves the method-ref binding -> AST011 (round-6 CONFIRM sweep C24).
    t = tarfile.open(path)
    ex = t.extractall
    ex: object
    ex("/srv/victim13")


def unpack_assigned_builtins_getattr(path):
    # the archive OPENER reached via an ASSIGNED builtins.getattr — `opener = builtins.getattr(
    # tarfile,"open")` then `arch = opener(path)`. The alias-timeline getattr branch now resolves
    # builtins.getattr, so opener canonicalizes to tarfile.open and arch is a provable archive
    # (round-8 audit F2, archive twin via the shared canon machinery) -> AST011.
    import builtins
    opener = builtins.getattr(tarfile, "open")
    arch = opener(path)
    arch.extractall("/srv/victim14")


def unpack_methodref_builtins_getattr(path):
    # the extractall METHOD-REF reached via builtins.getattr — `ex = builtins.getattr(t,
    # "extractall")` on a provable archive receiver (round-8 audit F2: the method-ref timeline's
    # getattr branch is now shadow-safe / builtins-aware) -> AST011.
    import builtins
    t = tarfile.open(path)
    ex = builtins.getattr(t, "extractall")
    ex("/srv/victim15")


def unpack_except_after(path):
    # archive provenance survives an except handler that reuses the name — `arch` is masked only
    # INSIDE the handler body (capture overlay), so the post-block extractall on the fall-through
    # path still resolves to the archive (round-8 audit F1 archive no-FN witness) -> AST011.
    a = tarfile.open(path)
    arch = a
    try:
        pass
    except Exception as arch:
        pass
    arch.extractall("/srv/victim16")


def unpack_methodref_walrus_getattr(path):
    # extractall METHOD-REF via a WALRUS-bound getattr — `ex = (g := getattr)(t, "extractall")`;
    # the getattr head is walrus-unwrapped in ref_info via _func_canon (round-8 re-sweep) -> AST011.
    ex = (g := getattr)(tarfile.open(path), "extractall")
    ex("/srv/victim17")


def unpack_capture_rebind_transitive(path):
    # `except E as ar` captures ar, but the handler REBINDS ar to a fresh archive — a SUPERSEDING
    # rebind — so a TRANSITIVE `bb = ar` inherits the archive provenance and bb.extractall() fires.
    # The transitive-capture check yields to a real rebind (round-8 re-sweep H7) -> AST011.
    try:
        validate(path)
    except Exception as ar:
        ar = tarfile.open(path)
        bb = ar
        bb.extractall("/srv/victim18")


def unpack_nested_walrus(path):
    # NESTED walrus receiver — `(a := (b := tarfile.open(path))).extractall(...)`. The provenance gate
    # now unwraps NamedExpr recursively (round-10: it unwrapped once) -> AST011.
    (a := (b := tarfile.open(path))).extractall("/srv/victim19")


def unpack_triple_walrus(path):
    # depth-3 walrus chain — still a provable archive after recursive unwrap (round-10) -> AST011.
    (a := (b := (c := tarfile.open(path)))).extractall("/srv/victim20")


def unpack_nested_walrus_methodref(path):
    # method-ref bound through a nested walrus, then called — `(a := (b := t.extractall))(...)` on a
    # provable archive receiver (round-10 recursive-unwrap in _extractall_on_archive) -> AST011.
    t = tarfile.open(path)
    (a := (b := t.extractall))("/srv/victim21")


def unpack_inline_list_subscript(path):
    # INLINE literal-list subscript `[tarfile.open(path)][0].extractall(...)` — a seq-of-archives
    # literal indexed directly (round-10: the Subscript arm handled only a Name receiver) -> AST011.
    [tarfile.open(path)][0].extractall("/srv/victim22")


def unpack_scalar_then_seq(path):
    # a name first a SCALAR archive, then UNCONDITIONALLY rebound to a sequence-of-archives, indexed
    # extractall — the seq rebind now supersedes the scalar (round-10 archive-precedence) -> AST011.
    z = tarfile.open(path)
    z = [tarfile.open(path)]
    z[0].extractall("/srv/victim23")


# --- set-model (Codex reject): the archive-method-ref AST011 gate is now MEMBERS-aware, so a provable
#     archive .extractall selected through a UNION callee fires too — the old _func_attr returned None
#     for an IfExp / Subscript callee, so these read GREEN (workflow re-sweep false-negatives). ---

def unpack_methodref_ifexp(path):
    # the archive .extractall is hidden in an IfExp arm — `(tarfile.open(p).extractall if c else f)(d)`;
    # a callee union member is a provable-archive method-ref -> AST011 (/srv/victim24).
    import math
    (tarfile.open(path).extractall if path else math.sin)("/srv/victim24")


def unpack_methodref_subscript(path):
    # the archive .extractall is selected by a literal-seq subscript — `[t.extractall][0](d)`;
    # the members-aware gate sees the archive method-ref at index 0 -> AST011 (/srv/victim25).
    [tarfile.open(path).extractall][0]("/srv/victim25")


# --- closure under expression constructors (Codex reject 2 + workflow re-sweep): the archive provenance
#     must survive an IfExp-with-__file__-arm / a for-target union / a comprehension subscript. ---

def unpack_archive_ifexp_file_arm(path):
    # `(tarfile.open(p) if c else __file__).extractall(d)` — the __file__ arm must NOT short-circuit the
    # IfExp to self-file and DROP the archive member (workflow re-sweep FN2) -> AST011 (/srv/victim26).
    (tarfile.open(path) if path else __file__).extractall("/srv/victim26")


def unpack_archive_for_union(path):
    # a for-target over a union of differing-length iterables, one holding an archive method-ref — the
    # loop var unions every element so the archive is reachable (workflow re-sweep FN3) -> AST011.
    import math
    for ex in ((tarfile.open(path).extractall,) if path else (math.sin, math.cos)):
        ex("/srv/victim27")


def unpack_archive_comprehension(path, items):
    # a comprehension of archive method-refs indexed at a constant >= its representative length — the
    # length is unknown, so the archive representative is selected (workflow re-sweep FN1) -> AST011.
    [tarfile.open(path).extractall for _ in items][2]("/srv/victim28")
