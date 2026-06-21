#!/usr/bin/env python3
"""Safe archive helper (example: the safe form of the Phase J AST patterns)."""

import subprocess
import tarfile

import pandas as pd


def parse_ids(df, series):
    # pandas Series.str.extractall — a common, documented benign API that shares the
    # `extractall` method name with the archive sink. AST011 is gated on receiver
    # PROVENANCE (the receiver must be a tarfile/zipfile archive), so a `.str` accessor
    # receiver does NOT fire (convergence sweep gap 5 FP guard).
    a = df["raw"].str.extractall(r"(?P<id>\d+)")
    b = series.str.extractall(r"([A-Z]{2})-(\d+)")
    return a, b


def parse_generic(obj):
    # a bare `obj.extractall()` on a non-archive object (here an opaque parameter) is also
    # not a provable archive -> no AST011 (gap-5 provenance guard).
    return obj.extractall()


archive = tarfile.open("base.tar")   # a module-level archive object


def consume(archive):
    # `archive` here is a PARAMETER that SHADOWS the module-level archive object above, so its
    # `.extractall()` is NOT a provable archive receiver -> no AST011: the innermost scope that
    # binds the name decides (round-4 audit param-shadow FP guard).
    return archive.extractall()


class SafeArchive:
    def extractall(self, *a):
        pass


def reopen_safe(path):
    # `a = tarfile.open(p)` then REBIND `a` to a non-archive BEFORE the extractall -> the
    # receiver is no longer a provable archive AS OF the call -> no AST011. A monotonic set
    # wrongly kept `a` an archive (round-4 audit FP); the position-aware timeline fixes it.
    a = tarfile.open(path)
    a = SafeArchive()
    a.extractall()


def methodref_safe(path, safe):
    # a method-ref `ex` bound to a SAFE callable is CALLED, then later rebound to t.extractall
    # — the call must resolve `ex` AS OF its position (safe), not the final-state (round-4 audit
    # pass 4 method-ref FP guard) -> no AST011.
    t = tarfile.open(path)
    ex = safe
    ex()
    ex = t.extractall


_outer_ref = tarfile.open("base.tar").extractall   # an outer method-ref to an archive


def call_ref(ex):
    # `ex` is a PARAMETER that shadows the outer archive method-ref above — a caller-supplied
    # callback, not the archive's extractall. The method-ref resolver must mask a param (the
    # innermost binding scope decides) -> no AST011 (round-4 audit pass 5 FP guard).
    return ex()


def list_contents(path):
    # argument list, no shell=True, with a timeout -> no AST finding
    return subprocess.run(["tar", "-tf", path], capture_output=True, timeout=10)


def extract(path, dest):
    # extractall WITH a member filter -> Zip-Slip-safe, AST011 exempt
    tarfile.open(path).extractall(dest, filter="data")


def extract_curated(path, dest):
    # members as an explicit list LITERAL of curated entries -> a visible guard, AST011
    # exempt (the round-2 boundary: a literal list is provable curation, a variable/
    # getmembers() is not)
    t = tarfile.open(path)
    safe = t.getmember("README")
    t.extractall(dest, members=[safe])


def extract_pep706(path, dest):
    # the PEP 706 CALLABLE safe filter (the stdlib-recommended form) -> AST011 exempt
    # (Codex round 3 FP: only the literal-string "data"/"tar" was accepted before)
    tarfile.open(path).extractall(dest, filter=tarfile.data_filter)


def _plain():
    return object()


def archive_for_reset(p, names):
    # `t` opens an archive, then `for t in names` REBINDS t to plain (non-archive) list
    # elements; the later t.extractall is NOT on a provable archive -> no AST011. The archive
    # timeline must apply the #3 for-reset to an UNCONDITIONAL top-level for (it had hardcoded
    # cond=True, so a top-level for never masked) (round-6 sweep FP-1 guard).
    with tarfile.open(p) as t:
        pass
    for t in names:
        print(t)
    t.extractall("/dest")


def archive_annassign_reset(p):
    # `t: object = _plain()` re-annotates and rebinds t to a non-archive value -> no AST011 (the
    # archive timeline gained the AnnAssign branch it was missing) (round-6 sweep FP-2 guard).
    t = tarfile.open(p)
    t.close()
    t: object = _plain()
    t.extractall("/dest")


def archive_augassign_reset(p, extra):
    # `t += extra` rebinds t so it is no longer a provable archive -> no AST011 (round-6 FP-3).
    t = tarfile.open(p)
    t += extra
    t.extractall("/dest")


def open_generated_report():
    # os.startfile opens a document with its associated default app (the Windows double-click
    # equivalent / xdg-open analog) — a benign desktop idiom, NOT process-image replacement, so
    # it must NOT fire AST010 (round-6 CONFIRM sweep R6-FP-startfile: os.startfile is deliberately
    # excluded from the os.exec*/os.spawn* family it was wrongly added to).
    import os
    os.startfile("report.pdf")


def archive_def_reset(p):
    # `t` opens an archive, then a `def t` REBINDS the name to a local function; the later
    # t.extractall() is on the function, not the archive -> no AST011. A def/class binds its name
    # in the enclosing scope, so it must reset the archive provenance (round-7 audit FP guard).
    t = tarfile.open(p)
    def t():
        return "ok"
    t.extractall("/dest")


def archive_except_capture_masked(p):
    # `t` opens an archive, but `except E as t` REBINDS t to the caught exception INSIDE the
    # handler — t.extractall() there is on the exception object, NOT the archive, so the block-
    # scoped capture masking suppresses AST011 (round-8 audit F1 archive FP guard).
    t = tarfile.open(p)
    try:
        validate(p)
    except Exception as t:
        t.extractall("/dest")


def archive_transitive_capture(p):
    # `archive` opens a tarfile, but `except E as archive` captures it as the exception; the
    # TRANSITIVE `b = archive` inside the handler must NOT inherit the archive provenance (the
    # capture overlay is consulted during propagation, not just at the final use) -> no AST011
    # (round-8 re-sweep H6 FP guard).
    archive = tarfile.open(p)
    try:
        validate(p)
    except Exception as archive:
        b = archive
        b.extractall("/dest")
