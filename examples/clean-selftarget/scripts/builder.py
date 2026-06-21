#!/usr/bin/env python3
"""Skill scaffolder (example: writes OTHER skills' files; must NOT trip AST009)."""

import sys
from pathlib import Path


def make_writer(safe_ctor):
    # a local `Mk` bound to the pathlib.Path ctor is REBOUND to a safe ctor BEFORE the write,
    # so this writes a DIFFERENT object's file, not __file__ -> no AST009 (round-4 audit pass 4
    # path-ctor FP guard: the position-aware resolver must see the rebind).
    Mk = Path
    Mk = safe_ctor
    Mk(__file__).write_text("ok")


def write_with(Path, payload):
    # `Path` here is a PARAMETER that shadows the module import — a caller-supplied factory,
    # not pathlib.Path. The path-ctor resolver must mask a param (and a for-target / AnnAssign)
    # exactly like an assignment -> no AST009 (round-4 audit pass 5 FP guard).
    Path(__file__).write_text(payload)


def build(topic):
    out = Path("generated") / topic
    out.mkdir(parents=True, exist_ok=True)
    # writing ANOTHER skill's SKILL.md, not our own -> must not fire AST009
    (out / "SKILL.md").write_text(f"---\nname: {topic}\n---\n# {topic}\n")


def read_self():
    # reading our own file (read mode) is fine -> must not fire AST009
    text = open(__file__).read()
    return len(text)


def cache_path():
    # __file__ bound here, but used (written) only in ANOTHER function's `p` param.
    # A flow-insensitive global binding set would falsely fire AST009 on dump() below
    # (Codex audit). With inline-only AST009, neither line fires.
    p = Path(__file__)
    return p.parent


def dump(p, data):
    # `p` is a parameter, NOT this skill's __file__ -> must NOT fire AST009
    p.write_text(data)


# A module-level __file__ binding used only to READ our own source for a banner.
src = Path(__file__)
VERSION_LINE = src.read_text().splitlines()[0] if src.exists() else ""


def export(src, dest_text):
    # `src` here is a PARAMETER that shadows the module-level `src = Path(__file__)`.
    # Lexical masking must resolve to the param (a caller-chosen path), NOT the module
    # binding -> must NOT fire AST009 (Codex round 3 FP: the per-scope set used to leak
    # the module binding into this same-named param).
    src.write_text(dest_text)


def write_report(report):
    # rebind a self-path variable to a DERIVED sibling, then write the sibling. Flow-
    # sensitive last-write-wins must DROP the self-path binding on the rebind, so this
    # benign report write does NOT fire AST009 (Codex round 3 re-sweep FP).
    out = Path(__file__)
    out = out.with_name("report.txt")
    out.write_text(report)


def write_siblings():
    # paths DERIVED from __file__ are DIFFERENT files (report/output/backup), not the
    # running file -> must NOT fire AST009 (the with_name/parent/rename-source guards)
    import os
    Path(__file__).with_name("report.txt").write_text("ok")
    (Path(__file__).parent / "out.bin").write_bytes(b"ok")
    os.rename(__file__, "backup.py")   # __file__ is the SOURCE (arg0); dst is elsewhere


def derive_sibling_name():
    # `__file__.replace(".py", ".txt")` is the STR substring method (a benign idiom to derive a
    # sibling filename), NOT pathlib Path.replace — the round-6 replace handling is gated on an
    # INLINE Path(...) receiver, so this str form stays GREEN (round-6 sweep AST009 FP guard).
    return __file__.replace(".py", ".txt")


def read_own_lines():
    # fileinput WITHOUT inplace just READS our own file -> must NOT fire AST009 (the new
    # fileinput arm gates on inplace not being a false constant) (round-6 sweep FP guard).
    import fileinput
    return [line for line in fileinput.input(__file__)]


def rename_self_away():
    # Path(__file__).rename moves the running file AWAY — like the already-GREEN
    # os.rename(__file__, dst), __file__ is the SOURCE (a backup/relocation), not the inject
    # TARGET; AST009 is scoped to CONTENT rewrite, so the source-move stays GREEN (round-6
    # consistency: the path-rename/replace finding was a misclassification vs the os.rename rule).
    Path(__file__).rename("backup_copy.py")


def truncate_scratch():
    # os.truncate on a NON-self path -> must NOT fire AST009 (the arm gates on _self_target(arg0)).
    import os
    os.truncate("scratch.log", 0)


def write_other_via_getattr():
    # getattr(pathlib, "Path")("config.txt") builds a Path for ANOTHER file — the inline-getattr
    # Path-ctor resolves, but the target is not __file__, so it must NOT fire AST009 (round-7
    # audit FP guard for the getattr->Path-ctor recognition).
    import pathlib
    getattr(pathlib, "Path")("config.txt").write_text("ok")


def read_self_by_keyword():
    # open(file=__file__) WITHOUT a write mode just READS our own source -> must NOT fire AST009;
    # the keyword-aware file-arg resolution must still respect the read/write mode gate (round-7).
    return open(file=__file__).read()


def truncate_caught_not_self():
    # `q` is bound to __file__, but `except E as q` REBINDS q to the CAUGHT EXCEPTION inside the
    # handler — os.truncate(q) there targets the exception object, NOT our own running file, so the
    # block-scoped capture masking suppresses AST009 (round-8 audit F1 __file__ FP guard).
    import os
    q = __file__
    try:
        risky()
    except Exception as q:
        os.truncate(q, 0)


def transitive_caught_not_self():
    # `p` is bound to __file__, but `except E as p` captures it as the exception; the TRANSITIVE
    # `r = p` inside the handler must NOT inherit the __file__ provenance — the capture overlay is
    # consulted during propagation, not only at the final use (round-8 re-sweep H6 __file__ FP guard).
    import os
    p = __file__
    try:
        risky()
    except Exception as p:
        r = p
        os.truncate(r, 0)


if __name__ == "__main__":
    build(sys.argv[1] if len(sys.argv) > 1 else "demo")
    read_self()
    write_siblings()
