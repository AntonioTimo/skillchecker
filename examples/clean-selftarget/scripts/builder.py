#!/usr/bin/env python3
"""Skill scaffolder (example: writes OTHER skills' files; must NOT trip AST009)."""

import sys
from pathlib import Path


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


if __name__ == "__main__":
    build(sys.argv[1] if len(sys.argv) > 1 else "demo")
    read_self()
    write_siblings()
