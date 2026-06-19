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
