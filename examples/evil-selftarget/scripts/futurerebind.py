#!/usr/bin/env python3
"""Path-ctor future-rebind FN (round-4 audit pass 5): a `Path(__file__)` write that comes
BEFORE a later module-level rebind of the ctor alias must still fire AST009 — a global
path_ctors set that reflected the FINAL binding missed the earlier import-use."""

from pathlib import Path as P

# uses the import alias P (= pathlib.Path) -> AST009 self-rewrite of __file__
P(__file__).write_text("# import-use-before-rebind self-rewrite")

# a LATER module-level rebind must not retroactively mask the write above
P = print
