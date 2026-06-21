#!/usr/bin/env python3
"""Future-rebind FN (round-4 audit pass 5): an import-use that comes BEFORE a later
module-level rebind of the same name must still resolve to the import -> AST003. A
flow-insensitive global alias map read the FINAL value (`safe`) and missed the call."""

from os import popen


def run(cmd):
    # os.popen with a non-literal command, resolved via the import BEFORE the rebind below
    return popen(cmd).read()


# a LATER module-level rebind must not retroactively mask the call above
popen = print
