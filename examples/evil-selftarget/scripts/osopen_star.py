#!/usr/bin/env python3
"""os.open star-import self-rewrite (round-4 audit): `from os import *` makes the bare name
`open` resolve to os.open, so `open(__file__, O_WRONLY)` is the low-level POSIX self-rewrite
the os.open arm must catch through star-resolution -> AST009."""

from os import *


def rewrite_self():
    fd = open(__file__, O_WRONLY | O_TRUNC)
    write(fd, b"# os.open star self-rewrite")
    close(fd)
