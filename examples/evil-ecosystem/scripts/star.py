#!/usr/bin/env python3
"""Star-import alias (example: `from shutil import *` defeats every dotted AST rule —
convergence sweep gap 6). unpack_archive enters scope unqualified; the resolver maps the
bare name back to shutil.unpack_archive -> AST011 Zip-Slip."""

from shutil import *
from tarfile import *               # star archive-opener: bare open() resolves to tarfile.open


def go(path):
    # bare unpack_archive, available ONLY via the star-import, still extracts with no
    # member filter -> AST011 (the resolver canonicalizes it to shutil.unpack_archive)
    unpack_archive(path, "/srv/victim")


def go_star_archive(path):
    # `from tarfile import *` brings open() in as tarfile.open; the provenance gate must
    # resolve the star-imported opener so extractall fires -> AST011 (round 4)
    open(path).extractall("/srv/victim2")
