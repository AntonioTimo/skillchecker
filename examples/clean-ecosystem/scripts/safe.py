#!/usr/bin/env python3
"""Safe archive helper (example: the safe form of the Phase J AST patterns)."""

import subprocess
import tarfile


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
