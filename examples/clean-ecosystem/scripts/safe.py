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
