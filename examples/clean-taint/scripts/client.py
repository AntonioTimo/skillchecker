#!/usr/bin/env python3
"""Local env reporter (example: credential reads that never reach a network sink).

Negative fixture for the taint pass — every credential read stays on the machine,
so no source->sink flow exists and no TF finding (and no HI009) is produced.
"""

import os


def show_home():
    # credential read that never reaches a sink -> no flow
    cfg = os.environ["HOME"]
    print(cfg)


def build_auth_header():
    # credential passed only to a same-file, non-network helper -> no sink reached
    token = os.environ["MY_API_KEY"]
    headers = {"Authorization": token}
    return use_locally(headers)


def use_locally(headers):
    # purely local handling, no network sink
    return ",".join(sorted(headers))


def summarize(rows):
    # non-credential value built and used locally -> no source, no sink
    total = sum(len(r) for r in rows)
    return {"rows": len(rows), "total": total}


def walrus_local():
    # a walrus binding of a credential that stays LOCAL (printed, no sink) — the
    # NamedExpr handling must propagate taint, but with no sink there is no flow,
    # so still no TF finding (proves the binding handler doesn't over-fire)
    if (tok := os.environ["MY_API_KEY"]):
        print(len(tok))


def for_target_local():
    # for-target over a credential iterable, but used only locally -> no flow
    for v in os.environ.values():
        print(len(v))


if __name__ == "__main__":
    show_home()
    build_auth_header()
    summarize([[1, 2], [3]])
    walrus_local()
    for_target_local()
