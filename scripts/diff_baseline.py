#!/usr/bin/env python3
"""Differential baseline harness for the round-9 abstract-interpreter migration (dev-only tool).

The four per-scope timeline walkers (alias / __file__ / archive / method-ref) are being unified into
ONE evaluator over `ValueFacts` (the single source of binding/resolution semantics that ends the
H1-H7 sibling cycle). To migrate SAFELY the scanner's OUTPUT must not drift: this tool captures a
GOLDEN snapshot of {rule_id, severity, line, snippet} per fixture (+ exit code) from the current
scanner, then compares a later run against it. Any drift on the corpus is a migration regression.

  python3 scripts/diff_baseline.py capture   # write golden (run on the verified-green baseline)
  python3 scripts/diff_baseline.py compare    # diff current output vs golden; exit 1 on drift

The golden file is gitignored (a local migration checkpoint, not a committed artifact). The corpus
is every examples/* fixture — which after round-8 covers all binding-form / provenance / shadow /
rebind / transitive / capture / walrus combinations the migration must preserve.
"""
import json
import os
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORPUS = sorted(
    d for d in os.listdir(os.path.join(REPO, "examples"))
    if os.path.isdir(os.path.join(REPO, "examples", d))
)
GOLDEN = os.path.join(REPO, "scripts", ".diff_golden.json")


def snapshot():
    out = {}
    for d in CORPUS:
        path = os.path.join(REPO, "examples", d)
        r = subprocess.run([sys.executable, os.path.join(REPO, "scripts", "scan.py"), path],
                           capture_output=True, text=True)
        try:
            data = json.loads(r.stdout)
            findings = sorted(
                [f["rule_id"], f["severity"], f.get("line"), f.get("snippet", "")]
                for f in data["findings"]
            )
        except Exception:
            findings = [["<PARSE-ERROR>", r.stdout[:300]]]
        out[d] = {"exit": r.returncode, "findings": findings}
    return out


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "compare"
    cur = snapshot()
    if mode == "capture":
        json.dump(cur, open(GOLDEN, "w"), indent=1, sort_keys=True)
        n = sum(len(v["findings"]) for v in cur.values())
        print(f"golden captured: {len(cur)} fixtures, {n} findings -> {os.path.relpath(GOLDEN, REPO)}")
        return 0
    if not os.path.exists(GOLDEN):
        print("no golden — run `python3 scripts/diff_baseline.py capture` first")
        return 2
    golden = json.load(open(GOLDEN))
    drift = 0
    for d in CORPUS:
        g, c = golden.get(d), cur.get(d)
        if g != c:
            drift += 1
            print(f"::DRIFT:: {d}")
            if (g or {}).get("exit") != (c or {}).get("exit"):
                print(f"   exit {(g or {}).get('exit')} -> {(c or {}).get('exit')}")
            gf = {tuple(x) for x in (g or {}).get("findings", [])}
            cf = {tuple(x) for x in (c or {}).get("findings", [])}
            for x in sorted(gf - cf):
                print(f"   LOST: {x[0]} {x[1]} L{x[2]} :: {str(x[3])[:80]}")
            for x in sorted(cf - gf):
                print(f"   NEW:  {x[0]} {x[1]} L{x[2]} :: {str(x[3])[:80]}")
    if drift:
        print(f"\n{drift} fixture(s) drifted from golden — migration regression")
        return 1
    print(f"differential OK — {len(CORPUS)} fixtures match golden (no output drift)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
