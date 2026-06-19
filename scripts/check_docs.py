#!/usr/bin/env python3
"""Doc-currency guard — fails (exit 1) if the docs drift from the product state.

Mechanically enforces "the docs ALWAYS reflect what the scanner actually does", so a
rule or fixture can never ship undocumented. Dependency-free, never executes anything;
reads files only. Wired into CI (.github/workflows/tests.yml) so every PR is gated.

Checks:
  1. Every rule ID the scanner can EMIT (a rule-list entry or a `rule_id="…"` Finding)
     is documented in THREAT_MODEL.md, references/red-flags.md, or SKILL.md.
  2. Every examples/<fixture>/ dir is exercised by the CI sweep in tests.yml.
  3. CHANGELOG.md has a top entry whose version is referenced in docs/ROADMAP.md
     (the shipped table) — so a release can't land without a roadmap row.

Internal/quality IDs (IO*, LO*) are exempt from the documentation check.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _read(rel):
    return (ROOT / rel).read_text(encoding="utf-8", errors="replace")


def emitted_rule_ids(scan: str) -> set:
    """Rule IDs the scanner can emit: every rule-list tuple `("XX###", …` and every
    structural `rule_id="XX###"`."""
    ids = set(re.findall(r'\(\s*"([A-Z]{2,4}\d{3})"\s*,', scan))
    ids |= set(re.findall(r'rule_id\s*=\s*"([A-Z]{2,4}\d{3})"', scan))
    return ids


def documented_ids(text: str) -> set:
    """Every rule ID a doc references — literal (`CR040`) AND expanded from a RANGE
    (`CR006–CR014`, `HI019-HI021`, `AST001–AST008`), so the readable range notation in
    THREAT_MODEL.md counts each member as documented."""
    out = set(re.findall(r'\b[A-Z]{2,4}\d{3}\b', text))
    for m in re.finditer(r'\b([A-Z]{2,4})(\d{3})\s*[–\-]\s*([A-Z]{2,4})?(\d{3})\b', text):
        pre, a, pre2, b = m.group(1), int(m.group(2)), m.group(3), int(m.group(4))
        if pre2 in (None, pre):
            for n in range(a, b + 1):
                out.add(pre + str(n).zfill(3))
    return out


def main() -> int:
    problems = []
    scan = _read("scripts/scan.py")
    ids = emitted_rule_ids(scan)

    # --- Check 1: every emitted detection rule is documented somewhere ---
    docs = _read("THREAT_MODEL.md") + "\n" + _read("references/red-flags.md") + "\n" + _read("SKILL.md")
    documented = documented_ids(docs)
    EXEMPT_PREFIX = ("IO", "LO")   # internal IO errors / quality nits
    undocumented = sorted(
        r for r in ids
        if not r.startswith(EXEMPT_PREFIX) and r not in documented
    )
    if undocumented:
        problems.append(
            "Undocumented rule IDs (emitted by scan.py but absent from THREAT_MODEL.md / "
            "red-flags.md / SKILL.md): " + ", ".join(undocumented))

    # --- Check 2: every example fixture is exercised by the CI sweep ---
    ci = _read(".github/workflows/tests.yml")
    fixtures = sorted(p.name for p in (ROOT / "examples").iterdir()
                      if p.is_dir() and not p.name.startswith("."))
    orphan_fixtures = [f for f in fixtures if f not in ci]
    if orphan_fixtures:
        problems.append(
            "Fixtures not referenced in tests.yml (an un-swept example silently rots): "
            + ", ".join(orphan_fixtures))

    # --- Check 3: the top CHANGELOG version has a docs/ROADMAP.md shipped row ---
    changelog = _read("CHANGELOG.md")
    m = re.search(r"^##\s*\[(\d+\.\d+\.\d+)\]", changelog, re.M)
    if not m:
        problems.append("CHANGELOG.md has no `## [X.Y.Z]` version entry.")
    else:
        ver = m.group(1)
        roadmap = _read("docs/ROADMAP.md")
        if ver not in roadmap:
            problems.append(
                f"CHANGELOG top version {ver} is not in docs/ROADMAP.md (the shipped table) "
                "— a release landed without a roadmap row.")

    if problems:
        print("DOC-CURRENCY CHECK FAILED — the docs no longer reflect the product:")
        for p in problems:
            print("  ✗ " + p)
        print("\nFix: document the rule (THREAT_MODEL.md row + red-flags.md), add the "
              "fixture to tests.yml, or add the ROADMAP/CHANGELOG row — in the SAME commit.")
        return 1

    print(f"doc-currency OK — {len(ids)} rule IDs all documented, "
          f"{len(fixtures)} fixtures all swept, CHANGELOG ↔ ROADMAP in sync ✓")
    return 0


if __name__ == "__main__":
    sys.exit(main())
