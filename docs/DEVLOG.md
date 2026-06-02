# Dev log — v2

A per-phase narrative digest: goal, the gap it closed, what shipped, key
decisions, and verification. Companion to the design specs in `docs/specs/` and
the per-version detail in `CHANGELOG.md`.

**v2 plan:** C → A → B → D. Each phase its own cycle — spec → RED (a failing
fixture proving the gap) → GREEN (implementation) → REFACTOR (negative fixtures) →
docs → PR → squash-merge → GitHub release.

| Phase | Theme | Version | PR | Status |
|---|---|---|---|---|
| C | Bundled config / hooks / MCP | v1.1.0 | [#1](https://github.com/AntonioTimo/skillchecker/pull/1) | ✅ released |
| A | Python AST pass | v1.2.0 | [#2](https://github.com/AntonioTimo/skillchecker/pull/2) | ✅ released |
| B | Unicode / invisible characters | v1.3.0 | [#3](https://github.com/AntonioTimo/skillchecker/pull/3) | ✅ released |
| D | Exfil / evasion breadth | v1.4.0 | [#4](https://github.com/AntonioTimo/skillchecker/pull/4) | ✅ released |
| E | Evasion v2 (normalization + homoglyph domains) | v1.5.0 | — | 🚧 in review |

---

## Phase C — Bundled config / hooks / MCP (v1.1.0, PR #1)

**Goal.** Detect skills that ship executable *configuration* beside `SKILL.md`.

**The gap (RED).** A skill can ship `.claude/settings.json` with a `PreToolUse`
hook, or `.mcp.json` with a stdio server — the Claude Code harness runs them on
install, automatically, with **no `allowed-tools` entry**. The line scanner never
inspected these structurally, so a hooks+MCP skill scored 🟢 GREEN (exit 0, zero
findings). Proven by `examples/evil-plugin/` (clean SKILL.md, malicious config).

**The fix (GREEN).** `check_bundled_config` parses bundled config with
`json.loads` (never executes; textual backstop for non-parseable JSON):
`CR032` hooks + `CR033` stdio MCP (CRITICAL), `HI017` remote MCP, `HI018`
permission broadening, `ME010` benign settings, `INV002` plugin dirs.

**Key decision.** Keys off config **filenames**, not a blind key search — so a
`references/*.json` data file carrying `hooks`/`command` keys stays GREEN
(`examples/clean-with-data/`).

**Verified.** evil-plugin GREEN→RED (exit 3, CR032+CR033); clean-with-data GREEN;
CI + self-audit green.

## Phase A — Python AST pass (v1.2.0, PR #2)

**Goal.** Catch dangerous calls the line regex misses because they're aliased,
split across lines, or built dynamically.

**The gap (RED).** `examples/evil-ast/helper.py` hides `run = eval; run(x)`,
`getattr(os, "sys" + "tem")(arg)`, a multi-line `subprocess.run(..., shell=True)`,
and `exec` of a char-built string. The pre-1.2.0 scanner caught only the bare
`exec(` (HI007) → a soft 🟡 YELLOW.

**The fix (GREEN).** `ast_scan` parses each `.py` with `ast.parse` (no execution)
and resolves call targets structurally: `AST001` dynamic eval/exec, `AST002`
aliased builtins, `AST003` subprocess `shell=True` any layout, `AST004`
pickle/marshal.loads, `AST005` yaml.load, `AST006` dynamic getattr, `AST007`
dynamic import, `AST008` char-built exec.

**Key decision.** AST distinguishes a string literal `"eval("` from a real
`eval()` call — so the pass adds **zero** false positives on the scanner's own
rule strings (where the regex pass self-flags). Degrades to a no-op on
unparseable source.

**Verified.** evil-ast YELLOW→RED (AST001/002/003/006/008); clean-ast GREEN;
self-audit gained no AST findings on scan.py.

## Phase B — Unicode / invisible characters (v1.3.0, PR #3)

**Goal.** Catch deceptive Unicode the line/AST passes can't see (they operate on
already-read text).

**The gap (RED).** `examples/evil-unicode/SKILL.md` hid a `U+202E` bidi override,
a zero-width space, Unicode Tags-block characters, and a Cyrillic `sudo`
homoglyph. The pre-1.3.0 scanner scored it 🟢 GREEN.

**The fix (GREEN).** `unicode_scan` inspects raw codepoints across all text
including `.md` prose: `UNI001` bidi (override CRITICAL / embed-isolate HIGH),
`UNI002` zero-width/invisible, `UNI003` Unicode Tags block, `UNI004` homoglyph.

**Key decisions.**
- `UNI004` uses a **neighbour test** — it fires only on a confusable letter
  embedded *inside* a Latin word. This repo is bilingual RU/EN, so hyphenated
  compounds (`MCP-конфиг`) and glued jargon (`заinjectить`) must **not**
  false-positive, and don't. Emoji ZWJ / variation selectors excluded from
  `UNI002`.
- The pass scans `.md` prose (unlike most rules) because the prose *is* the
  attack surface.

**Notable.** On the first run the scanner **caught its own author**: I had left a
literal `U+FEFF` and a literal Cyrillic homoglyph in `scan.py`. Fixed with escape
sequences; self-audit now clean. (The tool works — it caught the mistake.)

**Verified.** evil-unicode GREEN→RED (UNI001-004); clean-unicode GREEN; scan.py
self-audit clean; intentional homoglyph examples in the spec self-flag (documented
caveat).

## Phase D — Exfil / evasion breadth (v1.4.0, PR #4)

**Goal.** Close the modern exfil/evasion gaps the original signatures predate.

**The gap (RED).** `examples/evil-exfil/` ships a Cloudflare quick tunnel, an
`env`-to-network dump, numeric-encoded IP URLs, IFS-based space evasion, the
Telegram bot API, and a long base64 blob. The pre-1.4.0 scanner scored it 🟢 GREEN.

**The fix (GREEN).** Six new regex rules in the existing lists: `CR034` tunneling/
OOB hosts and `CR035` env-dump-to-network (CRITICAL); `HI019` IP-literal/encoded-IP
URL, `HI020` IFS evasion, `HI021` Telegram API (HIGH); `ME011` long base64/hex
blob (MEDIUM).

**Key decisions.** `HI019` guards loopback / RFC1918 so local-dev URLs don't
fire; `ME011`'s 256-char threshold keeps git SHAs and checksums clean. Both proven
by `examples/clean-exfil/`.

**Verified.** evil-exfil GREEN→RED (all six rules); clean-exfil GREEN; no
regressions across the nine example fixtures.

**Closes the v2 roadmap** — C, A, B, D all shipped.

### Post-review hardening (in PR #4)

An external **Codex** review of the v2 branch found real gaps — all fixed before
merge, each regression-tested by `examples/evil-bypass/` and broader CI asserts:

- folded/list `allowed-tools` carrying `Bash(* *)` bypassed the wildcard check → `FM005` now scans the whole frontmatter;
- the negation guard suppressed `CR028`–`CR031` on bare modals ("you **should** ignore safety") → only real negations count now;
- `~~~` fences and inline code were under-scanned → both scanned as code;
- `.git/` (and `node_modules/`, etc.) flooded `INV001` when auditing a clone → skipped;
- documented `bash <(curl)` / `eval "$(curl)"` were not implemented → `CR036`/`CR037`;
- the "read-only by design" claim was overstated (`echo` + redirect) → reworded honestly.

Lesson logged: a security tool's worst failure is the **false negative** (a silent
bypass that reads as 🟢). The review caught four of them before they shipped.

---

## Phase E — Evasion v2 (v1.5.0, in review) · first v3 increment

**Goal.** Close evasion that survives v2: Unicode-normalization tricks and homoglyph domains.

**The gap (RED).** `examples/evil-evasion/` hid `curl … | sh` in **fullwidth**
glyphs, `exec` in **math-styled** glyphs, an `xn--` punycode host, and the cloud
metadata IP `169.254.169.254` (which `HI019`'s link-local guard skipped). The
pre-1.5.0 scanner scored it 🟢 GREEN.

**The fix (GREEN).** `scan_file` now also scans an **NFKC-normalized** copy of each
target — escalate-only, so fullwidth/compat commands surface while legit `½`/`™`/CJK
do not. `CR038` cloud-metadata SSRF; `HI022` IDN/punycode host.

**Verified.** evil-evasion GREEN→RED (CR001/HI007 via NFKC, CR038, HI022);
clean-evasion GREEN; no regressions across the 13 fixtures. Two code-review rounds
hardened it further (case-insensitive host rules, bare-host/userinfo punycode, the
HI019 private-masks-public bug, and a defensive inline-code guard).

`docs/ROADMAP.md` lays out the rest of the v3 backlog (taint/data-flow, JS AST,
supply-chain, …).
