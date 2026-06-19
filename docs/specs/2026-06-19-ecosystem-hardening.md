# Spec — Ecosystem hardening: 2026 supply-chain + prompt-injection + MCP secret-egress (Phase J)

- **Date:** 2026-06-19
- **Status:** Proposed (awaiting review)
- **Target version:** 1.10.0
- **Branch:** `feat/ecosystem-hardening`
- **Phase:** J — a multi-source "borrow-from-the-field" increment. *Source: a 5-lane web sweep of the agent-skill / MCP / LLM-app security ecosystem (MITRE ATT&CK, Vigil-llm, Bandit, Token Security, StepSecurity, Socket.dev, mcp-scan), scoped against our invariants. Every gap was grep-verified absent from `scan.py`.*

---

## 1. Problem

After the SkillSpector borrows (Phases H–I), a wider ecosystem sweep found **six
genuine dependency-free false-negative classes** that remain — verified absent from
`scan.py`. They share a character: each **completes a surface we opened one field
short**, plus two genuinely new primitives (ChatML delimiters, `/dev/tcp`). All are
RED/HIGH drivers, not MEDIUM noise.

1. **Forged-instruction prose.** A `SKILL.md` that pastes a forged chat-template turn
   (`<|im_start|>system … <|im_end|>`, `<<SYS>>`, `[INST]`, `{{#system~}}`) or a
   "disregard all previous instructions" override structurally prompt-injects the
   host model. `CR029`/`CR031` return GREEN on all of these (verified).
2. **Python process-replacement + native-FFI sinks.** `AST003` models only
   `os.system`/`os.popen`/`subprocess.*` — so `os.execv("/bin/sh", …)` /
   `os.spawnv` / `os.posix_spawn` read GREEN (the obvious `AST003` bypass). And
   `tarfile/zipfile.extractall` without a member filter is Zip-Slip path traversal
   (overwrite `~/.ssh/authorized_keys` / `~/.claude`).
3. **MCP secret-egress.** `check_bundled_config`'s `mcpServers` loop reads only
   `command`/`args`/`url` — a hardcoded live token in `env` (`GITHUB_…: ghp_…`) or a
   concrete `Authorization` header leaks a secret we read as a mere presence flag
   (~20% of MCP configs carry hardcoded secrets — Token Security). This is the named
   `docs/ROADMAP.md` "MCP env/headers secret-egress" candidate.
4. **`binding.gyp` install-RCE (Phantom Gyp).** `CR039` keys off
   `package.json`/`pyproject`/`requirements` lifecycle scripts; `node-gyp` runs
   `binding.gyp` on `npm install` with **no** package.json script, and its `<!(…)`
   command-substitution smuggles a shell command (a live 2026 worm campaign).
5. **Second-stage payload sources + inbound C2.** `CR026` covers exfil *destinations*
   (upload); the *download/staging* source class (`transfer.sh`, `gofile.io`,
   `bashupload.com`, `file.io`, `0x0.st`, …) that feeds two-stage `curl|bash` is the
   canonical MITRE T1608.001 vector and reads GREEN. A bash reverse shell over
   `/dev/tcp/HOST/PORT` (inbound C2) also reads GREEN.
6. **Bundled native executable (precision).** `INV001` already RED-flags any binary,
   but does not say it is *executable*; a magic-byte check (ELF/PE/Mach-O) escalates
   the precise case to CRITICAL with a believable message.

**Diagnosis.** Each is a missing entry in an **existing** pass — not a new subsystem.
The fix completes the `AST003` sink set, the `mcpServers` parse, the `CR039` manifest
set, and the `CR026` host axis, and adds two new line primitives. Argued from the
budget, grounded in a cited source per rule.

## 2. Approach (all dependency-free, never-executes, in existing passes)

**Forged-instruction prose → `PROSE_TARGETING` line rules:**
- `CR041` (CRITICAL) — chat-template control tokens, a fixed literal set ported from
  Vigil-llm `system_instructions.yar`: `<|im_start|>`/`<|im_end|>`, `<<SYS>>` /
  `<</SYS>>`, `[INST]`/`[/INST]`, `[system](#assistant|#context|#system)`,
  `{{#system~}}`/`{{/system}}`. No ML author types these in prose.
- `HI026` (HIGH) — the instruction-override **triple gate**: an override verb
  (`ignore`/`disregard`/`forget`/`override`/`bypass`) + a prior-reference
  (`previous`/`preceding`/`above`/`prior`/`earlier`/`all`/`the system`) + an
  instruction-noun (`instructions`/`directives`/`context`/`rules`/`prompt`/
  `guidance`). The triple gate means `ignore errors` / `skip the above step` don't
  fire. Both join `PROSE_TARGETING` (+ the negation guard).

**Python process-replacement + FFI → `ast_scan` (`_AstAuditor.visit_Call`):**
- `AST010` — the `os.exec*` / `os.spawn*` / `os.posix_spawn[p]` family. Severity
  mirrors `AST003`: **CRITICAL** when the program-path arg is non-literal,
  **HIGH** when fully literal (a literal exec of a fixed helper).
- `AST011` (MEDIUM) — `.extractall(…)` with no `members=` and no `filter=` kwarg, and
  `shutil.unpack_archive` — Zip-Slip path traversal (Bandit B202 / Ruff S202). The
  `filter=` keyword check mirrors how `AST005` inspects `yaml.load`'s `Loader=`.

**MCP secret-egress → `check_bundled_config` (sibling of the `mcpServers` loop):**
- `CR042` (CRITICAL) — an `mcpServers.<name>.env` value or a `headers` value that is a
  **concrete live-secret shape** (`ghp_`/`gho_`/`ghs_`, `sk-[A-Za-z0-9]{20,}`,
  `xox[baprs]-`, `AKIA[0-9A-Z]{16}`, `AIza…`, an `eyJ…` JWT). **Placeholder guard:**
  never fire on `${VAR}`, `<…>`, `YOUR_…_HERE`, `xxx`, or a bare ENV-name echo.
- `HI027` (HIGH) — an `env`/`headers` value that is a **credential-file reference**
  (reuse the `CR025` regex) or a **reputation-bad destination** (reuse
  `_reputation_bad_dest`). Inherits those passes' tuned FP profiles.

**`binding.gyp` → `check_supply_chain` (one filename added):**
- `CR043` (CRITICAL) — a `binding.gyp` string value containing the gyp
  command-substitution token `<!(` or `<!@(`. JSON-parse then walk; textual `<!(`
  backstop if it won't parse (mirrors the `CR039` backstop).
- `HI028` (HIGH) — bare presence of `binding.gyp` in a skill (a Claude skill is never
  a legitimately npm-installed native addon). Presence is HIGH; the `<!(` token is
  CRITICAL.

**Staging hosts + reverse shell → line rules:**
- `CR044` (CRITICAL) — `/dev/(tcp|udp)/` pseudo-device and the `nc`/`ncat`/`netcat … -e`
  exec form (a bash/netcat reverse shell — inbound C2). No legit skill use.
- `HI029` (HIGH) — anonymous file-staging / paste **download** hostnames
  (`transfer.sh`, `gofile.io`, `file.io`, `bashupload.com`, `anonfile`, `0x0.st`,
  `tmpfiles.org`, `oshi.at`, `ix.io`, `0bin`, `controlc.com`), a `CR026`-shaped
  line-regex. HIGH not CRITICAL (`transfer.sh` has some legit dev use).

**Bundled-binary precision → `INV001` escalation (no new rule):**
- When a non-text file's first bytes are a known executable magic number (ELF
  `\x7fELF`, PE `MZ`, Mach-O `\xfe\xed\xfa\xce`/`\xcf\xfa\xed\xfe`, Java `\xca\xfe\xba\xbe`),
  raise the existing `INV001` from HIGH to **CRITICAL** with an "executable" message,
  reusing the bytes already read in `_looks_like_text`.

## 3. Rules

| Rule | Catches | Severity | Pass |
|---|---|---|---|
| `CR041` | chat-template control tokens forging a system/assistant turn in SKILL.md prose | CRITICAL | line (PROSE) |
| `HI026` | "disregard all previous instructions"-grammar override (verb+prior-ref+noun) | HIGH | line (PROSE) |
| `AST010` | `os.exec*`/`os.spawn*`/`posix_spawn` process replacement (CRITICAL non-literal, HIGH literal) | CRITICAL/HIGH | AST |
| `AST011` | `extractall`/`unpack_archive` without a member filter (Zip-Slip) | MEDIUM | AST |
| `CR042` | a **live-token** value in a bundled MCP `env`/`headers` | CRITICAL | structural |
| `HI027` | a credential-file ref or reputation-bad dest in a bundled MCP `env`/`headers` | HIGH | structural |
| `CR043` | gyp `<!(` command-substitution in a bundled `binding.gyp` | CRITICAL | structural |
| `HI028` | bare presence of a bundled `binding.gyp` | HIGH | structural |
| `CR044` | `/dev/tcp` reverse shell / `nc -e` inbound C2 | CRITICAL | line |
| `HI029` | anonymous file-staging / paste **download** host | HIGH | line |
| `INV001`↑ | bundled file whose magic bytes are an executable (ELF/PE/Mach-O) | HIGH→CRITICAL | inventory |

**Severity (argued from the FP budget).** The CRITICALs (`CR041`/`CR042`/`CR043`/
`CR044`, and `AST010` non-literal) each have a near-empty benign population by
construction: ML control tokens, a live-token string in a shipped config, a gyp
`<!(`, a `/dev/tcp`, and a non-literal `os.exec` have no legitimate skill use. The
HIGHs (`HI026`/`HI027`/`HI028`/`HI029`, `AST010` literal) carry a small but real
benign tail (a documented override phrase, a real native addon, `transfer.sh` dev
use) → review, not auto-refuse. `AST011` is MEDIUM (a vuln-class, not pure malice).

## 4. False-positive guards

- **PROSE negation guard (inherited).** `CR041`/`HI026` join `CR028–031` etc. in the
  position-based clause-aware negation guard — a skill *documenting* these patterns
  defensively is suppressed; a `references/*.md` self-flags only under self-audit.
- **`HI026` triple gate.** verb **and** prior-ref **and** instruction-noun — `ignore
  previous deprecation warnings` (no instruction-noun) does not fire.
- **`CR042` placeholder guard.** `${VAR}` / `<…>` / `YOUR_…_HERE` / `xxx` / bare
  ENV-name echoes never fire; only a concrete token *shape*.
- **`AST010`/`AST011` reuse `_dotted_name`/`_is_literal`** and the keyword-walk — a
  string-literal `"os.execv("` in scanner code is not a call (no self-FP), and
  `extractall(filter="data")` / `members=[…]` is exempt.
- **`CR043`/`HI028` filename gate.** Only an actual `binding.gyp` (by filename) is
  inspected; prose / a `references/*.json` mentioning it stays GREEN.
- **`HI029` host list is staging-specific**, not general infra (no github/s3) — HIGH,
  and the most-FP-prone (`transfer.sh`) is kept HIGH not CRITICAL.
- **`INV001`↑ reuses bytes already read** — no new file open; non-executable binaries
  stay HIGH.

## 5. Test plan (RED → GREEN → REFACTOR)

**RED.** `examples/evil-ecosystem/` — a real skill carrying one vector per rule:
SKILL.md prose with a ChatML token + an override sentence (`CR041`/`HI026`);
`scripts/x.py` with `os.execv` + `tarfile.extractall` (`AST010`/`AST011`); a
`.mcp.json` with `env: {GITHUB_TOKEN: ghp_…}` + a remote server with an
`Authorization` header token (`CR042`/`HI027`); a `binding.gyp` with `<!(` (`CR043`/
`HI028`); a shell block with `/dev/tcp` + a `transfer.sh` download (`CR044`/`HI029`);
and a bundled ELF stub for `INV001`-CRITICAL. CI asserts exit 3 + each id + per-form
snippets.

**REFACTOR (negatives).** `examples/clean-ecosystem/` must stay GREEN, exit 0: a
SKILL.md that *defensively* names the override grammar ("never disregard previous
instructions"); a `.py` with `subprocess.run([…])` + `extractall(filter="data")`; a
`.mcp.json` with `env: {TOKEN: "${GITHUB_TOKEN}"}` (placeholder) and an
`Authorization: Bearer ${VAR}` header; **no** `binding.gyp`; prose mentioning
`transfer.sh` inside a defensive `references`-style note; and a normal text file.

**CI.** `evil-ecosystem` exit 3 with all ids + snippet locks; `clean-ecosystem` exit
0 with none. Full fixture sweep additive. A pre-merge **adversarial parser review**
per the project ritual (the prose triple-gate and the live-token shapes especially).

## 6. Out of scope (the dropped ecosystem borrows, recorded)

- **OPT-IN (behind a flag / a follow-up — fits invariants but not default):**
  conditional/sleeping-payload AST+shell **sink-gated co-occurrence** (needs new
  subtree-walk machinery — M-effort), `ctypes`/`cffi` native-loading, the
  read+egress capability **amplifier**, suspicious-TLD links, dependency-confusion
  self-version inflation, the inlined-`.mcp.json`-`tools[]` schema scan, **SARIF
  output**, **TT4 file-read→network taint**.
- **Reserved for v2.0 (a real capability leap, opens a new surface):** the **JS/TS
  AST pass** — the first second-language parse, which unlocks the npm
  serialize-environment / silent-process-execution classes that are SKIP-by-language
  today, and forces the vendored-parser-vs-dependency decision. SARIF + TT4 bundle
  into that 2.0. A coarse regex JS pass is **rejected** (the HI019 fragile-sibling
  lesson).
- **SKIP (breaks an invariant):** live MCP tool-poisoning / line-jumping (tool
  descriptions live on the running server at `tools/list` — needs network+exec);
  rug-pull tool-description diffing (cross-session state + live fetch); XXE
  (FP-budget without taint+dep-suppression); JS env-dump regex (belongs in the JS
  pass, not a fragile regex); money/crypto wallet terms (low CC base rate, broad FP).
- **Needs an LLM (Claude-side):** the semantic intent of a live MCP tool description;
  DAN/persona disambiguation for a borderline `HI026` hit; whether a read+egress
  posture is malicious in *this* skill's stated purpose. All handled by the
  `SKILL.md` verdict steps, not the scanner.

## 7. Versioning

A multi-rule ecosystem-hardening increment (≈10 rules across existing passes + an
`INV001` precision escalation), no new subsystem, no new language → **1.10.0**, a
minor. **Not v2.0** — that is reserved for the JS/TS pass (a genuine new surface);
calling "8 more rules in five existing passes" a major would be version inflation,
off-brand for this project's "findings must be believed" culture.
