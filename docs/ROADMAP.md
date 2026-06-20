# Roadmap

Shipped and candidate work. Each shipped phase has a `docs/specs/` design and a
`DEVLOG.md` entry; each candidate cites its source — a `THREAT_MODEL.md` "What is
out of scope" item or a spec "Non-goals" line.

## Shipped

| | Theme | Version |
|---|---|---|
| v1 | Initial auditor: LLM audit steps + regex scanner | 1.0.0–1.0.1 |
| C | Bundled config / hooks / MCP | 1.1.0 |
| A | Python AST pass | 1.2.0 |
| B | Unicode / invisible characters | 1.3.0 |
| D | Exfil / evasion breadth + code-review hardening | 1.4.0 |
| E | Evasion v2: NFKC normalization + homoglyph domains | 1.5.0 |
| F | Supply-chain: bundled dependency manifests | 1.6.0 |
| G | MCP / hook destination reputation (`CR040`) | 1.7.0 |
| H | Taint / data-flow: credential → network exfil (`TF001`/`TF002`) | 1.8.0 |
| I | Self-targeting prose + self-modification + activation-surface (`HI024`/`HI025`/`ME013`/`ME014`/`ME015`/`AST009`) — borrow-from-SkillSpector | 1.9.0 |
| J | Ecosystem hardening — forged-instruction prose, `os.exec`/Zip-Slip, MCP secret-egress, Phantom Gyp, reverse-shell + staging hosts (`CR041`–`CR044`/`HI026`–`HI029`/`AST010`/`AST011`) | 1.10.0 |
| — | Adversarial-audit hardening (Codex + self-run multi-agent sweeps, to convergence): fail-closed `IO004`, comma-coordinator negation guard, walrus/`for`/comprehension taint + `HI009` httpx, per-scope-lexical `AST009`, value-aware `AST011` + `.extract`/method-ref + import-alias resolver, recursive manifest discovery, bounded tree walks; AST-based `check_docs.py` doc-currency gate | 1.11.0 |

## Road to v2.0

By the v1.10.0 ecosystem sweep's own assessment, the well of **dependency-free
static gaps is largely dry** — the remaining minors complete surfaces already opened
(see "Next minors" below). The one move that genuinely earns a **major v2.0** is a
**new surface**:

- **★ v2.0 headline — JS / TS AST pass.** A real parser for JavaScript/TypeScript
  the way `ast` is for Python — the scanner's **first second language**. Unlocks the
  classes that are SKIP-by-language today (npm serialize-environment / env-dump→
  network, silent `child_process` execution, JS dynamic eval beyond the `HI016`
  regex). *Source: spec A; the v1.10.0 ecosystem spec §6.* **The hard decision it
  forces** — there is no stdlib JS parser, so a major version must resolve the
  no-dependency invariant: either **vendor a pure-Python JS tokenizer/parser** (a
  large blob to audit — ironic for a tool that flags unaudited blobs) **or accept a
  parser dependency** (breaks "dependency-free"). A **coarse regex JS pass is
  rejected** — the `HI019` fragile-sibling lesson: a line-regex over a structured
  language spawns sibling forms forever.
- **Bundle into the same v2.0:** **SARIF 2.1.0 output** (`--format sarif`, a pure
  stdlib `json.dumps` transform — GitHub code-scanning / IDE interop) and the
  **`TT4` file-read→network taint** extension (reuses `_TaintAuditor`; behind a flag
  because the file-read source surface is broad). Both are ready ergonomics that ride
  the major so it carries a real surface expansion plus the deferred niceties.

## Next minors (deepen existing passes — dependency-free)

- **Taint next increment.** Other source/sink families on the v1.8.0 `_TaintAuditor`:
  external-input→exec (`TT5`, mostly subsumed by `AST001`/`AST003`), tainted→
  file-write (exfil-to-disk). Plus the architectural reach: **cross-function** and
  **inter-file** flow (a call graph), **container-mutation aliasing**, **`socket.send`
  sinks** (need type inference). *Source: THREAT_MODEL #4; spec H §6.* (`TT4`
  file-read→network is bundled into v2.0 above.)

## OPT-IN backlog (behind a flag — fits invariants, not default-on)

Each is dependency-free and never-executes, but breaks an FP budget or needs new
machinery if default-on; ship behind a flag. *Source: spec `2026-06-19-ecosystem-
hardening.md` §6 + `2026-06-19-self-targeting.md` §6.*

- **Conditional / sleeping-payload (logic-bomb) co-occurrence** — an AST `If`/`IfExp`
  whose test is a time/`$CI`/`NODE_ENV`/hostname/counter gate AND whose body holds an
  already-recognized exec/taint/network sink (sink-gated, so the conditional alone
  never fires). The one M-effort item — needs new subtree-walk machinery. *Repello AI,
  OWASP-Agentic two-stage payload.*
- **`ctypes` / `cffi` native-code loading** — `ctypes.CDLL`/`cdll.LoadLibrary` (AST,
  reuses `_dotted_name`/`_is_literal`). HIGH-default; a `.so` perf helper is a
  plausible benign case.
- **read + egress capability amplifier** — `Read`+`WebFetch` (or `Bash(curl)`) both in
  `allowed-tools`: a severity *amplifier* when it co-occurs with a flagged exfil host /
  credential read, info-only alone (high benign base rate). *3 skill scanners.*
- **`.mcp.json` inlined tool-schema injection** — if a bundled config statically
  inlines a `tools[]`/`inputSchema` array, walk its description/default strings with
  the existing prose/exfil regexes (filename-keyed). *mcp-shield.* (The common case —
  tool descriptions from the **running** server — is SKIP: needs network.)
- **Typosquatting** — dependency name edit-distance to a **bundled** popular-package
  frozenset (no network, but a guaranteed-stale list; tight distance guards). *Phylum/
  Socket.dev.*
- **Suspicious-TLD / disposable-host links** (`.tk/.ml/.xyz/.top` + free dynamic-DNS)
  in a network context — a corroborating MEDIUM, network-context-gated. *GuardDog.*
- **Dependency-confusion self-version inflation** (`package.json` version ≥99 /
  `X.X.X` with X≥90) — a MEDIUM nudge folded into the supply-chain pass. *Microsoft.*

## SKIP / needs an LLM (recorded so the next session doesn't re-litigate)

- **SKIP — breaks an invariant:** OSV/CVE live lookups, abandoned-dep flags (network);
  YARA-via-`yara-python` (dependency); **live MCP tool-poisoning / rug-pull** (tool
  descriptions are returned by the *running* server at `tools/list` — needs network +
  execution); a coarse regex JS pass (HI019 lesson); XXE (FP budget); money/crypto
  wallet terms (low CC base rate). *Spec ecosystem §6.*
- **Needs an LLM (the Claude-side `SKILL.md` steps, not the scanner):** semantic intent
  of a live MCP tool description; description-vs-behavior mismatch (`TP4`, already a
  Step 7.5 advisory); DAN/persona disambiguation for a borderline override hit.

## Architecturally out of scope (a different tool, or never)
- **Dynamic analysis / runtime sandboxing** — changes what the tool *is*
  (pre-install gate → runtime monitor). *Source: THREAT_MODEL #1/#6.*
- **Author / repo reputation** — deliberately the user's call. *Source:
  THREAT_MODEL #5.*
