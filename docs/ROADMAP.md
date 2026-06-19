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

## v3 candidates

### Deepen existing passes
- **E — Evasion v2 (✅ shipped in v1.5.0):** NFKC normalization pre-scan (fullwidth /
  compatibility-character evasion), IDN / punycode + homoglyph domains, and the
  cloud-metadata SSRF endpoint (`CR038`) that `HI019`'s link-local guard would
  otherwise skip. *Source: spec B's "full TR39 / NFKC / IDN homoglyphs"
  non-goal, plus a guard gap found after v1.4.0.*
- **Taint / data-flow AST (✅ partially shipped in v1.8.0):** Phase H added an
  intraprocedural, single-file taint pass connecting a **credential source**
  (`os.environ`/`os.getenv`) to a **network sink** — `TF001` CRITICAL (reputation-bad
  / user-controlled destination), `TF002` HIGH (hardcoded named host). Additive-only;
  reuses the `CR040` destination machinery; the URL position is excluded from payload
  taint to spare configurable env→URL endpoints. *Source: THREAT_MODEL #4, spec A;
  cross-checked vs NVIDIA SkillSpector `behavioral_taint_tracking`.* Residual / next
  increment: **cross-function** and **inter-file** flow (no call graph), **other
  source/sink families** (file-read→network à la SkillSpector TT4, external-input→exec
  TT5, tainted→file-write), **container-mutation aliasing**, and **`socket.send`
  sinks** (need type inference). Caveat preserved: the pass never REDUCES paranoia —
  it only adds/escalates on top of the non-literal-sink findings the tool already
  emits.
- **JS / TS AST pass:** a real parser for JS like `ast` is for Python. *Source:
  spec A.* Blocked on a dependency-free JS parser (the scanner ships no deps,
  makes no network calls).
- **MCP / hook destination reputation (✅ shipped in v1.7.0):** `CR040` escalates
  a bundled hook / MCP destination (hook `command`, stdio `command`+`args`, remote
  `url`) pointed at a public-IP literal or punycode/IDN host to CRITICAL — the
  severity gap where a lone bare-IP / punycode MCP read YELLOW. Reuses
  `_public_ip_in` / `HI022`; keyed off config filenames. *Source: spec C.* Residual
  out of scope: MCP `env`/`headers` secret-egress, full engine re-run over hook
  command content, ordinary named-domain MCP reputation (no network feed).
- **MCP `env` / `headers` secret-egress.** A bundled MCP server config that injects
  a credential reference (`"env": {"TOKEN": "${ANTHROPIC_API_KEY}"}`, an
  `Authorization` header) forwards the user's secrets to a third party. *Source:
  Phase G spec out-of-scope #1.* Judgment-heavy on FP (env/headers are how MCP
  servers legitimately auth to their own service) — needs a narrow signal
  (shell-style interpolation / credential-shaped var names) to stay in budget.

### New threat classes
- **Supply-chain (✅ shipped in v1.6.0):** a structural pass over bundled
  dependency manifests — `CR039` npm install-lifecycle scripts, `HI023`
  non-registry (git/URL/tarball/index-redirect) sources, `ME012` unpinned installs.
  Keyed off manifest filenames, never executes the file. *Source: THREAT_MODEL
  #2/#3.* Residual out of scope: transitive deps, malicious updates to
  already-pinned libs, CVE/version reputation, typosquatting, runtime fetches.

### Architecturally out of scope (a different tool, or never)
- **Dynamic analysis / runtime sandboxing** — changes what the tool *is*
  (pre-install gate → runtime monitor). *Source: THREAT_MODEL #1/#6.*
- **Author / repo reputation** — deliberately the user's call. *Source:
  THREAT_MODEL #5.*
