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

## v3 candidates

### Deepen existing passes
- **E — Evasion v2 (✅ shipped in v1.5.0):** NFKC normalization pre-scan (fullwidth /
  compatibility-character evasion), IDN / punycode + homoglyph domains, and the
  cloud-metadata SSRF endpoint (`CR038`) that `HI019`'s link-local guard would
  otherwise skip. *Source: spec B's "full TR39 / NFKC / IDN homoglyphs"
  non-goal, plus a guard gap found after v1.4.0.*
- **Taint / data-flow AST:** cross-function flow so a dangerous sink fed by a
  traced value is distinguished. *Source: THREAT_MODEL #4, spec A.* Caveat: must
  not REDUCE paranoia — the tool flags every non-literal sink today.
- **JS / TS AST pass:** a real parser for JS like `ast` is for Python. *Source:
  spec A.* Blocked on a dependency-free JS parser (the scanner ships no deps,
  makes no network calls).
- **MCP reputation / hook-content inspection.** *Source: spec C.*

### New threat classes
- **Supply-chain:** bundled `requirements.txt` / `package.json` / lockfiles that
  pull from a git or URL source, unpinned installs. *Source: THREAT_MODEL #2/#3.*

### Architecturally out of scope (a different tool, or never)
- **Dynamic analysis / runtime sandboxing** — changes what the tool *is*
  (pre-install gate → runtime monitor). *Source: THREAT_MODEL #1/#6.*
- **Author / repo reputation** — deliberately the user's call. *Source:
  THREAT_MODEL #5.*
