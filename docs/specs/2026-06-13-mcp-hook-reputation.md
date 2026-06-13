# Spec — MCP / hook destination reputation (Phase G)

- **Date:** 2026-06-13
- **Status:** Proposed (awaiting review)
- **Target version:** 1.7.0
- **Branch:** `feat/mcp-hook-reputation`
- **Phase:** G — the first "deepen an existing pass" v3 increment. *Source: `docs/ROADMAP.md` "Deepen existing passes → MCP reputation / hook-content inspection", spec C.*

---

## 1. Problem

`check_bundled_config` (Phase C) detects the **presence** of a bundled hook
(`CR032`), a stdio MCP server (`CR033`), or a remote MCP server (`HI017`). It does
**not** look at *where* that hook/server points. The per-line scan of the `.json`
files (Step 2) does see the host independently — `HI019` flags a public-IP literal,
`HI022` a punycode host — but neither subsystem connects "this is a config the
harness auto-loads on session start" with "and its destination is reputation-bad".
The two findings land separately, each HIGH, so the verdict under-calls.

Verified empirically against the current scanner (single bundled remote MCP server,
the realistic one-server attack):

| Bundled config | Today | Rules | Verdict |
|---|---|---|---|
| `.mcp.json` remote MCP → **raw public IP** (`https://185.220.101.5/sse`) | exit **1** | `HI017`+`HI019` | 🟡 YELLOW |
| `.mcp.json` remote MCP → **punycode** (`https://xn--80ak6aa92e.com/mcp`) | exit **1** | `HI017`+`HI022` | 🟡 YELLOW |
| `.mcp.json` remote MCP → **encoded IP** (`http://0x08080808/mcp`) | exit **1** | `HI017`+`HI019` | 🟡 YELLOW |
| `.mcp.json` remote MCP → ordinary named domain | exit 1 | `HI017` | 🟡 YELLOW *(correct — no reputation signal; a human reviews)* |

A bundled MCP server that the Claude Code harness **auto-loads on session start**,
hardcoded to a bare public IP (185.220.101.0/24 is a real Tor exit range) or a
punycode homoglyph host, is malware-tier — yet it reads 🟡 YELLOW ("patch and
proceed"), the same severity as a hygiene nit. That is a **severity false negative**:
the correct verdict is 🔴 RED ("refuse — the user adds MCP servers themselves,
never the skill, and never to a bare IP"). This is the project's worst-failure
class (a dangerous skill under-rated), just one notch up from a silent GREEN —
HI017 already raises *a* flag, but the wrong-severity flag.

**Diagnosis (not the symptom).** The bug is not "HI019 should be CRITICAL in a
`.json`" (it must not — a public IP in a *data file* is only a HIGH-worthy note).
The bug is that **two subsystems each hold half the signal and neither escalates**:
`check_bundled_config` knows it is an auto-loaded MCP/hook destination but does not
classify the host; the line pass classifies the host but does not know it is an
auto-loaded destination. The fix unifies them at the structural layer — exactly the
`check_bundled_config`/`check_supply_chain` pattern of composing a known detector
(host reputation) over a newly-recognized structural surface (the parsed
hook/MCP destination), keyed off config **filenames**.

## 2. Approach

No new line-regex subsystem (the project's recurring lesson: a line heuristic
spawns sibling forms — rebuild structurally instead). Inside the existing
`check_bundled_config`, when a hook `command`, a stdio MCP `command`+`args`, or a
remote MCP `url` is found, **classify its destination host** and, if it is
reputation-bad, emit `CR040` (CRITICAL).

Host classification **reuses the canonical detectors** — no parallel host list
that could drift from `HI019`/`HI022`:

- `_public_ip_in(text)` (the existing `urllib.parse` + `ipaddress` + `shlex`
  extractor behind `HI019`) → a public-IP literal, including hex/decimal-encoded
  IPv4 (`0x08080808`, `2130706433`), while loopback / RFC1918 / link-local skip.
- the `HI022` punycode check (`xn--`) → an IDN / homoglyph host.

**Scope of the reputation signal — deliberately narrow.** `CR040` fires only on
the two signals the line rules rate merely HIGH: **public-IP literal** and
**punycode/IDN**. A known exfil/tunnel/cloud-metadata host (`webhook.site`,
`trycloudflare.com`, `169.254.169.254`, …) is **already** CRITICAL via the line
rules `CR026`/`CR034`/`CR038` scanning the `.json` — so `CR040` intentionally does
**not** re-flag those (no double-emit, no noise), and an ordinary named domain is
**not** a reputation signal (it stays `HI017` YELLOW for human review, per the
threat model). The job of `CR040` is precisely the severity gap: a bare-IP /
punycode destination inside an auto-loaded config.

`CR040` is emitted at each of the three sites in `check_bundled_config`:

1. **remote MCP `url`** — the verdict-flip case (escalates `HI017` YELLOW → RED).
2. **hook `command`** (walked out of the nested `hooks` structure) — already RED
   via `CR032`; `CR040` adds the precise destination attribution and catches a
   host assembled across the command string that a single `.json` line might miss.
3. **stdio MCP `command`+`args`** (joined) — already RED via `CR033`; same
   attribution/robustness value.

On a config that won't parse as JSON, `CR040` is skipped (best-effort on parseable
configs only) — the per-line `HI019`/`HI022` scan still covers the host, and the
textual `CR032`/`HI017` backstop still flags the presence.

## 3. Rules

| Rule | Catches | Severity | Where |
|---|---|---|---|
| `CR040` | A bundled hook / MCP destination (hook `command`, stdio MCP `command`+`args`, or remote MCP `url`) whose **host** is a **public-IP literal** — IPv4 or bracketed IPv6, incl. single-integer and dotted hex/octal encodings — or a **punycode/IDN** host — an auto-loaded config pointed at a reputation-bad endpoint | CRITICAL | structural (`check_bundled_config`) |

**Severity resolution (argued from the FP budget, ≤5%).** `CR040` is **CRITICAL**:
a bundled config the harness auto-loads on session start, hardcoded to a bare
public IP or a punycode homoglyph host, has no legitimate form — legitimate MCP
servers use named registry-style domains, and legitimate local-dev servers use
loopback / RFC1918 (which `_public_ip_in` skips). It is the structural twin of
`CR038` (a metadata IP is CRITICAL wherever it appears) and `CR032`/`CR033`
(bundled auto-exec is CRITICAL on presence). The FP class is near-empty once the
host gate excludes private/loopback and named domains.

## 4. False-positive guards

- **Filename gate (master guard, inherited).** `CR040` runs only inside
  `check_bundled_config`, which collects candidates strictly by config **basename**
  (`settings.json` / `settings.local.json` / `.mcp.json` / `mcp.json` /
  `plugin.json`, root + `.claude/` + `.claude-plugin/`, symlinks skipped). A
  `references/*.json` data file describing MCP servers — even with `url` / `command`
  keys and even with a raw-IP value — never reaches this code, so it cannot be
  escalated to CRITICAL. (A raw IP in a data file still earns the per-line `HI019`
  HIGH, which is correct: a literal public IP merits a note, not a refusal.)
- **Private / loopback / encoded-loopback gate.** `_public_ip_in` classifies
  `127.0.0.1`, `192.168.x`, `10.x`, `169.254.x` (link-local — the metadata IP is
  `CR038`'s job, not here) and reserved/unspecified as **private** → no `CR040`. A
  local-dev MCP server at `http://127.0.0.1:7000/sse` stays `HI017` YELLOW.
- **Named-domain discrimination.** A remote MCP at `https://mcp.example.com/sse`
  has no IP literal and no `xn--` → no `CR040`; it stays `HI017` YELLOW (the
  user reviews the URL and decides). This is the load-bearing negative.
- **No double-emit on already-CRITICAL hosts.** Tunnel / exfil / cloud-metadata
  hosts are left to `CR026`/`CR034`/`CR038` (already CRITICAL via the line scan) —
  `CR040`'s host gate is IP-literal + punycode only.
- **Host-gated, not whole-string.** Both signals (IP and punycode) classify on the
  host(s) `_candidate_hosts` extracts, never the raw string — so a public IP or an
  `xn--` label sitting in a URL **path / query / fragment** of a benign named host
  does not escalate (added after the adversarial review caught the path-`xn--` FP).
- **Single source of truth.** Reuses `_candidate_hosts` / `_ip_publicness` and the
  `xn--` form — no copied host table to drift from `HI019`/`HI022`. Fixing the
  shared extractor for IPv6 and dotted-encoded IPv4 (review round) closed the same
  hole in `HI019` for free.

## 5. Test plan (RED → GREEN → REFACTOR)

**Gap proof (severity FN, reproducible).** A *minimal* fixture — one `.mcp.json`
with a single remote MCP at a raw public IP, nothing else — scores **exit 1
(YELLOW)** today (`HI017`+`HI019`) and must score **exit 3 (RED)** after `CR040`.
This single-server case is the realistic attack and the clean verdict-flip; it is
demonstrated inline (a richer fixture is RED today already, because ≥3 `HI017` or a
`CR032` hook independently route to RED, so the flip is only *visible* on the
one-server minimal case).

**RED.** `examples/evil-mcp/` ships real config files (filename-gated):

- `.mcp.json` with five servers — `raw-IP` (`HI017`+`HI019`+**`CR040`**),
  `punycode` (`HI017`+`HI022`+**`CR040`**), `encoded-IP` (`HI017`+`HI019`+**`CR040`**),
  `named-domain` (`HI017` only — **no `CR040`**, discrimination), and
  `loopback` (`HI017` only — **no `CR040`**, private-IP gate).
- `.claude/settings.json` with a `PreToolUse` hook whose command targets a public
  IP — `CR032` + **`CR040`** (hook-command attribution).

The richer dir is RED today (the hook's `CR032`); CI asserts `CR040` **presence**,
per-variant snippets (raw-IP / punycode / encoded-IP / hook-command), and that the
named-domain and loopback servers carry `HI017` but **no** `CR040`.

**GREEN.** Add the `CR040` emission → the three reputation-bad MCP servers + the
hook command flag `CR040` → 🔴 RED with `CR040` present.

**REFACTOR (negatives).** `examples/clean-mcp/` must stay GREEN, exit 0:
a `references/mcp-catalog.json` **data file** documenting MCP servers with `url` /
`command` keys at **named** hosts (filename gate keeps it GREEN — the
`api-shapes.json` precedent), plus `SKILL.md` prose that mentions MCP servers,
`url`, and hooks in plain documentation. No bundled config file, so no
`CR032`/`CR033`/`HI017`/`CR040` — the clean fixture proves the structural rules
never touch a look-alike data file.

**CI.** `evil-mcp` must exit 3 with `CR040` present (+ per-variant snippet asserts
+ named-domain/loopback discrimination); `clean-mcp` must exit 0 with zero
`CR040`. Wired into `.github/workflows/tests.yml` mirroring the `evil-plugin` /
`clean-with-data` blocks.

## 6. Out of scope (residual, after Phase G)

1. **MCP `env` / `headers` secret-egress.** A server config that injects a
   credential reference (`"env": {"TOKEN": "${ANTHROPIC_API_KEY}"}`, an
   `Authorization` header) forwards the user's secrets to a third party. Real, but
   judgment-heavy on FP (env/headers are legitimately how MCP servers authenticate
   to *their own* service) — deferred to a later phase, kept narrow. Promote to
   `docs/ROADMAP.md` as the next "deepen existing passes" candidate.
2. **Full engine re-run over extracted hook/MCP command content.** Running the
   joined command through all of `ALL_RULES` would attribute every rule, but
   `CR032`/`CR033` already route hooks/stdio MCP to RED, so the marginal verdict
   value is ~zero and the double-emit noise is real. Deferred.
3. **Ordinary named-domain remote MCP.** Stays `HI017` YELLOW by design — no
   reputation signal to escalate on without an allowlist/reputation feed the
   dependency-free, no-network scanner forbids (THREAT_MODEL #5).
4. **Non-TLS `http://` to a named host.** Cleartext egress is a weaker signal than
   IP/punycode and false-positives on legitimate local/dev servers; not escalated.
5. **Trailing-dot IP literal** (`185.220.101.5.`). A confirmed but narrow under-call
   (the shared `_ip_publicness` reads the FQDN-rooted form as a named host; affects
   `HI019` too, and resolution is client-dependent). Deferred — close it in the
   shared extractor in a later pass, with the same fixture+CI lock.
6. **Shell `VAR=ip cmd $VAR` in a hook/stdio command.** A public IP assigned to a
   var and dereferenced (`X=45.83.122.10 curl $X`) escapes the `_candidate_hosts`
   shell walk (the assignment token precedes the command, and `$X` is unexpanded).
   Attribution-only and never a verdict miss — a bundled hook/stdio is already
   `CR032`/`CR033` RED, and the only verdict-flipping path (remote `url`) is a plain
   string, never shell-parsed. The correct fix is the ROADMAP's taint/data-flow
   shell-walker (track assignments, resolve `$VAR` before host classification),
   done once for `HI019` + `CR040` together.

## 7. Versioning

A new detection (one structural rule, deepening an existing pass) → **1.7.0**.
