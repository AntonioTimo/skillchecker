# Spec — Exfil / evasion breadth (Phase D)

- **Date:** 2026-06-01
- **Status:** Proposed (awaiting review)
- **Target version:** 1.4.0
- **Branch:** `feat/exfil-breadth`
- **Phase:** D of the v2 plan — the **final** increment (C, A, B done → **D**).

---

## 1. Problem

The exfiltration signatures (`CR026`) and shell checks predate a wave of newer
techniques that a careful attacker now reaches for:

- **Modern tunneling / OOB-interaction services** — Cloudflare quick tunnels,
  `serveo`, `localtunnel`, `localhost.run`, interactsh (`*.oast.*`), request
  collectors (`pipedream`, `beeceptor`, `requestcatcher`). They point at the
  attacker's box and are absent from `CR026`'s list.
- **IP-literal and numeric-encoded IP URLs** (`http://203.0.113.5/`,
  `http://2130706433/`, `http://0x7f000001/`) — dodge domain-based blocklists.
- **`${IFS}` shell evasion** — spaces without spaces, to slip past naive checks.
- **Environment-variable dumps piped to the network** (`env | curl …`) —
  wholesale secret theft in one line.
- **Long high-entropy base64/hex blobs** — embedded payloads the decode-exec
  rules miss when the decode happens elsewhere.

## 2. Approach

Breadth, not a new pass: mostly new **line-based regex rules** added to the
existing `CRITICAL_RULES` / `HIGH_RULES` / `MEDIUM_RULES` lists, plus one
per-rule guard (private-IP) in `scan_file`.

## 3. Rules

| Rule | Catches | Severity |
|---|---|---|
| `CR034` | tunneling / OOB exfil host (`trycloudflare.com`, `serveo.net`, `loca.lt`, `lhr.life`, `localhost.run`, `*.oast.*`, `pipedream.net`, `beeceptor.com`, `requestcatcher.com`, `telebit`) | CRITICAL |
| `CR035` | env-var dump piped to a network command (`env`/`printenv` → `curl`/`wget`/`nc`) | CRITICAL |
| `HI019` | IP-literal or numeric-encoded IP in a URL (dotted public IPv4 / `0x`-hex / decimal / IPv6) | HIGH |
| `HI020` | `${IFS}` / `$IFS` shell space-substitution evasion | HIGH |
| `HI021` | `api.telegram.org/bot…` — Telegram bot API as an exfil channel | HIGH |
| `ME011` | long (≥256) high-entropy base64/hex literal not part of a decode chain — possible embedded payload | MEDIUM |

**False-positive guards**
- `HI019` skips loopback and private ranges (`127/8`, `10/8`, `192.168/16`,
  `172.16–31/12`, `169.254/16`, `0.x`, `::1`) — local-dev URLs like
  `http://127.0.0.1:8080` do **not** fire.
- `ME011` requires length ≥ 256 and skips 40-/64-char hex (git SHA-1 / SHA-256),
  so commit hashes and checksums do not fire.
- `HI021` is HIGH (not CRITICAL) because a genuine Telegram-bot skill legitimately
  uses it — the auditor confirms intent.

## 4. Documentation & catalogue
- `references/red-flags.md`: new exfil/evasion rows.
- `references/patch-templates.md`: "remove the endpoint / use the user's own
  configured channel" guidance.
- `THREAT_MODEL.md`: new rule rows under data-exfiltration.
- `CHANGELOG.md`: `## [1.4.0]`.

## 5. Test plan (RED → GREEN → REFACTOR)
**RED.** `examples/evil-exfil/` exercises every new pattern (tunnel host,
numeric-encoded IP, `${IFS}`, `env | curl`, Telegram API, base64 blob). The
current scanner misses the new ones.

**GREEN.** Add the rules → each fires → 🔴 RED.

**REFACTOR (negatives).** `examples/clean-exfil/` — a `http://127.0.0.1:8080`
local-dev URL, a 40-char git SHA, and a hardcoded trusted public API over HTTPS —
must stay GREEN.

**CI.** `evil-exfil` must exit 3 with `CR034`+`CR035`; `clean-exfil` must exit 0.

## 6. Versioning

New detections → **1.4.0**. This closes the v2 roadmap (C, A, B, D).
