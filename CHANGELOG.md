# Changelog

All notable changes to skill-checker.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.8.0] — 2026-06-19

Deepens the Python AST pass into **data flow**: a new **taint pass** connecting a
**credential source** (`os.environ` / `os.getenv`) to a **network sink** across
intervening assignments. The line and AST passes classify one node at a time, so a
secret read in one statement, packaged in a second, and shipped in a third reads
only 🟡 YELLOW (a lone `HI009`). That split-variable credential exfil is the
project's worst-failure class — a dangerous skill under-rated — and now reads 🔴 RED.
The central FP tension (a legitimate authenticated API client is the same shape) is
resolved **by construction**, gating CRITICAL on the **destination**, not the flow —
no in-loop LLM, unlike the SkillSpector reference impl this phase cross-checked.

### Added
- `scripts/scan.py`: a new **`TF` family** (taint-flow) in a new pass `taint_scan`,
  called from `main()` per `.py` file after `ast_scan` (re-parses; never executes).
  - **`TF001` (CRITICAL)** — a credential-tainted value reaches an HTTP-client
    network sink whose destination is **reputation-bad or user-controlled**: a
    non-literal URL, a public-IP literal (incl. hex/decimal-encoded), a punycode/IDN
    host, or a known exfil/tunnel/metadata host. Two rare facts ANDed
    (secret-tainted **and** bad/dynamic dest) keep it in the ≤5% budget — a legit API
    client cannot land here.
  - **`TF002` (HIGH)** — the same flow to a **hardcoded named-HTTPS** host (incl.
    loopback/RFC1918): the legit-client shape, a secret still leaving the machine, so
    a human reviews — not auto-refused.
  - Intraprocedural, source-order, monotonic (no taint kill); container literals,
    f-strings, and concatenation propagate for free. Sinks: `requests`/`httpx`/
    `aiohttp` `.get/.post/.put/.patch/.delete/.request/.head/.options`,
    `urllib.request.urlopen`/`Request` (the `HI009` vocabulary). Reuses the `CR040`
    destination machinery (`_reputation_bad_dest`/`_public_ip_in`) and derives
    `_EXFIL_HOST_RES` **from** the `CR026`/`CR034`/`CR038` line rules — one source of
    truth, no parallel host table.
  - **Additive only**: never suppresses or downgrades a line/AST finding (`HI009`
    still fires on every network call); the URL position is excluded from payload
    taint, so a configurable env→URL endpoint with a non-secret body is not a false
    CRITICAL.
- `examples/evil-taint/` — a clean `SKILL.md` shipping `scripts/upload.py` with seven
  credential→bad/dynamic-dest chains (`TF001`: public IP, user-URL, f-string dest,
  hex-IP, punycode, `webhook.site`, urllib) plus two benign-shaped egresses
  (`TF002`: a named API in an `Authorization` header, a loopback dev callback) that
  prove the named/loopback destinations are **not** over-escalated to CRITICAL.
- `examples/clean-taint/` — credential reads that never reach a network sink (no
  `requests`/`httpx`/`urllib` at all) → exit 0, zero `TF` findings.
- CI: `evil-taint` must exit 3 with `TF001`≥6 + `TF002` + per-destination-form
  snippet asserts + named-host/loopback discrimination (`TF002` not `TF001`);
  `clean-taint` must exit 0 with no `TF` leakage.
- `docs/specs/2026-06-19-taint-flow.md`; `references/red-flags.md` rows;
  `references/patch-templates.md` § taint TF002; `THREAT_MODEL.md` rows + acceptable
  + out-of-scope; `README.md` Limitations; `SKILL.md` Step + Limitations.

## [1.7.0] — 2026-06-13

Deepens an existing pass: **MCP / hook destination reputation**.
`check_bundled_config` (Phase C) flagged the *presence* of a bundled hook
(`CR032`), stdio MCP (`CR033`), or remote MCP (`HI017`) but never looked at
*where* it pointed. A lone bundled remote MCP server hardcoded to a bare public IP
or a punycode host therefore scored 🟡 YELLOW (`HI017` + the per-line `HI019`/
`HI022`), the same severity as a hygiene nit — a severity false negative on an
auto-loaded, malware-tier destination (verified: a single bare-IP `.mcp.json`
server scored exit 1 before this change). The fix unifies the two half-signals —
"this is an auto-loaded config" and "its host is reputation-bad" — at the
structural layer.

### Added
- `scripts/scan.py`: `CR040` (CRITICAL), emitted inside `check_bundled_config`.
  When a hook `command`, a stdio MCP `command`+`args`, or a remote MCP `url`
  points at a **public-IP literal** (incl. hex/decimal-encoded) or a **punycode /
  IDN** host, the bundled-config finding escalates to CRITICAL → 🔴 RED. Host
  classification **reuses** `_public_ip_in` (the `urllib` + `ipaddress` + `shlex`
  extractor behind `HI019`) and the `HI022` `xn--` form — no parallel host table.
  New helpers `_reputation_bad_dest`, `_hook_command_strings`, `_cr040_finding`.
- `examples/evil-mcp/` — a clean `SKILL.md` shipping a `.mcp.json` with remote MCP
  servers at a raw public IP, a punycode host, and an encoded IP (each
  `HI017`+`CR040`), a stdio server with a public IP in `args` (`CR033`+`CR040`), a
  named-domain server and a loopback server (`HI017` only — discrimination), plus a
  `.claude/settings.json` hook whose command reaches a public IP (`CR032`+`CR040`).
- `examples/clean-mcp/` — a `references/mcp-catalog.json` data file documenting MCP
  servers with `mcpServers`/`url`/`command` keys at **named** hosts; the filename
  gate keeps it GREEN (the `api-shapes.json` precedent).
- CI: `evil-mcp` must exit 3 with `CR040` present (+ per-destination-variant
  snippet asserts + named-domain/loopback discrimination); `clean-mcp` must exit 0
  with no `CR040`/`CR032`/`CR033`/`HI017` leaking onto the data file.
- `docs/specs/2026-06-13-mcp-hook-reputation.md`; `references/red-flags.md` row;
  `references/patch-templates.md` § bundled-config CR040; `THREAT_MODEL.md` rows +
  acceptable + out-of-scope; `SKILL.md` Step 1.5 row; `docs/ROADMAP.md` → shipped.

### False-positive guards
- **Filename gate (inherited).** `CR040` runs only inside `check_bundled_config`,
  which collects candidates by config **basename** — a `references/*.json` data
  file describing MCP servers (even with a raw-IP value) never reaches it and so is
  never escalated to CRITICAL (a literal public IP there still earns the per-line
  `HI019` HIGH, which is correct).
- **Private / loopback gate.** `_public_ip_in` skips loopback / RFC1918 /
  link-local, so a local-dev MCP at `http://127.0.0.1:7000/sse` stays `HI017`.
- **Named-domain discrimination.** A remote MCP at a named host (no IP literal, no
  `xn--`) stays `HI017` YELLOW — the user reviews the URL and decides.
- **No double-emit.** Known exfil/tunnel/cloud-metadata hosts are left to
  `CR026`/`CR034`/`CR038` (already CRITICAL via the line scan); `CR040`'s host gate
  is IP-literal + punycode only.

### Out of scope (residual, after Phase G)
MCP `env`/`headers` secret-egress (judgment-heavy FP — promoted to
`docs/ROADMAP.md` as the next "deepen existing passes" candidate), a full engine
re-run over extracted hook/MCP command content (`CR032`/`CR033` already route to
RED — marginal value, double-emit noise), an ordinary named-domain remote MCP
(stays `HI017` by design — no reputation feed in a no-network scanner), and a
non-TLS `http://` to a named host (weak signal, FPs on dev servers).

### Fixed (pre-release adversarial review)
A multi-agent adversarial pass over the new destination extraction found four
real gaps — all in the **shared** `_candidate_hosts` / `_ip_publicness` engine
(so the fixes also close the identical hole in `HI019`), each reproduced against
the live scanner and locked with a fixture form + a CI snippet assert:
- **Public IPv6 literal in a remote MCP `url` was missed** — the URL-extraction
  regex excludes `]`, so `http://[2606:4700:4700::1111]/sse` truncated mid-literal
  and `urlsplit` raised → no host → no `CR040` (a bare-IPv6 MCP read YELLOW). The
  URL pass now falls back to pulling the bracketed IPv6 literal directly; loopback
  / ULA / link-local IPv6 still read private (no `CR040`).
- **Dotted-encoded IPv4 was missed** — `_ip_publicness` only decoded a single hex
  integer (`0x08080808`) or `\d{8,10}` decimal, so the per-octet forms a real
  client dials — dotted-hex (`0x08.0x08.0x08.0x08`), dotted-octal (`0250.0.0.1`),
  mixed — slipped, despite the spec promising "incl. hex/decimal-encoded". A
  4-octet form with any hex/octal octet now classifies as public (the obfuscation
  is the signal, the single-integer twin's logic); a plain dotted-decimal is taken
  by `ipaddress` first and a named host never parses, so no new FPs.
- **Punycode in a URL path/query/fragment over-flagged (FP)** — `_reputation_bad_dest`
  ran the `xn--` regex against the whole string, so a benign named host with an
  `xn--` label in the path (`https://api.example.com/xn--cache/list`) wrongly
  escalated to CRITICAL (over the ≤5% budget). Both signals (IP **and** punycode)
  are now classified on the **extracted host(s)** only, mirroring the IP branch —
  `xn--` in a path no longer fires `CR040` (a genuine punycode **host** still does).
- **Deferred (recorded, not fixed):** a trailing-dot IP literal (`185.220.101.5.`)
  and a shell `VAR=ip cmd $VAR` env-assignment/deref in a hook/stdio command — both
  are attribution-only (the env-assignment case never flips a verdict: `CR032`/
  `CR033` already route to RED, and the verdict-flipping remote-`url` path is a
  plain string never shell-parsed). The env-assignment root belongs to the
  ROADMAP's taint/data-flow shell-walker; both are noted in the spec out-of-scope.

## [1.6.0] — 2026-06-03

New threat class: **supply-chain** — bundled dependency manifests. The line rules
need a runtime install *verb* (`CR021`) or a public-IP literal (`HI019`); a
bundled `package.json` / `requirements.txt` / `pyproject.toml` / lockfile is a
*declaration*, so its dangerous forms were silent (verified: an evil manifest dir
scored exit 0, zero findings, before this change).

### Added
- `scripts/scan.py`: new **structural pass** `check_supply_chain(skill_root)`,
  modeled on `check_bundled_config` — it keys off manifest **filenames** (root +
  `scripts/`/`references/`/`assets/`, symlinks skipped), parses stdlib-only and
  **never executes** the file (`json.loads` for `package.json`/JSON locks, a
  line-based section-aware parse for `requirements*.txt`/`pyproject.toml`, a
  generic off-registry source scan for `yarn.lock`/`pnpm-lock.yaml`/`Pipfile`/
  `Cargo.toml`/`Gemfile`/`go.mod`/`environment.yml` — section-aware for TOML, so a
  crate's `[package]` `repository`/`homepage`/`documentation` metadata URL is not
  misread as a dependency source). Wired into `main()` right after the
  bundled-config pass.
  - `CR039` — npm/yarn/pnpm install-lifecycle script (`preinstall`/`install`/
    `postinstall`/`prepare`/`prepublish`/`prepublishOnly`) in a bundled
    `package.json` → CRITICAL. Presence is the danger (RCE on a plain
    `npm install`), keyed off the script **name**, not the command text — the
    static twin of a bundled hook (`CR032`). Textual backstop on JSON parse fail.
  - `HI023` — dependency from a **non-registry source**: VCS (`git+`/`hg+`/`svn+`/
    `bzr+`, `github:`/bare `user/repo`), an arbitrary URL/tarball/wheel, non-TLS
    `http://`, an index/source redirect (`--extra-index-url`/`--trusted-host`),
    or a poisoned lockfile `resolved` → HIGH.
  - `ME012` — bundled top-level manifest ships **unpinned** deps (only the open
    forms: `*`, `latest`, a bare name, an unbounded `>=`) → MEDIUM, aggregated one
    finding per manifest.
- `examples/evil-supplychain/` (package.json install scripts + git/shorthand/
  tarball deps; requirements with git/tarball/`--extra-index-url`/non-TLS/bare;
  pyproject git+wheel+bare; yarn.lock off-registry `resolved`) and
  `examples/clean-supplychain/` (exact+`--hash` pins, caret + `workspace:`/`file:`
  local deps, registry-`resolved` lock, normal `go.mod`, and a `references/
  graph.json` data file with `dependencies`/`scripts` keys the filename gate keeps
  GREEN).
- CI: `evil-supplychain` must exit 3 with `CR039`+`HI023`+`ME012` (plus per-source
  variant and per-manifest aggregate snippet asserts); `clean-supplychain` exit 0.
- `docs/specs/2026-06-03-supplychain.md`; `references/patch-templates.md` § supply-chain;
  `references/red-flags.md` rows; `THREAT_MODEL.md` rows + out-of-scope #2 narrowed;
  `SKILL.md` Limitations §2 + Step 1.6; `docs/ROADMAP.md` supply-chain → shipped.

### False-positive guards
- **Filename gate** — only files named exactly as a manifest (or `requirements*.txt`)
  are inspected; a `references/*.json` data file and prose/fenced docs stay GREEN.
- **Registry-host allowlist** — `pypi.org`/`files.pythonhosted.org`/
  `registry.npmjs.org`/`registry.yarnpkg.com`/`crates.io`/`rubygems.org`/
  `proxy.golang.org`/`conda.anaconda.org` (and subdomains) never fire, so lockfile
  `resolved` URLs and `--index-url https://pypi.org/simple` stay GREEN.
- **Local-vs-remote gate** — `file:`/`workspace:`/`link:`/`./`/`../` are not a
  remote bypass.
- **Bounded ranges are pinned-enough** — `^`/`~`/`~=`/`<`-bounded/comma-bounded
  stay GREEN (caret/tilde are the npm/PEP440 default; flagging them would blow the
  MEDIUM budget). Only the unambiguous open forms are `ME012`.
- **`CR039` keys off the lifecycle script name** — `build`/`test`/`ci` never fire
  even when their command text contains `npm install`; `CR021`'s quote-prefix
  guard already keeps a JSON `"ci": "npm install …"` GREEN.
- **Lockfiles + `go.mod` exempt from `ME012`** (pinned by construction); a
  non-registry dep is `HI023` only, never also `ME012`; `ME011` does not fire on
  lock integrity hashes (sha512 ~88 / sha256 64-hex < 256).

### Out of scope (narrows `THREAT_MODEL.md` #2 to "partially covered")
Transitive dependencies, a malicious update to an already-pinned registry library,
CVE/version reputation (#3), typosquatting (#5), and runtime fetches (`CR021`'s
job) remain out of scope — the dependency-free, no-network scanner reads the direct
manifest only.

### Fixed (pre-release code-review — Codex)
An external Codex pass over the branch found parser-form gaps; all fixed before
merge, each locked by a fixture form + a CI snippet assert:
- **`requirements.txt` source forms** — an `-e git+https://…` editable remote, a
  `--extra-index-url=…` (the `--opt=value` equals form), and a PEP 508
  `name @ git+ssh://…` direct reference all read GREEN. `_classify_source` now
  strips the PEP 508 `@` marker (so `@ git+ssh://…` classifies), the option parser
  accepts `--opt=value` and `-e`/`--editable`, and `git+ssh://` matches as VCS.
- **`[project.optional-dependencies]` arrays** — parsed element-wise now (incl.
  multi-line accumulation), so `dev = ["evil @ git+…", "bare"]` yields `HI023` +
  `ME012` instead of being read as one row.
- **`go.mod replace => remote`** — promised under `HI023` but unimplemented; now a
  dedicated `_supply_gomod` flags a `replace` whose target is a remote module
  (single-line and `replace ( … )` block), while a local `=> ../vendor` and a
  normal `require` stay GREEN.
- **`Cargo.lock` `[[package]]` regression** — the Cargo metadata-skip wrongly
  skipped `[[package]]` array-of-tables (where lock `source` lives). Double-bracket
  tables are no longer skipped; a `source = "git+https://…"` flags while a normal
  `registry+`/`sparse+` source (the GitHub-hosted crates.io index) stays GREEN.
- **`package-lock.json` metadata FP** — a `funding.url` / `repository.url` was read
  as a dependency source; the lock walk now inspects only `resolved`/`tarball`.
- **x-range `1.x` / `1.2.*`** now read as unpinned (`ME012`), matching the rule
  table; caret/tilde/exact stay pinned.
- `README.md` Limitation #2 updated from "No supply-chain analysis" to the partial
  coverage now shipped.

A second Codex pass found three more (all fixed, fixture + CI-locked):
- **`registry+`/`sparse+` allowlist was too broad** — it exempted *any* host, so a
  `registry+https://attacker.test/…` alternate registry read GREEN. Now only the
  official crates.io index (the GitHub-hosted git index / `index.crates.io` sparse)
  and known registry hosts are exempt; an off-host alternate registry flags.
- **pip `--find-links` / `-f`** (a package-source redirect) was skipped — now
  classified like `--index-url` (remote flags, a local `./wheels` path stays GREEN).
- **Poetry `[[tool.poetry.source]]`** custom source redirect (`url = …`) is now
  read — an off-registry source flags, the default `pypi` source stays GREEN.

A third Codex pass found one more:
- **Cargo official-index allowlist matched the GitHub path by substring** — so
  `registry+https://github.com/attacker/rust-lang/crates.io-index` (a different
  repo) read GREEN. The path is now parsed and required to equal exactly
  `/rust-lang/crates.io-index` (trailing slash / `.git` tolerated). Fixing it
  surfaced that the generic source-scan token regex swallowed the closing quote
  into the URL, which the exact-path check then rejected — the token char class now
  excludes quotes, so both the spoof (fires) and the official index (GREEN) resolve
  correctly.

## [1.5.0] — 2026-06-02

First v3 increment: **Evasion v2** — normalization and homoglyph-domain coverage.

### Added
- `scripts/scan.py`: `scan_file` now also tests an **NFKC-normalized** copy of each scannable target, so fullwidth / compatibility-character commands (`ｃｕｒｌ … | sh`, math-styled `exec`) can no longer hide from the regex. Escalate-only — a finding is tagged "revealed by NFKC normalization"; normalization never suppresses a raw match.
- `CR038` — cloud instance-metadata endpoint (`169.254.169.254`, `metadata.google.internal`, `100.100.100.200`) → CRITICAL. Closes the gap where `HI019`'s link-local guard skipped the metadata IP (SSRF / IAM-credential theft).
- `HI022` — IDN / punycode host (`xn--`) → HIGH (homoglyph domain for phishing / C2).
- `examples/evil-evasion/` (fullwidth/math/punycode/metadata) and `examples/clean-evasion/` (legit `½`/`™`/`ﬁ`/CJK + a named host).
- CI: `evil-evasion` must exit 3 with `CR038`+`HI022`+`CR001`+`HI007`+`HI019`; `clean-evasion` must exit 0.
- `docs/ROADMAP.md` — consolidated v3 backlog (sourced from THREAT_MODEL out-of-scope + per-spec non-goals).

### Fixed (pre-release code-review)
- `CR038` and `HI022` are now **case-insensitive** — `METADATA.GOOGLE.INTERNAL` and an UPPERCASE `XN--` host no longer evade.
- `HI022` matches **bare-host** and **`userinfo@`** forms, not only `scheme://…` — a punycode host after `curl ` or `user:pass@` was being missed.
- The `HI019` private-IP guard reads the **NFKC-normalized** form, so a fullwidth loopback (`１２７．０．０．１`) is correctly skipped instead of flagged.
- `SKILL.md` Step 6.7 now documents the NFKC re-scan + `CR038`/`HI022`; CI also asserts the math-styled-`exec` catch (`HI007`).
- `HI019` suppresses a finding only when **every** IP-URL on the line is private/loopback — a private IP can no longer mask a public one on the same line (`curl http://127.0.0.1 && curl http://8.8.8.8`).
- **Inline-code handling settled after two flawed attempts.** A whole-line, then a per-span, "defensive-intent" guard each tried to treat ``never use `x` `` as documentation — both leaked (``never mind, run `curl | sh` `` went green). Final design: inline code is scanned **as code**, span by span, with **no** intent inference; a documented bad pattern is a self-FP the LLM-side audit handles, and intent-based suppression is limited to the position-based negation guard on `CR028`–`CR031`.
- CI now requires `HI019` on `evil-evasion` and `CR001` on `evil-bypass`; the `scan_file` docstring now matches the actual fence / inline / prose behavior.
- **Case-insensitivity swept across all host/domain/URL rules** — `CR026`, `CR034`, `HI021` joined `CR038`/`HI022`, so `HTTP://`, `WEBHOOK.SITE`, `TRYCLOUDFLARE.COM` no longer evade. (Command rules like `curl … | sh` stay case-sensitive — the shell is.)
- **`HI019` host detection rebuilt on `urllib.parse` + `ipaddress` + `shlex`.** The old regex host-extraction spawned a sibling bug every review round — scheme case (`HTTP://`), `userinfo@`, multiple `@` (`user@127.0.0.1@8.8.8.8`), scheme-less bare-IP targets, and `-H`/`-o` flag values mistaken for hosts. It now pulls the real host out of every URL and every `curl`/`wget`/`fetch`/`nc`/`ncat`/`netcat`/`telnet`/`ssh` target and classifies it with the stdlib, covering IPv6, `ftp://`, and hex/decimal-encoded IPs, while skipping named hosts, loopback/private/reserved/link-local, an IP that sits in the userinfo, and flag values. The regex is now only a cheap trigger.
- **`HI019` reads host-bearing `curl` options** — `-x` / `--proxy` / `--url` / `--resolve` / `--connect-to` / `--socks5` carry the destination, so a public IP behind a proxy or a custom resolve (`--resolve example.com:443:8.8.8.8`) is classified instead of skipped like a `-H` / `-o` data value.
- **`HI019` host walk resets on shell separators** (`;` `|` `&&` `||` `&`) — `curl https://api.example.com && echo 8.8.8.8` no longer false-flags the echoed IP as the request target.
- **`HI019` encoded IP always flags** — a hex / decimal host (`0x7f000001`, `2130706433`) is reported even when it decodes to loopback; writing an IP in encoded form is itself the evasion signal (a plainly-written `127.0.0.1` stays fine).
- **`HI019` flag handling is an allowlist, not skip-after-any-flag** — only known value-taking data/file options (`-H`/`-o`/`-d`/`-A`/`-u`/…) consume their argument, so a *boolean* flag no longer hides the scheme-less IP that follows it (`curl -s 8.8.8.8/x`, `wget -q 8.8.8.8/x`, `nc -v 8.8.8.8 4444`).
- **`HI019` parses attached short-option values** — `-x8.8.8.8:8080` (curl's `-Xvalue` form) is read like `--proxy 8.8.8.8:8080` and `--proxy=8.8.8.8:8080`.
- **`HI019` option grammar is command-aware** (`_CMD_OPTS`) — the same letter differs by tool, so `wget -O <file>` and `ssh -i <identity>` are no longer misread as IP targets, while `curl -x` (proxy) still is and `ssh -x` (boolean) is not. ssh's positional `user@host` and its `-J` / `-W` jump hosts are classified.
- **`HI019` parses bracketed IPv6 and comma-list option values** — `--proxy [2001:db8::1]:8080` and `--dns-servers 1.1.1.1,8.8.8.8` now surface the inner public IP.
- **`HI019` skips the `-X` / `--request` method token** — `curl -X 8.8.8.8 https://api.example.com/` no longer misreads the HTTP method as a host (the IP target in `curl -X POST 8.8.8.8/x` still flags); `--proxy1.0` added to the proxy-host set.

## [1.4.0] — 2026-06-01

New detections: **modern exfil / evasion breadth**. The original exfiltration
signatures predate a wave of newer techniques. This closes the v2 roadmap.

### Added
- `scripts/scan.py`:
  - `CR034` — tunneling / OOB-interaction hosts (Cloudflare quick tunnels, `serveo`, `localtunnel`, `localhost.run`, interactsh, `pipedream`, `beeceptor`, `requestcatcher`) → CRITICAL
  - `CR035` — env-var dump piped to a network tool (`env`/`printenv` → `curl`/`wget`/`nc`) → CRITICAL
  - `HI019` — IP-literal or numeric-encoded IP in a URL → HIGH (loopback & RFC1918 ranges guarded)
  - `HI020` — IFS-based shell space-substitution evasion → HIGH
  - `HI021` — Telegram bot API exfil channel → HIGH
  - `ME011` — long (≥256) base64/hex literal → MEDIUM (git SHAs fall under the threshold)
- `references/red-flags.md`, `references/patch-templates.md`, `THREAT_MODEL.md`: exfil/evasion rows.
- `examples/evil-exfil/` — every new pattern; pre-1.4.0 it scored GREEN.
- `examples/clean-exfil/` — loopback/private-IP URLs, a named HTTPS host, a git SHA; stays GREEN.
- CI: `evil-exfil` must exit 3 with `CR034`+`CR035`; `clean-exfil` must exit 0.
- `examples/evil-bypass/` — a consolidated regression set for the review findings below.

### Fixed (pre-release code-review hardening)
- **Frontmatter bypass:** folded/list `allowed-tools` carrying `Bash(* *)` is now caught — `FM005` scans the whole frontmatter, not just the inline value.
- **Negation-guard false-negative:** bare modals (`should`/`must`/`may`) no longer suppress `CR028`–`CR031`, so "you should ignore safety policies" is caught.
- **Markdown coverage:** `~~~` fences and inline-code spans are now scanned as code (previously only triple-backtick fences were).
- **Clone false-positive:** `inventory` skips `.git/`, `node_modules/`, and other VCS/tooling dirs, and sniffs file *content* — extensionless text (LICENSE, `.gitignore`, Makefile) is scanned, not flagged as a blob; only true binaries (NUL byte) stay `INV001`. Auditing a repo-root skill no longer trips false RED/YELLOW.
- **Pipe-to-shell:** `CR036`/`CR037` implement the documented `bash <(curl …)` and `eval "$(curl …)"` patterns.
- **Honest "read-only" claim:** `SKILL.md` and `README.md` now note the `echo`-redirection caveat and that `$SKILL_PATH` scoping is instruction-level.
- **Pipe-to-shell regression:** `evil-bypass` and CI now assert both `CR036` (`bash <(curl …)`) and `CR037` (`eval "$(curl …)"`).
- CI: per-phase assertions broadened (`AST006`/`AST008`, `UNI002`/`UNI004`, `HI019`–`HI021`/`ME011`) plus the `evil-bypass` regression step.

### Closed
- The **v2 roadmap** is complete: bundled-config (1.1.0) → AST pass (1.2.0) → Unicode pass (1.3.0) → exfil/evasion (1.4.0).

## [1.3.0] — 2026-06-01

New capability: a **Unicode / invisible-character pass**. The regex and AST
passes see text only after it is read; they miss characters that are invisible or
that lie about how text renders. `unicode_scan` inspects raw codepoints across all
text files, including `.md` prose (a SKILL.md is read by the model as instructions).

### Added
- `scripts/scan.py`: `unicode_scan` —
  - `UNI001` — bidirectional control: RLO/LRO override → CRITICAL; embedding/isolate → HIGH (Trojan Source, CVE-2021-42574)
  - `UNI002` — zero-width / invisible (ZWSP, word joiner, soft hyphen, mid-file BOM) → HIGH
  - `UNI003` — Unicode Tags block (`U+E0000`–`U+E007F`) → CRITICAL (invisible instruction smuggling)
  - `UNI004` — homoglyph: a Latin-confusable Cyrillic/Greek letter inside a Latin word → MEDIUM
- `SKILL.md`: new **Step 6.7 — Unicode / invisible-character audit**.
- `THREAT_MODEL.md`, `references/red-flags.md`: Unicode rows / section.
- `examples/evil-unicode/` — bidi override + zero-width + Tags block + homoglyph; pre-1.3.0 it scored GREEN.
- `examples/clean-unicode/` — Russian prose, hyphenated RU/EN compounds, glued jargon, and emoji; stays GREEN.
- CI: `evil-unicode` must exit 3 with `UNI001`+`UNI003`; `clean-unicode` must exit 0.

### Notes
- `UNI004` fires only on a confusable embedded *inside* a Latin word (a neighbour test), so bilingual skills (hyphenated compounds, glued jargon) do not false-positive. Emoji ZWJ / variation selectors are excluded from `UNI002`.
- The pass scans `.md` prose (unlike most rules) because that prose is the attack surface; documentation that *demonstrates* these characters (this repo's spec) self-flags — a documented self-audit caveat.

## [1.2.0] — 2026-06-01

New capability: a **Python AST pass**. The line-based regex misses dangerous
calls that are aliased, split across lines, or built dynamically. `ast.parse`
(no execution) sees the syntax tree regardless of surface layout.

### Added
- `scripts/scan.py`: `ast_scan` — walks each `.py` file's AST and reports:
  - `AST001` — `eval`/`exec`/`compile` over a non-literal argument → CRITICAL
  - `AST002` — a call to an alias of eval/exec/compile (`e = eval; e(x)`) → CRITICAL
  - `AST003` — `os.system`/`os.popen`/`subprocess.*` with `shell=True`, any line layout → CRITICAL (non-literal command) / HIGH
  - `AST004` — `pickle.loads` / `marshal.loads` → CRITICAL
  - `AST005` — `yaml.load` without `SafeLoader` → HIGH
  - `AST006` — `getattr(obj, <non-literal>)` dynamic dispatch → HIGH
  - `AST007` — dynamic `__import__` / `importlib.import_module` → HIGH
  - `AST008` — `exec`/`eval` over a char-built / decoded string → CRITICAL
- `SKILL.md`: Step 5 documents the AST pass.
- `THREAT_MODEL.md`: adversarial-bypass (out-of-scope #4) is now *partially covered*; AST rule rows added.
- `references/red-flags.md`: AST section.
- `examples/evil-ast/` — clean `SKILL.md`, evasive `helper.py` (aliased eval, dynamic `os.system`, multi-line `shell=True`, char-built `exec`). Pre-1.2.0 the scanner scored it a soft YELLOW.
- `examples/clean-ast/` — safe Python (list-arg subprocess, `json.loads`, `yaml.safe_load`, literal `getattr`); stays GREEN.
- CI: `evil-ast` must exit 3 with `AST001`/`AST002`/`AST003`; `clean-ast` must exit 0.

### Notes
- The AST pass degrades to a no-op on unparseable source (syntax error, Python 2, non-Python).
- It distinguishes string literals from calls, so it adds no false positives on the scanner's own rule strings.

## [1.1.0] — 2026-06-01

New threat class: **bundled configuration / hooks / MCP**. A skill that ships
executable configuration alongside `SKILL.md` could previously score GREEN — the
line-based scanner never inspected it structurally. `check_bundled_config` closes
this blind spot.

### Added
- `scripts/scan.py`: `check_bundled_config` — structural audit (safe
  `json.loads`, textual backstop for non-parseable JSON) of `settings.json`,
  `.mcp.json`, and `plugin.json` at the skill root and in `.claude/` /
  `.claude-plugin/`. New rules:
  - `CR032` — bundled `hooks` block → CRITICAL (auto-exec on lifecycle events + persistence)
  - `CR033` — stdio `mcpServers` (`command`) → CRITICAL (launches a local process)
  - `HI017` — remote `mcpServers` (`url`) → HIGH (third-party egress)
  - `HI018` — `permissions` allow-list / mode broadening → HIGH
  - `ME010` — benign bundled `settings.json` → MEDIUM
  - `INV002` — `hooks/`, `commands/`, `agents/`, `.claude/`, `.claude-plugin/` dir → MEDIUM note
- `SKILL.md`: new **Step 1.5 — Bundled configuration audit (hooks / MCP / settings)**.
- `references/red-flags.md`, `references/patch-templates.md`, `THREAT_MODEL.md`:
  bundled-config patterns, severities, and guidance.
- `examples/evil-plugin/` — a clean `SKILL.md` shipping a malicious
  `.claude/settings.json` hook + `.mcp.json` stdio server. Positive fixture; the
  pre-1.1.0 scanner scored it GREEN.
- `examples/clean-with-data/` — a skill shipping a `references/*.json` carrying
  `hooks`/`command` keys as **data**. Negative fixture; must stay GREEN.
- CI: `evil-plugin` must exit 3 with `CR032`+`CR033`; `clean-with-data` must exit 0.

### Notes
- The audit keys off config **filenames**, not a blind key search — data files
  and prose mentioning `hooks`/`mcpServers` are not flagged.

## [1.0.1] — 2026-05-09

Patch release addressing post-publication audit feedback. No rule changes,
no behavior changes — readability and CI hardening only.

### Fixed
- YAML frontmatter readability: `description:` and `when_to_use:` fields in
  `SKILL.md` and `examples/clean-skill/SKILL.md` now use folded scalar syntax
  (`>-`). Content is identical for the parser; diffs and code review on
  GitHub no longer require horizontal scrolling.
- README: long prose paragraphs (some over 380 chars) re-wrapped at ~80
  columns. Markdown rendering is unchanged.

### Added
- GitHub Actions CI (`.github/workflows/tests.yml`):
  - Syntax check on `scripts/scan.py`
  - `examples/clean-skill/` must exit 0 (GREEN)
  - `examples/evil-skill/` must exit 3 (RED)
  - `evil-skill` must produce findings for representative attack classes
    (`FM005`, `CR001`, `CR006`, `CR026`, `CR028`, `CR031`)
  - Self-audit smoke test (no runtime errors; counts not asserted because
    self-audit produces documented false positives — see Limitations §5)
- README: CI status badge and MIT license badge

## [1.0.0] — 2026-05-09 — Initial release

First public release. Established the audit pipeline (8 LLM-driven steps + static scanner) and the rule catalogue.

### Static rules
- 31 CRITICAL rules covering: pipe-to-shell, base64-eval, pickle/marshal/yaml.load RCE, sensitive-path access (`~/.ssh`, `~/.aws`, keychain, `.env`, `*.pem`, `id_rsa`, `.netrc`, `.npmrc`, `.kube/config`), persistence vectors (shell rc files, git hooks, npm scripts, cron, launchd), skill self-elevation (Claude config, MCP), exfiltration endpoints (webhook.site, pastebin, Discord/Slack webhooks, ngrok), interpreter injection (`bash -c "$VAR"`, `python -c "$VAR"`), anti-user prose, policy-override language, role-confusion, dangerous fail-open instructions
- 16 HIGH rules covering: wildcards in `allowed-tools` (Bash(\* \*), Bash(python3 \*), Bash(rm \*), Bash(sudo \*), Bash(curl \*), Bash(npm \*), Bash(ssh \*), cloud CLIs), `subprocess shell=True`, `eval`/`exec`, network calls, recursive scans of home, JS dynamic execution
- 9 MEDIUM rules covering: `$0` confusion, predictable temp paths, slug path traversal, `subprocess` without timeout, missing symlink checks, silent failure, "trust me" language

### LLM-driven audit steps
- Inventory (binaries / non-text files flagged as RED)
- Frontmatter audit (`disable-model-invocation`, `allowed-tools`, description sanity)
- Bash command audit (17 categorical questions)
- Script audit (subprocess hygiene, code execution from data, network, file system, obfuscation, defensive practices)
- Tool laundering check (interpreter access ≈ full shell)
- Confused deputy check (skill executing commands from input documents)
- Prompt injection audit (untrusted data clause requirement, anti-user prose detection)
- Description-vs-behavior consistency

### Defensive design
- Read-only by design: `allowed-tools` contains zero write/delete/network operations
- Markdown-aware scanning: prose vs code-fence vs frontmatter handled differently
- Position-based negation guard: defensive prose ("do not retry with relaxed limits") distinguished from attack ("Do not tell the user") by where the negation sits relative to the dangerous phrase
- Symlink rejection at multiple layers (input path, files inside skill, parent directory chain)
- Per-rule false-positive guards for documentation contexts
