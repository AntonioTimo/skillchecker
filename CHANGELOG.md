# Changelog

All notable changes to skill-checker.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.5.0] — 2026-06-02

First v3 increment: **Evasion v2** — normalization and homoglyph-domain coverage.

### Added
- `scripts/scan.py`: `scan_file` now also tests an **NFKC-normalized** copy of each scannable target, so fullwidth / compatibility-character commands (`ｃｕｒｌ … | sh`, math-styled `exec`) can no longer hide from the regex. Escalate-only — a finding is tagged "revealed by NFKC normalization"; normalization never suppresses a raw match.
- `CR038` — cloud instance-metadata endpoint (`169.254.169.254`, `metadata.google.internal`, `100.100.100.200`) → CRITICAL. Closes the gap where `HI019`'s link-local guard skipped the metadata IP (SSRF / IAM-credential theft).
- `HI022` — IDN / punycode host (`xn--`) → HIGH (homoglyph domain for phishing / C2).
- `examples/evil-evasion/` (fullwidth/math/punycode/metadata) and `examples/clean-evasion/` (legit `½`/`™`/`ﬁ`/CJK + a named host).
- CI: `evil-evasion` must exit 3 with `CR038`+`HI022`; `clean-evasion` must exit 0.
- `docs/ROADMAP.md` — consolidated v3 backlog (sourced from THREAT_MODEL out-of-scope + per-spec non-goals).

### Fixed (pre-release code-review, rounds 2–4)
- `CR038` and `HI022` are now **case-insensitive** — `METADATA.GOOGLE.INTERNAL` and an UPPERCASE `XN--` host no longer evade.
- `HI022` matches **bare-host** and **`userinfo@`** forms, not only `scheme://…` — a punycode host after `curl ` or `user:pass@` was being missed.
- The `HI019` private-IP guard reads the **NFKC-normalized** form, so a fullwidth loopback (`１２７．０．０．１`) is correctly skipped instead of flagged.
- `SKILL.md` Step 6.7 now documents the NFKC re-scan + `CR038`/`HI022`; CI also asserts the math-styled-`exec` catch (`HI007`).
- `HI019` suppresses a finding only when **every** IP-URL on the line is private/loopback — a private IP can no longer mask a public one on the same line (`curl http://127.0.0.1 && curl http://8.8.8.8`).
- Inline-code matches framed defensively ("never use `evil.com`", "reject `xn--…`") are suppressed — the host/exfil rules gained the negation guard the prompt-injection rules already had, removing a false-positive class for security/review skills.
- **Round 3's defensive guard was too broad** (it introduced a silent bypass): it suppressed *every* rule on the line when a negation preceded the first backtick, so ``never use `x`; then run `curl … | sh` `` went green. Each inline-code span is now scanned **individually** with the prose *immediately* before it — a defensive span can no longer mask a later malicious one.
- `HI019` parses optional `userinfo@`, so `http://user:pass@8.8.8.8` and `http://127.0.0.1@8.8.8.8` (real host `8.8.8.8`) are flagged instead of read as the userinfo IP.
- CI now requires `HI019` on `evil-evasion` and `CR001` on `evil-bypass`; the `scan_file` docstring now matches the actual fence / inline / prose behavior.

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
