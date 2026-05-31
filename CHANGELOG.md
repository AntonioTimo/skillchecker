# Changelog

All notable changes to skill-checker.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
