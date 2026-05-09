# Changelog

All notable changes to skill-checker.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
