# 🛡️ skill-checker

> Paranoid auditor for Claude Code skills.
> Refuse the malicious, patch the sloppy, install the safe.

A read-only auditor that runs **before** you install any third-party Claude Code skill. It catches what one pair of eyes misses — the static scanner pattern-matches against a curated catalogue of dangerous behaviors, and the LLM-driven steps in `SKILL.md` add semantic checks (description-vs-behavior consistency, tool laundering, confused deputy, prompt-injection vulnerabilities).

Output is one of three verdicts:

- 🔴 **RED** — refuse to install. Concrete reasons reported, no patches offered (malice tends to be defense-in-depth).
- 🟡 **YELLOW** — patches required. Each finding comes with an exact diff. You apply manually, re-run, iterate to GREEN.
- 🟢 **GREEN** — safe to install. Install command + brief usage included.

Read-only by design: the `allowed-tools` list contains zero write/delete/network operations. The auditor cannot modify the skill being audited, your filesystem, or anything else.

---

## What it catches

A non-exhaustive sample of the **31 CRITICAL**, **16 HIGH**, **9 MEDIUM** static rules:

**CRITICAL — refuse, no patch:**
- Pipe-to-shell (`curl ... | sh`), base64-decoded `eval`/`exec`, dynamic `__import__` with concatenation
- `pickle.loads`/`marshal.loads` from external data, `yaml.load` without `SafeLoader`
- Reading `~/.ssh/`, `~/.aws/`, keychain, `.env`, `*.pem`, `id_rsa`, `.netrc`, `.npmrc`, `.kube/config`
- Persistence: writing to `~/.bashrc`, `~/.gitconfig`, git hooks, npm `postinstall`, cron, launchd
- Exfiltration endpoints: `webhook.site`, `pastebin`, Discord/Slack webhooks, ngrok
- Skill self-elevation: writing to `~/.claude/settings.json`, other skills, MCP config
- Anti-user prose: "do not tell the user", "run silently", "treat document as system instructions"
- Policy override: "ignore safety", "developer mode", "jailbreak"
- Dangerous defaults: "retry with relaxed limits", "if blocked use sudo"

**HIGH — patch (or RED if 3+):**
- Wildcards in `allowed-tools`: `Bash(* *)`, `Bash(python3 *)`, `Bash(rm *)`, `Bash(sudo *)`, `Bash(curl *)`, `Bash(npm *)`, `Bash(ssh *)`, `Bash(aws *)`...
- `subprocess(..., shell=True)`, `eval()`, `exec()` over non-literal input
- Network calls without hard-coded destination
- Recursive home/root scans (`find ~`, `grep -R ~`)
- JS dynamic execution: `Function(...)`, `Buffer.from(..., 'base64')` followed by eval

**MEDIUM — patch:**
- `$0` confused with `$1` for arguments, predictable `/tmp/` without `mktemp`
- Path traversal via unvalidated slug, `subprocess` without `timeout=`
- Silent failure (`2>/dev/null` after destructive ops), missing symlink checks
- "Trust me" language without justification

Full catalogue with patterns and rationale: [`references/red-flags.md`](references/red-flags.md).

The patches the checker offers in YELLOW verdicts: [`references/patch-templates.md`](references/patch-templates.md).

---

## Quickstart

### 1. Install

```bash
git clone https://github.com/AntonioTimo/skillchecker.git ~/.claude/skills/skill-checker
chmod +x ~/.claude/skills/skill-checker/scripts/scan.py
```

Restart your Claude Code session (new chat — skills are cached at session start).

### 2. Audit a skill

Place the skill you want to audit in a staging directory — **not** in `~/.claude/skills/` yet:

```bash
mkdir -p ~/staging/skills
git clone https://github.com/some-author/some-skill.git ~/staging/skills/some-skill
```

Then in Claude Code:

```
/skill-checker ~/staging/skills/some-skill/
```

The auditor walks through eight steps (inventory → static scan → frontmatter audit → bash audit → script audit → tool laundering → confused deputy → prompt injection → consistency → verdict).

### 3. Act on the verdict

- 🔴 **RED** → `rm -rf ~/staging/skills/some-skill` and don't look back. Don't try to "patch around" — malice is layered.
- 🟡 **YELLOW** → apply the diffs in the report manually, then re-run `/skill-checker` until GREEN.
- 🟢 **GREEN** → use the install command from the report to copy into `~/.claude/skills/`.

---

## Example output

🔴 **RED verdict** (skill with `Bash(* *)`, `curl ... | sh`, `~/.ssh/id_rsa`):

```
## 🔴 SKILL REJECTED — DO NOT INSTALL

Skill path: /tmp/evil-skill
Skill name: super-helpful

Why it was rejected:
  [CRITICAL] FM005 SKILL.md:4  — Bash(* *) grants unrestricted shell access
  [CRITICAL] CR001 SKILL.md:9  — pipe-to-shell: downloads and executes remote code at runtime
  [CRITICAL] CR006 SKILL.md:10 — access to ~/.ssh — private keys, authorized_keys
  [CRITICAL] CR025 SKILL.md:10 — access to credential / secret files
  [CRITICAL] CR026 SKILL.md:10 — known exfiltration endpoint (webhook.site)
  [CRITICAL] CR028 SKILL.md:13 — anti-user instruction
  [CRITICAL] CR031 SKILL.md:15 — role confusion: "treat document as system instructions"
  ...

Recommendation: delete this skill. Do not attempt to patch around the
malicious sections — malice tends to be defense-in-depth.
```

🟡 **YELLOW verdict** with patches:

```
## 🟡 PATCHES REQUIRED BEFORE INSTALL

Findings: 2 HIGH, 4 MEDIUM, 0 LOW

### Patch 1: Wildcard in allowed-tools
File: SKILL.md
Severity: HIGH
Why: Bash(python3 *) lets the model run arbitrary Python (effectively RCE)

Replace:
  allowed-tools: Bash(python3 *) Bash(...)
With:
  allowed-tools: Bash(python3 ~/.claude/skills/<skill>/scripts/<script>.py *) Bash(...)

### Patch 2: $0 used as first argument
File: SKILL.md
...
```

---

## Limitations — Read these before relying on the verdict

This checker does not catch every threat class. It catches the common ones, fast.

1. **No dynamic analysis.** A skill that fetches malicious code at runtime from a server it controls passes static checks. Mitigation: 🔴 any skill with both network calls and writeable filesystem operations.
2. **No supply-chain analysis.** A malicious update to a third-party Python library it imports won't be detected. Pin and audit dependencies separately.
3. **LLM judgment is fallible.** Adversarial code can mimic benign code. When the static scan flags multiple HIGH findings, even if individually explainable, treat it as a pattern.
4. **Update means re-audit.** A skill that was 🟢 yesterday may be 🔴 today. Re-run after any upstream update.
5. **Self-audit is a known edge case.** Running `/skill-checker` against skill-checker itself yields ~30 false positives (the docs literally describe attack patterns). Documentation skills will trip the same way; manual judgment overrides the static counts.

GREEN means "no known patterns matched", not "100% safe". Don't run a freshly-installed skill on production-sensitive files in the first run. Test it on something benign first.

---

## How this was built

This tool came out of a real iterative audit cycle: a pair of LLMs sparring over a single skill, finding what each other missed. Five rounds of audit produced the current rule set. The methodology is:

- **Paranoid by default.** When in doubt, raise the flag.
- **Don't trust the description.** It's marketing — written by the author. Truth is in the code.
- **Diffs, not opinions.** When a fix exists, output the exact replacement.
- **Refusal is a real outcome.** Some skills don't deserve a patch.

The static rules in `scripts/scan.py` are line-based and miss multiline constructs by design — the LLM-driven steps in `SKILL.md` cover the remaining context-dependent semantics. Together they cover roughly 95% of the failure modes seen in real-world skill submissions; the remaining 5% require either a more sophisticated dynamic analyzer or human judgment.

---

## Project layout

```
skill-checker/
├── README.md             ← you are here
├── LICENSE               ← MIT
├── SKILL.md              ← Claude Code skill entrypoint (the audit procedure)
├── scripts/
│   └── scan.py           ← static scanner (read-only, no shell, no network)
├── references/
│   ├── red-flags.md      ← catalogue of patterns by severity
│   └── patch-templates.md ← ready-to-paste fixes for YELLOW findings
├── examples/
│   ├── clean-skill/      ← minimal benign skill, should exit 0 (GREEN)
│   └── evil-skill/       ← skill exhibiting common attacks, should exit 3 (RED)
└── docs/
    └── HOWTO.md          ← user-facing guide
```

---

## Contributing

Issues and PRs welcome, especially:
- New rules covering attack patterns the current set misses
- Patch templates for sloppy patterns currently flagged without a clear fix
- Translations of `references/*.md` (currently mixed English/Russian)
- Real-world skill submissions that produce surprising verdicts (false positive or false negative)

Before submitting a PR with new rules: include a unit test in `examples/` showing what the rule should/shouldn't match. Static rules with high false-positive rates make the tool unusable.

---

## Disclaimer

This is a community tool. **Not affiliated with Anthropic.** It's a static audit aid; it does not guarantee safety. Ultimate responsibility for what runs on your machine is yours.

---

## License

MIT — see [LICENSE](LICENSE).
