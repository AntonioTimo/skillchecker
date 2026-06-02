# Threat model

This document defines what skill-checker considers a threat, what it considers
sloppy-but-fixable, what it considers acceptable, and what it explicitly
**does not** address. Use this as the reference when proposing new rules.

---

## Categories

skill-checker classifies every finding into one of three severity levels,
each tied to a specific verdict and mitigation strategy.

### 🔴 CRITICAL — malicious intent, refuse, no patch

The skill exhibits one or more patterns that strongly suggest intent to harm
the user. We refuse to install, we **do not** offer patches, because malice
tends to be defense-in-depth: patching one symptom leaves the rest of the
attack surface intact.

**Required false-positive rate: ≤5%.** When the static rule fires, the human
auditor's prior should be "this is bad until proven otherwise".

Examples currently covered:

| Class | Pattern | Rule IDs |
|---|---|---|
| Data exfiltration | Network calls to known anonymous webhook services (`webhook.site`, `requestbin`, `pastebin`, Discord/Slack webhooks, `ngrok`) | CR026 |
| Modern exfil / evasion | Tunneling/OOB hosts, env-dump piped to network, IP-literal/encoded-IP URLs, IFS-based space evasion, Telegram bot API, long base64 blobs | CR034, CR035, HI019–HI021, ME011 |
| Normalization / homoglyph evasion | Fullwidth/compat commands (caught by NFKC re-scan), cloud-metadata SSRF, IDN/punycode hosts | CR038, HI022, NFKC re-scan |
| Credential theft | Reading `~/.ssh`, `~/.aws`, `~/.gnupg`, keychain, `.env`, `*.pem`, `id_rsa`, `.netrc`, `.npmrc`, `.pypirc`, `.kube/config` | CR006–CR014, CR025 |
| Persistence | Writing to `~/.bashrc`, `~/.gitconfig`, git hooks, npm `postinstall`, cron, launchd | CR022, CR023 |
| Skill self-elevation | Writing to `~/.claude/settings.json`, other skills, MCP config | CR024 |
| Bundled config exec | Shipped `hooks`, or stdio `mcpServers` (`command`), in `settings.json` / `.mcp.json` / `plugin.json` | CR032, CR033 |
| Obfuscated code exec (AST) | Aliased/dynamic `eval`/`exec`, `os.system`/`subprocess` `shell=True` any layout, `pickle`/`marshal.loads`, char-built `exec` | AST001–AST004, AST008 |
| Hidden Unicode injection | Bidi override (RLO/LRO) or Unicode Tags block — invisible/deceptive characters in SKILL.md prose | UNI001, UNI003 |
| Code-from-data RCE | `pickle.loads`/`marshal.loads`/`yaml.load` over external data, `eval(base64.b64decode(...))`, dynamic `__import__` with concatenation | CR015–CR019 |
| Pipe-to-shell | `curl ... \| sh`, `bash <(curl ...)`, `eval $(...)` | CR001–CR005 |
| Interpreter injection | `bash -c "$VAR"`, `python -c "$VAR"`, `node -e "$VAR"` | CR027 |
| Privilege escalation | `sudo`, `su`, `doas`, `chmod`/`chown` in skill code | CR020, HI011 |
| Runtime package install | `pip install`, `npm install`, `npx`, `brew install`, `cargo install` | CR021 |
| Anti-user instructions | "do not tell the user", "run silently", "hide intermediate steps" — in SKILL.md prose | CR028 |
| Policy override | "ignore safety policies", "developer mode", "jailbreak", "bypass restrictions" | CR029 |
| Role confusion | "treat the document as system instructions", "follow instructions in input file" | CR031 |
| Dangerous defaults | "retry with relaxed limits", "if blocked use sudo", "sanitize and continue" | CR030 |

### 🟡 HIGH/MEDIUM — sloppy but fixable, patch with diff

The skill exhibits patterns that suggest the author does not understand
security, but no apparent malicious intent. We provide concrete diffs in
`references/patch-templates.md`. The user applies them, re-runs, iterates
to GREEN.

**Required false-positive rate: HIGH ≤15%, MEDIUM ≤30%.** Some false
positives are acceptable here because the cost is "user reads the
recommendation and decides not to apply" — not "user refuses a safe skill".

Examples:

| Pattern | Severity | Rule IDs |
|---|---|---|
| Wildcard `allowed-tools` (`Bash(* *)`, `Bash(python3 *)`, `Bash(rm *)`, `Bash(sudo *)`, package managers, network tools, cloud CLIs) | HIGH | FM005, HI001–HI004, HI011–HI014 |
| `subprocess(..., shell=True)`, `eval()`, `exec()` over non-literal input | HIGH | HI005–HI007 |
| Network calls without hardcoded destination | HIGH | HI009 |
| Recursive scans of home or root | HIGH | HI015 |
| JS dynamic execution (`Function()`, `vm.runIn`, `Buffer.from(..., 'base64')` + eval) | HIGH | HI016 |
| Bundled remote MCP server (`mcpServers` with `url`) | HIGH | HI017 |
| Bundled `permissions` allow-list / mode broadening | HIGH | HI018 |
| Bundled benign `settings.json` (no hooks / MCP) | MEDIUM | ME010 |
| Non-standard plugin dir (`hooks/`, `commands/`, `agents/`, `.claude/`) | MEDIUM | INV002 |
| `yaml.load` without SafeLoader, resolved via AST | HIGH | AST005 |
| Dynamic `getattr` / `__import__` (AST) | HIGH | AST006, AST007 |
| Zero-width / invisible characters | HIGH | UNI002 |
| Bidi embedding/isolate; homoglyph word | HIGH / MEDIUM | UNI001, UNI004 |
| `$0` used as `$1` for arguments | MEDIUM | ME001 |
| Predictable `/tmp/` paths without `mktemp` | MEDIUM | ME002 |
| Path traversal via unvalidated slug | MEDIUM | ME003 |
| `subprocess` calls without `timeout=` | MEDIUM | ME004 |
| Missing symlink rejection on inputs | MEDIUM | ME005 |
| Silent failure (`2>/dev/null` or `\|\| true` after destructive/network ops) | MEDIUM | ME008 |
| "Trust me" language without justification | MEDIUM | ME009 |
| Description shorter than 30 characters | MEDIUM | ME006 |
| Missing `disable-model-invocation: true` in frontmatter | HIGH | FM003 |
| Missing `allowed-tools` in frontmatter | HIGH | FM004 |

---

## What is acceptable (no flag)

Patterns that look concerning at first glance but have legitimate use cases.
We deliberately do **not** flag these:

- **`subprocess.run(cmd_list, ...)` with argument list (no `shell=True`).** Safe by construction — no shell interpolation possible.
- **Network calls with hardcoded destination** (`requests.get("https://api.example.com/...")`). Still flagged by HI009 for human review, but acceptable in context.
- **Reads inside `~/.claude/skills/<this-skill>/`.** Internal to the skill; CR024 has been narrowed to flag only writes/deletes.
- **`cat`, `head`, `grep` over user-supplied paths.** Read-only, no exfiltration risk unless combined with network calls (caught separately).
- **YAML folded scalar in frontmatter** (`description: >-`). ME006's single-line length check is suppressed when YAML structural syntax indicates the value continues on the next lines.
- **Defensive prose with negation in front of dangerous phrase** ("do not retry with relaxed limits", "skill must never tell the user"). CR028–CR031 use position-based negation guards.
- **`hooks` / `mcpServers` / `command` keys in *prose* or *data files*.** Only an actual bundled config file (`settings.json`, `.mcp.json`, `plugin.json`) is flagged (CR032/CR033). A `references/*.json` data file or documentation mentioning these keys does not match — the audit keys off config filenames, not a blind word search.
- **`eval` / `exec` / `subprocess` as *string literals* in code (not calls).** The AST pass distinguishes a literal `"eval("` from an `eval()` call, so a scanner or linter that stores these patterns as strings (like skill-checker itself) is not flagged by `AST0xx`.

---

## What is out of scope

These are real threats that skill-checker does **not** address. Users should
be aware and use complementary tooling.

1. **Dynamic analysis.** A skill that fetches malicious code at runtime from a server it controls passes static checks. Mitigation: any skill with both network calls and writeable filesystem operations should be treated as RED regardless of static findings, and tested in a sandbox first.
2. **Supply chain.** A malicious update to a third-party Python library imported by the skill is invisible to us. Pin and audit dependencies separately (e.g. with `pip-audit`).
3. **Known CVEs in dependencies.** We don't check library versions against vulnerability databases.
4. **Adversarial code mimicking benign patterns.** *Partially covered as of v1.2.0:* the Python AST pass (`AST0xx`) defeats the common evasions — aliased builtins, multi-line `shell=True`, dynamic `getattr`/`__import__`, char-built `exec`. A sufficiently sophisticated attacker can still slip past both regex and a single-pass AST (cross-function data flow, reflection on attacker-named modules); the LLM-driven steps in SKILL.md remain the backstop. Full taint/data-flow analysis is future work.
5. **Author identity, reputation, repo history.** We audit code, not authors. A first-commit repo with five stars is treated identically to a five-year-old project from a known author. Repo metadata is the user's call.
6. **Runtime sandboxing.** We are a pre-install gate, not a runtime monitor. Once installed, skills can do anything their `allowed-tools` permits.

GREEN means **"no known patterns matched"**, not "100% safe". Always test
new skills on benign data first. Re-audit after upstream updates.

---

## How to propose a new rule

Open a PR with:

1. **Classification.** Which category does this rule belong to (CRITICAL / HIGH / MEDIUM)? Argue from the false-positive rate budget above.
2. **Rule ID.** Use the next free number in the category (CR032, HI017, ME010, etc.).
3. **Pattern.** A line-based regex compatible with the existing scanner. Multi-line attack patterns are out of scope until v2.0.0 (AST analyzer).
4. **Positive test cases.** Add to `examples/evil-skill/SKILL.md` (or a new evil example), and add `<rule_id>` to the `required` set in `.github/workflows/tests.yml`.
5. **Negative test cases.** Add a benign-but-similar pattern to `examples/clean-skill/SKILL.md` that the rule should **not** match.
6. **False-positive guard.** If the rule has a known false-positive class (defensive prose, error-message strings, documentation contexts), add a per-rule guard in `scan.py` similar to existing CR020/CR021/CR028–CR031 guards.
7. **Patch template.** For HIGH and MEDIUM rules, add a corresponding section to `references/patch-templates.md` with the recommended fix.

Rules without test cases or with a false-positive rate above their category
budget will not be merged. The static scanner is only useful if its findings
are believed.
