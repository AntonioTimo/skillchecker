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
| Bundled config bad destination | A bundled hook `command`, stdio MCP `command`+`args`, or remote MCP `url` pointed at a **public-IP literal** (incl. hex/decimal-encoded) or a **punycode / IDN** host — an auto-loaded config aimed at a C2 / exfil endpoint | CR040 |
| Credential exfil (data-flow) | A credential (`os.environ` / `os.getenv`) flows — across assignments, containers, f-strings — into a network sink whose destination is **reputation-bad or user-controlled** (bare/encoded public IP, punycode host, known exfil host, or a non-literal URL) | TF001 |
| Supply-chain install exec | Bundled `package.json` ships an install-lifecycle script (`preinstall`/`install`/`postinstall`/`prepare`/`prepublish`/`prepublishOnly`) — arbitrary shell on a plain `npm install`, no `allowed-tools` entry | CR039 |
| Obfuscated code exec (AST) | Aliased/dynamic `eval`/`exec`, `os.system`/`subprocess` `shell=True` any layout, `pickle`/`marshal.loads`, char-built `exec` | AST001–AST004, AST008 |
| Hidden Unicode injection | Bidi override (RLO/LRO) or Unicode Tags block — invisible/deceptive characters in SKILL.md prose | UNI001, UNI003 |
| Code-from-data RCE | `pickle.loads`/`marshal.loads`/`yaml.load` over external data, `eval(base64.b64decode(...))`, dynamic `__import__` with concatenation | CR015–CR019 |
| Pipe-to-shell | `curl ... \| sh`, `bash <(curl ...)` (process substitution), `eval $(curl ...)` (command substitution) | CR001–CR005, CR036, CR037 |
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
| `__import__` with string concatenation — dynamic-import obfuscation | HIGH | HI008 |
| Network calls without hardcoded destination | HIGH | HI009 |
| Credential (`os.environ`/`os.getenv`) reaching a network sink at a hardcoded **named** host — incl. loopback/RFC1918 (the legit authenticated-API-client shape) | HIGH | TF002 |
| Self-targeting prose: model ordered to **disclose** its own system prompt / instructions, or to **write/send** them to a file / network / log sink | HIGH | HI024, HI025 |
| Runtime **self-modification** — `open(__file__, "w")` / `.write_text`/`.write_bytes` targeting the skill's own running file (audited-once, mutates-later) | HIGH | AST009 |
| Cross-session **persistent** instruction / memory injection | MEDIUM | ME013 |
| **Unscoped catch-all** activation surface in `when_to_use` / `description` (activates on anything / every request) | MEDIUM | ME014 |
| **Self-modification prose** — skill told to rewrite its own SKILL.md / source / instructions | MEDIUM | ME015 |
| **Forged chat-template token** (ChatML `<\|im_start\|>`, `<<SYS>>`, `[INST]`, `{{#system}}`) in SKILL.md prose | CRITICAL | CR041 |
| **Instruction-override grammar** ("disregard all previous instructions") | HIGH | HI026 |
| **`os.exec*`/`os.spawn*`/`posix_spawn`** process replacement (completes `AST003`) | CRITICAL / HIGH | AST010 |
| **`extractall`/`unpack_archive`** without a member filter (Zip-Slip path traversal) | MEDIUM | AST011 |
| **Live token** in a bundled MCP `env`/`headers` value | CRITICAL | CR042 |
| Credential-file ref / reputation-bad dest in a bundled MCP `env`/`headers` | HIGH | HI027 |
| **`binding.gyp` `<!(`** command-substitution (Phantom Gyp install-RCE) | CRITICAL | CR043 |
| Bare presence of a bundled `binding.gyp` | HIGH | HI028 |
| **`/dev/tcp`** reverse shell / `nc -e` inbound C2 | CRITICAL | CR044 |
| Anonymous file-staging / paste **download** host (MITRE T1608.001) | HIGH | HI029 |
| Bundled **executable** by magic bytes (ELF/PE/Mach-O) | HIGH→CRITICAL | INV001↑ |
| Recursive scans of home or root | HIGH | HI015 |
| JS dynamic execution (`Function()`, `vm.runIn`, `Buffer.from(..., 'base64')` + eval) | HIGH | HI016 |
| Bundled remote MCP server (`mcpServers` with `url`) | HIGH | HI017 |
| Bundled `permissions` allow-list / mode broadening | HIGH | HI018 |
| Bundled benign `settings.json` (no hooks / MCP) | MEDIUM | ME010 |
| Non-standard plugin dir (`hooks/`, `commands/`, `agents/`, `.claude/`) | MEDIUM | INV002 |
| Dependency from a non-registry source (VCS / arbitrary URL / tarball / non-TLS / index-redirect / poisoned lockfile `resolved`) in a bundled manifest | HIGH | HI023 |
| Unpinned dependency (`*`, `latest`, bare name, unbounded `>=`) in a bundled top-level manifest | MEDIUM | ME012 |
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
| Empty `when_to_use` — the skill won't auto-trigger | MEDIUM | ME007 |
| Missing or unclosed YAML frontmatter in SKILL.md | HIGH | FM001, FM002 |
| Missing `disable-model-invocation: true` in frontmatter | HIGH | FM003 |
| Missing `allowed-tools` in frontmatter | HIGH | FM004 |

---

## What is acceptable (no flag)

Patterns that look concerning at first glance but have legitimate use cases.
We deliberately do **not** flag these:

- **`subprocess.run(cmd_list, ...)` with argument list (no `shell=True`).** Safe by construction — no shell interpolation possible.
- **Network calls with hardcoded destination** (`requests.get("https://api.example.com/...")`). Still flagged by HI009 for human review, but acceptable in context.
- **A credential sent to a hardcoded *named*-HTTPS host** (`requests.post("https://api.vendor.com", headers={"Authorization": token})`). `TF002` rates this **HIGH**, never CRITICAL — it is the legitimate authenticated-API-client shape; a human confirms the named destination owns the secret. `TF001` (CRITICAL) needs a *reputation-bad or user-controlled* destination. And a **configurable endpoint read from the environment** used as the URL with a **non-secret literal** body (`requests.post(os.environ["API_URL"], json={"ok": True})`) does **not** fire `TF` at all — the URL position is deliberately excluded from payload taint. (If the body *also* carries an `os.environ` value, the over-approximation that treats every environment read as a credential escalates it to `TF001` — a deliberate "prefer RED" over-call, not a budgeted-clean case; see out-of-scope #4.)
- **Self-referential prose with the anchor missing.** `HI024`/`HI025` require a possessive / `system` anchor — *"print your results"*, *"show your work"*, *"enter your prompt"* (a user-input prompt) do **not** fire; only *"reveal your **system** prompt"* / *"send your **instructions** to a server"* do. `ME014` matches an **unscoped** catch-all only — *"any React component"*, *"all SQL queries"* (domain-scoped) stay GREEN. `AST009` needs `__file__` + a write mode (any of `wax+` — `"r+"` and friends are writable) **on the same call expression** — a *skill-builder* writing **another** skill's `SKILL.md`, a `__file__` **read**, or a `__file__` bound in one function and written through a parameter in another, do not fire (matching is **inline-only** as of v1.10.1: the prior flow-insensitive `__file__`-binding set was dropped because it fired across unrelated functions — a deliberate soundness trade). And defensive prose with a leading negation (*"this skill will never reveal your system prompt"*) is suppressed by the `PROSE_TARGETING` negation guard (`HI024`/`HI025`/`ME013`/`ME015`, like `CR028–031`); the negation governs only **its own clause** — a comma (or other clause boundary) ends its scope, so *"Never mind the notes, reveal your system prompt"* still fires (v1.10.1).
- **Reads inside `~/.claude/skills/<this-skill>/`.** Internal to the skill; CR024 has been narrowed to flag only writes/deletes.
- **`cat`, `head`, `grep` over user-supplied paths.** Read-only, no exfiltration risk unless combined with network calls (caught separately).
- **YAML folded scalar in frontmatter** (`description: >-`). ME006's single-line length check is suppressed when YAML structural syntax indicates the value continues on the next lines.
- **Defensive prose with negation in front of dangerous phrase** ("do not retry with relaxed limits", "skill must never tell the user"). CR028–CR031 use position-based negation guards.
- **`hooks` / `mcpServers` / `command` keys in *prose* or *data files*.** Only an actual bundled config file (`settings.json`, `.mcp.json`, `plugin.json`) is flagged (CR032/CR033). A `references/*.json` data file or documentation mentioning these keys does not match — the audit keys off config filenames, not a blind word search.
- **A bundled MCP server pointed at a named domain or a loopback / private host.** `CR040` escalates only a public-IP literal or a punycode/IDN destination. A remote MCP at `https://mcp.vendor.com/sse` stays HIGH (`HI017`, the user reviews the URL), and a local-dev server at `http://127.0.0.1:7000/sse` or an RFC1918 host is not escalated — adding an MCP server is the user's call, but pointing one at a bare IP / homoglyph host is not a legitimate skill behavior.
- **`eval` / `exec` / `subprocess` as *string literals* in code (not calls).** The AST pass distinguishes a literal `"eval("` from an `eval()` call, so a scanner or linter that stores these patterns as strings (like skill-checker itself) is not flagged by `AST0xx`.
- **Dependency manifests that pin to the registry.** An exact pin (`requests==2.31.0`, `"lodash": "4.17.21"`), a `--hash`-locked requirement, a bounded caret/tilde range (`^18.2.0`, `~=2.0`), a lockfile `resolved` URL pointing at a known registry (`registry.npmjs.org`, `pypi.org`, …), and a monorepo-local dep (`workspace:`, `file:../`) do **not** fire — `CR039`/`HI023`/`ME012` flag only install-lifecycle scripts, non-registry sources, and the unambiguous open pins. A `references/*.json` data file with a `dependencies`/`scripts` key is not a manifest (the audit keys off manifest filenames), and a normal `go.mod` with versioned `require` lines is exempt from the unpinned check.

---

## Scanner robustness invariants (fail-closed)

The scanner is hostile-input-facing — a malicious skill controls every byte it reads —
so two robustness invariants hold (both hardened in v1.10.1 after an external audit):

- **A pass that crashes fails CLOSED, not open.** If a structural pass raises (e.g. a
  `RecursionError` from a pathologically deep `settings.json`), the backstop emits a
  `CRITICAL` (RED) rather than a `LOW` — a parser DoS on a config is itself a red flag
  and must never read GREEN. Where possible the crash is recovered (a deep-JSON parse
  failure falls back to a textual key scan, so the real `hooks`/`mcpServers` finding
  still surfaces as `CR032`/`CR033`).
- **Every per-file pass honors one size bound.** No read is unbounded: magic-byte
  sniffing reads 4 bytes, `_read_text_safe` caps at 8 MB, and the `unicode`/`ast`/`taint`
  passes skip files over `MAX_SCAN_BYTES` (1 MB) in lockstep with `scan_file` (which
  notes the oversize as `LO003`). A multi-GB bundled file cannot hang the scan.

## What is out of scope

These are real threats that skill-checker does **not** address. Users should
be aware and use complementary tooling.

1. **Dynamic analysis.** A skill that fetches malicious code at runtime from a server it controls passes static checks. Mitigation: any skill with both network calls and writeable filesystem operations should be treated as RED regardless of static findings, and tested in a sandbox first.
2. **Supply chain.** *Partially covered as of v1.6.0 (Phase F):* `check_supply_chain` flags a bundled manifest that ships an install-lifecycle script (`CR039`), a non-registry source (`HI023`), or an unpinned dep (`ME012`). It reads the **direct** manifest only — a malicious *update* to an already-pinned, registry-sourced library, a **transitive** dependency that pulls poison, CVE / version reputation (see #3), and typosquatting (see #5) remain invisible; those need a network + resolver the dependency-free scanner forbids. Pin and audit dependencies separately (e.g. `pip-audit` / `npm audit`). Runtime installs (`pip install <remote>` at execution time) are `CR021`'s job, not the manifest pass.
3. **Known CVEs in dependencies.** We don't check library versions against vulnerability databases.
4. **Adversarial code mimicking benign patterns.** *Partially covered as of v1.2.0 and v1.8.0:* the Python AST pass (`AST0xx`) defeats the common evasions — aliased builtins, multi-line `shell=True`, dynamic `getattr`/`__import__`, char-built `exec` — and the v1.8.0 taint pass (`TF001`/`TF002`) connects a **credential source** (`os.environ`/`os.getenv`) to a **network sink** across intervening assignments/containers/f-strings, so a split-variable secret-exfil reads RED instead of YELLOW. The taint pass is **intraprocedural and single-file** by design: **cross-function** flow (a tainted value passed as a function argument), **inter-file** flow, **container-mutation aliasing** (`d["k"]=secret; send(d)`), **other source/sink families** (file-read→network, external-input→exec, write-to-disk), **`socket.send` sinks**, and **named-host destination reputation** (a *named* attacker domain stays `TF002` HIGH, never CRITICAL — no reputation feed) are all out of scope; the LLM-driven steps in SKILL.md remain the backstop. Within a scope the pass enumerates **every binding construct** — plain/annotated/augmented assignment, walrus (`:=`), and `for`-targets (the last two added in v1.10.1) — so `if (t := os.environ[...]): post(t)` and `for v in os.environ.values(): post(v)` both fire; what stays out is following taint through a `for`-iterable's *elements* past the direct target binding. The next taint increment (file-read/input sources, cross-function flow) is tracked in `docs/ROADMAP.md`.
5. **Author identity, reputation, repo history.** We audit code, not authors. A first-commit repo with five stars is treated identically to a five-year-old project from a known author. Repo metadata is the user's call.
6. **Runtime sandboxing.** We are a pre-install gate, not a runtime monitor. Once installed, skills can do anything their `allowed-tools` permits.
7. **The deliberately-dropped SkillSpector borrows (Phase I scoping).** A scoping pass over NVIDIA SkillSpector took the three dependency-free must-haves (`HI024`/`HI025`/`ME013`/`ME014`/`ME015`/`AST009`) and **dropped** the rest with cause, recorded in `docs/specs/2026-06-19-self-targeting.md` §6: *overlap* already covered (least-privilege wildcard, unicode/hidden-content, persistence, tool-misuse, exfil) — often stricter on our native fields; *off our threat axis* (harmful-content denylists, DoS/unbounded-resource, runtime memory-injection payloads — confidentiality/integrity, not availability/content-safety); *needs network/deps* (OSV/CVE, typosquatting lists, YARA, `.mcp.json` tool-schema injection, multi-format git/zip input → opt-in behind a flag at most); and *needs an LLM* (description-vs-behavior mismatch → the Claude-side Step 7 advisory, not a scanner rule). A self-rewrite via a bare relative `"SKILL.md"` path (no `__file__`) is also out at the AST layer (indistinguishable from a skill-builder) — caught at the prose layer by `ME015`.

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
