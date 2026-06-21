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
| Runtime **self-modification** — `open(__file__, "w")` / `.write_text`/`.write_bytes` / `os.open(__file__, O_WRONLY)` / `os.truncate(__file__)` / `fileinput(__file__, inplace=…)` / `os.replace`/`os.rename`/`os.symlink`/`os.link`/`shutil.copy*`(`…, __file__`) targeting the skill's own running file for a content rewrite or relink (audited-once, mutates-later). NOT the SOURCE-move forms (`os.rename(__file__, dst)` / `Path(__file__).rename/.replace(dst)` move the file away, a backup — GREEN, scoped to TARGET rewrite) | HIGH | AST009 |
| Cross-session **persistent** instruction / memory injection | MEDIUM | ME013 |
| **Unscoped catch-all** activation surface in `when_to_use` / `description` (activates on anything / every request) | MEDIUM | ME014 |
| **Self-modification prose** — skill told to rewrite its own SKILL.md / source / instructions | MEDIUM | ME015 |
| **Forged chat-template token** (ChatML `<\|im_start\|>`, `<<SYS>>`, `[INST]`, `{{#system}}`) in SKILL.md prose | CRITICAL | CR041 |
| **Instruction-override grammar** ("disregard all previous instructions") | HIGH | HI026 |
| **`os.exec*`/`os.spawn*`/`posix_spawn`** process replacement (completes `AST003`) | CRITICAL / HIGH | AST010 |
| **`extractall`/`unpack_archive`** without a member filter (Zip-Slip path traversal), incl. method-ref / import-alias / star-import indirection; exempt only on a provable guard — `filter="data"/"tar"` or `filter=tarfile.data_filter` (PEP 706), or a literal `members=[…]` (a variable / `getmembers()` is not a guard). `extractall` is gated on receiver **provenance** (v1.11.1): it fires only when the receiver provably resolves to a tarfile/zipfile archive object — `tarfile.open`/`TarFile`/`TarFile.open`/`gzopen`/`bz2open`/`xzopen`, `zipfile.ZipFile`/`PyZipFile`, via import/star/assignment alias — so pandas `Series.str.extractall` and any non-archive `.extractall()` stay GREEN; `shutil.unpack_archive` is unconditional (module-qualified). The archive provenance is a POSITION-AWARE, CONDITIONAL-aware per-scope timeline: a rebind after the use does not mask (`a=tarfile.open(p); a.extractall(); a=None` fires), an UNCONDITIONAL rebind before the use does (`a=tarfile.open(); a=Safe(); a.extractall()` GREEN), a SIBLING-branch rebind does not (`try: a=tarfile.open() except: a=None; a.extractall()` fires — the success path is live), the innermost scope decides (param shadow GREEN), and the archive may come from an `IfExp` arm, a `with`-as, or a list element (`for a in [tarfile.open(p)]` / `archives[0]`). Bare `.extract()` and an opaque-receiver `extractall` (archive from another fn/file) are OOS | MEDIUM | AST011 |
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
| Dependency from a non-registry source (VCS / arbitrary URL / tarball / non-TLS / poisoned lockfile `resolved`) in a bundled manifest, OR an off-registry **index redirect** in a bundled package-manager config — `.npmrc` / `.yarnrc` / `.yarnrc.yml` (`registry=` / `@scope:registry=` / `npmRegistryServer:` / `//host/:_authToken`), `pip.conf` / `pip.ini` (`index-url`/`extra-index-url`/`trusted-host`), `.cargo/config.toml` (`[source.*] registry`/`replace-with`), `.gemrc` (`:sources:`), or a `pyproject.toml` custom source (`[[tool.poetry.source]]`/`[[tool.uv.index]]`/`[[tool.pdm.source]]`) — the dependency-confusion vector (v1.11.1; localhost/loopback dev mirrors stay GREEN). The gate is a closed filename allowlist, so `.condarc`/`.bundle/config`/`nuget.config`/`composer.json`/`.gitconfig insteadOf`/Homebrew taps are NOT yet covered (a future increment) | HIGH | HI023 |
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
- **Self-referential prose with the anchor missing.** `HI024`/`HI025` require a possessive / `system` anchor — *"print your results"*, *"show your work"*, *"enter your prompt"* (a user-input prompt) do **not** fire; only *"reveal your **system** prompt"* / *"send your **instructions** to a server"* do. `ME014` matches an **unscoped** catch-all only — *"any React component"*, *"all SQL queries"* (domain-scoped) stay GREEN. `AST009` needs `__file__` + a write mode (any of `wax+` — `"r+"` is read-WRITE) reaching a write sink (`open`/`io.open`/aliased-`open`, `Path.open`, `.write_text`/`.write_bytes`, `os.replace`/`os.rename`/`shutil.copy*`, or low-level `os.open(__file__, O_WRONLY|…)`), where the target may be **`__file__`/`Path(__file__)` inline OR a local name that resolves to it** — same-scope assignment, walrus (`:=`), tuple-unpack, a transitive `q = p` chain, or `for p in [Path(__file__)]` / a comprehension all fire. Resolution is **per-scope and POSITION-AWARE** by `(lineno, col_offset)`: a name fires only while it IS `__file__` *at the write position* (so `p=__file__; p.write(); p=None` fires — incl. all three on ONE line, since the rebind is at a LATER column — but `p=Path(__file__); p=p.with_name(x); p.write()` does **not** — rebound to a sibling first), and a *same-named parameter* (or any non-`__file__` binding) MASKS an outer `__file__` binding, so a skill-builder's `def export(src, …): src.write_text(…)` with a module-level `src = Path(__file__)` does **not** fire; a *derived sibling* (`.with_name`/`.parent`/`os.path.dirname`) or a `__file__` **read** also stay GREEN. And defensive prose with a leading negation (*"this skill will never reveal your system prompt"*) is suppressed by the `PROSE_TARGETING` negation guard (`HI024`/`HI025`/`ME013`/`ME015`/`CR041`/`HI026`, like `CR028–031`) — but ONLY when the negation **adjacently governs** the match: there must be NO clause boundary between the negation and the dangerous verb, AND the gap must not be a polarity-INVERTING bridge. ANY clause boundary fires, decided by **Unicode property, NOT an enumerated codepoint or name list** (v1.11.1): ASCII clause punctuation `, . ; : ! ?`, and — the disease fix for the whole separator class — any char NOT in a small non-terminating set is a boundary. NON-terminating = a letter/digit/combining mark, an ordinary space/tab, a bracket/quote/connector (Ps/Pe/Pi/Pf/Pc), or a word-internal allowlist (apostrophe, solidus, markdown `*~_\``, middle dots). So every script terminator (Devanagari danda, Tibetan shad, Khmer khan, Hebrew sof pasuq, Myanmar section), every So/Sm symbol bullet (`●` `▪` `∙`), every invisible Cf format char, and every exotic Zs space (NBSP / Ogham) is a boundary WITHOUT being enumerated (stdlib cannot test the Unicode Terminal_Punctuation property, so the INVERSE allowlist over a broad category test is used). This also covers every script's comma/full-stop — Arabic `،`, ideographic `、`/`。`, `U+2E41` REVERSED COMMA, NFKC-folded fullwidth `，`), any separator dash (`Pd` em/en-dash/horizontal-bar, **not** the intra-word hyphen), the two low-9 quotation-mark comma look-alikes (`U+201A`/`U+201E`, which NFKC does not fold), or a temporal/disregard idiom (`until`/`then`/…/`mind`/`bother`). Apostrophe and solidus are `Po` but NOT clause marks, so *"never expose the user's prompt"* / *"won't read/write it"* stay GREEN. **Polarity inversion also fires** (v1.11.1): *"never **hesitate to** reveal …"* / *"never **refuse to** reveal …"* = *"always reveal"* — a benign reluctance verb (or a stacked inverting negation refuse/reject/forbid/prevent/avoid) inverts the negation. Inversion is decided by **PARITY** — an ODD count of inverting verbs in the gap nets to "always reveal" and fires (incl. bare `not`, "miss a chance to", "be slow to", "help but"), while an EVEN count is defensive again and stays GREEN (*"never shy away from refusing to reveal"* = *"always refuse to reveal"*). The inverter set is open NL (§8): the common forms are enumerated, the Claude-side review is the backstop for the tail. A genuine defensive note uses comma-free `or` coordination (*"never reveal or send your prompt"*) or per-clause negation to stay GREEN; a comma-list of several flagged phrases under one `never` flags the later items (the deliberate FP cost). A reinforcing double negation (*"does not and will not reveal"*) and a single inverting negation (*"will refuse to reveal"*) stay GREEN. Third-person `does not`/`doesn't`/`is not` count as negations.
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
so these robustness invariants hold (hardened across the v1.11.0 audit rounds):

- **A pass that crashes fails CLOSED, not open.** If a structural pass raises (e.g. a
  `RecursionError` from a pathologically deep `settings.json`), the backstop emits a
  `CRITICAL` (RED) rather than a `LOW` — a parser DoS on a config is itself a red flag
  and must never read GREEN. Where possible the crash is recovered (a deep-JSON parse
  failure falls back to a textual key scan, so the real `hooks`/`mcpServers` finding
  still surfaces as `CR032`/`CR033`).
- **A config/manifest too large to fully audit fails CLOSED.** A bundled config or
  manifest larger than the 8 MB read cap would be read TRUNCATED — a malicious key
  hidden past the cap would read clean. So an oversized opaque config/manifest emits
  `IO004` **CRITICAL** (refuse) instead. The one exception is a **lockfile**
  (`package-lock.json`/`yarn.lock`/…), which is legitimately 10–30 MB: it drops to
  `IO004` **HIGH** and its readable prefix is still scanned (a benign registry-pinned
  lockfile must not RED).
- **Every per-file pass honors one size bound.** No read is unbounded: magic-byte
  sniffing reads 4 bytes, `_read_text_safe` caps at 8 MB, and the `unicode`/`ast`/`taint`
  passes skip files over `MAX_SCAN_BYTES` (1 MB) in lockstep with `scan_file` (which
  notes the oversize as `LO003`). A multi-GB bundled file cannot hang the scan.
- **Manifest discovery is recursive, with no depth cap, and FAILS LOUD if truncated.**
  Dependency manifests are found at ANY depth in the skill tree (an `npm install`-time
  `postinstall`/`binding.gyp` activates wherever it sits — `src/`, `vendor/`, deeply
  nested `node_modules/`), keying off manifest FILENAMES so a `references/*.json` data
  file stays GREEN. The walk is bounded only by a total node cap (symlink- and
  `.git`-skipping, so no cycles); if that cap is hit (e.g. a directory flood), the audit
  emits a HIGH `IO004` "tree truncated — inspect by hand" — it never silently reads GREEN.
  The **file `inventory()`** walk is bounded by the same node cap and ALSO fails loud (`IO004`
  HIGH) when truncated, so a binary/symlink/script hidden past the cap can't read GREEN
  (round-4 audit: it used to drop them silently).
  Bundled **config** discovery (`settings.json`/`.mcp.json`/`plugin.json`) stays at the
  harness-honored locations (root / `.claude` / `.claude-plugin`) — a config the runtime
  never auto-loads is inert.

## What is out of scope

These are real threats that skill-checker does **not** address. Users should
be aware and use complementary tooling.

1. **Dynamic analysis.** A skill that fetches malicious code at runtime from a server it controls passes static checks. Mitigation: any skill with both network calls and writeable filesystem operations should be treated as RED regardless of static findings, and tested in a sandbox first.
2. **Supply chain.** *Partially covered as of v1.6.0 (Phase F):* `check_supply_chain` flags a bundled manifest that ships an install-lifecycle script (`CR039`), a non-registry source (`HI023`), or an unpinned dep (`ME012`). It reads the **direct** manifest only — a malicious *update* to an already-pinned, registry-sourced library, a **transitive** dependency that pulls poison, CVE / version reputation (see #3), and typosquatting (see #5) remain invisible; those need a network + resolver the dependency-free scanner forbids. Pin and audit dependencies separately (e.g. `pip-audit` / `npm audit`). Runtime installs (`pip install <remote>` at execution time) are `CR021`'s job, not the manifest pass.
3. **Known CVEs in dependencies.** We don't check library versions against vulnerability databases.
4. **Adversarial code mimicking benign patterns.** *Partially covered as of v1.2.0 and v1.8.0:* the Python AST pass (`AST0xx`) defeats the common evasions — aliased builtins, multi-line `shell=True`, dynamic `getattr`/`__import__`, char-built `exec`, and (v1.11.0) **import aliasing** (`import shutil as sh` / `from shutil import unpack_archive`, canonicalized through an import-map so *every* dotted-name rule resolves it), **star-import aliasing** (`from shutil import *` / `from os import *`, resolved for the finite dangerous-leaf set, v1.11.1), the **aliased `Path` constructor** for `AST009` (`from pathlib import Path as P`, v1.11.1), **ASSIGNMENT aliasing** of a callable OR module (`mv = os.replace` / `PP = pathlib.Path` / `from builtins import open as o` / `a = os; a.replace` / `o = getattr(builtins,"open")`, transitive + head-resolved, v1.11.1 — the sibling of import aliasing; a name bound by a LOCAL param/assignment MASKS a module import of the same name, so `def f(system): system(...)` is not read as `os.system`). **Every per-scope resolver is POSITION-AWARE** (resolved as of the call's `(lineno, col_offset)`): the `__file__` binding, the callable alias, the `AST011` archive-receiver provenance, the **`pathlib.Path` constructor alias** (`P=pathlib.Path; P(__file__); P=safe` flags; `from pathlib import Path as P; P=safe; P(__file__)` does not), and the **`extractall` method reference** (`ex=t.extractall; ex(); ex=safe` flags; `ex=safe; ex(); ex=t.extractall` does not). So a rebind masks a later use and a benign rebind un-masks. The shadow decision is uniform — driven by the innermost scope that binds the name AT OR BEFORE the call (a param, `for`-target, `AnnAssign`, or assignment all mask), so a FUTURE rebind never retroactively masks an earlier import-use (`from os import system; system(cmd); system=safe` still flags the call) and a param/`for`/`AnnAssign` named after a module masks just like an assignment. All four per-scope value-timelines cover the same binding FORMS in **lock-step** (v1.11.1 round 6): `Assign` with recursive matched-length tuple/list pairing (`runner, opts = os.system, {}` resolves `runner`), walrus, `AnnAssign` (a value (re)binds; a bare `mv: object` is a NO-OP that preserves the prior binding), `AugAssign` (reset), `for`-target (reset, or a `seq_alias`/`seq_ref` resolve of `for f in [os.system]: f(c)` / `for ex in [t.extractall]: ex()`), `with … as` (reset), and **`def`/`class NAME`** (a reset — it rebinds NAME in the enclosing scope; a `lambda` binds nothing) (v1.11.1 round 7). An **inline `getattr(os,"system")(…)`** dispatches like `os.system(…)` across every dotted rule, the archive-opener gate, AND the `pathlib.Path` ctor gate (`getattr(pathlib,"Path")(__file__)`) — but ONLY when the getattr head resolves to the BUILTIN getattr (`builtins.getattr` too; a locally-shadowed `getattr` param is inert), with the base resolved recursively. The `AST009` file-sink arms read the file argument **keyword-aware** (`open(file=__file__)`, `os.open(path=…)`, `os.truncate(path=…)`, `fileinput.input(files=…)`), as the dest-arm reads `dst=` (round 7). Flow-insensitivity is out only for CROSS-function/inter-file flow. Also **method-reference indirection** (`ex = t.extractall` / `getattr(t, "extractall")`) — and the v1.8.0 taint pass (`TF001`/`TF002`) connects a **credential source** (`os.environ`/`os.getenv`) to a **network sink** across intervening assignments/containers/f-strings, so a split-variable secret-exfil reads RED instead of YELLOW. The taint pass is **intraprocedural and single-file** by design: **cross-function** flow (a tainted value passed as a function argument), **inter-file** flow, **container-mutation aliasing** (`d["k"]=secret; send(d)` / `bag.append(secret)` — the always-firing `HI009` line rule, which now matches `httpx.<method>`/`aiohttp.<method>`, is the backstop here), **other source/sink families** (file-read→network, external-input→exec, write-to-disk), **`socket.send` sinks**, and **named-host destination reputation** (a *named* attacker domain stays `TF002` HIGH, never CRITICAL — no reputation feed) are all out of scope; the LLM-driven steps in SKILL.md remain the backstop. Within a scope the pass enumerates **every binding construct** — plain/annotated/augmented assignment, walrus (`:=`), `for`-targets, and comprehension generator targets (v1.11.0) — so `if (t := os.environ[...]): post(t)`, `for v in os.environ.values(): post(v)`, and `[post(v) for v in os.environ.values()]` all fire; what stays out is following taint through a container's *contents* past the direct binding. The next taint increment (file-read/input sources, cross-function flow) is tracked in `docs/ROADMAP.md`.
5. **Author identity, reputation, repo history.** We audit code, not authors. A first-commit repo with five stars is treated identically to a five-year-old project from a known author. Repo metadata is the user's call.
6. **Runtime sandboxing.** We are a pre-install gate, not a runtime monitor. Once installed, skills can do anything their `allowed-tools` permits.
7. **The deliberately-dropped SkillSpector borrows (Phase I scoping).** A scoping pass over NVIDIA SkillSpector took the three dependency-free must-haves (`HI024`/`HI025`/`ME013`/`ME014`/`ME015`/`AST009`) and **dropped** the rest with cause, recorded in `docs/specs/2026-06-19-self-targeting.md` §6: *overlap* already covered (least-privilege wildcard, unicode/hidden-content, persistence, tool-misuse, exfil) — often stricter on our native fields; *off our threat axis* (harmful-content denylists, DoS/unbounded-resource, runtime memory-injection payloads — confidentiality/integrity, not availability/content-safety); *needs network/deps* (OSV/CVE, typosquatting lists, YARA, `.mcp.json` tool-schema injection, multi-format git/zip input → opt-in behind a flag at most); and *needs an LLM* (description-vs-behavior mismatch → the Claude-side Step 7 advisory, not a scanner rule). A self-rewrite via a bare relative `"SKILL.md"` path (no `__file__`) is also out at the AST layer (indistinguishable from a skill-builder) — caught at the prose layer by `ME015`.

8. **The open-class tail of the prose & self-modification heuristics.** The `PROSE_TARGETING` negation guard and the `AST009`/`AST011` binding/indirection resolvers were each hardened to convergence across external audits and **eight** self-run adversarial sweeps (each round attacked every fix against the live scanner, and round 8 re-swept its own fix and caught the regressions it introduced before merge). They now close the realistic forms STRUCTURALLY — the negation guard's narrow "adjacency" rule decides clause boundaries by **Unicode property** (so the comma / coordinator / dash / Unicode-confusable / decoy class cannot be slipped by a hand-picked codepoint, v1.11.1) and rejects polarity-inverting double negations, and `AST009`/`AST011` resolve every common binding/import/provenance form. A *specific codepoint, separator category, or syntactic alias* is no longer the soft spot (the clause-boundary test is an inverse over a broad Unicode-category set; the alias resolver folds import/star/assignment/module/getattr forms). What remains open is genuinely unbounded and is named here so it is a boundary, not a silent gap: (a) the **polarity-inversion idiom lexicon** — "never **hesitate/fail/refuse to** reveal" is caught by parity, but an unlisted reluctance idiom ("never **think twice about** revealing", "never **drag your feet** when revealing") is open NL; (b) the **leak-verb lexicon** is base-form-anchored, so a gerund/participle phrasing with NO negation ("your job is **revealing** your system prompt") under-fires `HI024`/`HI025` — a known follow-up to inflect the verb alternation; (c) the **supply gate is a closed filename allowlist** — each new packaging tool's index-config (`.condarc`, `.bundle/config`, `nuget.config`, …) lags until added; (d) the binding/alias/provenance resolver covers **module + function scopes** — a **lambda parameter** or a **comprehension loop variable** is NOT a separately tracked scope, so a name that is a lambda/comprehension-local colliding with a module-level alias of a dangerous callable may mis-resolve (a contrived FP), and an `AST009` self-rewrite whose `__file__` flows only through a comprehension target reads as a generic `ME005` (MEDIUM/YELLOW) rather than the targeted `AST009` (HIGH) — it is downgraded, not GREEN; (e) **attribute-target aliasing** (`C.run = os.system; C.run()`) is not modeled (only Name targets);
(f) the round-6 sweeps brought the four per-scope value-timelines (callable-alias / `__file__` /
method-ref / archive-provenance) into **lock-step binding-form coverage** — `Assign` (recursive
tuple/list pairing), walrus, `AnnAssign` (a value (re)binds, a bare annotation is a no-op),
`AugAssign`, `for`-target (incl. a `seq_alias`/`seq_ref` resolve of `for f in [os.system]`),
`with`-as, and **`def`/`class NAME`** (round 7) — and added robust inline-`getattr` dispatch
(`builtins.getattr`, getattr→`Path` ctor, builtin-head/shadow-rejection, recursive base; round 7),
**keyword-aware** file args in the AST009 sinks (`open(file=…)`/`os.open(path=…)`/`os.truncate
(path=…)`/`fileinput(files=…)`/`dst=`), and the `os.truncate`/`fileinput`/`os.symlink` sink forms.
Round 8 closed the last finite binding forms: an **`except … as name` / `match`-case capture** masks
the name inside the block (the caught exception / matched sub-value, not a prior alias) via a
**block-scoped region overlay** (`_capture_masked`) the resolvers consult — leaving the timelines
untouched, so a post-block use on the fall-through path still fires (no FN) and an otherwise-unbound
captured builtin is not poisoned; **`import … as` / `from … import … as`** is now a binding form in
all four timelines (a prior local binding no longer masks a later import); and a **walrus call target**
(`(run := os.system)(…)`) resolves the walrus value as the callee.
The FINITE form space (binding forms incl. except/match/import-as, keyword args, alias/getattr/walrus
canonicalization, AND — v1.11.1 round 11 — **SET-valued unions**) is thus closed and fixture-guarded. A
callee that denotes a SET of possible callables (an `IfExp` arm, a literal-sequence element, a bound
name, a method-ref through them) is now resolved as that set: `_VF.members` holds the union and `_VF.seq`
is POSITIONAL, so the dispatch enumerates every member (a benign arm can NOT hide a dangerous one — the
`(math.sin if c else os.system)(cmd)` / self-file `open` / archive `.extractall` hidden-in-a-union FNs are
closed), a literal subscript HONORS its constant index (incl. negative — `(a, b)[1]` ≡ element `b`, even
through a Name-bound sequence), a dynamic index is CONSERVATIVE (fires if ANY element is dangerous — a
possible FP, never an FN), and a cross-rule union fires EVERY member's rule (`(os.system if c else
pickle.loads)(x)` → both AST003 and AST004), order-independent (the join is commutative / associative /
idempotent — its deduplication keys a nested union by its member SET, so even a union nested inside a
sequence `((a if … else b),)` retains every member regardless of arm order — v1.11.1 round 13). The set model is **CLOSED under every expression constructor** (v1.11.1 round 12): an
Attribute / getattr / Subscript DISTRIBUTES over the union members then joins (`(math if c else os).system`
→ {math.system, os.system}; a Subscript over a union of DIFFERENT-length sequences indexes each member
separately so none is hidden), the Path constructor preserves self-file provenance through a subscript
(`Path((__file__, x)[0]).write_text()`), an IfExp whose other arm is `__file__` no longer short-circuits to
self-file and DROP the dangerous arm (`(os.system if c else __file__)(cmd)` fires), a for-target unions
every element across all members, and a comprehension is an UNBOUNDED-length sequence (a constant index at
any position yields its representative). What remains open here is a **comprehension loop-variable** (its own
scope, not modeled — so `[g for g in (os.system,)][0]()` reads GREEN) and a **dict/set-literal subscript
callee** (`{0: os.system}[0]()` — only list/tuple carry a positional seq), both the obfuscation tail; plus
**cross-scope `nonlocal`**
writes propagated up to an enclosing scope,
**return-value modeling** (`importlib.import_module("os").system`, `functools.partial(os.system)`),
two **capture-mask edges** (a use INSIDE an `except`/`case` block AFTER an in-body reassignment of the
captured name to a dangerous value but BEFORE leaving the block — contrived, no evasion incentive since
a direct call fires; and cross-scope closure capture of an outer block's name), a **CLOSURE free
variable** read inside a nested function (its value at CALL time is interprocedural — no single textual
position resolves `def inner(): run(); inner(); run=os.system` (fire), `from os import popen; def f():
popen(); popen=print` (fire), and `op=os.system; def op(): …; def f(): op()` (GREEN) at once), and a
`global`-rebind made in a called function and observed at a MODULE-level call —
all value-flow / interprocedural, the same boundary as conditional-control-flow masking
(`if False: system=safe; system(cmd)` reads GREEN by latest-binding; the symmetric dangerous
`if c: runner=os.system; runner(cmd)` correctly fires) and mid-file re-import; `os.startfile` is
deliberately not in `AST010` (dual-use Windows open-with-default-app, predominantly a benign
document-open). But adversarial **natural language** (prose crafted to read defensive while injecting) and **arbitrary syntactic indirection** (a `__file__` or a method reference laundered through a dict/attribute/deeply-nested container, cross-function or inter-file flow) are **open classes** a dependency-free static heuristic cannot exhaustively decide. These are an accepted boundary, not a silent gap: the heuristics are advisory inputs, and the **Claude-side review steps in `SKILL.md`** (which read the whole skill in context) are the backstop for the long tail. The worst case — a *dangerous skill reading GREEN* — is mitigated by the breadth of the signal set (a real attack rarely appears as a single obfuscated form alone) plus that human/LLM review; the CI fixture corpus guards against regression (drift) on the forms already closed.

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
