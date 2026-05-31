# Spec — Bundled config / hooks / MCP audit (Phase C)

- **Date:** 2026-06-01
- **Status:** Proposed (awaiting review)
- **Target version:** 1.1.0 (new threat class → minor bump)
- **Branch:** `feat/bundled-config-audit`
- **Phase:** C of the v2 plan (C → A → B → D). See "Roadmap context" below.

---

## 1. Problem

A Claude Code skill is *expected* to contain `SKILL.md`, optional `scripts/`, and
optional `references/`. Nothing stops an author from shipping **configuration
files that execute code or rewrite the user's environment**:

- `settings.json`, `settings.local.json`, `.claude/settings.json` — Claude Code
  settings that can carry a **`hooks`** block. Hooks are shell commands the
  harness runs **automatically** on lifecycle events (`PreToolUse`, `PostToolUse`,
  `UserPromptSubmit`, `Stop`, `SessionStart`, …). A bundled settings file with a
  hook is **automatic RCE + persistence** — it fires on events the user never
  associates with the skill, and it survives deleting the skill body. Crucially,
  **it needs nothing from `allowed-tools`.**
- `.mcp.json`, `mcp.json`, `.claude/mcp.json` — MCP server definitions. A
  stdio server (`command` + `args`) launches an arbitrary local binary; a remote
  server (`url`) ships data to a third party.
- `.claude-plugin/plugin.json` — a plugin manifest that can itself declare
  `hooks`, `mcpServers`, `commands`, and `agents`.
- Plugin directories: `hooks/`, `commands/`, `agents/`, `.claude/`,
  `.claude-plugin/`.

This is a *distinct* threat class from "a script that writes to `~/.claude/`"
(already covered by `CR024`). Here nothing is written at runtime — the malicious
capability is **shipped as a static file** and activated by the harness on
install.

## 2. The gap (current behavior)

`scan.py` treats `.json` as a text file and scans it **line by line** against
`ALL_RULES`. No rule targets a `hooks` / `mcpServers` / `PreToolUse` structure:

- `CR024` only matches `mcpServers` when preceded by a shell redirect
  (`>`, `>>`, `tee`, `cat >`) — i.e. a script *writing* config, not a static
  `.mcp.json`.
- `hooks`, `PreToolUse`, `command`/`args` keys appear in **no** rule.

Result: a skill that ships `.claude/settings.json` with a `PreToolUse` hook and a
`.mcp.json` stdio server produces **zero findings → 🟢 GREEN**. For a security
gate this is the worst possible failure — a confident false "safe". The RED
baseline test (§6) demonstrates this against the current scanner before any code
is written.

## 3. Goals / Non-goals

**Goals**
- Detect bundled config files by name and structurally classify what they carry.
- Treat shipped `hooks` and stdio `mcpServers` as CRITICAL (refuse).
- Keep the CRITICAL false-positive rate at ~0 (a real skill has no reason to ship
  these), within the THREAT_MODEL budget of ≤5%.
- Follow the existing contribution protocol (positive + negative fixtures, CI
  required set, patch templates, threat-model rows).

**Non-goals (YAGNI for Phase C)**
- No inspection of *what a hook command does* beyond "a hook exists" — presence
  is already disqualifying.
- No MCP server reputation / URL allow-listing.
- No AST analysis (Phase A) and no Unicode/bidi detection (Phase B).
- No change to the line-based engine for `.md`/`.py`/`.sh` files.

## 4. Detection design

New function in `scripts/scan.py`:

```
check_bundled_config(skill_root: Path) -> list[Finding]
```

Called from `main()` after `inventory()` and before/with the per-file pass. It
does **not** execute anything and **does not** follow symlinks (consistent with
the rest of the scanner).

### 4.1 Locate

Config files, by exact name, at skill root and one level into `.claude/` /
`.claude-plugin/`:

| File | Meaning |
|---|---|
| `settings.json`, `settings.local.json`, `.claude/settings.json`, `.claude/settings.local.json` | Claude Code settings (may carry `hooks`, `permissions`) |
| `.mcp.json`, `mcp.json`, `.claude/mcp.json` | MCP server definitions |
| `.claude-plugin/plugin.json`, `plugin.json` | Plugin manifest (may carry `hooks`, `mcpServers`, `commands`, `agents`) |

Also note the *presence* of directories `hooks/`, `commands/`, `agents/`,
`.claude/`, `.claude-plugin/` inside the skill (inventory-level signal).

### 4.2 Parse

1. `json.load` the file (safe — `json` does not execute code, unlike
   `pickle`/`yaml.load`).
2. If parsing fails (JSONC comments, trailing commas), fall back to a **regex
   backstop** scanning for the key tokens (`"hooks"`, `"mcpServers"`,
   `"PreToolUse"`, `"command"`). A backstop match still emits the finding, with
   `why` noting "could not parse as JSON; matched textually" so the human auditor
   knows confidence is lower.

### 4.3 Classify

| Condition in a bundled config | Rule | Severity | Rationale |
|---|---|---|---|
| `hooks` present with any entries (settings or plugin manifest) | `CR032` | CRITICAL | Auto-exec on lifecycle events + persistence; no legitimate reason for a skill to install hooks. FP ≈ 0. |
| `mcpServers` entry with `command`/`args` (stdio) | `CR033` | CRITICAL | Launches an arbitrary local binary as a server. FP ≈ 0. |
| `mcpServers` entry with only remote `url` (`type: http`/`sse`) | `HI017` | HIGH | Egress to a third party; may be legitimate but needs explicit user consent. |
| `permissions` block that **adds** allow-rules (`permissions.allow`, `defaultMode: bypassPermissions`/`acceptEdits`) | `HI018` | HIGH | Silent permission broadening — the skill widens what the harness will auto-approve. |
| Bundled settings with only benign keys (`model`, `theme`, `statusLine`, `env` without commands) | `ME010` | MEDIUM | A skill still should not rewrite the user's settings, but it is not RCE. |
| Presence of `hooks/`, `commands/`, `agents/`, `.claude/`, `.claude-plugin/` dirs | `INV002` | (note) | Non-standard layout; surfaced to the LLM-side review, not auto-blocking. |

Findings carry the real file path and (where the parse succeeded) the offending
key, so the Step-9 report can cite `settings.json` → `hooks.PreToolUse`.

### 4.4 Verdict mapping

Unchanged: any CRITICAL → 🔴 RED. `CR032`/`CR033` therefore push to RED on their
own, matching the philosophy that shipped auto-exec config is refuse-not-patch.
`HI017`/`HI018` follow the existing HIGH rules (patch, or RED if 3+ HIGH).

## 5. Documentation & rule-catalogue changes

- **`SKILL.md`** — new **"Step 1.5 — Bundled configuration audit (hooks / MCP /
  settings)"** between Inventory and Static scan: explains the threat, tells the
  auditor to read `check_bundled_config` findings, and adds the judgment call
  (an MCP `command` pointing at a script *inside* the skill is still RCE → refuse;
  a remote `url` is the user's call). Update the Step 1 "standard layout" note and
  the Limitations list.
- **`references/red-flags.md`** — new section "Bundled config / hooks / MCP" with
  the pattern→weight table.
- **`references/patch-templates.md`** — template for the HIGH cases: remove the
  bundled config; if the user genuinely wants the MCP server they add it
  themselves, explicitly. (No template for `CR032`/`CR033` — those are refuse.)
- **`THREAT_MODEL.md`** — add the new rule IDs to the CRITICAL/HIGH tables; add to
  "What is acceptable" that `hooks`/`mcpServers` named in *documentation prose* is
  fine — only an actual config file is flagged.
- **`CHANGELOG.md`** — `## [1.1.0]` — new threat class.

## 6. Test plan (RED → GREEN → REFACTOR)

Follows the THREAT_MODEL "How to propose a new rule" protocol and the
writing-skills Iron Law (watch it fail first).

**RED (baseline).** Add `examples/evil-plugin/`:
- `SKILL.md` — benign-looking summarizer description.
- `.claude/settings.json` — a `PreToolUse` hook running `curl … | sh`.
- `.mcp.json` — a stdio server (`command: node`, `args: ["evil.js"]`).

Run the **current** `scan.py` against it and record that it returns no findings
(GREEN). This is the failing test.

**GREEN.** Implement `check_bundled_config`. Re-run → `CR032` + `CR033` fire,
verdict 🔴 RED (exit 3).

**REFACTOR (close loopholes).**
- Negative fixture: a benign `.json` in `references/` containing a `"command"`
  key (e.g. a documented example) must **not** trip `CR033`; `red-flags.md`
  mentioning `hooks` in prose must **not** trip `CR032` (guaranteed because we key
  off real config files, not `.md`). Add to `examples/clean-skill/` or a new
  `examples/clean-with-data/`.
- Confirm `examples/clean-skill/` still exits 0.

**CI (`.github/workflows/tests.yml`).** Add `CR032`, `CR033` to the evil
`required` set; add an `evil-plugin must exit 3` step; keep the clean-skill
exit-0 step green.

## 7. Versioning

New detection capability, backward compatible → **1.1.0**. `CHANGELOG.md` entry
records the new rules and the new example.

## 8. Roadmap context

Phase C is the first of four v2 increments, each its own spec → plan → TDD cycle:

- **C (this spec)** — bundled config / hooks / MCP. Closes a complete blind spot.
- **A** — Python AST pass (`ast.parse`, no execution): catches aliased/obfuscated
  dangerous calls that line regex cannot see. The `THREAT_MODEL` "v2.0.0 AST
  analyzer" item.
- **B** — Unicode / bidi / zero-width / homoglyph detection in prose and code.
- **D** — exfil/evasion breadth (IP-literal URLs, tunneling hosts, `${IFS}`,
  `os.environ` dumps, entropy heuristic on long base64/hex blobs).

## 9. Open questions

- `examples/evil-plugin/` as a **separate** example vs. extending
  `examples/evil-skill/`. Recommendation: separate — keeps the existing evil-skill
  CI assertions stable and gives the new class a clean home.
- Whether `HI018` (permission broadening) lands in Phase C or defers to D.
  Recommendation: keep in C — it is the same "bundled settings.json" parse and
  cheap to add once the file is already loaded.
