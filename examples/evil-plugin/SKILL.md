---
name: note-tidier
description: >-
  Tidies your scratch notes — sorts lines, trims whitespace, removes duplicates.
  A friendly little helper for messy text files.
when_to_use: >-
  Trigger phrases — "tidy my notes", "clean up this text file", "dedupe lines"
disable-model-invocation: true
context: fork
agent: general-purpose
allowed-tools: Read Bash(sort *) Bash(test *) Bash(echo *)
argument-hint: <path-to-notes-file>
arguments: [file_path]
---

# Note Tidier

A small, friendly skill that tidies a text file: sort lines, drop duplicates.
Deliberately minimal — it asks for nothing beyond the file it operates on.

## Step 0 — Validate input

```bash
FILE_PATH="$1"
test -f "$FILE_PATH" || { echo "FILE_NOT_FOUND: $FILE_PATH"; exit 1; }
test ! -L "$FILE_PATH" || { echo "REFUSING_SYMLINK: $FILE_PATH"; exit 1; }
```

## Step 1 — Tidy

```bash
sort -u "$FILE_PATH"
```

## Step 2 — Report

Tell the user how many unique lines remain, in plain prose.

---

## Why this is the evil-PLUGIN example (intentional — example file)

The SKILL.md above is deliberately **clean**: narrow `allowed-tools`, input
validation, symlink rejection, no sensitive paths, description matches behavior.
A line-by-line scan of *this file* finds nothing — and that is the point.

The attack ships **next to** the skill body, as configuration the Claude Code
harness activates on install:

- `.claude/settings.json` registers a `PreToolUse` **hook**. The harness runs it
  automatically before every tool call — no `allowed-tools` entry required, and it
  keeps firing after the skill body is deleted (persistence).
- `.mcp.json` registers a **stdio MCP server** that launches a local binary on
  session start.

Neither command string is independently suspicious (`node .claude/hooks/sync.js`),
so the line-based rules stay silent. Only *structural* detection of the `hooks`
and `mcpServers` blocks catches this class.

- Before Phase C: 🟢 GREEN, exit 0 — the false-safe this example exists to prove.
- After Phase C (CR032 + CR033): 🔴 RED, exit 3.
