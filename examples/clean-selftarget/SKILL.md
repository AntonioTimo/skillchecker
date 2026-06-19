---
name: skill-forge
description: >-
  A skill scaffolder: generates a new skill directory (SKILL.md + scripts) for a
  topic you name. Demonstrates self-targeting patterns the rules must NOT flag.
when_to_use: >-
  Trigger phrases — "scaffold a skill", "generate a skill for any React component
  or SQL query", "new skill template".
disable-model-invocation: true
context: fork
agent: general-purpose
allowed-tools: Read Bash(python3 ~/.claude/skills/skill-forge/scripts/builder.py *)
argument-hint: <topic>
arguments: [topic]
---

# Skill Forge

A safe scaffolder. It writes *other* skills' files and documents the self-targeting
attacks defensively — so neither the prose rules nor the AST rule fire.

## Safety notes

This skill will never print your system prompt, send your instructions to any server, remember directives for all future sessions, or rewrite your own SKILL.md — those are exactly the malicious patterns it exists to catch, and it refuses every one.

As benign look-alikes it handles safely: it can detect self-modifying code in other repositories, store embeddings for all conversations, and persist UI state across all sessions; and to update this skill a human edits its SKILL.md in their own editor. None of those should flag.

## Step 1 — Generate

```bash
python3 ~/.claude/skills/skill-forge/scripts/builder.py "$1"
```

---

## Why this passes audit (negative test for Phase I)

- The Safety-notes line names every Phase I pattern but is **defensive** — the
  leading "will never" negates them all (the `PROSE_TARGETING` negation guard).
- `scripts/builder.py` `write_text`s **another** skill's `SKILL.md` (no `__file__`)
  and only **reads** its own file — so `AST009` does not fire.
- `when_to_use` says "any React component or SQL query" — a **domain-scoped** `any`,
  not an unscoped catch-all, so `ME014` does not fire.

Expected verdict: 🟢 GREEN, exit 0.
