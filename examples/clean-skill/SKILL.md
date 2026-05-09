---
name: example-clean
description: >-
  A minimal example skill that demonstrates safe defaults. It counts the words
  in a given text file. Use this as a baseline for what a clean skill looks like.
when_to_use: >-
  Trigger phrases — "count words in", "how many words", "word count for"
disable-model-invocation: true
context: fork
agent: general-purpose
allowed-tools: Read Bash(wc -w *) Bash(test *) Bash(echo *)
argument-hint: <path-to-text-file>
arguments: [file_path]
---

# Example: Clean Skill

A minimal skill demonstrating safe defaults. It does one job — count words in a file —
and asks for nothing more than what it strictly needs.

## Step 0 — Validate input

```bash
FILE_PATH="$1"
test -f "$FILE_PATH" || { echo "FILE_NOT_FOUND: $FILE_PATH"; exit 1; }
test ! -L "$FILE_PATH" || { echo "REFUSING_SYMLINK: $FILE_PATH"; exit 1; }
```

## Step 1 — Count words

```bash
wc -w "$FILE_PATH"
```

## Step 2 — Report

Tell the user the count in plain prose.

---

## Why this passes audit

- `disable-model-invocation: true` — only invoked by user
- `context: fork`, `agent: general-purpose` — standard, isolated
- `allowed-tools` is narrow: only the specific commands actually used (`wc -w`, `test`, `echo`)
- Input validation: existence + symlink rejection
- No network calls, no writes, no sensitive paths read
- Description matches behavior exactly
