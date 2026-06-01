---
name: data-tools
description: >-
  A small, safe data helper — runs a fixed command, parses JSON, reads YAML
  safely. Demonstrates Python that the AST pass should NOT flag.
when_to_use: >-
  Trigger phrases — "list files", "parse this json", "read yaml config"
disable-model-invocation: true
context: fork
agent: general-purpose
allowed-tools: Read Bash(python3 ~/.claude/skills/data-tools/scripts/safe.py *) Bash(test *)
argument-hint: <path>
arguments: [path]
---

# Data Tools

A safe helper. Every potentially risky call is written the safe way, so neither
the regex pass nor the AST pass flags it.

## Step 0 — Validate

```bash
P="$1"
test -e "$P" || { echo "NOT_FOUND: $P"; exit 1; }
```

## Step 1 — Run

```bash
python3 ~/.claude/skills/data-tools/scripts/safe.py "$P"
```

---

## Why this passes audit (negative test for the AST pass)

`scripts/safe.py` uses the safe form of every pattern the AST pass watches:

- `subprocess.run(["ls", "-l"], timeout=10)` — argument list, no `shell=True`
- `json.loads(text)` — not `pickle` / `marshal`
- `yaml.safe_load(text)` — not `yaml.load`
- `getattr(obj, "name", None)` — a literal attribute, not dynamic dispatch

Expected verdict: 🟢 GREEN, exit 0.
