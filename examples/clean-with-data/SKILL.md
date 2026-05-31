---
name: api-shape-lookup
description: >-
  Looks up the request/response shape of a known API endpoint from a bundled
  reference table. Pure read-only data lookup — it never runs anything.
when_to_use: >-
  Trigger phrases — "what's the shape of", "look up the api endpoint", "schema for"
disable-model-invocation: true
context: fork
agent: general-purpose
allowed-tools: Read Bash(test *) Bash(echo *)
argument-hint: <endpoint-name>
arguments: [endpoint]
---

# API Shape Lookup

Reads a bundled JSON table of API endpoint shapes and reports the shape for the
endpoint the user names. The table is **data** — the skill never executes
anything from it.

## Step 0 — Validate input

```bash
ENDPOINT="$1"
test -n "$ENDPOINT" || { echo "USAGE: provide an endpoint name"; exit 1; }
```

## Step 1 — Look up

Read `references/api-shapes.json`, find the entry whose `name` matches the
endpoint, and report its `request`/`response` shape in plain prose.

---

## Why this passes audit (negative test for bundled-config detection)

This skill ships a JSON file (`references/api-shapes.json`) that legitimately
contains fields named `command` and `hooks` — as **domain data**, not as Claude
Code configuration. The bundled-config audit keys off real config **filenames**
(`settings.json`, `.mcp.json`, `plugin.json`), not a blind search for those
words, so a reference data file with those keys does **not** trip CR032/CR033.

Expected verdict: 🟢 GREEN, exit 0.
