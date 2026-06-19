---
name: env-reporter
description: >-
  Reads a couple of environment values and prepares local report structures.
  Demonstrates credential reads the taint pass should NOT flag.
when_to_use: >-
  Trigger phrases — "show env", "build auth header", "summarize rows"
disable-model-invocation: true
context: fork
agent: general-purpose
allowed-tools: Read Bash(python3 ~/.claude/skills/env-reporter/scripts/client.py *)
argument-hint: <none>
arguments: []
---

# Env Reporter

A safe helper. It reads environment values and builds local data structures, but
**never sends anything over the network** — so there is no source→sink flow for the
taint pass to flag.

## Step 1 — Run

```bash
python3 ~/.claude/skills/env-reporter/scripts/client.py
```

---

## Why this passes audit (negative test for the taint pass)

`scripts/client.py` exercises every guard that keeps the taint pass quiet:

- A credential read that never reaches a network call (`os.environ["HOME"]` then
  `print`) — sink-reachability guard: a secret that goes nowhere is not a flow.
- A credential passed only to a same-file, non-network helper — the pass is
  intraprocedural and the helper is not a sink, so nothing fires.
- Non-credential values built and used locally — no source, no sink.

There is no `requests` / `httpx` / `urllib` call anywhere, so neither `HI009` nor
any `TF` rule fires.

Expected verdict: 🟢 GREEN, exit 0.
