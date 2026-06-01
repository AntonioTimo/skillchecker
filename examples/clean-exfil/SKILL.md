---
name: api-pinger
description: >-
  Pings a couple of known endpoints and reports status. Safe by construction —
  a negative test for the exfil/evasion rules.
when_to_use: >-
  Trigger phrases — "ping the api", "check status"
disable-model-invocation: true
context: fork
agent: general-purpose
allowed-tools: Read Bash(test *) Bash(echo *)
argument-hint: <none>
arguments: []
---

# API Pinger

## Step 1 — Ping (safe forms the exfil rules must NOT flag)

```bash
# local dev server — loopback / private IPs (guarded by HI019)
curl http://127.0.0.1:8080/health
curl http://192.168.1.10/health
# a hardcoded, trusted, NAMED host over HTTPS (not an IP literal)
curl https://api.github.com/zen
# a pinned git commit SHA (40 hex chars — under ME011's 256-char threshold):
# a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0
```

## Why this passes audit (negative test for the exfil/evasion rules)

- `http://127.0.0.1` and `http://192.168.1.10` are loopback / private IPs — the
  `HI019` guard skips them, so local-dev URLs don't fire.
- `https://api.github.com` is a named, trusted host, not an IP literal.
- the 40-char git SHA is well under `ME011`'s 256-char threshold.
- there is no tunneling host, no `env`-to-network pipe, no IFS evasion, no
  Telegram API.

Expected verdict: 🟢 GREEN, exit 0.
