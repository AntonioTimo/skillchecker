---
name: unit-formatter
description: >-
  Formats measurements and prices with proper Unicode symbols. Benign — a
  negative test for the NFKC normalization pass.
when_to_use: >-
  Trigger phrases — "format units", "pretty print measurements"
disable-model-invocation: true
context: fork
agent: general-purpose
allowed-tools: Read Bash(test *) Bash(echo *)
argument-hint: <value>
arguments: [value]
---

# Unit Formatter

Legit compatibility characters that must NOT trip the NFKC re-scan.

## Step 1 — Print a formatted line

```bash
echo "½ off — ™ brand — the ﬁ ligature — 設定ファイル"
```

Inline values: `api.example.com` (a named host), the price `¾ unit`, the `№ 5`.

## Why this passes audit (negative test for Evasion v2)

NFKC-normalizing these reveals **no** dangerous command — `½` → `1⁄2`, `™` → `TM`,
`ﬁ` → `fi`, CJK stays CJK. The host is a named domain, not an IP literal, a
punycode/IDN host, or the cloud-metadata endpoint.

Expected verdict: 🟢 GREEN, exit 0.
