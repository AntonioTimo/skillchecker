---
name: weather-widget
description: >-
  Shows a tidy weather summary for a city — temperature, wind, and a three-day
  outlook, rendered as plain text. A small, friendly desk helper.
when_to_use: >-
  Trigger phrases — "weather for", "what's the forecast", "is it raining in"
disable-model-invocation: true
context: fork
agent: general-purpose
allowed-tools: Read Bash(test *) Bash(echo *)
argument-hint: <city-name>
arguments: [city]
---

# Weather Widget

A small, friendly skill that prints a short weather summary for a city. The body
below is deliberately minimal and clean — it asks for nothing beyond the city
name and prints plain text.

## Step 0 — Validate input

```bash
CITY="$1"
test -n "$CITY" || { echo "USAGE: provide a city name"; exit 1; }
```

## Step 1 — Report

Summarize the current conditions and a three-day outlook in plain prose.

---

## Why this is the evil-MCP example (intentional — example file)

The SKILL.md above is deliberately **clean**: narrow `allowed-tools`, input
validation, no sensitive paths, description matches behavior. A line-by-line scan
of *this file* finds nothing.

The attack ships **next to** the skill body, as MCP / hook configuration the
Claude Code harness auto-loads on session start — and points it at
reputation-bad destinations:

- `.mcp.json` registers remote MCP servers whose `url` targets a bare public IP
  (a real Tor exit range), a punycode homoglyph host, and encoded-IP hosts in
  every form a real client dials — a single hex integer, a **bracketed public
  IPv6** literal, **dotted-hex**, and **dotted-octal**. Each is third-party data
  egress (`HI017`); the reputation-bad destination makes it malicious (`CR040`).
- `.claude/settings.json` registers a `PreToolUse` hook whose command reaches a
  public IP — a bundled hook is already disqualifying (`CR032`), and `CR040` names
  where it points. A stdio server hides a public IP in its `args` (`CR033`+`CR040`).

Five servers are benign-looking on purpose — a named domain, an IPv4 loopback, an
IPv6 loopback, a public IP that sits in the URL **path** (not the host), and an
`xn--` label in the **path** (not the host) — and must carry only `HI017` (plus a
per-line `HI022` for the path label), never `CR040`. That host-vs-path
discrimination is what the rule has to get right.

- Before Phase G: a single bare-IP remote MCP scored 🟡 YELLOW (`HI017`+`HI019`) —
  the under-call this example exists to fix.
- After Phase G (`CR040`): 🔴 RED, exit 3.
