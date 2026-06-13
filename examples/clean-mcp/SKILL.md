---
name: mcp-catalog-lookup
description: >-
  Looks up a known MCP server's transport and endpoint from a bundled reference
  catalogue, and explains in prose how the user would add it themselves. Pure
  read-only data lookup — it never registers anything.
when_to_use: >-
  Trigger phrases — "what's the endpoint for", "look up the mcp server", "how do
  I add the server"
disable-model-invocation: true
context: fork
agent: general-purpose
allowed-tools: Read Bash(test *) Bash(echo *)
argument-hint: <server-name>
arguments: [server]
---

# MCP Catalog Lookup

Reads a bundled JSON catalogue of known MCP servers and reports the transport and
endpoint for the server the user names. The catalogue is **data** — the skill
never registers a server, never ships a hook, and never writes any config. It
only describes, in plain prose, what the user would do.

## Step 0 — Validate input

```bash
SERVER="$1"
test -n "$SERVER" || { echo "USAGE: provide a server name"; exit 1; }
```

## Step 1 — Look up

Read `references/mcp-catalog.json`, find the entry whose name matches the server,
and report its transport and endpoint in plain prose. Then remind the user that
adding an MCP server is **their** decision: they edit their own configuration
after reviewing the endpoint, and a skill should never register a server, a hook,
or a command on their behalf.

---

## Why this passes audit (negative test for MCP destination detection)

This skill ships a JSON file (`references/mcp-catalog.json`) that legitimately
contains fields named `mcpServers`, `url`, and `command` — as **catalogue data**,
not as Claude Code configuration. The bundled-config audit (and the `CR040`
destination-reputation check that rides on it) keys off real config **filenames**
(`settings.json`, `.mcp.json`, `plugin.json`), not a blind search for those keys,
so a reference data file with those keys does **not** trip
`CR032` / `CR033` / `HI017` / `CR040`. Every endpoint in the catalogue is a named
host, so no per-line host rule fires either.

Expected verdict: 🟢 GREEN, exit 0.
