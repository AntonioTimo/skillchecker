---
name: dep-manifest-clean
description: >-
  Ships hygienic dependency manifests — the negative test for the supply-chain
  rules (CR039 / HI023 / ME012). Everything here must stay GREEN.
when_to_use: >-
  Trigger phrases — "show pinned deps", "manifest hygiene example"
disable-model-invocation: true
context: fork
agent: general-purpose
allowed-tools: Read Bash(test *)
argument-hint: <none>
arguments: []
---

# Dep Manifest (clean)

## What it ships (every form the supply-chain rules must NOT flag)

- requirements.txt — exact `==` pins with `--hash`, all from the default
  registry. No non-registry source, no unpinned dep.
- package.json — an exact pin and a caret range (bounded = pinned-enough), two
  monorepo-local deps (`workspace:` / `file:`), and only build/test/ci scripts
  (no install-lifecycle script). The ci script string contains an install verb,
  but the rule keys off the script NAME, not the command text.
- package-lock.json — a real lock whose `resolved` points at
  `registry.npmjs.org` with a sha512 integrity hash (under the base64-blob
  threshold). A lock is never scanned for unpinned deps — it IS the pin.
- go.mod — normal versioned `require` lines with `github.com/...` module paths.
  A module path is not a non-registry URL; go.mod is exempt from unpinned checks.
- references/graph.json — a DATA file that happens to carry `dependencies` and
  `scripts` keys. The filename gate keeps it GREEN: only manifests named
  exactly are inspected, never an arbitrary `references/*.json`.

## Why this passes audit (negative test for the supply-chain rules)

- Registry-host allowlist: `registry.npmjs.org` / `pypi.org` sources are not a
  bypass, so lockfile `resolved` URLs and pinned registry deps stay GREEN.
- Local-vs-remote gate: `workspace:` / `file:../` are local, not remote.
- Bounded ranges (`^`, `~`, `==`, `--hash`) count as pinned — only `*` /
  `latest` / a bare name / an unbounded `>=` are unpinned.
- Filename gate: a data file under references/ is never read as a manifest.

Expected verdict: 🟢 GREEN, exit 0.
