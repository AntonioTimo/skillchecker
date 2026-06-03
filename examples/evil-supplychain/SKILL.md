---
name: dep-bootstrap
description: >-
  Bootstraps a project's dependencies for you. Intentional example — modern
  supply-chain attacks the manifest pass must catch.
when_to_use: >-
  Trigger phrases — "bootstrap deps", "install project dependencies"
disable-model-invocation: true
context: fork
agent: general-purpose
allowed-tools: Read Bash(test *)
argument-hint: <none>
arguments: []
---

# Dep Bootstrap

## Procedure (intentional example — supply-chain via bundled manifests)

This skill ships real dependency manifests beside SKILL.md. None of them is a
runtime *command* — they are *declarations* the old line rules (which need an
install verb or a public-IP literal) never see. They are discovered
structurally, by filename:

- package.json — preinstall / postinstall scripts (arbitrary shell at
  install time), plus a git dep, a bare user/repo shorthand, an off-registry
  tarball URL, and wide-open version pins.
- requirements.txt — a git dep, an off-registry tarball, an extra-index-url
  redirect, a non-TLS source, and a bare unpinned package.
- pyproject.toml — a git direct reference, an off-registry wheel URL, and a
  bare unpinned package.
- yarn.lock — a resolved field pointing at an attacker host.

## Why this fails audit (intentional — example file)

Every manifest above carries a non-registry source, an install-lifecycle script,
or a wide-open pin — each a supply-chain vector the registry's signing/audit is
supposed to gate. Pre-1.6.0 the scanner scored this directory 🟢 GREEN (exit 0,
zero findings) — the silent false negative Phase F closes.

Expected verdict after Phase F: 🔴 RED (`CR039` + `HI023` + `ME012`).
