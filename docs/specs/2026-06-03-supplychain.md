# Spec — Supply-chain (bundled dependency manifests) (Phase F)

- **Date:** 2026-06-03
- **Status:** Proposed (awaiting review)
- **Target version:** 1.6.0
- **Branch:** `feat/supplychain`
- **Phase:** F — the supply-chain increment. *Source: `THREAT_MODEL.md` out-of-scope #2/#3, `docs/ROADMAP.md` "New threat classes → Supply-chain".*

---

## 1. Problem

A skill ships dependency manifests (`package.json`, `requirements.txt`,
`pyproject.toml`, lockfiles, …). Today these are inventoried and *line*-scanned
via `_looks_like_text`, but the existing line rules need a runtime *verb*
(`CR021` matches `pip|npm … install`) or a public-IP literal (`HI019`). A bundled
manifest is a *declaration*, not a command — so the dangerous forms are **silent
today**. Verified empirically: a directory whose manifests contain a
`postinstall` script, a `git+https` dep, a bare `user/repo` shorthand, an
off-registry tarball URL, a `--extra-index-url`, and a `*` pin scores **zero
findings, exit 0** under the current scanner. That silent GREEN is the project's
stated worst failure (the false negative).

Three threat shapes, all bundled-manifest, all currently missed:

- **npm lifecycle install scripts** (`preinstall`/`install`/`postinstall`/
  `prepare`) in `package.json` — arbitrary shell on a plain `npm install`, no
  `allowed-tools` entry. Literal RCE-on-install, the static twin of a bundled
  hook (`CR032`).
- **Non-registry sources** — a dep pulled from VCS (`git+`/`hg+`/`svn+`/`bzr+`,
  `github:user/repo`, bare `user/repo`), an arbitrary URL/tarball/wheel, plain
  non-TLS `http://`, an index/source redirect (`--extra-index-url`,
  `verify_ssl=false`, Cargo `[source]`), or a poisoned lockfile `resolved`
  field — bypassing the registry's signing/audit, and (for git/tarball) running
  the fetched package's own build hooks at install.
- **Unpinned installs** — `*`, `latest`, a bare name, an unbounded `>=` — a
  future malicious release lands silently at the next install (the
  event-stream / xz pattern).

## 2. Approach

A new **structural pass**, not new line-regex rules — exactly the
`check_bundled_config` decision. The danger is the **presence** of a
source/script/open-pin inside a recognized **manifest file**, not a string that
can appear anywhere. Keying off manifest **filenames** is what keeps a
`references/*.json` data file with a `dependencies` key GREEN (the
`api-shapes.json` precedent) and keeps prose/fenced documentation GREEN by
construction.

New function `check_supply_chain(skill_root)` emits `Finding`s directly, called
from `main()` right after `check_bundled_config(skill_root)`. Parsing is
stdlib-only and **never executes** the file: `json.loads` for
`package.json`/JSON locks (reusing `_parse_json`/`_mentions_key`), a careful
**line-based, section-aware** parse for TOML/Pipfile/requirements/Gemfile/go.mod
(no `tomllib` — keep the existing 3.9 floor: no walrus, no `match`, no `tomllib`
in `scan.py`), and an indentation line scan for `environment.yml`/`yarn.lock`/
`pnpm-lock.yaml` (no `yaml.load`, which `CR017` itself bans). On parse failure
it degrades to a textual note (like `check_bundled_config`), never raising.

## 3. Rules

| Rule | Catches | Severity | Where |
|---|---|---|---|
| `CR039` | npm/yarn/pnpm install-lifecycle script (`preinstall`/`install`/`postinstall`/`prepare`/`prepublish`/`prepublishOnly`) in a bundled `package.json` — RCE on a plain `npm install` | CRITICAL | structural |
| `HI023` | dependency from a NON-registry source: VCS (`git+`/`hg+`/`svn+`/`bzr+`, `github:`/bare `user/repo`), arbitrary URL/tarball/wheel, non-TLS `http://`, index/source redirect (`--extra-index-url`/`--trusted-host`/`verify_ssl=false`/Cargo `[source]`/Gemfile non-default `source`), poisoned lockfile `resolved`, go.mod `replace => remote` | HIGH | structural |
| `ME012` | bundled top-level manifest ships UNPINNED deps — only the open forms (`*`, `latest`/`next`, `x`, bare name, unbounded `>=`/`>`) — aggregated one finding per manifest | MEDIUM | structural |

**Severity resolution (the one real conflict — argued from the FP budgets):**
`CR039` is **CRITICAL** because it is presence-based RCE-on-install with a
near-empty FP class once keyed to the lifecycle key set and the `package.json`
filename — a skill is `SKILL.md` + `scripts/` + `references/`, never an
`npm install`-ed package, so an install script is gratuitous (mirrors `CR032`
hooks). `HI023` is **HIGH, not CRITICAL** (the attacker lens's instinct), because
monorepo `file:`/internal-fork pins are legitimate-but-discouraged — the FP cost
is "read and decide", which fits HIGH ≤15%, not "refuse a safe skill"; and **3+
HIGH already routes to RED**, so a multi-dep evil manifest still escalates without
overclaiming on a single fork pin. `ME012` is **MEDIUM, open-forms-only**: caret/
tilde/bounded ranges are the npm/PEP440 default and ubiquitous in legitimate
skills — flagging them would blow the MEDIUM ≤30% budget and cause alarm fatigue
(the second-worst failure after the false negative), so they stay GREEN and only
the unambiguous open specifiers fire.

## 4. False-positive guards

- **Filename gate (master guard).** Candidates are collected strictly by basename
  against a fixed manifest-filename set (root + `scripts/`/`references/`/`assets/`,
  one level, symlinks skipped) — like `BUNDLED_*_NAMES`. A `references/graph.json`
  data file with a `dependencies`/`scripts` key, and any prose/fenced doc, stay
  GREEN because the pass never inspects them.
- **Registry-host allowlist.** A URL whose host is `pypi.org`,
  `files.pythonhosted.org`, `registry.npmjs.org`, `registry.yarnpkg.com`,
  `crates.io`, `rubygems.org`, `proxy.golang.org`, `conda.anaconda.org` (and
  mirrors) does **not** fire — so lockfile `resolved` URLs and
  `--index-url https://pypi.org/simple` stay GREEN.
- **Local-vs-remote gate.** `file:./`, `../`, `workspace:`, `link:`, `-e ./pkg`,
  `path="../x"`, `replace => ./local` are not remote bypass — excluded from
  `HI023` (keeps the CRITICAL/HIGH FP rate down on monorepos).
- **npm bare-shorthand guard.** `user/repo` fires only with exactly one `/`, no
  scheme, no leading `@`, left segment not in `{npm,file,link,workspace,portal}`,
  and not a semver range — so `^1.2.3`/`~2`/`1.x`/`*`/`latest` never match.
- **CR039 lifecycle-key keying.** Only `{preinstall,install,postinstall,prepare,
  prepublish,prepublishOnly}` with a non-empty string value fire; `build`/`test`/
  `ci`/`start`/`lint` never fire even if their command text contains
  `npm install`/`curl`. (`CR021`'s quote-prefix guard already keeps
  `"ci": "npm install …"` GREEN — verified.)
- **ME012 scoping.** Never on lockfiles or `go.mod` (pinned by construction);
  bounded ranges treated as pinned; `\`-continuation joined before classifying;
  one aggregated finding per manifest; a non-registry dep is `HI023` only, never
  also `ME012`.
- **Section-aware TOML.** `git=`/`url=` under `[project.urls]`/`[tool.poetry.urls]`/
  `[package.metadata]` (metadata) never fire; PEP 621 multiline `dependencies = [
  … ]` arrays are accumulated so a dep on a continuation line is not a silent
  miss.
- **No regressions.** `ME011` does not fire on lock integrity hashes (sha512 ~88,
  sha256 64-hex < 256 — confirmed); `HI019` co-fires only additively when a source
  host is a public IP literal (distinct rule_id, accepted).

## 5. Test plan (RED → GREEN → REFACTOR)

**RED.** `examples/evil-supplychain/` ships real manifests:
`package.json` (postinstall+preinstall, git dep, bare `user/repo`, off-registry
tarball, `*`/`latest`), `requirements.txt` (`git+https`, off-registry tarball,
`--extra-index-url`, non-TLS `http://`, bare `requests`), `pyproject.toml`
(`@ git+`, off-registry wheel, bare `chalk`), `yarn.lock` (`resolved` →
`attacker.test`), and `Cargo.toml` (a `[dependencies]` `git = …` source, with a
`[package]` `repository`/`homepage` metadata URL alongside that must *not* fire).
The current scanner misses all of it (verified: 0 findings).

**GREEN.** Add `check_supply_chain` → `CR039` + `HI023` + `ME012` fire → 🔴 RED,
exit 3.

**REFACTOR (negatives).** `examples/clean-supplychain/` must stay GREEN, exit 0:
pinned `requirements.txt` with `--hash`; `package.json` with an exact pin + caret
+ `workspace:`/`file:` local deps + only build/test/ci scripts; a
`package-lock.json` whose `resolved` points at `registry.npmjs.org` with a real
sha512 integrity; a `Cargo.toml` carrying only `[package]` metadata URLs
(`repository`/`homepage`/`documentation`) + registry deps; a normal `go.mod`
(versioned `require` github.com paths must not trip `HI023`; exempt from `ME012`);
and `references/graph.json` — a data file with `dependencies`/`scripts` keys that
the filename gate keeps GREEN.

**CI.** `evil-supplychain` must exit 3 with `{CR039, HI023, ME012}` present;
`clean-supplychain` must exit 0. Wired into `.github/workflows/tests.yml`
mirroring the `evil-exfil`/`clean-exfil` blocks.

## 6. Out of scope (residual, after Phase F)

Phase F narrows `THREAT_MODEL.md` out-of-scope #2 to "partially covered". It does
**not** address, and these remain another tool's / the user's job:

1. **Transitive dependencies.** We read the direct manifest only — a clean direct
   manifest whose registry deps pull poison is invisible (full resolution needs a
   network + resolver the dependency-free scanner forbids).
2. **Malicious update to an already-pinned, registry-sourced library.** A
   `requests==2.31.0` pin looks identical before and after upstream is
   compromised — THREAT_MODEL #1 (dynamic) / #3 (CVE) territory; use `pip-audit`.
3. **Version reputation / known CVEs** (#3) and **typosquatting / package-name
   reputation** (#5) — deliberately the user's call.
4. **Runtime fetches** — `pip install`/`npm install <remote>` *at execution time*
   is `CR021`'s job (a runtime verb), complementary to this manifest pass.
5. **Exotic manifests** outside the v1.6.0 filename set (composer.json, gradle,
   Podfile, `bun.lockb` — binary, trips `INV001` anyway).
6. **Caret/tilde tolerance** — a `^1` that resolves to a future malicious minor is
   not flagged: a conscious FP-budget trade (caret is the npm default), justified
   because the unambiguous open forms are caught and the malice weight sits on
   `CR039`/`HI023`.

## 7. Versioning

New detections (a new structural pass + three rules) → **1.6.0**.
