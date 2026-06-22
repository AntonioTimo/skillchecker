# Changelog

All notable changes to skill-checker.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.11.1] — 2026-06-22

**Convergence sweep — round 4 (two adversarial passes).** Self-run multi-agent adversarial
sweeps against the v1.11.0 scanner, then a re-verification pass that attacked every round-4
fix in turn, surfaced **20+ confirmed defects** (mostly false-**NEGATIVE** bypasses, plus
false-**POSITIVE**s). Each was reproduced against the live scanner *before* fixing
(RED→GREEN), fixed at the **disease class** rather than the reported instance, and locked
with a permanent fixture vector + a CI snippet assert. No new rule IDs — every fix hardens
an existing rule.

### Fixed — round-6: uniform binding-form coverage + sink-arm completeness (two more sweeps)

Two further adversarial sweeps (a finder pass + a confirmation pass that attacked the finder's
own fixes) found **17 bounded resolver gaps**, then **3 regressions/FPs the fixes themselves
introduced** — all reproduced against the live scanner, fixed at the disease class, locked with
fixtures + CI. Still no new rule IDs.

- **The four per-scope value-timelines now cover Python's binding forms in LOCK-STEP.** The
  round-4 flow-sensitivity work left the four timelines (callable-alias / `__file__` /
  method-ref / archive-provenance) with *checkered* form coverage, so a name rebound by a form
  one timeline forgot kept a stale binding: an `AnnAssign`-bound archive read GREEN (`arch:
  object = tarfile.open(p); arch.extractall()` — AST011 FN), a `with … as` rebind did not reset
  a callable alias (AST003 FP), a **tuple-unpack** alias was dropped (`runner, opts = os.system,
  {}` — AST003 FN), and an archive name rebound by a top-level `for`/`AnnAssign`/`AugAssign` kept
  firing (AST011 FPs). All four now handle the same set — `Assign` (recursive matched-length
  tuple/list pairing), walrus, `AnnAssign` (a value (re)binds; a **bare** annotation is a no-op
  that PRESERVES the prior binding), `AugAssign` (reset), `for`-target (reset, or seq-resolve),
  `with … as` (reset) — keyed off one documented invariant so a future form stays in sync.
- **`for f in [os.system]: f(cmd)`** (and `for ex in [t.extractall]: ex()`) now resolve the
  loop variable through a literal sequence to the dangerous callable / archive method-ref,
  mirroring the existing archive `seqarch` path → AST003 / AST011. An opaque iterable still
  resets the loop variable (the benign-reuse guard is preserved).
- **Inline `getattr(os,"system")(…)`** now dispatches like `os.system(…)` across every dotted
  rule AND the archive-opener gate (one `_func_canon` reconstructs `<base>.<literal>` from a
  getattr call used as a call's func) — only the *assigned* `fn = getattr(...)` form fired before.
- **New AST009 self-rewrite sink FORMS:** `os.truncate(__file__, …)` (in-place destroy),
  `fileinput.input/FileInput(__file__, inplace=…)` (stdlib in-place edit), and
  `os.symlink/os.link(src, __file__)` incl. the `dst=` keyword form (relink the running file).
  `Path(__file__).rename/.replace(dst)` is deliberately **NOT** flagged — like the already-GREEN
  `os.rename(__file__, dst)`, `__file__` there is the SOURCE moved away (a backup/relocation),
  not the inject TARGET; AST009 is scoped to CONTENT rewrite.
- **`os.startfile` reverted out of the os.exec family (AST010).** It is the Windows
  "open with the associated default app" call (double-click / xdg-open equivalent), a benign
  document-open idiom — classifying it as process-image replacement false-fired on
  `os.startfile("report.pdf")`.

The confirmation sweep also reconfirmed the documented **dataflow boundary** (left unfixed, by
design — they need a reaching-definitions / value-flow / interprocedural engine the heuristic is
not, with the Claude-side review as the backstop): conditional-control-flow masking
(`if False: system=safe; system(cmd)` — the *symmetric* dangerous `if c: runner=os.system;
runner(cmd)` correctly fires), mid-file re-import, cross-scope `nonlocal` writes, and
`importlib.import_module()` / `functools.partial` return-value modeling.

### Fixed — round-7: the last finite binding / keyword / getattr forms

A seventh sweep found three more bounded form gaps — all reproduced against the live scanner,
finishing the FINITE part of the form space (after these, the residual is the documented INFINITE
boundary: dynamic dispatch / NL prose / cross-function dataflow, with the Claude-side review as the
backstop). Still no new rule IDs.

- **`def NAME` / `class NAME` is a binding form** — it rebinds NAME in the enclosing scope, the
  one form missing from the lock-step set. `runner = os.system; def runner(): …; runner(c)` read
  RED (AST003 FP — the alias leaked because the def node was skipped wholesale), same for an
  archive name shadowed by a later `def`. All four timelines now record a `def`/`class` name as a
  reset before skipping its (nested-scope) body; a `lambda` binds no name.
- **Inline `getattr` is now robust.** `builtins.getattr(os,"system")(c)` (qualified head) and
  `getattr(pathlib,"Path")(__file__).write_text()` (a getattr→Path constructor → AST009) were
  missed; a **locally-shadowed** `def f(getattr): getattr(os,"system")(c)` false-fired AST003. One
  `_func_canon` now dispatches inline getattr ONLY when the head resolves to the **builtin** getattr
  (a shadowed `getattr` param is inert), resolves the base **recursively**, and feeds the Path-ctor
  / archive-opener gates too.
- **The AST009 file-sink arms read the file argument keyword-aware.** `open(file=__file__,
  mode="w")`, `io.open(file=__file__, …)`, `os.open(path=__file__, flags=os.O_WRONLY)`,
  `os.truncate(path=__file__)`, and `fileinput.input(files=__file__, inplace=True)` are valid Python
  the positional-only check read GREEN; each now resolves the file arg via `_arg_or_kw` (the
  dest-arm already did `dst=`). Read-mode keyword forms (`open(file=__file__)`) stay GREEN.
- **Confirmation sweep — the def/class reset must hold CROSS-scope.** The round-7 def-reset
  updated the per-scope timelines, but `_canon` for a call in a NESTED scope fell through to the
  flow-insensitive global alias map, which still held `runner → os.system` (and had no def/class
  reset) — so a benign dispatch module (`runner = os.system; def runner(c): …; def main():
  runner(…)`) read AST003, escalating to CRITICAL/RED with a non-literal arg. A name bound by a
  `def`/`class` is now dropped from that global map (it is a function/class, not a callable
  alias), so the per-scope reset is authoritative everywhere; the genuine cross-scope global-rebind
  (`x=None; … global x; x=os.system; x(c)`) and `def`-then-`x=os.system` still fire.

### Fixed — round-13: nested-union dedup key (Codex reject 3)

Codex found the one remaining hole in the set model's commutativity: `_vf_dedup_key` (which `_vf_join`
uses to deduplicate union members) recursed into a `_VF`'s positional `seq` elements but NOT into a nested
union's `members`. A `seq` element can itself be a union (`((x if a else y),)`), and two DIFFERENT inner
unions both summarize to `canon=None`, so their keys collided and `_vf_join` dropped one — so
`((math.sin if a else os.system),) if b else ((math.cos if c else pickle.loads),)` indexed `[0]` fired only
the first arm's rule, and swapping the arms changed the result (`AST003` ↔ `AST004`, non-commutative). The
key now includes the nested `members` as an order-independent FROZENSET, so a union-in-a-sequence retains
every member and arm/grouping order is immaterial (commutativity / associativity hold for nested unions
too). One-line change; golden byte-identical on the existing 23 fixtures; no new rule IDs.

### Fixed — round-12: set-model CLOSURE under expression constructors (Codex reject 2 + re-sweep)

Codex rejected round-11 again: the SET model was correct at the top level but NOT CLOSED under expression
CONSTRUCTORS — a union was lost the moment an Attribute / getattr / Subscript was applied on top, because
`_facts_of` / `eval_expr` read the SUMMARY of the base/value (`base.canon`, `v.seq`) instead of mapping
over the members. So `(math if c else os).system(cmd)` read GREEN (the Attribute saw the summary canon
None), a Subscript over a union of DIFFERENT-length sequences hid the dangerous element (the summary `seq`
is None when lengths disagree), and `_self_target` did not consult the unified resolver for a subscript
(`open((__file__, "safe")[0], "w")` read GREEN / a generic ME005).

The fix makes every constructor a HOMOMORPHISM over the union — it distributes over `_vf_members` then
joins: `_vf_attr` lifts attribute/getattr access (`(math if c else os).system` → the union {math.system,
os.system}); `_subscript_union` indexes each member's positional seq (a constant index per member, an
out-of-a-member's-range constant being that member's dead path); the Path constructor preserves self-file
provenance (`Path((__file__, x)[0]).write_text()`); and `_self_target` reads the final `self_file` fact
via `_facts_of`. An adversarial re-sweep then surfaced three more closure breaks, each fixed: (FN2, broad)
`_is_own_file_target` recursed an IfExp with OR and, as a top short-circuit, collapsed the WHOLE ternary to
self-file whenever EITHER arm was `__file__` — discarding the other arm — so `(os.system if c else
__file__)(cmd)` / `(tarfile.open(p) if c else __file__).extractall()` read GREEN; self-file now lifts
through the IfExp JOIN like every other domain. (FN3) the for-target bound the loop var from the scalar
summary `it.seq`, so a union of differing-length iterables lost a member; it now unions every element
across `_vf_members`. (FN1) a comprehension was modeled as a fixed length-1 representative, so a constant
index ≥ 1 was wrongly a dead path; a new `seq_open` flag marks an UNBOUNDED-length sequence (a
comprehension) whose subscript at ANY index yields the representative. Golden byte-identical on the existing
23 fixtures; no new rule IDs. The closure was validated by a constructor-closure matrix (Attribute /
getattr / Subscript / Path-ctor / IfExp-with-`__file__`-arm / for-target / comprehension over a union,
nested and across all four domains, plus a self-file regression battery). Remaining OOS unchanged
(value-flow / interproc; comprehension loop-variable scope; dict/set-literal subscript callee).

### Fixed — round-11: SET-valued union resolution (Codex reject of the round-10 `a or b` collapse)

Codex rejected the round-10 union handling: a callee that denotes a SET of possible callables — an
`IfExp` arm, a literal-sequence element, a bound name, a method-ref through them — was collapsed to a
single first-truthy / danger-preferred representative, so a **benign arm could hide a dangerous one**
(`(math.sin if c else os.system)(cmd)` read GREEN), a literal subscript **ignored its index** (both an
FN `(math.sin, os.system)[1]` and an FP `(os.system, math.sin)[1]`), and findings depended on arm ORDER
(not commutative). An adversarial re-sweep confirmed the class plus eleven siblings (self-file `open`/
`os.open`/`Path` ctor and archive `.extractall` hidden behind a benign union arm — the danger set was
incomplete AND a single canon can't carry a union).

The fix makes `_VF` REPRESENT THE SET: `members` (the union alternatives) + a POSITIONAL `seq` (tuple
of element facts, so `(a, b)[1]` selects exactly `b`). A single commutative / associative / idempotent
`_vf_join` builds unions; a unified visit-time `_facts_of` resolves any callee to its member set and the
dispatch enumerates them (firing every member's rule, deduplicated by rule_id) — so a benign member
never hides a dangerous one, a constant index (incl. negative) is honored positionally, a dynamic index
is conservative (fire if ANY element is dangerous), and a cross-rule union fires BOTH rules
(`(os.system if c else pickle.loads)(x)` → AST003 **and** AST004), order-independent. The five old
per-domain visit-time resolvers (`_func_canon` / `_func_attr` / `_method_ref_at` / `_name_archive_state`
/ `_is_archive_expr` / `_extractall_on_archive`) and the round-10 `_danger_pref` / `_canon_is_dangerous`
collapse helpers became dead and were DELETED — `_facts_of` + the build-time `eval_expr` are now the sole
binding/resolution source. Golden byte-identical on all 23 fixtures (the union changes are additive on
new forms); no new rule IDs. Remaining OOS (documented, value-flow / obfuscation tail): a closure
free-variable / `global`-rebind resolved at call time, a comprehension loop-variable (its own scope), and
a dict/set-literal subscript callee (not positional).

### Refactor — round-9: unified ValueFacts evaluator (single binding/resolution source)

The four per-scope timeline walkers (callable-alias / `__file__` / archive / method-ref) that the
H1–H7 sibling-bug cycle kept re-diverging were collapsed into ONE abstract interpreter over a single
value-facts type (`_VF`): one `eval_expr` / `bind_target` builds `{name: [(pos, _VF, cond)]}`, and
every resolver (`_canon` / `_self_target` / `_name_archive_state` / `_method_ref_at`) reads it. Done
incrementally (build parallel → differential against the old resolvers → switch domain-by-domain →
delete the old walkers), each step a commit gated by a golden-output baseline (`scripts/diff_baseline.py`).
The unified evaluator reached **zero differential divergence** across the whole corpus and the cutover is
byte-identical to the golden baseline — empirical equivalence on the (finite) corpus, not a formal proof.
Net ≈ −560 lines. A new binding-form × provenance × shadow/rebind/transitive/capture/walrus/cond
combination is now handled in ONE place, so the H1–H7 family is constructively unreachable. No rule IDs.

### Fixed — round-10: form-coverage hardening (pre-existing FNs surfaced by the round-9 sweep)

An adversarial sweep against the unified evaluator (162 constructions → 16 confirmed defects) was each
reproduced against BOTH the old (pre-cutover) and new scanner: **all 16 produced identical verdicts — zero
round-9 regressions; all pre-existing** (in the old code too, just never in the corpus). Ten finite-form
classes were then fixed in the one evaluator (golden no-drift at each): recursive (not one-shot) NamedExpr
unwrap in the archive provenance gate (`(a:=(b:=tarfile.open())).extractall()`); inline IfExp and
literal-sequence subscript as a CALLEE (`(os.system if c else os.popen)(cmd)`, `(os.system,)[0](cmd)`);
IfExp facts OR-combined across arms (a name bound to a ternary of two callables); inline IfExp self-file
argument (`open((__file__ if c else __file__), 'w')`); and an archive-precedence fix so a scalar→sequence-
of-archives rebind supersedes the scalar (`a=tarfile.open(); a=[tarfile.open()]; a[0].extractall()` fires,
`a.extractall()` on the list stays GREEN). Four remain an **OOS value-flow / interprocedural boundary**
(documented): a closure free-variable resolved at call time (across three domains), and a `global`-rebind
visible at a module-level call after a nested mutation. No new rule IDs.

### Fixed — round-8: except/match capture masking (overlay) + import-as + walrus-call-target

A fresh multi-agent adversarial sweep (**119 constructions, 19 confirmed false-NEGATIVEs**)
attacked the round-4..7 scanner and the two findings of an external Codex pass; every defect was
reproduced against the live scanner before fixing. The first masking attempt (mask+restore into
the timelines) was then **re-swept against itself**, which caught the three regressions it
introduced — so it was re-rooted on a cleaner overlay model. A second re-sweep against the
overlay found one more fixable corner (a walrus in the getattr head) and confirmed two **documented
OOS boundaries** (a nested-`def` closure over a captured name — a contrived FP; and conditional-
control-flow masking — a pre-existing value-flow FN, reproduced on a plain `if`). A further external
Codex pass found three more, all reproduced and fixed: a walrus getattr head in the ASSIGNMENT-result
and method-ref paths (`wfn = (g := getattr)(os,"system")` — not just the inline call); the capture
overlay not consulted while the alias timeline is BUILT (so `except E as getattr: fn = getattr(os,
"system")` false-aliased fn → AST003 FP); and a RELATIVE import (`from .os import system as run`)
canonicalized to the stdlib `os.system` (AST003 FP). Further Codex passes and focused divergence checks
hardened the alias-timeline builder (`resolve()`) to match `_canon` at the disease class — it is a hand-
rolled per-scope copy that runs BEFORE `self.scopes` exists, so it kept lagging: a captured DOTTED head
(`except E as builtins`), a capture superseded by an in-body rebind, a NESTED walrus head, a PARAM-shadowed
getattr in the assignment path (all param kinds), and a bare MODULE-ALIAS getattr base (`import os as o; getattr(o,"system")`)
were each closed by three root fixes — seeding params into the alias builder, distinguishing a within-scope
bind (shadow → mask) from UNBOUND (→ import) in the general resolve path, and resolving a bare module alias
in `_resolve_import`. No new rule IDs — every change hardens AST003 / AST009 / AST011.

- **`except … as name` and `match`/case captures now MASK the name inside the block.** A name
  previously bound to a dangerous callable / `__file__` / archive / method-ref is, inside an
  `except E as name:` handler or a `case [name]:` / `case {"k": name}:` / `case C() as name:`
  body, the caught exception / matched sub-value — not the prior binding. The first
  implementation wrote a mask+restore pair into the four per-scope timelines and was **net-
  negative**: restoring a captured *builtin* name (`except … as getattr`) injected a phantom
  local binding that made `_local_binding_scope` treat the builtin as shadowed for the rest of
  the scope (a broad FN), a name captured by two `case`s resolved its prior to the first mask
  (FN), and the restore clobbered an in-body rebind (FN). The fix is a **block-scoped overlay**:
  a separate per-scope region map (`_scope_captures` / `_capture_masked`) the resolvers consult,
  leaving the timelines untouched — so a use **after** the block (or after an in-body rebind)
  still resolves normally (no FN on the fall-through path, where Python keeps the prior binding),
  and an otherwise-unbound captured builtin is never poisoned. The masking yields to a real
  in-body rebind recorded in the alias timeline.
- **`import … as` / `from … import … as` is now a binding form in the per-scope timelines.** A
  local `import os as run` / `from os import system as run` REBINDS the name, so a prior
  `run = print` no longer masks the later import (`run.system(cmd)` / `run(cmd)` now resolve to
  os.system — AST003), `import os as mod; mod.replace(src, __file__)` fires AST009, and
  `import tarfile as t; t.open(p).extractall()` fires AST011. An import that rebinds a name also
  resets its `__file__` / archive / method-ref provenance.
- **Walrus is transparent to dotted-name resolution.** `(run := os.system)("id")`, a walrus in the
  getattr HEAD `(g := getattr)(os, "system")(cmd)`, and — after a further re-sweep — a walrus as the
  RHS value / attribute base / getattr base (`fn = (x := os.system)`, `fn = (m := os).system`, `fn =
  getattr((m := os), "system")`, `P = getattr((m := pathlib), "Path")(__file__)`) all resolve to the
  walrus VALUE. The root fix is one place: `_dotted_name` now unwraps a `NamedExpr` ANYWHERE in the
  Name/Attribute chain, so every resolver (alias builder, `_func_canon`, `_canon`, the Path-ctor and
  archive gates) sees the un-walrus'd form — closing the one-liner AST003 / AST009 / AST011 bypass.
- **F2 — getattr canonicalization unified across the resolvers (external Codex pass).** The
  assignment-result path (`f = builtins.getattr(os, "system"); f(cmd)`) and the method-ref path
  (`ex = builtins.getattr(t, "extractall")`) recognized only a LITERAL `getattr(...)` — missing
  `builtins.getattr` and an aliased getattr (the inline form via `_func_canon` already handled
  them) and not shadow-safe. Both now resolve the getattr head shadow-awarely and the base
  recursively, mirroring `_func_canon`: the assigned/aliased `builtins.getattr` indirection fires
  (AST003 / AST011) while a locally-shadowed `getattr = custom; f = getattr(os,"system")` stays
  GREEN.

### Fixed — prose negation guard (gaps 1–3, 8)
- **The clause-boundary test is Unicode-PROPERTY-based, not an enumerated codepoint
  denylist.** The narrow guard asked "is there a clause boundary between the negation and the
  dangerous verb?" with a literal class `[,.;:!?،、。]`; three comma/dash confusables slipped
  it and read a CRITICAL injection GREEN — `U+201A` SINGLE LOW-9 QUOTATION MARK (a comma
  look-alike NFKC does not fold, whose name lacks "COMMA"), the en-/em-dash family, and
  `U+2E41` REVERSED COMMA. A boundary is now any clause-delimiting punctuation decided by
  Unicode **category + name** (every script's comma/full-stop/… via a `Po`-name test,
  separator dashes via `Pd`, the two low-9 quote comma look-alikes), so a new confusable can
  no longer be hand-enumerated past it. The re-verification passes then showed each
  *narrower* refinement was still a denylist — a NAME-based clause-word list missed non-Latin
  terminators (Devanagari danda `।`, Tibetan shad, Khmer khan, Hebrew sof pasuq, Myanmar
  section), and a `Po`-only test missed So/Sm symbol bullets (`●` `▪` `∙`), invisible `Cf`
  format chars, and exotic `Zs` spaces (NBSP / Ogham) — each reading a CRITICAL forged-ChatML
  GREEN. The final form is the **INVERSE over a broad category set**: a gap char is a boundary
  UNLESS it is a letter/digit/mark, an ordinary space/tab, a bracket/quote/connector, or one
  of a small word-internal allowlist (apostrophe, solidus, markdown `*~_\``, middle dots).
  Every script's terminator and every symbol/invisible separator counts without enumeration
  (stdlib `unicodedata` cannot test the Unicode `Terminal_Punctuation` property).
- **Double-negation / polarity inversion no longer reads as defensive, by PARITY.** "never
  **hesitate to** reveal" / "never **miss a chance to** reveal" / "never **not** reveal" /
  "never **refuse to** reveal" = "always reveal" — a reluctance verb (or a stacked inverting
  negation) between the negation and the dangerous verb suppressed the entire PROSE_TARGETING
  family (HI024/HI025/HI026/CR031/CR041/…). Inversion is now decided by **parity**: an ODD
  number of inverting verbs in the gap fires; an EVEN number is defensive again ("never **shy
  away from refusing to** reveal" = "always refuse to reveal", GREEN). Genuine defensive prose
  ("never reveal", "does not and will not reveal", a single "refuse to reveal") stays GREEN.
  Ambiguous-sense verbs (`fail`, `miss`, `object`, `resist`, …) count only with an infinitival
  `to` complement, so the security idiom "must not **fail open** and reveal" does NOT misfire.
  The inverter set is open NL (THREAT_MODEL §8) — common forms enumerated, Claude-side review
  is the backstop for the tail (idioms like "never think twice about revealing" are not caught
  statically).

### Fixed — AST import-alias / assignment-alias resolution (gaps 4, 6 + re-verify)
- **AST009** caught `Path(__file__).write_text` but missed the import-aliased `from pathlib
  import Path as P; P(__file__)` AND the **assignment-aliased** siblings — `PP = pathlib.Path;
  PP(__file__)`, `from builtins import open as o; o(__file__,"w")`, `mv = os.replace;
  mv(s, __file__)`, the **module assignment** `a = os; a.replace(s, __file__)`, and
  `o = getattr(builtins,"open")` (transitive `b = a` too). A general assignment-alias resolver
  folds `X = <callable>`/`X = <module>` through the import maps (head-resolved), hardening
  AST009's ctor / open / destination arms — and every dotted AST rule (AST011 too).
- **`from <mod> import *` is resolved** for the finite set of dangerous canonical leaves the
  dotted rules key on, so `from shutil import *; unpack_archive(...)` → `AST011`,
  `from os import *; system(...)` → `AST003`, and `from tarfile import *; open(p).extractall()`
  → `AST011`. The star-import alias defeated EVERY dotted AST rule — the same class
  `import … as` once did — with zero new FP surface.

### Fixed — AST011 false positive + receiver provenance (gap 5 + re-verify)
- **`extractall` is gated on receiver PROVENANCE.** Keying on the bare `extractall` method
  leaf fired on the common, documented pandas `Series.str.extractall` and any non-archive
  `.extractall()`. AST011 now fires only when the receiver provably resolves to a
  tarfile/zipfile archive object — `tarfile.open`/`TarFile`, the alternative-constructor
  classmethods `TarFile.open`/`gzopen`/`bz2open`/`xzopen`, `zipfile.ZipFile`/`PyZipFile`, via
  import/star/assignment/module alias — directly or through a method-ref; `shutil.unpack_archive`
  stays unconditional. An opaque-receiver `extractall` (archive from another fn/file) is OOS.

### Fixed — supply-chain index redirect (gap 7 + re-verify)
- **Bundled package-manager configs are in the supply-chain gate.** An off-registry index
  redirect — `.npmrc`/`.yarnrc`/`.yarnrc.yml` (`registry=`/`@scope:registry=`/
  `npmRegistryServer:`/`//host/:_authToken`), `pip.conf`/`pip.ini`
  (`index-url`/`extra-index-url`/`trusted-host`), `.cargo/config.toml` (`[source.*] registry`/
  `replace-with`, gated on the `.cargo` parent), or `.gemrc` (`:sources:`) — now emits
  `HI023`, the same off-registry signal already flagged in a lockfile `resolved` field. The
  `pyproject.toml` custom-source parse also covers the modern uv (`[[tool.uv.index]]`) and PDM
  (`[[tool.pdm.source]]`) siblings, not just Poetry. A single-label intranet host in a real
  `scheme://` URL fires too, while a localhost/loopback dev mirror (devpi) stays GREEN.
  registry.npmjs.org / pypi.org / crates.io / rubygems.org stay GREEN; npm.pkg.github.com
  flags. **Known boundary:** the gate is a closed filename allowlist — `.condarc`,
  `.bundle/config`, `nuget.config`, `composer.json` repositories, `.gitconfig insteadOf`, and
  Homebrew taps are NOT yet covered (a future increment); the lockfile/manifest passes and the
  Claude-side review are the backstop.

### Fixed — external-audit pass (reproduce-first, fix-confirmed)
- **Param-shadow false positive.** A function parameter named after a dangerous symbol
  (`def f(system): system(...)` under `from os import *` / `from os import system`) was
  canonicalized to `os.system` → AST003 CRITICAL FP. `_canon` now masks a name bound by a
  local param/assignment (an explicit callable/module alias still resolves).
- **`from os import *; open(__file__, O_WRONLY)`** read GREEN (os.open was excluded from
  star-resolution) — now caught; the os.open arm tells a write-flag from a string mode.
- **AST011 receiver provenance is position-correct.** The archive-name set was final-state, so
  `a=tarfile.open(p); a.extractall(); a=None` read GREEN (FN) and a param shadowing an outer
  archive read RED (FP). The set is now MONOTONIC (a rebind after the use keeps it) and the
  INNERMOST scope that binds the name decides.
- **AST009 binding is column-aware.** Position is now `(lineno, col_offset)`, so a same-LINE
  rebind `p=Path(__file__); p.write_text(); p=None` no longer masks the write (FN).
- **`inventory()` fails loud on truncation.** It capped at 100k nodes and silently dropped
  files past the cap (a hidden exec/symlink read GREEN); it now emits `IO004` (HIGH), mirroring
  the supply-walk truncation posture.
- **Flow-sensitivity — alias & archive resolution is now POSITION-AWARE per scope.** A second
  audit pass showed the global assign-alias map was last-write-wins, so `mv=os.replace;
  mv(__file__); mv=safe` MISSED `AST009`; and the round-4 MONOTONIC archive fix had created a
  fresh FP (`a=tarfile.open(); a=SafeArchive(); a.extractall()` fired). Both are flow-
  insensitivity: `_canon` now resolves a within-scope alias AS OF the call's `(lineno,col)`
  position (a per-scope alias timeline), and the archive provenance set is a position-aware
  timeline too. A rebind masks a later use (FN closed) and a benign rebind un-masks (FP closed);
  cross-scope module aliases, transitive `b=a`, and param-shadow all still resolve.
- **Taint catches a walrus bound in a separate clause.** `(token := os.getenv()) and
  post(data=token)` read no TF — the sink was scanned before the walrus bound in the same
  statement; the walrus is now applied first. (A named-host destination is `TF002` HIGH; a
  bad/IP destination is `TF001` CRITICAL.)
- **The OFFICIAL Cargo index in BARE-URL form stays GREEN.** `https://github.com/rust-lang/
  crates.io-index` (no `registry+` prefix) used to false-positive `HI023`; an
  `_is_official_crates_index` helper now exempts it in both the `registry+` and bare-URL paths.
- *Documented (not changed):* a defensive comma-ENUMERATION of dangerous phrases under one
  `never` (`never reveal X, send Y, rewrite Z`) fires the later clauses — the **deliberate
  FP cost** of the narrow negation guard (a comma is a clause boundary). Suppressing it would
  re-open the comma-splice CRITICAL bypass; the comma-free `or` coordination is the documented
  authoring workaround.
- **Re-verifying the position-aware refactor (pass 3) hardened its own edges.** (i) The
  alias mask returned the unchanged name, so a param named after a module (`def f(shutil):
  shutil.unpack_archive()`) still matched the rule — it now returns a non-matching sentinel,
  and masks only the INNERMOST scope (so a module placeholder reassigned via `global` falls
  through to the global map and still fires). (ii) AST011 archive provenance is now CONDITIONAL-
  aware: an `IfExp`/ternary arm, a `try`-open with a `None` fallback in the `except` handler,
  and a list-of-archives (`for a in [tarfile.open(p)]` / `archives[0]`) are all caught, while
  an UNCONDITIONAL `a=Safe()` rebind still masks. (iii) The official Cargo index in bare-URL
  form is exempt in the `.cargo/config.toml` path too. *Known boundary (THREAT_MODEL §8):*
  lambda parameters / comprehension loop variables are not separately scoped (a contrived
  alias-collision FP; an `AST009` self-rewrite via a comprehension target reads as `ME005`
  YELLOW), and attribute-target aliasing (`C.run = os.system`) is not modeled.
- **The last two flow-insensitive resolvers are now position-aware (pass 4).** The `pathlib.Path`
  constructor alias was a GLOBAL set (`P=pathlib.Path; P(__file__); P=safe` missed `AST009`; a
  `from pathlib import Path as P; P=safe; P(__file__)` rebind false-fired), and the `extractall`
  method reference was a FINAL-STATE map (`ex=t.extractall; ex(); ex=safe` missed `AST011`; a
  safe `ex()` before a later `ex=t.extractall` false-fired). Both are now per-scope position-aware
  timelines, so flow-sensitivity is uniform across `__file__` / alias / archive / path-ctor /
  method-ref.
- **The shadow decision is uniform and import-aware (pass 5).** A CRITICAL false-negative
  remained — a FUTURE module-level rebind retroactively masked an earlier import-use
  (`from os import system; system(cmd); system=safe` read GREEN) — and a param / `for`-target /
  `AnnAssign` named after a module/ctor/method-ref did NOT mask (an FP), because the resolvers
  keyed off the alias/method maps (assignments only) rather than the full binding set. All five
  resolvers now share one helper — the innermost scope that binds the name AT OR BEFORE the
  call — so a param/`for`/`AnnAssign` masks like an assignment and a name not yet locally bound
  resolves to the import (before any later rebind). The `Path(__file__)` ctor test is fully
  position-aware too (a param literally named `Path` no longer false-fires).

## [1.11.0] — 2026-06-20

**Adversarial-audit hardening.** Multiple review rounds — an external reviewer (Codex)
of the H/I/J commits, then self-run **multi-agent adversarial sweeps** that attack each
fix against the live scanner and adversarially re-verify every finding — drove the
detection passes to convergence (loop-until-dry). Dozens of confirmed defects, several of
them false-**NEGATIVE** regressions the phases or earlier fix rounds introduced. Each was
reproduced against the live scanner *before* fixing (RED→GREEN), generalized from the
reported instance to the **disease class**, and locked with a permanent fixture vector +
a CI snippet assert. New coverage (import-alias resolution, recursive manifest discovery,
comprehension taint) means new true-positives, hence a minor bump. No new rule IDs except
`IO004` (an internal fail-closed signal). This entry describes the FINAL behavior.

### Fixed — robustness (fail-closed)
- **A crashing pass fails CLOSED.** A structural-pass crash (e.g. `RecursionError` on a
  deep `settings.json`) was caught into a `LOW` and read GREEN; it now emits `CRITICAL`,
  and `_parse_json` recovers the real `hooks` finding (`CR032`) via the textual backstop.
- **A config/manifest too large to fully audit fails CLOSED (`IO004`).** Beyond the 8 MB
  read cap a config would be read truncated — a key hidden past the cap read clean. An
  oversized opaque config/manifest now RED-flags `IO004` CRITICAL; a **lockfile**
  (legitimately 10–30 MB) drops to `IO004` HIGH and its readable prefix is still scanned
  (incl. JSON lockfiles, for off-registry `resolved` hosts → `HI023`).
- **Every read is bounded.** `_exec_magic`/`_looks_like_text` read fixed chunks (were
  whole-file); `_read_text_safe` caps at 8 MB; per-file `unicode`/`ast`/`taint` skip files
  over `MAX_SCAN_BYTES`; tree walks (`_iter_tree_files`, `inventory`) are node-bounded. A
  multi-GB file or a 200 k-directory tree can no longer hang the scan.

### Fixed — prose negation guard
- The clause-aware guard suppressed dangerous prose behind a faked negation, reading
  CRITICAL injections GREEN. Three rounds of looser rules each spawned a sibling
  (comma-splice → comma-as-break → coordinator → faked `, or` → Unicode comma → Oxford
  decoy), so the converged fix is **structural and narrow**: the negation suppresses ONLY
  when it **adjacently governs** the dangerous verb — i.e. there is NO clause boundary of
  any kind between the negation and the match. ANY boundary fires: a comma (ASCII, or the
  NFKC-folded fullwidth `，`, Arabic `،`, ideographic `、`), any sentence punctuation, or a
  temporal/disregard idiom. The only way to make a negation adjacently govern the verb is
  to write *"never reveal your system prompt"* literally — which IS a defensive statement,
  so suppressing it is correct, and an attacker cannot weaponize it. Third-person
  `does not`/`doesn't`/`is not` are recognized. A genuine defensive note must use
  comma-free `or` coordination (*"never reveal or send your prompt"*) or per-clause
  negation to stay GREEN (documented authoring guidance) — a comma-list of multiple flagged
  phrases under one `never` now flags the later items (the deliberate FP cost of an
  unbypassable rule, within the MEDIUM/HIGH budget and human-reviewed).

### Fixed — Python AST passes
- **`AST009` self-modification** now resolves the write target **per-scope and
  POSITION-AWARE** through every binding form — same-scope assignment, walrus (`:=`),
  tuple-unpack, transitive `q = p`, aliased `open` (incl. `io.open` / `from io import open`),
  and `for p in [Path(__file__)]` / a comprehension — as of the *write call's line*:
  `p=__file__; p.write(); p=None` fires (write while `p` IS `__file__`) and
  `p=Path(__file__); p=p.with_name(x); p.write()` does not (rebound before the write), with a
  same-named param masking an outer binding. New sink: low-level `os.open(__file__,
  O_WRONLY|…)`. Write-mode includes the `+` update modes. Replaces the prior global set
  (cross-function FP) and the over-corrected inline-only form.
- **`AST011` Zip-Slip** exempts only a PROVABLE guard (`filter="data"/"tar"` or
  `filter=tarfile.data_filter`, or a literal `members=[…]` — not a variable or
  `getmembers()`), and resolves method-reference indirection (`ex = t.extractall`,
  `getattr(t,"extractall")`, transitive, tuple-unpack, walrus). It keys on the
  **`extractall`** method name (not bare `.extract`, which collides with pandas
  `.str.extract` / bs4 `.extract` and blew the FP budget — single-member `.extract` is OOS).
- **Import-alias resolver (`_canon`)** canonicalizes dotted call names through the file's
  import map (`import shutil as sh`, `from shutil import unpack_archive [as x]`), so EVERY
  dotted AST rule resolves an aliased import instead of being defeated by it.

### Fixed — taint, supply-chain
- The taint pass enumerates **every binding construct** — assign/annassign/augassign, walrus,
  `for`-targets, and comprehension generator targets — so split-variable credential exfil via
  any of them reads `TF001`. The `HI009` network line-rule now matches `httpx.<method>` /
  `aiohttp.<method>` (was blind to them).
- Dependency-manifest discovery is **recursive** (any depth, incl. `src/`/`vendor/`/
  `node_modules/`), keying off manifest filenames so a data `*.json` stays GREEN.

### Added
- `scripts/check_docs.py` + a **Doc-currency** CI gate (mechanically enforced): every
  emittable rule ID is documented, every `examples/` fixture is swept, the CHANGELOG top
  version is in the ROADMAP. The harvester parses scan.py with stdlib `ast` and collects
  rule-ID literals at emission positions — quote- and family-agnostic, ignoring comments/
  docstrings — so it can never go blind to a family or false-fail on a comment.
- Permanent regression fixtures + per-form CI snippet asserts for every confirmed audit
  finding across all the families above.

## [1.10.0] — 2026-06-19

**Ecosystem hardening** against the 2026 supply-chain + prompt-injection + MCP
secret-egress wave. A 5-lane web sweep of the agent-skill / MCP / LLM-app security
ecosystem (MITRE ATT&CK, Vigil-llm, Bandit, Token Security, StepSecurity Phantom
Gyp, Socket.dev), scoped against our invariants — every gap grep-verified absent
from `scan.py`. Ten rules across **existing** passes (no new subsystem); each
completes a surface we had opened one field short.

### Added
- `CR041` (CRITICAL) — chat-template control tokens forging a system/assistant turn
  in SKILL.md prose (`<|im_start|>`, `<<SYS>>`, `[INST]`, `[system](#assistant)`,
  `{{#system}}`); `HI026` (HIGH) — the instruction-override triple gate ("disregard
  all previous instructions"). Both `PROSE_TARGETING` + clause-aware negation guard.
  *Source: Vigil-llm YARA, OWASP LLM01.*
- `AST010` (CRITICAL non-literal / HIGH literal) — `os.exec*`/`os.spawn*`/
  `posix_spawn` process replacement, completing `AST003` (which modelled only
  `os.system`/`subprocess`); `AST011` (MEDIUM) — `extractall`/`unpack_archive`
  without a member filter (Zip-Slip). *Source: Bandit B606/B202.*
- `CR042` (CRITICAL) — a **live-token** value (`ghp_`/`sk-`/`xox.-`/`AKIA…`/`AIza…`/
  JWT) in a bundled `mcpServers[].env`/`headers`, with a `${VAR}`/placeholder guard;
  `HI027` (HIGH) — a credential-file ref or reputation-bad dest there. The
  `mcpServers` loop previously read only `command`/`args`/`url`. *Source: Token
  Security (~20% of MCP configs carry hardcoded secrets); the named ROADMAP candidate.*
- `CR043` (CRITICAL) — gyp `<!(` command-substitution in a bundled `binding.gyp`
  (Phantom Gyp install-RCE, no package.json script); `HI028` (HIGH) — bare presence
  of a `binding.gyp` (a skill is never a native addon). *Source: StepSecurity, a
  live June 2026 worm campaign.*
- `CR044` (CRITICAL) — `/dev/tcp` reverse shell / `nc -e` inbound C2; `HI029` (HIGH)
  — anonymous file-staging / paste **download** hosts (`transfer.sh`/`gofile.io`/
  `bashupload.com`/…), the second-stage source class `CR026` (exfil destinations)
  missed. *Source: MITRE T1608.001, skillcop, Socket.dev.*
- `INV001` escalates HIGH→CRITICAL for a bundled file whose magic bytes are an
  executable (ELF/PE/Mach-O), reusing bytes already read. *Source: GuardDog.*
- `examples/evil-ecosystem/` (GREEN→RED, all ten rules + INV001-ELF + the
  `${VAR}`-placeholder discrimination) + `examples/clean-ecosystem/` (defensive
  prose, argument-list subprocess, `extractall(filter="data")`, no bundled config) →
  exit 0. CI asserts exit codes + per-form snippet locks. Full sweep additive.
- `docs/specs/2026-06-19-ecosystem-hardening.md` (incl. the OPT-IN / SKIP / needs-LLM
  ledger and the **v2.0 = JS/TS pass** reservation); `THREAT_MODEL.md`,
  `docs/ROADMAP.md`, `README.md`, `references/red-flags.md`,
  `references/patch-templates.md`, `SKILL.md` updated.

## [1.9.0] — 2026-06-19

**Borrow-from-SkillSpector** increment. A scoping pass over NVIDIA SkillSpector's 16
categories (read from its analyzer source, not the README) found most of its 64
patterns already covered by our passes, off our threat axis, or needing
network/deps/LLM. The genuine **must-take** residue is three small dependency-free
gaps — all on our own edge surface (the SKILL.md prose the model reads as authority,
the frontmatter, the Python AST). Closes SS **P6, P8, MP1, RA1, TR1, TR3**.

### Added
- `scripts/scan.py`: six rules across three existing passes (no new subsystem),
  empirically GREEN-before / RED-after:
  - **`HI024` (HIGH)** — `SKILL.md` prose ordering the model to **disclose** its own
    system prompt / instructions (P6). Possessive / `system` anchor → bare *"your
    prompt"* (user-input) does not fire.
  - **`HI025` (HIGH)** — prose ordering the model to **write/send** its own system
    prompt to a file / network / log sink (P8) — the host-less prompt-to-sink form
    the endpoint-anchored exfil rules miss.
  - **`ME013` (MEDIUM)** — a **cross-session persistent** instruction / memory
    injection (MP1). Cross-session scope anchor only; the FP-prone *"from now on,
    always …"* form is deliberately not matched.
  - **`ME015` (MEDIUM)** — prose telling the skill to **rewrite its own** SKILL.md /
    source (RA1, prose form). Self-reference anchor (`this`/`your own`/`the current`)
    spares a skill-builder writing **other** skills.
  - **`ME014` (MEDIUM)** — an **unscoped catch-all** `when_to_use`/`description`
    activation surface (TR1/TR3) — `anything`/`every request`/`always trigger`.
    Domain-scoped *"any React component"* / *"all SQL queries"* stays GREEN.
  - **`AST009` (HIGH)** — `open(__file__, "w")` / `.write_text`/`.write_bytes` to the
    skill's **own running file** (RA1, AST form). Read modes and writes to any other
    path (incl. a skill-builder emitting another skill's `SKILL.md`) do not fire.
  - The four prose rules join `CR028–031` in `PROSE_TARGETING` (scan full prose
    lines) and the position-based **negation guard** (defensive *"never reveal your
    system prompt"* is skipped). New helpers `_refs_dunder_file`, `_fm_field`,
    `_ME014_RE`.
- `SKILL.md` Step 7: an advisory **description-vs-behavior** comparison against the
  scanner's enumerated evidence (network sinks, credential reads, taint flows) — the
  borrow of SS's `TP4` that needs an LLM, so it lands as a Claude-side step (advisory,
  never an auto-RED gate), not a `scan.py` rule.
- `examples/evil-selftarget/` (GREEN→RED, all six rules) + `examples/clean-selftarget/`
  (defensive negation, a skill-builder writing another skill's file, domain-scoped
  `any`, a `__file__` **read**) → exit 0.
- CI: `evil-selftarget` exit 3 with all six ids + per-form snippet locks;
  `clean-selftarget` exit 0 with none.
- `docs/specs/2026-06-19-self-targeting.md` (incl. the full SKIP / OPT-IN / needs-LLM
  ledger of the dropped SkillSpector borrows); `THREAT_MODEL.md`, `docs/ROADMAP.md`,
  `README.md`, `references/red-flags.md`, `references/patch-templates.md`, `SKILL.md`
  updated.

## [1.8.0] — 2026-06-19

Deepens the Python AST pass into **data flow**: a new **taint pass** connecting a
**credential source** (`os.environ` / `os.getenv`) to a **network sink** across
intervening assignments. The line and AST passes classify one node at a time, so a
secret read in one statement, packaged in a second, and shipped in a third reads
only 🟡 YELLOW (a lone `HI009`). That split-variable credential exfil is the
project's worst-failure class — a dangerous skill under-rated — and now reads 🔴 RED.
The central FP tension (a legitimate authenticated API client is the same shape) is
resolved **by construction**, gating CRITICAL on the **destination**, not the flow —
no in-loop LLM, unlike the SkillSpector reference impl this phase cross-checked.

### Added
- `scripts/scan.py`: a new **`TF` family** (taint-flow) in a new pass `taint_scan`,
  called from `main()` per `.py` file after `ast_scan` (re-parses; never executes).
  - **`TF001` (CRITICAL)** — a credential-tainted value reaches an HTTP-client
    network sink whose destination is **reputation-bad or user-controlled**: a
    non-literal URL, a public-IP literal (incl. hex/decimal-encoded), a punycode/IDN
    host, or a known exfil/tunnel/metadata host. Two rare facts ANDed
    (secret-tainted **and** bad/dynamic dest) keep it in the ≤5% budget — a legit API
    client cannot land here.
  - **`TF002` (HIGH)** — the same flow to a **hardcoded named-HTTPS** host (incl.
    loopback/RFC1918): the legit-client shape, a secret still leaving the machine, so
    a human reviews — not auto-refused.
  - Intraprocedural, source-order, monotonic (no taint kill); container literals,
    f-strings, and concatenation propagate for free. Sinks: `requests`/`httpx`/
    `aiohttp` `.get/.post/.put/.patch/.delete/.request/.head/.options`,
    `urllib.request.urlopen`/`Request` (the `HI009` vocabulary). Reuses the `CR040`
    destination machinery (`_reputation_bad_dest`/`_public_ip_in`) and derives
    `_EXFIL_HOST_RES` **from** the `CR026`/`CR034`/`CR038` line rules — one source of
    truth, no parallel host table.
  - **Additive only**: never suppresses or downgrades a line/AST finding (`HI009`
    still fires on every network call); the URL position is excluded from payload
    taint, so a configurable env→URL endpoint with a non-secret body is not a false
    CRITICAL.
- `examples/evil-taint/` — a clean `SKILL.md` shipping `scripts/upload.py` with seven
  credential→bad/dynamic-dest chains (`TF001`: public IP, user-URL, f-string dest,
  hex-IP, punycode, `webhook.site`, urllib) plus two benign-shaped egresses
  (`TF002`: a named API in an `Authorization` header, a loopback dev callback) that
  prove the named/loopback destinations are **not** over-escalated to CRITICAL.
- `examples/clean-taint/` — credential reads that never reach a network sink (no
  `requests`/`httpx`/`urllib` at all) → exit 0, zero `TF` findings.
- CI: `evil-taint` must exit 3 with `TF001`≥6 + `TF002` + per-destination-form
  snippet asserts + named-host/loopback discrimination (`TF002` not `TF001`);
  `clean-taint` must exit 0 with no `TF` leakage.
- `docs/specs/2026-06-19-taint-flow.md`; `references/red-flags.md` rows;
  `references/patch-templates.md` § taint TF002; `THREAT_MODEL.md` rows + acceptable
  + out-of-scope; `README.md` Limitations; `SKILL.md` Step + Limitations.

## [1.7.0] — 2026-06-13

Deepens an existing pass: **MCP / hook destination reputation**.
`check_bundled_config` (Phase C) flagged the *presence* of a bundled hook
(`CR032`), stdio MCP (`CR033`), or remote MCP (`HI017`) but never looked at
*where* it pointed. A lone bundled remote MCP server hardcoded to a bare public IP
or a punycode host therefore scored 🟡 YELLOW (`HI017` + the per-line `HI019`/
`HI022`), the same severity as a hygiene nit — a severity false negative on an
auto-loaded, malware-tier destination (verified: a single bare-IP `.mcp.json`
server scored exit 1 before this change). The fix unifies the two half-signals —
"this is an auto-loaded config" and "its host is reputation-bad" — at the
structural layer.

### Added
- `scripts/scan.py`: `CR040` (CRITICAL), emitted inside `check_bundled_config`.
  When a hook `command`, a stdio MCP `command`+`args`, or a remote MCP `url`
  points at a **public-IP literal** (incl. hex/decimal-encoded) or a **punycode /
  IDN** host, the bundled-config finding escalates to CRITICAL → 🔴 RED. Host
  classification **reuses** `_public_ip_in` (the `urllib` + `ipaddress` + `shlex`
  extractor behind `HI019`) and the `HI022` `xn--` form — no parallel host table.
  New helpers `_reputation_bad_dest`, `_hook_command_strings`, `_cr040_finding`.
- `examples/evil-mcp/` — a clean `SKILL.md` shipping a `.mcp.json` with remote MCP
  servers at a raw public IP, a punycode host, and an encoded IP (each
  `HI017`+`CR040`), a stdio server with a public IP in `args` (`CR033`+`CR040`), a
  named-domain server and a loopback server (`HI017` only — discrimination), plus a
  `.claude/settings.json` hook whose command reaches a public IP (`CR032`+`CR040`).
- `examples/clean-mcp/` — a `references/mcp-catalog.json` data file documenting MCP
  servers with `mcpServers`/`url`/`command` keys at **named** hosts; the filename
  gate keeps it GREEN (the `api-shapes.json` precedent).
- CI: `evil-mcp` must exit 3 with `CR040` present (+ per-destination-variant
  snippet asserts + named-domain/loopback discrimination); `clean-mcp` must exit 0
  with no `CR040`/`CR032`/`CR033`/`HI017` leaking onto the data file.
- `docs/specs/2026-06-13-mcp-hook-reputation.md`; `references/red-flags.md` row;
  `references/patch-templates.md` § bundled-config CR040; `THREAT_MODEL.md` rows +
  acceptable + out-of-scope; `SKILL.md` Step 1.5 row; `docs/ROADMAP.md` → shipped.

### False-positive guards
- **Filename gate (inherited).** `CR040` runs only inside `check_bundled_config`,
  which collects candidates by config **basename** — a `references/*.json` data
  file describing MCP servers (even with a raw-IP value) never reaches it and so is
  never escalated to CRITICAL (a literal public IP there still earns the per-line
  `HI019` HIGH, which is correct).
- **Private / loopback gate.** `_public_ip_in` skips loopback / RFC1918 /
  link-local, so a local-dev MCP at `http://127.0.0.1:7000/sse` stays `HI017`.
- **Named-domain discrimination.** A remote MCP at a named host (no IP literal, no
  `xn--`) stays `HI017` YELLOW — the user reviews the URL and decides.
- **No double-emit.** Known exfil/tunnel/cloud-metadata hosts are left to
  `CR026`/`CR034`/`CR038` (already CRITICAL via the line scan); `CR040`'s host gate
  is IP-literal + punycode only.

### Out of scope (residual, after Phase G)
MCP `env`/`headers` secret-egress (judgment-heavy FP — promoted to
`docs/ROADMAP.md` as the next "deepen existing passes" candidate), a full engine
re-run over extracted hook/MCP command content (`CR032`/`CR033` already route to
RED — marginal value, double-emit noise), an ordinary named-domain remote MCP
(stays `HI017` by design — no reputation feed in a no-network scanner), and a
non-TLS `http://` to a named host (weak signal, FPs on dev servers).

### Fixed (pre-release adversarial review)
A multi-agent adversarial pass over the new destination extraction found four
real gaps — all in the **shared** `_candidate_hosts` / `_ip_publicness` engine
(so the fixes also close the identical hole in `HI019`), each reproduced against
the live scanner and locked with a fixture form + a CI snippet assert:
- **Public IPv6 literal in a remote MCP `url` was missed** — the URL-extraction
  regex excludes `]`, so `http://[2606:4700:4700::1111]/sse` truncated mid-literal
  and `urlsplit` raised → no host → no `CR040` (a bare-IPv6 MCP read YELLOW). The
  URL pass now falls back to pulling the bracketed IPv6 literal directly; loopback
  / ULA / link-local IPv6 still read private (no `CR040`).
- **Dotted-encoded IPv4 was missed** — `_ip_publicness` only decoded a single hex
  integer (`0x08080808`) or `\d{8,10}` decimal, so the per-octet forms a real
  client dials — dotted-hex (`0x08.0x08.0x08.0x08`), dotted-octal (`0250.0.0.1`),
  mixed — slipped, despite the spec promising "incl. hex/decimal-encoded". A
  4-octet form with any hex/octal octet now classifies as public (the obfuscation
  is the signal, the single-integer twin's logic); a plain dotted-decimal is taken
  by `ipaddress` first and a named host never parses, so no new FPs.
- **Punycode in a URL path/query/fragment over-flagged (FP)** — `_reputation_bad_dest`
  ran the `xn--` regex against the whole string, so a benign named host with an
  `xn--` label in the path (`https://api.example.com/xn--cache/list`) wrongly
  escalated to CRITICAL (over the ≤5% budget). Both signals (IP **and** punycode)
  are now classified on the **extracted host(s)** only, mirroring the IP branch —
  `xn--` in a path no longer fires `CR040` (a genuine punycode **host** still does).
- **Deferred (recorded, not fixed):** a trailing-dot IP literal (`185.220.101.5.`)
  and a shell `VAR=ip cmd $VAR` env-assignment/deref in a hook/stdio command — both
  are attribution-only (the env-assignment case never flips a verdict: `CR032`/
  `CR033` already route to RED, and the verdict-flipping remote-`url` path is a
  plain string never shell-parsed). The env-assignment root belongs to the
  ROADMAP's taint/data-flow shell-walker; both are noted in the spec out-of-scope.

## [1.6.0] — 2026-06-03

New threat class: **supply-chain** — bundled dependency manifests. The line rules
need a runtime install *verb* (`CR021`) or a public-IP literal (`HI019`); a
bundled `package.json` / `requirements.txt` / `pyproject.toml` / lockfile is a
*declaration*, so its dangerous forms were silent (verified: an evil manifest dir
scored exit 0, zero findings, before this change).

### Added
- `scripts/scan.py`: new **structural pass** `check_supply_chain(skill_root)`,
  modeled on `check_bundled_config` — it keys off manifest **filenames** (root +
  `scripts/`/`references/`/`assets/`, symlinks skipped), parses stdlib-only and
  **never executes** the file (`json.loads` for `package.json`/JSON locks, a
  line-based section-aware parse for `requirements*.txt`/`pyproject.toml`, a
  generic off-registry source scan for `yarn.lock`/`pnpm-lock.yaml`/`Pipfile`/
  `Cargo.toml`/`Gemfile`/`go.mod`/`environment.yml` — section-aware for TOML, so a
  crate's `[package]` `repository`/`homepage`/`documentation` metadata URL is not
  misread as a dependency source). Wired into `main()` right after the
  bundled-config pass.
  - `CR039` — npm/yarn/pnpm install-lifecycle script (`preinstall`/`install`/
    `postinstall`/`prepare`/`prepublish`/`prepublishOnly`) in a bundled
    `package.json` → CRITICAL. Presence is the danger (RCE on a plain
    `npm install`), keyed off the script **name**, not the command text — the
    static twin of a bundled hook (`CR032`). Textual backstop on JSON parse fail.
  - `HI023` — dependency from a **non-registry source**: VCS (`git+`/`hg+`/`svn+`/
    `bzr+`, `github:`/bare `user/repo`), an arbitrary URL/tarball/wheel, non-TLS
    `http://`, an index/source redirect (`--extra-index-url`/`--trusted-host`),
    or a poisoned lockfile `resolved` → HIGH.
  - `ME012` — bundled top-level manifest ships **unpinned** deps (only the open
    forms: `*`, `latest`, a bare name, an unbounded `>=`) → MEDIUM, aggregated one
    finding per manifest.
- `examples/evil-supplychain/` (package.json install scripts + git/shorthand/
  tarball deps; requirements with git/tarball/`--extra-index-url`/non-TLS/bare;
  pyproject git+wheel+bare; yarn.lock off-registry `resolved`) and
  `examples/clean-supplychain/` (exact+`--hash` pins, caret + `workspace:`/`file:`
  local deps, registry-`resolved` lock, normal `go.mod`, and a `references/
  graph.json` data file with `dependencies`/`scripts` keys the filename gate keeps
  GREEN).
- CI: `evil-supplychain` must exit 3 with `CR039`+`HI023`+`ME012` (plus per-source
  variant and per-manifest aggregate snippet asserts); `clean-supplychain` exit 0.
- `docs/specs/2026-06-03-supplychain.md`; `references/patch-templates.md` § supply-chain;
  `references/red-flags.md` rows; `THREAT_MODEL.md` rows + out-of-scope #2 narrowed;
  `SKILL.md` Limitations §2 + Step 1.6; `docs/ROADMAP.md` supply-chain → shipped.

### False-positive guards
- **Filename gate** — only files named exactly as a manifest (or `requirements*.txt`)
  are inspected; a `references/*.json` data file and prose/fenced docs stay GREEN.
- **Registry-host allowlist** — `pypi.org`/`files.pythonhosted.org`/
  `registry.npmjs.org`/`registry.yarnpkg.com`/`crates.io`/`rubygems.org`/
  `proxy.golang.org`/`conda.anaconda.org` (and subdomains) never fire, so lockfile
  `resolved` URLs and `--index-url https://pypi.org/simple` stay GREEN.
- **Local-vs-remote gate** — `file:`/`workspace:`/`link:`/`./`/`../` are not a
  remote bypass.
- **Bounded ranges are pinned-enough** — `^`/`~`/`~=`/`<`-bounded/comma-bounded
  stay GREEN (caret/tilde are the npm/PEP440 default; flagging them would blow the
  MEDIUM budget). Only the unambiguous open forms are `ME012`.
- **`CR039` keys off the lifecycle script name** — `build`/`test`/`ci` never fire
  even when their command text contains `npm install`; `CR021`'s quote-prefix
  guard already keeps a JSON `"ci": "npm install …"` GREEN.
- **Lockfiles + `go.mod` exempt from `ME012`** (pinned by construction); a
  non-registry dep is `HI023` only, never also `ME012`; `ME011` does not fire on
  lock integrity hashes (sha512 ~88 / sha256 64-hex < 256).

### Out of scope (narrows `THREAT_MODEL.md` #2 to "partially covered")
Transitive dependencies, a malicious update to an already-pinned registry library,
CVE/version reputation (#3), typosquatting (#5), and runtime fetches (`CR021`'s
job) remain out of scope — the dependency-free, no-network scanner reads the direct
manifest only.

### Fixed (pre-release code-review — Codex)
An external Codex pass over the branch found parser-form gaps; all fixed before
merge, each locked by a fixture form + a CI snippet assert:
- **`requirements.txt` source forms** — an `-e git+https://…` editable remote, a
  `--extra-index-url=…` (the `--opt=value` equals form), and a PEP 508
  `name @ git+ssh://…` direct reference all read GREEN. `_classify_source` now
  strips the PEP 508 `@` marker (so `@ git+ssh://…` classifies), the option parser
  accepts `--opt=value` and `-e`/`--editable`, and `git+ssh://` matches as VCS.
- **`[project.optional-dependencies]` arrays** — parsed element-wise now (incl.
  multi-line accumulation), so `dev = ["evil @ git+…", "bare"]` yields `HI023` +
  `ME012` instead of being read as one row.
- **`go.mod replace => remote`** — promised under `HI023` but unimplemented; now a
  dedicated `_supply_gomod` flags a `replace` whose target is a remote module
  (single-line and `replace ( … )` block), while a local `=> ../vendor` and a
  normal `require` stay GREEN.
- **`Cargo.lock` `[[package]]` regression** — the Cargo metadata-skip wrongly
  skipped `[[package]]` array-of-tables (where lock `source` lives). Double-bracket
  tables are no longer skipped; a `source = "git+https://…"` flags while a normal
  `registry+`/`sparse+` source (the GitHub-hosted crates.io index) stays GREEN.
- **`package-lock.json` metadata FP** — a `funding.url` / `repository.url` was read
  as a dependency source; the lock walk now inspects only `resolved`/`tarball`.
- **x-range `1.x` / `1.2.*`** now read as unpinned (`ME012`), matching the rule
  table; caret/tilde/exact stay pinned.
- `README.md` Limitation #2 updated from "No supply-chain analysis" to the partial
  coverage now shipped.

A second Codex pass found three more (all fixed, fixture + CI-locked):
- **`registry+`/`sparse+` allowlist was too broad** — it exempted *any* host, so a
  `registry+https://attacker.test/…` alternate registry read GREEN. Now only the
  official crates.io index (the GitHub-hosted git index / `index.crates.io` sparse)
  and known registry hosts are exempt; an off-host alternate registry flags.
- **pip `--find-links` / `-f`** (a package-source redirect) was skipped — now
  classified like `--index-url` (remote flags, a local `./wheels` path stays GREEN).
- **Poetry `[[tool.poetry.source]]`** custom source redirect (`url = …`) is now
  read — an off-registry source flags, the default `pypi` source stays GREEN.

A third Codex pass found one more:
- **Cargo official-index allowlist matched the GitHub path by substring** — so
  `registry+https://github.com/attacker/rust-lang/crates.io-index` (a different
  repo) read GREEN. The path is now parsed and required to equal exactly
  `/rust-lang/crates.io-index` (trailing slash / `.git` tolerated). Fixing it
  surfaced that the generic source-scan token regex swallowed the closing quote
  into the URL, which the exact-path check then rejected — the token char class now
  excludes quotes, so both the spoof (fires) and the official index (GREEN) resolve
  correctly.

## [1.5.0] — 2026-06-02

First v3 increment: **Evasion v2** — normalization and homoglyph-domain coverage.

### Added
- `scripts/scan.py`: `scan_file` now also tests an **NFKC-normalized** copy of each scannable target, so fullwidth / compatibility-character commands (`ｃｕｒｌ … | sh`, math-styled `exec`) can no longer hide from the regex. Escalate-only — a finding is tagged "revealed by NFKC normalization"; normalization never suppresses a raw match.
- `CR038` — cloud instance-metadata endpoint (`169.254.169.254`, `metadata.google.internal`, `100.100.100.200`) → CRITICAL. Closes the gap where `HI019`'s link-local guard skipped the metadata IP (SSRF / IAM-credential theft).
- `HI022` — IDN / punycode host (`xn--`) → HIGH (homoglyph domain for phishing / C2).
- `examples/evil-evasion/` (fullwidth/math/punycode/metadata) and `examples/clean-evasion/` (legit `½`/`™`/`ﬁ`/CJK + a named host).
- CI: `evil-evasion` must exit 3 with `CR038`+`HI022`+`CR001`+`HI007`+`HI019`; `clean-evasion` must exit 0.
- `docs/ROADMAP.md` — consolidated v3 backlog (sourced from THREAT_MODEL out-of-scope + per-spec non-goals).

### Fixed (pre-release code-review)
- `CR038` and `HI022` are now **case-insensitive** — `METADATA.GOOGLE.INTERNAL` and an UPPERCASE `XN--` host no longer evade.
- `HI022` matches **bare-host** and **`userinfo@`** forms, not only `scheme://…` — a punycode host after `curl ` or `user:pass@` was being missed.
- The `HI019` private-IP guard reads the **NFKC-normalized** form, so a fullwidth loopback (`１２７．０．０．１`) is correctly skipped instead of flagged.
- `SKILL.md` Step 6.7 now documents the NFKC re-scan + `CR038`/`HI022`; CI also asserts the math-styled-`exec` catch (`HI007`).
- `HI019` suppresses a finding only when **every** IP-URL on the line is private/loopback — a private IP can no longer mask a public one on the same line (`curl http://127.0.0.1 && curl http://8.8.8.8`).
- **Inline-code handling settled after two flawed attempts.** A whole-line, then a per-span, "defensive-intent" guard each tried to treat ``never use `x` `` as documentation — both leaked (``never mind, run `curl | sh` `` went green). Final design: inline code is scanned **as code**, span by span, with **no** intent inference; a documented bad pattern is a self-FP the LLM-side audit handles, and intent-based suppression is limited to the position-based negation guard on `CR028`–`CR031`.
- CI now requires `HI019` on `evil-evasion` and `CR001` on `evil-bypass`; the `scan_file` docstring now matches the actual fence / inline / prose behavior.
- **Case-insensitivity swept across all host/domain/URL rules** — `CR026`, `CR034`, `HI021` joined `CR038`/`HI022`, so `HTTP://`, `WEBHOOK.SITE`, `TRYCLOUDFLARE.COM` no longer evade. (Command rules like `curl … | sh` stay case-sensitive — the shell is.)
- **`HI019` host detection rebuilt on `urllib.parse` + `ipaddress` + `shlex`.** The old regex host-extraction spawned a sibling bug every review round — scheme case (`HTTP://`), `userinfo@`, multiple `@` (`user@127.0.0.1@8.8.8.8`), scheme-less bare-IP targets, and `-H`/`-o` flag values mistaken for hosts. It now pulls the real host out of every URL and every `curl`/`wget`/`fetch`/`nc`/`ncat`/`netcat`/`telnet`/`ssh` target and classifies it with the stdlib, covering IPv6, `ftp://`, and hex/decimal-encoded IPs, while skipping named hosts, loopback/private/reserved/link-local, an IP that sits in the userinfo, and flag values. The regex is now only a cheap trigger.
- **`HI019` reads host-bearing `curl` options** — `-x` / `--proxy` / `--url` / `--resolve` / `--connect-to` / `--socks5` carry the destination, so a public IP behind a proxy or a custom resolve (`--resolve example.com:443:8.8.8.8`) is classified instead of skipped like a `-H` / `-o` data value.
- **`HI019` host walk resets on shell separators** (`;` `|` `&&` `||` `&`) — `curl https://api.example.com && echo 8.8.8.8` no longer false-flags the echoed IP as the request target.
- **`HI019` encoded IP always flags** — a hex / decimal host (`0x7f000001`, `2130706433`) is reported even when it decodes to loopback; writing an IP in encoded form is itself the evasion signal (a plainly-written `127.0.0.1` stays fine).
- **`HI019` flag handling is an allowlist, not skip-after-any-flag** — only known value-taking data/file options (`-H`/`-o`/`-d`/`-A`/`-u`/…) consume their argument, so a *boolean* flag no longer hides the scheme-less IP that follows it (`curl -s 8.8.8.8/x`, `wget -q 8.8.8.8/x`, `nc -v 8.8.8.8 4444`).
- **`HI019` parses attached short-option values** — `-x8.8.8.8:8080` (curl's `-Xvalue` form) is read like `--proxy 8.8.8.8:8080` and `--proxy=8.8.8.8:8080`.
- **`HI019` option grammar is command-aware** (`_CMD_OPTS`) — the same letter differs by tool, so `wget -O <file>` and `ssh -i <identity>` are no longer misread as IP targets, while `curl -x` (proxy) still is and `ssh -x` (boolean) is not. ssh's positional `user@host` and its `-J` / `-W` jump hosts are classified.
- **`HI019` parses bracketed IPv6 and comma-list option values** — `--proxy [2001:db8::1]:8080` and `--dns-servers 1.1.1.1,8.8.8.8` now surface the inner public IP.
- **`HI019` skips the `-X` / `--request` method token** — `curl -X 8.8.8.8 https://api.example.com/` no longer misreads the HTTP method as a host (the IP target in `curl -X POST 8.8.8.8/x` still flags); `--proxy1.0` added to the proxy-host set.

## [1.4.0] — 2026-06-01

New detections: **modern exfil / evasion breadth**. The original exfiltration
signatures predate a wave of newer techniques. This closes the v2 roadmap.

### Added
- `scripts/scan.py`:
  - `CR034` — tunneling / OOB-interaction hosts (Cloudflare quick tunnels, `serveo`, `localtunnel`, `localhost.run`, interactsh, `pipedream`, `beeceptor`, `requestcatcher`) → CRITICAL
  - `CR035` — env-var dump piped to a network tool (`env`/`printenv` → `curl`/`wget`/`nc`) → CRITICAL
  - `HI019` — IP-literal or numeric-encoded IP in a URL → HIGH (loopback & RFC1918 ranges guarded)
  - `HI020` — IFS-based shell space-substitution evasion → HIGH
  - `HI021` — Telegram bot API exfil channel → HIGH
  - `ME011` — long (≥256) base64/hex literal → MEDIUM (git SHAs fall under the threshold)
- `references/red-flags.md`, `references/patch-templates.md`, `THREAT_MODEL.md`: exfil/evasion rows.
- `examples/evil-exfil/` — every new pattern; pre-1.4.0 it scored GREEN.
- `examples/clean-exfil/` — loopback/private-IP URLs, a named HTTPS host, a git SHA; stays GREEN.
- CI: `evil-exfil` must exit 3 with `CR034`+`CR035`; `clean-exfil` must exit 0.
- `examples/evil-bypass/` — a consolidated regression set for the review findings below.

### Fixed (pre-release code-review hardening)
- **Frontmatter bypass:** folded/list `allowed-tools` carrying `Bash(* *)` is now caught — `FM005` scans the whole frontmatter, not just the inline value.
- **Negation-guard false-negative:** bare modals (`should`/`must`/`may`) no longer suppress `CR028`–`CR031`, so "you should ignore safety policies" is caught.
- **Markdown coverage:** `~~~` fences and inline-code spans are now scanned as code (previously only triple-backtick fences were).
- **Clone false-positive:** `inventory` skips `.git/`, `node_modules/`, and other VCS/tooling dirs, and sniffs file *content* — extensionless text (LICENSE, `.gitignore`, Makefile) is scanned, not flagged as a blob; only true binaries (NUL byte) stay `INV001`. Auditing a repo-root skill no longer trips false RED/YELLOW.
- **Pipe-to-shell:** `CR036`/`CR037` implement the documented `bash <(curl …)` and `eval "$(curl …)"` patterns.
- **Honest "read-only" claim:** `SKILL.md` and `README.md` now note the `echo`-redirection caveat and that `$SKILL_PATH` scoping is instruction-level.
- **Pipe-to-shell regression:** `evil-bypass` and CI now assert both `CR036` (`bash <(curl …)`) and `CR037` (`eval "$(curl …)"`).
- CI: per-phase assertions broadened (`AST006`/`AST008`, `UNI002`/`UNI004`, `HI019`–`HI021`/`ME011`) plus the `evil-bypass` regression step.

### Closed
- The **v2 roadmap** is complete: bundled-config (1.1.0) → AST pass (1.2.0) → Unicode pass (1.3.0) → exfil/evasion (1.4.0).

## [1.3.0] — 2026-06-01

New capability: a **Unicode / invisible-character pass**. The regex and AST
passes see text only after it is read; they miss characters that are invisible or
that lie about how text renders. `unicode_scan` inspects raw codepoints across all
text files, including `.md` prose (a SKILL.md is read by the model as instructions).

### Added
- `scripts/scan.py`: `unicode_scan` —
  - `UNI001` — bidirectional control: RLO/LRO override → CRITICAL; embedding/isolate → HIGH (Trojan Source, CVE-2021-42574)
  - `UNI002` — zero-width / invisible (ZWSP, word joiner, soft hyphen, mid-file BOM) → HIGH
  - `UNI003` — Unicode Tags block (`U+E0000`–`U+E007F`) → CRITICAL (invisible instruction smuggling)
  - `UNI004` — homoglyph: a Latin-confusable Cyrillic/Greek letter inside a Latin word → MEDIUM
- `SKILL.md`: new **Step 6.7 — Unicode / invisible-character audit**.
- `THREAT_MODEL.md`, `references/red-flags.md`: Unicode rows / section.
- `examples/evil-unicode/` — bidi override + zero-width + Tags block + homoglyph; pre-1.3.0 it scored GREEN.
- `examples/clean-unicode/` — Russian prose, hyphenated RU/EN compounds, glued jargon, and emoji; stays GREEN.
- CI: `evil-unicode` must exit 3 with `UNI001`+`UNI003`; `clean-unicode` must exit 0.

### Notes
- `UNI004` fires only on a confusable embedded *inside* a Latin word (a neighbour test), so bilingual skills (hyphenated compounds, glued jargon) do not false-positive. Emoji ZWJ / variation selectors are excluded from `UNI002`.
- The pass scans `.md` prose (unlike most rules) because that prose is the attack surface; documentation that *demonstrates* these characters (this repo's spec) self-flags — a documented self-audit caveat.

## [1.2.0] — 2026-06-01

New capability: a **Python AST pass**. The line-based regex misses dangerous
calls that are aliased, split across lines, or built dynamically. `ast.parse`
(no execution) sees the syntax tree regardless of surface layout.

### Added
- `scripts/scan.py`: `ast_scan` — walks each `.py` file's AST and reports:
  - `AST001` — `eval`/`exec`/`compile` over a non-literal argument → CRITICAL
  - `AST002` — a call to an alias of eval/exec/compile (`e = eval; e(x)`) → CRITICAL
  - `AST003` — `os.system`/`os.popen`/`subprocess.*` with `shell=True`, any line layout → CRITICAL (non-literal command) / HIGH
  - `AST004` — `pickle.loads` / `marshal.loads` → CRITICAL
  - `AST005` — `yaml.load` without `SafeLoader` → HIGH
  - `AST006` — `getattr(obj, <non-literal>)` dynamic dispatch → HIGH
  - `AST007` — dynamic `__import__` / `importlib.import_module` → HIGH
  - `AST008` — `exec`/`eval` over a char-built / decoded string → CRITICAL
- `SKILL.md`: Step 5 documents the AST pass.
- `THREAT_MODEL.md`: adversarial-bypass (out-of-scope #4) is now *partially covered*; AST rule rows added.
- `references/red-flags.md`: AST section.
- `examples/evil-ast/` — clean `SKILL.md`, evasive `helper.py` (aliased eval, dynamic `os.system`, multi-line `shell=True`, char-built `exec`). Pre-1.2.0 the scanner scored it a soft YELLOW.
- `examples/clean-ast/` — safe Python (list-arg subprocess, `json.loads`, `yaml.safe_load`, literal `getattr`); stays GREEN.
- CI: `evil-ast` must exit 3 with `AST001`/`AST002`/`AST003`; `clean-ast` must exit 0.

### Notes
- The AST pass degrades to a no-op on unparseable source (syntax error, Python 2, non-Python).
- It distinguishes string literals from calls, so it adds no false positives on the scanner's own rule strings.

## [1.1.0] — 2026-06-01

New threat class: **bundled configuration / hooks / MCP**. A skill that ships
executable configuration alongside `SKILL.md` could previously score GREEN — the
line-based scanner never inspected it structurally. `check_bundled_config` closes
this blind spot.

### Added
- `scripts/scan.py`: `check_bundled_config` — structural audit (safe
  `json.loads`, textual backstop for non-parseable JSON) of `settings.json`,
  `.mcp.json`, and `plugin.json` at the skill root and in `.claude/` /
  `.claude-plugin/`. New rules:
  - `CR032` — bundled `hooks` block → CRITICAL (auto-exec on lifecycle events + persistence)
  - `CR033` — stdio `mcpServers` (`command`) → CRITICAL (launches a local process)
  - `HI017` — remote `mcpServers` (`url`) → HIGH (third-party egress)
  - `HI018` — `permissions` allow-list / mode broadening → HIGH
  - `ME010` — benign bundled `settings.json` → MEDIUM
  - `INV002` — `hooks/`, `commands/`, `agents/`, `.claude/`, `.claude-plugin/` dir → MEDIUM note
- `SKILL.md`: new **Step 1.5 — Bundled configuration audit (hooks / MCP / settings)**.
- `references/red-flags.md`, `references/patch-templates.md`, `THREAT_MODEL.md`:
  bundled-config patterns, severities, and guidance.
- `examples/evil-plugin/` — a clean `SKILL.md` shipping a malicious
  `.claude/settings.json` hook + `.mcp.json` stdio server. Positive fixture; the
  pre-1.1.0 scanner scored it GREEN.
- `examples/clean-with-data/` — a skill shipping a `references/*.json` carrying
  `hooks`/`command` keys as **data**. Negative fixture; must stay GREEN.
- CI: `evil-plugin` must exit 3 with `CR032`+`CR033`; `clean-with-data` must exit 0.

### Notes
- The audit keys off config **filenames**, not a blind key search — data files
  and prose mentioning `hooks`/`mcpServers` are not flagged.

## [1.0.1] — 2026-05-09

Patch release addressing post-publication audit feedback. No rule changes,
no behavior changes — readability and CI hardening only.

### Fixed
- YAML frontmatter readability: `description:` and `when_to_use:` fields in
  `SKILL.md` and `examples/clean-skill/SKILL.md` now use folded scalar syntax
  (`>-`). Content is identical for the parser; diffs and code review on
  GitHub no longer require horizontal scrolling.
- README: long prose paragraphs (some over 380 chars) re-wrapped at ~80
  columns. Markdown rendering is unchanged.

### Added
- GitHub Actions CI (`.github/workflows/tests.yml`):
  - Syntax check on `scripts/scan.py`
  - `examples/clean-skill/` must exit 0 (GREEN)
  - `examples/evil-skill/` must exit 3 (RED)
  - `evil-skill` must produce findings for representative attack classes
    (`FM005`, `CR001`, `CR006`, `CR026`, `CR028`, `CR031`)
  - Self-audit smoke test (no runtime errors; counts not asserted because
    self-audit produces documented false positives — see Limitations §5)
- README: CI status badge and MIT license badge

## [1.0.0] — 2026-05-09 — Initial release

First public release. Established the audit pipeline (8 LLM-driven steps + static scanner) and the rule catalogue.

### Static rules
- 31 CRITICAL rules covering: pipe-to-shell, base64-eval, pickle/marshal/yaml.load RCE, sensitive-path access (`~/.ssh`, `~/.aws`, keychain, `.env`, `*.pem`, `id_rsa`, `.netrc`, `.npmrc`, `.kube/config`), persistence vectors (shell rc files, git hooks, npm scripts, cron, launchd), skill self-elevation (Claude config, MCP), exfiltration endpoints (webhook.site, pastebin, Discord/Slack webhooks, ngrok), interpreter injection (`bash -c "$VAR"`, `python -c "$VAR"`), anti-user prose, policy-override language, role-confusion, dangerous fail-open instructions
- 16 HIGH rules covering: wildcards in `allowed-tools` (Bash(\* \*), Bash(python3 \*), Bash(rm \*), Bash(sudo \*), Bash(curl \*), Bash(npm \*), Bash(ssh \*), cloud CLIs), `subprocess shell=True`, `eval`/`exec`, network calls, recursive scans of home, JS dynamic execution
- 9 MEDIUM rules covering: `$0` confusion, predictable temp paths, slug path traversal, `subprocess` without timeout, missing symlink checks, silent failure, "trust me" language

### LLM-driven audit steps
- Inventory (binaries / non-text files flagged as RED)
- Frontmatter audit (`disable-model-invocation`, `allowed-tools`, description sanity)
- Bash command audit (17 categorical questions)
- Script audit (subprocess hygiene, code execution from data, network, file system, obfuscation, defensive practices)
- Tool laundering check (interpreter access ≈ full shell)
- Confused deputy check (skill executing commands from input documents)
- Prompt injection audit (untrusted data clause requirement, anti-user prose detection)
- Description-vs-behavior consistency

### Defensive design
- Read-only by design: `allowed-tools` contains zero write/delete/network operations
- Markdown-aware scanning: prose vs code-fence vs frontmatter handled differently
- Position-based negation guard: defensive prose ("do not retry with relaxed limits") distinguished from attack ("Do not tell the user") by where the negation sits relative to the dangerous phrase
- Symlink rejection at multiple layers (input path, files inside skill, parent directory chain)
- Per-rule false-positive guards for documentation contexts
