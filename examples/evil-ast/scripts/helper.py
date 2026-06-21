"""Helper for text-processor (example fixture — intentionally evasive).

Every dangerous call here is written so the line-based regex pass misses it.
The AST pass (Phase A) is meant to catch them all.
"""
import os
import subprocess
from os import *          # star-import — every dotted AST rule must still resolve through it


# 0. Star-import alias — `from os import *` brings system() in unqualified; the resolver
#    maps the bare name back to os.system -> AST003 (convergence sweep gap 6).
def shell_star(cmd):
    system(cmd)


# 0b. Global-rebind alias — a module placeholder `dispatch_fn = None` is reassigned to
#     os.system inside a nested function via `global`; the call resolves it via the global
#     alias map -> AST003 (round-4 audit pass 2: a per-scope-only resolver missed it).
dispatch_fn = None


def _configure():
    global dispatch_fn
    dispatch_fn = os.system


def run_configured(cmd):
    dispatch_fn(cmd)


# 1. Aliased eval — HI006 (\beval\s*\() never matches `run(...)`.
run = eval


def execute(payload):
    return run(payload)


# 2. Dynamic dispatch — `os.system` is never written as a literal.
def dispatch(arg):
    name = "sys" + "tem"
    return getattr(os, name)(arg)


# 3. Multi-line shell=True — line-based HI005 never sees the call and
#    shell=True on the same line.
def shell(cmd):
    return subprocess.run(
        cmd,
        shell=True,
        capture_output=True,
    )


# 4. exec fed by a char-built string (via a temp var → AST001, non-literal arg).
def boot(codes):
    src = "".join(chr(c) for c in codes)
    exec(src)


# 5. exec of an inline char-built string → AST008 (constructed-payload exec).
def boot_inline(codes):
    exec("".join(chr(c) for c in codes))


# 6. Tuple-unpack callable alias — `runner, opts = os.system, {}` binds runner to os.system
#    via matched-length tuple pairing; the call resolves it -> AST003 (round-6 sweep F1: the
#    alias timeline + global builder dropped tuple targets while __file__/method-ref handled them).
def tuple_alias(cmd):
    runner, opts = os.system, {}
    runner(cmd)


# 6b. NESTED tuple-unpack alias — recursive matched-length pairing binds b -> os.system (round-6 F3).
def nested_alias(arg):
    (a, (b, c)) = (1, (os.system, 2))
    b(arg)


# 7. for-target over a LITERAL list holding a dangerous callable — seq_alias resolves f to
#    os.system (mirrors the archive seqarch path) -> AST003 (round-6 sweep R6-2).
def seq_callable(cmd):
    for f in [os.system]:
        f(cmd)


# 8. INLINE getattr with a LITERAL attr name — getattr(os,"system")(cmd) is a static dispatch
#    the call site now canonicalizes to os.system -> AST003 (round-6 sweep: only the ASSIGNED
#    `fn = getattr(os,"system")` form fired before; the inline call-as-func was skipped).
def inline_getattr(cmd):
    getattr(os, "system")(cmd)


# 9. BARE AnnAssign (annotation, NO value) does NOT rebind at runtime — `mv: object` after
#    `mv = os.system` PRESERVES the alias, so the call still fires AST003. A reset here was an
#    FN regression (round-6 CONFIRM sweep C19: a no-value AnnAssign is a no-op, lock-step __file__).
def annassign_noval(cmd):
    mv = os.system
    mv: object
    mv(cmd)


# 10. QUALIFIED builtins.getattr(os,"system")(cmd) — the getattr head canonicalizes to the
#     builtin getattr, so the inline-getattr dispatch resolves os.system -> AST003 (round-7 audit:
#     only the bare `getattr` head was recognized; `builtins.getattr` was missed).
def qualified_getattr(cmd):
    import builtins
    builtins.getattr(os, "system")(cmd)


# 11. ASSIGNED builtins.getattr RESULT — `bg = builtins.getattr(os,"system"); bg(cmd)` resolves
#     bg to os.system through the alias timeline's getattr branch. The assignment-path resolver
#     used to match only a LITERAL `getattr(...)`, missing `builtins.getattr` and an aliased
#     getattr (the inline form via _func_canon already handled them) — round-8 audit F2 -> AST003.
def assigned_builtins_getattr(cmd):
    import builtins
    bg = builtins.getattr(os, "system")
    bg(cmd)


# 12. ASSIGNED ALIASED getattr RESULT — `ga = getattr; ax = ga(os,"system"); ax(cmd)` (round-8
#     audit F2: the getattr head is resolved shadow-safely, so an alias to the builtin dispatches).
def assigned_aliased_getattr(cmd):
    ga = getattr
    ax = ga(os, "system")
    ax(cmd)


# 13. except-as BLOCK-SCOPED masking must NOT open a false-NEGATIVE — on the fall-through (no-
#     exception) path the alias is STILL os.system after the handler (Python deletes the except-
#     name only on the CAUGHT path), so the post-block call fires. A naive flat reset would mask
#     this (round-8 audit F1 no-FN witness) -> AST003.
def except_after(cmd):
    run0 = os.system
    try:
        pass
    except Exception as run0:
        pass
    run0(cmd)


# 14. TRANSITIVE alias through an except handler — the prior binding is RESTORED after the block,
#     so dst is os.system again on the fall-through path (round-8 audit F1 no-FN) -> AST003.
def except_transitive_after(cmd):
    src = os.system
    dst = src
    try:
        pass
    except Exception as dst:
        pass
    dst(cmd)


# 15. match-capture masking is BOUNDED to the case body — the capture `hsel` is masked inside the
#     case, but a later `hsel = os.system` rebinds it and the post-match call fires (round-8 audit
#     F1: position-aware restore must not swallow a real later alias) -> AST003.
def match_then_alias(cmd):
    match cmd:
        case [hsel]:
            hsel("noop")
    hsel = os.system
    hsel(cmd)


# 16. WALRUS-bound getattr as the dispatch HEAD — `(g := getattr)(os,"system")(cmd)` resolves the
#     walrus value to the builtin getattr. The head was read via _dotted_name (None for a walrus);
#     it is now resolved via _func_canon, shadow-safely (round-8 re-sweep) -> AST003.
def walrus_getattr_head(cmd):
    (g := getattr)(os, "system")(cmd)


# 17. ASSIGNED walrus-getattr — `wfn = (g := getattr)(os,"system"); wfn(cmd)` runs through the alias
#     timeline's getattr branch, whose head is now walrus-unwrapped too (round-8 re-sweep: the inline
#     _func_canon fix did not cover the assignment-result path in resolve()) -> AST003.
def assigned_walrus_getattr(cmd):
    wfn = (g := getattr)(os, "system")
    wfn(cmd)


# 18. capture-then-REBIND — `except E as getattr` captures the name, but the handler then REBINDS it
#     to the real builtin getattr, so the later `gfn(...)` IS os.system. The capture mask must yield
#     to the in-body rebind (round-8 re-sweep H2) -> AST003.
def capture_then_rebind(cmd):
    import builtins as B
    try:
        risky()
    except Exception as getattr:
        getattr = B.getattr
        gfn = getattr(os, "system")
        gfn(cmd)


# 19. NESTED walrus head — `nwf = (h := (g := getattr))(os,"system"); nwf(cmd)` — the alias builder
#     unwraps walruses RECURSIVELY now (round-8 re-sweep H3: a single-level unwrap missed it) -> AST003.
def nested_walrus_getattr(cmd):
    nwf = (h := (g := getattr))(os, "system")
    nwf(cmd)


# 20. getattr BASE is a bare MODULE ALIAS — `import os as omod; mab = getattr(omod,"system"); mab(cmd)`.
#     The assignment-path base must resolve the bare module alias to its module (round-8 re-sweep:
#     _resolve_import resolved a module alias only as a dotted head, not bare) -> AST003.
def getattr_module_alias_base(cmd):
    import os as omod
    mab = getattr(omod, "system")
    mab(cmd)


# 21. WALRUS as the RHS value / attribute base / getattr base — `wr = (x := os.system); wr(cmd)` and
#     `wb = getattr((m := os), "system"); wb(cmd)`. _dotted_name now unwraps a NamedExpr ANYWHERE in
#     the Name/Attribute chain, not just at the getattr head (round-8 re-sweep one-liner bypass) -> AST003.
def walrus_rhs_alias(cmd):
    wr = (x := os.system)
    wr(cmd)


def walrus_getattr_base(cmd):
    wb = getattr((m := os), "system")
    wb(cmd)
