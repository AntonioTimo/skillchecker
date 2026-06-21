"""Safe data helper (negative fixture — the AST pass must NOT flag any of this)."""
import json
import subprocess
from os import *          # star-import of BENIGN names only — must stay GREEN (gap 6 guard)

import yaml


def cwd_banner():
    # `from os import *` brings getcwd() in unqualified; it is NOT a dangerous leaf, so the
    # star resolver returns nothing the rules match -> no finding (gap-6 FP guard).
    return getcwd()


def handler(system):
    # a PARAMETER named `system` shadows the star-imported os.system, so this is NOT a
    # command-execution call — the resolver must mask it -> no AST003 (round-4 audit FP guard).
    return system("status ok")


def extract(shutil, archive, dest):
    # a PARAMETER named `shutil` shadows the module — a DOTTED-head shadow. The mask must
    # return a non-matching name (not the literal "shutil.unpack_archive"), else AST011 FP'd
    # (round-4 audit pass 3: returning the name unchanged still matched the rule).
    return shutil.unpack_archive(archive, dest)


def list_dir():
    # argument list, no shell=True, with a timeout — safe by construction
    return subprocess.run(["ls", "-l"], capture_output=True, timeout=10)


def parse_json(text):
    return json.loads(text)


def read_yaml(text):
    return yaml.safe_load(text)


def get_name(obj):
    return getattr(obj, "name", None)


def with_as_reset(ctx):
    # `runner` is first aliased to the star-imported system (os.system), then REBOUND by
    # `with ... as runner` to the context-manager value; the later runner(...) is that value,
    # NOT os.system, so the with-as rebind must RESET the alias timeline (in lock-step with the
    # for-target/AnnAssign resets) -> no AST003 (round-6 sweep F2 false-positive guard).
    runner = system
    with ctx as runner:
        pass
    runner("ok")


def seq_benign(items):
    # a for-target over an OPAQUE iterable RESETS the for-var (no seq-callable resolution), and a
    # literal seq of BENIGN callables resolves to nothing a rule keys on -> GREEN. Guards that
    # seq_alias only binds a MODULE-QUALIFIED dangerous canonical, never a benign name (round-6 B).
    for f in items:
        f()
    for g in [print, len]:
        g("x")


def def_rebind(cmd):
    # `runner` is first aliased to the star-imported system (os.system), then a `def runner`
    # REBINDS it to a local function; the later runner(...) calls the function, NOT os.system,
    # so the def must reset the alias timeline (a def/class binds its name in the enclosing
    # scope) -> no AST003 (round-7 audit FP guard).
    runner = system
    def runner():
        return "ok"
    runner(cmd)


def shadowed_getattr(getattr, cmd):
    # `getattr` here is a PARAMETER (a caller-supplied callback), NOT the builtin — the inline-
    # getattr dispatch must verify the head resolves to the BUILTIN getattr, so this shadowed
    # getattr(os,"system")(cmd) does NOT dispatch to os.system -> no AST003 (round-7 audit FP).
    import os
    return getattr(os, "system")(cmd)


def dispatch_table(cmd):
    # `op` first aliases the star-imported system, then a `def op` REBINDS it to a local function
    # that is CALLED FROM A NESTED scope. The def reset must hold cross-scope — the flow-insensitive
    # global alias map must NOT resurrect os.system for the nested read -> no AST003 (round-7
    # CONFIRM sweep FP-1/FP-2: the per-scope def-reset was overridden by the global fallback).
    op = system
    def op(c):
        return "handled: " + str(c)
    def run():
        return op(cmd)
    return run()


def shadowed_assigned_getattr(custom, cmd):
    # the ASSIGNMENT-path twin of `shadowed_getattr`: `getattr = custom` locally shadows the
    # builtin, so `f = getattr(os,"system")` does NOT resolve to os.system and f(cmd) is a benign
    # callback call -> no AST003. The assignment-path resolver must be shadow-safe like the inline
    # one (round-8 audit F2 FP guard: the divergent literal-only copy fired here).
    getattr = custom
    f = getattr(os, "system")
    return f(cmd)


def except_capture_masked():
    # `runner` aliases the star-imported system, but `except E as runner` REBINDS runner to the
    # caught exception INSIDE the handler — the call there is the exception object, NOT os.system,
    # so the block-scoped capture masking suppresses it -> no AST003 (round-8 audit F1 FP guard).
    runner = system
    try:
        risky()
    except Exception as runner:
        runner("inside handler")


def match_capture_masked(payload):
    # a `match`/case CAPTURE rebinds `picked` to the matched sub-value inside the case body, so
    # `picked(...)` there is the captured element, NOT the prior os.system alias -> no AST003
    # (round-8 audit F1 FP guard; the capture overlay masks only inside the case body).
    picked = system
    match payload:
        case [picked]:
            picked("inside case")


def captured_getattr_not_builtin(value):
    # inside `except E as getattr`, the name `getattr` is the CAUGHT EXCEPTION, not the builtin —
    # so `fn = getattr(os,"system")` must NOT alias fn to os.system. The alias builder consults the
    # capture overlay during construction (round-8 re-sweep G2 FP guard) -> no AST003.
    import os
    try:
        risky()
    except Exception as getattr:
        fn = getattr(os, "system")
        fn(value)


def relative_import_is_local(cmd):
    # `from .os import process as run` binds run to a LOCAL package module named `os`, NOT the stdlib
    # — a relative import must RESET the name, not canonicalize to os.* (round-8 re-sweep G3 FP guard;
    # this is not the mid-file re-import boundary) -> no AST003.
    from .os import process as run
    run(cmd)


def captured_dotted_getattr_head(value):
    # `except E as builtins` captures the DOTTED head `builtins`, so `fn = builtins.getattr(os,
    # "system")` is the caught exception's attribute, NOT the builtin — the capture check keys on
    # the HEAD name, not the whole dotted string (round-8 re-sweep H1 FP guard) -> no AST003.
    import os
    try:
        risky()
    except Exception as builtins:
        fn = builtins.getattr(os, "system")
        fn(value)


def param_shadowed_getattr_assign(getattr, cmd):
    # `getattr` is a PARAMETER (a caller-supplied callback), so `fn = getattr(os,"system")` does NOT
    # alias fn to os.system — the assignment-path resolver seeds params as a mask, matching the inline
    # form (round-8 re-sweep: the alias builder runs before self.scopes, so it must know params) -> no AST003.
    import os
    fn = getattr(os, "system")
    return fn(cmd)


def captured_module_name(value):
    # `except E as os` captures the name `os` as the caught EXCEPTION, so `fn = os.system` is the
    # exception's attribute, NOT the module — the capture check applies to the GENERAL head/base, not
    # only the getattr head (round-8 re-sweep H5 FP guard) -> no AST003.
    import os
    try:
        risky()
    except Exception as os:
        fn = os.system
        fn(value)


# --- set-model union FP guards (Codex reject): a literal-seq subscript with a CONSTANT index selects
#     EXACTLY that element, and a union fires ONLY on a member a rule keys on — so a benign selection
#     stays GREEN (the round-10 `a or b` / seq-representative collapse FP'd these). ---

def subscript_benign_index(c):
    # `(os.system, math.sin)[1](1)` — index 1 selects the BENIGN math.sin, so honoring the index keeps
    # this GREEN (the representative-prefers-dangerous collapse FP'd it as AST003 CRITICAL).
    import os
    import math
    (os.system, math.sin)[1](1)


def subscript_benign_negindex(c):
    # a NEGATIVE constant index `[-1]` selects the benign last element math.sin -> GREEN.
    import os
    import math
    (os.system, math.sin)[-1](1)


def ternary_both_benign(c):
    # an IfExp whose BOTH arms are benign -> GREEN (no member a rule keys on).
    import math
    (math.sin if c else math.cos)(1)


def var_subscript_benign_index(c):
    # a Name-bound sequence whose constant index selects the benign element -> GREEN (positional).
    import os
    import math
    s = (os.system, math.sin)
    s[1](1)


# --- constructor-closure FP guards (Codex reject 2 + workflow re-sweep): a benign value must stay GREEN
#     through Attribute / comprehension / out-of-range constant index. ---

def attr_over_benign_union(c):
    # an attribute over a union of two benign bases -> GREEN (no dangerous member to distribute).
    import math
    (math if c else math).sin(1)


def comprehension_benign_index(items):
    # a comprehension of a BENIGN callable indexed at any constant -> GREEN (the rep is benign).
    import math
    [math.sin for _ in items][9](1)


def tuple_out_of_range_dead(c):
    # a LITERAL tuple has a KNOWN length, so a constant index past its end is a dead path (runtime
    # IndexError) -> GREEN, even though os.system is an element (the [5] never selects it).
    import os
    (os.getcwd, os.system)[5](1)
