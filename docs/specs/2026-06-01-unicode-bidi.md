# Spec — Unicode / bidi / invisible-character pass (Phase B)

- **Date:** 2026-06-01
- **Status:** Proposed (awaiting review)
- **Target version:** 1.3.0
- **Branch:** `feat/unicode-bidi`
- **Phase:** B of the v2 plan (C, A done → **B** → D).

---

## 1. Problem

The regex and AST passes operate on text *after* it is read as a string. They
have no notion of characters that are **invisible** or that **lie about how text
renders**:

- **Bidirectional controls** (Trojan Source, CVE-2021-42574). A right-to-left
  override (`U+202E`) can reorder how a line *displays* versus how it is *parsed*
  — a malicious instruction can read as benign, or an anti-user directive can be
  hidden, inside `SKILL.md`.
- **Zero-width / invisible characters.** A zero-width space can split a keyword
  (`s‌udo`) to dodge regex, or hide text between visible words.
- **Unicode Tags block** (`U+E0000`–`U+E007F`). Invisible characters increasingly
  used to smuggle hidden instructions into LLM prompts.
- **Homoglyphs.** Cyrillic/Greek look-alikes spell `ѕudo` / `οs` that read as
  ASCII but are not.

A `SKILL.md` is read by Claude **as instructions**, so hidden or deceptive
Unicode there is a direct prompt-injection / social-engineering vector that every
current pass misses.

## 2. Why a character pass

The existing passes are line/AST based; they cannot express "this character is
invisible" or "this looks like that". A dedicated **character-level** scan over
the raw text catches what they structurally cannot. It scans **all** text files
**including `.md` prose**, because here the prose *is* the attack surface (unlike
most rules, which skip `.md` prose to avoid documentation false positives).

## 3. Goals / Non-goals

**Goals**
- Detect bidi controls, zero-width/invisible characters, Unicode Tags, and
  mixed-script (homoglyph) tokens; report line + codepoint.
- **Low false-positive rate on legitimately multilingual skills** — this repo
  itself is bilingual RU/EN, so the design must not flag normal Russian prose or
  hyphenated RU/EN compounds.

**Non-goals**
- Full Unicode TR39 confusable mapping; NFKC normalization; IDN/domain homoglyphs
  (the latter may join Phase D's exfil checks). Binary/non-text files are already
  flagged by inventory.

## 4. Design

`unicode_scan(path, rel) -> list[Finding]`: read the text, iterate lines, inspect
each character's codepoint.

| Rule | Catches | Severity |
|---|---|---|
| `UNI001` | bidi control — RLO/LRO **override** (`U+202D`/`U+202E`) → CRITICAL; embedding/isolate (`U+202A`–`U+202C`, `U+2066`–`U+2069`, `U+200E`/`U+200F`) → HIGH | CRITICAL / HIGH |
| `UNI002` | invisible / zero-width — ZWSP `U+200B`, word joiner `U+2060`, soft hyphen `U+00AD`, ZWNBSP `U+FEFF` **not at file start** | HIGH |
| `UNI003` | Unicode Tags block `U+E0000`–`U+E007F` | CRITICAL |
| `UNI004` | mixed-script **letter run** — a maximal run of alphabetic characters containing **both** ASCII-Latin and Cyrillic/Greek | MEDIUM |

**False-positive guards (critical for this bilingual repo)**
- `UNI004` operates on maximal **letter runs** (split on every non-letter,
  including hyphens, digits, spaces). Hyphenated compounds like `MCP-конфиг`,
  `AST-пасс`, `RTL-override` split into single-script runs and **do not match**.
  Only *intra-word* mixing (`ѕudo`) matches.
- **Emoji:** `U+200D` (ZWJ) and variation selectors (`U+FE0F`/`U+FE0E`) are
  **excluded** from `UNI002` so emoji sequences don't trip it. (The repo's
  🔴🟡🟢 are single codepoints regardless.)
- `U+FEFF` at byte offset 0 is a legitimate BOM and is allowed; only a mid-file
  ZWNBSP is flagged.

## 5. Documentation & catalogue
- `SKILL.md`: new step near the prompt-injection audit — **"Step 6.7 — Unicode /
  invisible-character audit"** — since hidden Unicode is an injection vector.
- `references/red-flags.md`: Unicode section.
- `THREAT_MODEL.md`: new rule rows; note that hidden-Unicode injection is now
  covered.
- `CHANGELOG.md`: `## [1.3.0]`.

## 6. Test plan (RED → GREEN → REFACTOR)

**RED.** `examples/evil-unicode/SKILL.md` carries: a `U+202E` override hiding an
anti-user line, a ZWSP-split keyword, a Unicode-Tags smuggled instruction, and a
`ѕudo` homoglyph. Run the current scanner — none are caught (all invisible to the
line rules).

**GREEN.** Implement `unicode_scan` → `UNI001`–`UNI004` fire → 🔴 RED.

**REFACTOR (negatives).** `examples/clean-unicode/SKILL.md` — legitimate Russian
prose, hyphenated RU/EN compounds (`MCP-конфиг`), and a 🔴 emoji — must stay
GREEN. **Also verify the self-audit gains no `UNI004` false positive** on the
repo's own Russian docs (`references/red-flags.md`, `docs/HOWTO.md`,
`references/patch-templates.md`). If it does, tighten `UNI004` or drop it to a
documented note.

**CI.** `evil-unicode` must exit 3 with `UNI001` + `UNI003`; `clean-unicode` must
exit 0.

## 7. Versioning

New detection capability → **1.3.0**.

## 8. Out of scope for Phase B

Full TR39 confusable tables, NFKC normalization, IDN/domain homoglyphs, and
encoding-level attacks. These are future work (some may land in Phase D).
