#!/usr/bin/env python3
"""
skill-checker static scanner — read-only regex pass over a skill directory.

Outputs JSON to stdout. The Claude-side audit reads this JSON, contextualizes
findings against surrounding code, and produces a final verdict.

Severities:
  CRITICAL — typically malicious; pushes verdict to RED.
  HIGH     — dangerous if used carelessly; multiple HIGHs → RED, otherwise YELLOW.
  MEDIUM   — sloppy; YELLOW.
  LOW      — quality issue; noted, not blocking.

This script never executes any file from the audited skill.
It opens files for read only. No subprocess, no network, no writes.
"""

import json
import os
import re
import sys
from dataclasses import dataclass, asdict
from pathlib import Path

# Files we examine. Anything else is reported as "unaudited file"
# and the Claude-side review treats binaries / blobs as a strong RED signal.
TEXT_EXTENSIONS = {".md", ".py", ".sh", ".bash", ".zsh", ".js", ".ts",
                   ".mjs", ".cjs", ".yml", ".yaml", ".json", ".toml"}

# Maximum size we scan per file. Anything larger gets a LOW finding —
# legitimate skill code shouldn't be huge, and a 5MB blob is suspicious on its own.
MAX_SCAN_BYTES = 1 * 1024 * 1024   # 1 MB


@dataclass
class Finding:
    severity: str       # CRITICAL | HIGH | MEDIUM | LOW
    rule_id: str
    file: str           # relative path inside the skill dir
    line: int
    snippet: str
    why: str
    suggested_fix: str = ""


# --------------------------------------------------------------------------
# Rule set. Each tuple: (rule_id, severity, regex, why, suggested_fix)
# --------------------------------------------------------------------------

CRITICAL_RULES = [
    ("CR001", r"curl\s+[^\n|;]*\|\s*(?:sh|bash|zsh|python\d?|perl|ruby)\b",
     "pipe-to-shell: downloads and executes remote code at runtime",
     "Refuse. Patching this is not enough — the skill is asking to run unaudited remote code."),

    ("CR002", r"wget\s+[^\n|;]*\|\s*(?:sh|bash|zsh|python\d?|perl|ruby)\b",
     "pipe-to-shell via wget",
     "Refuse."),

    ("CR003", r"\bbase64\s+(?:-d|--decode|-D)\s*[|<]",
     "base64-decoded payload piped or fed into another process — classic obfuscation",
     "Refuse. Ask the author what's being decoded; until inspected, treat as malicious."),

    ("CR004", r"\beval\s*\(\s*(?:base64|codecs|bytes\.fromhex|''.join)",
     "eval() over decoded data — payload obfuscation",
     "Refuse."),

    ("CR005", r"\bexec\s*\(\s*(?:base64|codecs|bytes\.fromhex|''.join|chr\(\s*\d)",
     "exec() over decoded/constructed data — payload obfuscation",
     "Refuse."),

    ("CR006", r"(?:~|\$HOME|os\.path\.expanduser\([\"']~[\"']\))[^\n]*\.ssh\b",
     "access to ~/.ssh — private keys, authorized_keys",
     "Refuse unless the skill is explicitly an SSH helper and clearly documented."),

    ("CR007", r"(?:~|\$HOME)[^\n]*\.aws\b",
     "access to ~/.aws — AWS credentials",
     "Refuse unless skill is explicitly an AWS helper."),

    ("CR008", r"(?:~|\$HOME)[^\n]*\.(?:gnupg|gpg)\b",
     "access to GPG keys",
     "Refuse unless explicitly a GPG helper."),

    ("CR009", r"\bauthorized_keys\b",
     "writes/reads SSH authorized_keys — persistence vector",
     "Refuse."),

    ("CR010", r"\b(?:crontab|launchctl\s+load|launchd|/etc/cron|LaunchAgents/)",
     "persistence install (cron / launchd / LaunchAgents)",
     "Refuse."),

    ("CR011", r"/etc/(?:passwd|shadow|sudoers|hosts)\b",
     "access to system identity / sudo files",
     "Refuse."),

    ("CR012", r"~/\.(?:bash|zsh)_history\b",
     "reads shell history — credential harvesting",
     "Refuse."),

    ("CR013", r"\bsecurity\s+(?:find-internet-password|find-generic-password|dump-keychain)\b",
     "macOS keychain extraction",
     "Refuse."),

    ("CR014", r"~/Library/(?:Keychains|Cookies|Application Support/Google/Chrome|Application Support/Firefox)",
     "browser profile / keychain access",
     "Refuse unless explicitly a browser-data helper."),

    ("CR015", r"\bpickle\.loads\s*\(",
     "pickle.loads on external data is RCE",
     "Replace with json or another safe format."),

    ("CR016", r"\bmarshal\.loads\s*\(",
     "marshal.loads is RCE",
     "Replace with safe format."),

    ("CR017", r"yaml\.load\s*\((?![^)]*Loader\s*=\s*(?:yaml\.)?(?:Safe|safe_))",
     "yaml.load without SafeLoader — RCE on malicious YAML",
     "Use yaml.safe_load(...)."),

    ("CR018", r"\bsubprocess\.[A-Za-z_]+\([^)]*shell\s*=\s*True[^)]*[+%]",
     "subprocess shell=True with string concatenation — command injection",
     "Pass arguments as a list and remove shell=True."),

    ("CR019", r"\bos\.system\s*\([^)]*[+%]",
     "os.system with concatenated input — command injection",
     "Use subprocess.run with an argument list."),

    ("CR020", r"\b(?:sudo|doas)\s+[A-Za-z]",
     "sudo/doas in skill code — privilege escalation, almost never legitimate",
     "Refuse. A skill should not require root."),

    ("CR021", r"\b(?:pip|pip3|npm|npx|brew|cargo|gem|go|poetry)\s+(?:install|add|exec|i\b)",
     "Package install at runtime — executes third-party code",
     "Refuse. Dependencies should be installed by the user explicitly, not by the skill."),

    ("CR022", r"(?:>>?|tee|echo[^|]*>)\s*(?:~|\$HOME)/\.(?:bashrc|zshrc|profile|bash_profile|zprofile|gitconfig)\b",
     "Writing to shell rc / git config — shell-init persistence",
     "Refuse."),

    ("CR023", r"\.git/hooks/|\.githooks/|core\.hooksPath|npm\s+set-script",
     "Modifying git hooks or npm scripts — supply-chain persistence",
     "Refuse."),

    ("CR024", r"(?:>|>>|tee|cat\s*>|echo[^|]*>|rm\s+-rf?|mv|cp)\s+[^\n]*?(?:~|\$HOME)/\.claude/(?:settings\.json|skills/)|claude_desktop_config\.json|(?:>|>>|tee|cat\s*>)[^\n]*?mcpServers",
     "Writing/deleting in ~/.claude/ or MCP config — skill self-elevation or attack on other skills",
     "Refuse. A skill should never modify Claude config or other skills via shell I/O."),

    ("CR025", r"(?:~|\$HOME|expanduser)[^\n]*?(?:\.env\b|\.env\.|/\.netrc\b|/\.npmrc\b|/\.pypirc\b|/\.kube/config|/\.gcloud/|id_rsa\b|id_ed25519\b|id_ecdsa\b|\.pem\b|\.key\b|credentials\.json)",
     "Access to credential / secret files",
     "Refuse unless skill is explicitly a credential helper and this is documented."),

    ("CR026", r"(?:webhook\.site|requestbin|pastebin\.com|paste\.rs|discord\.com/api/webhooks|hooks\.slack\.com|ngrok\.io|ngrok-free\.app|burpcollaborator|interactsh)",
     "Known exfiltration endpoint — data leakage to attacker-controlled service",
     "Refuse."),

    ("CR027", r"(?:bash|sh|zsh|python\d?|node|ruby|perl)\s+-(?:c|e)\s+[\"']?\$\{?[A-Z_a-z]",
     "Interpreter -c/-e with variable input — command injection",
     "Pass arguments to a script file, not via -c with a variable."),

    ("CR028", r"(?i)(?:do\s+not|don'?t|never)\s+(?:tell|inform|notify|disclose|show|reveal|mention)\s+(?:the\s+)?user",
     "Anti-user instruction — skill is asking the model to hide its actions from the user",
     "Refuse. This is a strong signal of malicious intent."),

    ("CR029", r"(?i)(?:ignore|bypass|disable|override)\s+(?:safety|security|policy|restrictions?|warnings?|guardrails?)|developer\s+mode|jailbreak\s+mode",
     "Policy override / jailbreak language — skill asks the model to disregard safety rules",
     "Refuse."),

    ("CR030", r"(?i)(?:retry|continue)\s+with\s+(?:relaxed|less[\s-]restrictive|reduced|no)\s+(?:limits?|checks?|validation)|if\s+blocked[,\s]+use\s+sudo|sanitize\s+and\s+continue",
     "Dangerous retry / fail-open behavior",
     "Refuse. Skills should fail closed."),

    ("CR031", r"(?i)(?:treat|use)\s+(?:the\s+)?(?:document|file|input|book|content)\s+as\s+(?:system\s+)?instructions|follow\s+(?:the\s+)?instructions\s+(?:in|inside)\s+(?:the\s+)?(?:document|file|input)",
     "Role confusion — skill asks the model to treat untrusted input as instructions",
     "Refuse. This is the prompt-injection vulnerability the skill should be defending against, not enabling."),
]

HIGH_RULES = [
    ("HI001", r"^allowed-tools:[^\n]*Bash\(\s*\*\s*\*\s*\)",
     "Bash(* *) is unrestricted shell access",
     "Narrow to specific commands the skill actually needs."),

    ("HI002", r"Bash\(\s*python\s*\*\s*\)|Bash\(\s*python3\s*\*\s*\)",
     "Bash(python3 *) lets the model run arbitrary Python (including python3 -c \"...\") — effectively RCE",
     "Narrow to the specific script: Bash(python3 ~/.claude/skills/<name>/scripts/<file>.py *)"),

    ("HI003", r"Bash\(\s*(?:rm|sudo|sh|bash|zsh)\s*\*",
     "Wildcard rm/sudo/shell allowed",
     "Narrow to specific paths/operations the skill actually needs, or remove."),

    ("HI004", r"Bash\(\s*curl\s*\*|Bash\(\s*wget\s*\*",
     "Wildcard curl/wget — exfiltration potential if combined with read-access",
     "Restrict to specific URLs or remove if skill should be offline."),

    ("HI005", r"\bsubprocess\.[A-Za-z_]+\([^)]*shell\s*=\s*True",
     "subprocess shell=True (no string concat detected, but still risky)",
     "Use argument list; drop shell=True."),

    ("HI006", r"\beval\s*\(",
     "eval over potentially non-literal input",
     "Verify input is hard-coded; otherwise replace with explicit parsing."),

    ("HI007", r"\bexec\s*\(",
     "exec over potentially non-literal input",
     "Verify input is hard-coded; otherwise refuse."),

    ("HI008", r"\b__import__\s*\([^)]*[+%]",
     "__import__ with concatenated string — likely obfuscation",
     "Use static imports."),

    ("HI009", r"\b(?:urllib\.request\.urlopen|requests\.(?:get|post|put|patch|delete)|httpx\.|aiohttp\.|socket\.connect)\s*\(",
     "Network call — verify destination is hard-coded and trusted",
     "If destination is user-controllable or sends local data outbound, refuse."),

    ("HI011", r"Bash\(\s*(?:sudo|chmod|chown|su|doas)\s*\*",
     "Wildcard sudo/chmod/chown in allowlist",
     "Remove. Skills should not need privilege/permission management."),

    ("HI012", r"Bash\(\s*(?:npm|pip|pip3|npx|brew|cargo|gem|poetry)\s*\*",
     "Wildcard package-manager in allowlist — installs untrusted code",
     "Remove. Dependencies should be installed by the user, with explicit versions."),

    ("HI013", r"Bash\(\s*(?:ssh|scp|nc|netcat|rsync)\s*\*",
     "Wildcard network-transfer tool in allowlist — exfiltration vector",
     "Remove unless the skill is a network helper and this is documented."),

    ("HI014", r"Bash\(\s*(?:gh|gcloud|aws|az|kubectl|docker|git\s+push)\s*\*",
     "Wildcard cloud/git-push allowlist — can push local data outbound",
     "Narrow to the specific subcommand the skill needs, or remove."),

    ("HI015", r"\b(?:find\s+(?:~|\$HOME|/)|grep\s+-[A-Za-z]*[Rr][A-Za-z]*\s+(?:~|\$HOME)|ls\s+-[A-Za-z]*[Rr][A-Za-z]*\s+(?:~|\$HOME))",
     "Recursive scan of home or root filesystem — over-broad, often credential-harvesting",
     "Limit scans to the specific project / input directory."),

    ("HI016", r"\bFunction\s*\(|\bBuffer\.from\s*\([^)]*[\"']base64[\"']\s*\)|\bvm\.runIn",
     "JavaScript dynamic code execution / base64 decode — common obfuscation pattern",
     "Refuse if used over non-literal input."),
]

MEDIUM_RULES = [
    ("ME001", r"\$0\b",
     "$0 is the script name, not the first argument — likely confused with $1",
     "Use $1 (and $2 for the second argument). Bind to named variables: BOOK_PATH=\"$1\"."),

    ("ME002", r"/tmp/[A-Za-z0-9_-]+(?!\.X{3,}|\.\$\{)",
     "Predictable /tmp path — should use mktemp -d",
     "Replace with WORKDIR=$(mktemp -d /tmp/<skill>.XXXXXX) and pass via env."),

    ("ME003", r"~/\.claude/skills/\$\{?[A-Z_a-z]+\}?",
     "User-supplied slug interpolated into ~/.claude/skills/ path without validation",
     "Validate against ^[a-z0-9][a-z0-9-]{1,63}$ and reject otherwise."),

    ("ME004", r"\bsubprocess\.run\((?![^)]*timeout\s*=)",
     "subprocess.run without timeout — can hang indefinitely",
     "Add timeout= parameter."),

    ("ME005", r"\bopen\s*\(\s*[^,)]+\s*,\s*[\"']w",
     "open(<var>, 'w') — verify the path is validated and not user-controllable",
     "Add path validation; check for symlinks before write."),

    ("ME006", r"^description:[^\n]{0,30}$",
     "description field is suspiciously short",
     "A skill description should clearly state what the skill does."),

    ("ME007", r"^when_to_use:\s*$",
     "when_to_use is empty — skill won't trigger automatically",
     "Add 5–15 trigger phrases describing typical user requests."),

    ("ME008", r"(?:rm\s+-rf|curl|wget|ssh|scp)[^\n]*\s+2>\s*/dev/null|(?:rm\s+-rf|curl|wget|ssh|scp)[^\n]*\|\|\s*true\b",
     "Destructive or network command with stderr suppressed / fail-open",
     "Drop the suppression — errors should surface, not be hidden."),

    ("ME009", r"(?i)(?:trust\s+me|this\s+is\s+safe|no\s+need\s+to\s+(?:inspect|review|check)|these\s+permissions\s+are\s+required|don'?t\s+worry\s+about)",
     "'Trust me' language — manipulation; safety should be argued from concrete constraints",
     "Replace with specific justifications for each permission requested."),
]

LOW_RULES = [
    ("LO001", r"#\s*TODO|#\s*FIXME|#\s*XXX|#\s*HACK",
     "Unfinished code marker",
     "Resolve before publishing."),

    ("LO002", r"print\([\"'][^\"']{200,}",
     "Very long literal print — possible debug residue or padding",
     "Trim or remove."),
]

ALL_RULES = (
    [(r[0], "CRITICAL", r[1], r[2], r[3]) for r in CRITICAL_RULES] +
    [(r[0], "HIGH", r[1], r[2], r[3]) for r in HIGH_RULES] +
    [(r[0], "MEDIUM", r[1], r[2], r[3]) for r in MEDIUM_RULES] +
    [(r[0], "LOW", r[1], r[2], r[3]) for r in LOW_RULES]
)


def scan_file(path: Path, root: Path) -> list[Finding]:
    """Open a file and run every rule's regex against each line.

    For .md files, only lines inside code-fence blocks (```...```) are scanned,
    because that's the only place where executable instructions live. Inline-code
    in prose (single backticks) is documentation — examples of patterns being
    discussed, not patterns being executed. Without this, a skill that documents
    its own threat model triggers itself.
    """
    rel = path.relative_to(root).as_posix()
    findings: list[Finding] = []

    try:
        size = path.stat().st_size
    except OSError as e:
        findings.append(Finding(
            severity="LOW", rule_id="IO001", file=rel, line=0,
            snippet="", why=f"could not stat: {e}",
        ))
        return findings

    if size > MAX_SCAN_BYTES:
        findings.append(Finding(
            severity="LOW", rule_id="LO003", file=rel, line=0,
            snippet=f"<{size} bytes>",
            why=f"file is unusually large ({size} bytes); inspect manually",
        ))
        return findings

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        findings.append(Finding(
            severity="LOW", rule_id="IO002", file=rel, line=0,
            snippet="", why=f"could not read: {e}",
        ))
        return findings

    lines = text.splitlines()
    is_markdown = path.suffix.lower() == ".md"
    in_code_fence = False
    in_frontmatter = False
    saw_frontmatter_start = False

    # These rules target instruction-injection patterns. They live in PROSE,
    # not in code — that's the whole point. So for .md files we still scan
    # them outside code-fence blocks, unlike the rest.
    PROSE_TARGETING = {"CR028", "CR029", "CR030", "CR031", "ME009"}

    for i, line in enumerate(lines, start=1):
        # Markdown YAML frontmatter delimiter (--- on its own line).
        # Frontmatter is treated as code, not prose — wildcards in
        # allowed-tools must be scanned by all rules.
        if is_markdown and re.match(r"^---\s*$", line):
            if not saw_frontmatter_start and i <= 2:
                in_frontmatter = True
                saw_frontmatter_start = True
                continue
            if in_frontmatter:
                in_frontmatter = False
                continue

        # Toggle code-fence state for markdown files (only outside frontmatter)
        if is_markdown and not in_frontmatter and re.match(r"^\s*```", line):
            in_code_fence = not in_code_fence
            continue

        # Prose = .md AND not in frontmatter AND not in code-fence.
        # Frontmatter and code-fence both get full scanning.
        is_prose_in_md = (is_markdown and not in_frontmatter
                          and not in_code_fence)

        for rule_id, severity, pattern, why, fix in ALL_RULES:
            # For .md prose: only scan instruction-injection rules. The rest
            # need code context to avoid false positives on documentation.
            if is_prose_in_md and rule_id not in PROSE_TARGETING:
                continue

            try:
                compiled = re.compile(pattern)
            except re.error:
                continue

            if compiled.search(line):
                # Per-rule false-positive guards
                if rule_id == "ME002":
                    if "mktemp" in line:
                        continue
                    if re.search(r"/tmp/[A-Za-z0-9_-]+\.\*", line):
                        continue
                    if re.search(r"(?:PREFIX|prefix)\s*=\s*['\"]/tmp/", line):
                        continue
                if rule_id == "ME004":
                    if line.rstrip().endswith((",", "(", "\\")):
                        continue
                if rule_id in ("CR020", "CR021"):
                    # Skip if match is inside a string literal that's an
                    # error/help message telling the user to install something
                    # — common in scripts (e.g. "ERROR: install poppler with: brew install poppler").
                    stripped = line.lstrip()
                    if (stripped.startswith(('"', "'", "f'", 'f"', '"""', "'''")) or
                        re.search(r"(?:print|stderr|sys\.exit|raise)\s*\(", line) or
                        line.rstrip().endswith(('\\n",', '\\n"', "\\n',", "\\n'"))):
                        continue
                if rule_id in ("CR028", "CR029", "CR030", "CR031"):
                    # Distinguish defensive prose from attack by where the
                    # negation sits. Defensive: negation PRECEDES the dangerous
                    # phrase ("do not retry with relaxed limits", "skill must
                    # never ignore safety"). Attack: dangerous phrase is the
                    # imperative ("Do not tell the user", "Ignore safety").
                    m = compiled.search(line)
                    if m:
                        prefix = line[: m.start()]
                        if re.search(
                            r"(?i)\b(?:do\s+not|don'?t|never|should|must|may|"
                            r"cannot|won'?t|shouldn'?t|mustn'?t|"
                            r"refuse\s+to|reject|forbid|prevent|"
                            r"avoid|skip|stop)\b",
                            prefix,
                        ):
                            continue

                snippet = line.strip()
                if len(snippet) > 200:
                    snippet = snippet[:197] + "..."
                findings.append(Finding(
                    severity=severity, rule_id=rule_id, file=rel,
                    line=i, snippet=snippet, why=why, suggested_fix=fix,
                ))

    return findings


def check_frontmatter(skill_md: Path, root: Path) -> list[Finding]:
    """Lightweight YAML-frontmatter checks. Doesn't parse YAML — uses line search.
    The Claude-side audit does the heavier semantic comparison."""
    findings: list[Finding] = []
    rel = skill_md.relative_to(root).as_posix()

    try:
        text = skill_md.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return findings

    if not text.startswith("---"):
        findings.append(Finding(
            severity="HIGH", rule_id="FM001", file=rel, line=1,
            snippet=text[:80].replace("\n", "\\n"),
            why="SKILL.md has no YAML frontmatter — required for a Claude Code skill",
            suggested_fix="Add a frontmatter block with name, description, when_to_use, allowed-tools.",
        ))
        return findings

    # Extract frontmatter block
    parts = text.split("---", 2)
    if len(parts) < 3:
        findings.append(Finding(
            severity="HIGH", rule_id="FM002", file=rel, line=1,
            snippet="<frontmatter>",
            why="SKILL.md frontmatter is not closed with a second '---'",
            suggested_fix="Close the frontmatter block.",
        ))
        return findings

    fm = parts[1]
    fm_lines = fm.splitlines()

    if not re.search(r"(?m)^\s*disable-model-invocation\s*:\s*true\b", fm):
        findings.append(Finding(
            severity="HIGH", rule_id="FM003", file=rel, line=1,
            snippet="<no disable-model-invocation: true>",
            why="Skill can be invoked by the model without user consent",
            suggested_fix="Add 'disable-model-invocation: true' to frontmatter.",
        ))

    # Find the allowed-tools value (could be one or many lines)
    at_match = re.search(r"(?m)^\s*allowed-tools\s*:\s*(.*)$", fm)
    if not at_match:
        findings.append(Finding(
            severity="HIGH", rule_id="FM004", file=rel, line=1,
            snippet="<no allowed-tools>",
            why="No allowed-tools restriction — skill inherits default permissions",
            suggested_fix="Declare an explicit allowed-tools list, narrowed to what the skill needs.",
        ))
    else:
        at_value = at_match.group(1)
        # Look for the broadest patterns
        if re.search(r"Bash\(\s*\*\s*\*\s*\)", at_value):
            findings.append(Finding(
                severity="CRITICAL", rule_id="FM005", file=rel,
                line=1 + fm.count("\n", 0, at_match.start()),
                snippet=at_value.strip()[:200],
                why="Bash(* *) grants unrestricted shell access",
                suggested_fix="Replace with specific Bash(<command> <pattern>) entries the skill actually needs.",
            ))

    return findings


def inventory(skill_root: Path) -> dict:
    """Walk the skill dir and classify every file."""
    text_files: list[str] = []
    other_files: list[str] = []
    total_bytes = 0

    for p in skill_root.rglob("*"):
        # Check symlink BEFORE is_file(), because a symlink to a directory
        # is not a file and would otherwise be silently skipped.
        if p.is_symlink():
            other_files.append(p.relative_to(skill_root).as_posix() + "  (SYMLINK)")
            continue
        if not p.is_file():
            continue

        try:
            total_bytes += p.stat().st_size
        except OSError:
            pass

        if p.suffix.lower() in TEXT_EXTENSIONS:
            text_files.append(p.relative_to(skill_root).as_posix())
        else:
            other_files.append(p.relative_to(skill_root).as_posix())

    return {
        "text_files": sorted(text_files),
        "other_files": sorted(other_files),
        "total_bytes": total_bytes,
    }


def main() -> int:
    if len(sys.argv) < 2:
        print(json.dumps({"error": "usage: scan.py <skill-directory>"}), file=sys.stderr)
        return 2

    # Check symlink BEFORE resolve() — resolve() dereferences and the
    # subsequent is_symlink() would always return False.
    raw_skill_root = Path(sys.argv[1])
    if raw_skill_root.is_symlink():
        print(json.dumps({"error": f"refusing symlink as input: {raw_skill_root}"}), file=sys.stderr)
        return 2

    skill_root = raw_skill_root.resolve()

    if not skill_root.is_dir():
        print(json.dumps({"error": f"not a directory: {skill_root}"}), file=sys.stderr)
        return 2

    skill_md = skill_root / "SKILL.md"
    if not skill_md.is_file():
        print(json.dumps({"error": f"no SKILL.md in {skill_root}"}), file=sys.stderr)
        return 2

    inv = inventory(skill_root)
    findings: list[Finding] = []

    # Frontmatter pass
    findings.extend(check_frontmatter(skill_md, skill_root))

    # Per-file pass
    for rel in inv["text_files"]:
        findings.extend(scan_file(skill_root / rel, skill_root))

    # Note any non-text or symlink files (Claude-side review treats these as red flags)
    for other in inv["other_files"]:
        sev = "CRITICAL" if "SYMLINK" in other else "HIGH"
        why = ("Symlink inside skill directory — refuse." if "SYMLINK" in other
               else "Binary or non-text file in skill — unauditable; treat as RED unless the author justifies it.")
        findings.append(Finding(
            severity=sev, rule_id="INV001", file=other, line=0,
            snippet="", why=why,
        ))

    # Summarize
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    out = {
        "skill_path": str(skill_root),
        "inventory": inv,
        "counts": counts,
        "findings": [asdict(f) for f in findings],
    }

    print(json.dumps(out, indent=2, ensure_ascii=False))

    # Exit code reflects severity for shell-level routing.
    if counts["CRITICAL"] > 0:
        return 3
    if counts["HIGH"] >= 3:
        return 3
    if counts["HIGH"] > 0 or counts["MEDIUM"] > 0:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
