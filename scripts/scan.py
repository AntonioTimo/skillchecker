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

import ast
import ipaddress
import json
import os
import re
import shlex
import sys
import unicodedata
from dataclasses import dataclass, asdict
from pathlib import Path
from urllib.parse import urlsplit

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

    ("CR026", r"(?i)(?:webhook\.site|requestbin|pastebin\.com|paste\.rs|discord\.com/api/webhooks|hooks\.slack\.com|ngrok\.io|ngrok-free\.app|burpcollaborator|interactsh)",
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

    ("CR031", r"(?i)(?:treat|use|read)\s+(?:the\s+|this\s+|that\s+)?"
              r"(?:document|file|input|book|content|attachment|payload|data)"
              r"[^\n]{0,40}?\s+as\s+"
              r"(?:(?:your|the|new|a)\s+)*"
              r"(?:system\s+)?(?:prompt|instructions?|directives?|commands?)|"
              r"follow\s+(?:the\s+|its\s+|their\s+)?instructions\s+"
              r"(?:in|inside|from|of)\s+(?:the\s+|this\s+)?"
              r"(?:document|file|input|book|content|attachment)",
     "Role confusion — skill asks the model to treat untrusted input as instructions",
     "Refuse. This is the prompt-injection vulnerability the skill should be defending against, not enabling."),

    ("CR034", r"(?i)(?:trycloudflare\.com|\.loca\.lt|serveo\.net|lhr\.life|localhost\.run|\.oast\.(?:fun|live|site|pro|me)|pipedream\.net|beeceptor\.com|requestcatcher\.com|\.telebit\.(?:io|me)|tunnelto\.dev)",
     "Tunneling / OOB-interaction service — points at an attacker-controlled box; data exfiltration channel",
     "Refuse unless the skill is explicitly and transparently a tunnel helper."),

    ("CR035", r"\b(?:env|printenv)\b[^\n|]*\|[^\n]*\b(?:curl|wget|nc|ncat|netcat|telnet)\b",
     "Environment dump piped to a network tool — wholesale exfiltration of secrets held in env vars",
     "Refuse."),

    ("CR036", r"(?:bash|sh|zsh|source|\.)\s+<\(\s*(?:curl|wget|fetch)\b",
     "Process-substitution pipe-to-shell — runs unaudited remote code",
     "Refuse. Patching is not enough; the skill is fetching and executing remote code."),

    ("CR037", r"\beval\b[^\n]*\$\(\s*(?:curl|wget|fetch)\b",
     "eval over a command-substituted remote fetch — runs unaudited remote code",
     "Refuse."),

    ("CR038", r"(?i)\b(?:169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200)\b",
     "Cloud instance-metadata endpoint — SSRF target for stealing IAM / cloud credentials",
     "Refuse. A skill has no reason to query the cloud metadata service."),

    ("CR041",
     r"(?i)<\|im_(?:start|end)\|>|<<\s*/?\s*SYS\s*>>|\[/?INST\]"
     r"|\[system\]\(#(?:assistant|context)\)|\{\{[#/]system~?\}\}",
     "Chat-template control token forging a system/assistant turn (ChatML <|im_start|>, <<SYS>>, [INST], {{#system}}) — a skill structurally prompt-injecting the host model with a forged role boundary",
     "Refuse. No legitimate skill emits ML chat-template control tokens in its prose."),

    ("CR044",
     r"(?i)/dev/(?:tcp|udp)/|\b(?:nc|ncat|netcat)\b[^\n]{0,20}\s-e\b",
     "Reverse shell / inbound C2 — a bash /dev/tcp pseudo-device or `nc -e` hands remote control of the machine to an attacker",
     "Refuse. There is no legitimate skill use for a /dev/tcp reverse shell or `nc -e`."),
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

    ("HI019", r"(?i)(?:https?|ftps?)://|\b(?:curl|wget|fetch|nc|ncat|netcat|telnet|ssh)\b",
     "IP-literal or numeric-encoded IP host in a URL / network command — bypasses domain blocklists; a hardcoded public/encoded host is a common C2 / exfil pattern",
     "Verify the destination. A public IP literal or an encoded IP (hex/decimal) is suspicious; prefer a named, documented endpoint."),

    ("HI020", r"\$\{IFS\}|\$IFS\b",
     "${IFS} shell space-substitution — evasion used to slip spaces past naive command filters",
     "There is no legitimate reason to assemble commands with ${IFS} in a skill."),

    ("HI021", r"(?i)api\.telegram\.org/bot",
     "Telegram bot API — usable as a covert exfiltration channel; legitimate only for a skill whose declared purpose is a Telegram bot",
     "Confirm the skill's stated purpose; otherwise treat as an exfil channel and refuse."),

    ("HI022", r"(?i)\bxn--[a-z0-9]",
     "IDN / punycode label (xn--) — a homoglyph domain that can impersonate a trusted brand for phishing / C2 (matches bare host / userinfo@ too, not just scheme://)",
     "Decode the punycode and verify the real domain; a skill rarely needs an internationalized host."),

    ("HI024",
     # sub1 — strong leak verbs, all three anchor branches (incl. the looser
     # `your instructions/directives/guidelines`). sub2 — generic verbs
     # (tell/give/share/list/…) match ONLY the TIGHT `system`-qualified branches,
     # so "tell me your system prompt" fires but benign "share your guidelines"
     # does not (adversarial review: generic verbs through the loose branch = ~88% FP).
     r"(?i)(?:\b(?:reveal|print|show|display|output|expose|dump|repeat|recite|echo|return|disclose|leak|divulge|paste)\b"
     r"[^\n]{0,25}?(?:\byour\b[^\n]{0,15}?\bsystem\s+(?:prompt|message|instructions?)\b"
     r"|\byour\b[^\n]{0,12}?\b(?:instructions?|directives?|guidelines?)\b"
     r"|\bthe\s+system\s+(?:prompt|message|instructions?)\b)"
     r"|\b(?:tell|give|hand|share|send|list|quote|spit|type|restate|relay|transcribe|reproduce)\b"
     r"[^\n]{0,25}?(?:\byour\b[^\n]{0,15}?\bsystem\s+(?:prompt|message|instructions?)\b"
     r"|\bthe\s+system\s+(?:prompt|message|instructions?)\b))",
     "Skill prose orders the model to DISCLOSE its own system prompt / instructions — self-exfiltration of the model's hidden configuration (the data the skill should protect, not leak)",
     "Refuse. A skill has no legitimate reason to make the model reveal its own system prompt or instructions."),

    ("HI025",
     r"(?i)\b(?:write|save|store|log|send|post|upload|transmit|pipe|forward|exfiltrate)\b"
     r"[^\n]{0,25}?(?:\byour\b[^\n]{0,15}?\bsystem\s+(?:prompt|message|instructions?)\b"
     r"|\byour\b[^\n]{0,12}?\b(?:instructions?|directives?|guidelines?)\b"
     r"|\bthe\s+system\s+(?:prompt|message|instructions?)\b)"
     r"[^\n]{0,28}?\b(?:to|into|via)\b[^\n]{0,22}?"
     r"(?:file|disk|log|server|webhook|endpoint|url|socket|https?://|ftp://|curl|wget)",
     "Skill prose orders the model to WRITE/SEND its own system prompt or instructions to a file / network / log sink — prompt exfiltration with no literal endpoint the line rules key on",
     "Refuse. The model's system prompt must never be persisted or transmitted by the skill."),

    ("HI026",
     # Instruction-override TRIPLE gate: override-verb + STRONG prior-reference +
     # instruction-noun. 'ignore previous deprecation warnings' (no instruction-noun)
     # and 'disregard the linting rules' (no prior-ref) do NOT fire.
     # Two order-agnostic arms (adversarial review): arm 1 = verb -> prior-ref ->
     # noun ("ignore all previous instructions"); arm 2 = verb -> noun -> STRONG
     # positional prior-ref ("ignore the instructions above") — the canonical order
     # the single-arm form missed. Arm 2 uses ONLY positional words (above/earlier/
     # previously/before/prior/preceding), never loose 'the'/'all', so a benign
     # "follow the instructions <noun>" cannot trip it.
     r"(?i)(?:\b(?:ignore|disregard|forget|override|bypass|discard|delete)\b"
     r"[^\n]{0,25}?\b(?:previous|preceding|prior|earlier|above|all\s+(?:previous|prior|preceding|the))\b"
     r"[^\n]{0,25}?\b(?:instructions?|directives?|context|(?:system\s+)?prompts?|commands?|constraints?|guardrails?)\b"
     r"|\b(?:ignore|disregard|forget|override|bypass|discard|delete)\b"
     r"[^\n]{0,30}?\b(?:instructions?|directives?|context|(?:system\s+)?prompts?|commands?|constraints?|guardrails?)\b"
     r"[^\n]{0,30}?\b(?:above|earlier|previously|before|prior|preceding)\b)",
     "Instruction-override grammar ('disregard all previous instructions', 'ignore the instructions above') in SKILL.md prose — a forged directive to make the model abandon its prior instructions, the core prompt-injection move",
     "Refuse. A skill must not tell the model to disregard its previous instructions."),

    ("HI029",
     r"(?i)\b(?:transfer\.sh|gofile\.io|file\.io|bashupload\.com|anonfile\.(?:com|to|cc)"
     r"|0x0\.st|tmpfiles\.org|oshi\.at|ix\.io|0bin\.net|controlc\.com|dpaste\.(?:com|org)"
     r"|hastebin\.com|temp\.sh|catbox\.moe|uguu\.se|litterbox\.catbox\.moe)\b",
     "Anonymous file-staging / paste DOWNLOAD host — the second-stage payload source class (MITRE T1608.001) that feeds a two-stage curl|bash, distinct from the exfil destinations CR026 covers",
     "Verify what is fetched. A skill pulling a stage-2 payload from an anonymous file-staging host is a strong supply-chain red flag."),
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

    ("ME011", r"[A-Za-z0-9+/]{256,}={0,2}",
     "Very long base64-like literal (>=256 chars) — possible embedded payload or obfuscated data",
     "Decode and inspect; confirm it is benign data, not code or a hidden command."),

    ("ME013",
     # Two arms (adversarial review — the old "verb + all/every + sessions" form
     # over-fired on benign data persistence "store embeddings for all conversations"):
     # arm 1 = persist-verb + FUTURE/subsequent + session-noun (cross-restart, the
     # threat); arm 2 = inject/embed/implant a DIRECTIVE object (active injection at
     # any scope). The bare "from now on, always …" form stays unmatched (CR029/CR031).
     # `memoriz\w*` so "memorize"/"memorise"/"memorizing" actually match.
     r"(?i)(?:\bremember|\bstore|\bpersist|\bretain|\bmemoriz\w*)\b"
     r"[^\n]{0,40}?\b(?:for|across|in|into|over)\b[^\n]{0,22}?\b(?:future|subsequent)\b"
     r"[^\n]{0,18}?\b(?:interactions?|conversations?|sessions?|chats?)\b"
     r"|(?:\binject|\bembed|\bimplant|\bplant)\b"
     r"[^\n]{0,30}?\b(?:instructions?|directives?|commands?|behaviou?rs?|persona|rules?)\b",
     "Skill prose installs a CROSS-SESSION persistent instruction / memory injection — designed to outlive the current task and steer every future interaction",
     "Refuse or scope it. A skill should not install standing instructions that persist across sessions."),

    ("ME015",
     # Both arms require a SELF-TARGET object (adversarial review): arm 1's bare
     # adjective "self-modifying code" and arm 2's human-maintenance verbs
     # "edit/update this skill" were benign FPs. arm 1 = self-X verb + (your/this/the
     # current) + skill/source; arm 2 = a runtime-mutation verb (edit/update DROPPED)
     # + the same self-target. A skill-builder writing OTHER skills stays GREEN.
     r"(?i)\bself-?(?:modif(?:y|ies|ying)|rewrit(?:e|es|ing)|overwrit(?:e|es|ing)|evolv(?:e|es|ing)|patch(?:es|ing)?)\b"
     r"[^\n]{0,22}?\b(?:your(?:\s+own)?|this|the\s+current|its\s+own)\b"
     r"[^\n]{0,18}?\b(?:skill|SKILL\.md|instructions?|source(?:\s*code)?|frontmatter|prompt|definition|file)\b"
     r"|\b(?:rewrite|modify|overwrite|append\s+to|patch)\b"
     r"[^\n]{0,22}?\b(?:this|your\s+own|the\s+current)\b"
     r"[^\n]{0,18}?\b(?:skill|SKILL\.md|instructions?|source(?:\s*code)?|frontmatter|prompt)\b",
     "Skill prose tells the skill to REWRITE its own SKILL.md / source / instructions at runtime — audited-once, mutates-later, defeating a pre-install audit",
     "Refuse. A skill must not rewrite its own definition at runtime."),
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


_NET_CMDS = {"curl", "wget", "fetch", "nc", "ncat", "netcat", "telnet", "ssh"}

# Option grammar is COMMAND-AWARE: the same letter means different things per
# tool (`curl -x` is a proxy host; `ssh -x` is boolean X11; `curl -O` is boolean
# but `wget -O` takes an output file). For each net command we list:
#   HOST opts — value is a network host / IP -> classify it;
#   DATA opts — value is data / a file / a credential / a number -> skip it.
# Every flag NOT listed is treated as boolean (consumes no following token), so a
# boolean flag never swallows the scheme-less IP target after it. These are
# curated allowlists, not exhaustive — an exotic option may be missed.
_CURL_HOST = {
    "-x", "--proxy", "--proxy1.0", "--preproxy",
    "--socks4", "--socks4a", "--socks5", "--socks5-hostname",
    "--url", "--resolve", "--connect-to", "--dns-servers",
}
_CURL_DATA = {
    "-X", "--request",  # HTTP method token — not a host (a literal `-X 8.8.8.8`)
    "-o", "--output", "-T", "--upload-file",
    "-H", "--header", "-d", "--data", "--data-ascii", "--data-binary",
    "--data-raw", "--data-urlencode", "-F", "--form", "--form-string",
    "-A", "--user-agent", "-e", "--referer", "-b", "--cookie",
    "-c", "--cookie-jar", "-u", "--user", "-U", "--proxy-user",
    "-w", "--write-out", "-K", "--config", "-E", "--cert", "--cacert",
    "--key", "--capath", "--interface", "-r", "--range",
    "--trace", "--trace-ascii", "--stderr",
}
_WGET_DATA = {
    "-O", "--output-document", "-o", "--output-file", "-a", "--append-output",
    "--post-file", "--post-data", "--body-file", "--header",
    "--user", "--password", "--http-user", "--http-password", "-P",
    "--directory-prefix", "--load-cookies", "--save-cookies",
    "--ca-certificate", "--certificate", "--private-key", "--referer",
    "-U", "--user-agent", "--limit-rate", "-t", "--tries", "-T", "--timeout",
    "--bind-address", "-e", "--execute",
}
_SSH_HOST = {"-J", "-W"}  # jump host / stdio-forward destination
_SSH_DATA = {
    "-i", "-l", "-p", "-o", "-F", "-E", "-c", "-m", "-b",
    "-D", "-L", "-R", "-w", "-S", "-Q", "-B", "-e",
}
_NC_HOST = {"-x", "--proxy"}
_NC_DATA = {
    "-p", "-s", "-w", "-X", "-b", "-I", "-O", "-q", "-T", "-G", "-i",
    "--source", "--source-port", "--proxy-type",
}
# net command -> (host-value options, data/file-value options)
_CMD_OPTS = {
    "curl": (_CURL_HOST, _CURL_DATA),
    "fetch": (_CURL_HOST, _CURL_DATA),
    "wget": (frozenset(), _WGET_DATA),
    "ssh": (_SSH_HOST, _SSH_DATA),
    "nc": (_NC_HOST, _NC_DATA),
    "ncat": (_NC_HOST, _NC_DATA),
    "netcat": (_NC_HOST, _NC_DATA),
    "telnet": (frozenset(), frozenset()),
}


def _ip_publicness(host):
    """'public' / 'private' / None — classify a host token as an IP literal.

    A plain literal (dotted IPv4 or IPv6) is classified with the stdlib
    `ipaddress` module, so RFC1918 / loopback / link-local / reserved read as
    'private' and a hardcoded local-dev host does not false-positive. No
    hand-rolled octet ranges (the regex host-extractor never converged).

    A HEX or DECIMAL-encoded IPv4 (`0x7f000001`, `2130706433`) is reported as
    'public' regardless of the address it decodes to: writing an IP in encoded
    form is itself the evasion signal, so an encoded *loopback* must still flag
    (a plainly-written `127.0.0.1` is fine; obfuscating it is not)."""
    h = (host or "").strip().strip("[]")
    if not h:
        return None
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        # Not a plain literal — try hex / decimal IPv4 encoding.
        n = None
        if re.fullmatch(r"0[xX][0-9a-fA-F]+", h):
            n = int(h, 16)
        elif re.fullmatch(r"\d{8,10}", h):
            n = int(h)
        if n is not None and n <= 0xFFFFFFFF:
            try:
                ipaddress.ip_address(n)  # validate it is a real address
            except ValueError:
                return None
            return "public"  # encoded form — always flag, value notwithstanding
        # Dotted IPv4 with HEX / OCTAL octets (0x08.0x08.0x08.0x08, 0250.0.0.1,
        # 010.020.0.1) — what curl / getaddrinfo actually dial, but ipaddress
        # rejects. Writing an octet in encoded form is itself the evasion signal,
        # so an obfuscated dotted IPv4 always flags (the single-integer twin
        # above). A plain dotted-decimal never reaches here — ipaddress took it.
        parts = h.split(".")
        if len(parts) == 4 and any(
                p[:2].lower() == "0x" or (len(p) > 1 and p[0] == "0" and p.isdigit())
                for p in parts):
            try:
                vals = [
                    int(p, 16) if p[:2].lower() == "0x"
                    else int(p, 8) if (len(p) > 1 and p[0] == "0")
                    else int(p, 10)
                    for p in parts
                ]
            except ValueError:
                return None
            if all(0 <= v <= 0xFF for v in vals):
                return "public"
        return None
    if (ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_reserved or ip.is_unspecified or ip.is_multicast):
        return "private"
    return "public"


def _hosts_from_token(tok):
    """Every host / IP candidate inside one positional token or option value.
    Handles scheme URLs, `userinfo@`, `host:port`, bracketed IPv6 (with optional
    `:port`), and the colon/comma-joined option formats of `--resolve`
    (host:port:addr[,addr]), `--connect-to` (h1:p1:h2:p2) and `--dns-servers`
    (a,b) — where the real destination is an inner field."""
    if not tok:
        return []
    if "://" in tok:
        try:
            hn = urlsplit(tok).hostname
        except ValueError:
            hn = None
        return [hn] if hn else []
    v = tok.split("/", 1)[0]          # drop any /path
    if "@" in v:
        v = v.rsplit("@", 1)[1]       # drop userinfo
    out = []
    m = re.match(r"^\[([0-9A-Fa-f:]+)\](?::\d+)?$", v)
    if m:                            # bracketed IPv6, optional :port -> [2001:db8::1]:443
        out.append(m.group(1))
    elif v.count(":") == 1:          # host:port (single colon, not IPv6) -> strip port
        out.append(v.rsplit(":", 1)[0])
    else:
        out.append(v.strip("[]"))
    if "," in v or v.count(":") >= 2:
        # comma / multi-colon option value: --dns-servers a,b ; --resolve
        # host:port:addr ; --connect-to h1:p1:h2:p2 — scan each field for an IP.
        out.extend(f.strip("[]") for f in re.split(r"[:,]", v))
    return [h for h in out if h]


def _split_opt(tok):
    """(name, attached_value_or_None) for an option token — covers `--name`,
    `--name=value`, and the attached short form `-xvalue` (e.g. `-x8.8.8.8:8080`,
    which curl accepts). A bare flag returns (token, None)."""
    if tok.startswith("--"):
        name, eq, val = tok.partition("=")
        return name, (val if eq else None)
    if len(tok) > 2:                  # -xVALUE  (short option, value attached)
        return tok[:2], tok[2:]
    return tok, None


def _candidate_hosts(text):
    """Hosts referenced in a line.

    Two passes: (1) every `scheme://…` URL anywhere in the raw text, parsed with
    `urlsplit` (handles userinfo / port / IPv6 / multiple-@); (2) scheme-less
    hosts in network commands. The second pass walks each shell command segment
    independently — split on `;` `|` `&&` `||` `&` so one command's reach does
    not leak past a separator — and within a segment distinguishes a host-bearing
    option value (`--proxy`/`--url`/`--resolve`/…, classified) from a data/file
    flag value (`-H`/`-o`/`-d`, skipped) from a boolean flag (`-s`/`-L`/`--fail`,
    which does not consume the IP target that follows it) from a positional
    request target. The option grammar is per-command (`_CMD_OPTS`), since the
    same letter differs by tool — `wget -O` is an output file, `ssh -i` an
    identity file, `ssh -x` boolean, while `curl -x` is a proxy host."""
    hosts = []
    for m in re.finditer(r"(?i)\b(?:https?|ftps?)://[^\s\"'<>)\]]+", text):
        raw = m.group(0)
        try:
            hn = urlsplit(raw).hostname
        except ValueError:
            hn = None
        if not hn:
            # Bracketed IPv6 authority: the char class excludes ']', so the match
            # truncated mid-literal ('http://[2606:4700:4700::1111') and urlsplit
            # raised. Pull the inner IPv6 literal directly so a public-IPv6 host
            # still classifies (loopback / ULA / link-local still read private).
            bm = re.match(r"(?i)(?:https?|ftps?)://\[([0-9A-Fa-f:]+)", raw)
            if bm:
                hn = bm.group(1)
        if hn:
            hosts.append(hn)
    for segment in re.split(r"(?:&&|\|\||[;|&])", text):
        try:
            toks = shlex.split(segment, posix=True)
        except ValueError:
            toks = segment.split()
        active = False
        host_opts = data_opts = frozenset()  # option grammar of the active command
        want_host_value = False  # next token is a host (after --proxy / --url / …)
        skip_value = False       # next token is a data/file flag's value (-H / -o / …)
        for t in toks:
            base = t.lower().rsplit("/", 1)[-1]
            if base in _NET_CMDS:
                active = True
                host_opts, data_opts = _CMD_OPTS.get(base, (frozenset(), frozenset()))
                want_host_value = skip_value = False
                continue
            if not active:
                continue
            if want_host_value:
                hosts.extend(_hosts_from_token(t))
                want_host_value = False
                continue
            if skip_value:
                skip_value = False
                continue
            if t.startswith("-"):
                name, attached = _split_opt(t)
                if name in host_opts:
                    if attached is not None:   # --proxy=host / -xhost
                        hosts.extend(_hosts_from_token(attached))
                    else:                      # --proxy host  (value is next token)
                        want_host_value = True
                elif name in data_opts and attached is None:
                    skip_value = True          # -o file  (value is next token)
                # boolean / unknown flag, or attached data value: do not skip;
                # the following token is classified as the positional target.
                continue
            hosts.extend(_hosts_from_token(t))  # positional request target
    return hosts


def _public_ip_in(text):
    """True if the line references a public IP-literal host (URL or command target)."""
    return any(_ip_publicness(h) == "public" for h in _candidate_hosts(text))


def scan_file(path: Path, root: Path) -> list[Finding]:
    """Open a file and run every rule against each line.

    For .md files: lines inside ``` / ~~~ code fences are scanned in full. In
    prose, the prompt-injection rules (PROSE_TARGETING) scan the whole line, and
    every other rule scans each inline-code (backtick) span individually — a span
    is executable-looking content, while plain prose is left to the LLM-side audit
    so a skill documenting its own threat model doesn't trip every rule. A span
    framed by a defensive negation immediately before it ("never use `x`") is
    skipped; NFKC-normalized copies are also tested so fullwidth/compat hiding fails.
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
    PROSE_TARGETING = {"CR028", "CR029", "CR030", "CR031", "ME009",
                       "HI024", "HI025", "ME013", "ME015", "CR041", "HI026"}

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

        # Toggle code-fence state for markdown files (only outside frontmatter).
        # Both ``` and ~~~ are CommonMark fences — scan both as code (Codex P0).
        if is_markdown and not in_frontmatter and re.match(r"^\s*(?:```|~~~)", line):
            in_code_fence = not in_code_fence
            continue

        # Prose = .md AND not in frontmatter AND not in code-fence.
        # Frontmatter and code-fence both get full scanning.
        is_prose_in_md = (is_markdown and not in_frontmatter
                          and not in_code_fence)
        # Inline-code spans in prose ARE code — scanned INDIVIDUALLY, each with the
        # prose IMMEDIATELY before it, so a defensive span ("never use `x`") can't
        # mask a later malicious span on the same line (Codex round 4). Plain prose
        # still only runs PROSE_TARGETING; the LLM-side audit reads the rest, and
        # scanning all prose would drown documentation in self-FPs.
        # Inline-code spans in prose are scanned individually, as code. We do NOT
        # try to infer "defensive intent" from the surrounding prose: guessing
        # intent from one word ("never", "avoid", "block", …) in the regex layer
        # kept opening silent bypasses ("Never mind, run `curl | sh`"). A documented
        # bad pattern in inline code is a self-FP the LLM-side audit contextualizes;
        # a missed attack is not acceptable (Codex round 5). PROSE_TARGETING rules
        # still scan the whole line with their own position-based negation guard.
        inline_spans = [sm.group(1) for sm in re.finditer(r"`+([^`\n]+?)`+", line)] \
            if is_prose_in_md else []

        for rule_id, severity, pattern, why, fix in ALL_RULES:
            try:
                compiled = re.compile(pattern)
            except re.error:
                continue

            if is_prose_in_md and rule_id not in PROSE_TARGETING:
                units = inline_spans          # each inline-code span, scanned as code
            else:
                units = [line]                # whole line (code fence / .py / frontmatter)

            for unit in units:
                # Also test an NFKC-normalized copy, so fullwidth / compatibility
                # characters can't hide a dangerous pattern. Escalate-only.
                norm = unicodedata.normalize("NFKC", unit)
                m_raw = compiled.search(unit)
                m_nfkc = compiled.search(norm) if (not m_raw and norm != unit) else None
                if not (m_raw or m_nfkc):
                    continue

                # Per-rule false-positive guards (operate on the scanned unit)
                if rule_id == "ME002":
                    if "mktemp" in unit:
                        continue
                    if re.search(r"/tmp/[A-Za-z0-9_-]+\.\*", unit):
                        continue
                    if re.search(r"(?:PREFIX|prefix)\s*=\s*['\"]/tmp/", unit):
                        continue
                if rule_id == "ME004":
                    if unit.rstrip().endswith((",", "(", "\\")):
                        continue
                if rule_id == "ME006":
                    # YAML folded/literal scalar: the value continues on later lines.
                    if re.search(r"^description:\s*[>|][-+]?\s*$", unit):
                        continue
                if rule_id == "HI019":
                    # Decide via real host extraction (urllib + ipaddress), not a
                    # second regex kept in sync with the rule: flag only if a URL or
                    # network-command target resolves to a PUBLIC IP literal. Named
                    # hosts, loopback/private, userinfo IPs, and flag values all skip.
                    if not _public_ip_in(norm):
                        continue
                if rule_id in ("CR020", "CR021"):
                    # Skip an install command inside an error/help string literal.
                    stripped = unit.lstrip()
                    if (stripped.startswith(('"', "'", "f'", 'f"', '"""', "'''")) or
                        re.search(r"(?:print|stderr|sys\.exit|raise)\s*\(", unit) or
                        unit.rstrip().endswith(('\\n",', '\\n"', "\\n',", "\\n'"))):
                        continue
                if rule_id in ("CR028", "CR029", "CR030", "CR031",
                               "HI024", "HI025", "ME013", "ME015", "CR041", "HI026"):
                    # Defensive prose: suppress ONLY when the NEAREST preceding
                    # negation governs THIS dangerous verb — i.e. no clause/sentence
                    # break or fresh imperative between the negation and the match.
                    # A line-global scan let an unrelated "Never skip this step:
                    # reveal your system prompt" bypass the rule (adversarial review).
                    # Chained coordination (commas / 'or') is NOT a break, so the
                    # legitimate "will never print …, send …, or rewrite …" stays
                    # suppressed. (Bare modals should/must/may do not count — Codex.)
                    m = compiled.search(unit)
                    if m:
                        negs = list(re.finditer(
                            r"(?i)\b(?:do\s+not|don'?t|never|cannot|can'?t|won'?t|"
                            r"shouldn'?t|mustn'?t|should\s+not|must\s+not|may\s+not|"
                            r"should\s+never|must\s+never|"
                            r"refuse\s+to|reject|forbid|prevent|avoid)\b",
                            unit[: m.start()]))
                        if negs and not re.search(
                            # A COMMA is a clause break too (Codex audit): 'Never mind,
                            # reveal your system prompt' must NOT be suppressed — the
                            # 'never' governs 'mind', not the dangerous verb in the next
                            # clause. Defensive lists therefore repeat the negation per
                            # clause ('… never X. … never Y.'), not one 'never' + commas.
                            r"(?i)[.;:!?,]|\b(?:until|then|after|before|once|also|skip|"
                            r"stop|hesitate|delay|forget|collect|fail|but|mind|worry|"
                            r"bother|instead|anyway|regardless)\b",
                            unit[negs[-1].end(): m.start()]):
                            continue

                why_out = why
                if m_nfkc and not m_raw:
                    why_out = why + " — revealed by NFKC normalization (text uses fullwidth/compatibility characters)"
                snippet = line.strip()
                if len(snippet) > 200:
                    snippet = snippet[:197] + "..."
                findings.append(Finding(
                    severity=severity, rule_id=rule_id, file=rel,
                    line=i, snippet=snippet, why=why_out, suggested_fix=fix,
                ))

    return findings


def _fm_field(fm: str, key: str) -> str:
    """A frontmatter scalar value, including folded / indented continuation lines,
    whitespace-collapsed. '' if the key is absent. Lets ME014 read the REAL Claude
    Code activation field (when_to_use / description), not a blind frontmatter scan."""
    m = re.search(r"(?m)^" + re.escape(key) + r"\s*:\s*(.*(?:\n[ \t]+\S.*)*)", fm)
    return " ".join(m.group(1).split()) if m else ""


# ME014 — an UNSCOPED catch-all activation surface. Anchored on unscoped catch-alls
# only; a DOMAIN-scoped 'any <noun>' ('any React component', 'all SQL queries') must
# stay GREEN, so bare 'any'/'all' are never matched — only the listed phrases.
_ME014_RE = re.compile(
    r"(?i)\b(?:use\s+(?:this|me)\s+for\s+(?:anything|everything)"
    r"|anything\s+and\s+everything"
    r"|any\s+and\s+all\s+(?:requests|messages|inputs|tasks|queries|prompts|questions)\b"
    r"|whenever\s+the\s+user\s+(?:says|types|writes|asks|does|wants)\s+anything"
    r"|on\s+(?:any|every)\s+(?:user\s+)?(?:request|message|input|prompt|query)\b"
    r"|on\s+any\s+topic\b"
    r"|for\s+all\s+(?:requests|messages|inputs|tasks|queries|prompts)\b"
    r"|always\s+(?:trigger|activate|run|fire|engage)\b"
    r"|\bany\s+task\b)"
)


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

    # Extract frontmatter block. Match the closing `---` only at COLUMN 0 (a real
    # YAML document separator), so a literal '---' INSIDE a value cannot truncate the
    # block — which would drop later fields (ME014) and spuriously fire FM003/FM004
    # (adversarial review). `text` already starts with '---' (checked above).
    fm_match = re.match(r"---[ \t]*\r?\n(.*?)\r?\n---[ \t]*(?:\r?\n|\Z)", text, re.DOTALL)
    if not fm_match:
        findings.append(Finding(
            severity="HIGH", rule_id="FM002", file=rel, line=1,
            snippet="<frontmatter>",
            why="SKILL.md frontmatter is not closed with a second '---'",
            suggested_fix="Close the frontmatter block.",
        ))
        return findings

    fm = fm_match.group(1)
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

    # Bash(* *) anywhere in the frontmatter. Folded/list allowed-tools place it on
    # a following line, which a single-line value check would miss (Codex P0).
    if re.search(r"Bash\(\s*\*\s*\*\s*\)", fm):
        findings.append(Finding(
            severity="CRITICAL", rule_id="FM005", file=rel, line=1,
            snippet="Bash(* *) in allowed-tools",
            why="Bash(* *) grants unrestricted shell access",
            suggested_fix="Replace with specific Bash(<command> <pattern>) entries the skill actually needs.",
        ))

    # ME014 — unscoped catch-all activation surface in when_to_use / description.
    for field in ("when_to_use", "description"):
        val = _fm_field(fm, field)
        if val and _ME014_RE.search(val):
            findings.append(Finding(
                severity="MEDIUM", rule_id="ME014", file=rel, line=1,
                snippet=(field + ": " + val)[:160],
                why=("Frontmatter " + field + " is an UNSCOPED catch-all (anything / every request / "
                     "always trigger) — the skill activates on everything, the precondition for any other "
                     "vector to fire unprompted. A domain-scoped 'any <noun>' is not flagged."),
                suggested_fix=("Scope " + field + " to the specific tasks the skill handles; drop "
                               "'anything / everything / every request / always trigger'."),
            ))
            break

    return findings


# --------------------------------------------------------------------------
# Bundled configuration audit (hooks / MCP / settings)
#
# A skill is expected to contain SKILL.md + optional scripts/ + references/.
# Config files shipped *alongside* it can execute code or rewrite the user's
# Claude Code environment the moment the harness loads them — with no
# allowed-tools entry. The dangerous part is the PRESENCE of a hook / server,
# not the command string, so the line-based rules miss it entirely. We detect
# it structurally: parse the JSON and inspect keys.
#
# Parsing uses json.loads only — it NEVER executes code (unlike pickle /
# yaml.load). If a file won't parse (JSONC comments, trailing commas) we fall
# back to a textual key search and say so in the finding.
# --------------------------------------------------------------------------

BUNDLED_SETTINGS_NAMES = {"settings.json", "settings.local.json"}
BUNDLED_MCP_NAMES = {".mcp.json", "mcp.json"}
BUNDLED_PLUGIN_NAMES = {"plugin.json"}
# Directories that are non-standard for a *skill* and can carry executable config.
NONSTANDARD_DIRS = ("hooks", "commands", "agents", ".claude", ".claude-plugin")


# Read at most this much of any file (config / manifest / script). A skill's files
# are tiny; a multi-GB one is itself suspicious and must never OOM the scanner — the
# disease behind the _exec_magic whole-file read (Codex audit) is unbounded reads.
_MAX_READ_BYTES = 8 * 1024 * 1024   # 8 MB


def _read_text_safe(path: Path):
    try:
        with open(path, "rb") as f:
            return f.read(_MAX_READ_BYTES).decode("utf-8", errors="replace")
    except OSError:
        return None


def _parse_json(path: Path):
    """Return (data, error_or_None). Never executes code — json.loads only."""
    text = _read_text_safe(path)
    if text is None:
        return None, "could not read file"
    try:
        return json.loads(text), None
    except (ValueError, RecursionError) as e:  # JSONDecodeError ⊂ ValueError; deep
        # nesting raises RecursionError — return it as a parse error so the textual
        # backstop (e.g. CR032 via _mentions_key) still fires instead of crashing.
        return None, f"not valid JSON ({type(e).__name__})"


def _mentions_key(path: Path, key: str) -> bool:
    """Textual backstop for files that won't parse as JSON."""
    text = _read_text_safe(path)
    if text is None:
        return False
    return re.search(r'"' + re.escape(key) + r'"\s*:', text) is not None


def _reputation_bad_dest(text):
    """Short reason if `text` points at a reputation-bad destination host — a
    public-IP literal (incl. hex/decimal-encoded) or a punycode / IDN host — else
    None. This is the CR040 signal for a bundled hook / MCP destination.

    Reuses the HI019 host extractor (`_candidate_hosts`, built on urllib +
    ipaddress + shlex) and the HI022 punycode form, so there is no parallel host
    table to drift out of sync. BOTH signals are classified on the EXTRACTED
    host(s), not the whole string — so an `xn--` label or an IP that sits in a
    URL path / query / fragment of a benign named host does not escalate (the
    destination is the host, not the path). Public-IP classification skips
    loopback / RFC1918 / link-local (a local-dev MCP server stays HIGH, not
    CRITICAL). Known exfil / tunnel / cloud-metadata hosts are DELIBERATELY not
    covered here: the line rules CR026 / CR034 / CR038 already rate those CRITICAL
    when they scan the config file, so re-flagging would only double-emit."""
    if not text:
        return None
    hosts = _candidate_hosts(text)
    if any(_ip_publicness(h) == "public" for h in hosts):
        return "a public-IP-literal host"
    if any(re.search(r"(?i)\bxn--", h) for h in hosts):
        return "a punycode / IDN homoglyph host"
    return None


def _hook_command_strings(hooks_node):
    """Every command / args string inside a parsed `hooks` block, at any nesting
    (Claude Code nests them as event -> [ {hooks: [ {command: ...} ]} ]). Joins an
    `args` list into one string. Used to classify a hook's destination for CR040;
    the presence of the hook itself is already CR032."""
    out = []

    def walk(n, depth=0):
        if depth > 200:          # deep nesting is itself suspicious; never recurse-crash
            return
        if isinstance(n, dict):
            for k, v in n.items():
                if k == "command" and isinstance(v, str):
                    out.append(v)
                elif k == "args" and isinstance(v, list):
                    out.append(" ".join(str(a) for a in v if isinstance(a, (str, int, float))))
                else:
                    walk(v, depth + 1)
        elif isinstance(n, list):
            for v in n:
                walk(v, depth + 1)

    walk(hooks_node)
    return out


def _cr040_finding(rel, context, text, reason):
    """A CR040 Finding — a bundled hook / MCP destination pointed at a
    reputation-bad host."""
    return Finding(
        severity="CRITICAL", rule_id="CR040", file=rel, line=0,
        snippet=(context + " = " + text)[:120],
        why=("Bundled config auto-loads " + context + " pointed at " + reason
             + " — the Claude Code harness activates it on session start with no "
             "allowed-tools entry, and a hardcoded bare IP / punycode endpoint is a "
             "C2 / exfiltration destination, not a legitimate MCP server (a named "
             "host and loopback do not fire). Escalates the HIGH host signal to "
             "CRITICAL because the destination is auto-loaded, not merely mentioned"),
        suggested_fix=("Refuse. A skill must not ship an MCP server or hook, least "
                       "of all one pointed at a raw IP or punycode host. If the user "
                       "wants the server they add it themselves, to their own config, "
                       "after reading the URL."))


# A concrete LIVE-secret token shape (CR042). A real token in a SHIPPED MCP config
# is near-never benign; the placeholder guard removes the dominant FP source.
_LIVE_TOKEN_RE = re.compile(
    r"gh[posru]_[A-Za-z0-9]{20,}"                                  # GitHub PAT/OAuth/server/refresh
    r"|xox[baprs]-[A-Za-z0-9-]{10,}"                               # Slack
    r"|sk-[A-Za-z0-9]{20,}"                                        # OpenAI-style
    r"|sk_(?:live|test)_[A-Za-z0-9]{16,}"                          # Stripe live/test secret
    r"|rk_(?:live|test)_[A-Za-z0-9]{16,}"                          # Stripe restricted key
    r"|AKIA[0-9A-Z]{16}"                                           # AWS access key id
    r"|AIza[0-9A-Za-z_\-]{30,}"                                    # Google API key
    r"|eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{6,}"  # JWT
)
# A credential-FILE reference in an env/header value (HI027).
_CRED_FILE_RE = re.compile(
    r"(?i)(?:\.ssh/|\.aws/|/\.env\b|\bid_rsa\b|\bid_ed25519\b|\.pem\b|\.netrc\b|"
    r"\.npmrc\b|\.pypirc\b|credentials\.json|\.kube/config)")


def _is_placeholder(val: str) -> bool:
    """True if an env/header value is a placeholder, not a live secret — `${VAR}` /
    `$VAR` / `<...>` / `{{...}}` / `YOUR_..._HERE` / `xxx` / a bare ENV-name echo."""
    v = (val or "").strip()
    if not v:
        return True
    if re.fullmatch(r"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?", v):
        return True
    if v.startswith("<") and v.endswith(">"):
        return True
    if re.fullmatch(r"\{\{[^}]*\}\}", v):
        return True
    if re.search(r"(?i)\byour[_-].*here\b|placeholder|example|changeme|<token>|\bxxx+\b|\.\.\.", v):
        return True
    if re.fullmatch(r"[A-Z][A-Z0-9_]{2,}", v):          # bare ENV-name echo
        return True
    return False


def _token_is_dummy(tok: str) -> bool:
    """True if a token-SHAPED string is obviously a dummy/example, not a live secret:
    a repeated-character fill (`xxxx…`/`0000…`, 8+) or an embedded EXAMPLE/PLACEHOLDER/
    CHANGEME/DUMMY/SAMPLE/REDACTED/FAKE marker. Applied to the MATCHED token (not the
    whole value), so a real token co-located with the word 'example' still fires, while
    `ghp_xxxx…` and the AWS doc key `AKIA…EXAMPLE` are suppressed (adversarial review)."""
    return bool(re.search(r"(?i)([A-Za-z0-9])\1{7,}|example|placeholder|changeme|dummy|sample|redacted|fake|test_key", tok))


def check_bundled_config(skill_root: Path) -> list[Finding]:
    """Detect bundled settings/MCP/plugin config that can execute code or alter
    the user's environment. Emits Findings directly, like check_frontmatter."""
    findings: list[Finding] = []

    # Locate candidate config files at root and one level into .claude/ and
    # .claude-plugin/. Never follow symlinks.
    search_dirs = [skill_root, skill_root / ".claude", skill_root / ".claude-plugin"]
    candidates: list[Path] = []
    for d in search_dirs:
        if d.is_symlink() or not d.is_dir():
            continue
        for p in sorted(d.iterdir()):
            if p.is_symlink() or not p.is_file():
                continue
            if (p.name in BUNDLED_SETTINGS_NAMES
                    or p.name in BUNDLED_MCP_NAMES
                    or p.name in BUNDLED_PLUGIN_NAMES):
                candidates.append(p)

    for path in candidates:
        rel = path.relative_to(skill_root).as_posix()
        data, err = _parse_json(path)
        is_dict = isinstance(data, dict)
        is_settings = path.name in BUNDLED_SETTINGS_NAMES
        note = "" if err is None else f"; could not parse JSON, matched textually ({err})"

        # ---- hooks -> CR032 (CRITICAL) ----
        if (is_dict and data.get("hooks")) or (data is None and _mentions_key(path, "hooks")):
            findings.append(Finding(
                severity="CRITICAL", rule_id="CR032", file=rel, line=0,
                snippet='"hooks": { ... }',
                why=("Bundled config installs a Claude Code hook — the harness runs its "
                     "shell command automatically on tool/lifecycle events, with no "
                     "allowed-tools entry, and it persists after the skill is deleted" + note),
                suggested_fix=("Refuse. A skill must not ship hooks. If the user wants one, "
                               "they add it to their own settings explicitly, after reading "
                               "the command."),
            ))
            # CR040 — the hook command points at a reputation-bad destination.
            if is_dict:
                for cmd in _hook_command_strings(data.get("hooks")):
                    reason = _reputation_bad_dest(cmd)
                    if reason:
                        findings.append(_cr040_finding(rel, "a hook command", cmd, reason))

        # ---- mcpServers -> CR033 (stdio) / HI017 (remote) ----
        mcp = data.get("mcpServers") if is_dict else None
        if isinstance(mcp, dict):
            for name, srv in mcp.items():
                if not isinstance(srv, dict):
                    continue
                if srv.get("command"):
                    findings.append(Finding(
                        severity="CRITICAL", rule_id="CR033", file=rel, line=0,
                        snippet=f'mcpServers.{name}.command = {srv.get("command")!r}',
                        why=("Bundled config registers a stdio MCP server that launches a "
                             "local process on session start — arbitrary code execution, no "
                             "allowed-tools entry needed"),
                        suggested_fix="Refuse. A skill must not ship a process-launching MCP server.",
                    ))
                    # CR040 — the launched command / args point at a bad destination.
                    cmdtext = str(srv.get("command"))
                    args = srv.get("args")
                    if isinstance(args, list):
                        cmdtext += " " + " ".join(str(a) for a in args if isinstance(a, (str, int, float)))
                    reason = _reputation_bad_dest(cmdtext)
                    if reason:
                        findings.append(_cr040_finding(
                            rel, f"stdio MCP server '{name}' command", cmdtext, reason))
                elif srv.get("url"):
                    findings.append(Finding(
                        severity="HIGH", rule_id="HI017", file=rel, line=0,
                        snippet=f'mcpServers.{name}.url = {srv.get("url")!r}',
                        why=("Bundled config registers a remote MCP server — data egress to a "
                             "third-party endpoint on session start"),
                        suggested_fix=("Remove. If the user wants this server they add it "
                                       "themselves after reviewing the URL."),
                    ))
                    # CR040 — the remote URL points at a reputation-bad host. This is
                    # the verdict-flip: a lone bare-IP / punycode MCP was YELLOW
                    # (HI017 + line HI019/HI022), now RED.
                    reason = _reputation_bad_dest(str(srv.get("url")))
                    if reason:
                        findings.append(_cr040_finding(
                            rel, f"remote MCP server '{name}' url", str(srv.get("url")), reason))

                # CR042 / HI027 — secret-egress in the server's env / headers (the
                # mcpServers loop reads command/args/url; env+headers were unread).
                for sect in ("env", "headers"):
                    bag = srv.get(sect)
                    if not isinstance(bag, dict):
                        continue
                    for vk, vv in bag.items():
                        if not isinstance(vv, str):
                            continue
                        # Test the LIVE-token shape FIRST (so a real token co-located
                        # with the word 'example' is not silenced), and gate on the
                        # MATCHED token being a non-dummy (so `ghp_xxxx…` / `AKIA…EXAMPLE`
                        # are suppressed and a well-formed AKIA key is not swallowed by
                        # the bare-ENV-echo placeholder branch) — adversarial review.
                        tok = _LIVE_TOKEN_RE.search(vv)
                        if tok and not _token_is_dummy(tok.group(0)):
                            findings.append(Finding(
                                severity="CRITICAL", rule_id="CR042", file=rel, line=0,
                                snippet=f"mcpServers.{name}.{sect}.{vk} = <live token>",
                                why=("Bundled MCP config hardcodes a LIVE credential in " + sect
                                     + " — a real token shape (not a ${VAR} placeholder) shipped inside the "
                                       "skill and forwarded to the server on session start"),
                                suggested_fix=("Refuse. Remove the hardcoded secret; an MCP server reads its "
                                               "credential from the user's own environment, never from a value "
                                               "baked into a shipped skill config.")))
                            continue
                        if _is_placeholder(vv):
                            continue
                        rep = _reputation_bad_dest(vv)
                        if rep or _CRED_FILE_RE.search(vv):
                            findings.append(Finding(
                                severity="HIGH", rule_id="HI027", file=rel, line=0,
                                snippet=f"mcpServers.{name}.{sect}.{vk} = {vv[:60]}",
                                why=("Bundled MCP " + sect + " value points at "
                                     + (rep if rep else "a credential file") + " — secret-egress / a "
                                       "credential reference forwarded to the server on session start"),
                                suggested_fix="Remove. Do not ship credential paths or off-host destinations in an MCP config."))
        elif data is None and _mentions_key(path, "mcpServers"):
            findings.append(Finding(
                severity="HIGH", rule_id="HI017", file=rel, line=0,
                snippet='"mcpServers": { ... }',
                why=(f"Bundled config references an MCP server but won't parse as JSON ({err}) "
                     "— inspect manually"),
                suggested_fix="Inspect the mcpServers block by hand.",
            ))

        # ---- permissions broadening (settings only) -> HI018 ----
        broad_perms = False
        if is_settings and is_dict and isinstance(data.get("permissions"), dict):
            perms = data["permissions"]
            if perms.get("allow") or perms.get("defaultMode") in ("bypassPermissions", "acceptEdits"):
                broad_perms = True
        if broad_perms:
            findings.append(Finding(
                severity="HIGH", rule_id="HI018", file=rel, line=0,
                snippet='"permissions": { ... }',
                why=("Bundled settings widen the permission allow-list or relax the default "
                     "permission mode — silent privilege broadening"),
                suggested_fix=("Remove the permissions block. Permission scope is the user's "
                               "call, not the skill's."),
            ))

        # ---- benign settings file still shouldn't be shipped -> ME010 ----
        if (is_settings and is_dict and not data.get("hooks")
                and not data.get("mcpServers") and not broad_perms):
            keys = ", ".join(sorted(str(k) for k in data.keys())) or "(empty)"
            findings.append(Finding(
                severity="MEDIUM", rule_id="ME010", file=rel, line=0,
                snippet=keys[:200],
                why=("Skill ships a settings.json. Even with benign keys, a skill should not "
                     "rewrite the user's Claude Code settings"),
                suggested_fix="Remove the bundled settings file.",
            ))

    # ---- non-standard dirs (inventory-level note) -> INV002 ----
    for d in NONSTANDARD_DIRS:
        p = skill_root / d
        if p.is_dir() and not p.is_symlink():
            findings.append(Finding(
                severity="MEDIUM", rule_id="INV002", file=d + "/", line=0,
                snippet="",
                why=("Non-standard directory for a skill (standard layout is SKILL.md + "
                     "scripts/ + references/). Hook/command/agent/plugin dirs can carry their "
                     "own executable config — review the contents."),
                suggested_fix="Confirm why a skill ships this directory.",
            ))

    return findings


# --------------------------------------------------------------------------
# Supply-chain audit (bundled dependency manifests)
#
# A skill is SKILL.md + scripts/ + references/. A bundled dependency manifest
# (package.json, requirements.txt, pyproject.toml, a lockfile, …) is a
# DECLARATION, not a command — so the line rules, which need a runtime install
# verb (CR021) or a public-IP literal (HI019), never see its dangerous forms:
#   - an npm install-lifecycle script (preinstall/postinstall/…) → arbitrary
#     shell on a plain `npm install`, the static twin of a bundled hook (CR032);
#   - a dependency pulled from a NON-REGISTRY source (VCS, an arbitrary URL /
#     tarball / wheel, non-TLS http, an index/source redirect, a poisoned
#     lockfile `resolved`) → bypasses the registry's signing/audit;
#   - an UNPINNED dep (`*`, `latest`, a bare name, an unbounded `>=`) → a future
#     malicious release lands silently at the next install.
#
# Detection is STRUCTURAL and keys off manifest FILENAMES (like
# check_bundled_config keys off config filenames) — so a references/*.json data
# file with a "dependencies" key, and prose / fenced docs, stay GREEN. Parsing is
# stdlib-only and NEVER executes the file: json.loads for package.json / JSON
# locks, a line-based section-aware parse for requirements / pyproject, and a
# generic source-line scan for the remaining text manifests (no tomllib — keeps
# the existing 3.9 floor; no yaml.load — CR017 itself bans it). On parse failure
# it degrades to a textual note, never raising.
# --------------------------------------------------------------------------

# npm script keys the package manager runs AUTOMATICALLY on a plain install.
LIFECYCLE_SCRIPTS = {"preinstall", "install", "postinstall",
                     "prepare", "prepublish", "prepublishOnly"}

# Hosts that ARE the registry — a URL here is not an off-registry bypass.
REGISTRY_HOSTS = frozenset({
    "pypi.org", "files.pythonhosted.org",
    "registry.npmjs.org", "registry.yarnpkg.com", "registry.npmmirror.com",
    "crates.io", "static.crates.io",
    "rubygems.org",
    "proxy.golang.org",
    "conda.anaconda.org", "repo.anaconda.com",
})

# Manifest filenames we inspect (the filename gate). Lockfiles are scanned for
# off-registry SOURCE only — never for ME012 (a lock IS the pin).
SUPPLY_MANIFEST_NAMES = {
    "package.json", "package-lock.json", "npm-shrinkwrap.json",
    "yarn.lock", "pnpm-lock.yaml",
    "Pipfile", "Pipfile.lock", "pyproject.toml",
    "Gemfile", "Gemfile.lock",
    "Cargo.toml", "Cargo.lock",
    "go.mod",
    "environment.yml", "environment.yaml",
    "binding.gyp",
}
LOCKFILE_NAMES = {
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
    "Pipfile.lock", "Gemfile.lock", "Cargo.lock",
}
# ME012 (unpinned) applies only to these top-level manifest kinds — a lock pins
# by construction, and go.mod is pinned + checksummed by go.sum.
ME012_KINDS = {"package.json", "pyproject.toml", "requirements"}

# Where a manifest can live (root + one level into common subdirs). Mirrors
# check_bundled_config's shallow, symlink-skipping discovery.
SUPPLY_SEARCH_SUBDIRS = ("scripts", "references", "assets")

_VCS_PREFIXES = ("git+", "hg+", "svn+", "bzr+", "git://", "git@")


def _is_requirements_txt(name: str) -> bool:
    return name.startswith("requirements") and name.endswith(".txt")


def _host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def _is_registry_host(host: str) -> bool:
    host = (host or "").lower()
    return host in REGISTRY_HOSTS or any(host.endswith("." + h) for h in REGISTRY_HOSTS)


def _unquote(spec) -> str:
    s = "" if spec is None else str(spec).strip()
    if len(s) >= 2 and s[0] in "\"'" and s[-1] == s[0]:
        s = s[1:-1].strip()
    return s


def _is_npm_bare_shorthand(s: str) -> bool:
    """`user/repo` (npm's github shorthand): exactly one slash, no scheme, no
    leading @scope, left segment not a protocol word, and not a version range —
    so `^1.2.3` / `~2` / `1.x` / `*` / `latest` / `dist/index.js`-style values
    never match (a real dep value is a version or a source, not a bin path)."""
    s = s.strip()
    if s.count("/") != 1 or "://" in s or s.startswith("@"):
        return False
    left = s.split("/", 1)[0].lower()
    if left in {"npm", "file", "link", "workspace", "portal", "path",
                "github", "gitlab", "bitbucket"}:
        return False
    if re.search(r"[<>=~^*\s]", s) or s[:1].isdigit():
        return False
    return bool(re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*(#.+)?$", s))


def _classify_source(spec):
    """Return a short reason string if `spec` names a NON-REGISTRY dependency
    source (the HI023 signal), else None. Local / workspace / relative paths and
    registry URLs return None."""
    s = _unquote(spec)
    if s.startswith("@"):                 # PEP 508 direct-ref marker (`name @ url`)
        s = s[1:].strip()
    if not s:
        return None
    low = s.lower()

    # Local / workspace / protocol-alias / relative — not a remote bypass.
    if low.startswith(("file:", "link:", "portal:", "workspace:", "path:",
                       "npm:", "./", "../", ".\\", "..\\", "/", "~")):
        return None

    # Registry source prefixes (Cargo.lock `registry+…` / `sparse+…`). Only the
    # OFFICIAL crates.io index (the GitHub-hosted git index or the sparse index) and
    # a known registry host are exempt — `registry+https://attacker.test/…` is an
    # off-registry alternate registry and still flags.
    if low.startswith(("registry+", "sparse+")):
        inner = s.split("+", 1)[1]
        ih = _host_of(inner)
        try:
            ipath = urlsplit(inner).path.rstrip("/").lower()
        except ValueError:
            ipath = ""
        if ipath.endswith(".git"):
            ipath = ipath[:-4]
        # Exact official path only — `github.com/attacker/rust-lang/crates.io-index`
        # is a DIFFERENT repo and must not be allowlisted by a substring match.
        if (ih in ("index.crates.io", "static.crates.io")
                or (ih == "github.com" and ipath == "/rust-lang/crates.io-index")
                or _is_registry_host(ih)):
            return None
        return "off-registry alternate registry source (" + (ih or inner) + ")"

    # VCS scheme prefixes (git+https, git+ssh, hg+, svn+, bzr+, git://, git@host:).
    for p in _VCS_PREFIXES:
        if low.startswith(p):
            return "VCS dependency source (" + p.rstrip("+:") + ")"

    # github:/gitlab:/bitbucket: shorthand.
    m = re.match(r"(?i)^(github|gitlab|bitbucket):", s)
    if m:
        return "VCS shorthand (" + m.group(1).lower() + ":)"

    # Any http(s)/ftp URL inside the spec (covers `name @ https://…` and bare URLs).
    um = re.search(r"(?i)(https?|ftp)://[^\s\"'#;,)\]]+", s)
    if um:
        url, scheme = um.group(0), um.group(1).lower()
        host = _host_of(url)
        if scheme == "http":
            return "non-TLS http dependency source (" + (host or "?") + ")"
        if host and not _is_registry_host(host):
            return "off-registry URL dependency source (" + host + ")"
        return None  # registry https — fine

    # Bare npm github shorthand `user/repo`.
    if _is_npm_bare_shorthand(s):
        return "git shorthand dependency (user/repo)"

    return None


def _is_pinned(spec) -> bool:
    """True if a dependency version specifier is pinned ENOUGH to stay GREEN:
    an exact `==`/`===`/exact-semver/`=X.Y.Z`, a `--hash`-locked line, OR a
    bounded range (`^`, `~`, `~=`, `<`-bounded, comma-bounded). Only the truly
    OPEN forms (`*`, `latest`/`next`, `x`-range, bare-empty, unbounded `>=`/`>`)
    are unpinned — caret/tilde are the npm/PEP440 default and flagging them would
    blow the MEDIUM budget."""
    s = _unquote(spec)
    low = s.lower()
    if not s:
        return False  # bare name, no version → unpinned
    # Local / workspace / protocol specs are pinned by locality.
    if low.startswith(("file:", "link:", "portal:", "workspace:", "path:",
                       "npm:", "./", "../", "/", "~")):
        return True
    if low in ("*", "x", "latest", "next") or low == "":
        return False
    # x-range / wildcard anywhere: *, x, 1.x, 1.2.x, 1.* → unpinned (an `x`/`*`
    # version component, the rest digits). Matches the rule table's open forms.
    xparts = s.lstrip("vV=").split(".")
    if (any(p in ("x", "X", "*") for p in xparts)
            and all(p.isdigit() or p in ("x", "X", "*", "") for p in xparts)):
        return False
    # Unbounded lower-bound only: >=1.0 / >1.0 with no upper bound, no comma.
    if re.match(r"^>=?\s*[0-9]", s) and "," not in s and "<" not in s:
        return False
    return True  # exact / bounded / hashed / caret / tilde → pinned-enough


# --- per-manifest parsers (each yields (name, spec, lineno); never executes) ---

def _join_requirements_lines(text):
    """Yield (logical_line, lineno) for a requirements file, joining
    `\\`-continuations and stripping comments (a `#` at line start or after
    whitespace — a URL fragment `…#egg=` is preceded by non-space and survives)."""
    buf, start = "", 0
    for ln_no, raw in enumerate(text.splitlines(), start=1):
        line = re.sub(r"(?:^|\s)#.*$", "", raw)
        if not buf:
            start = ln_no
        if line.rstrip().endswith("\\"):
            buf += line.rstrip()[:-1] + " "
            continue
        buf += line
        if buf.strip():
            yield buf.strip(), start
        buf = ""
    if buf.strip():
        yield buf.strip(), start


def _supply_requirements(text, rel):
    findings, unpinned = [], []
    for line, ln in _join_requirements_lines(text):
        low = line.lower()
        if line.startswith("-"):
            # Option lines: index/source redirects, trusted-host (disables TLS),
            # and editable installs. Accept both `--opt value` and `--opt=value`.
            om = re.match(r"(?i)^(--index-url|--extra-index-url|-i|--trusted-host|-e|--editable|-f|--find-links)(?:[=\s]+(.*))?$", line)
            if om:
                opt, val = om.group(1).lower(), (om.group(2) or "").strip()
                if opt in ("-e", "--editable", "-f", "--find-links"):
                    reason = _classify_source(val)            # remote VCS/URL source; local ./ skipped
                elif "://" in val:
                    reason = _classify_source(val)            # --index-url with a URL
                elif val and not _is_registry_host(_host_of("//" + val) or val):
                    reason = "off-registry index host (" + val + ")"   # bare --trusted-host
                else:
                    reason = None
                if reason:
                    findings.append(Finding(
                        severity="HIGH", rule_id="HI023", file=rel, line=ln,
                        snippet=line[:120],
                        why="Dependency index / source redirect to a non-registry host — " + reason
                            + "; pulls packages past the registry's signing and audit (dependency confusion).",
                        suggested_fix="Remove the redirect; install from the default registry, or pin with --hash."))
            continue
        dep = line.split(";", 1)[0].strip()         # drop env marker
        if " @ " in dep:                            # PEP 508 direct reference
            name, _, tail = dep.partition(" @ ")
            name, spec = name.strip(), "@ " + tail.strip()
        elif re.match(r"(?i)^(?:https?|ftp)://|^git[+@]|^(?:hg|svn|bzr)\+", dep):
            name, spec = "", dep                    # bare URL / VCS dependency
        else:
            mm = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)$", dep)
            if not mm:
                continue
            name, spec = mm.group(1), mm.group(2).strip()
        reason = _classify_source(spec)
        if reason:
            findings.append(Finding(
                severity="HIGH", rule_id="HI023", file=rel, line=ln,
                snippet=line[:120],
                why="Dependency from a non-registry source — " + reason
                    + "; bypasses the registry's signing/audit and (for git/tarball) runs the fetched package's own build hooks at install.",
                suggested_fix="Pin to a registry release (name==X.Y.Z), or vendor and audit the source explicitly."))
        elif not _is_pinned(spec):
            unpinned.append(name or dep[:30])
    return findings, unpinned


def _supply_pyproject(text, rel):
    """Section-aware line parse of pyproject.toml — only the dependency tables:
    the PEP 621 `[project]` `dependencies`/`optional-dependencies` arrays, the
    `[project.optional-dependencies]` group arrays, and the Poetry
    `[tool.poetry(.group.*).(dev-)dependencies]` tables. Arrays are accumulated
    across lines so a dep on a continuation line is not a silent miss.
    `[project.urls]` and other metadata are ignored, so a Homepage git URL never
    fires."""
    findings, unpinned = [], []
    section = ""
    in_array = False                                 # accumulating a PEP 508 array

    def handle_dep(name, spec, ln, raw):
        reason = _classify_source(spec)
        if reason:
            findings.append(Finding(
                severity="HIGH", rule_id="HI023", file=rel, line=ln,
                snippet=raw[:120],
                why="Dependency from a non-registry source — " + reason
                    + "; bypasses the registry's signing/audit and may run build hooks at install.",
                suggested_fix="Pin to a registry release, or vendor and audit the source."))
        elif name and not _is_pinned(spec):
            unpinned.append(name)

    def handle_pep508(item, ln, raw):
        nm = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)", item)
        spec = item[nm.end():].strip() if nm else item
        handle_dep(nm.group(1) if nm else "", spec, ln, raw)

    def is_poetry_table(sec):
        return (sec in ("tool.poetry.dependencies", "tool.poetry.dev-dependencies")
                or (sec.startswith("tool.poetry.group.") and sec.endswith(".dependencies")))

    def is_pep508_array_section(sec):
        return sec == "project" or sec.startswith("project.optional-dependencies")

    for ln_no, raw in enumerate(text.splitlines(), start=1):
        line = re.sub(r"(?:^|\s)#.*$", "", raw).rstrip()
        st = line.strip()
        if not st:
            continue
        hm = re.match(r"^\[+([^\]]+)\]+\s*$", st)
        if hm:
            section, in_array = hm.group(1).strip(), False
            continue
        if in_array:                                 # continuation of a PEP 508 array
            for a, b in re.findall(r"\"([^\"]+)\"|'([^']+)'", st):
                handle_pep508(a or b, ln_no, raw)
            if "]" in st:
                in_array = False
            continue
        if section == "tool.poetry.source":          # [[tool.poetry.source]] url = "…"
            um = re.search(r"(?i)\burl\s*=\s*[\"']([^\"']+)[\"']", st)
            if um:
                reason = _classify_source(um.group(1))
                if reason:
                    findings.append(Finding(
                        severity="HIGH", rule_id="HI023", file=rel, line=ln_no,
                        snippet=raw.strip()[:120],
                        why="Poetry custom package source points off-registry — " + reason
                            + "; a dependency tagged with this source is fetched past the default registry's audit.",
                        suggested_fix="Remove the custom source, or point it at the official index."))
            continue
        if is_pep508_array_section(section):
            am = re.match(r"^([A-Za-z0-9_.-]+)\s*=\s*\[(.*)$", st)
            if am:
                key = am.group(1).strip()
                # under [project] only the dep keys are deps (not keywords/classifiers);
                # under [project.optional-dependencies] every key is a dep group.
                if section != "project" or key in ("dependencies", "optional-dependencies"):
                    for a, b in re.findall(r"\"([^\"]+)\"|'([^']+)'", am.group(2)):
                        handle_pep508(a or b, ln_no, raw)
                    in_array = "]" not in st
                    continue
        if is_poetry_table(section):                 # name = "^1.2"  or  name = { git = "…" }
            km = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*=\s*(.+)$", st)
            if not km:
                continue
            name, val = km.group(1), km.group(2).strip()
            if name.lower() == "python":             # poetry's python constraint, not a dep
                continue
            if val.startswith("{"):                  # inline table: scan for git/url/path
                im = re.search(r"(?:git|url)\s*=\s*([\"'][^\"']+[\"'])", val)
                if im:
                    handle_dep(name, im.group(1), ln_no, raw)
                vm = re.search(r"version\s*=\s*([\"'][^\"']+[\"'])", val)
                if vm and not _is_pinned(vm.group(1)):
                    unpinned.append(name)
            else:
                handle_dep(name, val, ln_no, raw)
    return findings, unpinned


def _supply_source_scan(text, rel, kind):
    """Generic off-registry SOURCE scan for the remaining text manifests
    (yarn.lock, pnpm-lock.yaml, Pipfile, Cargo.toml, Gemfile, go.mod,
    environment.yml). Flags VCS / off-registry-URL / shorthand sources per line;
    no ME012 (unpinned) detection for these kinds. Dedups HI023 per host/reason.

    Section-aware for TOML manifests: skips a single-bracket project-METADATA
    section ([package], [package.metadata.*], [badges], [workspace.package]) so a
    crate's repository / homepage / documentation URL — present on nearly every
    published crate — is not misread as a dependency source. A DOUBLE-bracket
    array-of-tables ([[package]] in Cargo.lock) is NOT metadata — it is a locked
    dependency entry whose `source` field must be scanned — so it is never skipped.
    Dependency / [source.*] tables are still scanned. For non-TOML manifests no
    [section] header matches, so the skip is inert and behavior is unchanged."""
    findings, seen = [], set()
    skip_section = False
    for ln_no, raw in enumerate(text.splitlines(), start=1):
        line = re.sub(r"(?:^|\s)#.*$", "", raw)
        hm = re.match(r"^\s*(\[\[?)\s*([^\]]+?)\s*\]\]?\s*$", line)
        if hm:
            is_array_table = hm.group(1) == "[["
            sec = hm.group(2).strip().strip("\"'").lower()
            skip_section = (not is_array_table) and (
                sec == "package" or sec.startswith("package.")
                or sec in ("badges", "workspace.package"))
            continue
        if skip_section:
            continue
        # The scheme-prefix alternative is matched FIRST and greedily so a
        # `registry+https://…` / `sparse+https://…` token is read WITH its prefix
        # (a Cargo.lock registry source is GitHub-hosted; without the prefix the
        # inner github URL would false-positive). git+/hg+/svn+/bzr+ flag as VCS.
        for m in re.finditer(r"(?i)(?:(?:git|hg|svn|bzr|registry|sparse)\+[^\s\"'#;,)\]]+"
                             r"|(?:https?|ftp)://[^\s\"'#;,)\]]+"
                             r"|(?:github|gitlab|bitbucket):[^\s\"'#;,)\]]+)", line):
            reason = _classify_source(m.group(0))
            if reason and reason not in seen:
                seen.add(reason)
                findings.append(Finding(
                    severity="HIGH", rule_id="HI023", file=rel, line=ln_no,
                    snippet=raw.strip()[:120],
                    why="Dependency/lockfile source points off-registry — " + reason
                        + "; bypasses the registry's signing/audit.",
                    suggested_fix="Resolve from the registry; remove the git/URL source or vendor & audit it."))
    return findings


def _supply_gomod(text, rel):
    """go.mod source scan. Normal `require github.com/x/y vN` lines are pinned +
    checksummed by go.sum (not flagged). The supply-chain signal is a
    `replace OLD => NEW` whose NEW is a REMOTE module path (a host-like first
    segment, not a local `./`/`../`/`/` path) — it redirects a dependency to a
    different, possibly attacker-controlled, module. Handles the single-line form
    and the `replace ( … )` block."""
    findings, seen = [], set()
    in_block = False
    for ln_no, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("//", 1)[0].strip()
        if not line:
            continue
        if re.match(r"^replace\s*\($", line):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        target = None
        m = re.match(r"^replace\s+\S.*?=>\s*(\S+)", line)
        if m:
            target = m.group(1)
        elif in_block:
            m2 = re.match(r"^\S.*?=>\s*(\S+)", line)
            if m2:
                target = m2.group(1)
        if not target or target.startswith(("./", "../", "/", ".\\", "..\\")):
            continue                                  # local replace — fine
        host_seg = target.split("/", 1)[0]
        if "." in host_seg and host_seg not in seen:  # remote module path
            seen.add(host_seg)
            findings.append(Finding(
                severity="HIGH", rule_id="HI023", file=rel, line=ln_no,
                snippet=line[:120],
                why="go.mod `replace` redirects a dependency to a remote module (" + target
                    + ") — swaps the resolved source for a different, possibly attacker-controlled, host.",
                suggested_fix="Remove the replace, or point it at an audited local vendor path."))
    return findings


def _supply_json_lock(data, rel):
    """Walk a JSON lockfile (package-lock.json / npm-shrinkwrap.json) for
    `resolved` / `tarball` URLs that point off-registry. Dedups per host. Only the
    dependency-SOURCE keys are inspected — a metadata `url` (e.g. `funding.url`,
    `repository.url`) is not a source and would otherwise false-positive."""
    findings, seen = [], set()
    def walk(node, depth=0):
        if depth > 200:          # deep nesting is itself suspicious; never recurse-crash
            return
        if isinstance(node, dict):
            for k, v in node.items():
                if k in ("resolved", "tarball") and isinstance(v, str):
                    reason = _classify_source(v)
                    if reason:
                        host = _host_of(v) or reason
                        if host not in seen:
                            seen.add(host)
                            findings.append(Finding(
                                severity="HIGH", rule_id="HI023", file=rel, line=0,
                                snippet=(k + ": " + v)[:120],
                                why="Lockfile resolves a package off-registry — " + reason
                                    + "; a poisoned `resolved` URL ships attacker code despite a clean top-level manifest.",
                                suggested_fix="Regenerate the lock against the official registry."))
                else:
                    walk(v, depth + 1)
        elif isinstance(node, list):
            for v in node:
                walk(v, depth + 1)
    walk(data)
    return findings


def _supply_package_json(data, path, rel):
    """CR039 (lifecycle scripts) + HI023/ME012 over the dependency tables."""
    findings, unpinned = [], []
    if not isinstance(data, dict):
        return findings, unpinned
    scripts = data.get("scripts")
    if isinstance(scripts, dict):
        for key in sorted(scripts):
            val = scripts[key]
            if key in LIFECYCLE_SCRIPTS and isinstance(val, str) and val.strip():
                findings.append(Finding(
                    severity="CRITICAL", rule_id="CR039", file=rel, line=0,
                    snippet=("scripts." + key + " = " + val)[:120],
                    why=("Bundled package.json defines an install-lifecycle script (" + key
                         + ") — the package manager runs it automatically on a plain `npm install`/"
                         "`npm ci`, with no allowed-tools entry. Presence is the danger, not the "
                         "command text; a skill is never an npm-installed package."),
                    suggested_fix="Refuse. Remove the install-lifecycle script; a skill must not run code on dependency install."))
    for dk in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        deps = data.get(dk)
        if not isinstance(deps, dict):
            continue
        for name in sorted(deps):
            spec = deps[name]
            if not isinstance(spec, str):
                continue
            reason = _classify_source(spec)
            if reason:
                findings.append(Finding(
                    severity="HIGH", rule_id="HI023", file=rel, line=0,
                    snippet=(name + ": " + spec)[:120],
                    why="npm dependency from a non-registry source — " + reason
                        + "; bypasses the registry and (for git/tarball) runs the fetched package's lifecycle scripts at install.",
                    suggested_fix="Pin to a registry version (name: \"X.Y.Z\"); remove the git/URL/shorthand source."))
            elif not _is_pinned(spec):
                unpinned.append(name)
    return findings, unpinned


def _supply_binding_gyp(path: Path, rel: str) -> list[Finding]:
    """binding.gyp (node-gyp) install-time RCE. A skill is never a legitimately
    npm-installed native addon, so PRESENCE is HIGH (HI028); a gyp command-
    substitution token `<!(` / `<!@(` in any string value runs a shell command on a
    plain `npm install` with NO package.json script (Phantom Gyp) -> CRITICAL (CR043)."""
    findings = [Finding(
        severity="HIGH", rule_id="HI028", file=rel, line=0, snippet="binding.gyp",
        why=("Bundled binding.gyp — node-gyp runs it automatically on `npm install` to build a "
             "native addon; a Claude skill is never a legitimately npm-installed native addon"),
        suggested_fix="Remove binding.gyp. A skill is SKILL.md + scripts/ + references/, not a native addon.")]
    data, err = _parse_json(path)
    found = []
    if err is None:
        _MAX = 200   # deep nesting is itself suspicious; bound below Python's ~1000 limit
        def walk(n, depth=0):
            if depth > _MAX:
                return
            if isinstance(n, dict):
                for v in n.values():
                    walk(v, depth + 1)
            elif isinstance(n, list):
                for v in n:
                    walk(v, depth + 1)
            elif isinstance(n, str) and ("<!(" in n or "<!@(" in n):
                found.append(n)
        walk(data)
    else:
        text = _read_text_safe(path) or ""
        if "<!(" in text or "<!@(" in text:
            found.append(text)
    for v in found[:3]:
        findings.append(Finding(
            severity="CRITICAL", rule_id="CR043", file=rel, line=0, snippet=v.strip()[:120],
            why=("binding.gyp uses a gyp command-substitution token (<!( / <!@() — node-gyp executes the "
                 "embedded shell command on `npm install` with NO package.json lifecycle script (Phantom "
                 "Gyp install-time RCE)" + ("" if err is None else "; matched textually (" + err + ")")),
            suggested_fix="Refuse. Remove the <!( command-substitution; it is arbitrary shell at install time."))
    return findings


def check_supply_chain(skill_root: Path) -> list[Finding]:
    """Detect bundled dependency manifests that ship install-lifecycle scripts
    (CR039), non-registry sources (HI023), or unpinned deps (ME012). Structural,
    filename-keyed, never executes the file. Emits Findings directly."""
    findings: list[Finding] = []

    search_dirs = [skill_root] + [skill_root / d for d in SUPPLY_SEARCH_SUBDIRS]
    candidates: list[Path] = []
    for d in search_dirs:
        if d.is_symlink() or not d.is_dir():
            continue
        for p in sorted(d.iterdir()):
            if p.is_symlink() or not p.is_file():
                continue
            if p.name in SUPPLY_MANIFEST_NAMES or _is_requirements_txt(p.name):
                candidates.append(p)

    for path in candidates:
        rel = path.relative_to(skill_root).as_posix()
        name = path.name
        is_lock = name in LOCKFILE_NAMES
        kind = ("requirements" if _is_requirements_txt(name) else name)
        unpinned: list[str] = []

        if name in ("package.json", "package-lock.json", "npm-shrinkwrap.json"):
            data, err = _parse_json(path)
            if err is not None:
                # Won't parse — textual backstop for lifecycle scripts.
                if name == "package.json":
                    for key in sorted(LIFECYCLE_SCRIPTS):
                        if _mentions_key(path, key):
                            findings.append(Finding(
                                severity="CRITICAL", rule_id="CR039", file=rel, line=0,
                                snippet='"' + key + '": ...',
                                why=("Bundled package.json references an install-lifecycle script (" + key
                                     + ") but won't parse as JSON (" + err + ") — inspect manually; "
                                     "a lifecycle script runs automatically on `npm install`."),
                                suggested_fix="Inspect by hand; remove any install-lifecycle script."))
                continue
            if name == "package.json":
                fs, unpinned = _supply_package_json(data, path, rel)
                findings.extend(fs)
            else:
                findings.extend(_supply_json_lock(data, rel))
        elif _is_requirements_txt(name):
            text = _read_text_safe(path) or ""
            fs, unpinned = _supply_requirements(text, rel)
            findings.extend(fs)
        elif name == "pyproject.toml":
            text = _read_text_safe(path) or ""
            fs, unpinned = _supply_pyproject(text, rel)
            findings.extend(fs)
        elif name == "go.mod":
            text = _read_text_safe(path) or ""
            findings.extend(_supply_gomod(text, rel))
        elif name == "binding.gyp":
            findings.extend(_supply_binding_gyp(path, rel))
        else:
            text = _read_text_safe(path) or ""
            findings.extend(_supply_source_scan(text, rel, kind))

        # ME012 — one aggregated finding per top-level manifest (never a lock).
        if unpinned and kind in ME012_KINDS and not is_lock:
            shown = ", ".join(unpinned[:8]) + (" …" if len(unpinned) > 8 else "")
            findings.append(Finding(
                severity="MEDIUM", rule_id="ME012", file=rel, line=0,
                snippet=shown[:160],
                why=(str(len(unpinned)) + " unpinned dependency(ies) in a bundled manifest ("
                     + shown + ") — an open specifier (*, latest, bare name, unbounded >=) lets a "
                     "future malicious release land silently at the next install."),
                suggested_fix="Pin each to an exact version (name==X.Y.Z / \"X.Y.Z\"), or lock with --hash."))

    return findings


# --------------------------------------------------------------------------
# Python AST pass
#
# The regex pass is line-based, so it misses dangerous calls that are aliased
# (`e = eval; e(x)`), split across lines (`subprocess.run(\n  cmd,\n  shell=True)`),
# or built dynamically (`getattr(os, "sys" + "tem")`). ast.parse builds the syntax
# tree WITHOUT executing the code, and the tree is immune to surface layout — a
# call is one Call node however it is written. This pass resolves call targets
# structurally.
#
# It NEVER executes the audited code (ast.parse only). If the source won't parse
# (syntax error, Python 2, non-Python), the pass degrades to a no-op and the
# regex pass still applies. It also distinguishes a string literal "eval(" from a
# real eval() call, so it does not reproduce the regex self-audit false positives.
# --------------------------------------------------------------------------

_CODE_EXEC_BUILTINS = {"eval", "exec", "compile"}

# os process-replacement / spawn family (AST010) — completes AST003, which models
# only os.system/os.popen/subprocess.*. Severity mirrors AST003: non-literal program
# path -> CRITICAL, literal -> HIGH.
_OS_EXEC_FAMILY = {
    "os.execv", "os.execve", "os.execvp", "os.execvpe",
    "os.execl", "os.execle", "os.execlp", "os.execlpe",
    "os.spawnv", "os.spawnve", "os.spawnvp", "os.spawnvpe",
    "os.spawnl", "os.spawnle", "os.spawnlp", "os.spawnlpe",
    "os.posix_spawn", "os.posix_spawnp",
}


def _is_own_file_target(node) -> bool:
    """True only if `node` IS, INLINE, the skill's own running file: bare `__file__`
    or `Path(__file__)` (single positional arg, no transform). A DERIVED sibling
    (`.with_name`/`.with_suffix`/`.parent`/`os.path.dirname`/`/`-join) is a DIFFERENT
    file and is NOT a self-target (AST009 FP guard). A Name BOUND to `__file__` on a
    prior line is deliberately NOT tracked — a global flow-insensitive binding set
    caused cross-function false AST009 (Codex audit); soundness over the clever catch."""
    if isinstance(node, ast.Name):
        return node.id == "__file__"
    if isinstance(node, ast.Call):
        f = node.func
        tail = f.attr if isinstance(f, ast.Attribute) else (f.id if isinstance(f, ast.Name) else None)
        if tail == "Path" and len(node.args) == 1 and not node.keywords:
            return _is_own_file_target(node.args[0])
    return False


def _extract_is_guarded(call) -> bool:
    """True if an `extractall` call has a REAL member guard (so AST011 does not fire):
    `filter="data"`/`"tar"` (the SAFE filters — `"fully_trusted"` is the legacy no-op
    that does NOT protect), or `members=<a specific list>` (NOT `t.getmembers()`/
    `getnames()`, which passes ALL members and is no protection at all) — Codex audit."""
    for kw in call.keywords:
        if kw.arg == "filter" and isinstance(kw.value, ast.Constant):
            if str(kw.value.value) in ("data", "tar"):
                return True
        if kw.arg == "members":
            v = kw.value
            if isinstance(v, ast.Call) and isinstance(v.func, ast.Attribute) \
                    and v.func.attr in ("getmembers", "getnames"):
                continue   # extractall(members=t.getmembers()) = all members, no guard
            return True
    return False


def _write_mode(node, idx) -> bool:
    """True if an open-style call's mode (positional `idx` or `mode=`) is a write mode
    (w/a/x) — so a READ of the skill's own file never fires AST009."""
    mode = ""
    if len(node.args) > idx and isinstance(node.args[idx], ast.Constant):
        mode = str(node.args[idx].value)
    for kw in node.keywords:
        if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
            mode = str(kw.value.value)
    # 'w'/'a'/'x' OR a '+' update mode ('r+'/'rb+' is read-WRITE — Codex audit).
    return any(c in mode for c in "wax+")


def _dotted_name(node):
    """Resolve a func/expr node to a dotted name ('os.system', 'eval').
    Returns None if it is not a plain Name/Attribute chain."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def _is_literal(node):
    """True if the node is a constant or a literal container of constants."""
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return all(_is_literal(e) for e in node.elts)
    if isinstance(node, ast.Dict):
        return all(
            (k is None or _is_literal(k)) and _is_literal(v)
            for k, v in zip(node.keys, node.values)
        )
    return False  # Name, Call, BinOp, JoinedStr (f-string), … → dynamic


def _uses_constructor(node):
    """True if the expression contains chr() / bytes.fromhex / codecs.decode /
    x.join(...) — signals a string assembled from data (obfuscation)."""
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            n = _dotted_name(sub.func)
            if n in ("chr", "bytes.fromhex", "codecs.decode") or (n and n.endswith(".join")):
                return True
    return False


class _AstAuditor(ast.NodeVisitor):
    def __init__(self, rel, src, alias):
        self.rel = rel
        self.src = src
        self.alias = alias            # name -> builtin it aliases
        self.findings = []

    def _add(self, node, rule_id, severity, why, fix=""):
        try:
            seg = ast.get_source_segment(self.src, node) or ""
        except Exception:
            seg = ""
        seg = " ".join(seg.split())
        if len(seg) > 120:
            seg = seg[:117] + "..."
        self.findings.append(Finding(
            severity=severity, rule_id=rule_id, file=self.rel,
            line=getattr(node, "lineno", 0), snippet=seg, why=why,
            suggested_fix=fix,
        ))

    def visit_Call(self, node):
        name = _dotted_name(node.func)
        arg0 = node.args[0] if node.args else None

        # AST009 — skill rewrites its OWN running file at runtime (the write TARGET is
        # INLINE __file__ / Path(__file__), not a derived sibling). Reads and other-path
        # writes never fire. Covers builtin open / Path(__file__).open / write_text|
        # write_bytes / os.replace|rename + shutil.copy*|move (destination). A Name bound
        # to __file__ on a prior line is NOT tracked (Codex audit: the global binding set
        # was flow-insensitive and produced cross-function false AST009).
        if name == "open" and arg0 is not None and _is_own_file_target(arg0):
            if _write_mode(node, 1):
                self._add(node, "AST009", "HIGH",
                          "open(__file__, <write>) writes the skill's own running file — runtime self-modification defeats a pre-install audit (audited-once, mutates-later)")
        elif (isinstance(node.func, ast.Attribute) and node.func.attr == "open"
              and _is_own_file_target(node.func.value) and _write_mode(node, 0)):
            self._add(node, "AST009", "HIGH",
                      "Path(__file__).open(<write>) writes the skill's own running file — runtime self-modification")
        elif (isinstance(node.func, ast.Attribute)
              and node.func.attr in ("write_text", "write_bytes")
              and _is_own_file_target(node.func.value)):
            self._add(node, "AST009", "HIGH",
                      "." + node.func.attr + "(...) targets the skill's own file (__file__) — runtime self-modification")
        elif (name in ("os.replace", "os.rename", "shutil.copyfile", "shutil.copy",
                       "shutil.copy2", "shutil.move")
              and len(node.args) >= 2 and _is_own_file_target(node.args[1])):
            self._add(node, "AST009", "HIGH",
                      name + "(..., __file__) overwrites the skill's own running file — runtime self-modification")

        if name in _CODE_EXEC_BUILTINS:
            if arg0 is not None and _uses_constructor(arg0):
                self._add(node, "AST008", "CRITICAL",
                          name + "() over a string built from char codes / decoded bytes — obfuscated payload execution")
            elif arg0 is None or not _is_literal(arg0):
                self._add(node, "AST001", "CRITICAL",
                          name + "() over a non-literal argument — dynamic code execution")

        elif name in self.alias:
            self._add(node, "AST002", "CRITICAL",
                      "call to '" + name + "', an alias of " + self.alias[name] + "() — hidden dynamic code execution")

        elif name in ("os.system", "os.popen"):
            nonlit = arg0 is not None and not _is_literal(arg0)
            self._add(node, "AST003", "CRITICAL" if nonlit else "HIGH",
                      name + "()" + (" with a non-literal command — command injection" if nonlit else " — shell execution"))

        elif name is not None and name.startswith("subprocess."):
            shell_true = any(
                kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                for kw in node.keywords
            )
            if shell_true:
                nonlit = arg0 is not None and not _is_literal(arg0)
                self._add(node, "AST003", "CRITICAL" if nonlit else "HIGH",
                          name + "(..., shell=True)" + (" with a non-literal command — command injection" if nonlit else " — prefer an argument list over shell=True"))

        elif name in ("pickle.loads", "marshal.loads"):
            self._add(node, "AST004", "CRITICAL",
                      name + "() deserializes arbitrary objects — remote code execution")

        elif name in _OS_EXEC_FAMILY:
            # The PROGRAM-PATH arg index is signature-dependent: os.spawn*(mode, file,
            # ...) puts the program at arg1 (arg0 is P_WAIT/P_NOWAIT); os.exec*(path,
            # ...) and os.posix_spawn[p](path, ...) put it at arg0 (adversarial review).
            idx = 1 if ".spawn" in name else 0
            prog = node.args[idx] if len(node.args) > idx else None
            nonlit = prog is not None and not _is_literal(prog)
            self._add(node, "AST010", "CRITICAL" if nonlit else "HIGH",
                      name + "() replaces/spawns a process image"
                      + (" with a non-literal program path — dynamic process execution (AST003 sibling)"
                         if nonlit else " — process execution (a literal exec of a fixed program)"))

        elif (name == "shutil.unpack_archive"
              or (isinstance(node.func, ast.Attribute) and node.func.attr == "extractall"
                  and not _extract_is_guarded(node))):
            self._add(node, "AST011", "MEDIUM",
                      "archive extractall / unpack_archive without a member filter — Zip-Slip path "
                      "traversal can overwrite files outside the target dir (e.g. ~/.ssh, ~/.claude)")

        elif name == "yaml.load":
            safe = any(
                kw.arg == "Loader" and "Safe" in (_dotted_name(kw.value) or "")
                for kw in node.keywords
            )
            if not safe:
                self._add(node, "AST005", "HIGH",
                          "yaml.load() without SafeLoader — RCE on crafted YAML; use yaml.safe_load")

        elif name == "getattr":
            if len(node.args) >= 2 and not _is_literal(node.args[1]):
                self._add(node, "AST006", "HIGH",
                          "getattr() with a non-literal attribute name — dynamic dispatch can reach dangerous methods (e.g. os.system)")

        elif name in ("__import__", "importlib.import_module"):
            if arg0 is not None and not _is_literal(arg0):
                self._add(node, "AST007", "HIGH",
                          name + "() with a non-literal module name — dynamic import")

        self.generic_visit(node)


def ast_scan(path: Path, rel: str) -> list[Finding]:
    """AST pass for a single .py file. Parses with ast.parse (never executes);
    degrades to a no-op if the source will not parse."""
    text = _read_text_safe(path)
    if text is None:
        return []
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return []

    # Pass 1 — alias map: `x = eval` / `x = exec` / `x = compile`.
    alias = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Name) \
                and node.value.id in _CODE_EXEC_BUILTINS:
            for tgt in node.targets:
                if isinstance(tgt, ast.Name):
                    alias[tgt.id] = node.value.id

    # Pass 2 — detect.
    auditor = _AstAuditor(rel, text, alias)
    auditor.visit(tree)
    return auditor.findings


# --------------------------------------------------------------------------
# Taint / data-flow pass (credential -> network exfil)
#
# The AST pass classifies one Call node at a time; it has no notion of where a
# value came from. This pass tracks a CREDENTIAL read (os.environ / os.getenv)
# through intervening assignments — variables, container literals, f-strings,
# concatenation — into a network-output SINK, and rates the flow by the sink's
# DESTINATION:
#   TF001 CRITICAL — destination is reputation-bad or user-controlled: a bare /
#     encoded public IP, a punycode host, a known exfil/tunnel/metadata host, or a
#     non-literal (runtime-chosen) URL. Two rare facts ANDed (secret-tainted AND
#     bad/dynamic dest) -> a legit API client cannot land here -> in the <=5% budget.
#   TF002 HIGH     — destination is a hardcoded NAMED host (the legitimate
#     authenticated-API-client shape, incl. loopback/RFC1918). A secret still leaves
#     the machine, so a human reviews, but it is not auto-refused.
#
# ADDITIVE-ONLY: it never suppresses or downgrades a line/AST finding (HI009 still
# fires on every network call). It NEVER executes the audited code (ast.parse only)
# and degrades to a no-op on a parse error. Intraprocedural, single file, monotonic
# (no taint kill). Cross-function / inter-file flow and container-mutation aliasing
# are out of scope (THREAT_MODEL #4); socket sinks need type inference we lack.
# --------------------------------------------------------------------------

# Network-output sinks, resolved by dotted callee name (the HI009 vocabulary). An
# instance method on an unknown variable (`session.post`) is out — same limitation
# HI009 carries; matching a bare `.post`/`.send` would be FP-prone without types.
_NET_SINK_NAMES = {"urllib.request.urlopen", "urllib.request.Request"}
_NET_SINK_BASES = ("requests", "httpx", "aiohttp")
_NET_SINK_METHODS = {"get", "post", "put", "patch", "delete", "request",
                     "head", "options"}

# Known exfil / tunnel / cloud-metadata host regexes, derived FROM the CRITICAL line
# rules so the taint gate and the line pass share ONE definition (no parallel host
# table to drift). CR026 = anonymous webhooks, CR034 = tunnels/OOB, CR038 = metadata.
_EXFIL_HOST_RES = [re.compile(p) for (rid, p, _w, _f) in CRITICAL_RULES
                   if rid in {"CR026", "CR034", "CR038"}]


def _is_cred_source(node) -> bool:
    """True if `node` reads the process environment — a single key
    (os.environ[...], os.getenv(...), os.environ.get(...)) OR the WHOLE environment
    (os.environ.copy()/items()/values()/keys(), dict(os.environ), or a bare
    os.environ mapping). A whole-environment read is STRICTLY more dangerous (it
    carries every secret at once), so it must be at least as detectable. All
    os.environ reads count — we cannot distinguish a SECRET var from a config var by
    name in this phase (over-paranoid by design)."""
    if isinstance(node, ast.Call):
        dn = _dotted_name(node.func)
        if dn in ("os.getenv", "os.environ.get", "os.environ.copy",
                  "os.environ.items", "os.environ.values", "os.environ.keys"):
            return True
        # dict(os.environ) / list(os.environ) / ... wrapping the bare mapping
        if dn in ("dict", "list", "tuple", "set", "frozenset") and any(
                _dotted_name(a) == "os.environ" for a in node.args):
            return True
        return False
    if isinstance(node, ast.Subscript):
        return _dotted_name(node.value) == "os.environ"
    if isinstance(node, ast.Attribute):
        return _dotted_name(node) == "os.environ"   # bare os.environ mapping read
    return False


def _is_net_sink(call) -> bool:
    """True if a Call's resolved callee is a recognized HTTP-client network sink."""
    name = _dotted_name(call.func)
    if not name:
        return False
    if name in _NET_SINK_NAMES:
        return True
    if "." in name:
        base, _, method = name.rpartition(".")
        return base.split(".", 1)[0] in _NET_SINK_BASES and method in _NET_SINK_METHODS
    return False


def _sink_url_arg(call):
    """The URL value node of a network sink: the `url=` kwarg if present, else the
    positional URL. For requests/httpx/aiohttp `.request(method, url, ...)` the HTTP
    method is arg0 and the URL is arg1; every other sink (.get/.post/…, urllib
    urlopen/Request) carries the URL at arg0. None if absent."""
    for kw in call.keywords:
        if kw.arg == "url":
            return kw.value
    name = _dotted_name(call.func) or ""
    base, _, method = name.rpartition(".")
    idx = 1 if (method == "request" and base.split(".", 1)[0] in _NET_SINK_BASES) else 0
    return call.args[idx] if len(call.args) > idx else None


def _expr_has_taint(node, tainted) -> bool:
    """True if any tainted Name OR an inline credential-source expression appears
    anywhere inside `node`. Container literals / f-strings / concatenation propagate
    for free because the tainted node is a descendant."""
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and sub.id in tainted:
            return True
        if _is_cred_source(sub):
            return True
    return False


def _sink_payload_tainted(call, tainted, url_node) -> bool:
    """True if a tainted value reaches the sink's PAYLOAD (any arg/kwarg EXCEPT the
    URL), or is EMBEDDED in a constructed URL (f-string / concat). The URL position
    itself is deliberately excluded from payload taint: a bare env value used AS the
    destination (`requests.post(os.environ['API_URL'], json=data)`) is a configurable
    endpoint, not secret exfiltration — flagging it would blow the budget. A secret
    BUILT INTO the URL (`f'https://evil/{secret}'`) is still caught, because that
    url_node is a JoinedStr/BinOp carrying the tainted sub-expression."""
    for a in call.args:
        if a is url_node:
            continue
        if _expr_has_taint(a, tainted):
            return True
    for kw in call.keywords:
        if kw.value is url_node:
            continue
        if _expr_has_taint(kw.value, tainted):
            return True
    if isinstance(url_node, (ast.JoinedStr, ast.BinOp)) and _expr_has_taint(url_node, tainted):
        return True
    return False


def _classify_dest(url_node):
    """(rule_id, reason) for a tainted sink's destination. TF001 (CRITICAL) when the
    destination is non-literal or reputation-bad; TF002 (HIGH) for a hardcoded named
    host. Reuses the CR040 machinery — _reputation_bad_dest needs the FULL URL string
    (with scheme), so a string Constant is passed whole."""
    if url_node is None:
        return "TF001", "no explicit destination (dynamic)"
    if not _is_literal(url_node):
        return "TF001", "a user-/runtime-controlled (non-literal) destination"
    if isinstance(url_node, ast.Constant) and isinstance(url_node.value, str):
        url = url_node.value
        reason = _reputation_bad_dest(url)
        if reason:
            return "TF001", reason
        if any(rx.search(url) for rx in _EXFIL_HOST_RES):
            return "TF001", "a known exfiltration / tunnel / cloud-metadata host"
        return "TF002", None
    return "TF001", "a non-string literal destination"


_TF_WHY = {
    "TF001": ("A value read from an environment secret (os.environ / os.getenv) flows "
              "into a network call pointed at {reason} — exfiltration of a credential "
              "to a reputation-bad or runtime-controlled endpoint. The flow crosses "
              "assignments/containers the line and AST passes scan one at a time, so it "
              "reads only YELLOW without data-flow tracking."),
    "TF002": ("A value read from an environment secret (os.environ / os.getenv) flows "
              "into a network call to a hardcoded NAMED host — the shape of a legitimate "
              "authenticated API client, but a secret is still leaving the machine to a "
              "third party. Not auto-refused; a human confirms the destination owns the "
              "credential."),
}
_TF_FIX = {
    "TF001": ("Refuse. A skill must not read an environment secret and send it to a bare "
              "IP, an encoded/punycode host, a known webhook, or a runtime-chosen URL. If "
              "outbound auth is required, the secret stays server-side."),
    "TF002": ("Confirm the named destination is the credential's own service. Prefer a "
              "vetted SDK, pin the endpoint, and never forward a secret to a host you do "
              "not control."),
}


class _TaintAuditor:
    """Intraprocedural, source-order, monotonic taint walker. One taint set per
    function/module scope; nested blocks (if/for/while/with/try) share the scope;
    nested function/class defs get a fresh scope (params are never tainted —
    cross-function flow is out of scope)."""

    def __init__(self, rel, src):
        self.rel = rel
        self.src = src
        self.findings = []
        self._seen = set()  # (lineno, col) of sink calls already emitted

    def run(self, tree):
        self._walk_block(tree.body, set())

    def _walk_block(self, stmts, tainted):
        for stmt in stmts:
            self._visit(stmt, tainted)

    def _visit(self, stmt, tainted):
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            self._walk_block(stmt.body, set())   # fresh scope; params untainted
            return
        # 1) sinks in this statement's OWN expressions (lambda bodies as fresh
        #    scopes; nested statement blocks are walked separately below)
        self._scan_sinks(stmt, tainted)
        # 2) seed / propagate taint from assignments AND walrus binds (after the RHS
        #    is scanned). A walrus `(t := os.environ["X"])` binds `t` in THIS scope —
        #    without this it read GREEN (Codex audit).
        self._apply_assign(stmt, tainted)
        self._apply_walrus(stmt, tainted)
        # 3) recurse into nested statement blocks (same scope, source order)
        for block in self._child_blocks(stmt):
            self._walk_block(block, tainted)

    def _apply_walrus(self, node, tainted):
        """Propagate taint through `(target := value)` named-expressions in this
        statement's OWN expressions (not nested stmts / defs / lambdas — those are
        their own scopes)."""
        nexpr = getattr(ast, "NamedExpr", None)
        if nexpr is None:
            return
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            return
        if isinstance(node, nexpr) and _expr_has_taint(node.value, tainted):
            self._mark(node.target, tainted)
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.stmt):
                continue
            self._apply_walrus(child, tainted)

    def _scan_sinks(self, node, tainted):
        """Evaluate every network sink in `node`'s expressions with `tainted`.
        A Lambda body is scanned as a FRESH scope (params untainted — cross-function
        flow is out of scope). Nested statements (and the def/class statements among
        them) are not descended here — they are walked separately as their own
        scopes — so a sink is evaluated exactly once, at its own statement."""
        if isinstance(node, ast.Lambda):
            self._scan_sinks(node.body, set())
            return
        if isinstance(node, ast.Call) and _is_net_sink(node):
            self._eval_sink(node, tainted)
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.stmt):
                continue
            self._scan_sinks(child, tainted)

    @staticmethod
    def _child_blocks(stmt):
        blocks = []
        for field in ("body", "orelse", "finalbody"):
            v = getattr(stmt, field, None)
            if isinstance(v, list) and v and all(isinstance(x, ast.stmt) for x in v):
                blocks.append(v)
        for h in getattr(stmt, "handlers", []) or []:
            if isinstance(h, ast.ExceptHandler):
                blocks.append(h.body)
        # match/case bodies (Python 3.10+). Guarded so the 3.9 floor never trips on
        # ast.match_case (a Match node can't exist there — 3.9 can't parse `match`).
        match_case = getattr(ast, "match_case", None)
        if match_case is not None:
            for c in getattr(stmt, "cases", []) or []:
                if isinstance(c, match_case):
                    blocks.append(c.body)
        return blocks

    def _apply_assign(self, stmt, tainted):
        if isinstance(stmt, ast.Assign):
            if _expr_has_taint(stmt.value, tainted):
                for tgt in stmt.targets:
                    self._mark(tgt, tainted)
        elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
            if _expr_has_taint(stmt.value, tainted):
                self._mark(stmt.target, tainted)
        elif isinstance(stmt, ast.AugAssign):
            if _expr_has_taint(stmt.value, tainted):
                self._mark(stmt.target, tainted)
        elif isinstance(stmt, (ast.For, ast.AsyncFor)):
            # `for v in os.environ.values(): post(..., data=v)` — each element of a
            # tainted iterable is tainted (the sibling of the walrus fix; same disease:
            # enumerate every binding construct, not just Assign — diagnosis, not symptom).
            if _expr_has_taint(stmt.iter, tainted):
                self._mark(stmt.target, tainted)

    def _mark(self, target, tainted):
        if isinstance(target, ast.Name):
            tainted.add(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self._mark(elt, tainted)
        elif isinstance(target, ast.Starred):
            self._mark(target.value, tainted)
        # Subscript / Attribute targets (d['k'] = secret) are container-mutation,
        # out of scope — not tracked.

    def _eval_sink(self, call, tainted):
        key = (getattr(call, "lineno", 0), getattr(call, "col_offset", 0))
        if key in self._seen:
            return
        url_node = _sink_url_arg(call)
        if not _sink_payload_tainted(call, tainted, url_node):
            return
        rule, reason = _classify_dest(url_node)
        self._seen.add(key)
        severity = "CRITICAL" if rule == "TF001" else "HIGH"
        why = _TF_WHY[rule].format(reason=reason) if reason else _TF_WHY[rule]
        try:
            seg = ast.get_source_segment(self.src, call) or ""
        except Exception:
            seg = ""
        seg = " ".join(seg.split())
        if len(seg) > 160:
            seg = seg[:157] + "..."
        self.findings.append(Finding(
            severity=severity, rule_id=rule, file=self.rel,
            line=getattr(call, "lineno", 0), snippet=seg, why=why,
            suggested_fix=_TF_FIX[rule],
        ))


def taint_scan(path: Path, rel: str) -> list[Finding]:
    """Taint pass for a single .py file. Parses with ast.parse (never executes);
    degrades to a no-op if the source will not parse."""
    text = _read_text_safe(path)
    if text is None:
        return []
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return []
    auditor = _TaintAuditor(rel, text)
    auditor.run(tree)
    return auditor.findings


# --------------------------------------------------------------------------
# Unicode / invisible-character pass
#
# The regex and AST passes operate on text after it is read; they cannot see
# characters that are invisible or that lie about how text renders. This pass
# inspects raw codepoints across ALL text files, INCLUDING .md prose — a
# SKILL.md's prose is read by the model as instructions, so hidden Unicode there
# is a direct injection vector.
# --------------------------------------------------------------------------

# Overrides (RLO/LRO) are the Trojan-Source weapons → CRITICAL. Embeddings and
# isolates can be legitimate in genuine RTL text but are also used in attacks → HIGH.
_BIDI_OVERRIDE = {0x202D, 0x202E}
_BIDI_OTHER = {0x202A, 0x202B, 0x202C, 0x2066, 0x2067, 0x2068, 0x2069, 0x200E, 0x200F}

# Invisible / zero-width used to hide text or split a keyword past the regex.
# ZWJ (200D) and variation selectors (FE0E/FE0F) are excluded so emoji don't trip it;
# U+FEFF is handled separately (allowed only as a leading BOM).
_INVISIBLE = {0x200B, 0x2060, 0x00AD}  # ZWSP, word joiner, soft hyphen

# Cyrillic/Greek letters visually confusable with ASCII Latin (homoglyph spoofing).
_CONFUSABLE = set(
    "\u0430\u0435\u043e\u0440\u0441\u0443\u0445\u0455\u0456\u0458\u0501\u04bb"
    "\u0410\u0412\u0415\u041a\u041c\u041d\u041e\u0420\u0421\u0422\u0423\u0425"
    "\u03bf\u03b1\u03c1\u03bd\u03c5\u0391\u0392\u0395\u039f\u03a1"
)


def _charname(ch):
    try:
        return unicodedata.name(ch)
    except ValueError:
        return "<unnamed control char>"


def _script_of(ch):
    """Coarse script bucket for a letter: 'latin', 'cyrillic', 'greek', or None."""
    o = ord(ch)
    if (0x41 <= o <= 0x5A) or (0x61 <= o <= 0x7A):
        return "latin"
    if 0x0400 <= o <= 0x052F:
        return "cyrillic"
    if (0x0370 <= o <= 0x03FF) or (0x1F00 <= o <= 0x1FFF):
        return "greek"
    return None


def unicode_scan(path: Path, rel: str) -> list[Finding]:
    """Character-level scan for bidi controls, invisible characters, the Unicode
    Tags block, and mixed-script (homoglyph) words. Reads text only."""
    text = _read_text_safe(path)
    if text is None:
        return []
    findings: list[Finding] = []

    for i, line in enumerate(text.splitlines(), start=1):
        for ch in line:
            o = ord(ch)
            if o in _BIDI_OVERRIDE:
                findings.append(Finding(
                    severity="CRITICAL", rule_id="UNI001", file=rel, line=i,
                    snippet=f"U+{o:04X} {_charname(ch)}",
                    why="Bidirectional override (Trojan Source) — reorders how the line renders vs. how it reads; can disguise or hide instructions in SKILL.md",
                    suggested_fix="Remove it. A skill has no legitimate use for a bidi override.",
                ))
            elif o in _BIDI_OTHER:
                findings.append(Finding(
                    severity="HIGH", rule_id="UNI001", file=rel, line=i,
                    snippet=f"U+{o:04X} {_charname(ch)}",
                    why="Bidirectional embedding/isolate control — can reorder rendered text; rare outside genuine RTL content",
                    suggested_fix="Remove unless the skill genuinely renders right-to-left text.",
                ))
            elif o in _INVISIBLE:
                findings.append(Finding(
                    severity="HIGH", rule_id="UNI002", file=rel, line=i,
                    snippet=f"U+{o:04X} {_charname(ch)}",
                    why="Invisible / zero-width character — can hide text or split a keyword to evade the line rules",
                    suggested_fix="Remove it.",
                ))
            elif 0xE0000 <= o <= 0xE007F:
                findings.append(Finding(
                    severity="CRITICAL", rule_id="UNI003", file=rel, line=i,
                    snippet=f"U+{o:04X} {_charname(ch)}",
                    why="Unicode Tags block character — invisible; used to smuggle hidden instructions into model input",
                    suggested_fix="Remove it. The Tags block has no legitimate use in skill text.",
                ))

        # UNI004 — homoglyph spoofing: a Cyrillic/Greek letter confusable with Latin
        # sitting INSIDE a Latin word (a Latin neighbour, no Cyrillic/Greek neighbour).
        # Catches 'paypal'/'sudo' spoofs while leaving genuine bilingual jargon (Latin
        # glued to a Cyrillic cluster, e.g. za+inject+it) and hyphenated compounds alone.
        for run in re.findall(r"[^\W\d_]+", line):
            for j, c in enumerate(run):
                if c not in _CONFUSABLE:
                    continue
                neigh = []
                if j > 0:
                    neigh.append(run[j - 1])
                if j < len(run) - 1:
                    neigh.append(run[j + 1])
                scr = {_script_of(n) for n in neigh}
                if "latin" in scr and not ({"cyrillic", "greek"} & scr):
                    findings.append(Finding(
                        severity="MEDIUM", rule_id="UNI004", file=rel, line=i,
                        snippet=run[:60],
                        why="Homoglyph spoofing: a Cyrillic/Greek look-alike (U+%04X) sits inside an otherwise-Latin word — disguised as Latin" % ord(c),
                        suggested_fix="Use a single script per word, or confirm the spelling is intentional.",
                    ))
                    break

    # U+FEFF mid-file (only a leading BOM at offset 0 is legitimate).
    idx = text.find("\uFEFF", 1)
    if idx != -1:
        findings.append(Finding(
            severity="HIGH", rule_id="UNI002", file=rel,
            line=text.count("\n", 0, idx) + 1,
            snippet="U+FEFF ZERO WIDTH NO-BREAK SPACE",
            why="Zero-width no-break space mid-file (only a leading BOM is legitimate) — invisible character",
            suggested_fix="Remove it.",
        ))

    return findings


def _exec_magic(path: Path):
    """A short label if the file's first bytes are a known EXECUTABLE magic number
    (ELF / PE / Mach-O / Mach-O-fat-or-Java) — escalates INV001 from HIGH to CRITICAL,
    since a bundled compiled executable is malware-tier, not merely 'unauditable'."""
    try:
        with open(path, "rb") as _f:        # read ONLY the magic bytes — never slurp
            head = _f.read(4)               # the whole file (a huge binary = memory DoS)
    except OSError:
        return None
    if head[:4] == b"\x7fELF":
        return "ELF"
    if head[:2] == b"MZ":
        return "PE/Windows"
    if head[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
                    b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
        return "Mach-O/Java"
    return None


def _looks_like_text(path: Path) -> bool:
    """Sniff a file's first chunk: text if it has no NUL byte and decodes as
    UTF-8 (a multibyte char cut at the chunk boundary is tolerated). Lets
    extensionless text files (LICENSE, .gitignore, Makefile) be scanned instead
    of flagged as unauditable blobs (Codex)."""
    try:
        chunk = path.read_bytes()[:8192]
    except OSError:
        return False
    if b"\x00" in chunk:
        return False
    try:
        chunk.decode("utf-8")
        return True
    except UnicodeDecodeError as e:
        return e.start >= len(chunk) - 4  # only trailing boundary-cut bytes failed


def inventory(skill_root: Path) -> dict:
    """Walk the skill dir and classify every file."""
    text_files: list[str] = []
    other_files: list[str] = []
    total_bytes = 0

    # Version-control / tooling internals are not part of the skill. Without this,
    # auditing a cloned repo floods INV001 with .git/ objects (Codex P0).
    skip_dirs = {".git", "node_modules", ".venv", "venv", "__pycache__",
                 ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox",
                 ".idea", ".vscode", "dist", "build"}

    for p in skill_root.rglob("*"):
        if any(part in skip_dirs for part in p.relative_to(skill_root).parts):
            continue
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

        if p.suffix.lower() in TEXT_EXTENSIONS or _looks_like_text(p):
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

    # Structural passes (parse JSON / never execute). Each is wrapped so a crash in
    # one pass — e.g. a RecursionError on a maliciously deep-nested config — degrades
    # to a LOW note instead of aborting the whole scan with no JSON (adversarial review).
    for _label, _fn in (("frontmatter", lambda: check_frontmatter(skill_md, skill_root)),
                        ("bundled-config", lambda: check_bundled_config(skill_root)),
                        ("supply-chain", lambda: check_supply_chain(skill_root))):
        try:
            findings.extend(_fn())
        except Exception as _e:  # never let one structural pass abort the whole scan
            findings.append(Finding(
                # FAIL-CLOSED to RED (Codex audit): a config that crashes the scanner
                # — e.g. pathologically deep nesting — is an evasion attempt, and a LOW
                # would let it read exit 0, hiding the CR032/CR033 it should have fired.
                severity="CRITICAL", rule_id="IO003", file="", line=0, snippet=str(_e)[:80],
                why=("the " + _label + " pass crashed on this skill's own config ("
                     + type(_e).__name__ + ") — failing CLOSED to RED, because a config that "
                       "breaks the parser is suspicious, not safe"),
                suggested_fix="Inspect this skill's config by hand; a config that crashes a parser is a red flag."))

    # Per-file pass (regex) + Unicode pass + AST pass for Python files
    for rel in inv["text_files"]:
        fpath = skill_root / rel
        findings.extend(scan_file(fpath, skill_root))
        # scan_file caps at MAX_SCAN_BYTES and notes oversize (LO003); the per-char
        # unicode pass and the AST/taint passes have NO such cap, so an oversized
        # file would make them the very DoS the read-cap was meant to stop. Skip them
        # in lockstep with scan_file — diagnosis: EVERY per-file pass must honor the
        # same size bound, not just scan_file (Codex whole-file-read, generalized).
        try:
            if fpath.stat().st_size > MAX_SCAN_BYTES:
                continue
        except OSError:
            continue
        findings.extend(unicode_scan(fpath, rel))
        if rel.endswith(".py"):
            findings.extend(ast_scan(fpath, rel))
            findings.extend(taint_scan(fpath, rel))

    # Note any non-text or symlink files (Claude-side review treats these as red flags)
    for other in inv["other_files"]:
        is_symlink = "SYMLINK" in other
        magic = None if is_symlink else _exec_magic(skill_root / other)
        if is_symlink:
            sev, why = "CRITICAL", "Symlink inside skill directory — refuse."
        elif magic:
            sev = "CRITICAL"
            why = ("Bundled " + magic + " EXECUTABLE in the skill — a compiled, unauditable binary that "
                   "runs native code; a skill is plain text (SKILL.md + scripts/ + references/), never a binary.")
        else:
            sev = "HIGH"
            why = "Binary or non-text file in skill — unauditable; treat as RED unless the author justifies it."
        findings.append(Finding(
            severity=sev, rule_id="INV001", file=other, line=0,
            snippet=(magic or ""), why=why,
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
