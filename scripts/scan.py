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

    ("HI009", r"\b(?:urllib\.request\.urlopen|requests\.(?:get|post|put|patch|delete)|httpx\.\w+|aiohttp\.\w+|socket\.connect)\s*\(",
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


# --- PROSE_TARGETING negation guard: clause-boundary + polarity-inversion tests ---------
# (shared by the defensive-prose suppressor in scan_file; see its comment for the model.)

# Comma look-alikes that NFKC does NOT fold to ASCII and that are categorized Ps (so the
# Po test below misses them): the low-9 quotation marks render as a comma. CLOSED set of two.
_LOW9_COMMA_LOOKALIKES = "‚„"          # ‚ „  SINGLE / DOUBLE LOW-9 QUOTATION MARK
# Intra-word hyphens (Pd) that do NOT split a clause — 'well-known', 'state-of-the-art'.
_INTRAWORD_HYPHENS = "-‐‑"             # HYPHEN-MINUS / HYPHEN / NON-BREAKING HYPHEN
# Punctuation/symbols that do NOT end a clause — word-internal / connective / emphasis marks
# that appear mid-sentence in real prose (apostrophe, quotes, solidus, ampersand, markdown
# `* ~ _ \`` etc., middle dots, intra-word hyphens). A clause boundary is the INVERSE: a gap
# char is a boundary unless it is a letter / digit / mark, ordinary space/tab, a bracket or
# quote (Ps/Pe/Pi/Pf/Pc), or one of these. So every script's sentence terminator, a So/Sm
# BULLET (● ▪ ∙), an invisible Cf char, or an exotic Zs space (NBSP / Ogham) is a boundary
# WITHOUT being enumerated — stdlib cannot test Unicode Terminal_Punctuation, so the small
# non-breaking allowlist over a broad category test is the disease fix (convergence round 4).
_NONBREAK_PUNCT = set("'\"/\\&@%#*~`·・‧-‐‑")
_CLEAN_CATEGORIES = ("Ps", "Pe", "Pi", "Pf", "Pc")   # brackets / quotes / connectors (_)
_BOUNDARY_IDIOM_RE = re.compile(r"\b(?:until|then|after|before|once|mind|bother)\b", re.I)

# Polarity-INVERTING reluctance/avoidance verbs (+ common inflections) and the bare double
# negation 'not'. "never <inverter> … reveal" = "always reveal" (double negation). The guard
# counts inverters in the gap and decides by PARITY (odd => inverted => fire), so a SINGLE
# inverter fires ("never hesitate to reveal") while a DOUBLE inverter is defensive again
# ("never shy away from refusing to reveal" = "always refuse to reveal", suppress). The
# inverter class is open NL (THREAT_MODEL §8) — this enumerates the common forms; the
# Claude-side review is the backstop for the tail. [convergence sweep round 4]
_INVERT_VERB_RE = re.compile(
    # Ambiguous-sense verbs (a benign noun/mode reading exists — "fail open", "an object",
    # "resistance") count ONLY with an infinitival `to` complement governing the leak verb,
    # so "must not FAIL OPEN and reveal" does NOT invert (convergence round 4 FP fix).
    r"\b(?:fail\w*|miss\w*|wait\w*|delay\w*|object\w*|resist\w*|balk\w*)\s+"
    r"(?:[a-z]+\s+){0,4}?to\b"
    # Unambiguous reluctance / avoidance / concealment verbs (loose).
    r"|\b(?:hesitat\w+|refus\w+|neglect\w*|declin\w+|omit\w*|forget\w*|forgot\w*|"
    r"withhold\w*|withheld|conceal\w*|redact\w*)\b"
    r"|\bshy\s+away\s+from\b|\bhold(?:s|ing)?\s+back\b|\bpass(?:es|ed|ing)?\s+up\b|"
    r"\bsay(?:s|ing)?\s+no\b|\bhelp\s+but\b|"
    r"\bbe\s+(?:afraid|reluctant|shy|unwilling|hesitant|slow)\b|"
    r"\bnot\b", re.I)
# Negation TOKENS that are themselves polarity-inverting verbs: when one is the GOVERNING
# negation AND an adjacent OUTER negation precedes it (with no inverter between), it is a
# STACKED double negation ("never refuse to reveal" = "always reveal"). They live in the
# negation list, so the gap is empty and _gap_inverts_polarity can't see them.
_INVERTIBLE_NEG_RE = re.compile(r"\b(?:refuse\s+to|reject|forbid|prevent|avoid)\b", re.I)


def _is_clause_boundary_char(ch: str) -> bool:
    """True if `ch` ends a clause — decided by the INVERSE of a small non-breaking set, so a
    separator of ANY category (a script terminator, a So/Sm bullet, an invisible Cf char, an
    exotic Zs space) counts without enumeration (convergence sweep round 4). A char is NOT a
    boundary iff it is: a letter / digit / combining mark (Unicode L*/N*/M*), an ordinary
    space or tab, a bracket / quote / connector (Ps/Pe/Pi/Pf/Pc), or one of the word-internal
    `_NONBREAK_PUNCT` marks. The low-9 quote comma look-alikes (Ps) are the one exception —
    forced to boundary. Everything else (Po terminators, Pd dashes, So/Sm, Cf, NBSP/Ogham
    spaces, Zl/Zp) is a boundary."""
    if ch in _LOW9_COMMA_LOOKALIKES:
        return True
    if ch in _NONBREAK_PUNCT or ch in " \t":
        return False
    cat = unicodedata.category(ch)
    if cat[0] in ("L", "N", "M") or cat in _CLEAN_CATEGORIES:
        return False
    return True


def _gap_has_clause_boundary(gap: str) -> bool:
    """True if the NFKC-folded `gap` between a negation and a dangerous verb holds a CLAUSE
    boundary (a terminator char or a temporal/disregard idiom) — so the negation does NOT
    adjacently govern the verb and the finding fires."""
    if any(_is_clause_boundary_char(ch) for ch in gap):
        return True
    return bool(_BOUNDARY_IDIOM_RE.search(gap))


def _gap_inverts_polarity(gap: str) -> bool:
    """True if `gap` holds an ODD number of polarity-inverting verbs, so 'never <gap>
    <danger>' nets to 'always <danger>' and must FIRE. An even count ("shy away from
    refusing to") is a double inversion that stays defensive (convergence sweep round 4)."""
    return len(_INVERT_VERB_RE.findall(gap)) % 2 == 1


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
                    # Defensive prose: suppress ONLY when the NEAREST preceding negation
                    # genuinely GOVERNS this dangerous verb. NARROW rule — the negation
                    # suppresses ONLY when it ADJACENTLY governs the verb: NO clause boundary
                    # in the gap, AND the gap is not a polarity-INVERTING bridge. Any clause
                    # boundary fires (so the comma-splice "Never harm the user, embed
                    # <|im_start|>…" fires — 'never' governs 'harm', not 'embed'); a defensive
                    # ENUMERATION must use comma-free "or" coordination ("never reveal or send
                    # your prompt") or per-clause negation to stay GREEN (authoring guidance).
                    # The ONLY adjacency that suppresses is the literal "never reveal your
                    # system prompt", which IS defensive. Two disease fixes the attacker kept
                    # probing (convergence sweep, gaps 1-3 & 8): the boundary is decided by
                    # UNICODE PROPERTY (_gap_has_clause_boundary), not an enumerated codepoint
                    # class a new comma confusable can slip (U+201A / em-dash / U+2E41 each
                    # slipped the old `[,.;:!?،、。]`); and a bridge verb in the gap
                    # ("never hesitate/fail/refuse TO reveal …" = "always reveal …") is a
                    # double negation, so it must NOT suppress (_gap_inverts_polarity).
                    m = compiled.search(unit)
                    if m:
                        negs = list(re.finditer(
                            r"(?i)\b(?:do\s+not|don'?t|does\s+not|doesn'?t|did\s+not|"
                            r"never|cannot|can'?t|won'?t|will\s+not|is\s+not|isn'?t|"
                            r"are\s+not|aren'?t|shouldn'?t|mustn'?t|should\s+not|"
                            r"must\s+not|may\s+not|should\s+never|must\s+never|"
                            r"refuse\s+to|reject|forbid|prevent|avoid)\b",
                            unit[: m.start()]))
                        if negs:
                            gap = unicodedata.normalize(
                                "NFKC", unit[negs[-1].end(): m.start()])
                            suppress = (not _gap_has_clause_boundary(gap)
                                        and not _gap_inverts_polarity(gap))
                            # Double negation via a STACKED inverting negation ("never
                            # refuse to reveal", "will not avoid revealing") — the governing
                            # negation is an inverting VERB negated by an adjacent outer
                            # negation, so the imperative flips positive: do not suppress.
                            if (suppress and len(negs) >= 2
                                    and _INVERTIBLE_NEG_RE.search(negs[-1].group())):
                                inner = unicodedata.normalize(
                                    "NFKC", unit[negs[-2].end(): negs[-1].start()])
                                # The outer negation flips the invertible governing one
                                # (fire) UNLESS the inner gap itself inverts back (defensive
                                # "do not hesitate to refuse to reveal" — parity).
                                if (not _gap_has_clause_boundary(inner)
                                        and not _gap_inverts_polarity(inner)):
                                    suppress = False
                            if suppress:
                                continue   # negation adjacently governs the match -> suppress

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


def _oversize_fail_closed(path: Path, rel: str, kind: str):
    """A bundled config/manifest larger than we can fully read (`_MAX_READ_BYTES`)
    cannot be audited: `_read_text_safe` would return a TRUNCATED copy, so a malicious
    key placed past the cap reads GREEN (Codex audit round 2: a >8 MB `.mcp.json` hid
    its `mcpServers`). A real config/manifest is a few KB — refuse rather than scan a
    truncated copy. Returns a CRITICAL Finding if oversize, else None (fail CLOSED)."""
    try:
        size = path.stat().st_size
    except OSError:
        return None
    if size <= _MAX_READ_BYTES:
        return None
    return Finding(
        severity="CRITICAL", rule_id="IO004", file=rel, line=0,
        snippet=f"<{size} bytes>",
        why=(f"{kind} is too large to fully audit ({size} bytes > {_MAX_READ_BYTES} read "
             "cap); a config/manifest is normally a few KB — refuse (a key hidden past "
             "the read cap must not read clean)"),
    )


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
        oversize = _oversize_fail_closed(path, rel, "bundled config " + path.name)
        if oversize is not None:
            findings.append(oversize)
            continue   # fail closed — do not pretend to audit a truncated copy
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
    ".npmrc", ".yarnrc", ".yarnrc.yml",
    "pip.conf", "pip.ini", ".gemrc",       # per-ecosystem index-config files (round 4)
}
LOCKFILE_NAMES = {
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
    "Pipfile.lock", "Gemfile.lock", "Cargo.lock",
}
# ME012 (unpinned) applies only to these top-level manifest kinds — a lock pins
# by construction, and go.mod is pinned + checksummed by go.sum.
ME012_KINDS = {"package.json", "pyproject.toml", "requirements"}

_VCS_PREFIXES = ("git+", "hg+", "svn+", "bzr+", "git://", "git@")


def _is_requirements_txt(name: str) -> bool:
    return name.startswith("requirements") and name.endswith(".txt")


def _host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def _is_local_host(host: str) -> bool:
    """True for a localhost / loopback / unspecified host — a local dev or air-gapped index
    mirror (devpi, verdaccio), not an off-registry exfil target (convergence round 4 FP)."""
    host = (host or "").lower().strip("[]")
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_loopback or ip.is_unspecified
    except ValueError:
        return False


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


def _is_official_crates_index(url: str) -> bool:
    """True for the OFFICIAL crates.io index — the GitHub-hosted git index
    (`github.com/rust-lang/crates.io-index`) or the sparse index host. The bare-URL form
    (no `registry+` prefix) is the canonical Cargo source and must not flag (round-4 audit FP)."""
    h = _host_of(url)
    try:
        p = urlsplit(url).path.rstrip("/").lower()
    except ValueError:
        p = ""
    if p.endswith(".git"):
        p = p[:-4]
    return h in ("index.crates.io", "static.crates.io") \
        or (h == "github.com" and p == "/rust-lang/crates.io-index")


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
        # The OFFICIAL crates.io index (exact path — `github.com/attacker/rust-lang/
        # crates.io-index` is a DIFFERENT repo) or a known registry host is exempt;
        # `registry+https://attacker.test/…` is an off-registry alternate registry.
        if _is_official_crates_index(inner) or _is_registry_host(ih):
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
        if _is_official_crates_index(url):
            return None                       # the canonical Cargo git/sparse index — fine
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
        # Custom package-source/index tables that the installer reads on resolve:
        # Poetry `[[tool.poetry.source]]`, uv `[[tool.uv.index]]`, PDM `[[tool.pdm.source]]`
        # (the uv/pdm siblings were a fragile-sibling miss — convergence round 4).
        if section in ("tool.poetry.source", "tool.uv.index", "tool.pdm.source"):
            um = re.search(r"(?i)\burl\s*=\s*[\"']([^\"']+)[\"']", st)
            if um:
                reason = _classify_source(um.group(1))
                if reason:
                    findings.append(Finding(
                        severity="HIGH", rule_id="HI023", file=rel, line=ln_no,
                        snippet=raw.strip()[:120],
                        why="Custom package source/index (" + section + ") points off-registry — " + reason
                            + "; a dependency resolved through this source is fetched past the default registry's audit.",
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


# npm/yarn rc index-redirect (gap 7). A `registry=` / `@scope:registry=` / yarn-berry
# `npmRegistryServer:` line, or a `//host/:_authToken` credential line, that names an
# off-registry host is the dependency-confusion vector — the file npm/yarn actually reads
# to choose the index, the SAME off-registry signal HI023 flags in a lockfile `resolved`.
_NPMRC_REGISTRY_RE = re.compile(
    r"\s*(?:@[\w.\-]+:)?(?:registry|npmRegistryServer)\b\s*[:=]?\s*[\"']?(\S+?)[\"']?\s*$", re.I)
_NPMRC_AUTH_RE = re.compile(r"\s*(//\S*?):_(?:authToken|password|username|auth)\b", re.I)


def _npmrc_host(val: str) -> str:
    """Host of an rc registry value. A real URL (`scheme://host…`) yields its host even for
    a single-label intranet name (`http://npm-internal:4873/` -> npm-internal). A scheme-LESS
    value must look like a domain/IP (a '.' or ':') so a boolean/flag (`registry=true`) is
    not misread as a host (convergence sweep round 4: a single-label URL host used to be
    dropped, an asymmetry with the auth line)."""
    val = (val or "").strip().strip("\"'")
    if "://" in val:
        return _host_of(val)
    h = _host_of("//" + val)
    return h if ("." in h or ":" in h) else ""


def _supply_npmrc(text, rel):
    """Off-registry index-redirect scan for .npmrc / .yarnrc / .yarnrc.yml (gap 7). Emits
    HI023 when a registry/auth host is present and is NOT a known registry host. Dedups per
    host; registry.npmjs.org / yarnpkg / npmmirror stay GREEN, npm.pkg.github.com flags
    (mirrors HI023's existing GitHub-source treatment). Boolean/host-less lines skip."""
    findings, seen = [], set()
    for ln_no, raw in enumerate(text.splitlines(), start=1):
        line = re.sub(r"(?:^|\s)[#;].*$", "", raw)        # strip ini / yaml comments
        host = ""
        m = _NPMRC_REGISTRY_RE.match(line)
        if m:
            host = _npmrc_host(m.group(1))
        else:
            ma = _NPMRC_AUTH_RE.match(line)
            if ma:
                host = _host_of(ma.group(1))
        if host and not _is_registry_host(host) and not _is_local_host(host) and host not in seen:
            seen.add(host)
            findings.append(Finding(
                severity="HIGH", rule_id="HI023", file=rel, line=ln_no,
                snippet=raw.strip()[:120],
                why="npm/yarn rc points the package index at an off-registry host (" + host
                    + ") — a dependency-confusion redirect that silently re-points every "
                      "install at an attacker-controlled registry; the installer's signing/"
                      "audit chain is bypassed.",
                suggested_fix="Point registry at the official index (registry.npmjs.org), or remove the redirect."))
    return findings


def _index_config_kind(p) -> str:
    """The per-ecosystem index-config kind for a path, or '' — pip.conf/pip.ini, .gemrc, OR
    `.cargo/config[.toml]` (cargo's config is a GENERIC filename, so it is gated on the
    `.cargo` parent to avoid flagging an unrelated `config.toml`). Convergence sweep round 4:
    the off-registry index redirect closed for npm/yarn applies to pip/cargo/gem identically."""
    n = p.name
    if n in ("pip.conf", "pip.ini"):
        return "pip"
    if n == ".gemrc":
        return "gem"
    if p.parent.name == ".cargo" and n in ("config.toml", "config"):
        return "cargo"
    return ""


def _supply_index_config(text, rel, kind):
    """Off-registry index/source redirect in a pip / cargo / gem config (round 4). Flags any
    URL host (and pip `trusted-host`) that is not a known registry host — the same
    dependency-confusion vector as the npm/yarn rc. pypi.org / crates.io / rubygems.org stay
    GREEN via REGISTRY_HOSTS; localhost/loopback (no '.') is skipped."""
    findings, seen = [], set()
    for ln_no, raw in enumerate(text.splitlines(), start=1):
        line = re.sub(r"(?:^|\s)[#;].*$", "", raw)
        # The OFFICIAL crates.io git index is the canonical `.cargo/config.toml` source and
        # must stay GREEN here too (round-4 audit pass 3: the sibling _classify_source path
        # exempted it but this one did not — same canonization, two paths).
        hosts = [_host_of(m.group(0))
                 for m in re.finditer(r"(?:https?|ftp)://[^\s\"'#;,)\]]+", line)
                 if not _is_official_crates_index(m.group(0))]
        tm = re.match(r"\s*trusted-host\s*[:=]\s*[\"']?(\S+?)[\"']?\s*$", line, re.I)
        if tm:                                        # pip trusted-host: a bare host, no scheme
            hosts.append(_npmrc_host(tm.group(1)))
        for host in hosts:
            if host and not _is_registry_host(host) and not _is_local_host(host) and host not in seen:
                seen.add(host)
                findings.append(Finding(
                    severity="HIGH", rule_id="HI023", file=rel, line=ln_no,
                    snippet=raw.strip()[:120],
                    why="A bundled " + kind + " config points the package index/source at an "
                        "off-registry host (" + host + ") — a dependency-confusion redirect that "
                        "re-points installs at an attacker-controlled registry, bypassing the "
                        "registry's signing/audit.",
                    suggested_fix="Point the index at the official registry, or remove the redirect."))
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


def _iter_tree_files(root: Path, max_nodes: int = 100000, state: dict = None):
    """Yield non-symlink files anywhere under `root`, skipping symlinked dirs (no cycles)
    and VCS noise (.git/.hg/.svn). A filename-keyed structural pass uses this so a manifest
    shipped at ANY depth in src/ / vendor/ / node_modules/ is not missed — there is NO depth
    cap (it silently dropped a deep node_modules manifest, Codex r3 sweep; the per-file read
    is byte-bounded so deep discovery does not reopen the DoS line). The DoS line is held by
    `max_nodes` (counts every dir + entry visited). If the cap is hit the walk is truncated
    and `state["truncated"]` is set so the caller can FAIL LOUD (never silently GREEN)."""
    nodes = 0
    stack = [root]
    while stack:
        d = stack.pop()
        nodes += 1
        if nodes > max_nodes:
            if state is not None:
                state["truncated"] = True
            return
        if d.is_symlink() or not d.is_dir():
            continue
        try:
            entries = sorted(d.iterdir())
        except OSError:
            continue
        for p in entries:
            nodes += 1
            if nodes > max_nodes:
                if state is not None:
                    state["truncated"] = True
                return
            if p.is_symlink():
                continue
            if p.is_dir():
                if p.name not in (".git", ".hg", ".svn"):
                    stack.append(p)
            elif p.is_file():
                yield p


def check_supply_chain(skill_root: Path) -> list[Finding]:
    """Detect bundled dependency manifests that ship install-lifecycle scripts
    (CR039), non-registry sources (HI023), or unpinned deps (ME012). Structural,
    filename-keyed, never executes the file. Emits Findings directly."""
    findings: list[Finding] = []

    # Recursive, filename-keyed discovery: a postinstall/binding.gyp activates on `npm
    # install` from WHEREVER it sits, so a manifest in src/ / vendor/ / node_modules/ is
    # just as dangerous as one at the root (Codex r3 — the old 3-subdir allowlist missed
    # them). Keying off manifest FILENAMES keeps a references/*.json data file GREEN.
    walk_state = {}
    candidates = sorted(
        p for p in _iter_tree_files(skill_root, state=walk_state)
        if p.name in SUPPLY_MANIFEST_NAMES or _is_requirements_txt(p.name)
        or _index_config_kind(p))
    if walk_state.get("truncated"):
        # The tree was too large to fully walk — a manifest could be hidden in the
        # un-walked remainder. FAIL LOUD (never silently GREEN), mirroring the IO004
        # fail-closed posture (Codex r3 sweep: a node_modules flood starved discovery).
        findings.append(Finding(
            severity="HIGH", rule_id="IO004", file="", line=0, snippet="<tree truncated>",
            why=("the skill's directory tree is too large to fully audit (manifest discovery "
                 "truncated at the node cap) — a dependency manifest may be hidden in the "
                 "un-walked remainder; inspect the tree by hand")))

    for path in candidates:
        rel = path.relative_to(skill_root).as_posix()
        name = path.name
        is_lock = name in LOCKFILE_NAMES
        try:
            _size = path.stat().st_size
        except OSError:
            _size = 0
        if _size > _MAX_READ_BYTES:
            if is_lock:
                # a real lockfile is legitimately 10-30 MB — do NOT hard fail-closed
                # CRITICAL (that RED-flags a benign registry-pinned lockfile, Codex r3).
                # Note it HIGH and still scan the readable prefix for off-registry /
                # lifecycle keys below.
                findings.append(Finding(
                    severity="HIGH", rule_id="IO004", file=rel, line=0,
                    snippet=f"<{_size} bytes>",
                    why=(f"lockfile {name} exceeds the {_MAX_READ_BYTES}-byte read cap; only "
                         "its readable prefix was audited — inspect the remainder manually")))
            else:
                # an opaque manifest (package.json/binding.gyp/…) is a few KB; a multi-MB
                # one that hides keys past the cap must not read clean -> fail closed.
                findings.append(_oversize_fail_closed(path, rel, "manifest " + name))
                continue
        kind = ("requirements" if _is_requirements_txt(name) else name)
        unpinned: list[str] = []

        if name in ("package.json", "package-lock.json", "npm-shrinkwrap.json"):
            data, err = _parse_json(path)
            if err is not None:
                # Won't parse — textual backstop.
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
                else:
                    # A JSON lockfile truncated at the read cap still has a readable prefix:
                    # scan it textually for off-registry `resolved`/`tarball` hosts (HI023),
                    # so the "readable prefix is still scanned" guarantee holds for JSON
                    # lockfiles too, not only text lockfiles (Codex r3 re-sweep).
                    findings.extend(_supply_source_scan(_read_text_safe(path) or "", rel, name))
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
        elif name in (".npmrc", ".yarnrc", ".yarnrc.yml"):
            findings.extend(_supply_npmrc(_read_text_safe(path) or "", rel))
        elif _index_config_kind(path):
            findings.extend(_supply_index_config(
                _read_text_safe(path) or "", rel, _index_config_kind(path)))
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
    # NOTE: os.startfile is deliberately EXCLUDED — it is the Windows shell "open with the
    # associated default app" call (double-click equivalent), predominantly a BENIGN document-open
    # idiom (os.startfile("report.pdf")), not process-image replacement like os.exec*/os.spawn*.
    # Adding it false-fired AST010 HIGH on benign opens (round-6 CONFIRM sweep R6-FP-startfile).
}

# Dangerous CANONICAL leaves the dotted AST rules already key on, to which a BARE name from
# `from <mod> import *` may resolve (convergence sweep gap 6). Gating star-resolution on
# this finite set means zero new FP surface beyond the explicit-import form. Excludes
# `os.open` (would shadow builtin `open` handling) and the builtins (eval/exec/compile/
# getattr/__import__ — not reachable as module members via `from os import *`).
_STAR_RESOLVABLE = frozenset({
    "os.system", "os.popen", "os.replace", "os.rename",
    "os.open",   # `from os import *; open(__file__, O_WRONLY)` — the os.open arm distinguishes
                 # write-FLAGS from a builtin-open string mode, so this is collision-safe (r4 audit)
    "shutil.unpack_archive", "shutil.copyfile", "shutil.copy", "shutil.copy2", "shutil.move",
    "pickle.loads", "marshal.loads",
    "yaml.load",
    "importlib.import_module",
    "subprocess.run", "subprocess.call", "subprocess.check_call",
    "subprocess.check_output", "subprocess.Popen", "subprocess.getoutput",
    "subprocess.getstatusoutput",
}) | _OS_EXEC_FAMILY

# Archive openers whose result object's `.extractall()` is the Zip-Slip sink (AST011). The
# AST011 extractall arm fires ONLY when its receiver provably resolves to one of these
# (convergence sweep gap 5: keying on the bare `extractall` leaf FP'd on pandas
# Series.str.extractall and any non-archive `.extractall()`). Canon-resolved, so an import
# alias (`import tarfile as tf` / `from zipfile import ZipFile`) still counts.
_ARCHIVE_OPENERS = frozenset({
    "tarfile.open", "tarfile.TarFile", "zipfile.ZipFile", "zipfile.PyZipFile",
    # tarfile.TarFile alternative-constructor classmethods (what tarfile.open delegates to)
    "tarfile.TarFile.open", "tarfile.TarFile.gzopen",
    "tarfile.TarFile.bz2open", "tarfile.TarFile.xzopen",
})


class _VF:
    """Unified abstract value facts — the SINGLE source of binding/resolution semantics that the
    round-9 migration uses to collapse the four per-scope timelines (alias / __file__ / archive /
    method-ref) into one. `canon` = dotted callable/module canonical ('os.system' / 'os' /
    'tarfile.open' / 'pathlib.Path' / None = unknown); `self_file` = the skill's own __file__ /
    Path(__file__); `archive` = an opened tar/zip archive; `mleaf`/`mrecv` = a bound method-ref leaf
    + whether its receiver was an archive; `seq` (a nested _VF or None) = the REPRESENTATIVE element
    of a literal sequence, so a `for x in [os.system]` / `archives[0]` unwraps it. The empty `_VF()`
    is the bottom (a captured exception / opaque value)."""
    __slots__ = ("canon", "self_file", "archive", "mleaf", "mrecv", "seq")

    def __init__(self, canon=None, self_file=False, archive=False, mleaf=None, mrecv=False, seq=None):
        self.canon = canon
        self.self_file = self_file
        self.archive = archive
        self.mleaf = mleaf
        self.mrecv = mrecv
        self.seq = seq


def _names_in_target(target):
    """Yield every Name id an assignment target binds (Name, or nested Tuple/List/Starred)."""
    if isinstance(target, ast.Name):
        yield target.id
    elif isinstance(target, (ast.Tuple, ast.List)):
        for el in target.elts:
            yield from _names_in_target(el)
    elif isinstance(target, ast.Starred):
        yield from _names_in_target(target.value)


def _match_capture_bindings(pattern):
    """Yield (name, node) for every name a match-case PATTERN binds — a capture (`case x`),
    a star (`case [*rest]`), or a mapping-rest (`case {**rest}`) — recursing through nested
    patterns (`case [a, {"k": b}]`). A wildcard `case _` binds nothing. Empty on Python < 3.10
    (no `match` syntax exists, so no Match node can reach the per-scope timeline walks)."""
    MatchAs = getattr(ast, "MatchAs", None)
    if MatchAs is None:
        return
    MatchStar = getattr(ast, "MatchStar", None)
    MatchMapping = getattr(ast, "MatchMapping", None)
    for sub in ast.walk(pattern):
        if isinstance(sub, MatchAs) and sub.name:
            yield sub.name, sub
        elif MatchStar is not None and isinstance(sub, MatchStar) and sub.name:
            yield sub.name, sub
        elif MatchMapping is not None and isinstance(sub, MatchMapping) and sub.rest:
            yield sub.rest, sub


def _conditional_rebinds(node):
    """Yield (name, mask_pos, restore_pos) for the names an `except E as name` handler or a
    `match`/case CAPTURE binds. Within [mask_pos, restore_pos) the name is the caught exception
    / captured sub-value — NOT any prior alias; AFTER restore_pos it is ambiguous (Python deletes
    an except-name on the CAUGHT path but keeps the prior binding on the fall-through path; a
    match capture persists only if its case ran). So the per-scope timelines MASK the name inside
    the block and RESTORE the prior binding after — killing the contrived within-block false-
    POSITIVE without masking a real post-block use, which would be a false-NEGATIVE (round-8
    audit: a naive flat reset breaks `run=os.system; try: ... except E as run: ...; run(cmd)`,
    where `run` is still os.system on the fall-through path)."""
    if isinstance(node, ast.ExceptHandler):
        if node.name:
            mask = (node.lineno, node.col_offset)
            rest = (getattr(node, "end_lineno", node.lineno) or node.lineno,
                    getattr(node, "end_col_offset", 0) or 0)
            yield node.name, mask, rest
        return
    Match = getattr(ast, "Match", None)
    if Match is not None and isinstance(node, Match):
        for case in node.cases:
            body = case.body
            rest = (getattr(body[-1], "end_lineno", 0) or 0,
                    getattr(body[-1], "end_col_offset", 0) or 0)
            for nm, sub in _match_capture_bindings(case.pattern):
                yield nm, (sub.lineno, sub.col_offset), rest


def _import_canon(node):
    """Yield (bound_name, dotted_canonical) for each name an `import` / `from … import` binds, so the
    per-scope timelines treat a local `import os as run` / `from os import system as run` as a REBIND
    of the name (round-8 audit sibling-form D: a local import re-binding a name previously bound to
    something else was invisible to the position-aware resolver, leaking the stale binding)."""
    if isinstance(node, ast.Import):
        for a in node.names:
            if a.asname:
                yield a.asname, a.name                      # import os.path as p  -> p = os.path
            else:
                top = a.name.split(".")[0]                  # import os[.path]      -> binds `os`
                yield top, top
    elif isinstance(node, ast.ImportFrom):
        if node.level and node.level > 0:
            # a RELATIVE import (`from .os import system as run`) binds the name to a LOCAL package
            # symbol, NOT the stdlib — canonicalizing it to `os.system` is a false positive
            # (round-8 re-sweep). Yield a None canonical so the name RESETS (masks a prior alias)
            # without resolving to any dangerous dotted name.
            for a in node.names:
                if a.name != "*":
                    yield (a.asname or a.name), None
            return
        mod = node.module or ""
        for a in node.names:
            if a.name == "*":
                continue                                    # star handled by the global star map
            yield (a.asname or a.name), (mod + "." + a.name if mod else a.name)


def _is_own_file_target(node, is_path_ctor=None) -> bool:
    """True only if `node` IS, INLINE, the skill's own running file: bare `__file__`
    or `Path(__file__)` (single positional arg, no transform), unwrapping a walrus
    `(p := …)` to its value. A DERIVED sibling (`.with_name`/`.with_suffix`/`.parent`/
    `os.path.dirname`/`/`-join) is a DIFFERENT file and is NOT a self-target (AST009 FP
    guard). A Name bound to `__file__` is resolved separately, per-scope, by the auditor.

    The Path constructor is recognized by leaf name (`pl.Path` / `pathlib.Path` attr, a bare
    `Path`) AND, when `is_path_ctor(func_node)` is supplied, by a POSITION-AWARE alias — so
    `from pathlib import Path as P; P(__file__)` is caught while a `P = Safe; P(__file__)`
    rebind is not (round-4 audit pass 3: the old global path_ctors set was flow-insensitive)."""
    NE = getattr(ast, "NamedExpr", None)
    if NE is not None and isinstance(node, NE):
        return _is_own_file_target(node.value, is_path_ctor)
    if isinstance(node, ast.Name):
        return node.id == "__file__"
    if isinstance(node, ast.Call):
        f = node.func
        if isinstance(f, (ast.Name, ast.Attribute)):
            # The Path-ctor test is POSITION-AWARE when a resolver is supplied (so a param /
            # for-target / local rebind named `Path`/`pl.Path` is shadow-masked — round-4 audit
            # pass 5 FP); a literal leaf-name fallback covers a None resolver.
            if is_path_ctor is not None:
                is_path = is_path_ctor(f)
            else:
                is_path = (f.attr == "Path") if isinstance(f, ast.Attribute) else (f.id == "Path")
        elif isinstance(f, ast.Call) and is_path_ctor is not None:
            is_path = is_path_ctor(f)       # inline getattr(<base>, "Path")(__file__) ctor (round-7)
        else:
            is_path = False
        if is_path and len(node.args) == 1 and not node.keywords:
            return _is_own_file_target(node.args[0], is_path_ctor)
    return False


def _extract_is_guarded(call) -> bool:
    """True only if an `extractall` call carries a guard whose SAFETY IS VISIBLE in the
    source (so AST011 does not fire) — Codex audit (rounds 1 & 2):
      - `filter="data"`/`"tar"` — the SAFE filters as a string LITERAL (`"fully_trusted"`
        is the legacy no-op; a non-literal `filter=var` is unprovable -> not a guard);
      - `members=[…]`/`(…)` — an explicit list/tuple LITERAL of curated members. A
        variable (`members=m`) or a call (`members=t.getmembers()`) is NOT a guard: the
        value check is defeated by one level of indirection (`m = t.getmembers()`), and
        getmembers/getnames pass ALL members. Prefer RED on anything not provably safe."""
    for kw in call.keywords:
        if kw.arg == "filter":
            if isinstance(kw.value, ast.Constant) and str(kw.value.value) in ("data", "tar"):
                return True
            # the PEP 706 callable form: filter=tarfile.data_filter / tar_filter (any
            # import alias) or a bare imported data_filter/tar_filter (Codex r3 FP).
            dn = _dotted_name(kw.value) or ""
            leaf = dn.rsplit(".", 1)[-1]
            if leaf in ("data_filter", "tar_filter"):
                return True
        if kw.arg == "members" and isinstance(kw.value, (ast.List, ast.Tuple)):
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


_OS_OPEN_WRITE_FLAGS = {"O_WRONLY", "O_RDWR", "O_TRUNC", "O_CREAT", "O_APPEND", "O_EXCL"}


def _os_open_writes(flags_node) -> bool:
    """True if an os.open() flags expression (possibly an OR of os.O_* attributes)
    references any write/create/truncate flag — so a read-only os.open never fires."""
    if flags_node is None:
        return False
    for sub in ast.walk(flags_node):
        if isinstance(sub, ast.Attribute) and sub.attr in _OS_OPEN_WRITE_FLAGS:
            return True
        if isinstance(sub, ast.Name) and sub.id in _OS_OPEN_WRITE_FLAGS:
            return True
    return False


def _inplace_edit(node) -> bool:
    """True if a fileinput.input/FileInput call has an `inplace` arg that is not a provably
    FALSE constant (kwarg or positional index 1). inplace=True redirects stdout INTO the named
    file, rewriting it in place; a read-only fileinput(__file__) has no inplace and stays GREEN."""
    for kw in node.keywords:
        if kw.arg == "inplace":
            return not (isinstance(kw.value, ast.Constant) and not kw.value.value)
    if len(node.args) > 1:                      # fileinput.input(files, inplace, backup, ...)
        a = node.args[1]
        return not (isinstance(a, ast.Constant) and not a.value)
    return False


def _arg_or_kw(node, idx, kwname):
    """The call argument at positional index `idx`, else the `kwname=` keyword value, else None —
    so a destination passed as `dst=__file__` is checked exactly like the positional form."""
    if len(node.args) > idx:
        return node.args[idx]
    for kw in node.keywords:
        if kw.arg == kwname:
            return kw.value
    return None


def _dotted_name(node):
    """Resolve a func/expr node to a dotted name ('os.system', 'eval').
    Returns None if it is not a plain Name/Attribute chain. A walrus `(m := os).system` / a bare
    `(x := os.system)` is TRANSPARENT — the NamedExpr is unwrapped to its value anywhere in the
    chain, so a walrus RHS / attribute base / getattr base resolves like the un-walrus'd form
    (round-8 re-sweep: walrus was unwrapped only at the getattr head, leaking a one-liner bypass)."""
    NE = getattr(ast, "NamedExpr", None)
    parts = []
    while True:
        if NE is not None and isinstance(node, NE):
            node = node.value
        elif isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        else:
            break
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
    def __init__(self, rel, src, alias, open_aliases=None, import_modules=None,
                 import_from=None, star_modules=None, assign_aliases=None):
        self.rel = rel
        self.src = src
        self.alias = alias            # name -> builtin it aliases (eval/exec/compile)
        self.open_aliases = open_aliases or set()   # names bound to the `open` builtin
        self.import_modules = import_modules or {}  # `import shutil as sh` -> sh: shutil
        self.import_from = import_from or {}        # `from shutil import x` -> x: shutil.x
        self.star_modules = star_modules or set()   # `from shutil import *` -> {shutil}
        self.assign_aliases = assign_aliases or {}  # `mv = os.replace` -> mv: os.replace
        self.method_scopes = []   # stack: name -> method-leaf (ex = t.extractall; getattr…)
        # Stack of (file_names, bound_names) per lexical scope. PER-SCOPE (not the old
        # global set, which leaked cross-function — Codex r1). `file_names` are names
        # bound to __file__/Path(__file__) in this scope (walrus / tuple-unpack /
        # transitive `q = p` included — Codex r3); `bound_names` is EVERY name bound here
        # (params + non-file assigns), so an inner binding MASKS an outer __file__ binding
        # of the same name (lexical resolution: a sibling fn's `src` param must not fire).
        self.scopes = []
        # Stack of per-scope POSITION-AWARE timelines (pushed in lockstep with self.scopes):
        #  archive_scopes: {name: [(pos, is_archive)]} for the AST011 receiver-provenance gate;
        #  alias_scopes:   {name: [(pos, canonical)]} for within-scope callable/module aliases,
        #  so _canon resolves a name AS OF the use position (round-4 audit flow-sensitivity).
        self.archive_scopes = []
        self.alias_scopes = []
        # capture_scopes: {name: [(mask_pos, restore_pos)]} per scope — the regions where a name is
        # an `except … as` / `match` CAPTURE (the caught exception / matched sub-value). _capture_
        # masked consults this so a use INSIDE the block resolves to nothing (not a pre-block alias/
        # __file__/archive/method-ref), while a use AFTER falls through to the normal timelines —
        # block-scoped masking that does NOT poison _local_binding_scope (round-8 audit F1).
        self.capture_scopes = []
        # round-9: the unified _VF timeline stack, pushed in lockstep with the four old timelines —
        # built parallel and differential-checked (self._diff) before switching the resolvers to it.
        self.fact_scopes = []
        self._diff = None           # when a list, _canon logs (pos, old, new) divergences for parity
        self.findings = []

    def _resolve_import(self, name):
        """Resolve a dotted name through the IMPORT maps only (import_from / import_modules /
        star_modules) — no assignment aliases, no shadow. The import-level canonical form,
        used both by _canon's fallback and by the per-scope alias-timeline builder."""
        if not name:
            return name
        if name in self.import_from:
            return self.import_from[name]
        head, dot, rest = name.partition(".")
        if dot and head in self.import_modules:
            return self.import_modules[head] + "." + rest
        if not dot and name in self.import_modules:
            return self.import_modules[name]      # a BARE module alias (`import os as o` -> o = os),
            # so a getattr base `getattr(o, "system")` resolves to os.system (round-8 re-sweep)
        if not dot and self.star_modules:
            # `from <mod> import *` brings a BARE dangerous name into scope; resolve it ONLY
            # to a known-dangerous canonical leaf (the finite set the dotted rules key on) ->
            # zero new FP surface, hardening every dotted AST rule against the star-import form
            # (gap 6), incl. the archive openers (`from tarfile import *; open(p).extractall()`).
            for mod in self.star_modules:
                cand = mod + "." + name
                if cand in _STAR_RESOLVABLE or cand in _ARCHIVE_OPENERS:
                    return cand
        return name

    def _local_binding_scope(self, head, pos):
        """Index of the INNERMOST active scope that binds `head` AT OR BEFORE `pos` — a param
        (at (0,0)), an assignment / for-target / AnnAssign / walrus at its position — or None if
        `head` is not locally bound yet at `pos` (so it is the module import / a future rebind).
        Drives the position-aware shadow decision uniformly across the alias / path-ctor /
        method-ref resolvers (round-4 audit pass 5: a FUTURE rebind must not retroactively mask
        an earlier import-use, and a param/for/AnnAssign must mask just like an assignment)."""
        for i in range(len(self.scopes) - 1, -1, -1):
            tl = self.scopes[i].get(head)
            if tl and any(bp <= pos for bp, _k in tl):
                return i
        return None

    def _path_ctor_at(self, func_node) -> bool:
        """True if a call's func resolves to the pathlib.Path CONSTRUCTOR as of its position —
        POSITION-AWARE (a rebind masks). Resolves an alias (`P = pathlib.Path` / `from pathlib
        import Path as P`) via the per-scope alias timeline (read directly, so it works while
        _scope_bindings is still computing self.scopes) then the import maps."""
        pos = (getattr(func_node, "lineno", 0), getattr(func_node, "col_offset", 0))
        nm = _dotted_name(func_node)
        if not nm:
            # an inline getattr(<base>, "Path")(...) ctor — the base resolves through imports
            return isinstance(func_node, ast.Call) and self._func_canon(func_node, pos) == "pathlib.Path"
        head, dot, rest = nm.partition(".")
        if self._capture_masked(head, pos):
            return False                        # the ctor name is an except/match capture here

        i = self._local_binding_scope(head, pos)
        if i is not None:                       # locally bound as of pos (param/for/assign/…)
            canon = None
            for bp, cn in self.alias_scopes[i].get(head, ()):
                if bp <= pos:
                    canon = cn
            resolved = (canon + "." + rest if dot else canon) if canon else None
            return resolved == "pathlib.Path"   # a non-alias local (param/for/AnnAssign) -> masked
        return self._resolve_import(nm) == "pathlib.Path"   # the import (before any rebind)

    def _canon(self, name, pos=None):
        """Differential wrapper (round-9): old _canon_impl, and when self._diff is active, log any
        divergence from the new _facts_at-based _canon_v so the migration can reach parity."""
        r = self._canon_impl(name, pos)
        # log only at REAL resolution depth (all scopes incl. fact_scopes pushed) — not during the
        # build of the old timelines, where fact_scopes for the current scope is not yet pushed.
        if self._diff is not None and pos is not None and name and len(self.fact_scopes) == len(self.scopes):
            v = self._canon_v(name, pos)
            if v != r:
                self._diff.append(("canon", name, pos, r, v))
        return r

    def _canon_impl(self, name, pos=None):
        """Canonicalize a dotted call name to its real `module.X`. When a `pos` (lineno,
        col_offset) is given, a WITHIN-SCOPE assignment alias is resolved POSITION-AWARELY
        first: the innermost scope that binds the head decides via its most-recent binding AS
        OF `pos`, so a rebind masks (`mv=os.replace; mv(__file__); mv=safe` still resolves mv
        -> os.replace AT the call, and a param `def f(system): system()` resolves to nothing)
        — round-4 audit flow-sensitivity. Otherwise falls back to the import/star maps and the
        flow-insensitive global assign map (`a = os; a.replace`) — used only when pos is None."""
        if not name:
            return name
        head, dot, rest = name.partition(".")
        if pos is not None and self._capture_masked(head, pos):
            return None                  # the head is an except/match capture here, not the alias
        if pos is not None:
            i = self._local_binding_scope(head, pos)
            if i is None:
                # NOT locally bound as of pos -> it is the module import (a later rebind must
                # not retroactively mask an earlier import-use — round-4 audit pass 5). Resolve
                # via the IMPORT maps, NOT the flow-insensitive global assign map.
                return self._resolve_import(name)
            local = None
            for bp, cn in self.alias_scopes[i].get(head, ()):
                if bp <= pos:
                    local = cn
            if local:
                return local + ("." + rest if dot else "")
            if i == len(self.scopes) - 1:
                # INNERMOST scope binds head to a non-alias (param / local var / for-target /
                # AnnAssign) -> a definite shadow. Return None, NOT the name: the unchanged
                # dotted string `shutil.unpack_archive` would still match the rule (round-4
                # audit pass 3). None matches no rule.
                return None
            # bound only in an OUTER scope to a non-alias (a module placeholder `run=None` later
            # reassigned via `global run; run=os.system`) -> fall through to the global map.
        if name in self.assign_aliases:
            return self.assign_aliases[name]   # `mv = os.replace` / `PP = pathlib.Path` (pos=None)
        if self._shadowed(head):
            return name
        if name in self.import_from:
            return self.import_from[name]
        if dot and head in self.import_modules:
            return self.import_modules[head] + "." + rest
        if dot and head in self.assign_aliases:
            return self.assign_aliases[head] + "." + rest   # `a = os; a.replace`
        return self._resolve_import(name)                    # star-import resolution

    def _shadowed(self, head) -> bool:
        """True if `head` is bound by a LOCAL param/assignment in an active scope (so a
        module-level import/star of the same name is masked) — but NOT if it is an explicit
        callable/module alias (those resolve). The position-aware path above subsumes this
        for `pos`-aware calls; this remains for the pos=None fallback."""
        return bool(head) and head not in self.assign_aliases \
            and any(head in binds for binds in self.scopes)

    def _func_canon(self, func, pos):
        """Canonical dotted name of a call's func, POSITION-AWARE — the single entry point so
        every dotted rule AND the archive-opener / Path-ctor gates see the inline-getattr form
        uniformly. An inline `getattr(<base>, "<literal>")(...)` resolves to `<base>.<literal>`
        ONLY when the getattr head itself resolves to the BUILTIN getattr (bare-unbound or
        `builtins.getattr`) — so a locally-shadowed `def f(getattr): getattr(os,"system")` does
        NOT dispatch (round-7 audit FP) — and the base is resolved RECURSIVELY (so `builtins.
        getattr`, a module alias, or a nested getattr all work; round-7 audit FN)."""
        NE = getattr(ast, "NamedExpr", None)
        if NE is not None and isinstance(func, NE):
            return self._func_canon(func.value, pos)   # `(run := os.system)(...)` — the walrus VALUE
                                                       # is the callee (round-8 audit sibling-form E).
        dn = _dotted_name(func)
        if dn:
            return self._canon(dn, pos)
        if isinstance(func, ast.Call) and len(func.args) >= 2 \
                and isinstance(func.args[1], ast.Constant) and isinstance(func.args[1].value, str):
            # resolve the getattr HEAD through _func_canon (not _dotted_name) so a walrus-bound
            # getattr `(g := getattr)(os,"system")(...)` dispatches too (round-8 re-sweep); still
            # shadow-safe — a locally-shadowed getattr param resolves to None, not the builtin.
            if self._func_canon(func.func, pos) in ("getattr", "builtins.getattr"):
                base = self._func_canon(func.args[0], pos)
                if base:
                    return self._canon(base + "." + func.args[1].value, pos)
        return None

    def _capture_masked(self, name, pos):
        """True if `name` is, AT pos, an `except … as` / `match` CAPTURE (the caught exception /
        matched sub-value) rather than any pre-block binding — so a use there must NOT resolve to a
        prior alias / __file__ / archive / method-ref. Block-scoped: only INSIDE the handler/case
        body, and only until a REAL rebind of the name inside that body (recorded in the alias
        timeline) supersedes the capture — then the normal position-aware timeline wins. Consulting
        a SEPARATE region map (not the timelines) is what keeps a post-block use firing and keeps
        _local_binding_scope clean for an otherwise-unbound captured builtin (round-8 audit F1)."""
        if not self.capture_scopes:
            return False
        regions = self.capture_scopes[-1].get(name)
        if not regions:
            return False
        for mp, rp in regions:
            if mp <= pos < rp:
                tl = self.alias_scopes[-1].get(name, ()) if self.alias_scopes else ()
                if not any(mp < bp <= pos for bp, _c in tl):   # no in-body rebind supersedes it yet
                    return True
        return False

    def _scope_captures(self, scope_node):
        """{name: [(mask_pos, restore_pos), …]} — the source regions where `name` is an except/
        match CAPTURE in THIS scope (NOT into nested function/class/lambda scopes, which own their
        captures). Drives _capture_masked (round-8 audit F1: the block-scoped masking overlay)."""
        regions = {}

        def walk(node):
            for n in ast.iter_child_nodes(node):
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                    continue                              # a nested scope owns its own captures
                for nm, mpos, rpos in _conditional_rebinds(n):
                    regions.setdefault(nm, []).append((mpos, rpos))
                walk(n)
        walk(scope_node)
        return regions

    # ===== round-9: unified abstract-interpreter evaluator =====================================
    # Built PARALLEL to the four old per-scope timeline walkers (alias / __file__ / archive /
    # method-ref). One eval_expr computes ALL provenance domains into one _VF; one bind_target stores
    # them; _facts_at reads as-of a position (cross-scope + capture overlay). Differential-checked
    # against the old resolvers on the corpus, then switched domain-by-domain. Ends the H1-H7 cycle.

    def _scope_facts(self, scope_node, param_names=()):
        """THE unified per-scope timeline {name: [(pos, _VF)]} — ONE walk + ONE bind_target + ONE
        eval_expr carrying ALL provenance domains. NOT into nested scopes. A capture (except/match)
        is recorded as its PRIOR binding here; local_at / _facts_at mask it block-scoped via the
        overlay, so a post-block / post-rebind use resolves normally."""
        facts = {}
        NE = getattr(ast, "NamedExpr", None)

        def add(name, pos, vf):
            facts.setdefault(name, []).append((pos, vf))

        for p in param_names:
            add(p, (0, 0), _VF())          # a param masks (opaque)

        def local_at(name, pos):
            for mp, rp in (self.capture_scopes[-1].get(name, ()) if self.capture_scopes else ()):
                if mp <= pos < rp and not any(mp < bp <= pos for bp, _f in facts.get(name, ())):
                    return _VF()           # a LIVE capture -> opaque (yields to an in-block rebind)
            vf, bound = None, False
            for bp, f in facts.get(name, ()):
                if bp <= pos:
                    bound, vf = True, f
            return vf if bound else None

        def is_getattr_call(node, pos):
            if not (isinstance(node, ast.Call) and len(node.args) >= 2
                    and isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str)):
                return None
            if eval_expr(node.func, pos).canon in ("getattr", "builtins.getattr"):
                return node.args[0], node.args[1].value
            return None

        def seq_rep(elts, pos):
            els = [eval_expr(e, pos) for e in elts]
            return _VF(
                canon=next((e.canon for e in els if e.canon and "." in e.canon), None),
                archive=any(e.archive for e in els),
                self_file=any(e.self_file for e in els),
                mleaf=next((e.mleaf for e in els if e.mleaf), None),
                mrecv=any(e.mrecv for e in els),
            )

        def eval_expr(node, pos):
            if NE is not None and isinstance(node, NE):
                return eval_expr(node.value, pos)
            if _is_own_file_target(node, self._path_ctor_at):
                return _VF(self_file=True)
            if isinstance(node, ast.Name):
                f = local_at(node.id, pos)
                return f if f is not None else _VF(canon=self._resolve_import(node.id))
            if isinstance(node, ast.Attribute):
                base = eval_expr(node.value, pos)
                canon = (base.canon + "." + node.attr) if base.canon else None
                return _VF(canon=canon, mleaf=node.attr, mrecv=base.archive)
            if isinstance(node, ast.Call):
                if self._func_canon(node.func, pos) in _ARCHIVE_OPENERS:
                    return _VF(archive=True)
                ga = is_getattr_call(node, pos)
                if ga:
                    base = eval_expr(ga[0], pos)
                    canon = (base.canon + "." + ga[1]) if base.canon else None
                    return _VF(canon=canon, mleaf=ga[1], mrecv=base.archive)
                return _VF()
            if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
                return _VF(seq=seq_rep(node.elts, pos))
            if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
                return _VF(seq=eval_expr(node.elt, pos))
            if isinstance(node, ast.Subscript):
                v = eval_expr(node.value, pos)
                return v.seq if v.seq is not None else _VF()
            if isinstance(node, ast.IfExp):
                a, b = eval_expr(node.body, pos), eval_expr(node.orelse, pos)
                return _VF(self_file=a.self_file or b.self_file, archive=a.archive or b.archive,
                           canon=a.canon if a.canon == b.canon else None)
            return _VF()

        def bind_target(target, value, pos):
            if isinstance(target, ast.Name):
                add(target.id, pos, eval_expr(value, pos) if value is not None else _VF())
            elif isinstance(target, (ast.Tuple, ast.List)) and isinstance(value, (ast.Tuple, ast.List)) \
                    and len(target.elts) == len(value.elts):
                for t_el, v_el in zip(target.elts, value.elts):
                    bind_target(t_el, v_el, pos)
            else:
                for nm in _names_in_target(target):
                    add(nm, pos, _VF())

        def walk(node):
            for n in ast.iter_child_nodes(node):
                pos = (getattr(n, "lineno", 0), getattr(n, "col_offset", 0))
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    add(n.name, pos, _VF())
                    continue
                if isinstance(n, ast.Lambda):
                    continue
                if NE is not None and isinstance(n, NE) and isinstance(n.target, ast.Name):
                    add(n.target.id, pos, eval_expr(n.value, pos))
                elif isinstance(n, ast.Assign):
                    for tgt in n.targets:
                        bind_target(tgt, n.value, pos)
                elif isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name):
                    if n.value is not None:
                        add(n.target.id, pos, eval_expr(n.value, pos))
                elif isinstance(n, ast.AugAssign) and isinstance(n.target, ast.Name):
                    add(n.target.id, pos, _VF())
                elif isinstance(n, (ast.For, ast.AsyncFor)):
                    if isinstance(n.target, ast.Name):
                        it = eval_expr(n.iter, pos)
                        add(n.target.id, pos, it.seq if it.seq is not None else _VF())
                    else:
                        for nm in _names_in_target(n.target):
                            add(nm, pos, _VF())
                elif isinstance(n, (ast.With, ast.AsyncWith)):
                    for item in n.items:
                        if item.optional_vars is not None:
                            if isinstance(item.optional_vars, ast.Name):
                                add(item.optional_vars.id, pos, _VF(archive=eval_expr(item.context_expr, pos).archive))
                            else:
                                for nm in _names_in_target(item.optional_vars):
                                    add(nm, pos, _VF())
                elif isinstance(n, (ast.Import, ast.ImportFrom)):
                    for bnd, canon in _import_canon(n):
                        add(bnd, pos, _VF(canon=self._resolve_import(canon)) if canon else _VF())
                walk(n)
        walk(scope_node)
        return facts

    def _facts_at(self, name, pos):
        """The _VF for `name` AS OF pos — the innermost fact-scope that binds it (cross-scope, like
        _local_binding_scope), masked block-scoped by the capture overlay. _VF() (opaque) if
        captured-not-rebound; None if not bound in any active scope (caller resolves via imports)."""
        if self._capture_masked(name, pos):
            return _VF()
        for binds in reversed(self.fact_scopes):
            tl = binds.get(name)
            if tl:
                vf, bound = None, False
                for bp, f in tl:
                    if bp <= pos:
                        bound, vf = True, f
                if bound:
                    return vf
        return None

    def _canon_v(self, name, pos):
        """NEW canonical resolver over the unified _VF timeline (round-9), structurally mirroring
        _canon_impl but reading fact_scopes: the innermost fact-scope binding the head decides; an
        outer-scope non-alias falls through to the SAME flow-insensitive global map (assign_aliases /
        imports) — so the cross-scope global-rebind (`global run; run=os.system`) still resolves."""
        head, dot, rest = name.partition(".")
        if self._capture_masked(head, pos):
            return None
        i = None
        for idx in range(len(self.fact_scopes) - 1, -1, -1):
            tl = self.fact_scopes[idx].get(head)
            if tl and any(bp <= pos for bp, _f in tl):
                i = idx
                break
        if i is None:
            return self._resolve_import(name)        # not locally bound -> import maps (not global)
        f = None
        for bp, ff in self.fact_scopes[i].get(head, ()):
            if bp <= pos:
                f = ff
        if f.canon:
            return f.canon + ("." + rest if dot else "")
        if i == len(self.fact_scopes) - 1:
            return None                              # innermost non-alias shadow -> masks
        if name in self.assign_aliases:              # outer-scope non-alias -> global fallback
            return self.assign_aliases[name]
        if self._shadowed(head):
            return name
        if name in self.import_from:
            return self.import_from[name]
        if dot and head in self.import_modules:
            return self.import_modules[head] + "." + rest
        if dot and head in self.assign_aliases:
            return self.assign_aliases[head] + "." + rest
        return self._resolve_import(name)

    def _scope_alias_bindings(self, scope_node, param_names=()):
        """{name: [((lineno,col), canonical_or_None), …]} in source order — a POSITION-AWARE
        per-scope timeline of callable/module assignment aliases: `mv = os.replace`, `a = os`,
        `o = getattr(builtins,"open")`, transitive `b = a` (resolved at the binding position
        through the import maps + this scope's earlier aliases). A non-alias assignment records
        `None` (so the name MASKS a module import of the same name). A PARAM is seeded as None at
        (0,0) so it masks too — this builder runs BEFORE self.scopes exists, so the assignment-path
        resolver could not otherwise see a param shadow (`def f(getattr): fn = getattr(os,"system")`
        / `def f(os): os.replace(...)`), unlike the inline path via _canon (round-8 re-sweep). NOT
        into nested scopes."""
        binds = {}
        NE = getattr(ast, "NamedExpr", None)

        def add(name, pos, canon):
            binds.setdefault(name, []).append((pos, canon))

        for p in param_names:
            add(p, (0, 0), None)                                 # a param MASKS a module import / alias

        def at(name, pos):
            c = None
            for bp, cn in binds.get(name, ()):
                if bp <= pos:
                    c = cn
            return c

        def head_canon_at(head, pos):
            # the dotted-head canonical AS OF pos, DISTINGUISHING a within-scope bind (None ->
            # definitively shadowed) from 'unbound' (-> the import/builtin) — so a shadowed
            # getattr does not dispatch while the bare builtin / a `builtins.getattr` alias does.
            bound, c = False, None
            for bp, cn in binds.get(head, ()):
                if bp <= pos:
                    bound, c = True, cn
            return c if bound else self._resolve_import(head)

        def head_is_capture(head, pos):
            # `head` is a live except/match CAPTURE at pos (the caught exception / matched value),
            # UNLESS a later in-body rebind in THIS alias timeline (`binds`) supersedes it. Keys on
            # the HEAD name and yields to an in-handler rebind, using the LOCAL `binds` so it is valid
            # DURING construction (round-8 re-sweep H1/H2: the old _head_captured matched the whole
            # dotted string and ignored a superseding rebind).
            for mp, rp in (self.capture_scopes[-1].get(head, ()) if self.capture_scopes else ()):
                if mp <= pos < rp and not any(mp < bp <= pos for bp, _c in binds.get(head, ())):
                    return True
            return False

        def resolve(value, pos):
            if isinstance(value, ast.Call) and len(value.args) >= 2 \
                    and isinstance(value.args[1], ast.Constant) and isinstance(value.args[1].value, str):
                gfunc = value.func
                while NE is not None and isinstance(gfunc, NE):  # `(h := (g := getattr))(...)` —
                    gfunc = gfunc.value                          # unwrap NESTED walruses (re-sweep H3)
                gh = _dotted_name(gfunc)                         # `o = getattr(<base>, "<literal>")`:
                ghead, gdot, grest = gh.partition(".") if gh else ("", "", "")
                if ghead and not head_is_capture(ghead, pos):   # the HEAD (not the whole dotted) must
                    gc = head_canon_at(ghead, pos)              # not be a live capture; dispatch ONLY
                    if gc and gdot:                             # when it resolves (shadow-safe) to the
                        gc = gc + "." + grest                   # BUILTIN getattr (`builtins.getattr` /
                    if gc in ("getattr", "builtins.getattr"):   # an alias / a walrus head all resolve).
                        bl = resolve(value.args[0], pos)
                        return bl + "." + value.args[1].value if bl else None
            dn = _dotted_name(value)
            if not dn:
                return None
            head, dot, rest = dn.partition(".")
            if head_is_capture(head, pos):                       # `except E as os: fn = os.system` —
                return None                                      # os is the caught exception, not the
            bound, lc = False, None                              # module (round-8 re-sweep H5: the
            for bp, cn in binds.get(head, ()):                   # capture check applied only to the
                if bp <= pos:                                    # getattr head, not the general head/
                    bound, lc = True, cn                         # base). distinguish a within-scope bind
            if bound:                                            # (None -> shadowed: param / non-alias
                return (lc + "." + rest if dot else lc) if lc else None  # assign / for) from UNBOUND ->
            return self._resolve_import(dn)                      # the import / transitive alias.

        def seq_alias(value, pos):
            # a for-target over a LITERAL sequence holding a callable alias resolves to it,
            # mirroring is_seqarch for archives (`for f in [os.system]: f(cmd)` -> f is os.system);
            # an opaque iterable (a Name / call) yields None so the for-target RESETS — so the #3
            # benign-reuse fix (`runner=os.system; for runner in items:`) is preserved (round-6 R6-2).
            elts = None
            if isinstance(value, (ast.List, ast.Tuple, ast.Set)):
                elts = value.elts
            elif isinstance(value, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
                elts = [value.elt]
            for e in (elts or ()):
                c = resolve(e, pos)
                if c and "." in c:          # prefer a module-qualified canonical (the dangerous one)
                    return c
            return None

        def add_target(target, value, pos):
            # recursive matched-length tuple/list pairing (mirrors _scope_bindings.bind_target),
            # so `runner, opts = os.system, {}` aliases runner -> os.system and `(a,(b,c)) =
            # (1,(os.system,2))` aliases b; an unpairable target RESETS every bound name to None.
            if isinstance(target, ast.Name):
                add(target.id, pos, resolve(value, pos) if value is not None else None)
            elif isinstance(target, (ast.Tuple, ast.List)) and isinstance(value, (ast.Tuple, ast.List)) \
                    and len(target.elts) == len(value.elts):
                for t_el, v_el in zip(target.elts, value.elts):
                    add_target(t_el, v_el, pos)
            else:
                for nm in _names_in_target(target):
                    add(nm, pos, None)

        def walk(node):
            for n in ast.iter_child_nodes(node):
                pos = (getattr(n, "lineno", 0), getattr(n, "col_offset", 0))
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    add(n.name, pos, None)         # def/class REBINDS its name here -> reset
                    continue                       # its body is a nested scope (not recursed)
                if isinstance(n, ast.Lambda):
                    continue                       # anonymous — binds no name in this scope
                # EVERY binding FORM that can (re)bind a name touches this timeline, in LOCK-STEP
                # with _scope_bindings / _scope_method_refs / _scope_archive_names — an aliasing
                # form sets a canonical, any other (re)bind RESETS to None so a prior alias does
                # not leak past it. (round-6 sweep: checkered form-coverage across the 4 value-
                # timelines was the disease — keep this branch set identical in all four.)
                if NE is not None and isinstance(n, NE) and isinstance(n.target, ast.Name):
                    add(n.target.id, pos, resolve(n.value, pos))
                elif isinstance(n, ast.Assign):
                    for tgt in n.targets:
                        add_target(tgt, n.value, pos)
                elif isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name):
                    if n.value is not None:
                        add(n.target.id, pos, resolve(n.value, pos))   # `mv: Callable = os.replace`
                    # a BARE annotation `mv: object` does NOT rebind at runtime (verified mv is
                    # os.system) -> NO-OP (preserve the prior binding), in lock-step with the
                    # __file__ timeline (round-6 CONFIRM sweep: a reset here was an FN regression).
                elif isinstance(n, ast.AugAssign) and isinstance(n.target, ast.Name):
                    add(n.target.id, pos, None)            # `mv += x` -> no longer a clean alias
                elif isinstance(n, (ast.For, ast.AsyncFor)):
                    seqc = seq_alias(n.iter, pos) if isinstance(n.target, ast.Name) else None
                    if seqc is not None:
                        add(n.target.id, pos, seqc)        # `for f in [os.system]:` -> f is os.system
                    else:
                        for nm in _names_in_target(n.target):  # a for-loop variable is not an alias
                            add(nm, pos, None)
                elif isinstance(n, (ast.With, ast.AsyncWith)):
                    for item in n.items:                   # `with X as name` rebinds name -> reset
                        if item.optional_vars is not None:
                            for nm in _names_in_target(item.optional_vars):
                                add(nm, pos, None)
                elif isinstance(n, (ast.Import, ast.ImportFrom)):
                    for bnd, canon in _import_canon(n):    # `import os as run` / `from os import
                        add(bnd, pos, self._resolve_import(canon))  # system as run` REBINDS the name
                    # to a module/callable; the position-aware resolver must see it so a prior local
                    # binding of the same name does not mask it (round-8 audit sibling-form D).
                walk(n)
        walk(scope_node)
        return binds

    @staticmethod
    def _scope_bindings(scope_node, param_names=(), is_path_ctor=None, is_captured=None):
        """POSITION-AWARE __file__ binding timeline for THIS scope (NOT into nested
        function/class/lambda scopes). Returns `binds = {name: [(pos, kind), …]}` in
        source order, pos = (lineno, col_offset), kind ∈ {'file','seqfile','other'}.
        _self_target resolves a name AS OF a write call's POSITION (its most recent prior
        binding), so `p=__file__; p.write(); p=None` fires (write while p IS __file__) and
        `p=Path(__file__); p=p.with_name(x); p.write()` does not (rebound to a sibling BEFORE
        the write). Position is (lineno, col) — NOT just lineno — so a same-LINE rebind
        `p=Path(__file__); p.write(); p=None` does not mask the write either (round-4 audit).
        A param (kind 'other' at pos (0,0)) masks an outer __file__ binding. 'seqfile' = bound
        to a literal/comprehension sequence holding __file__ (`for p in paths` binds p 'file')."""
        binds = {}
        NE = getattr(ast, "NamedExpr", None)

        def add(name, pos, kind):
            binds.setdefault(name, []).append((pos, kind))

        for p in param_names:
            add(p, (0, 0), "other")

        def latest(name, pos):
            st = None
            for bp, k in binds.get(name, ()):
                if bp <= pos:
                    st = k
            return st

        def seq_holds_file(value):
            if isinstance(value, (ast.List, ast.Tuple)):
                return any(_is_own_file_target(e, is_path_ctor) for e in value.elts)
            if isinstance(value, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
                return _is_own_file_target(value.elt, is_path_ctor)
            return False

        def kind_of(value, lineno):
            if _is_own_file_target(value, is_path_ctor):
                return "file"
            if isinstance(value, ast.Name) and latest(value.id, lineno) == "file" \
                    and not (is_captured and is_captured(value.id, lineno)):
                return "file"                      # transitive q = p (a captured p does NOT propagate)
            if seq_holds_file(value):
                return "seqfile"
            return "other"

        def bind_target(target, value, lineno):
            if isinstance(target, ast.Name):
                add(target.id, lineno, kind_of(value, lineno))
            elif isinstance(target, (ast.Tuple, ast.List)):
                if isinstance(value, (ast.Tuple, ast.List)) and len(target.elts) == len(value.elts):
                    for t_el, v_el in zip(target.elts, value.elts):
                        bind_target(t_el, v_el, lineno)
                else:
                    for nm in _names_in_target(target):
                        add(nm, lineno, "other")
            else:
                for nm in _names_in_target(target):
                    add(nm, lineno, "other")

        def walk(node):
            for n in ast.iter_child_nodes(node):
                ln = (getattr(n, "lineno", 0), getattr(n, "col_offset", 0))
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    add(n.name, ln, "other")       # def/class REBINDS its name here -> reset
                    continue                       # a nested scope owns its own bindings
                if isinstance(n, ast.Lambda):
                    continue                       # anonymous — binds no name in this scope
                if NE is not None and isinstance(n, NE) and isinstance(n.target, ast.Name):
                    bind_target(n.target, n.value, ln)
                elif isinstance(n, ast.Assign):
                    for tgt in n.targets:
                        bind_target(tgt, n.value, ln)
                elif isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name):
                    bind_target(n.target, n.value if n.value is not None else n.target, ln)
                elif isinstance(n, ast.AugAssign) and isinstance(n.target, ast.Name):
                    add(n.target.id, ln, "other")
                elif isinstance(n, (ast.For, ast.AsyncFor)):
                    if isinstance(n.target, ast.Name):
                        it = n.iter
                        holds = seq_holds_file(it) or (isinstance(it, ast.Name) and latest(it.id, ln) == "seqfile")
                        add(n.target.id, ln, "file" if holds else "other")
                    else:
                        for nm in _names_in_target(n.target):
                            add(nm, ln, "other")
                elif isinstance(n, (ast.With, ast.AsyncWith)):
                    for item in n.items:           # `with X as name` rebinds name -> reset (not __file__)
                        if item.optional_vars is not None:
                            for nm in _names_in_target(item.optional_vars):
                                add(nm, ln, "other")
                elif isinstance(n, (ast.Import, ast.ImportFrom)):
                    for bnd, _c in _import_canon(n):       # an import REBINDS the name to a module,
                        add(bnd, ln, "other")              # never this skill's __file__ (sibling D).
                walk(n)                            # recurse in source order
        walk(scope_node)
        return binds

    def _scope_method_refs(self, scope_node):
        """{name: [(pos, method-leaf-or-None, receiver_is_archive), …]} — a POSITION-AWARE
        timeline of a method REFERENCE bound in THIS scope: `ex = t.extractall`, `fn =
        getattr(t, "extractall")`, a transitive `b = a`, a tuple-unpack, or a walrus. A rebind
        to a NON-ref records leaf=None (so `ex = a.extractall; ex(); ex = safe` does not flag
        the LATER non-ref use, and a safe `ex()` BEFORE a later `ex = a.extractall` does not
        flag — round-4 audit pass 3 final-state-map FN/FP). `receiver_is_archive` is resolved
        AT the binding position. NOT into nested scopes; relies on this scope's archive set
        already on self.archive_scopes."""
        refs = {}
        NE = getattr(ast, "NamedExpr", None)

        def ref_at(name, pos):
            leaf, recv = None, False
            for bp, lf, rc in refs.get(name, ()):
                if bp <= pos:
                    leaf, recv = lf, rc
            return (leaf, recv) if leaf is not None else None

        def ref_info(value, pos):
            if NE is not None and isinstance(value, NE):
                return ref_info(value.value, pos)
            if isinstance(value, ast.Attribute):
                return (value.attr, self._is_archive_expr(value.value))
            if isinstance(value, ast.Call) and len(value.args) >= 2 \
                    and isinstance(value.args[1], ast.Constant) and isinstance(value.args[1].value, str) \
                    and self._func_canon(value.func, pos) in ("getattr", "builtins.getattr"):
                # `fn = getattr(t, "extractall")` — builtins.getattr / an alias / a walrus head all
                # resolve through _func_canon (shadow-safe + walrus-unwrap; method refs build after
                # alias_scopes), round-8 audit + re-sweep.
                return (value.args[1].value, self._is_archive_expr(value.args[0]))
            if isinstance(value, ast.Name):
                if self._capture_masked(value.id, pos):    # a LIVE captured `ex` does NOT propagate its
                    return None                            # method-ref to `f = ex`; a captured name
                return ref_at(value.id, pos)       # rebound to a real ref DOES (round-8 re-sweep H6/H7)
            return None

        def bind(name, pos, value):
            info = ref_info(value, pos)
            refs.setdefault(name, []).append((pos, info[0] if info else None, info[1] if info else False))

        def reset(name, pos):
            refs.setdefault(name, []).append((pos, None, False))   # a non-ref rebind clears the ref

        def seq_ref(value, pos):
            # a for-target over a LITERAL sequence holding a method-ref resolves to it, mirroring
            # is_seqarch (`for ex in [t.extractall]: ex()`); an opaque iterable yields None -> reset.
            elts = None
            if isinstance(value, (ast.List, ast.Tuple, ast.Set)):
                elts = value.elts
            elif isinstance(value, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
                elts = [value.elt]
            for e in (elts or ()):
                info = ref_info(e, pos)
                if info:
                    return info
            return None

        def bind_target(target, value, pos):
            # recursive matched-length tuple/list pairing (mirrors _scope_bindings.bind_target):
            # `ex, _ = t.extractall, 0` and nested `(a,(ex,c)) = (1,(t.extractall,2))` both bind ex;
            # an unpairable target RESETS every bound name (no ref).
            if isinstance(target, ast.Name):
                bind(target.id, pos, value)
            elif isinstance(target, (ast.Tuple, ast.List)) and isinstance(value, (ast.Tuple, ast.List)) \
                    and len(target.elts) == len(value.elts):
                for t_el, v_el in zip(target.elts, value.elts):
                    bind_target(t_el, v_el, pos)
            else:
                for nm in _names_in_target(target):
                    reset(nm, pos)

        def walk(node):
            for n in ast.iter_child_nodes(node):
                pos = (getattr(n, "lineno", 0), getattr(n, "col_offset", 0))
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    reset(n.name, pos)             # def/class REBINDS its name here -> reset
                    continue
                if isinstance(n, ast.Lambda):
                    continue                       # anonymous — binds no name in this scope
                # branch set kept in LOCK-STEP with the other three value-timelines (round-6 sweep).
                if NE is not None and isinstance(n, NE) and isinstance(n.target, ast.Name):
                    bind(n.target.id, pos, n.value)
                elif isinstance(n, ast.Assign):
                    for tgt in n.targets:
                        bind_target(tgt, n.value, pos)
                elif isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name):
                    if n.value is not None:
                        bind(n.target.id, pos, n.value)        # `ex: Callable = t.extractall`
                    # bare `ex: object` does NOT rebind at runtime -> NO-OP (preserve), lock-step
                    # with __file__ (round-6 CONFIRM sweep C24: a reset here was an AST011 FN regression).
                elif isinstance(n, ast.AugAssign) and isinstance(n.target, ast.Name):
                    reset(n.target.id, pos)
                elif isinstance(n, (ast.For, ast.AsyncFor)):
                    info = seq_ref(n.iter, pos) if isinstance(n.target, ast.Name) else None
                    if info is not None:
                        refs.setdefault(n.target.id, []).append((pos, info[0], info[1]))
                    else:
                        for nm in _names_in_target(n.target):   # for-loop var is not a method-ref
                            reset(nm, pos)
                elif isinstance(n, (ast.With, ast.AsyncWith)):
                    for item in n.items:                        # `with X as name` rebinds -> reset
                        if item.optional_vars is not None:
                            for nm in _names_in_target(item.optional_vars):
                                reset(nm, pos)
                elif isinstance(n, (ast.Import, ast.ImportFrom)):
                    for bnd, _c in _import_canon(n):            # an import REBINDS to a module, not a
                        reset(bnd, pos)                         # method reference (sibling D).
                walk(n)
        walk(scope_node)
        return refs

    def _method_ref_at(self, name_node):
        """(leaf, receiver_is_archive) for a Name that holds a method reference AS OF its
        position (a later rebind to a non-ref does not leak back), or None."""
        pos = (getattr(name_node, "lineno", 0), getattr(name_node, "col_offset", 0))
        if self._capture_masked(name_node.id, pos):
            return None                         # the name is an except/match capture here, not a ref
        # the innermost scope that BINDS the name decides (a param / for / AnnAssign masks an
        # outer archive method-ref — round-4 audit pass 5 FP); resolve its ref timeline as of pos.
        i = self._local_binding_scope(name_node.id, pos)
        if i is not None:
            tl = self.method_scopes[i].get(name_node.id)
            if tl:
                leaf, recv = None, False
                for bp, lf, rc in tl:
                    if bp <= pos:
                        leaf, recv = lf, rc
                return (leaf, recv) if leaf is not None else None
        return None

    def _func_attr(self, func):
        """The method leaf a call invokes: a direct `obj.attr`, an inline walrus
        `(a := t.extractall)(…)`, OR a Name bound in scope to a method reference AS OF its
        position (`ex = t.extractall` / `fn = getattr(t, "extractall")` / transitive / unpack)."""
        NE = getattr(ast, "NamedExpr", None)
        if NE is not None and isinstance(func, NE):
            return self._func_attr(func.value)
        if isinstance(func, ast.Attribute):
            return func.attr
        if isinstance(func, ast.Name):
            info = self._method_ref_at(func)
            return info[0] if info else None
        return None

    @staticmethod
    def _archive_state(timeline, pos):
        """The state of a name AS OF `pos` from its archive timeline of (pos, kind, cond),
        kind in {'arch','seqarch','other'}: returns 'arch' / 'seqarch' / 'other'. A 'other'
        (non-archive) rebind masks an earlier 'arch'/'seqarch' ONLY when it is UNCONDITIONAL
        (cond=False, a top-level statement) — a rebind in a sibling try/except/if branch does
        NOT mask the live archive on the other path (round-4 audit pass 3 #4)."""
        last_arch = last_seq = None
        for bp, kind, _cond in timeline:
            if bp <= pos:
                if kind == "arch":
                    last_arch = bp
                elif kind == "seqarch":
                    last_seq = bp

        def live(last):
            if last is None:
                return False
            for bp, kind, cond in timeline:
                if kind == "other" and not cond and last < bp <= pos:
                    return False
            return True
        if live(last_arch):
            return "arch"
        if live(last_seq):
            return "seqarch"
        return "other"

    def _name_archive_state(self, name_node):
        """The 'arch'/'seqarch'/'other' state of a Name as of its position — the innermost
        scope that binds it decides (param shadow), resolving AS OF the use position."""
        pos = (getattr(name_node, "lineno", 0), getattr(name_node, "col_offset", 0))
        if self._capture_masked(name_node.id, pos):
            return "other"                      # the name is an except/match capture here, not an archive
        for i in range(len(self.scopes) - 1, -1, -1):
            if name_node.id in self.scopes[i]:
                return self._archive_state(self.archive_scopes[i].get(name_node.id, ()), pos)
        for binds in reversed(self.archive_scopes):          # closure: not locally bound
            if name_node.id in binds:
                return self._archive_state(binds[name_node.id], pos)
        return "other"

    def _is_archive_expr(self, node) -> bool:
        """True if `node` PROVABLY evaluates to a tarfile/zipfile archive object: an opener
        Call (canon-resolved), an IfExp whose either arm is an archive, a Name bound to one in
        scope (assign / with-as / transitive / walrus, position-aware), or an indexed element
        of a sequence-of-archives (`archives[0]`). A pandas `.str` accessor, a bs4 object, an
        opaque param is NOT provable, so its `.extractall()` does not fire AST011."""
        NE = getattr(ast, "NamedExpr", None)
        if NE is not None and isinstance(node, NE):
            node = node.value
        if isinstance(node, ast.Call):
            return self._func_canon(node.func,
                               (getattr(node.func, "lineno", 0), getattr(node.func, "col_offset", 0))) in _ARCHIVE_OPENERS
        if isinstance(node, ast.IfExp):
            return self._is_archive_expr(node.body) or self._is_archive_expr(node.orelse)
        if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name):
            return self._name_archive_state(node.value) == "seqarch"   # archives[0].extractall()
        if isinstance(node, ast.Name):
            return self._name_archive_state(node) == "arch"
        return False

    def _extractall_on_archive(self, func) -> bool:
        """True if the `extractall` receiver is a provable archive — a direct
        `archive.extractall()` (incl. inline walrus) OR a method-ref `ex = archive.extractall;
        ex()` whose receiver was an archive. Gap-5 provenance gate for AST011."""
        NE = getattr(ast, "NamedExpr", None)
        if NE is not None and isinstance(func, NE):
            func = func.value
        if isinstance(func, ast.Attribute):
            return self._is_archive_expr(func.value)
        if isinstance(func, ast.Name):
            info = self._method_ref_at(func)
            return info[1] if info else False
        return False

    def _scope_archive_names(self, scope_node):
        """{name: [(pos, kind, cond), …]} per-scope timeline. kind in {'arch','seqarch',
        'other'}: 'arch' = a tarfile/zipfile archive object (opener Call / with-as / IfExp arm
        / transitive); 'seqarch' = a sequence HOLDING an opener (so `for x in <seqarch>` binds x
        'arch', and `<seqarch>[i]` is an archive). `cond` marks a binding inside a conditional
        sub-block. _archive_state resolves a name AS OF a use position: an UNCONDITIONAL non-
        archive rebind masks an earlier archive; a sibling try/except/if-branch rebind does NOT
        (round-4 audit pass 3 #3/#4/#5: a live archive on one path stays detected). NOT into
        nested function/class/lambda scopes."""
        binds = {}
        NE = getattr(ast, "NamedExpr", None)

        def add(name, pos, kind, cond):
            binds.setdefault(name, []).append((pos, kind, cond))

        def state(name, pos):
            return self._archive_state(binds.get(name, ()), pos)

        def is_opener(value):
            return isinstance(value, ast.Call) \
                and self._func_canon(value.func,
                                (getattr(value.func, "lineno", 0), getattr(value.func, "col_offset", 0))) in _ARCHIVE_OPENERS

        def is_arch(value, pos):
            if NE is not None and isinstance(value, NE):
                return is_arch(value.value, pos)
            if is_opener(value):
                return True
            if isinstance(value, ast.IfExp):
                return is_arch(value.body, pos) or is_arch(value.orelse, pos)
            if isinstance(value, ast.Name):
                return state(value.id, pos) == "arch" and not self._capture_masked(value.id, pos)  # b = a
            return False

        def is_seqarch(value, pos):
            if isinstance(value, (ast.List, ast.Tuple, ast.Set)):
                return any(is_arch(e, pos) for e in value.elts)
            if isinstance(value, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
                return is_arch(value.elt, pos)
            if isinstance(value, ast.Name):
                return state(value.id, pos) == "seqarch" and not self._capture_masked(value.id, pos)
            return False

        def kind_of(value, pos):
            if is_arch(value, pos):
                return "arch"
            if is_seqarch(value, pos):
                return "seqarch"
            return "other"

        def bind_target(target, value, pos, cond):
            # recursive matched-length tuple/list pairing (mirrors _scope_bindings.bind_target):
            # `t, _ = tarfile.open(p), 0` records t 'arch'; an unpairable target RESETS to 'other'.
            if isinstance(target, ast.Name):
                add(target.id, pos, kind_of(value, pos), cond)
            elif isinstance(target, (ast.Tuple, ast.List)) and isinstance(value, (ast.Tuple, ast.List)) \
                    and len(target.elts) == len(value.elts):
                for t_el, v_el in zip(target.elts, value.elts):
                    bind_target(t_el, v_el, pos, cond)
            else:
                for nm in _names_in_target(target):
                    add(nm, pos, "other", cond)

        def walk(node, cond):
            for n in ast.iter_child_nodes(node):
                pos = (getattr(n, "lineno", 0), getattr(n, "col_offset", 0))
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    add(n.name, pos, "other", cond)  # def/class REBINDS its name here -> reset
                    continue
                if isinstance(n, ast.Lambda):
                    continue                         # anonymous — binds no name in this scope
                if isinstance(n, (ast.With, ast.AsyncWith)):
                    for item in n.items:
                        ov = item.optional_vars
                        if isinstance(ov, ast.Name):
                            add(ov.id, pos, "arch" if is_opener(item.context_expr) else "other", cond)
                if NE is not None and isinstance(n, NE) and isinstance(n.target, ast.Name):
                    add(n.target.id, pos, kind_of(n.value, pos), cond)
                elif isinstance(n, ast.Assign):
                    for tgt in n.targets:
                        bind_target(tgt, n.value, pos, cond)
                elif isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name):
                    # `arch: T = tarfile.open(p)` records 'arch'; `arch: object = None` records the
                    # non-archive value (resets). A BARE `arch: object` (no value) is a NO-OP that
                    # preserves the prior provenance — lock-step with __file__ (round-6 CONFIRM sweep
                    # C23: a reset on a bare annotation was an AST011 FN regression).
                    if n.value is not None:
                        add(n.target.id, pos, kind_of(n.value, pos), cond)
                elif isinstance(n, ast.AugAssign) and isinstance(n.target, ast.Name):
                    add(n.target.id, pos, "other", cond)       # `t += x` -> not a provable archive (FP-3)
                elif isinstance(n, (ast.For, ast.AsyncFor)):
                    # a for-target over a seqarch is 'arch'; otherwise it RESETS with the LIVE cond —
                    # a top-level (unconditional) for-rebind masks an earlier archive, mirroring the
                    # #3 for-reset in the other three timelines (sweep FP-1; was hardcoded cond=True,
                    # so a top-level for never masked and leaked stale provenance).
                    if isinstance(n.target, ast.Name):
                        add(n.target.id, pos, "arch" if is_seqarch(n.iter, pos) else "other", cond)
                    else:
                        for nm in _names_in_target(n.target):
                            add(nm, pos, "other", cond)
                elif isinstance(n, (ast.Import, ast.ImportFrom)):
                    for bnd, _c in _import_canon(n):    # an import REBINDS to a MODULE (not an opened
                        add(bnd, pos, "other", cond)    # archive object) -> reset provenance (sibling D).
                child_cond = cond or isinstance(n, (ast.If, ast.For, ast.AsyncFor, ast.While,
                                                    ast.Try, ast.With, ast.AsyncWith))
                walk(n, child_cond)
        walk(scope_node, False)
        return binds

    def _self_target(self, node) -> bool:
        """The skill's own running file: inline `__file__`/`Path(__file__)` (walrus
        unwrapped), OR a Name resolving to it. Resolution is per-scope and POSITION-AWARE:
        the innermost scope that binds the name decides via its most-recent binding AS OF
        this node's line (so a write fires only while the name IS __file__, and a param or
        a rebind to a non-file value masks an outer __file__ binding)."""
        if _is_own_file_target(node, self._path_ctor_at):
            return True
        if isinstance(node, ast.Name):
            pos = (getattr(node, "lineno", 0), getattr(node, "col_offset", 0))
            if self._capture_masked(node.id, pos):
                return False                    # the name is an except/match capture here, not __file__
            for binds in reversed(self.scopes):
                if node.id in binds:
                    st = None
                    for bp, k in binds[node.id]:
                        if bp <= pos:
                            st = k
                    return st == "file"       # 'other'/'seqfile'/use-before-bind -> masked
        return False

    def visit_Module(self, node):
        # capture_scopes FIRST (depends only on the AST): _scope_alias_bindings reads it (via the
        # local head_is_capture) during construction. Then alias_scopes (read by _path_ctor_at /
        # _canon), then scopes/archive/method.
        self.capture_scopes.append(self._scope_captures(node))
        self.alias_scopes.append(self._scope_alias_bindings(node))
        self.scopes.append(self._scope_bindings(node, is_path_ctor=self._path_ctor_at, is_captured=self._capture_masked))
        self.archive_scopes.append(self._scope_archive_names(node))
        self.method_scopes.append(self._scope_method_refs(node))
        self.fact_scopes.append(self._scope_facts(node))         # round-9: parallel unified timeline
        self.generic_visit(node)
        self.alias_scopes.pop()
        self.capture_scopes.pop()
        self.scopes.pop()
        self.archive_scopes.pop()
        self.method_scopes.pop()
        self.fact_scopes.pop()

    def visit_FunctionDef(self, node):
        params = [a.arg for a in self._arg_names(node)]
        self.capture_scopes.append(self._scope_captures(node))   # before alias: builders read it
        self.alias_scopes.append(self._scope_alias_bindings(node, params))
        self.scopes.append(self._scope_bindings(node, params, self._path_ctor_at, self._capture_masked))
        self.archive_scopes.append(self._scope_archive_names(node))
        self.method_scopes.append(self._scope_method_refs(node))
        self.fact_scopes.append(self._scope_facts(node, params))  # round-9: parallel unified timeline
        self.generic_visit(node)
        self.alias_scopes.pop()
        self.capture_scopes.pop()
        self.scopes.pop()
        self.archive_scopes.pop()
        self.method_scopes.pop()
        self.fact_scopes.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    @staticmethod
    def _arg_names(fn):
        a = fn.args
        out = list(a.args) + list(getattr(a, "posonlyargs", []) or []) + list(a.kwonlyargs)
        if a.vararg:
            out.append(a.vararg)
        if a.kwarg:
            out.append(a.kwarg)
        return out

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
        name = self._func_canon(node.func,
                           (getattr(node.func, "lineno", 0), getattr(node.func, "col_offset", 0)))
        arg0 = node.args[0] if node.args else None

        # AST009 — skill rewrites its OWN running file at runtime (the write TARGET is
        # INLINE __file__ / Path(__file__), not a derived sibling). Reads and other-path
        # writes never fire. Covers builtin open / Path(__file__).open / write_text|
        # write_bytes / os.replace|rename + shutil.copy*|move (destination). A Name bound
        # to __file__ on a prior line is NOT tracked (Codex audit: the global binding set
        # was flow-insensitive and produced cross-function false AST009).
        # the FILE argument is read keyword-aware (`open(file=__file__)`, `os.open(path=…)`,
        # `os.truncate(path=…)`, `fileinput.input(files=…)` are valid Python the positional-only
        # check missed — round-7 audit), via _arg_or_kw; _self_target(None) is False.
        if (name in ("open", "io.open", "builtins.open") or name in self.open_aliases) \
                and self._self_target(_arg_or_kw(node, 0, "file")):
            # builtin open / io.open (io.open IS builtins.open) / an aliased open (Codex r3)
            if _write_mode(node, 1):
                self._add(node, "AST009", "HIGH",
                          "open(__file__, <write>) writes the skill's own running file — runtime self-modification defeats a pre-install audit (audited-once, mutates-later)")
        elif name == "os.open" and self._self_target(_arg_or_kw(node, 0, "path")) \
                and _os_open_writes(_arg_or_kw(node, 1, "flags")):
            # low-level os.open(__file__, O_WRONLY|O_TRUNC|…) + os.write — the POSIX-fd
            # form of a self-rewrite (Codex r3 sweep); flag at the writable open site.
            self._add(node, "AST009", "HIGH",
                      "os.open(__file__, <write flags>) opens the skill's own running file for writing — runtime self-modification (low-level POSIX form)")
        elif (isinstance(node.func, ast.Attribute) and node.func.attr == "open"
              and self._self_target(node.func.value) and _write_mode(node, 0)):
            self._add(node, "AST009", "HIGH",
                      "Path(__file__).open(<write>) writes the skill's own running file — runtime self-modification")
        elif (isinstance(node.func, ast.Attribute)
              and node.func.attr in ("write_text", "write_bytes")
              and self._self_target(node.func.value)):
            self._add(node, "AST009", "HIGH",
                      "." + node.func.attr + "(...) targets the skill's own file (__file__) — runtime self-modification")
        # NOTE: Path(__file__).rename/.replace(dst) is deliberately NOT flagged — like the
        # already-GREEN os.rename/os.replace(__file__, dst), __file__ there is the SOURCE moved
        # AWAY (a backup/relocation), not the inject TARGET. AST009 is scoped to CONTENT rewrite
        # of __file__ (DEST form); the source-move form stays out for consistency (round-6 sweep:
        # the path-rename/replace finding was a misclassification vs the existing os.rename rule).
        elif name == "os.truncate" and self._self_target(_arg_or_kw(node, 0, "path")):
            # os.truncate(__file__, 0) zero-outs the running file (path form; os.ftruncate is on
            # an fd and out of scope) — runtime self-modification (round-6 sweep AST009-truncate).
            self._add(node, "AST009", "HIGH",
                      "os.truncate(__file__, ...) truncates the skill's own running file — runtime self-modification")
        elif (name in ("fileinput.input", "fileinput.FileInput")
              and self._self_target(_arg_or_kw(node, 0, "files")) and _inplace_edit(node)):
            # fileinput with inplace=True redirects stdout INTO __file__, rewriting it in place —
            # the stdlib in-place-edit idiom turned on the running file (round-6 sweep AST009-fileinput).
            self._add(node, "AST009", "HIGH",
                      "fileinput.input(__file__, inplace=True) rewrites the skill's own running file in place — runtime self-modification")
        elif (name in ("os.replace", "os.rename", "os.symlink", "os.link", "shutil.copyfile",
                       "shutil.copy", "shutil.copy2", "shutil.move")
              and self._self_target(_arg_or_kw(node, 1, "dst"))):
            # destination = __file__ (positional arg1 OR `dst=` keyword): overwrite (replace/
            # rename/copy*/move) OR relink (symlink/link) the running file with attacker-chosen
            # content (round-6 sweep AST009-symlink; CONFIRM sweep D-1: the dst= keyword form leaked).
            self._add(node, "AST009", "HIGH",
                      name + "(..., __file__) overwrites/relinks the skill's own running file — runtime self-modification")

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
              or (self._func_attr(node.func) == "extractall"
                  and self._extractall_on_archive(node.func)
                  and not _extract_is_guarded(node))):
            # The extractall arm is gated on RECEIVER PROVENANCE (_extractall_on_archive):
            # it fires only when the receiver provably resolves to a tarfile/zipfile archive
            # (directly or through a method-ref). Keying on the bare `extractall` leaf alone
            # FP'd on the common pandas `Series.str.extractall` and any non-archive
            # `.extractall()` (convergence sweep gap 5) — and bare `.extract` was already
            # excluded for the same collision reason (pandas `.str.extract`, bs4). The
            # module-qualified `shutil.unpack_archive` is unambiguous, so it needs no gate.
            # An OPAQUE-receiver extractall (archive object from another fn/file) is OOS
            # (cross-function flow, THREAT_MODEL #4), as is single-member `.extract()`.
            self._add(node, "AST011", "MEDIUM",
                      "archive extractall / unpack_archive without a member filter — Zip-Slip "
                      "path traversal can overwrite files outside the target dir (e.g. ~/.ssh, ~/.claude)")

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


_DIFF_SINK = None   # round-9 migration: set to a list to collect old-vs-new resolver divergences


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

    # Pass 1 — alias maps: `x = eval`/`exec`/`compile` (dynamic-exec), `x = open`
    # (self-rewrite via an aliased builtin — AST009), and IMPORT aliases so a dotted-name
    # rule is not defeated by `import shutil as sh` / `from shutil import unpack_archive`
    # (a CLASS blind spot for every dotted AST rule — Codex r3).
    alias = {}
    open_aliases = set()
    import_modules = {}   # local alias -> real module:  `import shutil as sh` -> sh: shutil
    import_from = {}      # local name  -> module.leaf:   `from shutil import unpack_archive [as up]`
    star_modules = set()  # `from shutil import *` -> {shutil}  (star-import alias, gap 6)
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Name):
            if node.value.id in _CODE_EXEC_BUILTINS:
                for tgt in node.targets:
                    if isinstance(tgt, ast.Name):
                        alias[tgt.id] = node.value.id
            elif node.value.id == "open":
                for tgt in node.targets:
                    if isinstance(tgt, ast.Name):
                        open_aliases.add(tgt.id)
        elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Attribute) \
                and node.value.attr == "open" and isinstance(node.value.value, ast.Name) \
                and node.value.value.id == "io":
            for tgt in node.targets:                # open2 = io.open (io.open IS builtin open)
                if isinstance(tgt, ast.Name):
                    open_aliases.add(tgt.id)
        elif isinstance(node, ast.Import):
            for a in node.names:
                if a.asname:
                    import_modules[a.asname] = a.name
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            for a in node.names:
                if a.name == "*":
                    star_modules.add(node.module)        # `from <mod> import *` (gap 6)
                else:
                    import_from[a.asname or a.name] = node.module + "." + a.name

    def _resolve_import(nm):
        if nm in import_from:
            return import_from[nm]
        head, dot, rest = nm.partition(".")
        if dot and head in import_modules:
            return import_modules[head] + "." + rest
        if not dot and star_modules:
            for mod in star_modules:
                cand = mod + "." + nm
                if cand in _STAR_RESOLVABLE or cand in _ARCHIVE_OPENERS:
                    return cand
        return nm

    # ASSIGNMENT aliases of a callable — `mv = os.replace`, `PP = pathlib.Path`, the
    # transitive `b = a` — resolved through the import maps to a canonical name. The import
    # resolver already folds `import as`/`from … import`; an assignment binding is the
    # SIBLING form that defeated AST009's ctor/open/dest arms (convergence sweep round 4).
    # A fixpoint propagates transitive chains; recording every alias is harmless (only the
    # ones that resolve to a name a rule keys on ever fire).
    assign_pairs = []
    def_class_names = set()                      # names bound by def/class are functions/classes,
    for node in ast.walk(tree):                  # never callable aliases — dropped from the map below
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            def_class_names.add(node.name)
        if not isinstance(node, ast.Assign):
            continue
        rhs = None
        if isinstance(node.value, (ast.Name, ast.Attribute)):
            rhs = _dotted_name(node.value)              # X = os.replace / X = os
        elif isinstance(node.value, ast.Call) \
                and _dotted_name(node.value.func) == "getattr" \
                and len(node.value.args) >= 2 \
                and isinstance(node.value.args[1], ast.Constant) \
                and isinstance(node.value.args[1].value, str):
            base = _dotted_name(node.value.args[0])      # o = getattr(builtins, "open")
            rhs = base + "." + node.value.args[1].value if base else None
        if rhs:
            for tgt in node.targets:
                if isinstance(tgt, ast.Name):
                    assign_pairs.append((tgt.id, rhs))
    assign_aliases = {}
    for _ in range(8):                       # transitive fixpoint (b = a = os.replace)
        changed = False
        for lhs, rhs in assign_pairs:
            resolved = assign_aliases.get(rhs) or _resolve_import(rhs)
            if assign_aliases.get(lhs) != resolved:
                assign_aliases[lhs] = resolved
                changed = True
        if not changed:
            break
    for nm in def_class_names:
        assign_aliases.pop(nm, None)             # a def/class rebinds the name -> NOT a dangerous
                                                 # callable alias in the flow-insensitive global map
                                                 # (round-7 CONFIRM FP-1/FP-2: the per-scope def-reset
                                                 # was overridden cross-scope by this fallback -> a
                                                 # benign dispatch module read AST003/RED).

    # Pass 2 — detect. (The aliased pathlib.Path constructor is resolved POSITION-AWARELY by
    # the auditor's _path_ctor_at via the per-scope alias timeline, not a global set.)
    auditor = _AstAuditor(rel, text, alias, open_aliases, import_modules, import_from,
                          star_modules, assign_aliases)
    auditor._diff = _DIFF_SINK            # round-9: collect old-vs-new resolver divergences (dev)
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
        # 1) apply WALRUS binds FIRST — a walrus binds within the expression and is
        #    available to the rest of the SAME statement (left-to-right eval), so
        #    `(t := os.getenv("X")) and post(data=t)` must taint t before the sink in
        #    the same statement is scanned (round-4 audit: sink-before-walrus read GREEN).
        self._apply_walrus(stmt, tainted)
        # 2) sinks in this statement's OWN expressions (lambda bodies as fresh
        #    scopes; nested statement blocks are walked separately below)
        self._scan_sinks(stmt, tainted)
        # 3) seed / propagate taint from plain assignments (for SUBSEQUENT statements).
        self._apply_assign(stmt, tainted)
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
        # A comprehension is its OWN scope: each generator target is bound to an ELEMENT
        # of its iterable, so a tainted iter (`for v in os.environ.values()`) taints the
        # target, and the element expr is a sink context that must see it (Codex round 2:
        # `[post(url, data=v) for v in os.environ.values()]` read GREEN).
        comps = (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)
        if isinstance(node, comps):
            comp_tainted = set(tainted)
            for gen in node.generators:
                self._scan_sinks(gen.iter, comp_tainted)   # iter may itself hold a sink
                if _expr_has_taint(gen.iter, comp_tainted):
                    self._mark(gen.target, comp_tainted)
                for cond in gen.ifs:
                    self._scan_sinks(cond, comp_tainted)
            if isinstance(node, ast.DictComp):
                self._scan_sinks(node.key, comp_tainted)
                self._scan_sinks(node.value, comp_tainted)
            else:
                self._scan_sinks(node.elt, comp_tainted)
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
        with open(path, "rb") as f:
            chunk = f.read(8192)   # bounded read — read_bytes()[:8192] loaded the WHOLE
                                   # file first (memory DoS on a giant blob — Codex audit)
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

    # Explicit bounded walk (NOT rglob, which traverses skip_dirs before filtering and
    # has no node bound — a tree of empty dirs hung the scan, Codex r3 re-sweep). Prune
    # skip_dirs at the directory level and cap total nodes visited.
    MAX_NODES = 100000
    nodes = 0
    truncated = False
    stack = [skill_root]
    while stack:
        d = stack.pop()
        nodes += 1
        if nodes > MAX_NODES:
            truncated = True
            break
        try:
            entries = sorted(d.iterdir())
        except OSError:
            continue
        for p in entries:
            nodes += 1
            if nodes > MAX_NODES:
                truncated = True
                break
            # Check symlink BEFORE is_dir()/is_file(): a symlink to a directory
            # is not descended (and is noted), avoiding loops.
            if p.is_symlink():
                other_files.append(p.relative_to(skill_root).as_posix() + "  (SYMLINK)")
                continue
            if p.is_dir():
                if p.name not in skip_dirs:
                    stack.append(p)
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
        "truncated": truncated,
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

    if inv.get("truncated"):
        # The inventory walk hit its node cap — files past the cap (a hidden exec binary,
        # symlink, or script) were NOT classified or scanned. FAIL LOUD, never silently
        # GREEN, mirroring the supply-walk truncation posture (convergence round-4 audit).
        findings.append(Finding(
            severity="HIGH", rule_id="IO004", file="", line=0, snippet="<tree truncated>",
            why=("the skill's directory tree is too large to fully inventory (node cap) — "
                 "files beyond the cap were not classified or scanned; a binary, symlink, or "
                 "script could be hidden in the un-walked remainder. Inspect the tree by hand."),
            suggested_fix="A skill should be a handful of text files; a >100k-node tree is itself a red flag."))

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
