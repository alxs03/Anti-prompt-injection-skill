import re

from sanitize_skill.textutil import make_finding

# Phrase lists are ours. Categories follow the public ClawDefender grouping
# (instruction override, credential theft, exfiltration, SSRF), not its script.

_RULES: list[tuple[str, str]] = [
    (
        "instruction_override",
        r"ignore\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|preceding)\s+instructions",
    ),
    (
        "instruction_override",
        r"disregard\s+(?:all\s+|any\s+|the\s+)?(?:previous\s+|prior\s+)?(?:instructions|rules|guidelines)",
    ),
    (
        "instruction_override",
        r"forget\s+(?:all\s+|your\s+|previous\s+|prior\s+)+(?:instructions|rules)",
    ),
    (
        "instruction_override",
        r"override\s+(?:the\s+)?(?:system|developer)\s+(?:prompt|message|instructions)",
    ),
    (
        "instruction_override",
        r"you\s+are\s+now\s+(?:a|an)\b",
    ),
    (
        "instruction_override",
        r"new\s+(?:system\s+)?instructions\s*:",
    ),
    (
        "instruction_override",
        r"do\s+not\s+(?:tell|inform|mention)\s+(?:this\s+to\s+)?the\s+(?:user|human)",
    ),
    (
        "instruction_override",
        r"reveal\s+(?:your\s+)?(?:hidden\s+|system\s+)?prompt",
    ),
    (
        "instruction_override",
        r"игнорир\w*\s+предыдущ\w*\s+инструкц",
    ),
    (
        "instruction_override",
        r"забудь\s+(?:все\s+|предыдущие\s+)?инструкц",
    ),
    (
        "instruction_override",
        r"не\s+сообщай\s+(?:об\s+этом\s+)?пользовател",
    ),
    (
        "instruction_override",
        r"системн\w+\s+промпт",
    ),
    (
        "credential_theft",
        r"(?:send|email|exfiltrate|paste|отправь|перешли|вышли).{0,48}(?:password|passwd|secret|token|api\s*key|парол)",
    ),
    (
        "credential_theft",
        r"(?:password|passwd|api\s*key|парол\w*).{0,32}(?:to\s+\S+@|на\s+\S+@)",
    ),
    (
        "credential_theft",
        r"\b\.env\b",
    ),
    (
        "credential_theft",
        r"\.ssh[/\\]",
    ),
    (
        "credential_theft",
        r"\bid_rsa\b",
    ),
    (
        "credential_theft",
        r"BEGIN\s+(?:RSA\s+|OPENSSH\s+)?PRIVATE\s+KEY",
    ),
    (
        "exfiltration",
        r"webhook\.site",
    ),
    (
        "exfiltration",
        r"requestbin(?:\.com)?",
    ),
    (
        "exfiltration",
        r"burpcollaborator",
    ),
    (
        "exfiltration",
        r"interact\.sh",
    ),
    (
        "exfiltration",
        r"oast\.(?:pro|fun|me|online|live)",
    ),
    (
        "exfiltration",
        r"ngrok\.io",
    ),
    (
        "exfiltration",
        r"pipedream\.net",
    ),
    (
        "exfiltration",
        r"canarytokens",
    ),
    (
        "exfiltration",
        r"discord\.com/api/webhooks",
    ),
    (
        "exfiltration",
        r"hooks\.slack\.com",
    ),
    (
        "ssrf",
        r"169\.254\.169\.254",
    ),
    (
        "ssrf",
        r"metadata\.google\.internal",
    ),
    (
        "ssrf",
        r"https?://(?:127\.|localhost\b|10\.\d|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)",
    ),
    (
        "ssrf",
        r"file://",
    ),
]

_COMPILED = [(name, re.compile(pattern, re.IGNORECASE)) for name, pattern in _RULES]
_LATIN = re.compile(r"[A-Za-z]")
_CYRILLIC = re.compile(r"[А-Яа-яЁё]")
_GREEK = re.compile(r"[\u0370-\u03FF]")


def has_signal(text: str) -> bool:
    return any(pattern.search(text) for _, pattern in _COMPILED)


def sentence_flagged(text: str) -> bool:
    return has_signal(text)


def _mixed_script_tokens(text: str) -> list[str]:
    found: list[str] = []
    for token in re.findall(r"\w{4,}", text, flags=re.UNICODE):
        scripts = 0
        if _LATIN.search(token):
            scripts += 1
        if _CYRILLIC.search(token):
            scripts += 1
        if _GREEK.search(token):
            scripts += 1
        if scripts >= 2:
            found.append(token)
            if len(found) >= 20:
                break
    return found


def scan_patterns(text: str) -> list[dict]:
    findings: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for category, pattern in _COMPILED:
        for match in pattern.finditer(text):
            snippet = match.group(0)
            key = (category, snippet.casefold())
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                make_finding(
                    "pattern_" + category,
                    "mark",
                    "Visible text matched a heuristic; it was not removed.",
                    snippet,
                )
            )
            if len(findings) >= 30:
                return findings
    for token in _mixed_script_tokens(text):
        findings.append(
            make_finding(
                "pattern_mixed_script",
                "mark",
                "A token mixes scripts; it was not removed.",
                token,
            )
        )
        if len(findings) >= 40:
            break
    return findings
