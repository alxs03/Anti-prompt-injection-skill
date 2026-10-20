import hashlib
import re


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def loose(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def alnum_count(text: str) -> int:
    return sum(ch.isalnum() for ch in text)


def excerpt(text: str, limit: int = 400) -> str:
    cleaned = loose(text)
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[: limit - 1] + "…"


def make_finding(category: str, severity: str, message: str, hidden: str = "") -> dict:
    return {
        "category": category,
        "severity": severity,
        "message": message,
        "excerpt": excerpt(hidden) if hidden else "",
    }


def make_info(category: str, message: str) -> dict:
    return {"category": category, "message": message}


def already_visible(hidden: str, visible: str) -> bool:
    needle = loose(hidden).casefold()
    haystack = loose(visible).casefold()
    if not needle:
        return True
    return needle in haystack


def worthy(text: str, signal: bool) -> bool:
    return alnum_count(text) >= 8 or signal


def coalesce(chunks: list[tuple[str, str]]) -> list[tuple[str, str]]:
    merged: list[tuple[str, str]] = []
    for text, category in chunks:
        if not text or not text.strip():
            continue
        if merged and merged[-1][1] == category:
            merged[-1] = (merged[-1][0] + "\n" + text, category)
        else:
            merged.append((text, category))
    return merged


def findings_from_hidden(
    chunks: list[tuple[str, str]],
    visible: str,
    signal,
) -> list[dict]:
    findings = []
    for text, category in coalesce(chunks):
        if already_visible(text, visible):
            continue
        if not worthy(text, signal(text)):
            continue
        findings.append(
            make_finding(
                category,
                "mismatch",
                "Hidden text was withheld from the model.",
                text,
            )
        )
    return findings


def cleanup_visible(parts: list[str]) -> str:
    text = "".join(parts)
    text = text.replace("\u00a0", " ").replace("\u202f", " ").replace("\u2007", " ")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"[ \t]+\n", "\n", text)
    text = re.sub(r"[ \t]{2,}", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def split_sentences(text: str) -> list[str]:
    parts = re.split(r"(?<=[.!?。])\s+|\n+", text)
    return [part.strip() for part in parts if part and part.strip()]


def shield_markers(text: str) -> str:
    return text.replace("<<<", "‹‹‹")
