"""Skeleton matches for Unicode confusables (UTS #39). Marks only, never cuts text."""

import json
import unicodedata
from functools import lru_cache
from pathlib import Path

from sanitize_skill.patterns import has_signal, pattern_spans
from sanitize_skill.textutil import make_finding

_DATA = Path(__file__).with_name("confusables.json")


@lru_cache(maxsize=1)
def prototypes() -> dict[str, str]:
    """Single-character prototypes from Unicode confusables.txt 15.1.0."""
    return json.loads(_DATA.read_text(encoding="utf-8"))


def skeleton_indexed(text: str) -> tuple[str, list[int]]:
    table = prototypes()
    chars: list[str] = []
    indexes: list[int] = []
    for index, char in enumerate(text):
        mapped = "".join(table.get(piece, piece) for piece in unicodedata.normalize("NFD", char))
        for piece in unicodedata.normalize("NFD", mapped):
            chars.append(piece)
            indexes.append(index)
    return "".join(chars), indexes


def scan_homoglyphs(text: str) -> list[dict]:
    """Mark a heuristic that appears only after confusable normalization."""
    if not text:
        return []
    skeleton, indexes = skeleton_indexed(text)
    if skeleton == text:
        return []
    findings = []
    seen: set[tuple[str, str]] = set()
    for category, start, end in pattern_spans(skeleton):
        if start >= len(indexes) or end <= start:
            continue
        original = text[indexes[start] : indexes[end - 1] + 1]
        normalized = skeleton[start:end]
        if not original or original == normalized or has_signal(original):
            continue
        key = (category, original)
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            make_finding(
                "homoglyph",
                "mark",
                f"Confusable characters match {category}; visible text was not removed.",
                original,
            )
        )
        if len(findings) >= 20:
            break
    return findings
