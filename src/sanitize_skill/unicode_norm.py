from sanitize_skill.patterns import has_signal
from sanitize_skill.textutil import make_finding, worthy

# U+202A..U+202E and U+2066..U+2069, plus the zero-width set from the design note.
_BIDI = {chr(code) for code in range(0x202A, 0x202F)} | {chr(code) for code in range(0x2066, 0x206A)}
_ZERO_WIDTH = {"\u200b", "\u200c", "\u2060", "\u180e", "\ufeff", "\u00ad"}


def _is_emoji(char: str) -> bool:
    code = ord(char)
    return (
        0x1F300 <= code <= 0x1FAFF
        or 0x2600 <= code <= 0x27BF
        or 0x1F1E6 <= code <= 0x1F1FF
        or code in {0x2764, 0x203C, 0x2049, 0x2122, 0x2139, 0x2194, 0x2195, 0x2196, 0x2197, 0x2198, 0x2199, 0x21A9, 0x21AA, 0x231A, 0x231B, 0x2328, 0x23CF, 0x23E9, 0x23EA, 0x23EB, 0x23EC, 0x23ED, 0x23EE, 0x23EF, 0x23F0, 0x23F1, 0x23F2, 0x23F3, 0x23F8, 0x23F9, 0x23FA, 0x24C2, 0x25AA, 0x25AB, 0x25B6, 0x25C0, 0x25FB, 0x25FC, 0x25FD, 0x25FE, 0x2600, 0x2614, 0x2615, 0x2648, 0x267F, 0x2693, 0x26A1, 0x26AA, 0x26AB, 0x26BD, 0x26BE, 0x26C4, 0x26C5, 0x26CE, 0x26D4, 0x26EA, 0x26F2, 0x26F3, 0x26F5, 0x26FA, 0x26FD, 0x2705, 0x270A, 0x270B, 0x2728, 0x274C, 0x274E, 0x2753, 0x2754, 0x2755, 0x2757, 0x2795, 0x2796, 0x2797, 0x27B0, 0x27BF, 0x2B1B, 0x2B1C, 0x2B50, 0x2B55}
    )


def _is_variation(char: str) -> bool:
    code = ord(char)
    return 0xFE00 <= code <= 0xFE0F or 0xE0100 <= code <= 0xE01EF


def _is_tag(char: str) -> bool:
    return 0xE0000 <= ord(char) <= 0xE007F


def _neighbor_emoji(text: str, index: int, step: int) -> bool:
    cursor = index + step
    while 0 <= cursor < len(text) and (_is_variation(text[cursor]) or text[cursor] == "\u200d"):
        cursor += step
    return 0 <= cursor < len(text) and _is_emoji(text[cursor])


def decode_tags(text: str) -> str:
    decoded = []
    for char in text:
        code = ord(char)
        if 0xE0020 <= code <= 0xE007E:
            decoded.append(chr(code - 0xE0000))
    return "".join(decoded)


def normalize(text: str) -> tuple[str, list[dict]]:
    """Strip invisible controls. Tag payloads that carry a message are mismatches."""
    decoded = decode_tags(text).strip()
    kept: list[str] = []
    counts = {"zero_width": 0, "bidi": 0, "variation": 0, "tag": 0, "zwj": 0}
    for index, char in enumerate(text):
        if _is_tag(char):
            counts["tag"] += 1
            continue
        if char in _BIDI:
            counts["bidi"] += 1
            continue
        if char in _ZERO_WIDTH:
            counts["zero_width"] += 1
            continue
        if char == "\u200d":
            if _neighbor_emoji(text, index, -1) and _neighbor_emoji(text, index, 1):
                kept.append(char)
            else:
                counts["zwj"] += 1
            continue
        if _is_variation(char):
            if _neighbor_emoji(text, index, -1):
                kept.append(char)
            else:
                counts["variation"] += 1
            continue
        kept.append(char)

    findings: list[dict] = []
    if decoded and worthy(decoded, has_signal(decoded)):
        findings.append(
            make_finding(
                "unicode_tag",
                "mismatch",
                "Unicode tag characters encoded text that is not on the page.",
                decoded,
            )
        )
    elif counts["tag"]:
        findings.append(
            make_finding(
                "unicode_tag",
                "mark",
                f"Removed {counts['tag']} Unicode tag characters.",
            )
        )
    removed = counts["zero_width"] + counts["bidi"] + counts["variation"] + counts["zwj"]
    if removed:
        detail = ", ".join(f"{name}={count}" for name, count in counts.items() if count and name != "tag")
        findings.append(
            make_finding(
                "unicode_format",
                "mark",
                f"Removed invisible formatting characters ({detail}).",
            )
        )
    return "".join(kept), findings
