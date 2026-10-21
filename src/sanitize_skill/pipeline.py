import json
import re

from sanitize_skill import __version__
from sanitize_skill.classify import classify_text
from sanitize_skill.homoglyphs import scan_homoglyphs
from sanitize_skill.html_clean import extract_html, homoglyph_hook as html_homoglyphs
from sanitize_skill.models import INSTRUCTION, Extract, Result, SanitizeError
from sanitize_skill.office_clean import extract_office, homoglyph_hook as office_homoglyphs
from sanitize_skill.patterns import scan_patterns, sentence_flagged
from sanitize_skill.pdf_clean import extract_pdf, homoglyph_hook as pdf_homoglyphs
from sanitize_skill.textutil import make_finding, sha256_bytes, sha256_text, shield_markers, split_sentences
from sanitize_skill.unicode_norm import normalize


def sanitize_bytes(
    data: bytes,
    *,
    filename: str = "input",
    content_type: str | None = None,
    level: int = 2,
    source_kind: str = "file",
    locator: str = "",
) -> Result:
    if level not in range(5):
        raise SanitizeError("level must be 0..4")
    _reject_unsupported(data)
    kind, extract = _extract(data, filename=filename, content_type=content_type)
    return _finish(
        data,
        extract,
        kind=kind,
        level=level,
        source_kind=source_kind,
        locator=locator or filename,
    )


def sanitize_text(text: str, *, level: int = 2, locator: str = "pasted-text") -> Result:
    data = text.encode("utf-8")
    extract = Extract(visible=text)
    return _finish(data, extract, kind="text", level=level, source_kind="text", locator=locator)


def _homoglyph_hook(kind: str):
    return {
        "html": html_homoglyphs,
        "pdf": pdf_homoglyphs,
        "docx": office_homoglyphs,
        "xlsx": office_homoglyphs,
        "pptx": office_homoglyphs,
    }.get(kind, scan_homoglyphs)


def _extract(data: bytes, *, filename: str, content_type: str | None) -> tuple[str, Extract]:
    if data.startswith(b"%PDF"):
        return "pdf", extract_pdf(data)
    if data[:2] == b"PK":
        return extract_office(data)
    if _looks_html(data, filename, content_type):
        return "html", extract_html(data)
    return "text", Extract(visible=_decode_text(data))


def _finish(data, extract: Extract, *, kind: str, level: int, source_kind: str, locator: str) -> Result:
    text = extract.visible
    auxiliary = {key: value for key, value in extract.auxiliary.items() if value}
    findings = list(extract.findings)
    unicode_normalized = False
    if level >= 1:
        text, text_findings = normalize(text)
        findings.extend(text_findings)
        normalized_aux = {}
        for key, value in auxiliary.items():
            cleaned, aux_findings = normalize(value)
            normalized_aux[key] = cleaned
            findings.extend(aux_findings)
        auxiliary = normalized_aux
        unicode_normalized = any(item["category"].startswith("unicode_") for item in findings)
    if level >= 2:
        findings.extend(scan_patterns(text))
        for value in auxiliary.values():
            findings.extend(scan_patterns(value))
        for side in extract.side_text:
            findings.extend(scan_patterns(side))
        findings.extend(_scan_excerpts(findings))
        hook = _homoglyph_hook(kind)
        for blob in (text, *auxiliary.values(), *extract.side_text):
            findings.extend(hook(blob))
    classifier = {"status": "not_requested"}
    if level >= 3:
        classifier = classify_text(text)
        if _classifier_hit(classifier):
            label = classifier.get("label") or ""
            message = "Classifier mark stored in evidence only."
            if re.fullmatch(r"[A-Za-z0-9_.: -]{1,40}", label):
                message = f"Classifier mark stored in evidence only ({label})."
            findings.append(make_finding("classifier", "mark", message))
    strict_cut = False
    if level >= 4:
        text, cuts = _cut(text)
        if cuts:
            findings.extend(cuts)
            strict_cut = True
    findings = _dedupe(findings)[:40]
    digest = sha256_bytes(data)
    mismatch = any(item["severity"] == "mismatch" for item in findings)
    marked = any(item["severity"] == "mark" for item in findings)
    if mismatch:
        verdict = "hidden_mismatch"
    elif marked:
        verdict = "marked"
    else:
        verdict = "clean"
    flags = {
        "hidden_withheld": mismatch,
        "unicode_normalized": unicode_normalized,
        "render_unverified": extract.render_unverified,
        "strict_cut": strict_cut,
    }
    source = {
        "kind": source_kind,
        "format": kind,
        "locator": locator,
        "sha256": digest,
    }
    model = {
        "tool_version": __version__,
        "level": level,
        "source": source,
        "instruction": INSTRUCTION,
        "visible_text": text,
        "visible_sha256": sha256_text(text),
        "auxiliary": auxiliary,
        "spotlight": _spotlight(text, auxiliary, locator, digest),
        "flags": flags,
    }
    evidence = {
        "tool_version": __version__,
        "level": level,
        "source": source,
        "verdict": verdict,
        "findings": findings,
        "infos": extract.infos,
        "classifier": classifier,
        "journal": "not_applicable",
        "quarantine_sha256": None,
    }
    return Result(raw=data, sha256=digest, model=model, evidence=evidence)


def _classifier_hit(result: dict) -> bool:
    if result.get("status") != "ok":
        return False
    score = result.get("score")
    if isinstance(score, (int, float)) and not isinstance(score, bool) and score >= 0.5:
        return True
    label = str(result.get("label") or "").casefold()
    return any(word in label for word in ("inject", "jailbreak", "malicious"))


def _scan_excerpts(findings: list[dict]) -> list[dict]:
    extra = []
    for item in list(findings):
        if item["severity"] == "mismatch" and item.get("excerpt"):
            extra.extend(scan_patterns(item["excerpt"]))
    return extra


def _cut(text: str) -> tuple[str, list[dict]]:
    kept = []
    cuts = []
    for sentence in split_sentences(text):
        if sentence_flagged(sentence):
            cuts.append(
                make_finding(
                    "strict_cut",
                    "mark",
                    "Level 4 removed a visible sentence that matched a heuristic.",
                    sentence,
                )
            )
        else:
            kept.append(sentence)
    return "\n".join(kept).strip(), cuts


def _spotlight(text: str, auxiliary: dict[str, str], locator: str, digest: str) -> str:
    blocks = [text]
    for key, value in auxiliary.items():
        blocks.append(f"[{key}]\n{value}")
    body = shield_markers("\n\n".join(blocks))
    return (
        f"<<<UNTRUSTED_DATA source={json.dumps(locator, ensure_ascii=False)} sha256={digest}>>>\n"
        f"{body}\n<<<END_UNTRUSTED_DATA>>>"
    )


def _dedupe(findings: list[dict]) -> list[dict]:
    seen = set()
    unique = []
    for item in findings:
        key = (item["category"], item["severity"], item.get("excerpt", ""))
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique


def _reject_unsupported(data: bytes) -> None:
    if data.startswith((b"\x89PNG", b"\xff\xd8\xff", b"GIF87a", b"GIF89a")):
        raise SanitizeError("image files are not extracted; text baked into pixels is out of scope")
    if data.startswith(b"RIFF") and b"WEBP" in data[:16]:
        raise SanitizeError("image files are not extracted; text baked into pixels is out of scope")
    if data.startswith(b"\xd0\xcf\x11\xe0"):
        raise SanitizeError("legacy office .doc/.xls is not supported; save as docx or xlsx")


def _looks_html(data: bytes, filename: str, content_type: str | None) -> bool:
    if content_type and "html" in content_type.lower():
        return True
    if filename.lower().endswith((".html", ".htm")):
        return True
    sample = data.lstrip()[:400].lower()
    return sample.startswith((b"<!doctype html", b"<html", b"<head", b"<body")) or b"<div" in sample or b"<p" in sample or b"<style" in sample


def _decode_text(data: bytes) -> str:
    if b"\x00" in data[:4096]:
        raise SanitizeError("unsupported binary file")
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16")
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise SanitizeError("file is not valid utf-8 text") from exc
