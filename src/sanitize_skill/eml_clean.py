"""Read an .eml message: body plus each attachment through its own extractor."""

from email import policy
from email.parser import BytesParser

from sanitize_skill.html_clean import extract_html
from sanitize_skill.models import Extract, SanitizeError
from sanitize_skill.office_clean import extract_office
from sanitize_skill.pdf_clean import extract_pdf
from sanitize_skill.textutil import cleanup_visible, make_info


def extract_eml(data: bytes) -> Extract:
    message = BytesParser(policy=policy.default).parsebytes(data)
    visible_parts: list[str] = []
    findings: list[dict] = []
    infos: list[dict] = []
    side: list[str] = []
    properties: list[str] = []
    unverified = False
    subject = message.get("subject")
    if subject and str(subject).strip():
        properties.append(str(subject).strip())
    for part in message.walk():
        if part.is_multipart():
            continue
        raw = part.get_payload(decode=True)
        payload = raw if isinstance(raw, bytes) else b""
        filename = part.get_filename() or ""
        disposition = (part.get_content_disposition() or "").lower()
        if disposition == "attachment" or filename:
            label, sub = _attachment(payload, filename, part.get_content_type())
            if isinstance(sub, str):
                infos.append(make_info("eml_attachment_skipped", sub))
                continue
            if sub.visible:
                visible_parts.append(f"# {label}\n{sub.visible}")
            findings.extend(sub.findings)
            infos.extend(sub.infos)
            side.extend(sub.side_text)
            properties.extend(sub.properties)
            unverified = unverified or sub.render_unverified
            continue
        if part.get_content_type() == "text/html":
            sub = extract_html(payload)
            if sub.visible:
                visible_parts.append(sub.visible)
            findings.extend(sub.findings)
            side.extend(sub.side_text)
            properties.extend(sub.properties)
            continue
        if part.get_content_maintype() == "text":
            charset = part.get_content_charset() or "utf-8"
            visible_parts.append(payload.decode(charset, "replace"))
    return Extract(
        visible=cleanup_visible(visible_parts),
        findings=findings,
        infos=infos,
        side_text=side,
        properties=properties,
        render_unverified=unverified,
    )


def _attachment(payload: bytes, filename: str, content_type: str) -> tuple[str, Extract | str]:
    name = filename or "attachment"
    try:
        if payload.startswith(b"%PDF") or name.lower().endswith(".pdf"):
            return name, extract_pdf(payload)
        if payload[:2] == b"PK" or name.lower().endswith((".docx", ".xlsx", ".pptx")):
            _kind, extract = extract_office(payload)
            return name, extract
        if content_type == "text/html" or name.lower().endswith((".html", ".htm")):
            return name, extract_html(payload)
        if content_type.startswith("text/") or name.lower().endswith(".txt"):
            return name, Extract(visible=payload.decode("utf-8", "replace"))
    except SanitizeError as exc:
        return name, str(exc)
    return name, "attachment format is not extracted"
