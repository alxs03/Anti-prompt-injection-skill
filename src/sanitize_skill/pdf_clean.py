import math
import shutil
import subprocess
import tempfile
from pathlib import Path

import pymupdf

from sanitize_skill.models import Extract, SanitizeError
from sanitize_skill.patterns import has_signal
from sanitize_skill.textutil import cleanup_visible, findings_from_hidden, make_info

_MAX_PAGES = 200
_CONTRAST = 0.18


def extract_pdf(data: bytes) -> Extract:
    try:
        document = pymupdf.open(stream=data, filetype="pdf")
    except Exception as exc:
        raise SanitizeError("could not read pdf") from exc
    try:
        if document.needs_pass:
            raise SanitizeError("encrypted pdf is not supported")
        hidden_layers = _hidden_layers(document)
        visible_parts: list[str] = []
        hidden: list[tuple[str, str]] = []
        infos = []
        unverified = False
        page_count = min(document.page_count, _MAX_PAGES)
        if document.page_count > _MAX_PAGES:
            infos.append(make_info("pdf_truncated", f"Only the first {_MAX_PAGES} pages were read."))
        for index in range(page_count):
            page_text, page_hidden, page_unverified = _page(document[index], hidden_layers)
            if page_text:
                visible_parts.append(page_text)
            hidden.extend(page_hidden)
            unverified = unverified or page_unverified
        if unverified:
            infos.append(
                make_info(
                    "render_compare_skipped",
                    "An invisible text layer was kept because it is the only text and was not compared to the rendered page.",
                )
            )
        visible = cleanup_visible(visible_parts)
        return Extract(
            visible=visible,
            findings=findings_from_hidden(hidden, visible, has_signal),
            infos=infos,
            render_unverified=unverified,
        )
    finally:
        document.close()


def _hidden_layers(document) -> set[str]:
    names: set[str] = set()
    try:
        groups = document.get_ocgs() or {}
    except Exception:
        return names
    for info in groups.values():
        if isinstance(info, dict) and not info.get("on", True) and info.get("name"):
            names.add(str(info["name"]))
    return names


def _page(page, hidden_layers: set[str]) -> tuple[str, list[tuple[str, str]], bool]:
    try:
        spans = page.get_texttrace() or []
    except Exception as exc:
        raise SanitizeError("could not read pdf text") from exc
    painted: list[tuple[float, float, float, str]] = []
    ocr_layer: list[tuple[float, float, float, str]] = []
    hidden: list[tuple[str, str]] = []
    for span in spans:
        text = _span_text(span).strip()
        if not text:
            continue
        reasons = _reasons(page, span, hidden_layers)
        if reasons == ["pdf_render_mode_3"]:
            ocr_layer.append(_item(span, text))
        elif not reasons:
            painted.append(_item(span, text))
        else:
            hidden.append((text, reasons[0]))
    painted_text = _join(painted)
    if painted:
        for item in ocr_layer:
            hidden.append((item[3], "pdf_render_mode_3"))
        return painted_text, hidden, False
    if not ocr_layer:
        return "", hidden, False
    ocr_text = _join(ocr_layer)
    extras = _ocr_extras(page, ocr_text)
    if extras is None:
        return ocr_text, hidden, True
    if not extras:
        return ocr_text, hidden, False
    kept = _without_sentences(ocr_text, extras)
    for extra in extras:
        hidden.append((extra, "pdf_render_mode_3"))
    return kept, hidden, False


class _PixmapCache:
    def __init__(self, page):
        self.page = page
        self.pix = None

    def get(self):
        if self.pix is None:
            self.pix = self.page.get_pixmap(alpha=False, colorspace=pymupdf.csRGB)
        return self.pix


def _reasons(page, span, hidden_layers: set[str]) -> list[str]:
    reasons: list[str] = []
    render_type = int(span.get("type") or 0)
    if render_type in {3, 7}:
        reasons.append(f"pdf_render_mode_{render_type}")
    bbox = span.get("bbox") or (0, 0, 0, 0)
    if not _on_page(bbox, page.rect):
        reasons.append("pdf_off_page")
    if float(span.get("size") or 12) < 1.5:
        reasons.append("pdf_tiny")
    if float(span.get("opacity") or 1) <= 0.05:
        reasons.append("pdf_transparent")
    layer = span.get("layer") or ""
    if layer and layer in hidden_layers:
        reasons.append("pdf_hidden_layer")
    if render_type not in {3, 7} and "pdf_off_page" not in reasons:
        color = _as_rgb(span.get("color"), span.get("colorspace"))
        if color is not None and _low_contrast(color, _background(page, bbox)):
            reasons.append("pdf_low_contrast")
    return reasons


def _background(page, bbox) -> tuple[float, float, float]:
    cache = getattr(page, "_sanitize_pix", None)
    if cache is None:
        cache = _PixmapCache(page)
        setattr(page, "_sanitize_pix", cache)
    pix = cache.get()
    x0, y0, x1, y1 = bbox
    mid_y = (y0 + y1) / 2
    for x, y in ((x0 - 3, mid_y), (x1 + 3, mid_y), ((x0 + x1) / 2, y0 - 3)):
        if not _on_page((x, y, x + 0.1, y + 0.1), page.rect):
            continue
        px, py = int(x), int(y)
        if px < 0 or py < 0 or px >= pix.width or py >= pix.height:
            continue
        sampled = pix.pixel(px, py)
        if sampled:
            red, green, blue = sampled[:3]
            return (red / 255, green / 255, blue / 255)
    return (1.0, 1.0, 1.0)


def _on_page(bbox, rect) -> bool:
    x0, y0, x1, y1 = bbox
    return x1 > rect.x0 and x0 < rect.x1 and y1 > rect.y0 and y0 < rect.y1


def _as_rgb(color, _colorspace) -> tuple[float, float, float] | None:
    if color is None:
        return None
    if isinstance(color, (int, float)) and not isinstance(color, bool):
        if isinstance(color, int) and color > 1:
            return (((color >> 16) & 255) / 255, ((color >> 8) & 255) / 255, (color & 255) / 255)
        gray = float(color)
        return (gray, gray, gray)
    if isinstance(color, (list, tuple)):
        if len(color) == 1:
            gray = float(color[0])
            return (gray, gray, gray)
        if len(color) >= 3:
            return (float(color[0]), float(color[1]), float(color[2]))
    return None


def _low_contrast(text_rgb, bg_rgb) -> bool:
    return math.dist(text_rgb, bg_rgb) < _CONTRAST


def _item(span, text: str) -> tuple[float, float, float, str]:
    bbox = span.get("bbox") or (0, 0, 0, 0)
    return (float(bbox[1]), float(bbox[0]), float(span.get("size") or 12), text)


def _join(items: list[tuple[float, float, float, str]]) -> str:
    if not items:
        return ""
    ordered = sorted(items, key=lambda item: (item[0], item[1]))
    lines: list[str] = []
    buffer: list[str] = []
    current_y = None
    current_size = 12.0
    for y, _x, size, text in ordered:
        if current_y is None or abs(y - current_y) <= max(2.0, current_size * 0.6):
            buffer.append(text)
            current_y = y if current_y is None else current_y
            current_size = size
        else:
            lines.append(" ".join(buffer))
            buffer = [text]
            current_y = y
            current_size = size
    if buffer:
        lines.append(" ".join(buffer))
    return "\n".join(lines)


def _span_text(span: dict) -> str:
    chars = []
    for char in span.get("chars") or []:
        if isinstance(char, str):
            chars.append(char)
            continue
        if not char:
            continue
        first = char[0]
        chars.append(first if isinstance(first, str) else chr(first))
    return "".join(chars)


def _ocr_extras(page, ocr_text: str) -> list[str] | None:
    executable = shutil.which("tesseract")
    if not executable:
        return None
    try:
        pixmap = page.get_pixmap(dpi=150, alpha=False)
        with tempfile.TemporaryDirectory() as folder:
            image = Path(folder) / "page.png"
            image.write_bytes(pixmap.tobytes("png"))
            completed = subprocess.run(
                [executable, str(image), "stdout", "-l", "eng+rus"],
                check=False,
                capture_output=True,
                timeout=60,
            )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    recognized = completed.stdout.decode("utf-8", "replace")
    if sum(char.isalnum() for char in recognized) < 20:
        return None
    return _extra_sentences(ocr_text, recognized)


def _extra_sentences(candidate: str, basis: str) -> list[str]:
    base = " ".join(basis.split()).casefold()
    extras = []
    for sentence in _sentences(candidate):
        folded = " ".join(sentence.split()).casefold()
        if folded and folded not in base:
            extras.append(sentence)
    return extras


def _sentences(text: str) -> list[str]:
    parts = []
    for line in text.splitlines():
        line = line.strip()
        if line:
            parts.append(line)
    return parts


def _without_sentences(text: str, extras: list[str]) -> str:
    drop = {" ".join(item.split()) for item in extras}
    kept = [line for line in text.splitlines() if " ".join(line.split()) not in drop]
    return "\n".join(kept).strip()
