import json
import math
import re
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


def homoglyph_hook(text: str) -> list[dict]:
    from sanitize_skill.homoglyphs import scan_homoglyphs

    return scan_homoglyphs(text)


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
            page = document[index]
            page_text, page_hidden, page_unverified = _page(page, hidden_layers)
            if page_text:
                visible_parts.append(page_text)
            hidden.extend(page_hidden)
            unverified = unverified or page_unverified
            if hasattr(page, "_sanitize_pix"):
                delattr(page, "_sanitize_pix")
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
            properties=_pdf_properties(document),
            render_unverified=unverified,
        )
    finally:
        document.close()


def _pdf_properties(document) -> list[str]:
    try:
        meta = document.metadata or {}
    except Exception:
        return []
    found = []
    for key in ("title", "author", "subject", "keywords"):
        value = str(meta.get(key) or "").strip()
        if value:
            found.append(value)
    return found


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
            if _has_ink(page, span.get("bbox")):
                painted.append(_item(span, text))
            else:
                hidden.append((text, "pdf_clip"))
        else:
            hidden.append((text, reasons[0]))
    for text in _invisible_dict_text(page):
        hidden.append((text, "pdf_render_mode_7"))
    painted_text = _join(painted)
    if painted:
        for item in ocr_layer:
            hidden.append((item[3], "pdf_render_mode_3"))
        return painted_text, hidden, False
    if not ocr_layer:
        return "", hidden, False
    ocr_text = _join(ocr_layer)
    recognized = recognize_page(page)
    if recognized is None:
        return ocr_text, hidden, True
    if layer_agrees(ocr_text, recognized, render_match_threshold()):
        return ocr_text, hidden, False
    hidden.append((ocr_text, "render_mismatch"))
    return recognized, hidden, False


class _PixmapCache:
    def __init__(self, page):
        self.page = page
        self.pix = None

    def get(self):
        if self.pix is None:
            self.pix = self.page.get_pixmap(alpha=False, colorspace=pymupdf.csRGB)
        return self.pix


def _has_ink(page, bbox) -> bool:
    """False when a span's box is flat on the rendered page, as with a clip."""
    if not bbox:
        return True
    try:
        pixmap = _pixmap(page)
    except Exception:
        return True
    x0 = max(0, int(bbox[0]))
    y0 = max(0, int(bbox[1]))
    x1 = min(pixmap.width, int(bbox[2]) + 1)
    y1 = min(pixmap.height, int(bbox[3]) + 1)
    if x1 - x0 < 2 or y1 - y0 < 2 or (x1 - x0) * (y1 - y0) > 200_000:
        return True
    colors = [pixmap.pixel(x, y)[:3] for y in range(y0, y1) for x in range(x0, x1)]
    if len(colors) < 4:
        return True
    background = _common_color(colors)
    ink = sum(1 for color in colors if _rgb_distance(color, background) > 40)
    return ink >= 3


def _pixmap(page):
    cache = getattr(page, "_sanitize_pix", None)
    if cache is None:
        cache = _PixmapCache(page)
        setattr(page, "_sanitize_pix", cache)
    return cache.get()


def _common_color(colors: list[tuple[int, int, int]]) -> tuple[int, int, int]:
    counts: dict[tuple[int, int, int], int] = {}
    for red, green, blue in colors:
        key = (red // 16, green // 16, blue // 16)
        counts[key] = counts.get(key, 0) + 1
    red, green, blue = max(counts, key=lambda item: counts[item])
    return (red * 16 + 8, green * 16 + 8, blue * 16 + 8)


def _rgb_distance(left: tuple[int, int, int], right: tuple[int, int, int]) -> float:
    return sum((a - b) ** 2 for a, b in zip(left, right)) ** 0.5


def _invisible_dict_text(page) -> list[str]:
    """Text get_texttrace skips. Render mode 7 arrives here with alpha 0."""
    try:
        blocks = page.get_text("dict").get("blocks") or []
    except Exception:
        return []
    found = []
    for block in blocks:
        for line in block.get("lines") or []:
            for span in line.get("spans") or []:
                alpha = span.get("alpha", 255)
                text = (span.get("text") or "").replace("\u00a0", " ").strip()
                if text and alpha == 0:
                    found.append(text)
    return found


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


def render_match_threshold(config_path: Path | None = None) -> float:
    """Share of invisible-layer words that must appear on the rendered page."""
    default = 0.7
    path = config_path or (Path.home() / ".sanitize" / "config.json")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default
    value = data.get("render_match", default)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return default
    value = float(value)
    if not 0.0 <= value <= 1.0:
        return default
    return value


def layer_agrees(extracted: str, recognized: str, threshold: float) -> bool:
    extracted_words = _words(extracted)
    recognized_words = set(_words(recognized))
    if not extracted_words:
        return True
    coverage = sum(1 for word in extracted_words if word in recognized_words) / len(extracted_words)
    if coverage < threshold:
        return False
    recognized_numbers = _numbers(recognized)
    return all(number in recognized_numbers for number in _numbers(extracted))


def recognize_page(page) -> str | None:
    """OCR the rendered page. None means the page could not be compared."""
    executable = shutil.which("tesseract")
    if not executable:
        return None
    try:
        pixmap = page.get_pixmap(dpi=200, alpha=False)
        png = pixmap.tobytes("png")
    except Exception:
        return None
    for language in ("rus+eng", "eng"):
        recognized = _tesseract(executable, png, language)
        if recognized is None:
            continue
        if sum(char.isalnum() for char in recognized) >= 8:
            return recognized
    return None


def _tesseract(executable: str, png: bytes, language: str) -> str | None:
    try:
        with tempfile.TemporaryDirectory() as folder:
            image = Path(folder) / "page.png"
            image.write_bytes(png)
            completed = subprocess.run(
                [executable, str(image), "stdout", "-l", language],
                check=False,
                capture_output=True,
                timeout=60,
            )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout.decode("utf-8", "replace")


def _words(text: str) -> list[str]:
    normalized = text.replace("\u00a0", " ").casefold()
    return re.findall(r"[^\W\d_]{2,}|\d{2,}", normalized, flags=re.UNICODE)


def _numbers(text: str) -> set[str]:
    compact = re.sub(r"(?<=\d)\s+(?=\d)", "", text.replace("\u00a0", " "))
    return set(re.findall(r"\d{2,}", compact))
