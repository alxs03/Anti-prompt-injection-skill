import io
import zipfile
import xml.etree.ElementTree as ET

from sanitize_skill.models import Extract, SanitizeError
from sanitize_skill.patterns import has_signal
from sanitize_skill.textutil import cleanup_visible, findings_from_hidden, make_info

W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
A = "http://schemas.openxmlformats.org/drawingml/2006/main"
P = "http://schemas.openxmlformats.org/presentationml/2006/main"
S = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
R = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
PKG = "http://schemas.openxmlformats.org/package/2006/relationships"

_ZIP_MAX = 40_000_000


def extract_office(data: bytes, max_total: int = _ZIP_MAX) -> tuple[str, Extract]:
    files = read_zip(data, max_total=max_total)
    kind = detect_kind(files)
    if kind == "docx":
        return kind, extract_docx(files)
    if kind == "xlsx":
        return kind, extract_xlsx(files)
    return kind, extract_pptx(files)


def read_zip(data: bytes, max_total: int = _ZIP_MAX) -> dict[str, bytes]:
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise SanitizeError("could not read office file") from exc
    infos = archive.infolist()
    if len(infos) > 4000:
        raise SanitizeError("office file has too many parts")
    total = 0
    files: dict[str, bytes] = {}
    for info in infos:
        if info.file_size > max_total or total + info.file_size > max_total:
            raise SanitizeError("office file is too large")
        total += info.file_size
        name = info.filename.replace("\\", "/")
        if name.startswith("/") or ".." in name.split("/"):
            raise SanitizeError("office part path is not allowed")
        files[name] = archive.read(info)
    return files


def detect_kind(files: dict[str, bytes]) -> str:
    content_types = files.get("[Content_Types].xml", b"").decode("utf-8", "ignore").lower()
    if "wordprocessingml" in content_types or "word/document.xml" in files:
        return "docx"
    if "spreadsheetml" in content_types or "xl/workbook.xml" in files:
        return "xlsx"
    if "presentationml" in content_types or "ppt/presentation.xml" in files:
        return "pptx"
    raise SanitizeError("unsupported zip file")


def extract_docx(files: dict[str, bytes]) -> Extract:
    style_map = _docx_styles(files)
    visible_parts: list[str] = []
    hidden: list[tuple[str, str]] = []
    infos = []
    for name in sorted(files):
        if not name.startswith("word/") or not name.endswith(".xml"):
            continue
        if name.startswith("word/comments") or name.startswith("word/customXml") or "/_rels/" in name:
            continue
        if "afchunk" in name:
            text = _plain_xml_text(files[name])
            if text:
                visible_parts.append(text)
                infos.append(make_info("docx_alt_chunk", "Alternative chunk text was included as visible."))
            continue
        root = _xml(files[name])
        if root is None:
            continue
        _docx_tree(root, style_map, visible_parts, hidden)
    visible = cleanup_visible(visible_parts)
    auxiliary = {}
    comments = _docx_comments(files)
    if comments:
        auxiliary["comments"] = comments
    for name, blob in files.items():
        if name.startswith("customXml/") and name.endswith(".xml") and not name.endswith(".rels"):
            text = _plain_xml_text(blob)
            if text:
                hidden.append((text, "docx_custom_xml"))
    return Extract(
        visible=visible,
        auxiliary=auxiliary,
        findings=findings_from_hidden(hidden, visible, has_signal),
        infos=infos,
    )


def _docx_tree(root, style_map, visible_parts, hidden) -> None:
    for paragraph in root.iter(_w("p")):
        for run in _paragraph_runs(paragraph):
            text, deleted = _run_text(run)
            props = _effective_rpr(paragraph, run, style_map)
            if deleted:
                hidden.append((deleted, "docx_revision"))
            if not text:
                continue
            if props["vanish"]:
                hidden.append((text, "docx_vanish"))
            elif _hex_contrast_low(props["color"], props["fill"]):
                hidden.append((text, "docx_low_contrast"))
            else:
                visible_parts.append(text)
        visible_parts.append("\n")


def _paragraph_runs(paragraph):
    runs = []
    for child in list(paragraph):
        if child.tag == _w("r"):
            runs.append(child)
        elif child.tag in {_w("hyperlink"), _w("ins"), _w("smartTag")}:
            runs.extend(node for node in list(child) if node.tag == _w("r"))
    return runs


def _run_text(run) -> tuple[str, str]:
    visible: list[str] = []
    deleted: list[str] = []
    for child in list(run):
        if child.tag == _w("t"):
            visible.append(child.text or "")
        elif child.tag == _w("delText"):
            deleted.append(child.text or "")
        elif child.tag == _w("tab"):
            visible.append("\t")
        elif child.tag in {_w("br"), _w("cr")}:
            visible.append("\n")
    return "".join(visible), "".join(deleted)


def _effective_rpr(paragraph, run, style_map) -> dict:
    merged = {"vanish": False, "color": None, "fill": "FFFFFF"}
    layers = []
    ppr = paragraph.find(_w("pPr"))
    if ppr is not None:
        p_style = _attr(_first(ppr, "pStyle"), "val")
        if p_style and p_style in style_map:
            layers.append(style_map[p_style])
        layers.append(_rpr(_first(ppr, "rPr")))
    rpr = _first(run, "rPr")
    if rpr is not None:
        r_style = _attr(_first(rpr, "rStyle"), "val")
        if r_style and r_style in style_map:
            layers.append(style_map[r_style])
        layers.append(_rpr(rpr))
    for layer in layers:
        if layer["vanish"] is not None:
            merged["vanish"] = layer["vanish"]
        if layer["color"]:
            merged["color"] = layer["color"]
        if layer["fill"]:
            merged["fill"] = layer["fill"]
    return merged


def _docx_styles(files) -> dict[str, dict]:
    root = _xml(files.get("word/styles.xml"))
    found: dict[str, dict] = {}
    if root is None:
        return found
    for style in root.findall(_w("style")):
        style_id = _attr(style, "styleId")
        if style_id:
            found[style_id] = _rpr(_first(style, "rPr"))
    return found


def _rpr(element) -> dict:
    info = {"vanish": None, "color": None, "fill": None}
    if element is None:
        return info
    vanish = _first(element, "vanish")
    web = _first(element, "webHidden")
    flag = vanish if vanish is not None else web
    if flag is not None:
        info["vanish"] = _flag_on(flag)
    color = _first(element, "color")
    if color is not None:
        info["color"] = _attr(color, "val")
    shade = _first(element, "shd")
    if shade is not None:
        info["fill"] = _attr(shade, "fill")
    return info


def _docx_comments(files) -> str:
    parts = []
    for name, blob in sorted(files.items()):
        if name.startswith("word/comments") and name.endswith(".xml"):
            text = _plain_xml_text(blob)
            if text:
                parts.append(text)
    return "\n".join(parts).strip()


def extract_xlsx(files: dict[str, bytes]) -> Extract:
    strings = _shared_strings(files)
    font_colors = _xlsx_font_colors(files)
    visible_parts: list[str] = []
    hidden: list[tuple[str, str]] = []
    for name, state, path in _xlsx_sheets(files):
        root = _xml(files.get(path))
        if root is None:
            continue
        hidden_cols = _hidden_columns(root)
        sheet_hidden = state in {"hidden", "veryhidden"}
        if not sheet_hidden:
            visible_parts.append(f"# {name}\n")
        for row in root.iter(_s("row")):
            row_hidden = (_attr(row, "hidden") or "0").lower() in {"1", "true"}
            cells = []
            row_secret: list[tuple[str, str]] = []
            for cell in row.findall(_s("c")):
                text = _cell_text(cell, strings)
                if not text:
                    cells.append("")
                    continue
                ref = _attr(cell, "r") or ""
                column = _column_index(ref)
                style = _attr(cell, "s")
                low = _xlsx_low_contrast(style, font_colors)
                if sheet_hidden:
                    row_secret.append((text, "xlsx_hidden_sheet"))
                elif row_hidden:
                    row_secret.append((text, "xlsx_hidden_row"))
                elif column in hidden_cols:
                    row_secret.append((text, "xlsx_hidden_column"))
                elif low:
                    row_secret.append((text, "xlsx_low_contrast"))
                else:
                    cells.append(text)
            hidden.extend(row_secret)
            if any(cells) and not sheet_hidden and not row_hidden:
                visible_parts.append("\t".join(cells).rstrip() + "\n")
    visible = cleanup_visible(visible_parts)
    return Extract(visible=visible, findings=findings_from_hidden(hidden, visible, has_signal))


def _xlsx_sheets(files) -> list[tuple[str, str, str]]:
    workbook = _xml(files.get("xl/workbook.xml"))
    rels = _xml(files.get("xl/_rels/workbook.xml.rels"))
    if workbook is None or rels is None:
        raise SanitizeError("xlsx workbook is missing")
    targets = {}
    for rel in rels:
        if not str(rel.tag).endswith("Relationship"):
            continue
        targets[rel.get("Id")] = rel.get("Target") or ""
    sheets = []
    for sheet in workbook.iter(_s("sheet")):
        name = _attr(sheet, "name") or "Sheet"
        state = (_attr(sheet, "state") or "visible").lower()
        rel_id = _attr_ns(sheet, R, "id")
        target = targets.get(rel_id, "")
        path = _join_xl(target)
        sheets.append((name, state, path))
    return sheets


def _join_xl(target: str) -> str:
    target = target.lstrip("/")
    if target.startswith("xl/"):
        return target
    return "xl/" + target


def _shared_strings(files) -> list[str]:
    root = _xml(files.get("xl/sharedStrings.xml"))
    if root is None:
        return []
    values = []
    for item in root.findall(_s("si")):
        values.append("".join(node.text or "" for node in item.iter(_s("t"))))
    return values


def _xlsx_font_colors(files) -> list[str | None]:
    """Map a cellXfs index to a font rgb, if the font has one."""
    root = _xml(files.get("xl/styles.xml"))
    if root is None:
        return []
    fonts = []
    fonts_node = root.find(_s("fonts"))
    if fonts_node is not None:
        for font in fonts_node.findall(_s("font")):
            color = font.find(_s("color"))
            fonts.append(_attr(color, "rgb") if color is not None else None)
    mapped = []
    cell_xfs = root.find(_s("cellXfs"))
    if cell_xfs is None:
        return mapped
    for xf in cell_xfs.findall(_s("xf")):
        try:
            font_id = int(_attr(xf, "fontId") or "0")
        except ValueError:
            font_id = 0
        mapped.append(fonts[font_id] if 0 <= font_id < len(fonts) else None)
    return mapped


def _hidden_columns(root) -> set[int]:
    hidden = set()
    for col in root.iter(_s("col")):
        if (_attr(col, "hidden") or "0").lower() in {"1", "true"}:
            start = int(_attr(col, "min") or "0")
            end = int(_attr(col, "max") or str(start))
            hidden.update(range(start, end + 1))
    return hidden


def _cell_text(cell, strings: list[str]) -> str:
    kind = _attr(cell, "t") or ""
    if kind == "inlineStr":
        return "".join(node.text or "" for node in cell.iter(_s("t")))
    value = cell.find(_s("v"))
    raw = value.text if value is not None and value.text else ""
    if kind == "s":
        try:
            return strings[int(raw)]
        except (ValueError, IndexError):
            return ""
    if kind == "b":
        return "TRUE" if raw == "1" else "FALSE"
    return raw


def _xlsx_low_contrast(style: str | None, font_colors: list[str | None]) -> bool:
    if style is None:
        return False
    try:
        index = int(style)
    except ValueError:
        return False
    if index < 0 or index >= len(font_colors):
        return False
    return _hex_contrast_low(font_colors[index], "FFFFFF")


def _column_index(ref: str) -> int:
    letters = "".join(char for char in ref if char.isalpha())
    index = 0
    for char in letters.upper():
        index = index * 26 + (ord(char) - 64)
    return index


def extract_pptx(files: dict[str, bytes]) -> Extract:
    width, height = _slide_size(files)
    visible_parts: list[str] = []
    hidden: list[tuple[str, str]] = []
    for name in sorted(files):
        if not (name.startswith("ppt/slides/slide") and name.endswith(".xml")):
            continue
        if "/_rels/" in name:
            continue
        root = _xml(files[name])
        if root is None:
            continue
        slide_hidden = (_attr(root, "show") or "1").lower() in {"0", "false"}
        background = _pptx_background(root)
        for shape in root.iter(_p("sp")):
            x, y, cx, cy = _shape_box(shape)
            outside = _off_slide(x, y, cx, cy, width, height)
            for run in shape.iter(_a("r")):
                text = "".join(node.text or "" for node in run.iter(_a("t"))).strip()
                if not text:
                    continue
                if slide_hidden:
                    hidden.append((text, "pptx_hidden_slide"))
                elif outside:
                    hidden.append((text, "pptx_off_slide"))
                elif _hex_contrast_low(_run_color(run), background):
                    hidden.append((text, "pptx_low_contrast"))
                else:
                    visible_parts.append(text + "\n")
    notes = []
    for name in sorted(files):
        if name.startswith("ppt/notesSlides/") and name.endswith(".xml") and "/_rels/" not in name:
            text = _plain_xml_text(files[name])
            if text:
                notes.append(text)
    visible = cleanup_visible(visible_parts)
    auxiliary = {"speaker_notes": "\n".join(notes)} if notes else {}
    return Extract(
        visible=visible,
        auxiliary=auxiliary,
        findings=findings_from_hidden(hidden, visible, has_signal),
    )


def _slide_size(files) -> tuple[int, int]:
    root = _xml(files.get("ppt/presentation.xml"))
    if root is None:
        return (12192000, 6858000)
    size = root.find(_p("sldSz"))
    if size is None:
        return (12192000, 6858000)
    return (int(_attr(size, "cx") or 12192000), int(_attr(size, "cy") or 6858000))


def _shape_box(shape) -> tuple[int, int, int, int]:
    off = shape.find(f".//{_a('off')}")
    ext = shape.find(f".//{_a('ext')}")
    if off is None:
        return (0, 0, 0, 0)
    x = int(_attr(off, "x") or 0)
    y = int(_attr(off, "y") or 0)
    cx = int(_attr(ext, "cx") or 0) if ext is not None else 0
    cy = int(_attr(ext, "cy") or 0) if ext is not None else 0
    return x, y, cx, cy


def _off_slide(x, y, cx, cy, width, height) -> bool:
    if x == 0 and y == 0 and cx == 0 and cy == 0:
        return False
    if cx == 0 and cy == 0:
        return x >= width or y >= height or x < 0 or y < 0
    return x >= width or y >= height or x + cx <= 0 or y + cy <= 0


def _pptx_background(root) -> str:
    background = root.find(f".//{_p('bg')}")
    if background is None:
        return "FFFFFF"
    color = background.find(f".//{_a('srgbClr')}")
    return _attr(color, "val") or "FFFFFF"


def _run_color(run) -> str | None:
    props = run.find(_a("rPr"))
    if props is None:
        return None
    color = props.find(f".//{_a('srgbClr')}")
    if color is None:
        return None
    return _attr(color, "val")


def _plain_xml_text(blob: bytes) -> str:
    root = _xml(blob)
    if root is None:
        return ""
    return " ".join(bit.strip() for bit in root.itertext() if bit and bit.strip())


def _xml(blob: bytes | None):
    if not blob:
        return None
    try:
        return ET.fromstring(blob)
    except ET.ParseError as exc:
        raise SanitizeError("could not read office xml") from exc


def _hex_contrast_low(color: str | None, fill: str | None) -> bool:
    text = _hex_rgb(color)
    background = _hex_rgb(fill) or (255, 255, 255)
    if text is None:
        return False
    distance = sum((a - b) ** 2 for a, b in zip(text, background)) ** 0.5
    return distance < 46


def _hex_rgb(value: str | None) -> tuple[int, int, int] | None:
    if not value:
        return None
    raw = value.strip().lstrip("#")
    if raw.lower() in {"auto", "none"}:
        return None
    if len(raw) == 8:
        raw = raw[2:]
    if len(raw) != 6:
        return None
    try:
        return (int(raw[0:2], 16), int(raw[2:4], 16), int(raw[4:6], 16))
    except ValueError:
        return None


def _flag_on(element) -> bool:
    value = _attr(element, "val")
    if value is None:
        return True
    return value.lower() not in {"0", "false", "off", "none"}


def _first(element, name: str):
    if element is None:
        return None
    return element.find(_w(name))


def _attr(element, name: str) -> str | None:
    if element is None:
        return None
    for namespace in (W, A, P, S, R, PKG, None):
        key = name if namespace is None else f"{{{namespace}}}{name}"
        value = element.get(key)
        if value is not None:
            return value
    return None


def _attr_ns(element, namespace: str, name: str) -> str | None:
    if element is None:
        return None
    return element.get(f"{{{namespace}}}{name}") or element.get(name)


def _w(name: str) -> str:
    return f"{{{W}}}{name}"


def _a(name: str) -> str:
    return f"{{{A}}}{name}"


def _p(name: str) -> str:
    return f"{{{P}}}{name}"


def _s(name: str) -> str:
    return f"{{{S}}}{name}"
