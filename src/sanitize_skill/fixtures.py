"""Builders for small HTML, PDF, and Office fixtures. Used by tests and the corpus."""

import io
import zipfile
from pathlib import Path
from xml.sax.saxutils import escape

import pymupdf

_FONT_CANDIDATES = (
    Path(r"C:\Windows\Fonts\arial.ttf"),
    Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
    Path("/usr/share/fonts/TTF/DejaVuSans.ttf"),
)


def _fontfile() -> str | None:
    for path in _FONT_CANDIDATES:
        if path.is_file():
            return str(path)
    return None


def html_document(body: str, head: str = "") -> bytes:
    page = (
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\">"
        f"{head}</head><body>{body}</body></html>"
    )
    return page.encode("utf-8")


def pdf_document(spans: list[dict], background: tuple[float, float, float] | None = None) -> bytes:
    document = pymupdf.open()
    page = document.new_page()
    if background is not None:
        page.draw_rect(page.rect, color=background, fill=background)
    fontfile = _fontfile()
    for span in spans:
        kwargs = {}
        if fontfile:
            kwargs["fontfile"] = fontfile
            kwargs["fontname"] = "fixture"
        page.insert_text(
            span.get("point", (72, 72)),
            span["text"],
            fontsize=span.get("fontsize", 12),
            color=span.get("color", (0, 0, 0)),
            render_mode=span.get("render_mode", 0),
            fill_opacity=span.get("opacity", 1),
            **kwargs,
        )
    data = document.tobytes()
    document.close()
    return data


def docx_document(paragraphs: list[list[dict]], comments: str = "", custom_xml: str = "") -> bytes:
    body = []
    for runs in paragraphs:
        run_xml = []
        for run in runs:
            props = []
            if run.get("vanish"):
                props.append("<w:vanish/>")
            if run.get("color"):
                props.append(f"<w:color w:val=\"{run['color']}\"/>")
            if run.get("style"):
                props.append(f"<w:rStyle w:val=\"{escape(run['style'])}\"/>")
            rpr = f"<w:rPr>{''.join(props)}</w:rPr>" if props else ""
            run_xml.append(f"<w:r>{rpr}<w:t xml:space=\"preserve\">{escape(run['text'])}</w:t></w:r>")
        body.append(f"<w:p>{''.join(run_xml)}</w:p>")
    document = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>{''.join(body)}</w:body>
</w:document>"""
    files = {
        "[Content_Types].xml": _content_types("word"),
        "_rels/.rels": _root_rels("word/document.xml"),
        "word/document.xml": document,
    }
    if any(run.get("style") for runs in paragraphs for run in runs):
        files["word/styles.xml"] = """<?xml version="1.0" encoding="UTF-8"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:style w:styleId="Hidden" w:type="character">
    <w:rPr><w:vanish/></w:rPr>
  </w:style>
</w:styles>"""
    if comments:
        files["word/comments.xml"] = f"""<?xml version="1.0" encoding="UTF-8"?>
<w:comments xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:comment w:id="1"><w:p><w:r><w:t>{escape(comments)}</w:t></w:r></w:p></w:comment>
</w:comments>"""
    if custom_xml:
        files["customXml/item1.xml"] = f"<note>{escape(custom_xml)}</note>"
    return _zip(files)


def xlsx_workbook(sheets: list[dict]) -> bytes:
    """Each sheet is name, optional state, rows of cells. A cell is str or {value, white}."""
    sheet_xml = []
    overrides = [
        '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>',
        '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>',
    ]
    rels = []
    workbook_sheets = []
    files: dict[str, str] = {}
    for index, sheet in enumerate(sheets, start=1):
        path = f"xl/worksheets/sheet{index}.xml"
        files[path] = _sheet_xml(sheet)
        overrides.append(
            f'<Override PartName="/{path}" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        )
        rels.append(
            f'<Relationship Id="rId{index}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet{index}.xml"/>'
        )
        state = sheet.get("state", "visible")
        state_attr = "" if state == "visible" else f' state="{state}"'
        workbook_sheets.append(
            f'<sheet name="{escape(sheet["name"])}" sheetId="{index}"{state_attr} r:id="rId{index}"/>'
        )
    style_rel = len(sheets) + 1
    rels.append(
        f'<Relationship Id="rId{style_rel}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>'
    )
    files["xl/workbook.xml"] = f"""<?xml version="1.0" encoding="UTF-8"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <sheets>{''.join(workbook_sheets)}</sheets>
</workbook>"""
    files["xl/_rels/workbook.xml.rels"] = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        + "".join(rels)
        + "</Relationships>"
    )
    files["xl/styles.xml"] = """<?xml version="1.0" encoding="UTF-8"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <fonts count="2">
    <font><sz val="11"/><name val="Calibri"/></font>
    <font><sz val="11"/><color rgb="FFFFFFFF"/></font>
  </fonts>
  <fills count="1"><fill><patternFill patternType="none"/></fill></fills>
  <borders count="1"><border/></borders>
  <cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
  <cellXfs count="2">
    <xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>
    <xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0"/>
  </cellXfs>
</styleSheet>"""
    files["[Content_Types].xml"] = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        + "".join(overrides)
        + "</Types>"
    )
    files["_rels/.rels"] = _root_rels("xl/workbook.xml")
    return _zip(files)


def pptx_deck(slides: list[dict]) -> bytes:
    """Slide dict: hidden, notes, shapes [{text, x, y, cx, cy, color}]. Coordinates are EMUs."""
    files = {
        "[Content_Types].xml": (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/>'
            + "".join(
                f'<Override PartName="/ppt/slides/slide{i}.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slide+xml"/>'
                for i in range(1, len(slides) + 1)
            )
            + "</Types>"
        ),
        "_rels/.rels": _root_rels("ppt/presentation.xml"),
        "ppt/presentation.xml": f"""<?xml version="1.0" encoding="UTF-8"?>
<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <p:sldIdLst>
    {''.join(f'<p:sldId id="{256+i}" r:id="rId{i}"/>' for i in range(1, len(slides)+1))}
  </p:sldIdLst>
  <p:sldSz cx="12192000" cy="6858000"/>
</p:presentation>""",
        "ppt/_rels/presentation.xml.rels": (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            + "".join(
                f'<Relationship Id="rId{i}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide" Target="slides/slide{i}.xml"/>'
                for i in range(1, len(slides) + 1)
            )
            + "</Relationships>"
        ),
    }
    for index, slide in enumerate(slides, start=1):
        show = ' show="0"' if slide.get("hidden") else ""
        shapes = []
        for shape_index, shape in enumerate(slide.get("shapes", []), start=2):
            color = shape.get("color")
            run_props = ""
            if color:
                run_props = f'<a:rPr><a:solidFill><a:srgbClr val="{color}"/></a:solidFill></a:rPr>'
            shapes.append(
                f"""<p:sp>
                  <p:spPr><a:xfrm><a:off x="{shape.get('x', 914400)}" y="{shape.get('y', 914400)}"/><a:ext cx="{shape.get('cx', 4000000)}" cy="{shape.get('cy', 600000)}"/></a:xfrm></p:spPr>
                  <p:txBody><a:bodyPr/><a:p><a:r>{run_props}<a:t>{escape(shape['text'])}</a:t></a:r></a:p></p:txBody>
                </p:sp>"""
            )
        files[f"ppt/slides/slide{index}.xml"] = f"""<?xml version="1.0" encoding="UTF-8"?>
<p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"{show}>
  <p:cSld><p:spTree>{''.join(shapes)}</p:spTree></p:cSld>
</p:sld>"""
        if slide.get("notes"):
            files[f"ppt/notesSlides/notesSlide{index}.xml"] = f"""<?xml version="1.0" encoding="UTF-8"?>
<p:notes xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
  <p:cSld><p:spTree><p:sp><p:txBody><a:p><a:r><a:t>{escape(slide['notes'])}</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld>
</p:notes>"""
    return _zip(files)


def _sheet_xml(sheet: dict) -> str:
    hidden_cols = sheet.get("hidden_columns") or []
    cols = ""
    if hidden_cols:
        cols = "<cols>" + "".join(f'<col min="{col}" max="{col}" hidden="1"/>' for col in hidden_cols) + "</cols>"
    rows = []
    for row_index, row in enumerate(sheet.get("rows", []), start=1):
        hidden = row.get("hidden") if isinstance(row, dict) else False
        values = row.get("cells") if isinstance(row, dict) else row
        attr = ' hidden="1"' if hidden else ""
        cells = []
        for col_index, cell in enumerate(values, start=1):
            white = False
            if isinstance(cell, dict):
                white = bool(cell.get("white"))
                value = str(cell.get("value", ""))
            else:
                value = str(cell)
            ref = f"{_column_letter(col_index)}{row_index}"
            style = ' s="1"' if white else ""
            cells.append(f'<c r="{ref}" t="inlineStr"{style}><is><t>{escape(value)}</t></is></c>')
        rows.append(f'<row r="{row_index}"{attr}>{"".join(cells)}</row>')
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  {cols}
  <sheetData>{''.join(rows)}</sheetData>
</worksheet>"""


def _column_letter(index: int) -> str:
    letters = ""
    while index:
        index, remainder = divmod(index - 1, 26)
        letters = chr(65 + remainder) + letters
    return letters


def _zip(files: dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in files.items():
            archive.writestr(name, content.encode("utf-8"))
    return buffer.getvalue()


def _content_types(kind: str) -> str:
    if kind == "word":
        override = '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
    else:
        override = ""
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        f"{override}</Types>"
    )


def _root_rels(target: str) -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        f'<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="{target}"/>'
        "</Relationships>"
    )
