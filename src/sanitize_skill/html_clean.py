import re

from bs4 import BeautifulSoup, Comment, NavigableString, Tag

from sanitize_skill.models import Extract
from sanitize_skill.patterns import has_signal
from sanitize_skill.textutil import cleanup_visible, findings_from_hidden

_BLOCK = {
    "address", "article", "aside", "blockquote", "br", "dd", "div", "dl", "dt",
    "figcaption", "figure", "footer", "form", "h1", "h2", "h3", "h4", "h5", "h6",
    "header", "hr", "li", "main", "ol", "p", "pre", "section", "table", "tr", "ul",
}
_SKIP_TREE = {"script", "style"}
_NAMED = {
    "black": (0, 0, 0, 1.0),
    "white": (255, 255, 255, 1.0),
    "red": (255, 0, 0, 1.0),
    "blue": (0, 0, 255, 1.0),
    "green": (0, 128, 0, 1.0),
    "gray": (128, 128, 128, 1.0),
    "grey": (128, 128, 128, 1.0),
    "silver": (192, 192, 192, 1.0),
    "transparent": (0, 0, 0, 0.0),
}


def homoglyph_hook(text: str) -> list[dict]:
    from sanitize_skill.homoglyphs import scan_homoglyphs

    return scan_homoglyphs(text)


def extract_html(data: bytes) -> Extract:
    soup = BeautifulSoup(data, "lxml")
    rules = _stylesheet(soup)
    visible_parts: list[str] = []
    hidden: list[tuple[str, str]] = []
    side: list[str] = []
    for element in list(soup.find_all(["script", "style"])):
        text = element.get_text(" ", strip=True)
        if text:
            side.append(text)
        element.decompose()
    titles = []
    for title in soup.find_all("title"):
        text = title.get_text(" ", strip=True)
        if text:
            titles.append(text)
    for meta in soup.find_all("meta"):
        content = meta.get("content")
        if isinstance(content, str) and content:
            side.append(content)
    root = soup.body or soup
    _walk(root, {"color": "#000000", "background-color": "#ffffff"}, False, rules, visible_parts, hidden, side)
    visible = cleanup_visible(visible_parts)
    findings = findings_from_hidden(hidden, visible, has_signal)
    auxiliary = {"title": "\n".join(titles)} if titles else {}
    return Extract(
        visible=visible,
        auxiliary=auxiliary,
        findings=findings,
        side_text=[text for text in side if text.strip()],
    )


def _stylesheet(soup: BeautifulSoup) -> list[tuple[str, dict[str, str]]]:
    rules: list[tuple[str, dict[str, str]]] = []
    for style in soup.find_all("style"):
        css = re.sub(r"/\*.*?\*/", "", style.get_text(), flags=re.S)
        for block in css.split("}"):
            if "{" not in block:
                continue
            selector_text, body = block.split("{", 1)
            declarations = _declarations(body)
            for selector in selector_text.split(","):
                selector = selector.strip().lower()
                if selector and not any(char in selector for char in " >:+[~"):
                    rules.append((selector, declarations))
    return rules


def _declarations(body: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for part in body.split(";"):
        if ":" not in part:
            continue
        key, value = part.split(":", 1)
        found[key.strip().lower()] = value.strip().lower()
    return found


def _attr_text(tag: Tag, name: str) -> str:
    value = tag.get(name)
    return value if isinstance(value, str) else ""


def _attr_list(tag: Tag, name: str) -> list[str]:
    value = tag.get(name)
    if isinstance(value, list):
        return [str(item) for item in value]
    if isinstance(value, str):
        return [value]
    return []


def _matches(selector: str, tag: Tag) -> bool:
    name = (tag.name or "").lower()
    classes = {str(item).lower() for item in _attr_list(tag, "class")}
    element_id = _attr_text(tag, "id").lower()
    if selector.startswith("."):
        return selector[1:] in classes
    if selector.startswith("#"):
        return selector[1:] == element_id
    if "." in selector:
        tag_name, class_name = selector.split(".", 1)
        return name == tag_name and class_name in classes
    if "#" in selector:
        tag_name, id_name = selector.split("#", 1)
        return name == tag_name and element_id == id_name
    return name == selector


def _computed(tag: Tag, inherited: dict[str, str], rules: list[tuple[str, dict[str, str]]]) -> dict[str, str]:
    style = {
        "color": inherited.get("color", "#000000"),
        "background-color": inherited.get("background-color", "#ffffff"),
        "font-size": inherited.get("font-size", ""),
        "visibility": inherited.get("visibility", "visible"),
    }
    for selector, declarations in rules:
        if _matches(selector, tag):
            style.update(declarations)
    style_value = tag.get("style")
    if isinstance(style_value, str):
        style.update(_declarations(style_value))
    shorthand = style.get("background", "")
    if shorthand and "url(" not in shorthand and "gradient" not in shorthand:
        token = shorthand.split()[-1]
        if token.startswith(("#", "rgb")) or token in _NAMED:
            style["background-color"] = token
    background = style.get("background-color", "")
    if background in {"", "transparent", "rgba(0, 0, 0, 0)", "rgba(0,0,0,0)"}:
        style["background-color"] = inherited.get("background-color", "#ffffff")
    return style


def _walk(tag, inherited, force_hidden, rules, visible_parts, hidden, side, forced_category=None) -> None:
    if isinstance(tag, Comment):
        hidden.append((str(tag), "html_comment"))
        return
    if isinstance(tag, NavigableString):
        text = str(tag)
        if text.strip():
            if force_hidden:
                hidden.append((text, forced_category or "html_hidden"))
            else:
                visible_parts.append(text)
        return
    if not isinstance(tag, Tag):
        return
    if tag.name in {"title", "meta", "link", "base"}:
        if tag.name == "title":
            side.append(tag.get_text(" ", strip=True))
        if tag.name == "meta":
            side.append(tag.get("content") or "")
        return
    if tag.name in _SKIP_TREE:
        return
    style = _computed(tag, inherited, rules)
    own = _hard_category(tag, style)
    hard = force_hidden or own is not None
    input_type = tag.get("type")
    if tag.name == "input" and isinstance(input_type, str) and input_type.lower() == "hidden":
        value = tag.get("value")
        hidden.append((value if isinstance(value, str) else "", "html_hidden_input"))
        return
    if tag.name == "template":
        hard = True
        own = own or "html_template"
    active = own or forced_category or "html_hidden"
    soft = _soft_category(style)
    if tag.name in _BLOCK and tag.name != "br":
        visible_parts.append("\n")
    if not hard:
        _labels(tag, hidden, visible_parts)
    for child in tag.children:
        if isinstance(child, Comment):
            hidden.append((str(child), "html_comment"))
            continue
        if isinstance(child, NavigableString):
            text = str(child)
            if not text.strip():
                if not hard and text:
                    visible_parts.append(text)
                continue
            if hard:
                hidden.append((text, active))
            elif soft:
                hidden.append((text, soft))
            else:
                visible_parts.append(text)
            continue
        if isinstance(child, Tag):
            if child.name == "br":
                visible_parts.append("\n")
                continue
            _walk(child, style, hard, rules, visible_parts, hidden, side, active if hard else None)
    if tag.name in _BLOCK and tag.name != "br":
        visible_parts.append("\n")


def _labels(tag: Tag, hidden: list[tuple[str, str]], visible_parts: list[str]) -> None:
    own = tag.get_text(" ", strip=True)
    for attr, category in (("aria-label", "html_aria_label"), ("title", "html_title")):
        value = tag.get(attr)
        if not value or not str(value).strip():
            continue
        label = str(value).strip()
        if not own:
            visible_parts.append(label + "\n")
        elif label.casefold() not in own.casefold():
            hidden.append((label, category))


def _hard_category(tag: Tag, style: dict[str, str]) -> str | None:
    if tag.has_attr("hidden"):
        return "html_hidden"
    if str(tag.get("aria-hidden", "")).lower() == "true":
        return "html_aria_hidden"
    display = style.get("display", "")
    if display == "none" or display.startswith("none "):
        return "html_display_none"
    visibility = style.get("visibility", "")
    if visibility in {"hidden", "collapse"}:
        return "html_visibility"
    if _opacity_hidden(style.get("opacity")):
        return "html_opacity"
    if _offscreen(style):
        return "html_offscreen"
    return None


def _soft_category(style: dict[str, str]) -> str | None:
    if _font_hidden(style.get("font-size")):
        return "html_font_size"
    color = _parse_color(style.get("color", ""))
    background = _parse_color(style.get("background-color", "")) or (255, 255, 255, 1.0)
    if color is not None:
        if color[3] <= 0.05:
            return "html_low_contrast"
        if _contrast_low(color[:3], background[:3]):
            return "html_low_contrast"
    return None


def _opacity_hidden(value: str | None) -> bool:
    if not value:
        return False
    try:
        return float(value) <= 0.05
    except ValueError:
        return False


def _font_hidden(value: str | None) -> bool:
    if not value:
        return False
    match = re.match(r"([0-9.]+)\s*(px|pt|em|rem|%)?$", value.strip())
    if not match:
        return False
    number = float(match.group(1))
    unit = match.group(2) or "px"
    if unit in {"px", "pt"} and number <= 1:
        return True
    return unit in {"em", "rem", "%"} and number == 0


def _length_px(value: str) -> float | None:
    match = re.match(r"(-?[0-9.]+)\s*(px|pt)?$", value.strip())
    if not match:
        return None
    number = float(match.group(1))
    if match.group(2) == "pt":
        number *= 1.333
    return number


def _offscreen(style: dict[str, str]) -> bool:
    if style.get("position") in {"absolute", "fixed"}:
        for prop in ("left", "top", "right", "bottom"):
            raw = style.get(prop)
            if not raw:
                continue
            number = _length_px(raw)
            if number is not None and number <= -100:
                return True
    indent = style.get("text-indent")
    if indent:
        number = _length_px(indent)
        if number is not None and number <= -50:
            return True
    clip = (style.get("clip") or "").replace(" ", "")
    if clip.startswith("rect(0"):
        return True
    if style.get("overflow") == "hidden":
        width = _length_px(style.get("width", "") or "")
        height = _length_px(style.get("height", "") or "")
        if width == 0 or height == 0:
            return True
    return False


def _parse_color(value: str) -> tuple[int, int, int, float] | None:
    if not value:
        return None
    value = value.strip().lower()
    if value in _NAMED:
        return _NAMED[value]
    hex_match = re.fullmatch(r"#([0-9a-f]{3,8})", value)
    if hex_match:
        raw = hex_match.group(1)
        if len(raw) == 3:
            raw = "".join(ch * 2 for ch in raw)
        if len(raw) == 6:
            return (int(raw[0:2], 16), int(raw[2:4], 16), int(raw[4:6], 16), 1.0)
        if len(raw) == 8:
            return (
                int(raw[0:2], 16),
                int(raw[2:4], 16),
                int(raw[4:6], 16),
                int(raw[6:8], 16) / 255,
            )
    rgb_match = re.fullmatch(r"rgba?\(([^)]+)\)", value)
    if not rgb_match:
        return None
    bits = [bit.strip() for bit in rgb_match.group(1).split(",")]
    if len(bits) < 3:
        return None
    try:
        rgb = tuple(int(float(bit)) for bit in bits[:3])
        alpha = float(bits[3]) if len(bits) > 3 else 1.0
    except ValueError:
        return None
    return rgb[0], rgb[1], rgb[2], alpha


def _contrast_low(text_rgb: tuple[int, int, int], bg_rgb: tuple[int, int, int]) -> bool:
    distance = sum((a - b) ** 2 for a, b in zip(text_rgb, bg_rgb)) ** 0.5
    return distance < 46
