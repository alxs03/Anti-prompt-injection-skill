"""Time and memory for a 200-page PDF and a 10 MB HTML file.

Run: python -m sanitize_skill.bench
"""

import tracemalloc
from time import perf_counter

import pymupdf

from sanitize_skill.pipeline import sanitize_bytes

_PAGE = "Страница {n}. Договор поставки без скрытых инструкций."


def main() -> None:
    pdf = _pdf(200)
    html = _html(10_000_000)
    pdf_report = _measure(pdf, "bench.pdf")
    html_report = _measure(html, "bench.html")
    print(
        f"pdf_pages=200 bytes={len(pdf)} seconds={pdf_report[0]:.2f} tracemalloc_mib={pdf_report[1]:.1f}"
    )
    print(
        f"html_bytes={len(html)} seconds={html_report[0]:.2f} tracemalloc_mib={html_report[1]:.1f}"
    )


def _measure(data: bytes, filename: str) -> tuple[float, float]:
    tracemalloc.start()
    started = perf_counter()
    sanitize_bytes(data, filename=filename, level=2)
    elapsed = perf_counter() - started
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return elapsed, peak / (1024 * 1024)


def _pdf(pages: int) -> bytes:
    document = pymupdf.open()
    for number in range(1, pages + 1):
        page = document.new_page()
        page.insert_text((72, 72), _PAGE.format(n=number), fontsize=12)
    data = document.tobytes(deflate=True, garbage=3)
    document.close()
    return data


def _html(size: int) -> bytes:
    paragraph = "<p>Договор поставки на сумму 1000 рублей. Скрытых инструкций здесь нет.</p>".encode()
    chunks = [b"<!DOCTYPE html><html><body>"]
    total = len(chunks[0])
    while total < size:
        chunks.append(paragraph)
        total += len(paragraph)
    chunks.append(b"</body></html>")
    return b"".join(chunks)


if __name__ == "__main__":
    main()
