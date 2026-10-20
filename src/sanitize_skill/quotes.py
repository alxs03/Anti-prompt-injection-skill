import argparse
import json
import re
import sys
from pathlib import Path

from sanitize_skill.journal import journal_dir, record_run
from sanitize_skill.models import SanitizeError
from sanitize_skill.textutil import loose, sha256_text


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sanitize-check", description="Check reader quotes against visible text.")
    parser.add_argument("reader", type=Path, help="Reader JSON path")
    parser.add_argument("--visible", required=True, type=Path, help="visible.txt from sanitize")
    parser.add_argument("--model", type=Path, help="Optional model.json; checks visible_sha256")
    parser.add_argument("--journal-dir", type=Path)
    args = parser.parse_args(argv)
    try:
        payload = json.loads(args.reader.read_text(encoding="utf-8"))
        visible = args.visible.read_text(encoding="utf-8")
        expected = None
        digest = ""
        if args.model:
            model = json.loads(args.model.read_text(encoding="utf-8"))
            expected = model.get("visible_sha256")
            digest = (model.get("source") or {}).get("sha256", "")
        if not isinstance(payload, dict):
            raise SanitizeError("reader json must be an object")
        result = check_reader(payload, visible, expected_visible_sha256=expected)
    except SanitizeError as exc:
        print(f"error={exc}", file=sys.stderr)
        return 1
    except (OSError, json.JSONDecodeError):
        print("error=could not read checker input", file=sys.stderr)
        return 1
    print(f"ok={str(result.ok).lower()}")
    print(f"errors={len(result.errors)}")
    if result.quote_failures:
        print("quote_index_failed=" + ",".join(str(index) for index in result.quote_failures))
    if result.number_failures:
        print("number_index_failed=" + ",".join(str(index) for index in result.number_failures))
    if result.summary_failures:
        print("summary_number_failed=" + ",".join(str(index) for index in result.summary_failures))
    print(f"actions={result.action_count}")
    if not result.ok and digest:
        record_run(journal_dir(args.journal_dir), digest, "quote_mismatch")
    return 0 if result.ok else 1


class CheckResult:
    def __init__(self):
        self.errors: list[str] = []
        self.quote_failures: list[int] = []
        self.number_failures: list[int] = []
        self.summary_failures: list[int] = []
        self.action_count = 0

    @property
    def ok(self) -> bool:
        return not self.errors


def check_reader(payload: dict, visible: str, *, expected_visible_sha256: str | None = None) -> CheckResult:
    result = CheckResult()
    if expected_visible_sha256 and expected_visible_sha256 != sha256_text(visible):
        result.errors.append("visible file does not match model.json")
    quotes = payload.get("quotes", [])
    numbers = payload.get("numbers", [])
    actions = payload.get("actions", [])
    summary = payload.get("summary", "")
    if not isinstance(summary, str) or not isinstance(quotes, list) or not isinstance(numbers, list):
        raise SanitizeError("reader json fields have the wrong type")
    if not isinstance(actions, list):
        raise SanitizeError("reader actions must be a list")
    result.action_count = len(actions)
    for index, quote in enumerate(quotes):
        text = quote.get("text") if isinstance(quote, dict) else None
        if not isinstance(text, str) or not loose(text) or loose(text) not in loose(visible):
            result.quote_failures.append(index)
            result.errors.append(f"quote {index} is not in the visible text")
    for index, number in enumerate(numbers):
        if not isinstance(number, dict):
            result.number_failures.append(index)
            result.errors.append(f"number {index} is not in the visible text")
            continue
        value = str(number.get("value", "")).strip()
        quote = number.get("quote", "")
        if (
            not value
            or not isinstance(quote, str)
            or loose(quote) not in loose(visible)
            or not _number_token(value, quote)
            or not _number_token(value, visible)
        ):
            result.number_failures.append(index)
            result.errors.append(f"number {index} is not in the visible text")
    for index, token in enumerate(_prose_numbers(summary)):
        if not _number_token(token, visible):
            result.summary_failures.append(index)
            result.errors.append(f"summary number {index} is not in the visible text")
    return result


def _prose_numbers(text: str) -> list[str]:
    return re.findall(r"\d[\d\s.,]*\d|\d{2,}", text)


def _number_token(value: str, haystack: str) -> bool:
    folded = loose(haystack)
    needle = loose(value)
    if not needle:
        return False
    return re.search(r"(?<!\d)" + re.escape(needle) + r"(?!\d)", folded) is not None


if __name__ == "__main__":
    raise SystemExit(main())
