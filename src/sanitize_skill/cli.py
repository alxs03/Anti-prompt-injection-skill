import argparse
import json
import sys
from pathlib import Path

from sanitize_skill import __version__
from sanitize_skill.fetch import fetch_url, public_locator
from sanitize_skill.journal import export_files, journal_dir, purge_expired, quarantine, record_file, retention_days
from sanitize_skill.models import DEFAULT_LEVEL, SanitizeError
from sanitize_skill.pipeline import sanitize_bytes, sanitize_text


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sanitize",
        description="Read a file or URL into model.json. Hidden layers stay in evidence.json.",
    )
    parser.add_argument("target", nargs="?", help="File path or http(s) URL")
    parser.add_argument("--text", help="Sanitize this text instead of a path")
    parser.add_argument("--stdin", action="store_true", help="Read UTF-8 text from stdin")
    parser.add_argument("--level", type=int, choices=range(5))
    parser.add_argument("--out", type=Path)
    parser.add_argument("--journal-dir", type=Path)
    parser.add_argument("--no-journal", action="store_true")
    parser.add_argument("--max-bytes", type=int, default=15_000_000)
    parser.add_argument("--timeout", type=float, default=20)
    parser.add_argument("--export-journal", type=Path, help="Write the privacy-safe file journal and exit")
    parser.add_argument("--version", action="store_true")
    args = parser.parse_args(argv)
    if args.version:
        print(__version__)
        return 0
    try:
        if args.export_journal:
            directory = journal_dir(args.journal_dir)
            purge_expired(directory, retention_days())
            count = export_files(directory, args.export_journal)
            print(f"exported={count}")
            return 0
        floor = load_floor()
        level = resolve_level(args.level, floor)
        if not args.no_journal:
            purge_expired(journal_dir(args.journal_dir), retention_days())
        result, locator, source_kind = _load(args, level)
        out = args.out or Path("sanitize-out") / result.sha256[:16]
        _write_outputs(result, out)
        if not args.no_journal and result.evidence["verdict"] == "hidden_mismatch":
            directory = journal_dir(args.journal_dir)
            status = record_file(
                directory,
                {
                    "source_kind": source_kind,
                    "locator": locator,
                    "sha256": result.sha256,
                    "level": level,
                    "finding_types": [
                        item["category"]
                        for item in result.evidence["findings"]
                        if item["severity"] == "mismatch"
                    ],
                },
            )
            quarantine(directory, result.sha256, result.raw)
            result.evidence["journal"] = status
            result.evidence["quarantine_sha256"] = result.sha256
            (out / "evidence.json").write_text(
                json.dumps(result.evidence, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        flags = result.model["flags"]
        print(f"verdict={result.evidence['verdict']}")
        print(f"hidden_withheld={str(flags['hidden_withheld']).lower()}")
        print(f"model={out / 'model.json'}")
        print(f"visible={out / 'visible.txt'}")
        print(f"evidence={out / 'evidence.json'}")
        return 0
    except SanitizeError as exc:
        print(f"error={exc}", file=sys.stderr)
        return 1


def load_floor(home: Path | None = None) -> int:
    path = (home if home is not None else Path.home()) / ".sanitize" / "config.json"
    if not path.is_file():
        return DEFAULT_LEVEL
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SanitizeError("cannot read the sanitize config") from exc
    level = data.get("level", DEFAULT_LEVEL)
    if isinstance(level, bool) or not isinstance(level, int) or level not in range(5):
        raise SanitizeError("config level must be an integer 0..4")
    return level


def resolve_level(requested: int | None, floor: int) -> int:
    if requested is None:
        return floor
    if requested < floor:
        raise SanitizeError(f"refusing level {requested}: floor is {floor}; the level cannot be lowered")
    return requested


def _load(args, level: int):
    if args.stdin:
        text = sys.stdin.read()
        result = sanitize_text(text, level=level, locator="stdin")
        return result, "stdin", "text"
    if args.text is not None:
        result = sanitize_text(args.text, level=level, locator="pasted-text")
        return result, "pasted-text", "text"
    if not args.target:
        raise SanitizeError("pass a path, a url, --text, or --stdin")
    target = args.target
    if target.startswith(("http://", "https://")):
        fetched = fetch_url(target, timeout=args.timeout, max_bytes=args.max_bytes)
        result = sanitize_bytes(
            fetched.data,
            filename=_name_from_locator(fetched.locator),
            content_type=fetched.content_type,
            level=level,
            source_kind="url",
            locator=fetched.locator,
        )
        return result, fetched.locator, "url"
    path = Path(target)
    if not path.is_file():
        raise SanitizeError("file not found")
    data = path.read_bytes()
    if len(data) > args.max_bytes:
        raise SanitizeError("file exceeds size limit")
    locator = str(path.resolve())
    result = sanitize_bytes(data, filename=path.name, level=level, source_kind="file", locator=locator)
    return result, locator, "file"


def _name_from_locator(locator: str) -> str:
    return public_locator(locator).rstrip("/").rsplit("/", 1)[-1] or "download"


def _write_outputs(result, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / "model.json").write_text(json.dumps(result.model, ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "visible.txt").write_text(result.visible_text, encoding="utf-8")
    (out / "evidence.json").write_text(json.dumps(result.evidence, ensure_ascii=False, indent=2), encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
