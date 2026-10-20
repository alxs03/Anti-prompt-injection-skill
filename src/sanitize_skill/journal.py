import json
from datetime import datetime, timezone
from pathlib import Path

from sanitize_skill import __version__


def journal_dir(explicit: Path | None = None, home: Path | None = None) -> Path:
    if explicit is not None:
        return explicit
    base = home if home is not None else Path.home()
    return base / ".sanitize"


def record_file(directory: Path, record: dict) -> str:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "files.jsonl"
    digest = record["sha256"]
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                old = json.loads(line)
            except json.JSONDecodeError:
                continue
            if old.get("sha256") == digest:
                return "already_recorded"
    safe = {
        "time": _now(),
        "source_kind": record["source_kind"],
        "locator": record["locator"],
        "sha256": digest,
        "level": record["level"],
        "verdict": "hidden_mismatch",
        "finding_types": sorted(set(record["finding_types"])),
        "tool_version": __version__,
    }
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(safe, ensure_ascii=False) + "\n")
    return "recorded"


def quarantine(directory: Path, digest: str, raw: bytes) -> None:
    folder = directory / "quarantine"
    folder.mkdir(parents=True, exist_ok=True)
    dest = folder / digest
    if not dest.exists():
        dest.write_bytes(raw)


def record_run(directory: Path, digest: str, reason: str) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "runs.jsonl"
    safe = {
        "time": _now(),
        "sha256": digest,
        "reason": reason,
        "tool_version": __version__,
    }
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(safe, ensure_ascii=False) + "\n")


def export_files(directory: Path, dest: Path) -> int:
    """Write the privacy-safe file journal. Records never contain document text."""
    source = directory / "files.jsonl"
    count = 0
    lines: list[str] = []
    if source.is_file():
        for line in source.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            record = json.loads(line)
            safe = {
                "time": record.get("time"),
                "source_kind": record.get("source_kind"),
                "locator": _strip_query(str(record.get("locator", ""))),
                "sha256": record.get("sha256"),
                "level": record.get("level"),
                "verdict": record.get("verdict"),
                "finding_types": record.get("finding_types", []),
                "tool_version": record.get("tool_version"),
            }
            lines.append(json.dumps(safe, ensure_ascii=False))
            count += 1
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return count


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _strip_query(locator: str) -> str:
    if "?" in locator:
        return locator.split("?", 1)[0]
    return locator
