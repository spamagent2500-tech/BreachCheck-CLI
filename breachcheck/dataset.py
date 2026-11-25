from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Iterator

from .models import BreachRecord

try:
    import ijson
except ImportError:  # pragma: no cover - requirements.txt installs it for large JSON files
    ijson = None


def normalize_email(value: object) -> str:
    return str(value or "").strip().lower()


def _record(raw: dict[str, object], source: str) -> BreachRecord:
    raw_classes = raw.get("classes", raw.get("data_classes", raw.get("DataClasses", "email")))
    if isinstance(raw_classes, list):
        classes = tuple(str(item).strip().lower() for item in raw_classes if str(item).strip())
    else:
        classes = tuple(item.strip().lower() for item in str(raw_classes).replace(";", ",").replace("|", ",").split(",") if item.strip())
    return BreachRecord(
        name=str(raw.get("name", raw.get("breach", raw.get("Name", "Imported breach")))).strip(),
        date=str(raw.get("date", raw.get("breach_date", raw.get("BreachDate", "unknown")))).strip(),
        classes=classes or ("email",),
        email=normalize_email(raw.get("email", raw.get("address", raw.get("Email", "")))),
        source=source,
    )


def _iter_json(path: Path) -> Iterator[dict[str, object]]:
    with path.open("rb") as handle:
        first = handle.read(1)
        while first and first.isspace():
            first = handle.read(1)
        handle.seek(0)
        if ijson is not None:
            prefix = "records.item" if first == b"{" else "item"
            yield from ijson.items(handle, prefix)
            return
        data = json.load(handle)
        rows = data if isinstance(data, list) else data.get("records", []) if isinstance(data, dict) else []
        for item in rows:
            if isinstance(item, dict):
                yield item


def iter_records(path: str | Path, source: str = "Local dataset") -> Iterator[BreachRecord]:
    file_path = Path(path)
    if file_path.suffix.lower() == ".csv":
        with file_path.open("r", encoding="utf-8-sig", newline="") as handle:
            for row in csv.DictReader(handle):
                yield _record(row, source)
    elif file_path.suffix.lower() in {".json", ".jsonl", ".ndjson"}:
        if file_path.suffix.lower() in {".jsonl", ".ndjson"}:
            with file_path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    if line.strip():
                        item = json.loads(line)
                        if isinstance(item, dict):
                            yield _record(item, source)
        else:
            for item in _iter_json(file_path):
                yield _record(item, source)
    else:
        raise ValueError(f"Unsupported dataset format: {file_path.suffix}. Use CSV, JSON, or JSONL.")


def find_matches(paths: list[str | Path], email: str) -> list[BreachRecord]:
    target = normalize_email(email)
    matches: list[BreachRecord] = []
    for path in paths:
        for record in iter_records(path):
            if record.email == target:
                matches.append(record)
    return matches
