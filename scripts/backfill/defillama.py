"""DeFiLlama hacks historical backfill. Bucket official JSON by incident date."""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

from common import (
    DEFILLAMA_URL,
    LAST_DAY,
    SCHEMA_DEFILLAMA,
    as_utc_day,
    fetch_bytes,
    parse_day,
    write_monthly_shards,
)


def load_hacks(raw: bytes) -> list[dict]:
    data = json.loads(raw.decode("utf-8"))
    if isinstance(data, dict):
        for key in ("hacks", "data", "incidents"):
            if isinstance(data.get(key), list):
                data = data[key]
                break
    if not isinstance(data, list):
        raise ValueError("DeFiLlama hacks JSON must be a list")
    return [row for row in data if isinstance(row, dict)]


def fetch_hacks(url: str = DEFILLAMA_URL) -> list[dict]:
    return load_hacks(fetch_bytes(url, accept="application/json"))


def _incident(row: dict, day: str) -> dict:
    item: dict = {
        "name": str(row.get("name") or "").strip(),
        "date": day,
    }
    if row.get("amount") not in (None, ""):
        item["amount"] = row.get("amount")
    source = str(row.get("source") or row.get("url") or row.get("link") or "").strip()
    if source.startswith("https://"):
        item["url"] = source
    if row.get("chain") not in (None, ""):
        item["chain"] = row.get("chain")
    if row.get("classification") not in (None, ""):
        item["classification"] = row.get("classification")
    if row.get("technique") not in (None, ""):
        item["technique"] = row.get("technique")
    if row.get("defillamaId") not in (None, ""):
        item["defillamaId"] = str(row.get("defillamaId"))
    if row.get("targetType") not in (None, ""):
        item["targetType"] = row.get("targetType")
    return item


def derive_defillama_days(
    rows: list[dict],
    *,
    last_day: date = LAST_DAY,
    first_day: date | None = None,
) -> tuple[list[dict], dict]:
    """Bucket by incident date. Days with no incidents are omitted (treat as zero)."""
    buckets: dict[str, list[dict]] = {}
    skipped = 0
    before_window = 0
    after_window = 0
    for row in rows:
        if row.get("date") in (None, ""):
            skipped += 1
            continue
        try:
            day = parse_day(as_utc_day(row.get("date")))
        except ValueError:
            skipped += 1
            continue
        if day > last_day:
            after_window += 1
            continue
        if first_day is not None and day < first_day:
            before_window += 1
            continue
        item = _incident(row, day.isoformat())
        if not item["name"]:
            skipped += 1
            continue
        buckets.setdefault(day.isoformat(), []).append(item)

    for items in buckets.values():
        items.sort(key=lambda item: (item["name"], str(item.get("defillamaId") or "")))

    days = [
        {"day": day, "incidents": items}
        for day, items in sorted(buckets.items())
    ]
    first = days[0]["day"] if days else None
    last = days[-1]["day"] if days else None
    meta = {
        "source_count": len(rows),
        "incident_days": len(days),
        "incidents": sum(len(row["incidents"]) for row in days),
        "skipped": skipped,
        "after_last_day": after_window,
        "before_first_day": before_window,
        "first_day": first,
        "last_day": last,
    }
    return days, meta


def write_defillama_backfill(
    out_dir: Path,
    rows: list[dict],
    *,
    last_day: date = LAST_DAY,
    first_day: date | None = None,
) -> tuple[list[Path], dict]:
    days, meta = derive_defillama_days(rows, last_day=last_day, first_day=first_day)
    written = write_monthly_shards(
        out_dir / "defillama" / "by-month",
        SCHEMA_DEFILLAMA,
        days,
    )
    meta["files"] = len(written)
    return written, meta
