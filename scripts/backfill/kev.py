"""CISA KEV historical backfill. Bucket official JSON by dateAdded."""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

from common import (
    KEV_FIRST_DAY,
    KEV_URL,
    LAST_DAY,
    SCHEMA_KEV,
    as_utc_day,
    each_day,
    fetch_bytes,
    fmt_day,
    parse_day,
    write_monthly_shards,
)


def load_kev_catalog(raw: bytes) -> dict:
    data = json.loads(raw.decode("utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
        raise ValueError("KEV JSON must be an object with a vulnerabilities list")
    return data


def fetch_kev_catalog(url: str = KEV_URL) -> dict:
    return load_kev_catalog(fetch_bytes(url, accept="application/json"))


def _added_row(row: dict) -> dict:
    return {
        "cveId": str(row.get("cveID") or "").strip(),
        "vendorProject": str(row.get("vendorProject") or "").strip(),
        "product": str(row.get("product") or "").strip(),
        "vulnerabilityName": str(row.get("vulnerabilityName") or "").strip(),
        "knownRansomwareCampaignUse": str(
            row.get("knownRansomwareCampaignUse") or ""
        ).strip(),
    }


def derive_kev_days(
    catalog: dict,
    *,
    first_day: date = KEV_FIRST_DAY,
    last_day: date = LAST_DAY,
) -> tuple[list[dict], dict]:
    """Return (days, meta). Include empty days so cumulative_count is walkable."""
    buckets: dict[str, list[dict]] = {}
    skipped = 0
    for row in catalog.get("vulnerabilities") or []:
        if not isinstance(row, dict):
            skipped += 1
            continue
        added = str(row.get("dateAdded") or "").strip()
        if not added:
            skipped += 1
            continue
        try:
            day = parse_day(as_utc_day(added))
        except ValueError:
            skipped += 1
            continue
        if day < first_day or day > last_day:
            skipped += 1
            continue
        item = _added_row(row)
        if not item["cveId"]:
            skipped += 1
            continue
        buckets.setdefault(fmt_day(day), []).append(item)

    for items in buckets.values():
        items.sort(key=lambda item: item["cveId"])

    days: list[dict] = []
    cumulative = 0
    for day in each_day(first_day, last_day):
        key = fmt_day(day)
        added = buckets.get(key, [])
        cumulative += len(added)
        days.append(
            {
                "day": key,
                "added": added,
                "cumulative_count": cumulative,
            }
        )

    meta = {
        "catalog_version": str(catalog.get("catalogVersion") or ""),
        "date_released": str(catalog.get("dateReleased") or ""),
        "source_count": int(catalog.get("count") or len(catalog.get("vulnerabilities") or [])),
        "window_added": cumulative,
        "skipped": skipped,
        "first_day": fmt_day(first_day),
        "last_day": fmt_day(last_day),
    }
    return days, meta


def write_kev_backfill(
    out_dir: Path,
    catalog: dict,
    *,
    first_day: date = KEV_FIRST_DAY,
    last_day: date = LAST_DAY,
) -> tuple[list[Path], dict]:
    days, meta = derive_kev_days(catalog, first_day=first_day, last_day=last_day)
    written = write_monthly_shards(out_dir / "kev" / "by-month", SCHEMA_KEV, days)
    meta["files"] = len(written)
    return written, meta
