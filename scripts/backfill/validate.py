#!/usr/bin/env python3
"""Validate committed (or generated) backfill shards. Offline, no live fetches."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import (
    EPSS_HIGH_THRESHOLD,
    MONTH_RE,
    SCHEMA_DEFILLAMA,
    SCHEMA_EPSS,
    SCHEMA_KEV,
    SCHEMA_MANIFEST,
    assert_no_forbidden_keys,
    load_simple_yaml,
    month_key,
    parse_day,
)

ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_DIR = ROOT / "backfill"

SOURCE_SCHEMAS = {
    "kev": SCHEMA_KEV,
    "epss": SCHEMA_EPSS,
    "defillama": SCHEMA_DEFILLAMA,
}


def _load_json(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a JSON object")
    return data


def validate_month_file(path: Path, expected_schema: str) -> list[str]:
    errors: list[str] = []
    try:
        data = _load_json(path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return [f"{path}: {exc}"]
    try:
        assert_no_forbidden_keys(data, path=str(path))
    except ValueError as exc:
        errors.append(str(exc))
    if data.get("schema") != expected_schema:
        errors.append(f"{path}: schema {data.get('schema')!r} != {expected_schema}")
    month = str(data.get("month") or "")
    if not MONTH_RE.match(month):
        errors.append(f"{path}: month must be YYYY-MM")
    if path.stem != month:
        errors.append(f"{path}: filename stem {path.stem!r} != month {month!r}")
    days = data.get("days")
    if not isinstance(days, list) or not days:
        errors.append(f"{path}: days must be a non-empty list")
        return errors
    prev = ""
    for i, row in enumerate(days):
        loc = f"{path} days[{i}]"
        if not isinstance(row, dict):
            errors.append(f"{loc}: expected object")
            continue
        try:
            day = parse_day(str(row.get("day") or ""))
        except ValueError:
            errors.append(f"{loc}: day must be YYYY-MM-DD")
            continue
        if month_key(day) != month:
            errors.append(f"{loc}: {row.get('day')} is not in month {month}")
        if prev and str(row["day"]) <= prev:
            errors.append(f"{loc}: days must be strictly increasing")
        prev = str(row["day"])
        if expected_schema == SCHEMA_KEV:
            added = row.get("added")
            if not isinstance(added, list):
                errors.append(f"{loc}: added must be a list")
            if not isinstance(row.get("cumulative_count"), int):
                errors.append(f"{loc}: cumulative_count must be an int")
            elif isinstance(added, list) and row["cumulative_count"] < len(added):
                errors.append(f"{loc}: cumulative_count < len(added)")
        elif expected_schema == SCHEMA_EPSS:
            if not isinstance(row.get("high_count"), int):
                errors.append(f"{loc}: high_count must be an int")
            if row.get("high_threshold") != EPSS_HIGH_THRESHOLD:
                errors.append(f"{loc}: high_threshold must be {EPSS_HIGH_THRESHOLD}")
            sample = row.get("sample_cves")
            if not isinstance(sample, list):
                errors.append(f"{loc}: sample_cves must be a list")
            elif len(sample) > 8:
                errors.append(f"{loc}: sample_cves longer than 8")
            if "scored_total" in row and not isinstance(row.get("scored_total"), int):
                errors.append(f"{loc}: scored_total must be an int when present")
        elif expected_schema == SCHEMA_DEFILLAMA:
            incidents = row.get("incidents")
            if not isinstance(incidents, list) or not incidents:
                errors.append(f"{loc}: incidents must be a non-empty list")
            elif any(not isinstance(item, dict) or not item.get("name") for item in incidents):
                errors.append(f"{loc}: each incident needs a name")
    return errors


def validate_tree(root: Path) -> list[str]:
    errors: list[str] = []
    manifest_path = root / "manifest.yaml"
    if not manifest_path.exists():
        return [f"{manifest_path}: missing"]
    try:
        manifest = load_simple_yaml(manifest_path)
    except ValueError as exc:
        return [str(exc)]
    if manifest.get("schema") != SCHEMA_MANIFEST:
        errors.append(f"{manifest_path}: schema {manifest.get('schema')!r} != {SCHEMA_MANIFEST}")
    if manifest.get("ranking") is True or manifest.get("class_taxonomy") is True:
        errors.append(f"{manifest_path}: ranking/class_taxonomy must be false")
    if manifest.get("invented_daily_releases") is True:
        errors.append(f"{manifest_path}: invented_daily_releases must be false")
    sources = manifest.get("sources")
    if not isinstance(sources, list) or not sources:
        errors.append(f"{manifest_path}: sources must be a non-empty list")
        return errors
    seen: set[str] = set()
    for src in sources:
        if not isinstance(src, dict):
            errors.append(f"{manifest_path}: source must be a map")
            continue
        sid = str(src.get("id") or "")
        seen.add(sid)
        expected = SOURCE_SCHEMAS.get(sid)
        if expected is None:
            errors.append(f"{manifest_path}: unknown source id {sid!r}")
            continue
        if src.get("schema") != expected:
            errors.append(f"{manifest_path}: {sid} schema {src.get('schema')!r} != {expected}")
        rel = str(src.get("path") or f"{sid}/by-month/")
        directory = root / rel
        if not directory.is_dir():
            errors.append(f"{directory}: missing month directory")
            continue
        files = sorted(directory.glob("????-??.json"))
        if not files:
            errors.append(f"{directory}: no YYYY-MM.json shards")
            continue
        for path in files:
            errors.extend(validate_month_file(path, expected))
        declared = src.get("files")
        if isinstance(declared, int) and declared != len(files):
            errors.append(f"{manifest_path}: {sid} files {declared} != {len(files)} on disk")
    return errors


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    root = Path(argv[0]) if argv else DEFAULT_DIR
    if not root.exists():
        print(f"FAIL: {root} does not exist", file=sys.stderr)
        return 1
    errors = validate_tree(root)
    if errors:
        for err in errors:
            print(f"FAIL: {err}", file=sys.stderr)
        return 1
    print(f"OK: backfill schema checks passed under {root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
