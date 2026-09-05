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
    each_day,
    load_simple_yaml,
    month_key,
    parse_day,
)


def resolve_under_root(root: Path, rel: str) -> Path:
    """Resolve rel under root. Reject absolute paths and `..` escapes."""
    text = str(rel).strip()
    if not text:
        raise ValueError("empty path")
    candidate = Path(text)
    if candidate.is_absolute() or candidate.drive or text.startswith(("/", "\\")):
        raise ValueError(f"absolute path not allowed: {rel!r}")
    if any(part == ".." for part in candidate.parts):
        raise ValueError(f"path escapes root via '..': {rel!r}")
    resolved = (root / candidate).resolve()
    root_res = root.resolve()
    if not resolved.is_relative_to(root_res):
        raise ValueError(f"path escapes {root}: {rel!r}")
    return resolved

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
            if isinstance(row.get("high_count"), int) and isinstance(sample, list):
                if row["high_count"] < len(sample):
                    errors.append(f"{loc}: high_count {row['high_count']} < len(sample_cves)")
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
        try:
            directory = resolve_under_root(root, rel)
        except ValueError as exc:
            errors.append(f"{manifest_path}: {sid} path rejected: {exc}")
            continue
        if not directory.is_dir():
            errors.append(f"{directory}: missing month directory")
            continue
        files = sorted(directory.glob("????-??.json"))
        if not files:
            errors.append(f"{directory}: no YYYY-MM.json shards")
            continue
        root_res = root.resolve()
        for path in files:
            resolved = path.resolve()
            if not resolved.is_relative_to(root_res):
                errors.append(f"{path}: resolved path escapes {root}")
                continue
            errors.extend(validate_month_file(resolved, expected))
        declared = src.get("files")
        if isinstance(declared, int) and declared != len(files):
            errors.append(f"{manifest_path}: {sid} files {declared} != {len(files)} on disk")
        if sid == "epss":
            errors.extend(_validate_epss_missing(root, src, files, manifest_path))
    return errors


def parse_missing_txt(path: Path) -> tuple[set[str], list[str]]:
    """Return (days, errors) from epss/missing.txt (`YYYY-MM-DD` or `YYYY-MM-DD:reason`)."""
    days: set[str] = set()
    errors: list[str] = []
    text = path.read_text(encoding="utf-8")
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        day_text = line.split(":", 1)[0].strip()
        try:
            day = parse_day(day_text).isoformat()
        except ValueError:
            errors.append(f"{path}:{lineno}: expected YYYY-MM-DD, got {line!r}")
            continue
        if day in days:
            errors.append(f"{path}:{lineno}: duplicate {day}")
        days.add(day)
    return days, errors


def _shard_days(files: list[Path]) -> tuple[set[str], list[str]]:
    present: set[str] = set()
    errors: list[str] = []
    for path in files:
        try:
            data = _load_json(path)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            errors.append(f"{path}: {exc}")
            continue
        for row in data.get("days") or []:
            if isinstance(row, dict) and row.get("day"):
                present.add(str(row["day"]))
    return present, errors


def _validate_epss_missing(
    root: Path,
    src: dict,
    files: list[Path],
    manifest_path: Path,
) -> list[str]:
    """Pin missing.txt to omitted EPSS days in the source window. Treat listed days as zero."""
    errors: list[str] = []
    try:
        missing_path = resolve_under_root(root, "epss/missing.txt")
    except ValueError as exc:
        return [f"{manifest_path}: epss missing.txt path rejected: {exc}"]

    listed: set[str] = set()
    if missing_path.is_file():
        listed, parse_errors = parse_missing_txt(missing_path)
        errors.extend(parse_errors)
    elif src.get("missing_days"):
        errors.append(f"{missing_path}: missing (manifest missing_days={src.get('missing_days')})")

    present, shard_errors = _shard_days(files)
    errors.extend(shard_errors)

    overlap = sorted(present & listed)
    if overlap:
        errors.append(
            f"{missing_path}: days also present in shards (must be omitted): "
            + ", ".join(overlap[:8])
        )

    first = src.get("first_day")
    last = src.get("last_day")
    if first and last:
        try:
            window = {d.isoformat() for d in each_day(parse_day(str(first)), parse_day(str(last)))}
        except ValueError as exc:
            errors.append(f"{manifest_path}: epss window: {exc}")
            window = set()
        if window:
            omitted = window - present
            extra_listed = sorted(listed - window)
            if extra_listed:
                errors.append(
                    f"{missing_path}: days outside epss window {first}..{last}: "
                    + ", ".join(extra_listed[:8])
                )
            unlisted = sorted(omitted - listed)
            if unlisted:
                errors.append(
                    f"{missing_path}: omitted shard days not listed (treat as zero, do not interpolate): "
                    + ", ".join(unlisted[:8])
                )

    if isinstance(src.get("missing_days"), int) and src["missing_days"] != len(listed):
        errors.append(
            f"{manifest_path}: epss missing_days {src['missing_days']} != {len(listed)} in missing.txt"
        )
    if isinstance(src.get("derived_days"), int) and src["derived_days"] != len(present):
        errors.append(
            f"{manifest_path}: epss derived_days {src['derived_days']} != {len(present)} shard days"
        )
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
