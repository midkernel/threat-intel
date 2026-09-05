#!/usr/bin/env python3
"""Fetch official catalogs and write derived historical backfill shards.

Never commits raw EPSS CSVs. No ranking, classes, or Midkernel scores.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import (
    DEFILLAMA_URL,
    EPSS_FIRST_DAY,
    EPSS_HIGH_THRESHOLD,
    KEV_FIRST_DAY,
    KEV_URL,
    LAST_DAY,
    SCHEMA_DEFILLAMA,
    SCHEMA_EPSS,
    SCHEMA_KEV,
    SCHEMA_MANIFEST,
    dump_simple_yaml,
    fmt_day,
    group_by_month,
    load_simple_yaml,
    parse_day,
)
from defillama import derive_defillama_days, fetch_hacks, load_hacks, write_defillama_backfill
from epss import generate_epss_days, write_epss_backfill
from kev import derive_kev_days, fetch_kev_catalog, load_kev_catalog, write_kev_backfill

ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURES = Path(__file__).resolve().parent / "fixtures"
DEFAULT_OUT = ROOT / "backfill"


def _merge_sources(out_dir: Path, sources: list[dict]) -> list[dict]:
    path = out_dir / "manifest.yaml"
    existing: list[dict] = []
    if path.exists():
        try:
            loaded = load_simple_yaml(path)
            if isinstance(loaded.get("sources"), list):
                existing = [row for row in loaded["sources"] if isinstance(row, dict)]
        except ValueError:
            existing = []
    by_id = {str(row.get("id")): row for row in existing}
    for row in sources:
        by_id[str(row.get("id"))] = row
    order = ["kev", "epss", "defillama"]
    merged = [by_id[key] for key in order if key in by_id]
    for key, row in by_id.items():
        if key not in order:
            merged.append(row)
    return merged


def _write_manifest(out_dir: Path, sources: list[dict], *, first_day: str, last_day: str) -> Path:
    payload = {
        "schema": SCHEMA_MANIFEST,
        "first_day": first_day,
        "last_day": last_day,
        "layout": "monthly-shards",
        "layout_note": (
            "Days are packed as kev|epss|defillama/by-month/YYYY-MM.json "
            "so the repo stays well under a few thousand files."
        ),
        "additive_only": True,
        "ranking": False,
        "class_taxonomy": False,
        "midkernel_scores": False,
        "invented_daily_releases": False,
        "sources": _merge_sources(out_dir, sources),
    }
    path = out_dir / "manifest.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dump_simple_yaml(payload), encoding="utf-8")
    return path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--sources",
        default="kev,epss,defillama",
        help="Comma-separated: kev,epss,defillama",
    )
    parser.add_argument(
        "--from-day",
        dest="from_day",
        default="",
        help="YYYY-MM-DD inclusive. Honored by KEV, EPSS, and DeFiLlama.",
    )
    parser.add_argument(
        "--to-day",
        dest="to_day",
        default="",
        help="YYYY-MM-DD inclusive. Clamped to 2026-09-04 unless --allow-past-last-day.",
    )
    parser.add_argument(
        "--allow-past-last-day",
        action="store_true",
        help=(
            "Permit --to-day after 2026-09-04 (overlaps live daily-* Releases). "
            "Default is to clamp. Do not use this to invent daily Releases."
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print derived counts and write nothing.",
    )
    parser.add_argument("--out", default=str(DEFAULT_OUT), help="Output directory (default: backfill/)")
    parser.add_argument("--kev-input", default="", help="Local KEV JSON instead of a live fetch")
    parser.add_argument("--hacks-input", default="", help="Local DeFiLlama hacks JSON")
    parser.add_argument("--epss-dir", default="", help="Local directory of daily EPSS CSVs")
    parser.add_argument(
        "--epss-method",
        choices=("csv", "api"),
        default="csv",
        help="Live EPSS source: empiricalsec daily CSV (default) or FIRST API",
    )
    parser.add_argument("--epss-workers", type=int, default=8)
    parser.add_argument(
        "--epss-threshold",
        type=float,
        default=EPSS_HIGH_THRESHOLD,
        help="High-EPSS cutoff (default 0.5). Cited threshold, not a Midkernel score.",
    )
    parser.add_argument(
        "--smoke",
        action="store_true",
        help="Offline fixture generate into a temp-like out dir (no live fetches)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    out_dir = Path(args.out)
    wanted = [part.strip() for part in args.sources.split(",") if part.strip()]
    unknown = [name for name in wanted if name not in {"kev", "epss", "defillama"}]
    if unknown:
        print(f"unknown sources: {', '.join(unknown)}", file=sys.stderr)
        return 2

    from_day_explicit = bool(args.from_day)
    smoke_kev_range = None
    smoke_epss_range = None
    if args.smoke:
        out_dir = Path(args.out) if args.out != str(DEFAULT_OUT) else ROOT / "backfill" / ".smoke"
        args.kev_input = args.kev_input or str(FIXTURES / "kev.json")
        args.hacks_input = args.hacks_input or str(FIXTURES / "hacks.json")
        args.epss_dir = args.epss_dir or str(FIXTURES / "epss")
        if not args.from_day:
            args.from_day = "2021-04-14"
        if not args.to_day:
            args.to_day = "2021-11-04"
        # Fixtures cover two EPSS days and two KEV days — do not walk the full window.
        smoke_kev_range = (parse_day("2021-11-03"), parse_day("2021-11-04"))
        smoke_epss_range = (parse_day("2021-04-14"), parse_day("2021-04-15"))
        wanted = wanted or ["kev", "epss", "defillama"]

    window_first = parse_day(args.from_day) if args.from_day else EPSS_FIRST_DAY
    window_last = parse_day(args.to_day) if args.to_day else LAST_DAY
    if window_last < window_first:
        print("--to-day must be on or after --from-day", file=sys.stderr)
        return 2
    if window_last > LAST_DAY and not args.allow_past_last_day:
        print(
            f"clamping --to-day {fmt_day(window_last)} to {fmt_day(LAST_DAY)} "
            "(default last_day; does not overlap daily-* Releases). "
            "Pass --allow-past-last-day to override.",
            file=sys.stderr,
        )
        window_last = LAST_DAY

    if args.dry_run:
        print("dry-run: printing counts, not writing files")
    else:
        out_dir.mkdir(parents=True, exist_ok=True)
    source_rows: list[dict] = []

    if "kev" in wanted:
        kev_first = max(window_first, KEV_FIRST_DAY)
        kev_last = window_last
        if smoke_kev_range:
            kev_first, kev_last = smoke_kev_range
        if args.kev_input:
            catalog = load_kev_catalog(Path(args.kev_input).read_bytes())
            method = "parse local CISA KEV JSON fixture; bucket by dateAdded"
            url = args.kev_input
        else:
            catalog = fetch_kev_catalog()
            method = "parse official CISA KEV JSON; bucket by dateAdded"
            url = KEV_URL
        if args.dry_run:
            days, meta = derive_kev_days(catalog, first_day=kev_first, last_day=kev_last)
            written = []
            meta["files"] = len(group_by_month(days))
        else:
            written, meta = write_kev_backfill(
                out_dir, catalog, first_day=kev_first, last_day=kev_last
            )
        print(
            f"KEV: {meta['window_added']} added across {meta['files']} month shards "
            f"({meta['first_day']}..{meta['last_day']}; catalogVersion={meta['catalog_version']})"
        )
        source_rows.append(
            {
                "id": "kev",
                "schema": SCHEMA_KEV,
                "method": method,
                "url": url,
                "first_day": meta["first_day"],
                "last_day": meta["last_day"],
                "path": "kev/by-month/",
                "catalog_version": meta["catalog_version"],
                "date_released": meta["date_released"],
                "files": meta["files"],
                "window_added": meta["window_added"],
            }
        )

    if "epss" in wanted:
        epss_first = max(window_first, EPSS_FIRST_DAY)
        epss_last = window_last
        if smoke_epss_range:
            epss_first, epss_last = smoke_epss_range
        csv_dir = Path(args.epss_dir) if args.epss_dir else None
        cache_dir = (
            None
            if args.smoke or args.dry_run or csv_dir is not None
            else (out_dir / ".cache" / "epss")
        )
        days, missing = generate_epss_days(
            first_day=epss_first,
            last_day=epss_last,
            method=args.epss_method,
            threshold=args.epss_threshold,
            workers=args.epss_workers,
            csv_dir=csv_dir,
            cache_dir=cache_dir,
        )
        written = [] if args.dry_run else write_epss_backfill(out_dir, days)
        method = (
            "read local empiricalsec-format daily CSVs; derive high_count; discard CSV"
            if csv_dir is not None
            else (
                "download empiricalsec daily CSV; derive high_count; never commit CSV"
                if args.epss_method == "csv"
                else "FIRST EPSS API date + epss-gt filter; derive high_count; no raw dump"
            )
        )
        n_months = len(written) if written else len(group_by_month(days))
        print(
            f"EPSS: {len(days)} derived days in {n_months} month shards "
            f"({fmt_day(epss_first)}..{fmt_day(epss_last)}; missing={len(missing)})"
        )
        if missing[:8]:
            print("EPSS missing (first few): " + ", ".join(missing[:8]))
        source_rows.append(
            {
                "id": "epss",
                "schema": SCHEMA_EPSS,
                "method": method,
                "url": (
                    str(csv_dir)
                    if csv_dir is not None
                    else (
                        "https://epss.empiricalsecurity.com/epss_scores-YYYY-MM-DD.csv.gz (github.com/empiricalsec/epss_scores fallback)"
                        if args.epss_method == "csv"
                        else "https://api.first.org/data/v1/epss"
                    )
                ),
                "first_day": fmt_day(epss_first),
                "last_day": fmt_day(epss_last),
                "path": "epss/by-month/",
                "high_threshold": args.epss_threshold,
                "files": n_months,
                "derived_days": len(days),
                "missing_days": len(missing),
            }
        )
        if missing and not args.dry_run:
            (out_dir / "epss").mkdir(parents=True, exist_ok=True)
            (out_dir / "epss" / "missing.txt").write_text(
                "\n".join(missing) + "\n", encoding="utf-8"
            )

    if "defillama" in wanted:
        if args.hacks_input:
            rows = load_hacks(Path(args.hacks_input).read_bytes())
            method = "parse local DeFiLlama hacks JSON fixture; bucket by incident date"
            url = args.hacks_input
        else:
            rows = fetch_hacks()
            method = "parse official DeFiLlama hacks JSON; bucket by incident date"
            url = DEFILLAMA_URL
        # Default (no --from-day) keeps the catalog's full incident history.
        # An explicit --from-day is honored — including when --smoke is also set.
        llama_first = window_first if from_day_explicit else None
        if args.dry_run:
            days, meta = derive_defillama_days(
                rows, last_day=window_last, first_day=llama_first
            )
            written = []
            meta["files"] = len(group_by_month(days))
        else:
            written, meta = write_defillama_backfill(
                out_dir,
                rows,
                last_day=window_last,
                first_day=llama_first,
            )
        print(
            f"DeFiLlama: {meta['incidents']} incidents on {meta['incident_days']} days "
            f"in {meta['files']} month shards ({meta['first_day']}..{meta['last_day']})"
            + (f"; before_from_day={meta['before_first_day']}" if llama_first else "")
        )
        source_rows.append(
            {
                "id": "defillama",
                "schema": SCHEMA_DEFILLAMA,
                "method": method,
                "url": url,
                "first_day": meta["first_day"] or "",
                "last_day": meta["last_day"] or "",
                "path": "defillama/by-month/",
                "files": meta["files"],
                "incidents": meta["incidents"],
                "incident_days": meta["incident_days"],
                "after_last_day": meta["after_last_day"],
                "before_first_day": meta["before_first_day"],
            }
        )

    # Smoke / explicit windows keep the requested range. Committed rebuilds
    # keep the documented max window even when only one source is regenerated.
    if args.smoke or args.from_day or args.to_day:
        manifest_first, manifest_last = fmt_day(window_first), fmt_day(window_last)
    else:
        manifest_first, manifest_last = fmt_day(EPSS_FIRST_DAY), fmt_day(LAST_DAY)
    if args.dry_run:
        print(
            f"dry-run: would write manifest {manifest_first}..{manifest_last} "
            f"({len(source_rows)} source(s))"
        )
        return 0
    manifest = _write_manifest(
        out_dir,
        source_rows,
        first_day=manifest_first,
        last_day=manifest_last,
    )
    print(f"wrote {manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
