"""FIRST EPSS derived daily backfill. Never commit raw CSVs."""

from __future__ import annotations

import csv
import json
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import date
from decimal import Decimal, InvalidOperation
from pathlib import Path

from common import (
    EPSS_API_URL,
    EPSS_CSV_URL,
    EPSS_FIRST_DAY,
    EPSS_HIGH_THRESHOLD,
    LAST_DAY,
    MAX_DECOMPRESS_BYTES,
    SAMPLE_CAP,
    SCHEMA_EPSS,
    BodyTooLargeError,
    decompress_gzip_capped,
    each_day,
    fetch_bytes,
    fmt_day,
    write_monthly_shards,
)


def _parse_threshold(value: float | str = EPSS_HIGH_THRESHOLD) -> Decimal:
    return Decimal(str(value))


def _model_version(comment_line: str) -> str:
    # "#model_version:v2026.06.15,score_date:2026-09-04T12:00:22Z"
    text = comment_line.lstrip("#").strip()
    for part in text.split(","):
        if part.startswith("model_version:"):
            return part.split(":", 1)[1].strip()
    return ""


def derive_epss_day(
    raw: bytes,
    day: date,
    *,
    threshold: float = EPSS_HIGH_THRESHOLD,
    sample_cap: int = SAMPLE_CAP,
) -> dict:
    """Derive one day's high-EPSS counts from a daily CSV (gz or plain). Do not keep the CSV."""
    if raw[:2] == b"\x1f\x8b":
        payload = decompress_gzip_capped(raw, label=f"epss {fmt_day(day)}")
    elif len(raw) > MAX_DECOMPRESS_BYTES:
        raise BodyTooLargeError(
            f"{fmt_day(day)}: EPSS CSV exceeds {MAX_DECOMPRESS_BYTES} bytes"
        )
    else:
        payload = raw
    text = payload.decode("utf-8")
    model_version = ""
    body_lines: list[str] = []
    for line in text.splitlines():
        if line.startswith("#"):
            if not model_version:
                model_version = _model_version(line)
            continue
        if line.strip():
            body_lines.append(line)
    if not body_lines:
        raise ValueError(f"{fmt_day(day)}: empty EPSS CSV")

    reader = csv.DictReader(body_lines)
    if not reader.fieldnames or "cve" not in reader.fieldnames or "epss" not in reader.fieldnames:
        raise ValueError(f"{fmt_day(day)}: CSV missing cve/epss columns")

    cutoff = _parse_threshold(threshold)
    high_count = 0
    scored_total = 0
    sample: list[dict[str, str]] = []
    for row in reader:
        cve = (row.get("cve") or "").strip()
        epss_raw = (row.get("epss") or "").strip()
        if not cve or not epss_raw:
            continue
        try:
            epss = Decimal(epss_raw)
        except InvalidOperation:
            continue
        scored_total += 1
        if epss < cutoff:
            continue
        high_count += 1
        if len(sample) < sample_cap:
            # Source document order. A sample of rows above threshold — not a ranking.
            sample.append({"cve": cve, "epss": epss_raw})

    out = {
        "day": fmt_day(day),
        "scored_total": scored_total,
        "high_count": high_count,
        "high_threshold": float(cutoff),
        "sample_cves": sample,
    }
    if model_version:
        out["model_version"] = model_version
    return out


def derive_epss_day_from_api(payload: dict, day: date, *, threshold: float = EPSS_HIGH_THRESHOLD) -> dict:
    """Derive from a FIRST API page. high_count comes from `total` when filtered."""
    rows = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        raise ValueError(f"{fmt_day(day)}: API payload missing data list")
    cutoff = _parse_threshold(threshold)
    sample: list[dict[str, str]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        cve = str(row.get("cve") or "").strip()
        epss_raw = str(row.get("epss") or "").strip()
        if not cve:
            continue
        try:
            if Decimal(epss_raw) < cutoff:
                continue
        except InvalidOperation:
            continue
        if len(sample) < SAMPLE_CAP:
            sample.append({"cve": cve, "epss": epss_raw})
    high = payload.get("total")
    high_count = int(high) if isinstance(high, int) else len(sample)
    scored = payload.get("scored_total")
    out = {
        "day": fmt_day(day),
        "high_count": high_count,
        "high_threshold": float(cutoff),
        "sample_cves": sample,
    }
    if isinstance(scored, int):
        out["scored_total"] = scored
    return out


def fetch_epss_csv(day: date) -> bytes:
    urls = [
        EPSS_CSV_URL.format(day=fmt_day(day)),
        (
            "https://raw.githubusercontent.com/empiricalsec/epss_scores/main/"
            f"{day.year}/epss_scores-{fmt_day(day)}.csv.gz"
        ),
    ]
    last_error: Exception | None = None
    for url in urls:
        try:
            return fetch_bytes(url, timeout=120)
        except urllib.error.HTTPError as exc:
            last_error = exc
            if exc.code in {403, 404}:
                continue
            raise
        except Exception as exc:
            last_error = exc
    if last_error is not None:
        raise last_error
    raise RuntimeError(f"no EPSS CSV URL tried for {fmt_day(day)}")


def fetch_epss_api(day: date, *, threshold: float = EPSS_HIGH_THRESHOLD) -> dict:
    cutoff = _parse_threshold(threshold)
    # epss-gt is inclusive (>=) on the FIRST API.
    high_url = (
        f"{EPSS_API_URL}?date={fmt_day(day)}&epss-gt={cutoff}&limit={SAMPLE_CAP}"
    )
    high_raw = fetch_bytes(high_url, accept="application/json")
    high = json.loads(high_raw.decode("utf-8"))
    total_url = f"{EPSS_API_URL}?date={fmt_day(day)}&limit=1"
    try:
        total_raw = fetch_bytes(total_url, accept="application/json")
        total = json.loads(total_raw.decode("utf-8"))
        if isinstance(total, dict) and isinstance(total.get("total"), int):
            high["scored_total"] = total["total"]
    except Exception:
        pass
    return high


def _one_csv_day(day: date, threshold: float) -> tuple[date, dict | None, str | None]:
    try:
        raw = fetch_epss_csv(day)
        return day, derive_epss_day(raw, day, threshold=threshold), None
    except urllib.error.HTTPError as exc:
        if exc.code in {403, 404}:
            return day, None, "archive_unavailable"
        if exc.code == 429:
            try:
                payload = fetch_epss_api(day, threshold=threshold)
                return day, derive_epss_day_from_api(payload, day, threshold=threshold), None
            except Exception as api_exc:
                return day, None, f"http_429_api:{api_exc}"
        return day, None, f"http_{exc.code}"
    except Exception as exc:
        text = str(exc)
        if "429" in text:
            try:
                payload = fetch_epss_api(day, threshold=threshold)
                return day, derive_epss_day_from_api(payload, day, threshold=threshold), None
            except Exception as api_exc:
                return day, None, f"{text}; api:{api_exc}"
        if "403" in text or "404" in text:
            return day, None, "archive_unavailable"
        return day, None, text


def _one_api_day(day: date, threshold: float) -> tuple[date, dict | None, str | None]:
    try:
        payload = fetch_epss_api(day, threshold=threshold)
        return day, derive_epss_day_from_api(payload, day, threshold=threshold), None
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return day, None, "http_404"
        return day, None, f"http_{exc.code}"
    except Exception as exc:
        return day, None, str(exc)


def derive_epss_from_dir(
    csv_dir: Path,
    *,
    first_day: date = EPSS_FIRST_DAY,
    last_day: date = LAST_DAY,
    threshold: float = EPSS_HIGH_THRESHOLD,
) -> tuple[list[dict], list[str]]:
    """Offline path: read `epss_scores-YYYY-MM-DD.csv` or `.csv.gz` from a directory."""
    days: list[dict] = []
    missing: list[str] = []
    for day in each_day(first_day, last_day):
        key = fmt_day(day)
        candidates = [
            csv_dir / f"epss_scores-{key}.csv.gz",
            csv_dir / f"epss_scores-{key}.csv",
            csv_dir / f"{key}.csv.gz",
            csv_dir / f"{key}.csv",
        ]
        path = next((p for p in candidates if p.exists()), None)
        if path is None:
            missing.append(key)
            continue
        days.append(derive_epss_day(path.read_bytes(), day, threshold=threshold))
    return days, missing


def generate_epss_days(
    *,
    first_day: date = EPSS_FIRST_DAY,
    last_day: date = LAST_DAY,
    method: str = "csv",
    threshold: float = EPSS_HIGH_THRESHOLD,
    workers: int = 8,
    csv_dir: Path | None = None,
    cache_dir: Path | None = None,
) -> tuple[list[dict], list[str]]:
    if csv_dir is not None:
        return derive_epss_from_dir(
            csv_dir,
            first_day=first_day,
            last_day=last_day,
            threshold=threshold,
        )
    if method not in {"csv", "api"}:
        raise ValueError("epss method must be csv or api")
    worker = _one_csv_day if method == "csv" else _one_api_day
    days: list[dict] = []
    missing: list[str] = []
    todo: list[date] = []
    if cache_dir is not None:
        cache_dir.mkdir(parents=True, exist_ok=True)
    for day in each_day(first_day, last_day):
        cached = cache_dir / f"{fmt_day(day)}.json" if cache_dir is not None else None
        if cached is not None and cached.exists():
            days.append(json.loads(cached.read_text(encoding="utf-8")))
            continue
        todo.append(day)
    done = 0
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = [pool.submit(worker, day, threshold) for day in todo]
        for fut in as_completed(futures):
            day, row, error = fut.result()
            done += 1
            if row is not None:
                days.append(row)
                if cache_dir is not None:
                    (cache_dir / f"{fmt_day(day)}.json").write_text(
                        json.dumps(row, ensure_ascii=False) + "\n",
                        encoding="utf-8",
                    )
            else:
                missing.append(f"{fmt_day(day)}:{error or 'error'}")
            if done % 50 == 0 or done == len(todo):
                print(f"EPSS {method}: {done}/{len(todo)} fetched ({len(missing)} missing)", flush=True)
    days.sort(key=lambda row: row["day"])
    missing.sort()
    return days, missing


def write_epss_backfill(
    out_dir: Path,
    days: list[dict],
) -> list[Path]:
    return write_monthly_shards(out_dir / "epss" / "by-month", SCHEMA_EPSS, days)
