"""Shared constants and helpers for historical backfill. Package and cite only."""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request
from datetime import date, datetime, timedelta
from pathlib import Path

# Official windows. Do not invent RSS daily-* Releases to fill gaps.
EPSS_FIRST_DAY = date(2021, 4, 14)
KEV_FIRST_DAY = date(2021, 11, 3)
# Day before the first midkernel/threat-intel daily Release (daily-2026-09-05).
LAST_DAY = date(2026, 9, 4)

SCHEMA_MANIFEST = "midkernel.threat-intel.backfill.manifest/v1"
SCHEMA_KEV = "midkernel.threat-intel.backfill.kev/v1"
SCHEMA_EPSS = "midkernel.threat-intel.backfill.epss/v1"
SCHEMA_DEFILLAMA = "midkernel.threat-intel.backfill.defillama/v1"

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
DEFILLAMA_URL = "https://api.llama.fi/hacks"
EPSS_CSV_URL = "https://epss.empiricalsecurity.com/epss_scores-{day}.csv.gz"
EPSS_API_URL = "https://api.first.org/data/v1/epss"

# Fixed threshold. Not a Midkernel score. Documented in backfill/README.md.
EPSS_HIGH_THRESHOLD = 0.5
SAMPLE_CAP = 8

USER_AGENT = "MidkernelThreatIntel/0.1 (+https://github.com/midkernel/threat-intel)"
DAY_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
MONTH_RE = re.compile(r"^\d{4}-\d{2}$")

# Ranking / class / Midkernel-score keys must never appear on backfill documents.
FORBIDDEN_KEYS = {
    "rank",
    "ranking",
    "score",
    "scores",
    "class",
    "classes",
    "taxonomy",
    "threat",
    "midkernel_score",
    "midkernel_scores",
}


def parse_day(value: str) -> date:
    text = str(value).strip()
    if not DAY_RE.match(text):
        raise ValueError(f"expected YYYY-MM-DD, got {value!r}")
    return datetime.strptime(text, "%Y-%m-%d").date()


def fmt_day(value: date) -> str:
    return value.isoformat()


def month_key(value: date) -> str:
    return value.strftime("%Y-%m")


def each_day(start: date, end: date):
    if end < start:
        return
    current = start
    while current <= end:
        yield current
        current += timedelta(days=1)


def group_by_month(days: list[dict]) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = {}
    for row in days:
        day = parse_day(row["day"])
        grouped.setdefault(month_key(day), []).append(row)
    for month in grouped:
        grouped[month].sort(key=lambda row: row["day"])
    return grouped


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def write_month_shard(
    directory: Path,
    schema: str,
    month: str,
    days: list[dict],
) -> Path:
    if not MONTH_RE.match(month):
        raise ValueError(f"expected YYYY-MM, got {month!r}")
    path = directory / f"{month}.json"
    write_json(
        path,
        {
            "schema": schema,
            "month": month,
            "days": days,
        },
    )
    return path


def write_monthly_shards(
    directory: Path,
    schema: str,
    days: list[dict],
) -> list[Path]:
    directory.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for month, month_days in group_by_month(days).items():
        written.append(write_month_shard(directory, schema, month, month_days))
    return written


def fetch_bytes(
    url: str,
    *,
    accept: str | None = None,
    timeout: int = 90,
    retries: int = 4,
) -> bytes:
    headers = {"User-Agent": USER_AGENT}
    if accept:
        headers["Accept"] = accept
    last_error: Exception | None = None
    for attempt in range(retries):
        request = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.read()
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                raise
            last_error = exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_error = exc
        time.sleep(min(2**attempt, 16))
    raise RuntimeError(f"fetch failed after {retries} tries: {url} ({last_error})")


def as_utc_day(value: object) -> str:
    if isinstance(value, (int, float)) and value > 10_000_000:
        return time.strftime("%Y-%m-%d", time.gmtime(int(value)))
    text = str(value).strip()
    if "T" in text:
        text = text.split("T", 1)[0]
    return parse_day(text).isoformat()


def assert_no_forbidden_keys(obj: object, *, path: str = "$") -> None:
    if isinstance(obj, dict):
        overlap = FORBIDDEN_KEYS & set(obj)
        if overlap:
            raise ValueError(f"{path}: forbidden ranking/class keys {sorted(overlap)}")
        for key, value in obj.items():
            assert_no_forbidden_keys(value, path=f"{path}.{key}")
    elif isinstance(obj, list):
        for i, value in enumerate(obj):
            assert_no_forbidden_keys(value, path=f"{path}[{i}]")


def load_simple_yaml(path: Path) -> dict:
    """Constrained YAML (scalars + one list of maps). No PyYAML dependency."""
    text = path.read_text(encoding="utf-8")
    doc: dict = {}
    current_list: list | None = None
    current_item: dict | None = None
    list_key: str | None = None

    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        if line.startswith("  - "):
            if current_list is None:
                raise ValueError(f"{path}:{lineno}: list item without a list key")
            if current_item is not None:
                current_list.append(current_item)
            current_item = {}
            rest = line[4:]
            if ":" not in rest:
                raise ValueError(f"{path}:{lineno}: expected 'key: value'")
            key, value = rest.split(":", 1)
            current_item[key.strip()] = _yaml_scalar(value)
            continue
        if line.startswith("    ") and current_item is not None:
            rest = line.strip()
            if ":" not in rest:
                raise ValueError(f"{path}:{lineno}: expected 'key: value'")
            key, value = rest.split(":", 1)
            current_item[key.strip()] = _yaml_scalar(value)
            continue
        if line.endswith(":") and ":" == line.strip()[-1] and line.count(":") == 1:
            if current_item is not None and current_list is not None:
                current_list.append(current_item)
                current_item = None
            key = line.strip()[:-1]
            current_list = []
            list_key = key
            doc[key] = current_list
            continue
        if ":" not in line:
            raise ValueError(f"{path}:{lineno}: expected 'key: value'")
        if current_item is not None and current_list is not None:
            current_list.append(current_item)
            current_item = None
            current_list = None
            list_key = None
        key, value = line.split(":", 1)
        doc[key.strip()] = _yaml_scalar(value)
        current_list = None
        list_key = None

    if current_item is not None and current_list is not None:
        current_list.append(current_item)
    if list_key and current_list is not None:
        doc[list_key] = current_list
    return doc


def _yaml_scalar(value: str) -> object:
    text = value.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in {"'", '"'}:
        return text[1:-1]
    if text in {"true", "True"}:
        return True
    if text in {"false", "False"}:
        return False
    if text in {"null", "Null", "~", ""}:
        return None
    try:
        if "." in text:
            return float(text)
        return int(text)
    except ValueError:
        return text


def dump_simple_yaml(payload: dict) -> str:
    lines: list[str] = []

    def emit_scalar(value: object) -> str:
        if isinstance(value, bool):
            return "true" if value else "false"
        if value is None:
            return "null"
        if isinstance(value, (int, float)):
            return str(value)
        text = str(value)
        if text == "" or any(ch in text for ch in ":#\n") or text[:1] in {"'", '"'}:
            return json.dumps(text, ensure_ascii=False)
        return text

    for key, value in payload.items():
        if isinstance(value, list):
            lines.append(f"{key}:")
            for item in value:
                if not isinstance(item, dict):
                    raise TypeError("manifest lists must contain maps")
                first = True
                for item_key, item_value in item.items():
                    prefix = "  - " if first else "    "
                    lines.append(f"{prefix}{item_key}: {emit_scalar(item_value)}")
                    first = False
            continue
        lines.append(f"{key}: {emit_scalar(value)}")
    return "\n".join(lines) + "\n"
