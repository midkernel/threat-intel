#!/usr/bin/env python3
"""Build a day's index from fetched bodies. This is an index, not intelligence."""

from __future__ import annotations

import csv
import hashlib
import heapq
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from xml.etree import ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parent))
from catalog import load_sources

ITEM_CAP = 25
JSON_CAP = 8
# Max structured items emitted per txt/csv source into the daily index.
# Full raw bodies remain archived; this only bounds ledger-facing itemization.
PLAINTEXT_ITEM_CAP = 500
# abuse.ch recent CSVs can dump well past the ledger cap (URLhaus csv_recent
# carried 14,449 URLs on 2026-10-06). Index every row newer than the last
# run's high-water mark, and stop only at this safety ceiling — with a warning.
ABUSECH_CSV_SAFETY_CEILING = 50_000
INDEX_SCHEMA = "midkernel.threat-intel.index/v1"
logger = logging.getLogger("threat-intel")


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _child_text(node: ET.Element, name: str) -> str:
    for child in list(node):
        if _local(child.tag) == name and child.text:
            return child.text.strip()
    return ""


def _attr(node: ET.Element, name: str) -> str:
    for key, value in node.attrib.items():
        if _local(key) == name and value:
            return value.strip()
    return ""


def _nz(value: object) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _index_item(
    title: str,
    url: str = "",
    published_at: str = "",
    item_id: str = "",
) -> dict[str, str | None]:
    return {
        "title": title or "(untitled)",
        "url": url or None,
        "published_at": published_at or None,
        "id": item_id or None,
    }


def _strip_bom(raw: bytes) -> bytes:
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw[3:]
    return raw


def _native_xml(node: ET.Element) -> dict:
    """Keep repeated names, namespace URIs, attributes and markup without guessing semantics."""
    fields: dict = {}
    for child in node:
        value = {"text": "".join(child.itertext()).strip(), "attributes": dict(child.attrib)}
        if len(child):
            value["xml"] = ET.tostring(child, encoding="unicode")
        fields.setdefault(child.tag, []).append(value)
    return {"tag": node.tag, "attributes": dict(node.attrib), "fields": fields}


def _with_evidence(item: dict, raw: dict, **extra) -> dict:
    item.update({
        "summary": None, "content": None, "modified_at": None,
        "withdrawn_at": None, "aliases": [], "references": [],
        "raw": raw,
        "raw_sha256": hashlib.sha256(json.dumps(raw, sort_keys=True, ensure_ascii=False,
                                                separators=(",", ":")).encode()).hexdigest(),
    })
    item.update(extra)
    return item


def feed_items(raw: bytes) -> tuple[str, list[dict]]:
    """Copy every feed record and its native evidence, including nonstandard Talos IDs."""
    try:
        root = ET.fromstring(_strip_bom(raw))
    except ET.ParseError:
        return "unknown", []
    kind = _local(root.tag).lower()
    if kind not in {"rss", "rdf", "feed"}:
        return "unknown", []
    atom = kind == "feed"
    items = []
    for node in root.iter():
        if _local(node.tag) != ("entry" if atom else "item"):
            continue
        links = [dict(c.attrib) for c in node if _local(c.tag) == "link"]
        link = _child_text(node, "link")
        if atom:
            link = next((x.get("href", "") for x in links if x.get("rel", "alternate") == "alternate"), "")
        item = _index_item(
            _child_text(node, "title"), link,
            (_child_text(node, "published") or _child_text(node, "updated")) if atom else
            (_child_text(node, "pubDate") or _child_text(node, "date")),
            _child_text(node, "guid") or _child_text(node, "id") or
            _child_text(node, "report_id") or _attr(node, "about"),
        )
        references = [x["href"] for x in links if x.get("href")]
        if link and link not in references:
            references.append(link)
        items.append(_with_evidence(item, _native_xml(node),
            summary=_child_text(node, "summary") or _child_text(node, "description") or None,
            content=_child_text(node, "content") or _child_text(node, "encoded") or None,
            modified_at=_child_text(node, "updated") or None,
            references=references))
    return "atom" if atom else "rss", items


def _as_date(value: object) -> str:
    if value in (None, ""):
        return ""
    if isinstance(value, (int, float)) and value > 10_000_000:
        return time.strftime("%Y-%m-%d", time.gmtime(int(value)))
    return str(value).strip()


def json_preview(data: object) -> tuple[int, list[str]]:
    """Count + newest few ids/names already present in the JSON. No scores."""
    if isinstance(data, dict) and isinstance(data.get("vulnerabilities"), list):
        rows = data["vulnerabilities"]
        dated = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            dated.append(
                (
                    str(row.get("dateAdded") or ""),
                    row.get("cveID") or "",
                    row.get("vulnerabilityName") or "",
                )
            )
        dated.sort(reverse=True)
        lines = [
            f"{cve}  {added}  {name}".rstrip()
            for added, cve, name in dated[:JSON_CAP]
            if cve
        ]
        return len(rows), lines

    if isinstance(data, dict) and isinstance(data.get("data"), list):
        rows = data["data"]
        dated = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            dated.append((str(row.get("date") or ""), row.get("cve") or ""))
        dated.sort(reverse=True)
        reported = data.get("total")
        count = int(reported) if isinstance(reported, int) else len(rows)
        lines = [f"{cve}  {day}".rstrip() for day, cve in dated[:JSON_CAP] if cve]
        if isinstance(reported, int) and reported != len(rows):
            lines.insert(0, f"fetched slice: {len(rows)} of {reported} (limit in URL)")
        return count, lines

    if isinstance(data, list):
        if data and isinstance(data[0], dict) and data[0].get("uid"):
            lines = []
            for row in data[:JSON_CAP]:
                if not isinstance(row, dict):
                    continue
                uid = str(row.get("uid") or "").strip()
                sev = str(row.get("severity") or "").strip()
                name = str(row.get("name") or "").strip()
                bit = "  ".join(part for part in (uid, sev, name) if part)
                if bit:
                    lines.append(bit)
            return len(data), lines
        dated = []
        for row in data:
            if not isinstance(row, dict):
                continue
            dated.append((_as_date(row.get("date")), row.get("name") or ""))
        dated.sort(reverse=True)
        lines = [f"{name}  {day}".rstrip() for day, name in dated[:JSON_CAP] if name]
        return len(data), lines

    return 0, ["(no catalog rows recognized; raw body is in the artifact)"]


def json_items(data: object) -> list[dict]:
    """Preserve structured upstream records; upstream scores are evidence, never our ranking."""
    if isinstance(data, dict) and data.get("collector") == "epss":
        return []  # Complete per-CVE rows live in the compressed sidecar.
    # NVD CVE API 2.0: {vulnerabilities: [{cve: {id, published, descriptions, ...}}]}
    if isinstance(data, dict) and isinstance(data.get("vulnerabilities"), list):
        sample = next((row for row in data["vulnerabilities"] if isinstance(row, dict)), None)
        if sample and isinstance(sample.get("cve"), dict):
            items = []
            for row in data["vulnerabilities"]:
                if not isinstance(row, dict) or not isinstance(row.get("cve"), dict):
                    continue
                cve = row["cve"]
                ident = _nz(cve.get("id"))
                if not ident:
                    continue
                descs = cve.get("descriptions") if isinstance(cve.get("descriptions"), list) else []
                title = next(
                    (_nz(d.get("value")) for d in descs
                     if isinstance(d, dict) and d.get("lang") == "en" and _nz(d.get("value"))),
                    "",
                ) or ident
                refs = []
                for ref in cve.get("references") or []:
                    if isinstance(ref, dict) and ref.get("url"):
                        refs.append(ref["url"])
                items.append(_with_evidence(
                    _index_item(title, refs[0] if refs else "", _as_date(cve.get("published")), ident),
                    row,
                    summary=title if title != ident else None,
                    modified_at=_as_date(cve.get("lastModified")) or None,
                    references=refs,
                ))
            return items
    kev = isinstance(data, dict) and isinstance(data.get("vulnerabilities"), list)
    rows = data.get("vulnerabilities") if kev else (
        data.get("records", data.get("data", [])) if isinstance(data, dict) else data)
    if not isinstance(rows, list):
        return []
    items = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        cve_meta = row.get("cveMetadata") if isinstance(row.get("cveMetadata"), dict) else {}
        cna = row.get("containers", {}).get("cna", {}) if cve_meta else {}
        if cve_meta:
            title, ident, published = cna.get("title"), cve_meta.get("cveId"), cve_meta.get("datePublished")
        elif kev:
            title, ident, published = row.get("vulnerabilityName"), row.get("cveID"), row.get("dateAdded")
        elif row.get("ghsa_id"):
            title, ident, published = row.get("summary"), row.get("ghsa_id"), row.get("published_at")
        elif row.get("id") and ("affected" in row or "modified" in row):
            title, ident, published = row.get("summary"), row.get("id"), row.get("published")
        elif row.get("uid"):
            title, ident, published = row.get("name"), row.get("uid"), None
        elif row.get("cve"):
            title, ident, published = row.get("cve"), row.get("cve"), row.get("date")
        elif row.get("ip"):
            # SANS ISC intelfeed and similar IP reputation JSON arrays
            title = row.get("description") or row.get("ip")
            ident, published = row.get("ip"), row.get("date")
        elif row.get("title") and (row.get("victim") is not None or row.get("claim_gang") is not None
                                   or row.get("group") is not None):
            # ransomware.live recentcyberattacks (and similar incident JSON)
            title = row.get("title")
            ident = row.get("id") or row.get("domain") or row.get("link") or row.get("url")
            published = row.get("date") or row.get("added") or row.get("discovered")
        elif row.get("group") and (row.get("domain") or row.get("victim")):
            # ransomware.live recentvictims (domain may be empty for some claims)
            victim = _nz(row.get("victim")) or _nz(row.get("domain"))
            title = f"{row.get('group')}: {victim}"
            ident = _nz(row.get("domain")) or victim
            published = row.get("discovered") or row.get("attackdate") or row.get("date") or row.get("added")
        else:
            title, ident, published = row.get("name"), row.get("id"), row.get("date")
        if not (title or ident):
            continue
        refs = cna.get("references", []) if cve_meta else row.get("references") if isinstance(row.get("references"), list) else []
        aliases = list(row.get("aliases") or [])
        aliases += [x["value"] for x in row.get("identifiers", []) if isinstance(x, dict) and x.get("value")]
        if row.get("cve_id"):
            aliases.append(row["cve_id"])
        url = ""
        for key in ("html_url", "link", "url", "claim_url", "source", "linkSource"):
            value = row.get(key)
            if isinstance(value, str) and value.strip() and value.strip().lower() not in {"false", "none"}:
                url = value.strip()
                break
        items.append(_with_evidence(_index_item(_nz(title or ident), _nz(url), _as_date(published), _nz(ident)),
            row, summary=row.get("summary") or row.get("shortDescription") or row.get("description") or cna.get("title"),
            content=row.get("details") or row.get("description") or "\n".join(x.get("value", "") for x in cna.get("descriptions", []) if isinstance(x, dict)) or None,
            modified_at=row.get("modified") or row.get("updated_at") or cve_meta.get("dateUpdated"),
            withdrawn_at=row.get("withdrawn") or row.get("withdrawn_at") or cve_meta.get("dateRejected"),
            aliases=sorted(set(aliases)), references=refs))
    return items


_CSV_VALUE_KEYS = (
    "url", "URL", "ioc", "IOC", "indicator", "Indicator",
    "domain", "Domain", "AdresDomeny", "host", "Host",
    "ip", "IP", "dstip", "DstIP", "srcip",
    "sha256", "SHA256", "sha1", "md5", "hash", "Hash",
    "cve", "CVE", "cve_id", "cveID", "ioc_value", "ip_address", "ja3_md5", "value", "Value", "name", "Name", "title", "Title",
)
_CSV_ID_KEYS = (
    "id", "ID", "PozycjaRejestru", "uid", "UUID", "sha256", "SHA256", "cve", "CVE", "cveID",
)
_CSV_URL_KEYS = ("url", "URL", "urlhaus_link", "link", "Link", "reference", "Reference")
_CSV_DATE_KEYS = (
    "dateadded", "date_added", "date", "Date", "DataWpisu", "published", "timestamp",
    "first_seen_utc", "first_seen", "firstseen", "last_seen", "lastseen",
    "discovered", "datetime", "Listingdate",
)


def _csv_pick(row: dict[str, str], keys: tuple[str, ...]) -> str:
    lower = {k.lower(): v for k, v in row.items()}
    for key in keys:
        value = row.get(key) or lower.get(key.lower())
        if value and str(value).strip() and str(value).strip().lower() not in {"none", "null"}:
            return str(value).strip()
    return ""


_CSV_HEADER_KEYS = {key.lower() for key in (*_CSV_VALUE_KEYS, *_CSV_ID_KEYS, *_CSV_URL_KEYS, *_CSV_DATE_KEYS)}


def _text_lines(text: str):
    """Yield lines without retaining a second list of the whole CSV."""
    start = 0
    length = len(text)
    while start < length:
        end = text.find("\n", start)
        if end == -1:
            line = text[start:]
            start = length
        else:
            line = text[start:end]
            start = end + 1
        if line.endswith("\r"):
            line = line[:-1]
        yield line


def _comment_header(text: str) -> list[str] | None:
    """Last # comment that names known columns, matching the historical parser."""
    header: list[str] | None = None
    for line in _text_lines(text):
        stripped = line.strip()
        if not stripped.startswith("#"):
            continue
        candidate = stripped.lstrip("#").strip()
        if not candidate or ("," not in candidate and "\t" not in candidate):
            continue
        delim = "\t" if candidate.count("\t") > candidate.count(",") else ","
        columns = next(csv.reader([candidate], delimiter=delim, skipinitialspace=True))
        if any(part.strip().lower() in _CSV_HEADER_KEYS for part in columns):
            header = [part.strip() for part in columns]
    return header


def _iter_csv_rows(raw: bytes):
    """Stream data rows as (header, cells). Does not retain parsed rows."""
    text = raw.decode("utf-8-sig", errors="replace")
    header = _comment_header(text)

    def data_lines():
        for line in _text_lines(text):
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                yield stripped

    lines = data_lines()
    try:
        first = next(lines)
    except StopIteration:
        return
    delimiter = "\t" if first.count("\t") > first.count(",") else ","

    def chained():
        yield first
        yield from lines

    reader = csv.reader(chained(), delimiter=delimiter, skipinitialspace=True)
    header_locked = header is not None
    for row in reader:
        if not any(cell.strip() for cell in row):
            continue
        if not header_locked:
            # Match whole column names; IOC values and CVE IDs are not headers.
            if any(cell.strip().lower() in _CSV_HEADER_KEYS for cell in row):
                header = [cell.strip() for cell in row]
                header_locked = True
                continue
            header_locked = True
        yield header, row


def _row_instant(value: str) -> datetime | None:
    """UTC instant for first_seen/dateadded high-water comparisons."""
    text = value.strip()
    if not text or text.lower() in {"none", "null"}:
        return None
    if text.isdigit():
        try:
            return datetime.fromtimestamp(int(text), timezone.utc).replace(microsecond=0)
        except (OverflowError, OSError, ValueError):
            return None
    normalized = text.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        try:
            parsed = datetime.strptime(text[:10], "%Y-%m-%d")
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).replace(microsecond=0)


def _instant_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _csv_record(header: list[str] | None, row_cells: list[str]) -> tuple[dict, datetime | None] | None:
    """One index item plus the row's first_seen/dateadded instant, if any."""
    if header and len(header) >= 1:
        mapped = {header[i]: row_cells[i] if i < len(row_cells) else "" for i in range(len(header))}
        value = _csv_pick(mapped, _CSV_VALUE_KEYS)
        if not value:
            value = next((str(v).strip() for v in mapped.values() if str(v).strip()), "")
        ident = _csv_pick(mapped, _CSV_ID_KEYS) or value
        url = _csv_pick(mapped, _CSV_URL_KEYS)
        if not url and value.startswith(("http://", "https://")):
            url = value
        published_raw = _csv_pick(mapped, _CSV_DATE_KEYS)
        published = _as_date(published_raw)
        raw_row: dict = mapped
        instant = _row_instant(published_raw)
    else:
        value = (row_cells[0] if row_cells else "").strip().strip('"')
        if not value:
            return None
        ident = value
        url = value if value.startswith(("http://", "https://")) else ""
        published = ""
        raw_row = {"columns": row_cells}
        instant = None
    if not value:
        return None
    item = _with_evidence(_index_item(value, url, published, ident), raw_row, summary=None)
    return item, instant


def csv_items(raw: bytes, *, cap: int = PLAINTEXT_ITEM_CAP) -> tuple[int, list[dict]]:
    """Line/row → bounded index items for CSV/TSV IOC and catalog downloads."""
    items: list[dict] = []
    received = 0
    for header, row_cells in _iter_csv_rows(raw):
        received += 1
        built = _csv_record(header, row_cells)
        if built is None or len(items) >= cap:
            continue
        items.append(built[0])
    return received, items


def _is_abusech_csv(src: dict) -> bool:
    if src.get("format") != "csv":
        return False
    ident = str(src.get("id") or "")
    url = str(src.get("url") or "")
    return ident.startswith("abuse-ch-") or "abuse.ch" in url.lower()


class AbusechCsvIngest:
    """Rows at or newer than the previous high-water mark, bounded by the safety ceiling."""

    def __init__(self) -> None:
        self.received = 0
        self.items: list[dict] = []
        self.skipped_existing = 0
        self.truncated = False
        self.previous_high_water: str | None = None
        self.high_water: str | None = None


def ingest_abusech_csv(
    raw: bytes,
    *,
    high_water: str | None,
    ceiling: int,
    source_id: str,
) -> AbusechCsvIngest:
    """Stream an abuse.ch CSV and keep every row at or newer than ``high_water``.

    abuse.ch writes same-second batches. The mark is that second, so a later
    export can still contain new ids at exactly the mark. Those rows are kept;
    rows strictly older than the mark are not. Re-sending the mark second is
    safe because the app upserts on source id. When more than ``ceiling``
    eligible rows are present, keep the oldest ones so the mark can advance
    contiguously, and log a warning. The ceiling holds the mark strictly below
    the newest evicted timestamp, so an unfinished second stays eligible.
    """
    result = AbusechCsvIngest()
    previous = _row_instant(high_water) if high_water else None
    result.previous_high_water = _instant_text(previous) if previous else None
    if ceiling < 1:
        raise ValueError("abuse.ch CSV safety ceiling must be positive")
    # Min-heap evicts the newest dated row (and undated rows first) once full.
    # Tuple prefix is unique via seq, so item dicts are never compared.
    heap: list[tuple] = []
    eligible = 0
    evicted_min: datetime | None = None
    seq = 0
    for header, row_cells in _iter_csv_rows(raw):
        result.received += 1
        built = _csv_record(header, row_cells)
        if built is None:
            continue
        item, instant = built
        if previous is not None and (instant is None or instant < previous):
            result.skipped_existing += 1
            continue
        eligible += 1
        seq += 1
        if instant is None:
            key = (0, 0, -seq)
        else:
            key = (1, -instant.timestamp(), -seq)
        heapq.heappush(heap, (key, seq, item, instant))
        if len(heap) > ceiling:
            popped = heapq.heappop(heap)
            popped_instant = popped[3]
            if isinstance(popped_instant, datetime):
                evicted_min = popped_instant if evicted_min is None else min(evicted_min, popped_instant)
    result.truncated = eligible > ceiling
    result.items = [entry[2] for entry in sorted(heap, key=lambda entry: entry[1])]
    selected = [entry[3] for entry in heap if isinstance(entry[3], datetime)]
    advanced: datetime | None = None
    if not result.truncated:
        if selected:
            advanced = max(selected)
    elif evicted_min is None:
        if selected:
            advanced = max(selected)
    else:
        fully_kept = [instant for instant in selected if instant < evicted_min]
        if fully_kept:
            advanced = max(fully_kept)
    if advanced is not None and (previous is None or advanced > previous):
        result.high_water = _instant_text(advanced)
    else:
        result.high_water = result.previous_high_water
    if result.truncated:
        logger.warning(
            "abuse.ch CSV safety ceiling hit for %s: indexed %s of %s rows at or newer than %s (ceiling %s)",
            source_id,
            len(result.items),
            eligible,
            result.previous_high_water or "bootstrap",
            ceiling,
        )
    return result


def _read_abusech_state(state_dir: Path | None, src_id: str) -> dict:
    if state_dir is None:
        return {}
    path = state_dir / f"{src_id}.json"
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _filter_mark(state: dict, body_sha: str | None) -> str | None:
    """Re-indexing the same body repeats that run; a new body uses the saved mark."""
    if body_sha and state.get("body_sha256") == body_sha:
        previous = state.get("previous_high_water")
        return previous if isinstance(previous, str) and previous.strip() else None
    current = state.get("high_water")
    return current if isinstance(current, str) and current.strip() else None


def _commit_abusech_state(
    state_dir: Path,
    src_id: str,
    *,
    used_mark: str | None,
    stored_mark: str | None,
    body_sha: str,
) -> None:
    path = state_dir / f"{src_id}.json"
    data = _read_abusech_state(state_dir, src_id)
    data["previous_high_water"] = used_mark
    data["high_water"] = stored_mark
    data["body_sha256"] = body_sha
    state_dir.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)


def text_items(raw: bytes, *, cap: int = PLAINTEXT_ITEM_CAP) -> tuple[int, list[dict]]:
    """Line → bounded index items for plaintext IOC / blocklist downloads."""
    text = raw.decode("utf-8-sig", errors="replace")
    received = 0
    items: list[dict] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        # Spamhaus DROP: "CIDR ; SBL…" — keep the network, drop the comment.
        value = stripped if stripped.startswith(("http://", "https://")) else stripped.split(";", 1)[0].strip()
        # AlienVault reputation.data: IP#score#categories…
        if "#" in value and not value.startswith(("http://", "https://")):
            value = value.split("#", 1)[0].strip()
        if not value:
            continue
        received += 1
        if len(items) >= cap:
            continue
        url = value if value.startswith(("http://", "https://")) else ""
        items.append(_with_evidence(
            _index_item(value, url, "", value),
            {"line": stripped},
        ))
    return received, items


def source_details(
    src: dict,
    meta: dict | None,
    body_path: Path,
    *,
    high_water: str | None = None,
    abusech_ceiling: int | None = None,
) -> tuple[list, dict]:
    """Report failed/partial parsing distinctly from a successfully empty observation."""
    status = {"fetch": "not_fetched", "parse": "not_attempted", "completeness": "unknown",
              "coverage": "rolling_window" if src["format"] in {"rss", "atom"} else "full_snapshot",
              "reasons": [], "received_count": 0, "parsed_count": 0, "rejected_count": 0}
    extra = {"status": status, "body_sha256": None, "diagnostics": []}
    if not meta:
        status["reasons"].append("not_fetched")
        return [], extra
    extra["diagnostics"] = meta.get("diagnostics", [])
    if meta.get("provenance"):
        extra["provenance"] = meta["provenance"]
    ok = isinstance(meta.get("status"), int) and 200 <= meta["status"] < 300
    status["fetch"] = "ok" if ok else "error"
    if not ok or not body_path.exists():
        status["reasons"].append("http_error" if not ok else "missing_body")
        if meta.get("time_budget_exhausted"):
            status["reasons"].append("collection_time_budget_exhausted")
        return [], extra
    raw = body_path.read_bytes()
    extra["body_sha256"] = hashlib.sha256(raw).hexdigest()
    data = None
    abusech_checkpoint = None
    try:
        if src["format"] in {"rss", "atom"}:
            kind, items = feed_items(raw)
            if kind == "unknown":
                raise ValueError("unrecognized or malformed XML feed")
            status["received_count"] = len(items)
            status["reasons"].append("rolling_feed_has_no_historical_completeness_guarantee")
        elif src["format"] == "txt":
            received, items = text_items(raw)
            status["received_count"] = received
            status["completeness"] = "complete"
            if received > len(items):
                status["completeness"] = "partial"
                status["reasons"].append("bounded_item_cap")
        elif src["format"] == "csv" and _is_abusech_csv(src):
            ceiling = ABUSECH_CSV_SAFETY_CEILING if abusech_ceiling is None else abusech_ceiling
            ingested = ingest_abusech_csv(
                raw, high_water=high_water, ceiling=ceiling, source_id=str(src.get("id") or "")
            )
            items = ingested.items
            status["received_count"] = ingested.received
            status["coverage"] = "incremental"
            status["completeness"] = "partial" if ingested.truncated else "complete"
            if ingested.truncated:
                status["reasons"].append("bounded_item_cap")
            if ingested.skipped_existing:
                status["reasons"].append("incremental_high_water")
            abusech_checkpoint = {
                "high_water": ingested.high_water,
                "previous_high_water": ingested.previous_high_water,
                "safety_ceiling": ceiling,
                "ceiling_hit": ingested.truncated,
                "commit": True,
            }
        elif src["format"] == "csv":
            received, items = csv_items(raw)
            status["received_count"] = received
            status["completeness"] = "complete"
            if received > len(items):
                status["completeness"] = "partial"
                status["reasons"].append("bounded_item_cap")
        else:
            data = json.loads(raw.decode("utf-8-sig"))
            items = json_items(data)
            if isinstance(data, dict) and data.get("collector"):
                status.update(data.get("status", {}))
                for key in ("statistics", "snapshot", "checkpoint", "raw"):
                    if key in data:
                        extra[key] = data[key]
            else:
                if isinstance(data, dict) and isinstance(data.get("vulnerabilities"), list):
                    rows = data["vulnerabilities"]
                else:
                    rows = data if isinstance(data, list) else (
                        data.get("vulnerabilities", data.get("data")) if isinstance(data, dict) else None)
                if not isinstance(rows, list):
                    raise ValueError("unrecognized JSON catalog")
                status["received_count"] = len(rows)
                status["completeness"] = "complete"
                # Homogeneous IP-reputation JSON arrays (e.g. SANS ISC intelfeed) can be
                # 100k+ rows — share the plaintext ledger cap so the daily index stays bounded.
                if (isinstance(data, list) and data and isinstance(data[0], dict)
                        and "ip" in data[0] and not any(k in data[0] for k in ("cveID", "ghsa_id", "uid"))):
                    if len(items) > PLAINTEXT_ITEM_CAP:
                        items = items[:PLAINTEXT_ITEM_CAP]
                        status["completeness"] = "partial"
                        status["reasons"].append("bounded_item_cap")
                if isinstance(data, dict):
                    extra["raw"] = {k: v for k, v in data.items() if k not in {"vulnerabilities", "data"}}
                    if isinstance(data.get("totalResults"), int) and data["totalResults"] > len(rows):
                        status["completeness"] = "partial"
                        status["reasons"].append("bounded_api_slice")
                    if isinstance(data.get("total"), int) and data["total"] > len(rows):
                        status["completeness"] = "partial"
                        status["reasons"].append("bounded_api_slice")
                    if isinstance(data.get("resultsPerPage"), int) and isinstance(data.get("totalResults"), int):
                        if data["totalResults"] > len(rows):
                            status["completeness"] = "partial"
                            if "bounded_api_slice" not in status["reasons"]:
                                status["reasons"].append("bounded_api_slice")
                    if isinstance(data.get("count"), int) and data["count"] != len(rows):
                        status["completeness"] = "partial"
                        status["reasons"].append("catalog_count_mismatch")
        status["parse"] = "ok"
        status["parsed_count"] = len(items)
        if src["format"] in {"txt", "csv"} or "bounded_item_cap" in status["reasons"]:
            # Cap truncates intentionally; remaining rows are archived, not rejected.
            status["rejected_count"] = 0
        elif not (isinstance(data, dict) and data.get("collector")):
            status["rejected_count"] = max(0, status["received_count"] - len(items))
            if status["rejected_count"]:
                status["completeness"] = "partial"
                status["reasons"].append("rejected_records")
        if meta.get("error"):
            status["completeness"] = "partial"
            status["reasons"].append(meta["error"])
        if abusech_checkpoint is not None:
            extra["checkpoint"] = abusech_checkpoint
        return items, extra
    except (ValueError, TypeError, UnicodeDecodeError) as exc:
        status["parse"] = "error"
        status["reasons"].append("parse_error")
        extra["diagnostics"].append({"stage": "parse", "message": str(exc)[:400]})
        return [], extra


def _read_meta(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _body_path(output_dir: Path, src_id: str) -> Path:
    body_path = output_dir / src_id / "body"
    for ext in (".json", ".xml", ".txt", ".csv", ""):
        candidate = output_dir / src_id / f"body{ext}"
        if candidate.exists():
            return candidate
    return body_path


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _utc_day() -> str:
    return time.strftime("%Y-%m-%d", time.gmtime())


def render_summary(document: dict) -> str:
    lines = [f"# Threat-intel fetch index — {document['day']} UTC", "",
             "Public evidence in source order; not ranking or a Midkernel class taxonomy.", ""]
    for src in document["sources"]:
        status = src["status"]
        lines += [f"## {src['name']}", "", f"- id: `{src['id']}`", f"- url: {src['url']}",
                  f"- http status: {src['http_status']}",
                  f"- parse: {status['parse']}; coverage: {status['coverage']}; completeness: {status['completeness']}",
                  f"- indexed items: {src['item_count']}; rejected: {status['rejected_count']}"]
        if status['reasons']:
            lines.append("- completeness notes: " + "; ".join(status['reasons']))
        if src.get("statistics"):
            stats = src['statistics']
            lines.append(f"- EPSS stock on {stats['score_date']}: {stats['scored_total']} scored CVEs; {stats['high_count']} at or above {stats['high_threshold']}")
            lines.append(f"- complete per-CVE artifact: {src['snapshot']['path']}")
        for item in src['items'][:ITEM_CAP]:
            lines.append(f"- {item['title']}" + (f" ({item['published_at']})" if item.get('published_at') else "") +
                         (f" {item['url']}" if item.get('url') else ""))
        lines.append("")
    return "\n".join(lines)



def build_summary(output_dir: Path, sources: list[dict], *, day: str | None = None) -> str:
    return render_summary(build_index(output_dir, sources, day=day))


def build_index(
    output_dir: Path,
    sources: list[dict[str, str]],
    *,
    day: str | None = None,
    generated_at: str | None = None,
    state_dir: Path | None = None,
    abusech_ceiling: int | None = None,
) -> dict:
    """Structured day's index. Not ranking, not a class taxonomy."""
    day = day or _utc_day()
    generated_at = generated_at or _utc_now()
    rows: list[dict] = []
    for src in sources:
        meta_path = output_dir / src["id"] / "meta.json"
        body_path = _body_path(output_dir, src["id"])
        meta = _read_meta(meta_path) if meta_path.exists() else None
        abusech = _is_abusech_csv(src)
        state = _read_abusech_state(state_dir, src["id"]) if abusech else {}
        body_sha = None
        if abusech and body_path.exists():
            body_sha = hashlib.sha256(body_path.read_bytes()).hexdigest()
        used_mark = _filter_mark(state, body_sha) if abusech else None
        items, details = source_details(
            src, meta, body_path, high_water=used_mark, abusech_ceiling=abusech_ceiling,
        )
        checkpoint = details.get("checkpoint")
        if isinstance(checkpoint, dict) and checkpoint.pop("commit", False):
            if state_dir is not None and isinstance(details.get("body_sha256"), str):
                _commit_abusech_state(
                    state_dir,
                    src["id"],
                    used_mark=used_mark,
                    stored_mark=checkpoint.get("high_water") if isinstance(checkpoint.get("high_water"), str) else used_mark,
                    body_sha=details["body_sha256"],
                )
        status = meta.get("status") if meta else None
        fetched_at = None
        if meta and meta.get("fetched_at"):
            fetched_at = str(meta["fetched_at"]).strip() or None
        rows.append(
            {
                "id": src["id"],
                "name": src["name"],
                "url": src["url"],
                "format": src["format"],
                "surface": src["surface"],
                "http_status": status if isinstance(status, int) else None,
                "fetched_at": fetched_at,
                "item_count": len(items),
                "items": items,
                **details,
            }
        )
    return {
        "schema": INDEX_SCHEMA,
        "day": day,
        "generated_at": generated_at,
        "parser_version": "2",
        "run_id": os.environ.get("COLLECTION_RUN_ID") or None,
        "archive_url": os.environ.get("COLLECTION_RELEASE_URL") or None,
        "note": (
            "Day's index of fetched public feeds. Not ranking, not a class "
            "taxonomy, and not Midkernel intelligence."
        ),
        "sources": rows,
    }


def write_outputs(
    output_dir: Path,
    sources: list[dict[str, str]],
    *,
    day: str | None = None,
    generated_at: str | None = None,
    state_dir: Path | None = None,
    abusech_ceiling: int | None = None,
) -> tuple[Path, Path]:
    day = day or _utc_day()
    generated_at = generated_at or _utc_now()
    output_dir.mkdir(parents=True, exist_ok=True)
    document = build_index(
        output_dir,
        sources,
        day=day,
        generated_at=generated_at,
        state_dir=state_dir,
        abusech_ceiling=abusech_ceiling,
    )
    summary_path = output_dir / "summary.md"
    index_path = output_dir / "index.json"
    summary_path.write_text(render_summary(document), encoding="utf-8")
    index_path.write_text(
        json.dumps(document, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return summary_path, index_path


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    output = Path(sys.argv[1]) if len(sys.argv) > 1 else root / "output"
    sources = load_sources(root / "sources.yaml")
    state = Path(os.environ.get("COLLECTION_STATE", root / "collection-state"))
    summary, index = write_outputs(output, sources, state_dir=state)
    print(f"wrote {summary}")
    print(f"wrote {index}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
