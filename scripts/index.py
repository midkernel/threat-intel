#!/usr/bin/env python3
"""Build a day's index from fetched bodies. This is an index, not intelligence."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from xml.etree import ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parent))
from catalog import load_sources

ITEM_CAP = 25
JSON_CAP = 8
INDEX_SCHEMA = "midkernel.threat-intel.index/v1"


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


def feed_items(raw: bytes) -> tuple[str, list[dict[str, str | None]]]:
    """Return ('rss'|'atom'|'unknown', items in document order)."""
    try:
        root = ET.fromstring(_strip_bom(raw))
    except ET.ParseError:
        return "unknown", []

    kind = _local(root.tag).lower()
    items: list[dict[str, str | None]] = []

    if kind == "rss" or kind == "rdf":
        for node in root.iter():
            if _local(node.tag) != "item":
                continue
            items.append(
                _index_item(
                    _child_text(node, "title"),
                    _child_text(node, "link"),
                    _child_text(node, "pubDate") or _child_text(node, "date"),
                    _child_text(node, "guid")
                    or _child_text(node, "id")
                    or _attr(node, "about"),
                )
            )
        return "rss", items

    if kind == "feed":
        for node in root.iter():
            if _local(node.tag) != "entry":
                continue
            link = ""
            for child in list(node):
                if _local(child.tag) != "link":
                    continue
                href = (child.get("href") or "").strip()
                rel = child.get("rel") or "alternate"
                if href and rel in {"alternate", ""}:
                    link = href
                    break
                if href and not link:
                    link = href
            items.append(
                _index_item(
                    _child_text(node, "title"),
                    link,
                    _child_text(node, "published") or _child_text(node, "updated"),
                    _child_text(node, "id"),
                )
            )
        return "atom", items

    return "unknown", []


def _as_date(value: object) -> str:
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


def json_items(data: object) -> list[dict[str, str | None]]:
    """Copy catalog rows already in the JSON. Document order. No scores."""
    if isinstance(data, dict) and isinstance(data.get("vulnerabilities"), list):
        items: list[dict[str, str | None]] = []
        for row in data["vulnerabilities"]:
            if not isinstance(row, dict):
                continue
            cve = _nz(row.get("cveID"))
            items.append(
                _index_item(
                    _nz(row.get("vulnerabilityName")) or cve,
                    "",
                    _nz(row.get("dateAdded")),
                    cve,
                )
            )
        return items

    if isinstance(data, dict) and isinstance(data.get("data"), list):
        items = []
        for row in data["data"]:
            if not isinstance(row, dict):
                continue
            cve = _nz(row.get("cve"))
            items.append(_index_item(cve, "", _nz(row.get("date")), cve))
        return items

    if isinstance(data, list):
        if data and isinstance(data[0], dict) and data[0].get("uid"):
            items = []
            for row in data:
                if not isinstance(row, dict):
                    continue
                uid = _nz(row.get("uid"))
                items.append(_index_item(_nz(row.get("name")) or uid, "", "", uid))
            return items
        items = []
        for row in data:
            if not isinstance(row, dict):
                continue
            name = _nz(row.get("name"))
            if not name:
                continue
            items.append(
                _index_item(
                    name,
                    _nz(row.get("link") or row.get("url")),
                    _as_date(row.get("date")) if row.get("date") not in (None, "") else "",
                    _nz(row.get("id")),
                )
            )
        return items

    return []


def _read_meta(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _body_path(output_dir: Path, src_id: str) -> Path:
    body_path = output_dir / src_id / "body"
    for ext in (".json", ".xml", ""):
        candidate = output_dir / src_id / f"body{ext}"
        if candidate.exists():
            return candidate
    return body_path


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _utc_day() -> str:
    return time.strftime("%Y-%m-%d", time.gmtime())


def build_summary(
    output_dir: Path,
    sources: list[dict[str, str]],
    *,
    day: str | None = None,
) -> str:
    day = day or _utc_day()
    lines = [
        f"# Threat-intel fetch index — {day} UTC",
        "",
        "This file is a day's index of fetched public feeds. It is not ranking,",
        "not a class taxonomy, and not Midkernel intelligence.",
        "",
    ]

    for src in sources:
        meta_path = output_dir / src["id"] / "meta.json"
        body_path = _body_path(output_dir, src["id"])

        lines.append(f"## {src['name']}")
        lines.append("")
        lines.append(f"- id: `{src['id']}`")
        lines.append(f"- url: {src['url']}")
        lines.append(f"- format: {src['format']}")
        lines.append(f"- surface: {src['surface']}")

        if not meta_path.exists():
            lines.append("- http status: (not fetched)")
            lines.append("")
            continue

        meta = _read_meta(meta_path)
        status = meta.get("status")
        lines.append(f"- http status: {status}")
        lines.append(f"- content-type: {meta.get('content_type') or '(none)'}")
        lines.append(f"- byte size: {meta.get('bytes', 0)}")
        if meta.get("error"):
            lines.append(f"- error: {meta['error']}")

        status_ok = isinstance(status, int) and 200 <= status < 300
        if status_ok and body_path.exists():
            raw = body_path.read_bytes()
            if src["format"] in {"rss", "atom"}:
                kind, items = feed_items(raw)
                lines.append(f"- parsed as: {kind}")
                lines.append(f"- item count: {len(items)}")
                shown = items[:ITEM_CAP]
                if shown:
                    lines.append("")
                    lines.append("Items (document order; not ranked):")
                    for item in shown:
                        bit = f"- {item['title']}"
                        if item.get("published_at"):
                            bit += f"  ({item['published_at']})"
                        if item.get("url"):
                            bit += f"  {item['url']}"
                        lines.append(bit)
                    if len(items) > ITEM_CAP:
                        lines.append(
                            f"- … {len(items) - ITEM_CAP} more items in the raw body"
                        )
            elif src["format"] == "json":
                try:
                    data = json.loads(raw.decode("utf-8"))
                    count, preview = json_preview(data)
                    lines.append(f"- catalog row count: {count}")
                    if preview:
                        lines.append("")
                        lines.append("Newest ids/names already in the JSON:")
                        for row in preview:
                            lines.append(f"- {row}")
                except json.JSONDecodeError as exc:
                    lines.append(f"- json parse error: {exc}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def _source_items(
    src: dict[str, str],
    meta: dict | None,
    body_path: Path,
) -> list[dict[str, str | None]]:
    if not meta:
        return []
    status = meta.get("status")
    status_ok = isinstance(status, int) and 200 <= status < 300
    if not status_ok or not body_path.exists():
        return []
    raw = body_path.read_bytes()
    if src["format"] in {"rss", "atom"}:
        _kind, items = feed_items(raw)
        return items
    if src["format"] == "json":
        try:
            data = json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return []
        return json_items(data)
    return []


def build_index(
    output_dir: Path,
    sources: list[dict[str, str]],
    *,
    day: str | None = None,
    generated_at: str | None = None,
) -> dict:
    """Structured day's index. Not ranking, not a class taxonomy."""
    day = day or _utc_day()
    generated_at = generated_at or _utc_now()
    rows: list[dict] = []
    for src in sources:
        meta_path = output_dir / src["id"] / "meta.json"
        body_path = _body_path(output_dir, src["id"])
        meta = _read_meta(meta_path) if meta_path.exists() else None
        items = _source_items(src, meta, body_path)
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
            }
        )
    return {
        "schema": INDEX_SCHEMA,
        "day": day,
        "generated_at": generated_at,
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
) -> tuple[Path, Path]:
    day = day or _utc_day()
    generated_at = generated_at or _utc_now()
    output_dir.mkdir(parents=True, exist_ok=True)
    summary_path = output_dir / "summary.md"
    index_path = output_dir / "index.json"
    summary_path.write_text(
        build_summary(output_dir, sources, day=day),
        encoding="utf-8",
    )
    index_path.write_text(
        json.dumps(
            build_index(
                output_dir,
                sources,
                day=day,
                generated_at=generated_at,
            ),
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    return summary_path, index_path


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    output = Path(sys.argv[1]) if len(sys.argv) > 1 else root / "output"
    sources = load_sources(root / "sources.yaml")
    summary, index = write_outputs(output, sources)
    print(f"wrote {summary}")
    print(f"wrote {index}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
