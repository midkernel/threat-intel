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


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _child_text(node: ET.Element, name: str) -> str:
    for child in list(node):
        if _local(child.tag) == name and child.text:
            return child.text.strip()
    return ""


def _strip_bom(raw: bytes) -> bytes:
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw[3:]
    return raw


def feed_items(raw: bytes) -> tuple[str, list[dict[str, str]]]:
    """Return ('rss'|'atom'|'unknown', items in document order)."""
    try:
        root = ET.fromstring(_strip_bom(raw))
    except ET.ParseError:
        return "unknown", []

    kind = _local(root.tag).lower()
    items: list[dict[str, str]] = []

    if kind == "rss" or kind == "rdf":
        for node in root.iter():
            if _local(node.tag) != "item":
                continue
            link = _child_text(node, "link")
            pub = _child_text(node, "pubDate") or _child_text(node, "date")
            items.append(
                {
                    "title": _child_text(node, "title") or "(untitled)",
                    "link": link,
                    "pubDate": pub,
                }
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
                {
                    "title": _child_text(node, "title") or "(untitled)",
                    "link": link,
                    "pubDate": _child_text(node, "published")
                    or _child_text(node, "updated"),
                }
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
        dated = []
        for row in data:
            if not isinstance(row, dict):
                continue
            dated.append((_as_date(row.get("date")), row.get("name") or ""))
        dated.sort(reverse=True)
        lines = [f"{name}  {day}".rstrip() for day, name in dated[:JSON_CAP] if name]
        return len(data), lines

    return 0, ["(no catalog rows recognized; raw body is in the artifact)"]


def _read_meta(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def build_summary(output_dir: Path, sources: list[dict[str, str]]) -> str:
    day = time.strftime("%Y-%m-%d", time.gmtime())
    lines = [
        f"# Threat-intel fetch index — {day} UTC",
        "",
        "This file is a day's index of fetched public feeds. It is not ranking,",
        "not a class taxonomy, and not Midkernel intelligence.",
        "",
    ]

    for src in sources:
        meta_path = output_dir / src["id"] / "meta.json"
        body_path = output_dir / src["id"] / "body"
        for ext in (".json", ".xml", ""):
            candidate = output_dir / src["id"] / f"body{ext}"
            if candidate.exists():
                body_path = candidate
                break

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
                        if item.get("pubDate"):
                            bit += f"  ({item['pubDate']})"
                        if item.get("link"):
                            bit += f"  {item['link']}"
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


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    output = Path(sys.argv[1]) if len(sys.argv) > 1 else root / "output"
    sources = load_sources(root / "sources.yaml")
    text = build_summary(output, sources)
    summary = output / "summary.md"
    summary.write_text(text, encoding="utf-8")
    print(f"wrote {summary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
