#!/usr/bin/env python3
"""Build a day's index from fetched bodies. This is an index, not intelligence."""

from __future__ import annotations

import json
import os
import hashlib
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
        else:
            title, ident, published = row.get("name"), row.get("id"), row.get("date")
        if not (title or ident):
            continue
        refs = cna.get("references", []) if cve_meta else row.get("references") if isinstance(row.get("references"), list) else []
        aliases = list(row.get("aliases") or [])
        aliases += [x["value"] for x in row.get("identifiers", []) if isinstance(x, dict) and x.get("value")]
        if row.get("cve_id"):
            aliases.append(row["cve_id"])
        url = row.get("html_url") or row.get("link") or row.get("url") or row.get("source") or row.get("linkSource")
        items.append(_with_evidence(_index_item(_nz(title or ident), _nz(url), _as_date(published), _nz(ident)),
            row, summary=row.get("summary") or row.get("shortDescription") or cna.get("title"),
            content=row.get("details") or row.get("description") or "\n".join(x.get("value", "") for x in cna.get("descriptions", []) if isinstance(x, dict)) or None,
            modified_at=row.get("modified") or row.get("updated_at") or cve_meta.get("dateUpdated"),
            withdrawn_at=row.get("withdrawn") or row.get("withdrawn_at") or cve_meta.get("dateRejected"),
            aliases=sorted(set(aliases)), references=refs))
    return items


def source_details(src: dict, meta: dict | None, body_path: Path) -> tuple[list, dict]:
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
        return [], extra
    raw = body_path.read_bytes()
    extra["body_sha256"] = hashlib.sha256(raw).hexdigest()
    try:
        if src["format"] in {"rss", "atom"}:
            kind, items = feed_items(raw)
            if kind == "unknown":
                raise ValueError("unrecognized or malformed XML feed")
            status["received_count"] = len(items)
            status["reasons"].append("rolling_feed_has_no_historical_completeness_guarantee")
        else:
            data = json.loads(raw.decode("utf-8-sig"))
            items = json_items(data)
            if isinstance(data, dict) and data.get("collector"):
                status.update(data.get("status", {}))
                for key in ("statistics", "snapshot", "checkpoint", "raw"):
                    if key in data:
                        extra[key] = data[key]
            else:
                rows = data if isinstance(data, list) else data.get("vulnerabilities", data.get("data"))
                if not isinstance(rows, list):
                    raise ValueError("unrecognized JSON catalog")
                status["received_count"] = len(rows)
                status["completeness"] = "complete"
                if isinstance(data, dict):
                    extra["raw"] = {k: v for k, v in data.items() if k not in {"vulnerabilities", "data"}}
                    if isinstance(data.get("total"), int) and data["total"] > len(rows):
                        status["completeness"] = "partial"
                        status["reasons"].append("bounded_api_slice")
                    if isinstance(data.get("count"), int) and data["count"] != len(rows):
                        status["completeness"] = "partial"
                        status["reasons"].append("catalog_count_mismatch")
        status["parse"] = "ok"
        status["parsed_count"] = len(items)
        if not (isinstance(locals().get("data"), dict) and data.get("collector")):
            status["rejected_count"] = status["received_count"] - len(items)
        if status["rejected_count"]:
            status["completeness"] = "partial"
            status["reasons"].append("rejected_records")
        if meta.get("error"):
            status["completeness"] = "partial"
            status["reasons"].append(meta["error"])
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
    for ext in (".json", ".xml", ""):
        candidate = output_dir / src_id / f"body{ext}"
        if candidate.exists():
            return candidate
    return body_path


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _utc_day() -> str:
    return time.strftime("%Y-%m-%d", time.gmtime())


def build_summary(output_dir: Path, sources: list[dict], *, day: str | None = None) -> str:
    document = build_index(output_dir, sources, day=day)
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
        items, details = source_details(src, meta, body_path)
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
