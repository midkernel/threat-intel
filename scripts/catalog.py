"""Parse the constrained sources.yaml catalog. No ranking or class mapping."""

from __future__ import annotations

import re
from pathlib import Path

REQUIRED = ("id", "name", "url", "format", "surface", "why")
FORMATS = {"rss", "atom", "json"}
SURFACES = {"web2", "web3"}
ID_RE = re.compile(r"^[a-z][a-z0-9-]*$")
HTTPS_RE = re.compile(r"^https://[^\s]+$")


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def load_sources(path: str | Path = "sources.yaml") -> list[dict[str, str]]:
    text = Path(path).read_text(encoding="utf-8")
    sources: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    seen_header = False

    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        if line == "sources:":
            seen_header = True
            continue
        if not seen_header:
            raise ValueError(f"{path}:{lineno}: expected top-level 'sources:' list")
        if line.startswith("  - "):
            if current:
                sources.append(current)
            current = {}
            rest = line[4:]
            if ":" not in rest:
                raise ValueError(f"{path}:{lineno}: expected 'key: value' on list item")
            key, value = rest.split(":", 1)
            current[key.strip()] = _unquote(value)
            continue
        if current is None or ":" not in line:
            raise ValueError(f"{path}:{lineno}: expected a source field")
        key, value = line.split(":", 1)
        current[key.strip()] = _unquote(value)

    if current:
        sources.append(current)
    if not sources:
        raise ValueError(f"{path}: no sources listed")
    return sources


def validate_sources(sources: list[dict[str, str]]) -> list[str]:
    errors: list[str] = []
    seen_ids: set[str] = set()
    seen_urls: set[str] = set()

    for i, src in enumerate(sources, 1):
        missing = [k for k in REQUIRED if not src.get(k, "").strip()]
        if missing:
            errors.append(f"source {i}: missing fields {', '.join(missing)}")
            continue
        sid = src["id"]
        if not ID_RE.match(sid):
            errors.append(f"source {i} ({sid}): id must be lowercase kebab-case")
        if sid in seen_ids:
            errors.append(f"source {i}: duplicate id {sid!r}")
        seen_ids.add(sid)
        if src["format"] not in FORMATS:
            errors.append(f"source {sid}: format must be rss|atom|json")
        if src["surface"] not in SURFACES:
            errors.append(f"source {sid}: surface must be web2|web3")
        if not HTTPS_RE.match(src["url"]):
            errors.append(f"source {sid}: url must be an https:// URL")
        if src["url"] in seen_urls:
            errors.append(f"source {sid}: duplicate url {src['url']}")
        seen_urls.add(src["url"])
        if "\n" in src["why"]:
            errors.append(f"source {sid}: why must be one line")
        extra = sorted(set(src) - set(REQUIRED))
        if extra:
            errors.append(f"source {sid}: unexpected fields {', '.join(extra)}")
    return errors
