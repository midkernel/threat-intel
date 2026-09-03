#!/usr/bin/env python3
"""CI check: sources.yaml parses and each url is https."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from catalog import load_sources, validate_sources

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    path = ROOT / "sources.yaml"
    try:
        sources = load_sources(path)
    except ValueError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    errors = validate_sources(sources)
    if errors:
        for err in errors:
            print(f"FAIL: {err}", file=sys.stderr)
        return 1
    print(f"OK: {len(sources)} sources in {path.name}")
    for src in sources:
        print(f"  {src['surface']:4}  {src['format']:4}  {src['id']}  {src['url']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
