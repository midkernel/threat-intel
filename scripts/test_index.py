#!/usr/bin/env python3
"""Offline checks for catalog parse + index helpers. Does not fetch URLs."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from catalog import load_sources, validate_sources
from index import feed_items, json_preview

ROOT = Path(__file__).resolve().parent.parent

RSS = b"""<?xml version="1.0"?>
<rss version="2.0"><channel>
<title>Example</title>
<item>
  <title>First advisory</title>
  <link>https://example.invalid/1</link>
  <pubDate>Wed, 03 Sep 2026 11:00:00 GMT</pubDate>
</item>
<item>
  <title>Second advisory</title>
  <link>https://example.invalid/2</link>
  <pubDate>Tue, 02 Sep 2026 11:00:00 GMT</pubDate>
</item>
</channel></rss>
"""

ATOM = b"""<?xml version="1.0"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>Example</title>
  <entry>
    <title>Commit signal</title>
    <link href="https://example.invalid/c" rel="alternate"/>
    <updated>2026-09-03T11:00:00Z</updated>
  </entry>
</feed>
"""


class CatalogTests(unittest.TestCase):
    def test_sources_yaml_validates(self) -> None:
        sources = load_sources(ROOT / "sources.yaml")
        self.assertGreaterEqual(len(sources), 1)
        self.assertEqual(validate_sources(sources), [])
        for src in sources:
            self.assertTrue(src["url"].startswith("https://"))

    def test_rejects_http_url(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sources.yaml"
            path.write_text(
                "sources:\n"
                "  - id: bad\n"
                "    name: Bad\n"
                "    url: http://example.invalid/feed\n"
                "    format: rss\n"
                "    surface: web2\n"
                "    why: should fail\n",
                encoding="utf-8",
            )
            errors = validate_sources(load_sources(path))
            self.assertTrue(any("https://" in e for e in errors))


class IndexTests(unittest.TestCase):
    def test_rss_items_document_order(self) -> None:
        kind, items = feed_items(RSS)
        self.assertEqual(kind, "rss")
        self.assertEqual([i["title"] for i in items], ["First advisory", "Second advisory"])
        self.assertEqual(items[0]["link"], "https://example.invalid/1")
        self.assertIn("2026", items[0]["pubDate"])

    def test_atom_items(self) -> None:
        kind, items = feed_items(ATOM)
        self.assertEqual(kind, "atom")
        self.assertEqual(items[0]["title"], "Commit signal")
        self.assertEqual(items[0]["link"], "https://example.invalid/c")

    def test_kev_json_preview_uses_cve_and_date(self) -> None:
        data = {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2026-1",
                    "dateAdded": "2026-01-01",
                    "vulnerabilityName": "Old",
                },
                {
                    "cveID": "CVE-2026-2",
                    "dateAdded": "2026-09-03",
                    "vulnerabilityName": "New",
                },
            ]
        }
        count, lines = json_preview(data)
        self.assertEqual(count, 2)
        self.assertTrue(lines[0].startswith("CVE-2026-2"))
        self.assertIn("2026-09-03", lines[0])

    def test_epss_json_lists_cve_not_scores(self) -> None:
        data = {
            "total": 367633,
            "data": [
                {"cve": "CVE-2026-9", "epss": "0.9", "percentile": "0.99", "date": "2026-09-03"}
            ],
        }
        count, lines = json_preview(data)
        self.assertEqual(count, 367633)
        blob = "\n".join(lines)
        self.assertIn("CVE-2026-9", blob)
        self.assertNotIn("0.9", blob)
        self.assertNotIn("0.99", blob)

    def test_llama_json_uses_name_and_date(self) -> None:
        data = [
            {"name": "OldHack", "date": 1647475200},
            {"name": "NewHack", "date": 1788134400},
        ]
        count, lines = json_preview(data)
        self.assertEqual(count, 2)
        self.assertTrue(lines[0].startswith("NewHack"))


if __name__ == "__main__":
    unittest.main()
