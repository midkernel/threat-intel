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
from index import INDEX_SCHEMA, build_index, feed_items, json_items, json_preview, write_outputs

ROOT = Path(__file__).resolve().parent.parent

RSS = b"""<?xml version="1.0"?>
<rss version="2.0"><channel>
<title>Example</title>
<item>
  <title>First advisory</title>
  <link>https://example.invalid/1</link>
  <guid>https://example.invalid/1</guid>
  <pubDate>Wed, 03 Sep 2026 11:00:00 GMT</pubDate>
</item>
<item>
  <title>Second advisory</title>
  <link>https://example.invalid/2</link>
  <guid isPermaLink="false">advisory-2</guid>
  <pubDate>Tue, 02 Sep 2026 11:00:00 GMT</pubDate>
</item>
</channel></rss>
"""

ATOM = b"""<?xml version="1.0"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>Example</title>
  <entry>
    <id>tag:example.invalid,2026:c</id>
    <title>Commit signal</title>
    <link href="https://example.invalid/c" rel="alternate"/>
    <updated>2026-09-03T11:00:00Z</updated>
  </entry>
</feed>
"""

RDF = b"""<?xml version="1.0" encoding="UTF-8"?>
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
         xmlns="http://purl.org/rss/1.0/"
         xmlns:dc="http://purl.org/dc/elements/1.1/">
  <channel rdf:about="https://example.invalid/dsa.rdf">
    <title>Example RDF</title>
    <items>
      <rdf:Seq>
        <rdf:li rdf:resource="https://example.invalid/1"/>
      </rdf:Seq>
    </items>
  </channel>
  <item rdf:about="https://example.invalid/1">
    <title>RDF advisory</title>
    <link>https://example.invalid/1</link>
    <dc:date>2026-09-04T11:00:00Z</dc:date>
  </item>
</rdf:RDF>
"""


class CatalogTests(unittest.TestCase):
    def test_sources_yaml_validates(self) -> None:
        sources = load_sources(ROOT / "sources.yaml")
        self.assertEqual(len(sources), 74)
        self.assertEqual(validate_sources(sources), [])
        ids = [src["id"] for src in sources]
        self.assertEqual(ids[:21], [
            "cisa-kev",
            "circl-kev",
            "github-security-blog",
            "github-advisory-database",
            "msrc-update-guide",
            "oss-security",
            "full-disclosure",
            "exploit-db",
            "project-zero",
            "trail-of-bits",
            "krebs-on-security",
            "cloudflare-security",
            "nuclei-templates",
            "first-epss",
            "immunefi-blog",
            "slowmist-medium",
            "peckshield-medium",
            "blocksec-medium",
            "openzeppelin-blog",
            "defihacklabs",
            "defillama-hacks",
        ])
        by_id = {src["id"]: src for src in sources}
        self.assertEqual(by_id["rekt-news"]["url"], "https://rekt.news/rss/feed.xml")
        self.assertEqual(
            by_id["certcc-vulnerability-notes"]["url"],
            "https://www.kb.cert.org/vuls/atomfeed/",
        )
        self.assertFalse(any("vulfeed" in src["url"] for src in sources))
        for src in sources:
            self.assertTrue(src["url"].startswith("https://"))
            self.assertNotIn("[curl]", src["why"])

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
        self.assertEqual(items[0]["url"], "https://example.invalid/1")
        self.assertEqual(items[0]["id"], "https://example.invalid/1")
        self.assertIn("2026", items[0]["published_at"])
        self.assertEqual(items[1]["id"], "advisory-2")

    def test_atom_items(self) -> None:
        kind, items = feed_items(ATOM)
        self.assertEqual(kind, "atom")
        self.assertEqual(items[0]["title"], "Commit signal")
        self.assertEqual(items[0]["url"], "https://example.invalid/c")
        self.assertEqual(items[0]["id"], "tag:example.invalid,2026:c")
        self.assertEqual(items[0]["published_at"], "2026-09-03T11:00:00Z")

    def test_rdf_rss10_items(self) -> None:
        kind, items = feed_items(RDF)
        self.assertEqual(kind, "rss")
        self.assertEqual(items[0]["title"], "RDF advisory")
        self.assertEqual(items[0]["url"], "https://example.invalid/1")
        self.assertEqual(items[0]["id"], "https://example.invalid/1")
        self.assertIn("2026-09-04", items[0]["published_at"])

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

    def test_solidity_bugs_json_uses_uid_severity_name(self) -> None:
        data = [
            {
                "uid": "SOL-2026-3",
                "name": "NewBug",
                "severity": "very low",
                "introduced": "0.8.0",
            },
            {
                "uid": "SOL-2016-1",
                "name": "OldBug",
                "severity": "low",
            },
        ]
        count, lines = json_preview(data)
        self.assertEqual(count, 2)
        self.assertTrue(lines[0].startswith("SOL-2026-3"))
        self.assertIn("very low", lines[0])
        self.assertIn("NewBug", lines[0])
        self.assertNotIn("None", "\n".join(lines))


FORBIDDEN_INDEX_KEYS = {
    "rank",
    "ranking",
    "score",
    "scores",
    "class",
    "classes",
    "taxonomy",
    "threat",
    "epss",
    "percentile",
}


def _assert_no_forbidden_keys(test: unittest.TestCase, obj: object) -> None:
    if isinstance(obj, dict):
        overlap = FORBIDDEN_INDEX_KEYS & set(obj)
        test.assertFalse(overlap, f"index must not carry ranking fields: {overlap}")
        for value in obj.values():
            _assert_no_forbidden_keys(test, value)
    elif isinstance(obj, list):
        for value in obj:
            _assert_no_forbidden_keys(test, value)


def _write_source(
    root: Path,
    src_id: str,
    *,
    status: int,
    body: bytes,
    ext: str,
    fetched_at: str = "2026-09-05T11:00:00Z",
) -> None:
    directory = root / src_id
    directory.mkdir(parents=True)
    (directory / f"body.{ext}").write_bytes(body)
    (directory / "meta.json").write_text(
        json.dumps(
            {
                "id": src_id,
                "status": status,
                "fetched_at": fetched_at,
            }
        ),
        encoding="utf-8",
    )


class IndexJsonTests(unittest.TestCase):
    def test_json_items_kev_document_order_no_scores(self) -> None:
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
        items = json_items(data)
        self.assertEqual(
            [row["id"] for row in items],
            ["CVE-2026-1", "CVE-2026-2"],
        )
        self.assertEqual(items[0]["title"], "Old")
        self.assertEqual(items[0]["published_at"], "2026-01-01")
        self.assertIsNone(items[0]["url"])

    def test_json_items_epss_omits_scores(self) -> None:
        data = {
            "total": 367633,
            "data": [
                {
                    "cve": "CVE-2026-9",
                    "epss": "0.9",
                    "percentile": "0.99",
                    "date": "2026-09-03",
                }
            ],
        }
        items = json_items(data)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["id"], "CVE-2026-9")
        self.assertEqual(items[0]["title"], "CVE-2026-9")
        self.assertEqual(items[0]["published_at"], "2026-09-03")
        blob = json.dumps(items)
        self.assertNotIn("0.9", blob)
        self.assertNotIn("0.99", blob)
        self.assertNotIn("epss", blob)

    def test_json_items_llama_and_solidity(self) -> None:
        llama = [
            {"name": "OldHack", "date": 1647475200, "url": "https://example.invalid/old"},
            {"name": "NewHack", "date": 1788134400},
        ]
        items = json_items(llama)
        self.assertEqual([row["title"] for row in items], ["OldHack", "NewHack"])
        self.assertEqual(items[0]["published_at"], "2022-03-17")
        self.assertEqual(items[0]["url"], "https://example.invalid/old")
        self.assertIsNone(items[1]["url"])

        bugs = [
            {"uid": "SOL-2026-3", "name": "NewBug", "severity": "very low"},
            {"uid": "SOL-2016-1", "name": "OldBug", "severity": "low"},
        ]
        items = json_items(bugs)
        self.assertEqual([row["id"] for row in items], ["SOL-2026-3", "SOL-2016-1"])
        self.assertEqual(items[0]["title"], "NewBug")
        self.assertIsNone(items[0]["published_at"])

    def test_build_index_from_fixture_feeds(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            _write_source(out, "example-rss", status=200, body=RSS, ext="xml")
            _write_source(out, "example-atom", status=200, body=ATOM, ext="xml")
            _write_source(
                out,
                "example-kev",
                status=200,
                body=json.dumps(
                    {
                        "vulnerabilities": [
                            {
                                "cveID": "CVE-2026-1",
                                "dateAdded": "2026-01-01",
                                "vulnerabilityName": "Old",
                            }
                        ]
                    }
                ).encode("utf-8"),
                ext="json",
            )
            _write_source(
                out,
                "example-down",
                status=503,
                body=b"",
                ext="xml",
                fetched_at="2026-09-05T11:01:00Z",
            )
            sources = [
                {
                    "id": "example-rss",
                    "name": "Example RSS",
                    "url": "https://example.invalid/rss",
                    "format": "rss",
                    "surface": "web2",
                    "why": "fixture",
                },
                {
                    "id": "example-atom",
                    "name": "Example Atom",
                    "url": "https://example.invalid/atom",
                    "format": "atom",
                    "surface": "web2",
                    "why": "fixture",
                },
                {
                    "id": "example-kev",
                    "name": "Example KEV",
                    "url": "https://example.invalid/kev.json",
                    "format": "json",
                    "surface": "web2",
                    "why": "fixture",
                },
                {
                    "id": "example-down",
                    "name": "Example Down",
                    "url": "https://example.invalid/down",
                    "format": "rss",
                    "surface": "web2",
                    "why": "fixture",
                },
                {
                    "id": "example-missing",
                    "name": "Example Missing",
                    "url": "https://example.invalid/missing",
                    "format": "rss",
                    "surface": "web2",
                    "why": "fixture",
                },
            ]
            index = build_index(
                out,
                sources,
                day="2026-09-05",
                generated_at="2026-09-05T11:05:00Z",
            )
            self.assertEqual(index["schema"], INDEX_SCHEMA)
            self.assertEqual(index["day"], "2026-09-05")
            self.assertEqual(index["generated_at"], "2026-09-05T11:05:00Z")
            self.assertIn("not ranking", index["note"].lower())
            self.assertEqual(
                [row["id"] for row in index["sources"]],
                [src["id"] for src in sources],
            )

            rss = index["sources"][0]
            self.assertEqual(rss["http_status"], 200)
            self.assertEqual(rss["fetched_at"], "2026-09-05T11:00:00Z")
            self.assertEqual(rss["item_count"], 2)
            self.assertEqual(rss["format"], "rss")
            self.assertEqual(rss["surface"], "web2")
            self.assertEqual(rss["items"][0]["title"], "First advisory")
            self.assertEqual(rss["items"][0]["url"], "https://example.invalid/1")
            self.assertEqual(rss["items"][0]["id"], "https://example.invalid/1")
            self.assertIsNotNone(rss["items"][0]["published_at"])

            atom = index["sources"][1]
            self.assertEqual(atom["item_count"], 1)
            self.assertEqual(atom["items"][0]["id"], "tag:example.invalid,2026:c")

            kev = index["sources"][2]
            self.assertEqual(kev["item_count"], 1)
            self.assertEqual(kev["items"][0]["id"], "CVE-2026-1")

            down = index["sources"][3]
            self.assertEqual(down["http_status"], 503)
            self.assertEqual(down["item_count"], 0)
            self.assertEqual(down["items"], [])

            missing = index["sources"][4]
            self.assertIsNone(missing["http_status"])
            self.assertIsNone(missing["fetched_at"])
            self.assertEqual(missing["item_count"], 0)
            _assert_no_forbidden_keys(self, index)

    def test_write_outputs_keeps_markdown_and_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            _write_source(out, "example-rss", status=200, body=RSS, ext="xml")
            sources = [
                {
                    "id": "example-rss",
                    "name": "Example RSS",
                    "url": "https://example.invalid/rss",
                    "format": "rss",
                    "surface": "web2",
                    "why": "fixture",
                }
            ]
            summary, index_path = write_outputs(
                out,
                sources,
                day="2026-09-05",
                generated_at="2026-09-05T11:05:00Z",
            )
            self.assertTrue(summary.exists())
            self.assertTrue(index_path.exists())
            text = summary.read_text(encoding="utf-8")
            self.assertIn("Example RSS", text)
            self.assertIn("First advisory", text)
            self.assertIn("not ranking", text.lower())
            payload = json.loads(index_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["schema"], INDEX_SCHEMA)
            self.assertEqual(payload["sources"][0]["item_count"], 2)


if __name__ == "__main__":
    unittest.main()
