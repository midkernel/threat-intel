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
from index import (
    ABUSECH_CSV_SAFETY_CEILING,
    INDEX_SCHEMA,
    PLAINTEXT_ITEM_CAP,
    build_index,
    csv_items,
    feed_items,
    json_items,
    json_preview,
    text_items,
    write_outputs,
)

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
        self.assertEqual(len(sources), 149)
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
        self.assertEqual(by_id["abuse-ch-feodo-ipblocklist"]["format"], "txt")
        self.assertEqual(by_id["abuse-ch-urlhaus-recent"]["format"], "csv")
        self.assertEqual(by_id["openphish-community"]["format"], "txt")
        self.assertEqual(by_id["cisa-kev-csv"]["format"], "csv")
        self.assertEqual(by_id["ransomware-live-victims"]["format"], "json")
        self.assertEqual(by_id["nvd-cve-api-2"]["format"], "json")
        self.assertFalse(any("vulfeed" in src["url"] for src in sources))
        for src in sources:
            self.assertTrue(src["url"].startswith("https://"))
            self.assertNotIn("[curl]", src["why"])
            self.assertIn(src["format"], {"rss", "atom", "json", "txt", "csv"})

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

    def test_json_items_epss_retains_upstream_scores(self) -> None:
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
        self.assertEqual(items[0]["raw"]["epss"], "0.9")
        self.assertEqual(items[0]["raw"]["percentile"], "0.99")

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


class PlaintextCsvIndexTests(unittest.TestCase):
    def test_text_items_skip_comments_and_emit_bounded_rows(self) -> None:
        body = (
            b"# banner\n"
            b"162.243.103.246\n"
            b"178.62.3.223\n"
            b"# END\n"
            b"\n"
            b"27.133.154.218\n"
        )
        received, items = text_items(body)
        self.assertEqual(received, 3)
        self.assertEqual([row["title"] for row in items], [
            "162.243.103.246",
            "178.62.3.223",
            "27.133.154.218",
        ])
        self.assertEqual(items[0]["id"], "162.243.103.246")
        self.assertIsNone(items[0]["url"])
        self.assertEqual(items[0]["raw"]["line"], "162.243.103.246")

    def test_text_items_openphish_urls_and_spamhaus_cidr(self) -> None:
        body = (
            b"https://evil.example/phish\n"
            b"1.2.3.0/24 ; SBL123\n"
            b"8.8.8.8#4#2#Malicious Host\n"
        )
        received, items = text_items(body)
        self.assertEqual(received, 3)
        self.assertEqual(items[0]["url"], "https://evil.example/phish")
        self.assertEqual(items[0]["title"], "https://evil.example/phish")
        self.assertEqual(items[1]["title"], "1.2.3.0/24")
        self.assertEqual(items[2]["title"], "8.8.8.8")

    def test_text_items_respect_cap(self) -> None:
        lines = "\n".join(f"10.0.0.{i}" for i in range(PLAINTEXT_ITEM_CAP + 25))
        received, items = text_items(lines.encode())
        self.assertEqual(received, PLAINTEXT_ITEM_CAP + 25)
        self.assertEqual(len(items), PLAINTEXT_ITEM_CAP)

    def test_csv_provider_columns_and_quoted_spacing(self) -> None:
        fixtures = [
            (b'cveID,vendorProject,dateAdded\nCVE-2026-1234,Vendor,2026-09-22\n', "CVE-2026-1234", "2026-09-22"),
            (b'# first_seen_utc,ioc_id,ioc_value\n"2026-09-22", "123", "https://example.invalid/a"\n', "https://example.invalid/a", "2026-09-22"),
            (b'# Listingdate,DstIP,DstPort\n2026-09-22,192.0.2.1,443\n', "192.0.2.1", "2026-09-22"),
            (b'# ja3_md5,first_seen\nabc123,2026-09-22\n', "abc123", "2026-09-22"),
        ]
        for raw, title, date in fixtures:
            with self.subTest(title=title):
                received, items = csv_items(raw)
                self.assertEqual(received, 1)
                self.assertEqual(items[0]["title"], title)
                self.assertTrue(items[0]["published_at"].startswith(date))

    def test_csv_headerless_values_and_prose_comments_are_not_headers(self) -> None:
        for value in ("https://example.invalid/domain", "CVE-2026-1234"):
            received, items = csv_items(f"# Example banner, updated daily\n{value}\n".encode())
            self.assertEqual(received, 1)
            self.assertEqual(items[0]["title"], value)

    def test_plaintext_url_preserves_semicolon(self) -> None:
        _, items = text_items(b"https://example.invalid/a;param=1\n")
        self.assertEqual(items[0]["url"], "https://example.invalid/a;param=1")

    def test_csv_items_urlhaus_style_comment_header(self) -> None:
        body = (
            b"################################################################\n"
            b"# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n"
            b'"1","2026-09-22 11:00:00","http://evil.example/a","online","2026-09-22",'
            b'"malware_download","None","https://urlhaus.abuse.ch/url/1/","tester"\n'
            b'"2","2026-09-22 11:01:00","http://evil.example/b","online","2026-09-22",'
            b'"malware_download","Mozi","https://urlhaus.abuse.ch/url/2/","tester"\n'
        )
        received, items = csv_items(body)
        self.assertEqual(received, 2)
        self.assertEqual(items[0]["title"], "http://evil.example/a")
        self.assertEqual(items[0]["url"], "http://evil.example/a")
        self.assertEqual(items[0]["id"], "1")
        self.assertIn("2026-09-22", items[0]["published_at"] or "")
        self.assertEqual(items[1]["id"], "2")

    def test_csv_items_cert_pl_tsv(self) -> None:
        body = (
            "PozycjaRejestru\tAdresDomeny\tDataWpisu\tDataWykreslenia\n"
            "665069\tevildomain.example\t2026-08-12T12:22:21+00:00\t\n"
            "607939\tother.example\t2026-05-29T16:26:59+00:00\t\n"
        ).encode()
        received, items = csv_items(body)
        self.assertEqual(received, 2)
        self.assertEqual(items[0]["title"], "evildomain.example")
        self.assertEqual(items[0]["id"], "665069")
        self.assertIn("2026-08-12", items[0]["published_at"] or "")

    def test_csv_items_respect_cap(self) -> None:
        header = "id,url\n"
        rows = "\n".join(f'{i},http://example.invalid/{i}' for i in range(PLAINTEXT_ITEM_CAP + 10))
        received, items = csv_items((header + rows).encode())
        self.assertEqual(received, PLAINTEXT_ITEM_CAP + 10)
        self.assertEqual(len(items), PLAINTEXT_ITEM_CAP)

    def test_build_index_txt_csv_fixtures(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            _write_source(
                out,
                "example-txt",
                status=200,
                body=b"# note\n1.1.1.1\n2.2.2.2\n",
                ext="txt",
            )
            _write_source(
                out,
                "example-csv",
                status=200,
                body=b"id,url,dateadded\n9,https://phish.example/,2026-09-22\n",
                ext="csv",
            )
            sources = [
                {
                    "id": "example-txt",
                    "name": "Example TXT",
                    "url": "https://example.invalid/list.txt",
                    "format": "txt",
                    "surface": "web2",
                    "why": "fixture",
                },
                {
                    "id": "example-csv",
                    "name": "Example CSV",
                    "url": "https://example.invalid/list.csv",
                    "format": "csv",
                    "surface": "web2",
                    "why": "fixture",
                },
            ]
            index = build_index(out, sources, day="2026-09-22", generated_at="2026-09-22T12:00:00Z")
            txt = index["sources"][0]
            self.assertEqual(txt["format"], "txt")
            self.assertEqual(txt["item_count"], 2)
            self.assertEqual(txt["status"]["parse"], "ok")
            self.assertEqual(txt["status"]["received_count"], 2)
            self.assertEqual(txt["items"][0]["title"], "1.1.1.1")
            csv_row = index["sources"][1]
            self.assertEqual(csv_row["item_count"], 1)
            self.assertEqual(csv_row["items"][0]["url"], "https://phish.example/")
            self.assertEqual(csv_row["items"][0]["id"], "9")

    def test_json_items_nvd_ransomware_and_sans(self) -> None:
        nvd = {
            "resultsPerPage": 1,
            "totalResults": 10,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2026-1",
                        "published": "2026-01-02T00:00:00.000",
                        "lastModified": "2026-01-03T00:00:00.000",
                        "descriptions": [
                            {"lang": "en", "value": "Example NVD CVE"},
                            {"lang": "es", "value": "Ejemplo"},
                        ],
                        "references": [{"url": "https://example.invalid/cve"}],
                    }
                }
            ],
        }
        items = json_items(nvd)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["id"], "CVE-2026-1")
        self.assertEqual(items[0]["title"], "Example NVD CVE")
        self.assertEqual(items[0]["url"], "https://example.invalid/cve")

        victims = [
            {
                "group": "akira",
                "domain": "paylogix.com",
                "victim": "Paylogix",
                "discovered": "2026-01-15T13:48:29+00:00",
                "claim_url": "",
            }
        ]
        items = json_items(victims)
        self.assertEqual(items[0]["id"], "paylogix.com")
        self.assertIn("akira", items[0]["title"])
        self.assertIn("2026-01-15", items[0]["published_at"] or "")

        attacks = [
            {
                "title": "City attacked",
                "domain": "ville.example",
                "date": "2026-08-27",
                "url": "https://news.example/story",
                "claim_gang": False,
                "victim": "Ville",
            }
        ]
        items = json_items(attacks)
        self.assertEqual(items[0]["title"], "City attacked")
        self.assertEqual(items[0]["url"], "https://news.example/story")

        sans = [{"ip": "1.2.3.4", "description": "openresolver"}]
        items = json_items(sans)
        self.assertEqual(items[0]["id"], "1.2.3.4")
        self.assertEqual(items[0]["title"], "openresolver")

        # Victims with empty domain still itemize via group+victim
        empty_domain = [
            {
                "group": "akira",
                "domain": "",
                "victim": "Mystery Corp",
                "discovered": "2026-01-15T13:48:29+00:00",
            }
        ]
        items = json_items(empty_domain)
        self.assertEqual(items[0]["id"], "Mystery Corp")
        self.assertEqual(items[0]["title"], "akira: Mystery Corp")


def _urlhaus_csv(rows: list[tuple[str, str, str]]) -> bytes:
    lines = ["# id,dateadded,url,url_status,threat"]
    for ident, added, url in rows:
        lines.append(f'"{ident}","{added}","{url}","online","malware_download"')
    return ("\n".join(lines) + "\n").encode()


def _abusech_source(src_id: str = "abuse-ch-urlhaus-recent") -> dict[str, str]:
    return {
        "id": src_id,
        "name": "Abuse.ch URLhaus recent malware URLs",
        "url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "format": "csv",
        "surface": "web2",
        "why": "fixture",
    }


class AbusechCsvIncrementalTests(unittest.TestCase):
    def test_safety_ceiling_is_above_the_old_ledger_cap(self) -> None:
        self.assertGreaterEqual(ABUSECH_CSV_SAFETY_CEILING, 50_000)
        self.assertGreater(ABUSECH_CSV_SAFETY_CEILING, PLAINTEXT_ITEM_CAP)

    def test_over_cap_fixture_ingests_fully_and_non_abuse_csv_stays_capped(self) -> None:
        count = PLAINTEXT_ITEM_CAP + 25
        rows = [
            (str(i), f"2026-10-06 12:00:{i % 60:02d}", f"http://evil.example/{i}")
            for i in range(count)
        ]
        body = _urlhaus_csv(rows)
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            state = out / "state"
            _write_source(out, "abuse-ch-urlhaus-recent", status=200, body=body, ext="csv")
            _write_source(out, "example-csv", status=200, body=body, ext="csv")
            sources = [
                _abusech_source(),
                {
                    "id": "example-csv",
                    "name": "Example CSV",
                    "url": "https://example.invalid/list.csv",
                    "format": "csv",
                    "surface": "web2",
                    "why": "fixture",
                },
            ]
            with self.assertNoLogs("threat-intel", level="WARNING"):
                index = build_index(
                    out, sources, day="2026-10-06", generated_at="2026-10-06T13:00:00Z", state_dir=state,
                )
            abuse = index["sources"][0]
            self.assertEqual(abuse["item_count"], count)
            self.assertEqual(abuse["status"]["received_count"], count)
            self.assertEqual(abuse["status"]["parsed_count"], count)
            self.assertEqual(abuse["status"]["completeness"], "complete")
            self.assertEqual(abuse["status"]["coverage"], "incremental")
            self.assertNotIn("bounded_item_cap", abuse["status"]["reasons"])
            self.assertEqual(abuse["status"]["rejected_count"], 0)
            self.assertEqual([item["id"] for item in abuse["items"]], [str(i) for i in range(count)])
            self.assertEqual(abuse["items"][0]["title"], "http://evil.example/0")
            self.assertEqual(abuse["items"][0]["url"], "http://evil.example/0")
            self.assertEqual(abuse["checkpoint"]["ceiling_hit"], False)
            self.assertEqual(abuse["checkpoint"]["safety_ceiling"], ABUSECH_CSV_SAFETY_CEILING)
            self.assertGreaterEqual(abuse["checkpoint"]["high_water"], "2026-10-06T12:00:00Z")
            saved = json.loads((state / "abuse-ch-urlhaus-recent.json").read_text(encoding="utf-8"))
            self.assertEqual(saved["high_water"], abuse["checkpoint"]["high_water"])
            self.assertIsNone(saved["previous_high_water"])

            other = index["sources"][1]
            self.assertEqual(other["item_count"], PLAINTEXT_ITEM_CAP)
            self.assertEqual(other["status"]["completeness"], "partial")
            self.assertIn("bounded_item_cap", other["status"]["reasons"])
            self.assertNotIn("checkpoint", other)

            again = build_index(
                out, sources[:1], day="2026-10-06", generated_at="2026-10-06T13:00:00Z", state_dir=state,
            )
            self.assertEqual(again["sources"][0]["item_count"], count)

    def test_incremental_high_water_keeps_only_newer_rows(self) -> None:
        first = _urlhaus_csv([
            ("1", "2026-10-01 00:00:00", "http://evil.example/1"),
            ("2", "2026-10-02 00:00:00", "http://evil.example/2"),
            ("3", "2026-10-03 00:00:00", "http://evil.example/3"),
        ])
        second = _urlhaus_csv([
            ("1", "2026-10-01 00:00:00", "http://evil.example/1"),
            ("3", "2026-10-03 00:00:00", "http://evil.example/3"),
            ("9", "2026-09-01 00:00:00", "http://evil.example/old"),
            ("4", "2026-10-04 08:30:00", "http://evil.example/4"),
        ])
        threatfox = (
            b"# first_seen_utc,ioc_id,ioc_value,ioc_type\n"
            b'"2026-10-03 00:00:00","10","http://c2.example/old","url"\n'
            b'"2026-10-05 01:02:03","11","http://c2.example/new","url"\n'
        )
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            state = out / "state"
            _write_source(out, "abuse-ch-urlhaus-recent", status=200, body=first, ext="csv")
            _write_source(out, "abuse-ch-threatfox-urls", status=200, body=threatfox, ext="csv")
            fox = {
                "id": "abuse-ch-threatfox-urls",
                "name": "Abuse.ch ThreatFox recent URLs",
                "url": "https://threatfox.abuse.ch/export/csv/urls/recent/",
                "format": "csv",
                "surface": "web2",
                "why": "fixture",
            }
            first_index = build_index(
                out, [_abusech_source(), fox], day="2026-10-05",
                generated_at="2026-10-05T00:00:00Z", state_dir=state,
            )
            self.assertEqual([item["id"] for item in first_index["sources"][0]["items"]], ["1", "2", "3"])
            self.assertEqual(first_index["sources"][0]["checkpoint"]["high_water"], "2026-10-03T00:00:00Z")
            fox_items = first_index["sources"][1]["items"]
            self.assertEqual([item["id"] for item in fox_items], ["http://c2.example/old", "http://c2.example/new"])
            self.assertEqual(fox_items[1]["title"], "http://c2.example/new")
            self.assertEqual(fox_items[1]["published_at"], "2026-10-05 01:02:03")
            self.assertEqual(first_index["sources"][1]["checkpoint"]["high_water"], "2026-10-05T01:02:03Z")

            (out / "abuse-ch-urlhaus-recent" / "body.csv").write_bytes(second)
            (out / "abuse-ch-urlhaus-recent" / "meta.json").write_text(json.dumps({
                "status": 200, "fetched_at": "2026-10-05T12:00:00Z", "diagnostics": [],
            }))
            second_index = build_index(
                out, [_abusech_source()], day="2026-10-05",
                generated_at="2026-10-05T12:00:00Z", state_dir=state,
            )
            row = second_index["sources"][0]
            self.assertEqual([item["id"] for item in row["items"]], ["4"])
            self.assertEqual(row["items"][0]["published_at"], "2026-10-04 08:30:00")
            self.assertEqual(row["status"]["received_count"], 4)
            self.assertEqual(row["status"]["parsed_count"], 1)
            self.assertEqual(row["status"]["completeness"], "complete")
            self.assertIn("incremental_high_water", row["status"]["reasons"])
            self.assertNotIn("bounded_item_cap", row["status"]["reasons"])
            self.assertEqual(row["checkpoint"]["previous_high_water"], "2026-10-03T00:00:00Z")
            self.assertEqual(row["checkpoint"]["high_water"], "2026-10-04T08:30:00Z")
            saved = json.loads((state / "abuse-ch-urlhaus-recent.json").read_text(encoding="utf-8"))
            self.assertEqual(saved["high_water"], "2026-10-04T08:30:00Z")
            self.assertEqual(saved["previous_high_water"], "2026-10-03T00:00:00Z")

    def test_safety_ceiling_warns_and_resumes_from_contiguous_mark(self) -> None:
        rows = [(str(i), f"2026-10-0{i} 00:00:00", f"http://evil.example/{i}") for i in range(1, 6)]
        body = _urlhaus_csv(rows)
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            state = out / "state"
            directory = out / "abuse-ch-urlhaus-recent"
            directory.mkdir()
            (directory / "body.csv").write_bytes(body)
            (directory / "meta.json").write_text(json.dumps({
                "status": 200, "fetched_at": "2026-10-06T00:00:00Z", "diagnostics": [],
            }))
            with self.assertLogs("threat-intel", level="WARNING") as logs:
                first = build_index(
                    out, [_abusech_source()], day="2026-10-06",
                    generated_at="2026-10-06T00:00:00Z", state_dir=state, abusech_ceiling=3,
                )
            self.assertTrue(any("safety ceiling" in line for line in logs.output))
            row = first["sources"][0]
            self.assertEqual([item["id"] for item in row["items"]], ["1", "2", "3"])
            self.assertEqual(row["status"]["completeness"], "partial")
            self.assertIn("bounded_item_cap", row["status"]["reasons"])
            self.assertTrue(row["checkpoint"]["ceiling_hit"])
            self.assertEqual(row["checkpoint"]["safety_ceiling"], 3)
            self.assertEqual(row["checkpoint"]["high_water"], "2026-10-03T00:00:00Z")

            (directory / "body.csv").write_bytes(body + b"\n")
            (directory / "meta.json").write_text(json.dumps({
                "status": 200, "fetched_at": "2026-10-06T04:00:00Z", "diagnostics": [],
            }))
            second = build_index(
                out, [_abusech_source()], day="2026-10-06",
                generated_at="2026-10-06T04:00:00Z", state_dir=state, abusech_ceiling=3,
            )
            self.assertEqual([item["id"] for item in second["sources"][0]["items"]], ["4", "5"])
            self.assertEqual(second["sources"][0]["checkpoint"]["high_water"], "2026-10-05T00:00:00Z")
            self.assertEqual(second["sources"][0]["status"]["completeness"], "complete")

    def test_same_timestamp_burst_does_not_advance_past_unindexed_rows(self) -> None:
        rows = [(str(i), "2026-10-06 01:02:03", f"http://evil.example/{i}") for i in range(4)]
        body = _urlhaus_csv(rows)
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            state = out / "state"
            _write_source(out, "abuse-ch-urlhaus-recent", status=200, body=body, ext="csv")
            with self.assertLogs("threat-intel", level="WARNING"):
                index = build_index(
                    out, [_abusech_source()], day="2026-10-06",
                    generated_at="2026-10-06T02:00:00Z", state_dir=state, abusech_ceiling=2,
                )
            row = index["sources"][0]
            self.assertEqual(row["item_count"], 2)
            self.assertIsNone(row["checkpoint"]["high_water"])
            self.assertTrue(row["checkpoint"]["ceiling_hit"])
            saved = json.loads((state / "abuse-ch-urlhaus-recent.json").read_text(encoding="utf-8"))
            self.assertIsNone(saved["high_water"])


if __name__ == "__main__":
    unittest.main()
