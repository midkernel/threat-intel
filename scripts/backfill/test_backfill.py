#!/usr/bin/env python3
"""Offline backfill tests. Fixture catalogs only — no live URLs."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))

from common import (  # noqa: E402
    LAST_DAY,
    SCHEMA_DEFILLAMA,
    SCHEMA_EPSS,
    SCHEMA_KEV,
    SCHEMA_MANIFEST,
    assert_no_forbidden_keys,
    load_simple_yaml,
)
from defillama import derive_defillama_days, load_hacks  # noqa: E402
from epss import derive_epss_day, derive_epss_from_dir  # noqa: E402
from generate import main as generate_main  # noqa: E402
from kev import derive_kev_days, load_kev_catalog  # noqa: E402
from validate import validate_tree  # noqa: E402

FIXTURES = HERE / "fixtures"


class KevDeriveTests(unittest.TestCase):
    def test_buckets_seed_day_and_cumulative(self) -> None:
        catalog = load_kev_catalog((FIXTURES / "kev.json").read_bytes())
        days, meta = derive_kev_days(
            catalog,
            first_day=__import__("datetime").date(2021, 11, 3),
            last_day=__import__("datetime").date(2021, 11, 4),
        )
        self.assertEqual(len(days), 2)
        seed = days[0]
        self.assertEqual(seed["day"], "2021-11-03")
        self.assertEqual([row["cveId"] for row in seed["added"]], ["CVE-2021-0001", "CVE-2021-0002"])
        self.assertEqual(seed["cumulative_count"], 2)
        nxt = days[1]
        self.assertEqual(nxt["day"], "2021-11-04")
        self.assertEqual([row["cveId"] for row in nxt["added"]], ["CVE-2021-0003"])
        self.assertEqual(nxt["cumulative_count"], 3)
        self.assertEqual(meta["window_added"], 3)
        # 2022 backlog row is outside this smoke window.
        assert_no_forbidden_keys(days)

    def test_full_window_keeps_2022_row_but_does_not_label_it(self) -> None:
        catalog = load_kev_catalog((FIXTURES / "kev.json").read_bytes())
        days, _meta = derive_kev_days(
            catalog,
            first_day=__import__("datetime").date(2021, 11, 3),
            last_day=__import__("datetime").date(2022, 3, 15),
        )
        by_day = {row["day"]: row for row in days}
        self.assertEqual(len(by_day["2022-03-15"]["added"]), 1)
        self.assertEqual(by_day["2022-03-15"]["added"][0]["cveId"], "CVE-2017-0144")
        blob = json.dumps(by_day["2022-03-15"])
        self.assertNotIn("active-exploit", blob)
        self.assertNotIn("trending", blob)


class EpssDeriveTests(unittest.TestCase):
    def test_fixture_csv_high_count_document_order_sample(self) -> None:
        raw = (FIXTURES / "epss" / "epss_scores-2021-04-14.csv").read_bytes()
        day = derive_epss_day(raw, __import__("datetime").date(2021, 4, 14))
        self.assertEqual(day["day"], "2021-04-14")
        self.assertEqual(day["scored_total"], 6)
        self.assertEqual(day["high_count"], 3)
        self.assertEqual(day["high_threshold"], 0.5)
        self.assertEqual(
            [row["cve"] for row in day["sample_cves"]],
            ["CVE-2020-5902", "CVE-2019-0232", "CVE-2021-0001"],
        )
        self.assertNotIn("model_version", day)
        assert_no_forbidden_keys(day)

    def test_comment_header_and_below_threshold(self) -> None:
        raw = (FIXTURES / "epss" / "epss_scores-2021-04-15.csv").read_bytes()
        day = derive_epss_day(raw, __import__("datetime").date(2021, 4, 15))
        self.assertEqual(day["high_count"], 1)
        self.assertEqual(day["sample_cves"][0]["cve"], "CVE-2019-0232")
        self.assertEqual(day["model_version"], "v2021.04.14")
        self.assertEqual(day["scored_total"], 3)

    def test_dir_reader_skips_missing_days(self) -> None:
        days, missing = derive_epss_from_dir(
            FIXTURES / "epss",
            first_day=__import__("datetime").date(2021, 4, 14),
            last_day=__import__("datetime").date(2021, 4, 16),
        )
        self.assertEqual([row["day"] for row in days], ["2021-04-14", "2021-04-15"])
        self.assertEqual(missing, ["2021-04-16"])


class DefillamaDeriveTests(unittest.TestCase):
    def test_buckets_and_clips_after_last_day(self) -> None:
        rows = load_hacks((FIXTURES / "hacks.json").read_bytes())
        days, meta = derive_defillama_days(rows, last_day=LAST_DAY)
        by_day = {row["day"]: row for row in days}
        self.assertIn("2019-06-26", by_day)
        self.assertEqual(by_day["2019-06-26"]["incidents"][0]["name"], "OldBridge")
        self.assertEqual(by_day["2019-06-26"]["incidents"][0]["url"], "https://example.invalid/oldbridge")
        self.assertIn("2021-04-14", by_day)
        self.assertNotIn("2026-09-08", by_day)
        self.assertEqual(meta["after_last_day"], 1)
        self.assertEqual(meta["incidents"], 3)
        assert_no_forbidden_keys(days)


class SmokeGenerateTests(unittest.TestCase):
    def test_smoke_writes_monthly_shards_and_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "backfill"
            rc = generate_main(["--smoke", "--out", str(out)])
            self.assertEqual(rc, 0)
            errors = validate_tree(out)
            self.assertEqual(errors, [])
            manifest = load_simple_yaml(out / "manifest.yaml")
            self.assertEqual(manifest["schema"], SCHEMA_MANIFEST)
            self.assertFalse(manifest["ranking"])
            self.assertFalse(manifest["class_taxonomy"])
            self.assertFalse(manifest["invented_daily_releases"])
            ids = [src["id"] for src in manifest["sources"]]
            self.assertEqual(ids, ["kev", "epss", "defillama"])

            kev = json.loads((out / "kev" / "by-month" / "2021-11.json").read_text(encoding="utf-8"))
            self.assertEqual(kev["schema"], SCHEMA_KEV)
            self.assertEqual(kev["month"], "2021-11")
            self.assertEqual(kev["days"][0]["cumulative_count"], 2)

            epss = json.loads((out / "epss" / "by-month" / "2021-04.json").read_text(encoding="utf-8"))
            self.assertEqual(epss["schema"], SCHEMA_EPSS)
            self.assertEqual(len(epss["days"]), 2)
            self.assertEqual(epss["days"][0]["high_count"], 3)

            llama = json.loads((out / "defillama" / "by-month" / "2019-06.json").read_text(encoding="utf-8"))
            self.assertEqual(llama["schema"], SCHEMA_DEFILLAMA)
            self.assertEqual(llama["days"][0]["incidents"][0]["name"], "OldBridge")

            # Raw EPSS CSVs must not land in the backfill tree.
            csvs = list(out.rglob("*.csv")) + list(out.rglob("*.csv.gz"))
            self.assertEqual(csvs, [])

    def test_smoke_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            a = Path(tmp) / "a"
            b = Path(tmp) / "b"
            self.assertEqual(generate_main(["--smoke", "--out", str(a)]), 0)
            self.assertEqual(generate_main(["--smoke", "--out", str(b)]), 0)
            files_a = sorted(p.relative_to(a) for p in a.rglob("*") if p.is_file())
            files_b = sorted(p.relative_to(b) for p in b.rglob("*") if p.is_file())
            self.assertEqual(files_a, files_b)
            for rel in files_a:
                self.assertEqual(
                    (a / rel).read_bytes(),
                    (b / rel).read_bytes(),
                    rel,
                )


if __name__ == "__main__":
    unittest.main()
