# Historical backfill

Derived, source-controlled history so [midkernel/app](https://github.com/midkernel/app) can build **ThreatClassDay** trends **before** the first daily Release (`daily-2026-09-05`).

This tree **packages and cites**. It does not rank, does not invent a class taxonomy, and does not attach Midkernel scores.

## Why monthly shards

A day file per source from 2021-04-14 through 2026-09-04 is ~5 900 JSON files. That is an awkward git tree.

Days are packed as:

```
backfill/<source>/by-month/YYYY-MM.json
```

Each file is `{schema, month, days:[…]}`. One object per calendar day that the source covers. The repo stays in the low hundreds of files, not thousands. Consumers that want a day walk `days` and match `day`.

CI never downloads the full EPSS daily archive. It validates this tree plus fixture smoke. A full rebuild is `workflow_dispatch` (`.github/workflows/backfill.yml`).

## Windows

| Source | First day | Last day | Why |
| --- | --- | --- | --- |
| EPSS (max backfill day) | **2021-04-14** | **2026-09-04** | Official FIRST / empiricalsec daily archive starts 2021-04-14. Last day is the UTC day before `daily-2026-09-05`. |
| CISA KEV | **2021-11-03** | **2026-09-04** | Catalog seed day (`dateAdded` begins here). |
| DeFiLlama hacks | earliest incident in the official JSON (2011-…) | **2026-09-04** | The hacks catalog has incident dates spanning years. Days with no incidents are omitted (treat as zero). Incidents on/after 2026-09-05 are left to daily Releases. |

There are **no** invented `daily-*` GitHub Releases for RSS/Atom sources. Those feeds are rolling windows. History for blogs and commit Atoms starts at the first real daily Release.

## 2022 KEV backlog year

CISA published the KEV catalog on **2021-11-03** (seed day, 287 rows in the current catalog). **2022 is a backlog-drain year**, not a real exploit spike. Hundreds of older CVEs were added that year as CISA caught up on historically exploited issues. `dateAdded` in 2022 is a cataloguing date, not “first exploited in 2022.” Trend charts that treat 2022 `added` counts as activity will lie. This repo still cites those rows; it does not reinterpret them.

## Schemas (additive only)

Stable ids. New fields may appear; existing fields keep their meaning. Ranking, class taxonomy, and Midkernel scores will not be added here.

### Manifest — `midkernel.threat-intel.backfill.manifest/v1`

`backfill/manifest.yaml`: sources, methods, first/last day, schema ids, shard layout.

### KEV — `midkernel.threat-intel.backfill.kev/v1`

Official JSON: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`

Bucket by `dateAdded`. Every calendar day from 2021-11-03 through 2026-09-04 is present so `cumulative_count` is walkable.

```json
{
  "schema": "midkernel.threat-intel.backfill.kev/v1",
  "month": "2021-11",
  "days": [
    {
      "day": "2021-11-03",
      "added": [
        {
          "cveId": "CVE-…",
          "vendorProject": "…",
          "product": "…",
          "vulnerabilityName": "…",
          "knownRansomwareCampaignUse": "Known|Unknown"
        }
      ],
      "cumulative_count": 287
    }
  ]
}
```

### EPSS — `midkernel.threat-intel.backfill.epss/v1`

**Derived only.** Raw daily CSVs (~tens/hundreds of thousands of rows) are never committed.

Method: download `https://epss.empiricalsecurity.com/epss_scores-YYYY-MM-DD.csv.gz` (official empiricalsec daily archive; FIRST historical API `?date=` is an alternate). Parse, count, discard the CSV.

High row: **`epss >= 0.5`**. That is a documented FIRST-score threshold, not a Midkernel score and not a percentile rank. `sample_cves` is the first eight source rows that meet the threshold (**document order**, not sorted by score).

```json
{
  "schema": "midkernel.threat-intel.backfill.epss/v1",
  "month": "2021-04",
  "days": [
    {
      "day": "2021-04-14",
      "scored_total": 64712,
      "high_count": 235,
      "high_threshold": 0.5,
      "sample_cves": [{"cve": "CVE-…", "epss": "0.65117"}]
    }
  ]
}
```

`model_version` is copied from the CSV `#model_version:` comment when present (EPSS v2+). Score-level shifts on model-change days are methodology changes, not vulnerability changes:

- v1: 2021-04-14
- v2 (`v2022.01.01`): publishing 2022-02-04
- v3 (`v2023.03.01`): publishing 2023-03-07
- v4 (`v2025.03.14`): publishing 2025-03-17
- v5 (`v2026.06.15`): publishing 2026-06-15

Missing archive days (HTTP 404 / fetch error) are listed in `epss/missing.txt` when a generate run finds any.

### DeFiLlama — `midkernel.threat-intel.backfill.defillama/v1`

Official JSON: `https://api.llama.fi/hacks`

Bucket by incident `date` (unix seconds → UTC `YYYY-MM-DD`). Only days that have at least one incident are written.

```json
{
  "schema": "midkernel.threat-intel.backfill.defillama/v1",
  "month": "2022-03",
  "days": [
    {
      "day": "2022-03-17",
      "incidents": [
        {
          "name": "ApeCoin",
          "date": "2022-03-17",
          "amount": 820000,
          "chain": ["Ethereum"],
          "classification": "Governance",
          "technique": "Flashloan Governance Attack",
          "defillamaId": "2665",
          "targetType": "Token"
        }
      ]
    }
  ]
}
```

`url` is included only when the catalog `source` is already an `https://` link.

## Generate

```bash
# live catalogs → backfill/  (EPSS downloads daily CSVs, derives, discards)
python3 scripts/backfill/generate.py

# one source / a shorter window
python3 scripts/backfill/generate.py --sources kev,defillama
python3 scripts/backfill/generate.py --sources epss --from-day 2021-04-14 --to-day 2021-04-30

# FIRST API instead of CSV (still derived counts only)
python3 scripts/backfill/generate.py --sources epss --epss-method api --from-day 2021-04-14 --to-day 2021-04-16

# CI / local smoke (fixtures only, no live URLs)
python3 scripts/backfill/generate.py --smoke --out /tmp/backfill-smoke
python3 scripts/backfill/test_backfill.py
python3 scripts/backfill/validate.py
```

Full rebuild on GitHub: Actions → **Backfill rebuild** → Run workflow. That job is `workflow_dispatch` only. It uploads `backfill/` as an artifact. It does not invent daily Releases and does not merge.

User-Agent: `MidkernelThreatIntel/0.1 (+https://github.com/midkernel/threat-intel)` (same as the daily fetch).

## Out of scope

- Ranking or a 1–N score
- Class taxonomy / ThreatClass mapping (that lives in midkernel/app)
- Midkernel scores
- RSS/Atom history (no fake `daily-*` tags)
- Cloudflare or website HTML
