# Evidence index and collection contract

The public data layer copies and cites source evidence. It does not infer exploitation from template commits, rank threats, map customer assets, or prescribe protection workflows. Native severity, CVSS and EPSS fields remain attributed to their upstream providers.

## Additive index v1 fields

`schema` remains `midkernel.threat-intel.index/v1`. Existing document, source and item fields keep their meanings. New document fields are `parser_version: "2"`, `run_id` (immutable collection tag or null for local execution), and `archive_url` (GitHub release-download base URL or null). `day` is the fetch day, never a substitute for a missing source publication date.

| Item field | Meaning |
| --- | --- |
| `id` | Source-native ID or null: includes Talos `report_id`, CVE, GHSA and OSV IDs; DeFiLlama protocol IDs are not incident IDs |
| `published_at` | Source date, nullable; Solidity undated bugs remain undated |
| `modified_at`, `withdrawn_at` | Source update/withdrawal dates, nullable |
| `summary`, `content` | Source-provided descriptive text, nullable; treat HTML as untrusted text |
| `aliases`, `references` | Source-provided alias IDs and references (reference strings or structured objects) |
| `raw` | Full upstream JSON record; XML maps `tag`, `attributes`, and repeated namespaced `fields` entries containing `text`, `attributes`, and optional `xml` |
| `raw_sha256` | SHA-256 of canonical JSON encoding of `raw` (UTF-8, sorted keys, no insignificant whitespace) |

Native fields include chains, techniques, incident amounts, affected/fixed versions, compiler settings, withdrawal details, and vendor provenance. Missing dates and item URLs remain null; do not synthesize a vulnerability publication date from KEV admission or EPSS score dates. KEV `published_at` remains its existing `dateAdded` mapping, and raw preserves the distinction. DeFiLlama `defillamaId` identifies a protocol, so consumers must distinguish repeated incidents using incident date/name and native evidence. Solidity IDs can span multiple version ranges; retain all rows as evidence.

Source `body_sha256` identifies the exact parser input. Source `raw` contains JSON catalog metadata such as KEV `catalogVersion`, `dateReleased` and `count`. HTTP observations and parser diagnostics remain independent of threat interpretation.

| Source status field | Values / meaning |
| --- | --- |
| `fetch` | `ok`, `error`, `not_fetched` |
| `parse` | `ok`, `error`, `not_attempted` |
| `coverage` | `full_snapshot`, `rolling_window`, `incremental` |
| `completeness` | `complete`, `partial`, `unknown` |
| `reasons` | Such as `not_fetched`, `http_error`, `parse_error`, `rejected_records`, `bounded_history`, `selected_ecosystems`, `collection_budget_pending`, `collection_error` |
| `received_count`, `parsed_count`, `rejected_count` | Input rows, indexed items, rejected rows; EPSS receives full CSV rows but emits zero inline items |

`item_count` always equals `len(items)`, never the upstream population size. A syntactically empty feed is a successful empty observation of that feed window, not proof of zero historical activity. Rolling feeds retain unknown historical completeness. Partial catalogs must not overwrite historical observations. Collector-generated `body.json` may contain successfully collected records despite later request failures; its diagnostics and checkpoint error explicitly retain that partial state.

## EPSS: complete daily stocks and per-CVE artifact

`first-epss` downloads FIRST's official compressed daily CSV. No 100-row API slice contributes a population statistic. The collector validates the source model/date header, CVE uniqueness, finite score/percentile ranges and every CSV row. Any malformed row fails the snapshot instead of silently reducing its denominator.

The index has `items: []`, plus:

```json
{
  "statistics": {
    "kind": "stock", "score_date": "2026-09-18", "model_version": "v2026.06.15",
    "scored_total": 376715, "high_count": 4348, "high_threshold": 0.5,
    "distribution": [{"lower_inclusive": 0, "upper": 0.01, "upper_inclusive": false, "count": 230737}]
  },
  "snapshot": {
    "path": "first-epss/epss-scores-2026-09-18.csv.gz",
    "format": "csv.gz", "row_count": 376715, "score_date": "2026-09-18",
    "sha256": "<compressed-source-body-sha256>", "bytes": 2651322,
    "url": "<immutable-collection-release-download-url>/epss-scores-2026-09-18.csv.gz"
  }
}
```

This excerpt shows only the first distribution bucket; the output always includes all five: `[0,.01)`, `[.01,.1)`, `[.1,.5)`, `[.5,.9)`, `[.9,1]`. The compressed original contains every CVE, score and percentile. It is both a standalone immutable release asset and a member of the run tarball. Its `path` is relative to `output/`; `url` exists in workflow executions. The index remains small.

Stocks are not newly high CVEs. Entrants/exits require joining successive complete snapshots by CVE, with consistent model versions and explicit missing days. Model changes must break comparisons or be labeled. Historical missing EPSS days are null observations, never zero.

## Structured advisories and declared coverage

GitHub `github-advisories-reviewed` and `github-advisories-malware` use the official advisory API independently. Each source begins with an explicit 30-day bootstrap window; its checkpoint records `coverage_from` and never claims a complete historical corpus. Requests fix a modification-date upper bound, follow validated `Link` cursors, and process at most `GHSA_MAX_PAGES` (default 5, 100 rows per page) per run. A failed page retains its cursor. Only a fully traversed window advances `through`; later windows overlap by one day. Native withdrawals are retained. An optional `GH_TOKEN` raises the public API rate budget; it is sent only to `api.github.com` and is never archived.

`osv-vulnerabilities` uses official per-ecosystem `modified_id.csv` manifests and native JSON records. Default ecosystems are npm, PyPI, Go, crates.io, Maven, NuGet, RubyGems, Packagist, GitHub Actions and `[EMPTY]` (withdrawn records without an ecosystem). `OSV_ECOSYSTEMS` can explicitly configure this comma-separated scope; changing scope requires a fresh state directory and a declared bootstrap. Checkpoints include that scope and `coverage_from`; a recent scoped slice is never labeled the global OSV corpus.

OSV processes up to `OSV_MAX_RECORDS` (default 500) changed records per run. Per-record source modification checkpoints are persisted only on successful downloads. Every poll re-reads the scoped manifests and prioritizes the newest unseen versions, so backlog work cannot hide current changes. Failed and deferred versions remain eligible on subsequent runs. `through` advances only when all listings and outstanding versions succeed. `pending_count`, `processed_versions`, and errors expose backlog and failure. Records with matching GHSA/CVE aliases require downstream canonical deduplication; raw source observations must remain distinct.

These APIs/manifests expose current versions, not a lossless historical event log: multiple upstream edits between polls may collapse to their latest state, and old withdrawals outside the declared bootstrap window are absent. Higher polling frequency and full archival improve recovery without pretending to eliminate this limit. A provider that removes a record without publishing a withdrawal cannot establish a tombstone here.

## Durability, recovery and validation

Each request saves a losslessly gzipped input and a request manifest containing its URL, fetched timestamp, HTTP headers (safe allowlist), source checksum and archived checksum. `manifest.json` checksums every run file. The workflow bundles those inputs, indexes and EPSS artifact into `threat-intel-DATE.tar.gz`, and checkpoint state into `collection-state.tar.gz`; top-level `SHA256SUMS` covers release bundles. The next run restores state from the newest `collection-*` release. It never trusts the short-lived Actions cache. Concurrency serialization prevents competing checkpoint writers.

Run tags are `collection-YYYYMMDDTHHMMSSZ-RUN_ID-ATTEMPT`; they are published as prereleases with `latest=false`. Index assets retain `index-YYYY-MM-DD.json` for compatibility. **Enumerate every collection tag and asset to replay incremental records.** Do not use only the mutable daily view. Retain each processed run ID/cursor, then deduplicate canonical records and revisions in the consuming evidence store. Existing daily releases remain replayable for the period before collection tags began.

All network requests have timeouts, bounded retries and a 128 MiB body/decompression limit. A failed source reports diagnostics and does not fabricate data. An interrupted process before index/archive completion leaves the previous durable release checkpoint intact, so the next run repeats eligible evidence. Partially successful runs are archived with matching state before any daily view is updated.

Offline checks:

```bash
python3 scripts/validate_sources.py
python3 scripts/test_index.py
python3 scripts/test_collect.py
python3 scripts/backfill/test_backfill.py
python3 scripts/backfill/validate.py
```

Primary references: [FIRST daily data](https://www.first.org/epss/data), [GitHub global advisories](https://docs.github.com/en/rest/security-advisories/global-advisories), [OSV exports and modified manifests](https://google.github.io/osv.dev/data/).

## Bounded live verification (2026-09-18)

A local smoke collection fetched the complete EPSS CSV (376,715 unique CVEs; 4,348 at or above 0.5; model v2026.06.15), one 100-record page from each GHSA stream, two OSV records per run with resumed checkpoints, 1,273 DeFiLlama rows, 2,216 Talos reports, and all 66 Solidity bug rows. Solidity dates stayed null and Talos IDs remained usable without invented links. All of those inputs parsed after correcting OSV IDs that contain colons. CISA's primary endpoint returned HTTP 403 from this environment; the later official mirror fallback recovered all 1,715 KEV rows with explicit provenance. A bounded CNA enrichment smoke then fetched two native CVE5 records and reported its remaining 1,713 admitted identifiers as pending. This smoke verification did not run the full catalog, publish releases, populate an application database, or establish complete advisory history.

## Official KEV recovery and scoped CNA enrichment

When the canonical CISA endpoint fails or returns an invalid catalog, the same `cisa-kev` source uses CISA's official `cisagov/kev-data` mirror (`develop/known_exploited_vulnerabilities.json`). `source.provenance` records the primary URL, actual effective URL, whether fallback was used, and outcomes of both attempts. Raw metadata retains CISA's catalog release date/version; the mirror never becomes a second vulnerability provider or duplicate source identity. [CISA's mirror documentation](https://github.com/cisagov/kev-data) states its relationship and update timing.

`cve-cna` enriches only CVE identifiers already observed in successful KEV or GHSA input. It reads individual CVE5 records from the [official CVE List cache](https://github.com/CVEProject/cvelistV5). It does not traverse the full CVE corpus. Default `CVE_MAX_RECORDS=200` bounds each run; durable state tracks the admitted identifiers, discovery providers, last check, content checksum, native modification date and errors. Identifiers become eligible for recheck after 24 hours and are processed in oldest-check order, preserving upstream discovery order for ties; the budget can extend refresh latency. Newly eligible identifiers and failures remain visible in checkpoint counts. Native rejected revisions are retained, including rejection reasons, without inventing a rejection date when one is absent.

Native `cveMetadata` and complete CNA/ADP containers remain in `item.raw`. Top-level ID/date/summary/reference fields copy the native record; affected product versions, problem-type CWEs and provider attribution remain structured. Every successful recheck is emitted (unchanged content does not create a semantic revision in the app), and every fetched raw revision remains in its immutable run archive. A mismatch between the requested identifier and response is rejected. This source reports incremental, explicitly scoped coverage rather than claiming global CVE completeness.
