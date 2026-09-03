# Midkernel Threat Intel

Public catalog of threat-intel **RSS/Atom** feeds and a few official **JSON** catalogs that have no RSS.

We **package and cite**. We do not originate. We do not rank here.

The public git product is this catalog plus a GitHub Action that fetches the listed URLs once a day and uploads a snapshot as an Actions artifact (raw bodies + a day's index). Aggregation, ranking, and class mapping live elsewhere (private).

## What this repo is

- `sources.yaml` — the catalog (name, url, format, surface, one-line why)
- `.github/workflows/daily.yml` — daily fetch + artifact upload
- A tiny fetch/index script (bash `curl` + Python stdlib XML/JSON). No ranking library, no ML, no class mapping

Daily dumps are **not** committed to git. They can be large. Download the `threat-intel-YYYY-MM-DD` artifact from the Action run.

## What this repo is not

Out of scope here (on purpose):

- Ranking or a 1–N score
- Class taxonomy (`evm.reentrancy`, `web2.authz-idor`, …)
- Adapters that transform sources into Midkernel classes
- A `--threat` API or focused Scan pin
- Status labels such as watching / trending / active-exploit
- Generating a Midkernel RSS of ranked classes
- Website HTML

[website#9](https://github.com/midkernel/website/issues/9) is still the website RSS ask. This repo does **not** generate that site feed yet.

Issues [#1](https://github.com/midkernel/threat-intel/issues/1)–[#4](https://github.com/midkernel/threat-intel/issues/4) describe ranking, classes, adapters, and a class-status RSS. They are not implemented in this catalog.

## Sources

URLs below returned HTTP 200 on 2026-09-03. Do not invent replacements without checking.

### Web2

| Name | Format | Why |
| --- | --- | --- |
| [CISA KEV catalog JSON](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) | json | Official KEV catalog; CISA retired the KEV RSS feed in 2025 |
| [CIRCL Vulnerability-Lookup CISA KEV Atom](https://vulnerability.circl.lu/known-exploited-vulnerabilities.atom) | atom | Third-party Atom feed of the same CISA KEV list |
| [GitHub Security blog RSS](https://github.blog/security/feed/) | rss | Official GitHub Security blog posts |
| [GitHub advisory-database commits Atom](https://github.com/github/advisory-database/commits/main.atom) | atom | Change signal for the GHSA dump; not a per-advisory RSS |
| [MSRC Security Update Guide RSS](https://api.msrc.microsoft.com/update-guide/rss) | rss | Microsoft Security Update Guide feed |
| [oss-security RSS](https://seclists.org/rss/oss-sec.rss) | rss | Public oss-security mailing-list archive |
| [Full Disclosure RSS](https://seclists.org/rss/fulldisclosure.rss) | rss | Public Full Disclosure mailing-list archive |
| [Exploit-DB RSS](https://www.exploit-db.com/rss.xml) | rss | Public Exploit-DB item feed |
| [Google Project Zero Atom](https://googleprojectzero.blogspot.com/feeds/posts/default) | atom | Google Project Zero blog posts |
| [Trail of Bits blog RSS](https://blog.trailofbits.com/feed/) | rss | Trail of Bits security research blog |
| [Krebs on Security RSS](https://krebsonsecurity.com/feed/) | rss | Krebs on Security news posts |
| [Cloudflare security RSS](https://blog.cloudflare.com/tag/security/rss/) | rss | Cloudflare blog posts tagged security |
| [Nuclei templates commits Atom](https://github.com/projectdiscovery/nuclei-templates/commits/main.atom) | atom | Public weaponization index signal (template commits) |
| [FIRST EPSS JSON](https://api.first.org/data/v1/epss?limit=100) | json | Official scores; no RSS; recent slice only — do not dump ~367k rows |

### Web3

| Name | Format | Why |
| --- | --- | --- |
| [Immunefi blog RSS](https://immunefi.com/blog/rss/) | rss | Official Immunefi blog |
| [SlowMist Medium RSS](https://slowmist.medium.com/feed) | rss | SlowMist public Medium posts |
| [PeckShield Medium RSS](https://peckshield.medium.com/feed) | rss | PeckShield public Medium posts |
| [BlockSec Medium RSS](https://blocksecteam.medium.com/feed) | rss | BlockSec public Medium posts |
| [OpenZeppelin blog RSS](https://blog.openzeppelin.com/rss.xml) | rss | Official OpenZeppelin blog |
| [DeFiHackLabs commits Atom](https://github.com/SunWeb3Sec/DeFiHackLabs/commits/main.atom) | atom | Public Web3 incident write-up repo commits |
| [DeFiLlama hacks JSON](https://api.llama.fi/hacks) | json | Official incident catalog; not RSS |

### Wanted, not fetched

These are documented so nobody “fixes” the catalog with a dead or wrong URL:

- **Rekt.news** — wanted Web3 incident source. As of 2026-09-03 there is no working public feed (`/rss`, `/feed`, `/feed.xml`, and `feed.rekt.news` all returned 500). Do not add a dead URL.
- **OSV** — API only (`POST /v1/query`), not RSS. A future/private aggregator may query it. This Action does not.
- **CISA official KEV RSS** — retired May 2025. Use the JSON catalog above (and the CIRCL Atom mirror).
- **NVD CVE RSS** — 404. Not listed.
- **DeFiLlama research RSS** — market research, not hacks. The hacks JSON is the catalog we fetch.
- **Immunefi Medium** — omitted because the official Immunefi blog RSS is already listed.

## Daily Action

`.github/workflows/daily.yml`:

- Schedule: **every day at 11:00 UTC**, including weekends (morning in America/Sao_Paulo). Threat intel is time-critical.
- Also `workflow_dispatch` for a manual dry run. That is enough; CI does **not** hammer third parties on every pull request.
- User-Agent: `MidkernelThreatIntel/0.1 (+https://github.com/midkernel/threat-intel)`
- Each listed URL is fetched with `curl` (timeout, follow redirects). Raw bodies land under `output/<id>/`.
- `summary.md` lists, for each source: name, url, HTTP status, content-type, byte size. For RSS/Atom it copies item titles, links, and pubDates from the feed (document order, not ranked). For JSON catalogs it copies a count and the newest few ids/names the JSON already contains (KEV `cveID`, DeFiLlama hacks `name`/`date`). This is an index, not intelligence.
- The job uploads **one** artifact named `threat-intel-YYYY-MM-DD` containing the raw files and `summary.md`.
- **Failure policy:** a single source 5xx is a warning. The job fails only if a **majority** of sources fail. One dead blog must not kill the daily run.

```bash
# local dry run (writes ./output; do not commit it)
bash scripts/fetch.sh
```

## CI

Pull requests run a cheap check: `sources.yaml` parses, required fields are present, and every `url` looks like `https://…`. Offline unit checks cover the index helpers. Live fetches stay on the daily / `workflow_dispatch` workflow.

## Voice

Public voice is **Midkernel**, never MidKernel.
