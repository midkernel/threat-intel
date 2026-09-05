# Midkernel Threat Intel

Public catalog of threat-intel **RSS/Atom** feeds and a few official **JSON** catalogs that have no RSS.

We **package and cite**. We do not originate. We do not rank here.

The public git product is this catalog plus a GitHub Action that fetches the listed URLs once a day and publishes a snapshot as a GitHub Release (raw bodies + a day's markdown index + a structured JSON index). Aggregation, ranking, and class mapping live elsewhere (private).

## What this repo is

- `sources.yaml` — the catalog (name, url, format, surface, one-line why)
- `.github/workflows/daily.yml` — daily fetch, artifact upload, and a soft Release
- A tiny fetch/index script (bash `curl` + Python stdlib XML/JSON). No ranking library, no ML, no class mapping

Daily dumps are **not** committed to git. They can be large. Download `daily-YYYY-MM-DD` from [Releases](https://github.com/midkernel/threat-intel/releases). Actions artifacts remain a 14-day debug cache.

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

URLs below returned HTTP 200 on 2026-09-04. Do not invent replacements without checking.

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
| [CERT/CC Vulnerability Notes](https://www.kb.cert.org/vuls/atomfeed/) | atom | Coordinated vulnerability notes with affected-product, impact, mitigation, and vendor context |
| [Zero Day Initiative Published Advisories](https://www.zerodayinitiative.com/rss/published/) | rss | Original coordinated vulnerability disclosures with technical and remediation details |
| [SANS Internet Storm Center Handler's Diary](https://isc.sans.edu/rssfeed_full.xml) | rss | Operational observations on active scanning, exploitation, malware, phishing, and incident patterns |
| [The DFIR Report](https://thedfirreport.com/feed/) | rss | Evidence-backed intrusion timelines, attacker TTPs, detections, and MITRE ATT&CK mappings |
| [Google Threat Intelligence](https://feeds.feedburner.com/threatintelligence/pvexyqv7v0v) | rss | Mandiant and GTIG investigations, threat-actor research, campaign analysis, and mitigation guidance |
| [UK NCSC Threat Reports](https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml) | rss | Vendor-neutral national cyber authority reporting on active threats and major campaigns |
| [Cisco Security Advisories](https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml) | rss | First-party Cisco PSIRT advisories for vulnerabilities requiring customer action |
| [Debian Security Advisories](https://www.debian.org/security/dsa-long) | rss | First-party Debian security advisories including complete advisory text and fixed package versions |
| [Ubuntu Security Notices](https://ubuntu.com/security/notices/rss.xml) | rss | First-party Ubuntu notices for fixed vulnerabilities across supported releases and packages |
| [Red Hat Security Advisories](https://security.access.redhat.com/data/meta/v1/rhsa.rss) | rss | First-party Red Hat Security Advisories released during the feed's recent rolling window |
| [GitLab Patch Releases](https://docs.gitlab.com/releases/patch-releases.xml) | atom | First-party GitLab patch and security releases with affected and fixed versions |
| [CERT-FR Threat and Incident Reports](https://www.cert.ssi.gouv.fr/cti/feed/) | rss | ANSSI and CERT-FR analysis of threat actors, campaigns, malware, and incident investigations |
| [JPCERT/CC English Alerts](https://www.jpcert.or.jp/english/rss/jpcert-en.rdf) | rss | English-language security alerts and incident information from Japan's national CSIRT |
| [CISA Cybersecurity Advisories RSS](https://www.cisa.gov/cybersecurity-advisories/all.xml) | rss | Official CISA advisories and alerts feed; KEV RSS is gone but this one still serves |
| [CVE List V5 commits Atom](https://github.com/CVEProject/cvelistV5/commits/main.atom) | atom | Change signal for the official CVE record repo; NVD has no RSS |
| [Metasploit Framework commits Atom](https://github.com/rapid7/metasploit-framework/commits/master.atom) | atom | Public weaponization signal from module commits, same idea as nuclei-templates |
| [PoC-in-GitHub commits Atom](https://github.com/nomi-sec/PoC-in-GitHub/commits/master.atom) | atom | Auto-collected index of CVE PoCs on GitHub; PoC-availability signal |
| [OpenSSF malicious-packages commits Atom](https://github.com/ossf/malicious-packages/commits/main.atom) | atom | Change signal for the OSSF malicious package reports (npm, PyPI, crates, and more) |
| [GreyNoise blog RSS](https://www.greynoise.io/blog/rss.xml) | rss | Mass-exploitation and scanner-traffic analyses per CVE |
| [PortSwigger Research RSS](https://portswigger.net/research/rss) | rss | Web application vulnerability-class research (authz, injection, desync) |
| [watchTowr Labs RSS](https://labs.watchtowr.com/rss) | rss | N-day and 0-day exploitation research on edge and enterprise software |
| [Sonar blog RSS](https://www.sonarsource.com/blog/rss.xml) | rss | Code-level vulnerability research in open-source web apps |
| [Talos Vulnerability Reports RSS](https://talosintelligence.com/vulnerability_reports/feed) | rss | Cisco Talos per-vulnerability disclosure reports |
| [Unit 42 RSS](https://unit42.paloaltonetworks.com/feed) | rss | Palo Alto Unit 42 threat and exploitation research |
| [Rapid7 blog RSS](https://blog.rapid7.com/rss) | rss | Rapid7 vulnerability analyses and Metasploit wrap-ups |
| [Check Point Research RSS](https://research.checkpoint.com/feed) | rss | Check Point Research vulnerability and malware write-ups |
| [Qualys Vulnerabilities and Threat Research RSS](https://blog.qualys.com/vulnerabilities-threat-research/feed) | rss | Qualys TRU disclosures (glibc, OpenSSH, sudo class of bugs) |
| [VulnCheck blog Atom](https://vulncheck.com/feed/blog/atom.xml) | atom | Exploitation-trend and KEV-gap analyses |
| [FortiGuard PSIRT Advisories RSS](https://filestore.fortinet.com/fortiguard/rss/ir.xml) | rss | Official Fortinet PSIRT advisories |
| [Palo Alto Networks Security Advisories RSS](https://security.paloaltonetworks.com/rss.xml) | rss | Official Palo Alto Networks security advisories |
| [RustSec advisory-db commits Atom](https://github.com/rustsec/advisory-db/commits/main.atom) | atom | Change signal for Rust crate advisories; upstream of GHSA for crates |
| [Go vulnerability database commits Atom](https://github.com/golang/vulndb/commits/master.atom) | atom | Change signal for the official Go vulnerability database |
| [PyPA advisory-database commits Atom](https://github.com/pypa/advisory-database/commits/main.atom) | atom | Change signal for the official PyPI advisory database |
| [Datadog Security Labs RSS](https://securitylabs.datadoghq.com/rss/feed.xml) | rss | Cloud and supply-chain attack research |
| [Elastic Security Labs RSS](https://www.elastic.co/security-labs/rss/feed.xml) | rss | Malware and intrusion research with detection details |
| [Wiz blog RSS](https://www.wiz.io/feed/rss.xml) | rss | Cloud vulnerability research |
| [Kaspersky Securelist RSS](https://securelist.com/feed) | rss | Securelist threat research |
| [ESET WeLiveSecurity RSS](https://www.welivesecurity.com/en/rss/feed) | rss | ESET threat research |
| [Microsoft Security blog RSS](https://www.microsoft.com/en-us/security/blog/feed) | rss | Microsoft Threat Intelligence posts; complements the MSRC update guide |
| [BleepingComputer RSS](https://www.bleepingcomputer.com/feed) | rss | Fast news on actively exploited bugs and breaches |
| [The Record RSS](https://therecord.media/feed) | rss | Recorded Future News; cybercrime and policy coverage |

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
| [Security Alliance Radar](https://radar.securityalliance.org/rss/) | rss | Crypto-native threat intelligence covering incidents, IOCs, drainers, phishing, DPRK, and supply-chain campaigns |
| [Web3 Is Going Just Great](https://www.web3isgoinggreat.com/feed.xml) | atom | Continuously updated chronology of Web3 hacks, scams, bugs, collapses, and affected technologies |
| [Zellic Research](https://www.zellic.io/blog/rss.xml) | rss | Technical smart-contract and protocol vulnerability research with exploit and incident analysis |
| [Halborn Security Blog](https://www.halborn.com/blog/feed.xml) | rss | Recurring explanations of blockchain hacks, exploit mechanisms, and defensive lessons |
| [Rekt RSS](https://rekt.news/rss/feed.xml) | rss | Live Rekt feed; research pieces only, not the hack post-mortems |
| [Solidity known compiler bugs JSON](https://raw.githubusercontent.com/ethereum/solidity/develop/docs/bugs.json) | json | Official catalog of Solidity compiler bugs (uid, severity, affected versions) |
| [Solidity bugs.json commits Atom](https://github.com/ethereum/solidity/commits/develop/docs/bugs.json.atom) | atom | Change signal scoped to the compiler bug catalog file |
| [Solidity blog Security Alerts RSS](https://soliditylang.org/security-alerts/feed.xml) | rss | Official Solidity security-alert posts |
| [BlockThreat RSS](https://blockthreat.com/rss/) | rss | Weekly blockchain security briefing |
| [Neodyme blog RSS](https://neodyme.io/rss.xml) | rss | Solana and cross-chain security research; non-EVM coverage |
| [Chainalysis blog RSS](https://blog.chainalysis.com/feed) | rss | Hack and crypto-crime reporting with fund-flow analysis |
| [Ackee Blockchain blog RSS](https://ackee.xyz/blog/feed) | rss | Audit firm research posts (Solana, EVM) |

### Wanted, not fetched

These are documented so nobody “fixes” the catalog with a dead or wrong URL:

- **Rekt.news `/rss`, `/feed`, `/feed.xml`** — still 500 as of 2026-09-04. Do not substitute those. The live URL is [`https://rekt.news/rss/feed.xml`](https://rekt.news/rss/feed.xml) (research posts only, not hack post-mortems), listed under Web3.
- **OSV** — API only (`POST /v1/query`), not RSS. A future/private aggregator may query it. This Action does not.
- **CISA official KEV RSS** — retired May 2025. Use the JSON catalog above (and the CIRCL Atom mirror). The broader CISA advisories RSS is listed.
- **NVD CVE RSS** — 404. Not listed. CVE List V5 commits Atom is the change signal.
- **DeFiLlama research RSS** — market research, not hacks. The hacks JSON is the catalog we fetch.
- **Immunefi Medium** — omitted because the official Immunefi blog RSS is already listed.
- **CERT/CC `/vulfeed`** — omitted; `certcc-vulnerability-notes` (`/vuls/atomfeed/`) is the listed CERT/CC feed.

## Daily Action

`.github/workflows/daily.yml`:

- Schedule: **every day at 11:00 UTC**, including weekends (morning in America/Sao_Paulo). Threat intel is time-critical.
- Also `workflow_dispatch` for a manual dry run. That is enough; CI does **not** hammer third parties on every pull request.
- User-Agent: `MidkernelThreatIntel/0.1 (+https://github.com/midkernel/threat-intel)`
- Each listed URL is fetched with `curl` (timeout, follow redirects). Raw bodies land under `output/<id>/`. JSON sources send `Accept: application/json` only — FIRST EPSS returns 400 if Accept lists RSS types.
- `summary.md` lists, for each source: name, url, HTTP status, content-type, byte size. For RSS/Atom it copies item titles, links, and pubDates from the feed (document order, not ranked). For JSON catalogs it copies a count and the newest few ids/names the JSON already contains (KEV `cveID`, DeFiLlama hacks `name`/`date`, Solidity bugs `uid`). This is an index, not intelligence.
- `index.json` is the same day's index in a stable machine-readable schema (see [Daily index JSON](#daily-index-json)). Prefer this asset for ingest; do not scrape `summary.md`.
- After the fetch, the job publishes a soft GitHub Release tagged `daily-YYYY-MM-DD` (title `Threat-intel fetch — YYYY-MM-DD UTC`) with the same payload as today's artifact: `summary-YYYY-MM-DD.md` (human index), `index-YYYY-MM-DD.json` (structured index; also `output/index.json` inside the tarball), and `threat-intel-YYYY-MM-DD.tar.gz` (`output/` — raw bodies + `summary.md` + `index.json` in document order). That is the durable public download path — browse [Releases](https://github.com/midkernel/threat-intel/releases) without an Actions login.
- The same `output/` tree is also uploaded as an Actions artifact named `threat-intel-YYYY-MM-DD` (14-day debug cache).
- Dumps stay out of git. Do not commit `output/`.
- **Failure policy:** a single source 5xx is a warning. The job fails only if a **majority** of sources fail. One dead blog must not kill the daily run.

```bash
# local dry run (writes ./output; do not commit it)
bash scripts/fetch.sh
```

## Daily index JSON

Each Release attaches `index-YYYY-MM-DD.json`. The tarball carries the same document as `output/index.json`. Midkernel/app should ingest that JSON instead of scraping the markdown summary.

This is a **feeds-only index**. It does not rank, classify, score, or attach Midkernel threat labels. The public repo stays catalog + fetch. No `--threat`.

### Schema (`midkernel.threat-intel.index/v1`)

Stable identifier: `schema` is the constant `midkernel.threat-intel.index/v1`. Additive fields may appear later; existing fields keep their meaning. Ranking, class taxonomy, scores, and `--threat` fields will not be added here.

**Document**

| Field | Type | Meaning |
| --- | --- | --- |
| `schema` | string | Constant `midkernel.threat-intel.index/v1` |
| `day` | string | Fetch day `YYYY-MM-DD` (UTC) |
| `generated_at` | string | UTC timestamp when the index was written (`YYYY-MM-DDTHH:MM:SSZ`) |
| `note` | string | Reminder that this is not ranking / not intelligence |
| `sources` | array | Catalog sources in `sources.yaml` document order |

**Source**

| Field | Type | Meaning |
| --- | --- | --- |
| `id` | string | Catalog id |
| `name` | string | Catalog name |
| `url` | string | Fetched URL |
| `format` | string | `rss` \| `atom` \| `json` |
| `surface` | string | `web2` \| `web3` |
| `http_status` | int \| null | HTTP status from the fetch; `null` if that source was not fetched |
| `fetched_at` | string \| null | UTC timestamp when that URL was fetched (`YYYY-MM-DDTHH:MM:SSZ`) |
| `item_count` | int | `len(items)` in this snapshot — not a remote catalog total |
| `items` | array | Entries in **document / catalog order**, not ranked |

**Item**

| Field | Type | Meaning |
| --- | --- | --- |
| `title` | string | Title, name, or CVE id already in the source |
| `url` | string \| null | Item link if the source provided one |
| `published_at` | string \| null | Source date string (copied, not normalized). Unix timestamps become `YYYY-MM-DD` |
| `id` | string \| null | RSS `guid`, Atom `id`, CVE id, Solidity `uid`, or other source-native id |

JSON catalogs map as follows (scores are omitted):

- CISA KEV: `vulnerabilityName` → `title`, `cveID` → `id`, `dateAdded` → `published_at`
- FIRST EPSS: `cve` → `title` and `id`, `date` → `published_at` (no `epss` / `percentile`)
- DeFiLlama hacks: `name` → `title`, `date` → `published_at`
- Solidity bugs: `name` → `title`, `uid` → `id`

Markdown `summary.md` remains the human-readable index. The tarball and `summary-YYYY-MM-DD.md` stay in the Release for backward compatibility.

## CI

Pull requests run a cheap check: `sources.yaml` parses, required fields are present, and every `url` looks like `https://…`. Offline unit checks cover the index helpers and the JSON emitter (fixture feeds, no live URLs). Live fetches stay on the daily / `workflow_dispatch` workflow.

## Voice

Public voice is **Midkernel**, never MidKernel.
