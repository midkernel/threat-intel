# Midkernel Threat Intel

Public catalog of threat-intel **RSS/Atom** feeds and a few official **JSON** catalogs that have no RSS.

We **package and cite**. We do not originate. We do not rank here.

The public git product is this catalog plus a GitHub Action that fetches the listed URLs every four hours and archives each collection as an immutable GitHub Release (raw bodies + a day's markdown index + a structured JSON index). This repository preserves upstream evidence and produces descriptive stock statistics; application aggregation and class mapping live elsewhere (private).

## What this repo is

- `sources.yaml` — the catalog (name, url, format, surface, one-line why)
- `.github/workflows/daily.yml` — four-hour collection, durable per-run archives/checkpoints, and a compatible daily view
- Python stdlib collectors for feeds, structured advisory changes and complete EPSS snapshots. No ranking library, ML, or class mapping

Daily dumps are **not** committed to git. They can be large. Download `daily-YYYY-MM-DD` from [Releases](https://github.com/midkernel/threat-intel/releases). Actions artifacts remain a 14-day debug cache.

Derived **historical backfill** for CISA KEV, FIRST EPSS (counts only), and DeFiLlama hacks **is** committed under [`backfill/`](backfill/README.md) so midkernel/app can build trends before the first daily Release (`daily-2026-09-05`). That tree still only packages and cites. It does not rank. Raw EPSS CSVs are never committed.

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

The catalog contains **93 sources** (69 Web2, 24 Web3). Original URLs were verified on 2026-09-04; the 15 additions on 2026-09-16 returned HTTP 200 and parsed with nonempty items using the existing index parser. Availability and publication frequency can change. Do not invent replacement URLs without checking.

See [source expansion and taxonomy proposal](docs/source-expansion.md) for verification evidence, feed limitations, optional sources, and proposed metadata improvements.

### Web2

| Name | Format | Why |
| --- | --- | --- |
| [CISA KEV catalog JSON](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) | json | Official KEV catalog; CISA retired the KEV RSS feed in 2025 |
| [CIRCL Vulnerability-Lookup aggregated KEV Atom](https://vulnerability.circl.lu/known-exploited-vulnerabilities.atom) | atom | Aggregated KEV entries from CISA and other providers; retain per-item provider attribution |
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
| [FIRST EPSS daily CSV](https://epss.empiricalsecurity.com/epss_scores-current.csv.gz) | json + csv.gz | Complete per-CVE sidecar and dated stock statistics; score date is not publication date |
| [GitHub reviewed advisories](https://api.github.com/advisories?type=reviewed) | json | Structured affected packages, aliases, modifications and withdrawals |
| [GitHub malware advisories](https://api.github.com/advisories?type=malware) | json | Explicit malware stream, with affected package versions and upstream evidence |
| [CVE Program CNA records](https://github.com/CVEProject/cvelistV5) | json | Bounded enrichment of KEV/GHSA identifiers with CNA affected versions, CWEs and rejected state |
| [OSV exports](https://google.github.io/osv.dev/data/) | json | Scoped incremental records from per-ecosystem manifests, including withdrawals |
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
| [CISA Cybersecurity Advisories RSS](https://www.cisa.gov/cybersecurity-advisories/all.xml) | rss | Official CISA cybersecurity advisories and alerts; separate from the retired KEV RSS |
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
| [AWS Security Bulletins](https://aws.amazon.com/security/security-bulletins/rss/feed/) | rss | First-party cloud bulletins covering AWS services and AWS-maintained software, with customer mitigation guidance |
| [Google Cloud Security Bulletins](https://cloud.google.com/feeds/google-cloud-security-bulletins.xml) | atom | First-party Google Cloud security bulletins with affected services, remediation and vulnerability references |
| [Kubernetes Official CVE Feed](https://kubernetes.io/docs/reference/issues-security/official-cve-feed/feed.xml) | rss | Official Kubernetes CVE announcements for core and covered project components |
| [Jenkins Security Advisories](https://www.jenkins.io/security/advisories/rss.xml) | rss | First-party Jenkins core and plugin advisories with affected components and remediation context |
| [HashiCorp Security Updates](https://discuss.hashicorp.com/c/security/52.rss) | rss | First-party HashiCorp security announcements covering Vault, Consul, Terraform and related components |
| [Okta Security](https://sec.okta.com/rss.xml) | rss | Original Okta identity-threat reporting, security advisories and security research |
| [Node.js Vulnerability Reports](https://nodejs.org/en/feed/vulnerability.xml) | rss | First-party Node.js vulnerability and security-release announcements for runtime and dependency exposure |
| [Socket Blog](https://socket.dev/api/blog/feed.atom) | atom | Original malicious-package and software supply-chain investigations from Socket |
| [StepSecurity Blog](https://www.stepsecurity.io/blog/rss.xml) | rss | Original GitHub Actions, CI/CD and package compromise investigations with defensive guidance |
| [Chrome Stable Releases](https://chromereleases.googleblog.com/feeds/posts/default/-/Stable%20updates?alt=rss) | rss | First-party Chrome Stable updates label; security and release notices, excluding other release-channel labels |

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
| [Bitcoin Core blog](https://bitcoincore.org/en/rss.xml) | rss | First-party Bitcoin node disclosures and update notices fill the missing Bitcoin/client layer |
| [Asymmetric Research](https://blog.asymmetric.re/rss/) | rss | Original protocol, validator, Solana and bridge research complements incident aggregators |
| [OtterSec research](https://osec.io/rss.xml) | rss | Independent original research on wallet integrations, proof systems, protocol risk and multi-chain audits |
| [Sigma Prime blog](https://sigmaprime.io/blog/feed.xml) | rss | Adds consensus-client/Lighthouse engineering and cryptography security context, underrepresented by contract-centric feeds |
| [Ledger Donjon research](https://donjon.ledger.com/blog/rss.xml) | rss | Wallet hardware, signing and cryptographic implementation research; excludes the separate Ledger security bulletins |

### Wanted, not fetched

These are documented so nobody “fixes” the catalog with a dead or wrong URL:

- **Rekt.news `/rss`, `/feed`, `/feed.xml`** — still 500 as of 2026-09-04. Do not substitute those. The live URL is [`https://rekt.news/rss/feed.xml`](https://rekt.news/rss/feed.xml) (research posts only, not hack post-mortems), listed under Web3.
- **CISA official KEV RSS** — retired May 2025. Use the official JSON catalog above. CIRCL also aggregates KEV entries from CISA and other providers; it is not a CISA-only mirror. The broader CISA advisories RSS is listed.
- **NVD CVE RSS** — 404. Not listed. CVE List V5 commits Atom is the change signal.
- **DeFiLlama research RSS** — market research, not hacks. The hacks JSON is the catalog we fetch.
- **Immunefi Medium** — omitted because the official Immunefi blog RSS is already listed.
- **CERT/CC `/vulfeed`** — omitted; `certcc-vulnerability-notes` (`/vuls/atomfeed/`) is the listed CERT/CC feed.

## Collection and evidence contract

The workflow runs at 03:00, 07:00, 11:00, 15:00, 19:00 and 23:00 UTC. Each run archives an immutable `collection-YYYYMMDDTHHMMSSZ-RUN_ID-ATTEMPT` release with raw inputs, index, checksums, sidecars and its matching incremental checkpoint. These releases are prereleases (`latest=false`); they are never overwritten by the workflow. Successful runs also refresh the compatible `daily-YYYY-MM-DD` release. Actions artifacts are a 14-day debug cache only.

**Incremental consumers must replay all `collection-*` indexes**, using immutable run identities and a durable cursor. The daily alias is only the latest view: it cannot recover earlier intraday GHSA/OSV batches. Raw inputs and checkpoints live in durable release assets, independent of Actions cache eviction. GitHub Release assets are administratively mutable; “immutable” here means the workflow never clobbers a collection run. Verify checksums on download.

[Evidence contract and operational details](docs/evidence-contract.md) document the additive v1 fields, coverage semantics, upstream limits, resumption and replay. Existing schema/fields keep their meanings; `parser_version` is now `2`. Source-native scores are preserved as attributed evidence, never a Midkernel ranking.

```bash
# Collect all catalog sources (network; writes ignored output and state directories).
bash scripts/fetch.sh

# Bounded source smoke collection.
GHSA_MAX_PAGES=1 OSV_MAX_RECORDS=2 python3 scripts/collect.py /tmp/intel-smoke \
  --state /tmp/intel-state --sources first-epss github-advisories-reviewed osv-vulnerabilities
```

Sources that fail to fetch or parse remain explicit failed observations. A majority of collection failures fails the job, but successful partial inputs and their corresponding checkpoints are still archived. Four-hour polling reduces rolling-feed gaps; it cannot recover material that disappeared before any successful observation.

## Historical backfill

[`backfill/`](backfill/README.md) holds monthly shards (`*/by-month/YYYY-MM.json`) derived from the official KEV JSON, empiricalsec EPSS daily CSVs (high-EPSS counts only; threshold `epss >= 0.5`), and the DeFiLlama hacks JSON.

- Max backfill day: **2021-04-14** (EPSS archive start). Last backfill day: **2026-09-04** (the UTC day before the first daily Release). Generate clamps `--to-day` there unless `--allow-past-last-day`.
- EPSS `high_count` is a **daily stock** (CVEs with `epss >= 0.5` that day), not new highs. Nine unavailable archive days are **unknown**, not zero or interpolated.
- KEV `dateAdded` starts **2021-11-03** (seed day). **2022 is a KEV backlog-drain year, not a real exploit spike.**
- DeFiLlama incident dates span years; `--from-day` is honored when set. Days without incidents are omitted.
- RSS/Atom sources are **not** backfilled. Do not invent old `daily-*` Releases.

Schemas are additive only: `midkernel.threat-intel.backfill.{kev,epss,defillama,manifest}/v1`. See [`backfill/README.md`](backfill/README.md).

```bash
python3 scripts/backfill/generate.py --smoke --out /tmp/backfill-smoke
python3 scripts/backfill/validate.py
```

A full live rebuild is `.github/workflows/backfill.yml` (`workflow_dispatch` only). CI does not download the EPSS daily archive on every pull request.

## CI

Pull requests run a cheap check: `sources.yaml` parses, required fields are present, and every `url` looks like `https://…`. Offline unit checks cover the index helpers, the JSON emitter, and backfill derive/schema checks (fixture catalogs, no live URLs). Live fetches stay on the daily / `workflow_dispatch` workflows.

## Voice

Public voice is **Midkernel**, never MidKernel.
