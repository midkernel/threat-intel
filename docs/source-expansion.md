# Source expansion and taxonomy proposal

Research date: **2026-09-16**. Baseline: catalog commit
[`ce1e611`](https://github.com/midkernel/threat-intel/tree/ce1e611e896aa1084ce31d119d40a51f8bd66868).

This expansion adds **15 feeds**, taking [the catalog](../sources.yaml) from
**74 to 89 sources**: 65 Web2 and 24 Web3, using 66 RSS, 19 Atom and four JSON
endpoints. It adds first-party cloud, infrastructure and runtime advisories;
identity and software supply-chain research; and Bitcoin, consensus-client,
non-EVM and wallet-security coverage.

The catalog keeps its six fields (`id`, `name`, `url`, `format`, `surface`, `why`)
and the index remains `midkernel.threat-intel.index/v1`. The taxonomy and
collection changes below are **proposals, not implemented by this expansion**.
Ranking and vulnerability-class mapping remain outside this repository.

## Added feeds and validation evidence

All 15 endpoints returned HTTP 200 and produced nonempty RSS/Atom item lists
through the existing [index parser](../scripts/index.py). Checks were recorded
on **2026-09-16, 12:52:40–12:52:41 UTC**, following redirects. The table records
the exact configured URLs and recognized formats, rather than inferring format
from filename extensions. Counts describe those snapshots only.

| Source / exact feed URL | Format | Items | Coverage added |
| --- | --- | ---: | --- |
| [AWS Security Bulletins](https://aws.amazon.com/security/security-bulletins/rss/feed/) | RSS | 42 | Official AWS service and software security bulletins |
| [Google Cloud Security Bulletins](https://cloud.google.com/feeds/google-cloud-security-bulletins.xml) | Atom | 30 | Official cloud advisories and mitigation guidance |
| [Kubernetes Official CVE Feed](https://kubernetes.io/docs/reference/issues-security/official-cve-feed/feed.xml) | RSS | 91 | Official Kubernetes project CVEs |
| [Jenkins Security Advisories](https://www.jenkins.io/security/advisories/rss.xml) | RSS | 102 | CI controller and plugin advisories |
| [HashiCorp Security Updates](https://discuss.hashicorp.com/c/security/52.rss) | RSS | 25 | Vault, Consul, Terraform and related security notices |
| [Okta Security](https://sec.okta.com/rss.xml) | RSS | 86 | Identity threats, advisories and original research |
| [Node.js Vulnerability Reports](https://nodejs.org/en/feed/vulnerability.xml) | RSS | 76 | Runtime security-release announcements |
| [Socket](https://socket.dev/api/blog/feed.atom) | Atom | 10 | Malicious packages and dependency investigations |
| [StepSecurity](https://www.stepsecurity.io/blog/rss.xml) | RSS | 100 | GitHub Actions, CI/CD and package-compromise research |
| [Chrome Stable Releases](https://chromereleases.googleblog.com/feeds/posts/default/-/Stable%20updates?alt=rss) | RSS | 25 | Stable-channel browser security and release notices |
| [Bitcoin Core](https://bitcoincore.org/en/rss.xml) | RSS | 112 | First-party node/client disclosures and release notices |
| [Asymmetric Research](https://blog.asymmetric.re/rss/) | RSS | 15 | Protocol, validator, Solana and bridge research |
| [OtterSec](https://osec.io/rss.xml) | RSS | 36 | Non-EVM, Solana/Move and protocol security research |
| [Sigma Prime](https://sigmaprime.io/blog/feed.xml) | RSS | 50 | Consensus/client and cryptography research |
| [Ledger Donjon](https://donjon.ledger.com/blog/rss.xml) | RSS | 5 | Wallet, hardware and cryptographic implementation research |

These checks establish transport and parser compatibility at the recorded time.
They do not establish future availability, complete historical coverage, or one
vulnerability per entry. One bulletin can cover several CVEs; several publishers
can report the same incident.

### Scope and selection limits

- Google Cloud redirects to [the documentation-domain feed](https://docs.cloud.google.com/feeds/google-cloud-security-bulletins.xml).
  It is **Atom**, and its 30-entry window is not the complete bulletin archive.
  Source update timestamps must not be treated as original incident dates.
- Chrome uses the publisher's `Stable updates` label. It excludes Extended
  Stable and most ChromeOS/LTS labels, and includes routine release notices.
- Kubernetes covers the project's official CVE issue set, not every operator
  or container image. Jenkins and Node.js publish announcements that can bundle
  several vulnerabilities. AWS also includes informational bulletins.
- HashiCorp's category exposes recent topics; Socket exposes only ten entries.
  Rolling feeds can discard entries between daily polls. Their item counts are
  fetched rows, not archive sizes or evidence of complete daily coverage.
- Okta, Socket, StepSecurity, OtterSec and Sigma Prime mix original security
  material with other publishing. Source membership is not an item-level verdict.
- Bitcoin Core's [blog feed](https://bitcoincore.org/en/rss/) retains disclosures
  missing from the smaller announcements feed. Asymmetric's full feed retains
  relevant recent research missing from its research-tag feed.
- Ledger Donjon's blog RSS does **not** include the separate
  [Ledger Security Bulletins](https://donjon.ledger.com/lsb/). That HTML bulletin
  index needs separate evaluation; adding research RSS does not close that gap.

## Optional second wave

These five endpoints also returned HTTP 200 and valid, nonempty RSS on
2026-09-16. They are not added in this expansion because their broader publishing
needs evaluation against the useful original coverage already available.

| Candidate / exact feed URL | Value | Limitation |
| --- | --- | --- |
| [Permiso](https://permiso.io/blog/rss.xml) | Cloud identity and SaaS intrusion research | Ten-entry mixed research/product window |
| [Aikido](https://www.aikido.dev/blog/rss.xml) | Malicious packages and application security | Substantial product/comparison publishing |
| [Ethereum Foundation](https://blog.ethereum.org/en/feed.xml) | First-party protocol and security notices | Broad grants, events and ecosystem feed |
| [Sui](https://www.sui.io/blog/rss.xml) | Move-chain incident and remediation context | Broad ecosystem feed; outages do not imply exploitation |
| [Least Authority](https://leastauthority.com/feed/) | Privacy, cryptography and audit expertise | General blog; published-audit catalog is separate |

## Proposed source taxonomy

Keep `surface: web2|web3` and stable source IDs. Add independent, optional facets
that describe usual source coverage, rather than replacing surface with a larger
flat category list or classifying every item from its publisher.

| Facet | Proposed values / shape | Purpose |
| --- | --- | --- |
| `content_types` | Array: advisory, research, incident-report, threat-report, news, vulnerability-catalog, incident-catalog, score-catalog, change-stream | Distinguish articles, records, scores and notifications |
| `domains` | Array: application, cloud, identity, supply-chain, endpoint, network, ot, blockchain | Describe the security problem areas covered |
| `ecosystems` | Optional namespaced tags such as `platform:kubernetes`, `runtime:evm`, `chain:solana`, `chain:bitcoin` | Express technology coverage independently of weakness |
| `publisher_id` | Stable publisher identifier | Preserve ownership independently of hosting domain |
| `relationships` | Objects with type, source ID and evidence URL; mirror-of, change-stream-for, overlaps-with | Document known dependence without claiming independent corroboration |
| `collection` | Mode: rolling-feed, full-catalog, bounded-slice; record unit and coverage note | State what a fetched record means and the snapshot's limits |

The current [catalog validator](../scripts/catalog.py) rejects extra fields and
its scalar YAML reader does not support typed arrays. A future implementation
should introduce a validated `source-metadata.json` keyed by existing IDs.
Reject dangling IDs, invalid enums and malformed relationships; allow partial
backfill. Use a supported `json_profile` identifier for structured endpoints.
Review vocabulary against representative sources before annotating all sources.

The sidecar can later populate optional source `metadata` in index v1 while
preserving existing field types, meanings and IDs. Keep `item_count` as fetched
row count. Add separate parse status, recognized format, body hash, byte count
and catalog revision; preserve source-native update dates separately from
publication dates. Test valid empty feeds, unsupported JSON, HTTP-200 non-feeds,
metadata references and legacy records without metadata before rollout.

Source taxonomy remains distinct from consumer vulnerability classes. In the
consumer, separate weakness/root cause, affected technology, adversary behavior
and evidence state. Map supported weaknesses to [CWE](https://cwe.mitre.org/about/index.html)
and observed behavior to [ATT&CK](https://attack.mitre.org/) where justified.
A bridge is a component, a flash loan is a mechanism, and an operational halt
does not establish hostile exploitation. Preserve unknown classifications and
item-level provenance rather than deriving state from feed membership.

## Existing collection quality observations

The [2026-09-16 release](https://github.com/midkernel/threat-intel/releases/tag/daily-2026-09-16)
index, generated at **11:08:39 UTC**, had usable entries from 72 of 74 sources.
CISA advisories returned 403 and Halborn 429. These are snapshot observations,
not permanent availability conclusions.

| Observation in that snapshot | Follow-up |
| --- | --- |
| PeckShield Medium's newest entry was 2021-08-15; NCSC threat reports' was 2025-05-07 | Review editorial scope and publisher-advertised replacements; HTTP success alone does not establish current coverage |
| CIRCL included provider-labelled Previdian and CISA entries | Describe aggregated KEV coverage and retain attribution; avoid labelling the whole feed a CISA-only mirror ([feed documentation](https://www.vulnerability-lookup.org/user-manual/feed-syndication/)) |
| EPSS uses `limit=100`, with score dates rather than vulnerability-publication dates | Describe a bounded score sample; use documented bulk access for full daily data ([FIRST guidance](https://www.first.org/epss/data)) |
| CVE List V5's 20 commits spanned 3h57m; GHSA's spanned 18h02m; OpenSSF malicious-packages' spanned 17h40m | Treat these as change notifications; daily snapshots can miss changes, though this review did not count missed records |
| HTTP-200 invalid/unsupported XML can produce zero indexed items | Report parse health separately from transport and publication age |

Preserve the resilient daily job while exposing per-source failures and last
successful parses. Quiet maintainer advisories can remain useful; publication
age alone should not disable them. Evaluate expansion by original useful records,
ecosystem coverage and collection gaps, alongside source count.

## Structured ingestion backlog

These sources require explicit parser and collection work before catalog entry:

| Priority source | Endpoint or documentation | Required support |
| --- | --- | --- |
| OSV records and change manifests | [Official distribution documentation](https://google.github.io/osv.dev/data/) | OSV profile; bounded incremental retrieval, durable checkpoints, aliases, revisions and withdrawals |
| curl vulnerability records | [Official OSV JSON](https://curl.se/docs/vuln.json), [publisher documentation](https://curl.se/docs/security.html) | OSV-array profile; current generic list handling expects `name` and skips these records |
| Cosmos SDK advisories | [Repository advisory API](https://api.github.com/repos/cosmos/cosmos-sdk/security-advisories?per_page=100) | GHSA profile; 14 rows observed on 2026-09-16 |
| IBC-Go advisories | [Repository advisory API](https://api.github.com/repos/cosmos/ibc-go/security-advisories?per_page=100) | GHSA profile; three rows observed on 2026-09-16 |
| CometBFT advisories | [Repository advisory API](https://api.github.com/repos/cometbft/cometbft/security-advisories?per_page=100) | GHSA profile; 12 rows observed on 2026-09-16 |

OSV provides individual records, archives and `modified_id.csv` manifests; it is
not API-only. GitHub records require explicit `ghsa_id`, `summary`, `html_url`
and publication/update mapping, plus pagination, rate-limit and withdrawal
handling following the [repository-advisory API documentation](https://docs.github.com/en/rest/security-advisories/repository-advisories#list-repository-security-advisories).
Adding `format: json` alone would not index these schemas correctly.

Prioritize OSV and GHSA ingestion before vendor CSAF/VEX or selective NVD
enrichment. Preserve upstream IDs, revisions and references; package matching,
equivalence decisions, evidence judgments and prioritization remain in the
consumer. Scoped maintainer APIs may overlap the existing GHSA database and
should not be counted as independent confirmations of the same advisory.
