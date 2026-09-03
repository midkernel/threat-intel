# Midkernel Threat Intel

Package and rank **existing public** threat sources (Web2 + Web3). Point [Midkernel Scan](https://midkernel.com/platform) at a named threat class. We do **not** claim to originate every item.

Ships with Scan for subscribers. Free-tier feed exists; do not market by knocking it. Pricing is TBD — no numbers here.

This repo is the TI specifics. The marketing site only **renders** the RSS and a page Marketing designs. Do not put ingest, ranking, or class taxonomy in `midkernel/website`. Do not mix this with the private Grok Bot `midkernel/skills` recipe repo.

Related public product repos (not this one): `midkernel/workflows` (collaborative registry, PRs welcome), `midkernel/runner`, `midkernel/bench`. People pay for the **run**, sold on real cost-performance on public benches (EVMbench, Web3 targets, …) vs other public workflow sets. No fake ranking numbers.

## Object model

Rank **threat classes**, not news stories.

| Object | Id example | What it is |
| --- | --- | --- |
| Class | `evm.reentrancy`, `web2.authz-idor` | Stable, CWE-aligned where it fits. Maps to one or more workflows. |
| Item | source + url | One advisory, incident, PoC, or KEV row. Always cited. |
| Trend | class + window | Ranked row for a time window, with evidence = item ids. |

A class folder (later) looks like:

```
classes/evm.reentrancy/
  class.yaml      # id, surface (web2|web3), cwe, workflow ids
  focus.md        # public instruction block injected into a focused Scan
```

UI copy stays SPEC.md: **workflow** (never “skill” in product UI), profiles always `low` / `balanced` / `max` in that order. Do not rename profiles. James’s uses: `low` = PRs; `balanced` = routine (at least monthly + on model releases); `max` = launches, major versions, or when TI flags a trending threat.

## Sources (package, cite, don’t originate)

v0 adapters — public HTTP/RSS/API only. Each item stores `source`, `url`, `published_at`.

**Web2:** CISA KEV, NVD/CVE, GitHub Security Advisories, OSV, FIRST EPSS (ranking signal), weaponization signal from public Nuclei/Metasploit indexes.

**Web3:** Rekt.news, DeFiHackLabs, SlowMist Hacked, DeFiLlama hacks, Immunefi public post-mortems.

If we later publish an original Research note, it is tagged `origin: midkernel`. Everything else is `origin: source`.

## Ranking (method, not a fake leaderboard)

Until there is enough ingested data, **do not ship a 1–N score**. Publish the method; ship qualitative status: `watching` | `trending` | `active-exploit`.

Signals (all cited, none invented):

- Recency (half-life in the window)
- Distinct-source corroboration
- Exploitation evidence (KEV, live PoC, on-chain drain)
- Breadth (packages / protocols / cited TVL or loss **from the source**)

The paid product is the dashboard + insight paragraph + “scan this class” action. The RSS is the public feed of the same ranked classes, not a dump of raw KEV/Rekt items.

## RSS (website consumes this)

Engineering generates the feed in this repo. Website hosts it (see [website#9](https://github.com/midkernel/website/issues/9)). Marketing owns the HTML page.

- URL on the site: `https://midkernel.com/threat-intel/rss.xml`
- One RSS item per **class** that changed status in the window (not per source article)
- `<title>`: class label + status
- `<link>`: `https://midkernel.com/threat-intel/{class}`
- `<description>`: our insight + source list (links, not pasted bodies)
- `<category>`: `web2` or `web3`
- `<guid>`: stable class id + status change timestamp
- Existing `/rss.xml` stays research posts; `/changelog/rss.xml` stays changelog

## Focused Scan

A run remains: repo + workflow + profile. Focus is an extra pin, not a fourth profile.

```
midkernel run <repo> --workflow <id> --profile max --threat evm.reentrancy
```

`--threat <class>`:

1. Selects the workflow(s) mapped in `class.yaml` (user can override)
2. Injects that class’s public `focus.md` so the harness is pointed at the class (the attacker move, sold to defenders)
3. Does not change `low` / `balanced` / `max`
4. UX may **suggest** `max` when status is `trending` or `active-exploit`; the user still chooses

`midkernel/workflows` manifests list `threat_classes: [evm.reentrancy]`. This repo owns the class ids; workflows repo owns the harness text.

## What this repo is not

- Not the Scan app, runner, or Prisma schema
- Not the public workflow registry (`midkernel/workflows`)
- Not bench scores (`midkernel/bench`)
- Not website copy (Marketing + `midkernel/website`)
- Not Grok Bot recipes (`midkernel/skills`)
