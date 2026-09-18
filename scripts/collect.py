#!/usr/bin/env python3
"""Bounded public evidence collection. No crawling, execution, or Midkernel ranking."""
from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import io
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

from catalog import load_sources
from index import write_outputs

MAX_BYTES = 128 * 1024 * 1024
SOURCE_SECONDS = 10 * 60
RUN_SECONDS = 30 * 60  # Leave 15 minutes for indexing, packing and release uploads.
UA = "MidkernelThreatIntel/0.2 (+https://github.com/midkernel/threat-intel)"
OSV_LIST = "https://storage.googleapis.com/osv-vulnerabilities/modified_id.csv"
OSV_ECOSYSTEMS = ("npm", "PyPI", "Go", "crates.io", "Maven", "NuGet", "RubyGems", "Packagist", "GitHub Actions", "[EMPTY]")
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
KEV_MIRROR = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
CVE_ROOT = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves"
SPECIAL = {"cve-cna", "first-epss", "github-advisories-reviewed", "github-advisories-malware", "osv-vulnerabilities"}


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def save(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n")
    tmp.replace(path)


class CollectionDeadline(RuntimeError):
    pass


class TimeBudget:
    def __init__(self, deadline: float, clock=time.monotonic):
        self.deadline, self.clock = deadline, clock

    def remaining(self) -> float:
        seconds = self.deadline - self.clock()
        if seconds <= 0:
            raise CollectionDeadline("collection_time_budget_exhausted")
        return seconds


def request(url: str, *, budget: TimeBudget | None = None) -> tuple[bytes, int, dict]:
    # A slow, continually streaming body must also yield to the collection budget.
    budget = budget or TimeBudget(time.monotonic() + 3 * 60)
    headers = {"User-Agent": UA, "Accept": "*/*"}
    if urllib.parse.urlparse(url).hostname == "api.github.com":
        headers.update({"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"})
        if os.environ.get("GH_TOKEN"):
            headers["Authorization"] = "Bearer " + os.environ["GH_TOKEN"]
    for attempt in range(3):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=min(60, budget.remaining())) as response:
                chunks, size = [], 0
                while True:
                    budget.remaining()
                    chunk = response.read1(min(64 * 1024, MAX_BYTES + 1 - size))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    size += len(chunk)
                    if size > MAX_BYTES:
                        raise ValueError("body exceeds collection byte budget")
                raw = b"".join(chunks)
                return raw, response.status, {k.lower(): v for k, v in response.headers.items()
                    if k.lower() in {"content-type", "etag", "last-modified", "link", "retry-after", "content-length"}}
        except urllib.error.HTTPError as exc:
            if exc.code not in {429, 500, 502, 503, 504} or attempt == 2:
                raise
            time.sleep(min(5, 2 ** attempt, budget.remaining()))
        except (TimeoutError, urllib.error.URLError):
            if attempt == 2:
                raise
            time.sleep(min(2 ** attempt, budget.remaining()))
    raise RuntimeError("request did not complete")


class Archive:
    def __init__(self, directory: Path, fetch=request, budget: TimeBudget | None = None):
        directory.mkdir(parents=True, exist_ok=True)
        self.directory, self.fetch, self.count = directory, fetch, 0
        self.budget = budget
        self.requests = []

    def get(self, url: str) -> tuple[bytes, int, dict]:
        if self.budget:
            self.budget.remaining()
        raw, code, headers = request(url, budget=self.budget) if self.fetch is request else self.fetch(url)
        self.count += 1
        path = self.directory / "inputs" / f"{self.count:05d}-{digest(raw)[:16]}.body.gz"
        path.parent.mkdir(parents=True, exist_ok=True)
        archived = gzip.compress(raw, mtime=0)
        path.write_bytes(archived)
        self.requests.append({"url": url, "path": str(path.relative_to(self.directory)),
                              "sha256": digest(archived), "source_sha256": digest(raw), "compression": "gzip", "bytes": len(archived), "http_status": code,
                              "headers": headers, "fetched_at": now()})
        save(self.directory / "requests.json", self.requests)
        if not 200 <= code < 300:
            raise ValueError(f"HTTP {code}")
        return raw, code, headers


def parse_epss(raw: bytes) -> dict:
    with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
        payload = stream.read(MAX_BYTES + 1)
    if len(payload) > MAX_BYTES:
        raise ValueError("EPSS decompression exceeds byte budget")
    lines = payload.decode("utf-8-sig").splitlines()
    metadata = {}
    for line in lines:
        if line.startswith("#"):
            for bit in line.lstrip("#").split(","):
                if ":" in bit:
                    key, value = bit.split(":", 1)
                    metadata[key.strip()] = value.strip()
    score_date = metadata.get("score_date", "")[:10]
    datetime.strptime(score_date, "%Y-%m-%d")  # Never substitute the fetch day.
    if not metadata.get("model_version"):
        raise ValueError("EPSS CSV missing model_version")
    reader = csv.DictReader(x for x in lines if x and not x.startswith("#"))
    if not {"cve", "epss", "percentile"}.issubset(reader.fieldnames or []):
        raise ValueError("EPSS CSV missing required columns")
    counts = [0] * 5
    bounds = [0, 0.01, 0.1, 0.5, 0.9, 1]
    seen = set()
    for row in reader:
        cve = row.get("cve", "")
        score, percentile = float(row["epss"]), float(row["percentile"])
        if not re.fullmatch(r"CVE-\d{4}-\d+", cve) or cve in seen or not 0 <= score <= 1 or not 0 <= percentile <= 1:
            raise ValueError("EPSS invalid or duplicate CVE/score row")
        seen.add(cve)
        counts[next((i for i in range(5) if score < bounds[i + 1]), 4)] += 1
    if not seen:
        raise ValueError("EPSS CSV is empty")
    return {"kind": "stock", "score_date": score_date, "model_version": metadata["model_version"],
            "scored_total": len(seen), "high_count": sum(counts[3:]), "high_threshold": 0.5,
            "distribution": [{"lower_inclusive": bounds[i], "upper": bounds[i + 1],
                              "upper_inclusive": i == 4, "count": counts[i]} for i in range(5)]}


def epss(archive: Archive) -> dict:
    raw, _, _ = archive.get(EPSS_URL)
    statistics = parse_epss(raw)
    path = archive.directory / f"epss-scores-{statistics['score_date']}.csv.gz"
    path.write_bytes(raw)
    result = {"collector": "epss", "records": [], "statistics": statistics,
            "snapshot": {"path": f"first-epss/{path.name}", "sha256": digest(raw), "bytes": len(raw),
                         "format": "csv.gz", "row_count": statistics["scored_total"],
                         "score_date": statistics["score_date"]},
            "status": {"coverage": "full_snapshot", "completeness": "complete", "reasons": [],
                       "received_count": statistics["scored_total"], "rejected_count": 0}}

    if os.environ.get("COLLECTION_RELEASE_URL"):
        result["snapshot"]["url"] = os.environ["COLLECTION_RELEASE_URL"].rstrip("/") + "/" + path.name
    return result


def initial_since(at: str) -> str:
    return (datetime.fromisoformat(at.replace("Z", "+00:00")) - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")


def overlap(at: str) -> str:
    return (datetime.fromisoformat(at.replace("Z", "+00:00")) - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")


def next_link(link: str) -> str | None:
    for part in link.split(","):
        match = re.search(r'<([^>]+)>;\s*rel="next"', part)
        if match:
            parsed = urllib.parse.urlparse(match[1])
            if parsed.scheme != "https" or parsed.netloc != "api.github.com" or parsed.path != "/advisories":
                raise ValueError("unexpected GitHub pagination destination")
            return match[1]
    return None


def incremental_result(collector: str, records: list, state: dict, pending: bool, error: str | None = None) -> dict:
    reasons = ["bounded_history"]
    if pending:
        reasons.append("collection_budget_pending")
    if error:
        reasons.append("collection_error")
        if "collection_time_budget_exhausted" in error:
            reasons.append("collection_time_budget_exhausted")
    return {"collector": collector, "records": records,
            "status": {"coverage": "incremental", "completeness": "partial", "reasons": reasons,
                       "received_count": len(records), "rejected_count": 0},
            "checkpoint": {"coverage_from": state["coverage_from"], "through": state.get("through"),
                           "cycle_complete": not pending and not error, "pending": pending,
                           "error": error, "historical_corpus_complete": False}}


def ghsa(archive: Archive, state: dict, advisory_type: str, *, at: str, max_pages: int = 5) -> dict:
    state.setdefault("coverage_from", initial_since(at))
    if not state.get("next_url"):
        state["cycle_until"] = at
        params = {"type": advisory_type, "sort": "updated", "direction": "asc", "per_page": 100,
                  "modified": f"{overlap(state['through']) if state.get('through') else state['coverage_from']}..{at}"}
        state["next_url"] = "https://api.github.com/advisories?" + urllib.parse.urlencode(params)
    records, error = [], None
    for _ in range(max_pages):
        url = state["next_url"]
        try:
            raw, _, headers = archive.get(url)
            rows = json.loads(raw)
            if not isinstance(rows, list) or any(not isinstance(r, dict) or not r.get("ghsa_id") for r in rows):
                raise ValueError("invalid GitHub advisory page")
            following = next_link(headers.get("link", ""))
            records.extend(rows)
            state["next_url"] = following
            if not following:
                state["through"] = state.pop("cycle_until")
                break
        except Exception as exc:
            error = str(exc)[:300]
            break  # Failed page remains the next checkpoint; no gaps.
    return incremental_result("ghsa", records, state, bool(state.get("next_url")), error)


def osv(archive: Archive, state: dict, state_dir: Path, *, at: str, max_records: int = 500,
        ecosystems: tuple = OSV_ECOSYSTEMS) -> dict:
    """Version checkpoints let every run pick up new changes while draining older backlog."""
    state.setdefault("coverage_from", initial_since(at))
    records, error = [], None
    processed = state.setdefault("processed", {})
    previous_scope = state.setdefault("ecosystems", list(ecosystems))
    if previous_scope != list(ecosystems):
        raise ValueError("OSV scope changed: use a fresh state directory to explicitly bootstrap that scope")
    candidates = {}
    errors = []
    # Each successful record advances only its own version checkpoint. A failed download
    # or absent listing cannot advance the global through watermark or hide pending work.
    for ecosystem in ecosystems:
        try:
            prefix = "https://storage.googleapis.com/osv-vulnerabilities/" + urllib.parse.quote(ecosystem, safe="") + "/"
            raw, _, _ = archive.get(prefix + "modified_id.csv")
            for row in csv.reader(io.StringIO(raw.decode("utf-8"))):
                if len(row) != 2:
                    raise ValueError("invalid OSV modified_id.csv row")
                stamp, identifier = row
                if stamp < state["coverage_from"]:
                    continue
                if not re.fullmatch(r"[A-Za-z0-9_.:-]+", identifier) or ".." in identifier:
                    raise ValueError("invalid OSV identifier")
                key = ecosystem + "/" + identifier
                if processed.get(key, "") < stamp:
                    candidates[key] = stamp
        except CollectionDeadline as exc:
            errors.insert(0, f"{ecosystem}: {exc}")
            break
        except Exception as exc:
            errors.append(f"{ecosystem}: {str(exc)[:160]}")
    pending = sorted(candidates, key=lambda key: (candidates[key], key), reverse=True)
    # Prioritize fresh evidence on every poll; failed and budget-deferred records remain
    # eligible next run because their source version never enters processed.
    for key in pending[:max_records]:
        try:
            url = "https://storage.googleapis.com/osv-vulnerabilities/" + urllib.parse.quote(key, safe="/") + ".json"
            raw, _, _ = archive.get(url)
            row = json.loads(raw)
            if not isinstance(row, dict) or not row.get("id") or not row.get("modified"):
                raise ValueError("invalid OSV advisory")
            if datetime.fromisoformat(row["modified"].replace("Z", "+00:00")) < datetime.fromisoformat(candidates[key].replace("Z", "+00:00")):
                raise ValueError("OSV record is older than its manifest version; retry required")
            records.append(row)
            processed[key] = candidates[key]
        except CollectionDeadline as exc:
            errors.insert(0, f"{key}: {exc}")
            break
        except Exception as exc:
            errors.append(f"{key}: {str(exc)[:160]}")
    state["pending"] = len(candidates) - len(records)
    if errors:
        error = "; ".join(errors)[:1000]
    elif not state["pending"]:
        state["through"] = at
    result = incremental_result("osv", records, state, bool(state["pending"]), error)
    result["checkpoint"].update({"ecosystems": list(ecosystems), "pending_count": state["pending"],
                                  "processed_versions": len(processed)})
    result["status"]["reasons"].append("selected_ecosystems")
    return result


def kev(archive: Archive, primary_url: str, meta: dict) -> tuple[bytes, int, dict]:
    attempts = []
    for url in (primary_url, KEV_MIRROR):
        try:
            raw, code, headers = archive.get(url)
            data = json.loads(raw)
            if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list) or data.get("count") != len(data["vulnerabilities"]):
                raise ValueError("invalid KEV catalog envelope or count")
            attempts.append({"url": url, "http_status": code, "outcome": "ok"})
            meta["provenance"] = {"primary_url": primary_url, "effective_url": url,
                                  "fallback_used": url != primary_url, "attempts": attempts}
            return raw, code, headers
        except Exception as exc:
            attempts.append({"url": url, "http_status": getattr(exc, "code", None), "outcome": "error", "error": str(exc)[:300]})
            meta["diagnostics"].append({"stage": "fetch", "url": url, "message": str(exc)[:300]})
    meta["provenance"] = {"primary_url": primary_url, "effective_url": None, "fallback_used": False, "attempts": attempts}
    raise ValueError("Both the official KEV endpoint and official CISA mirror failed")


def observed_cves(output: Path) -> dict[str, list[str]]:
    """Only enrich identifiers supplied by KEV/GHSA, never crawl the CVE corpus."""
    targets: dict[str, list[str]] = {}
    for source_id in ("cisa-kev", "github-advisories-reviewed", "github-advisories-malware"):
        directory = output / source_id
        if not (directory / "meta.json").exists() or not (directory / "body.json").exists():
            continue
        meta = json.loads((directory / "meta.json").read_text())
        if not 200 <= meta.get("status", 0) < 300:
            continue
        data = json.loads((directory / "body.json").read_text())
        rows = data.get("vulnerabilities", data.get("records", [])) if isinstance(data, dict) else data
        for row in rows:
            identifiers = [row.get("cveID"), row.get("cve_id")] + [entry.get("value") for entry in row.get("identifiers", []) if isinstance(entry, dict)]
            for identifier in identifiers:
                if isinstance(identifier, str) and re.fullmatch(r"CVE-\d{4}-\d{4,}", identifier):
                    targets.setdefault(identifier, []).append(source_id)
    return {identifier: sorted(set(origins)) for identifier, origins in targets.items()}


def cna(archive: Archive, state: dict, output: Path, *, at: str, max_records: int = 200) -> dict:
    state.setdefault("coverage_from", at)
    targets = state.setdefault("targets", {})
    for identifier, origins in observed_cves(output).items():
        entry = targets.setdefault(identifier, {"first_seen": at, "origins": []})
        entry["origins"] = sorted(set(entry["origins"] + origins))
    cutoff = overlap(at)  # Recheck admitted CVEs at least when their bounded queue comes due.
    due = sorted((identifier for identifier, entry in targets.items() if entry.get("checked_at", "") <= cutoff),
                 key=lambda identifier: targets[identifier].get("checked_at", ""))
    records, errors = [], []
    checked = unchanged = 0
    for identifier in due[:max_records]:
        entry = targets[identifier]
        _, year, sequence = identifier.split("-")
        url = f"{CVE_ROOT}/{year}/{sequence[:-3]}xxx/{identifier}.json"
        try:
            raw, _, _ = archive.get(url)
            row = json.loads(raw)
            metadata = row.get("cveMetadata", {}) if isinstance(row, dict) else {}
            if metadata.get("cveId") != identifier or metadata.get("state") not in {"PUBLISHED", "REJECTED"}:
                raise ValueError("invalid or mismatched CVE5 record")
            if not isinstance(row.get("containers", {}).get("cna"), dict):
                raise ValueError("CVE5 record missing CNA container")
            version = digest(json.dumps(row, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode())
            if version == entry.get("sha256"):
                unchanged += 1
            records.append(row)
            entry.update({"sha256": version, "checked_at": at, "modified_at": metadata.get("dateUpdated"),
                          "state": metadata["state"], "url": url, "error": None})
            checked += 1
        except CollectionDeadline as exc:
            # Never mark unattempted/unfinished records checked when the run is due
            # to archive. Their queue positions remain eligible next collection.
            errors.insert(0, f"{identifier}: {exc}")
            break
        except Exception as exc:
            entry.update({"checked_at": at, "error": str(exc)[:200]})
            errors.append(f"{identifier}: {str(exc)[:160]}")
    pending = len(due) - checked
    unresolved = sum(bool(entry.get("error")) for entry in targets.values())
    if not pending and not unresolved:
        state["through"] = at
    result = incremental_result("cve-cna", records, state, pending > 0 or unresolved > 0,
                                "; ".join(errors)[:1000] or None)
    result["status"]["reasons"] = ["observed_identifier_scope"] + [reason for reason in result["status"]["reasons"] if reason != "bounded_history"]
    if unresolved and "collection_error" not in result["status"]["reasons"]:
        result["status"]["reasons"].append("collection_error")
    result["checkpoint"].update({"target_count": len(targets), "checked_count": checked, "unchanged_count": unchanged,
                                 "pending_count": pending, "failed_identifiers": unresolved,
                                 "refresh_interval_hours": 24, "scope": "identifiers_observed_in_kev_and_ghsa"})
    result["raw"] = {"provider": "CVE Program CNA/ADP records", "distribution": CVE_ROOT}
    return result


def collect_source(src: dict, output: Path, state_dir: Path, *, fetch=request, at: str | None = None,
                   run_deadline: float | None = None, budget: TimeBudget | None = None) -> bool:
    at = at or now()
    directory = output / src["id"]
    directory.mkdir(parents=True, exist_ok=True)
    budget = budget or TimeBudget(min(time.monotonic() + SOURCE_SECONDS,
                                      run_deadline if run_deadline is not None else float("inf")))
    archive = Archive(directory, fetch, budget)
    meta = {"id": src["id"], "url": src["url"], "fetched_at": at, "status": 0, "diagnostics": []}
    try:
        if src["id"] in SPECIAL:
            state_path = state_dir / (src["id"] + ".json")
            state = json.loads(state_path.read_text()) if state_path.exists() else {}
            if src["id"] == "cve-cna":
                data = cna(archive, state, output, at=at, max_records=int(os.environ.get("CVE_MAX_RECORDS", "200")))
            elif src["id"] == "first-epss":
                data = epss(archive)
            elif src["id"].startswith("github-advisories-"):
                data = ghsa(archive, state, src["id"].rsplit("-", 1)[1], at=at,
                            max_pages=int(os.environ.get("GHSA_MAX_PAGES", "5")))
            else:
                data = osv(archive, state, state_dir, at=at,
                           max_records=int(os.environ.get("OSV_MAX_RECORDS", "500")),
                           ecosystems=tuple(os.environ.get("OSV_ECOSYSTEMS", ",".join(OSV_ECOSYSTEMS)).split(",")))
            save(directory / "body.json", data)
            save(state_path, state)
            meta["status"] = 200
            meta["error"] = data.get("checkpoint", {}).get("error")
            if meta["error"]:
                meta["diagnostics"].append({"stage": "collection", "message": meta["error"]})
        else:
            raw, code, headers = kev(archive, src["url"], meta) if src["id"] == "cisa-kev" else archive.get(src["url"])
            (directory / ("body.json" if src["format"] == "json" else "body.xml")).write_bytes(raw)
            meta.update({"status": code, "bytes": len(raw), "sha256": digest(raw),
                         "content_type": headers.get("content-type"), "headers": headers})
    except Exception as exc:
        meta.update({"status": getattr(exc, "code", 0), "error": str(exc)[:400]})
        meta["time_budget_exhausted"] = isinstance(exc, CollectionDeadline)
        meta["diagnostics"].append({"stage": "fetch", "message": meta["error"]})
    save(directory / "meta.json", meta)
    return 200 <= meta["status"] < 300 and not meta.get("error")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", nargs="?", type=Path, default=Path("output"))
    parser.add_argument("--state", type=Path, default=Path("collection-state"))
    parser.add_argument("--sources", nargs="*", help="Optional catalog IDs for a bounded smoke collection")
    args = parser.parse_args()
    args.state.mkdir(parents=True, exist_ok=True)
    sources = load_sources(Path(__file__).resolve().parent.parent / "sources.yaml")
    if args.sources:
        sources = [s for s in sources if s["id"] in args.sources]
    if not sources:
        parser.error("no sources selected")
    started_at = now()
    run_deadline = time.monotonic() + RUN_SECONDS
    independent = [src for src in sources if src["id"] != "cve-cna"]
    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(lambda src: collect_source(src, args.output, args.state, at=started_at,
                                                         run_deadline=run_deadline), independent))
    for src in sources:
        if src["id"] == "cve-cna":
            results.append(collect_source(src, args.output, args.state, at=started_at, run_deadline=run_deadline))
    write_outputs(args.output, sources, day=os.environ.get("COLLECTION_DAY") or started_at[:10])
    manifest = {"schema": "midkernel.threat-intel.archive/v1", "generated_at": now(), "files": []}
    for path in sorted(args.output.rglob("*")):
        if path.is_file():
            manifest["files"].append({"path": str(path.relative_to(args.output)), "sha256": digest(path.read_bytes()), "bytes": path.stat().st_size})
    save(args.output / "manifest.json", manifest)
    print(f"Collected {sum(results)}/{len(results)} sources; per-source diagnostics in index.json")
    return 1 if sum(not x for x in results) * 2 > len(results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
