#!/usr/bin/env bash
# Fetch cataloged public feeds. No ranking. Dumps stay out of git.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-"$ROOT/output"}"
UA="MidkernelThreatIntel/0.1 (+https://github.com/midkernel/threat-intel)"
TIMEOUT="${FETCH_TIMEOUT:-90}"

mkdir -p "$OUT"

mapfile -t ROWS < <(python3 - "$ROOT/sources.yaml" "$ROOT/scripts" <<'PY'
import sys
sys.path.insert(0, sys.argv[2])
from catalog import load_sources

for src in load_sources(sys.argv[1]):
    print("\t".join([src["id"], src["url"], src["format"], src["name"]]))
PY
)

if [[ ${#ROWS[@]} -eq 0 ]]; then
  echo "no sources listed" >&2
  exit 1
fi

total=0
failed=0

fetch_one() {
  local id="$1" url="$2" format="$3"
  local dir="$OUT/$id"
  mkdir -p "$dir"
  local ext="xml"
  if [[ "$format" == "json" ]]; then
    ext="json"
  fi
  local body="$dir/body.$ext"
  local headers="$dir/headers.txt"
  local err="$dir/curl.err"
  local status=0
  local ctype=""
  local bytes=0
  local curl_exit=0
  local error=""

  # FIRST EPSS returns 400 if Accept lists RSS types. JSON catalogs get JSON only.
  local accept="application/rss+xml, application/atom+xml, application/xml, application/json, text/xml, */*"
  if [[ "$format" == "json" ]]; then
    accept="application/json"
  fi

  set +e
  local writeout
  writeout="$(
    curl -sS -L --compressed \
      --max-time "$TIMEOUT" \
      --connect-timeout 20 \
      -A "$UA" \
      -H "Accept: $accept" \
      -D "$headers" \
      -o "$body" \
      -w '%{http_code}\t%{content_type}\t%{size_download}' \
      -- "$url" 2>"$err"
  )"
  curl_exit=$?
  set -e

  if [[ $curl_exit -eq 0 ]]; then
    IFS=$'\t' read -r status ctype _ <<<"$writeout"
  else
    status=0
    error="$(tr '\n' ' ' <"$err" | head -c 400)"
    [[ -f "$body" ]] || : >"$body"
  fi
  # Index the saved body size, not curl's compressed transfer size.
  bytes=0
  if [[ -f "$body" ]]; then
    bytes="$(wc -c <"$body" | tr -d ' ')"
  fi
  if [[ ! -s "$err" ]]; then
    rm -f "$err"
  fi

  python3 - "$dir/meta.json" "$id" "$url" "$format" "$status" "$ctype" "$bytes" "$curl_exit" "$error" <<'PY'
import json, sys
path, sid, url, fmt, status, ctype, nbytes, curl_exit, error = sys.argv[1:10]
meta = {
    "id": sid,
    "url": url,
    "format": fmt,
    "status": int(status or 0),
    "content_type": ctype,
    "bytes": int(nbytes or 0),
    "curl_exit": int(curl_exit or 0),
    "error": error,
}
with open(path, "w", encoding="utf-8") as fh:
    json.dump(meta, fh, indent=2)
    fh.write("\n")
PY

  if [[ "$status" =~ ^2[0-9][0-9]$ ]]; then
    echo "OK   $status  $id  ($bytes bytes)"
    return 0
  fi
  if [[ "$status" =~ ^5[0-9][0-9]$ ]]; then
    echo "WARN $status  $id  (5xx; daily run continues unless a majority fail)" >&2
    return 1
  fi
  echo "FAIL $status  $id  ${error:-non-2xx}" >&2
  return 1
}

for row in "${ROWS[@]}"; do
  IFS=$'\t' read -r id url format name <<<"$row"
  total=$((total + 1))
  echo "fetch $id"
  if ! fetch_one "$id" "$url" "$format"; then
    failed=$((failed + 1))
  fi
done

python3 "$ROOT/scripts/index.py" "$OUT"

echo "fetched $((total - failed))/$total sources ($failed failed)"
if (( failed * 2 > total )); then
  echo "FAIL: majority of sources failed ($failed/$total)" >&2
  exit 1
fi
if (( failed > 0 )); then
  echo "WARN: $failed source(s) failed; job continues (not a majority)" >&2
fi
