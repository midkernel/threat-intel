#!/usr/bin/env bash
# All collection is bounded; structured checkpoints are archived by the workflow.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
exec python3 "$ROOT/scripts/collect.py" "${1:-$ROOT/output}" --state "${COLLECTION_STATE:-$ROOT/collection-state}"
