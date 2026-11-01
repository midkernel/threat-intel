#!/bin/sh
# Run from the repository root. Validate committed inputs; never collect/fetch.
set -eu
command -v python3 >/dev/null 2>&1 || {
    echo 'pre-push: Python >=3.10 is required; see docs/prepush.md.' >&2
    exit 127
}
python3 -I -c 'import sys; sys.version_info >= (3, 10) or sys.exit("pre-push: Python >=3.10 is required.")'
python3 -I -B scripts/validate_sources.py
exec python3 -I -B scripts/backfill/validate.py
