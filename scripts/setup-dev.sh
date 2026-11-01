#!/bin/sh
# This repository's validators need only Python's standard library.
set -eu
cd "$(dirname "$0")/.."
for tool in git python3; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "setup: $tool is required; see docs/prepush.md." >&2
        exit 127
    }
done
python3 -I -c 'import sys; sys.version_info >= (3, 10) or sys.exit("setup: Python >=3.10 is required.")'
exec python3 -I scripts/prepush/install.py
