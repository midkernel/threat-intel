#!/usr/bin/env python3
"""Keep release descriptions bounded; full evidence remains in attached assets."""
import sys
from pathlib import Path

NOTES_LIMIT = 12_000


def release_notes(summary: str, day: str) -> str:
    header = (f"# Evidence collection — {day} UTC\n\n"
              "Public source evidence and collection diagnostics, with matching durable checkpoints.\n"
              f"Full summary: `summary-{day}.md`. Machine-readable evidence: `index-{day}.json`.\n"
              "Raw inputs, checksums and checkpoint state are attached to this immutable run.\n\n"
              "The excerpt below is bounded; consult the attached summary for all sources.\n\n")
    return header + "\n".join(summary.splitlines()[:80])[:NOTES_LIMIT - len(header) - 1] + "\n"


if __name__ == "__main__":
    print(release_notes(Path(sys.argv[1]).read_text(), sys.argv[2]), end="")
