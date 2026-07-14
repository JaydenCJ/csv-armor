#!/usr/bin/env bash
# Example CI gate: scan an exported CSV and fail the pipeline when a
# high-severity injection (code execution or data exfiltration) is present.
# Wire it into any CI step or a pre-commit hook. Usage:
#
#   bash examples/scan-ci.sh [csv-path]
#
# Exit code 1 means the gate is breached; 0 means the file is safe to ship.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
CSV="${1:-$HERE/exports.csv}"

# Build once so the example runs from a clean checkout without installing.
BIN="$(mktemp -d)/csv-armor"
trap 'rm -rf "$(dirname "$BIN")"' EXIT
(cd "$ROOT" && go build -o "$BIN" ./cmd/csv-armor)

# Policy: block anything that can execute code or exfiltrate data on open.
# Lower the threshold to "medium" to also block plain evaluated formulas.
"$BIN" scan --profile all --fail-on high "$CSV"
