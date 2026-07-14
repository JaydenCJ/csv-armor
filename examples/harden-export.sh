#!/usr/bin/env bash
# Example export hardening: sanitize a CSV before it is handed to a user, so
# no cell can be interpreted as a formula when opened in a spreadsheet. This
# is the pattern an export-feature owner drops in front of a download route.
# Usage:
#
#   bash examples/harden-export.sh [csv-path]
#
# The sanitized file is written next to the input as <name>.safe.csv and then
# re-scanned to prove it is clean at every severity.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
CSV="${1:-$HERE/exports.csv}"
SAFE="${CSV%.csv}.safe.csv"

BIN="$(mktemp -d)/csv-armor"
trap 'rm -rf "$(dirname "$BIN")"' EXIT
(cd "$ROOT" && go build -o "$BIN" ./cmd/csv-armor)

# Prefix risky cells with a single quote (the OWASP recommendation): the
# visible value is unchanged, but nothing evaluates.
"$BIN" sanitize --profile all --mode quote --output "$SAFE" "$CSV"

# Prove it: a low-threshold scan of the hardened file must exit 0.
"$BIN" scan --profile all --fail-on low "$SAFE"
echo "hardened export written to $SAFE"
