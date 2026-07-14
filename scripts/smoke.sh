#!/usr/bin/env bash
# End-to-end smoke test for csv-armor: builds the binary, fabricates a CSV
# with known injection payloads, and asserts on the real CLI output across
# every subcommand and format. No network, idempotent, finishes in seconds.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

fail() {
  echo "SMOKE FAIL: $*" >&2
  exit 1
}

BIN="$WORKDIR/csv-armor"
CSV="$WORKDIR/exports.csv"

echo "1. build"
(cd "$ROOT" && go build -o "$BIN" ./cmd/csv-armor) || fail "go build failed"

echo "2. version matches manifest"
"$BIN" --version | grep -qx "csv-armor 0.1.0" || fail "--version mismatch"

echo "3. fabricate a CSV with mixed safe/malicious cells"
cat > "$CSV" <<'CSVEOF'
id,name,note,phone
1,Alice,welcome,+1 555-0100
2,Bob,=1+1,-25.00
3,Mallory,=cmd|' /C calc'!A0,+81 90-1234-5678
4,Eve,=WEBSERVICE("http://127.0.0.1/x"),0
CSVEOF

echo "4. text scan flags the payloads and exits 1 on high severity"
set +e
OUT="$("$BIN" scan "$CSV")"
CODE=$?
set -e
[ "$CODE" -eq 1 ] || fail "scan should exit 1 on a high-severity finding, got $CODE"
echo "$OUT" | grep -q "dde" || fail "DDE finding missing"
echo "$OUT" | grep -q "exfiltration" || fail "exfiltration finding missing"
echo "$OUT" | grep -q "R3C3" || fail "location R3C3 missing"

echo "5. safe cells are not flagged (no false positives)"
echo "$OUT" | grep -q "555-0100" && fail "phone number should not appear as a finding"
echo "$OUT" | grep -q "findings       3" || fail "expected exactly 3 findings"

echo "6. JSON output is machine-readable and correct"
JSON="$("$BIN" scan --format json "$CSV" || true)"
echo "$JSON" | grep -q '"tool": "csv-armor"' || fail "json envelope missing"
echo "$JSON" | grep -q '"schema_version": 1' || fail "json schema_version missing"
echo "$JSON" | grep -q '"kind": "dde"' || fail "json dde kind missing"

echo "7. SARIF output is valid for CI security tabs"
SARIF="$("$BIN" scan --format sarif "$CSV" || true)"
echo "$SARIF" | grep -q '"version": "2.1.0"' || fail "sarif version missing"

echo "8. profile scoping: sheets ignores the Excel-only @ trigger"
printf 'x\n@SUM(A1:A9)\n' > "$WORKDIR/at.csv"
"$BIN" scan --profile sheets --fail-on low "$WORKDIR/at.csv" >/dev/null \
  || fail "sheets profile should not flag a leading @"

echo "9. fail-on none never breaches"
"$BIN" scan --fail-on none "$CSV" >/dev/null || fail "--fail-on none should exit 0"

echo "10. sanitize neutralizes, then a re-scan is clean"
"$BIN" sanitize --in-place "$CSV" 2>/dev/null || fail "sanitize failed"
"$BIN" scan --fail-on low "$CSV" >/dev/null || fail "sanitized file still flagged"
grep -q "'=cmd" "$CSV" || fail "DDE cell was not quoted"
grep -q "555-0100" "$CSV" || fail "safe phone number was altered"

echo "11. usage errors exit 2"
set +e
"$BIN" scan --format yaml "$CSV" >/dev/null 2>&1
[ $? -eq 2 ] || fail "bad --format should exit 2"
set -e

echo "SMOKE OK"
