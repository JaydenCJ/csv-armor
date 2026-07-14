# csv-armor examples

A malicious sample file plus two runnable scripts, all offline and
self-contained.

## exports.csv

A small customer-export CSV that mixes safe data (names, negative balances,
international phone numbers) with one instance of every injection class
csv-armor detects: a plain formula, a DDE command payload, a Google Sheets
`IMPORTXML` exfiltration, a legacy `@`-function, and a `HYPERLINK` data leak.
Use it to see both subcommands in action:

```bash
csv-armor scan examples/exports.csv
csv-armor sanitize examples/exports.csv
```

## scan-ci.sh

Uses `csv-armor scan --fail-on high` as a CI gate: it exits non-zero when a
file contains a code-execution or data-exfiltration payload, so it can block
a pipeline or a pre-commit hook.

```bash
bash examples/scan-ci.sh; echo "exit: $?"
```

## harden-export.sh

Shows the export-owner pattern: `csv-armor sanitize` rewrites risky cells so
they render as literal text, then a second scan proves the output is clean.

```bash
bash examples/harden-export.sh
```

Both scripts build the binary into a temp dir, so they run from a clean
checkout without installing anything.
