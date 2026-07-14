# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-07-12

### Added

- Rule-based cell detection engine classifying formula injection into seven
  kinds — formula, arithmetic, at-sign, DDE, exfiltration, control, and
  embedded — each with a severity and a quotable, human-readable reason.
- Per-application `--profile` rule sets (excel, sheets, libreoffice, and their
  union `all`) covering the trigger characters and network-capable functions
  each spreadsheet program honors, documented in `docs/escaping-rules.md`.
- Escalation of triggered cells that reach DDE (`=cmd|'…'!A0`, `DDE()`) or a
  network function (`WEBSERVICE`, `IMPORTXML`, `HYPERLINK`, …) to high severity.
- Leading-whitespace bypass handling and TAB/CR cell-start detection, plus
  multi-line "embedded" detection for cells that re-arm when re-exported.
- False-positive guards for signed numbers, international phone numbers, and
  bare `@handles`, with a `--paranoid` flag to disable them.
- `scan` subcommand with text, JSON (`schema_version: 1`), and SARIF 2.1.0
  output; directory recursion over `.csv`/`.tsv`/`.psv`; delimiter sniffing;
  and a `--fail-on` severity gate returning exit code 1 for CI.
- `sanitize` subcommand with `quote` (OWASP apostrophe) and `strip` modes,
  writing to stdout, `--output`, or `--in-place`, and preserving the source's
  BOM, delimiter, and line endings.
- CSV I/O layer: BOM handling, quoted-field-aware delimiter sniffing, ragged
  row and lazy-quote tolerance for hostile input, and byte-faithful writing.
- Runnable examples (`examples/exports.csv`, `scan-ci.sh`, `harden-export.sh`)
  and an escaping-rules reference (`docs/escaping-rules.md`).
- 90 deterministic offline tests (unit + in-process CLI integration) and
  `scripts/smoke.sh`.

[0.1.0]: https://github.com/JaydenCJ/csv-armor/releases/tag/v0.1.0
