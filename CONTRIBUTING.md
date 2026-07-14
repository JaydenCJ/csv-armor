# Contributing to csv-armor

Issues, discussions and pull requests are all welcome.

## Getting started

You need Go ≥1.22 and nothing else — csv-armor has zero runtime dependencies.

```bash
git clone https://github.com/JaydenCJ/csv-armor && cd csv-armor
go build ./...
go test ./...
bash scripts/smoke.sh
```

`scripts/smoke.sh` builds the binary, fabricates a CSV with known injection
payloads in a temp dir, and asserts on the real CLI output across every
subcommand and output format; it must finish by printing `SMOKE OK`.

## Before you open a pull request

1. `gofmt -l .` reports nothing (formatting is enforced).
2. `go vet ./...` passes with no findings.
3. `go test ./...` passes (90 deterministic tests, no network).
4. `bash scripts/smoke.sh` prints `SMOKE OK`.
5. Add tests for behavior changes; keep logic in pure, unit-testable
   modules (detection and sanitization never touch the filesystem — only the
   `cli` package reads and writes files).

## Ground rules

- Keep dependencies at zero; adding one needs strong justification in the PR.
- No network calls, ever — csv-armor reads local files and writes local
  files, nothing more. No telemetry.
- Detection rules are data: new spreadsheet triggers or network functions go
  into the profile table in `internal/inject/profiles.go` with a test
  reproducing the real payload, and a row in `docs/escaping-rules.md`.
- Code comments and doc comments are written in English.
- Determinism first: identical input must produce byte-identical reports,
  including finding order and JSON key order.

## Reporting bugs

Include the output of `csv-armor version`, the exact command you ran, the CSV
cell (or a minimal reproduction of it), and which spreadsheet application and
`--profile` you expected the verdict for — the classifier's decision depends
on the profile, so that context is what lets us reproduce it.

## Security

Please do not open public issues for security problems; use GitHub's private
vulnerability reporting on this repository instead.
