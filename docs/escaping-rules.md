# Escaping rules per spreadsheet application

csv-armor's detection and sanitization are driven by how each spreadsheet
application actually parses a cell. This document is the reference behind the
`--profile` flag; every rule here is exercised by a test in `internal/inject`.

## Why the cell start matters

A CSV cell is just text. It becomes dangerous only when a spreadsheet decides
the text is a *formula* and evaluates it. Every mainstream application makes
that decision from the **first significant character** of the cell — so the
defense is likewise about the cell start.

Two subtleties bite naive filters:

1. **Leading whitespace is trimmed first.** Excel strips leading spaces before
   the formula check, so `   =1+1` still evaluates. A filter that only looks
   at index 0 is bypassed. csv-armor trims leading spaces (and non-breaking
   spaces) before classifying, and flags the bypass explicitly.
2. **TAB and CR are triggers too.** Beyond the obvious `= + - @`, the OWASP
   guidance lists a leading TAB (`0x09`) and CR (`0x0D`) as characters Excel
   honors at cell start. csv-armor treats them as their own low-severity
   finding under the Excel-family profiles.

## Trigger characters by profile

| Character | Excel | Google Sheets | LibreOffice Calc |
|---|:---:|:---:|:---:|
| `=` (formula) | yes | yes | yes |
| `+` (expression) | yes | yes | yes |
| `-` (expression) | yes | yes | yes |
| `@` (Lotus function) | yes | no | no |
| TAB at start | yes | no | no |
| CR at start | yes | no | no |

`--profile all` (the default) is the union of every row — the right choice
when you do not control which application opens the export.

## Network-capable functions by profile

A formula is worse than "the app computed a number" when it can reach the
network: those payloads exfiltrate the sheet's contents or beacon that it was
opened. csv-armor escalates any triggered cell whose body calls one of these
to **high** severity.

| Function | Excel | Google Sheets | LibreOffice Calc |
|---|:---:|:---:|:---:|
| `WEBSERVICE` | yes | — | yes |
| `FILTERXML` | yes | — | — |
| `RTD` | yes | — | — |
| `HYPERLINK` | yes | yes | yes |
| `IMPORTXML` / `IMPORTHTML` / `IMPORTDATA` | — | yes | — |
| `IMPORTRANGE` / `IMPORTFEED` | — | yes | — |
| `IMAGE` | — | yes | — |

DDE (Dynamic Data Exchange) is handled separately: Excel's legacy
`=cmd|' /C calc'!A0` pipe syntax and LibreOffice's `DDE()` function are both
**high** severity because they can launch a local program. Google Sheets has
no DDE, so a matching string is reported as its base kind there.

## Neutralization

The write side (`csv-armor sanitize`) offers two modes.

| Mode | What it does | Trade-off |
|---|---|---|
| `quote` (default) | Prefix the cell with a single quote (`'`). | Loss-light: the visible value is unchanged in every application, but the apostrophe is present in the raw bytes. This is the OWASP-recommended fix. |
| `strip` | Remove leading whitespace and trigger characters until the cell is inert. | Lossy: changes the value. Use only when a downstream consumer cannot tolerate the apostrophe. |

Both modes share one classification with the scanner: whatever `scan`
reports at cell start, `sanitize` neutralizes — a property the test suite
asserts over the whole payload corpus.

## What is deliberately *not* flagged

To stay usable on real data, the default rules exempt values that begin with a
trigger character but are plainly data, not formulas:

- **Signed numbers** — `-12.5`, `+1,234.56`, `-1.2e-3`, `-85%`.
- **International phone numbers** — `+81 90-1234-5678`, `+1 (555) 010-0100`.
- **Bare `@handles`** — `@jaydencj` (no function-call parentheses).

Pass `--paranoid` to flag these too. It is the right setting when silent data
corruption — Excel computing `+1-555-0100` into a single negative number —
matters as much as code execution.
