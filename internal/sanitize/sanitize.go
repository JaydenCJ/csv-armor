// Package sanitize neutralizes cells the inject engine flags. It is the
// write-side twin of inject: both share one classification, so everything
// the scanner reports at cell start, the sanitizer defuses — a property the
// test suite asserts over the whole payload corpus.
package sanitize

import (
	"fmt"
	"strings"

	"github.com/JaydenCJ/csv-armor/internal/inject"
)

// Mode selects how a risky cell is neutralized.
type Mode string

const (
	// ModeQuote prepends a single quote (') to the cell — the OWASP
	// recommendation. Excel, Google Sheets and LibreOffice all read a
	// leading apostrophe as "treat the rest as literal text", so the
	// visible value is unchanged and nothing evaluates. Lossless-ish:
	// the apostrophe itself lands in the raw data.
	ModeQuote Mode = "quote"
	// ModeStrip deletes the leading trigger characters (and any
	// whitespace padding hiding them) until the cell no longer triggers.
	// Lossy by design: use it when downstream consumers cannot tolerate
	// the extra apostrophe.
	ModeStrip Mode = "strip"
)

// ParseMode validates a user-supplied mode name.
func ParseMode(s string) (Mode, error) {
	switch Mode(strings.ToLower(s)) {
	case ModeQuote:
		return ModeQuote, nil
	case ModeStrip:
		return ModeStrip, nil
	}
	return "", fmt.Errorf("unknown mode %q (valid: quote, strip)", s)
}

// Cell neutralizes one cell value if the inject engine flags it at cell
// start, returning the (possibly rewritten) value and whether it changed.
// Embedded multi-line findings are not rewritten here — the CSV writer's
// mandatory quoting keeps them inert in the output file; they only become
// dangerous if a later tool re-exports the value carelessly.
func Cell(cell string, p inject.Profile, mode Mode, opts inject.Options) (string, bool) {
	if !riskyAtStart(cell, p, opts) {
		return cell, false
	}
	switch mode {
	case ModeStrip:
		out := cell
		// Peel padding and trigger characters until the classification
		// clears. Each pass removes at least one byte, so this terminates.
		for riskyAtStart(out, p, opts) {
			trimmed := strings.TrimLeftFunc(out, func(r rune) bool {
				return r == ' ' || r == 0xA0 || (r < 0x20 && r >= 0)
			})
			if trimmed == "" {
				return "", true
			}
			if trimmed == out {
				// No padding left, so the first rune is a trigger
				// character (all triggers are single-byte ASCII).
				out = out[1:]
			} else {
				out = trimmed
			}
		}
		return out, true
	default: // ModeQuote
		return "'" + cell, true
	}
}

// riskyAtStart reports whether any cell-start finding exists.
func riskyAtStart(cell string, p inject.Profile, opts inject.Options) bool {
	for _, f := range inject.ScanCell(cell, p, opts) {
		if f.AtStart {
			return true
		}
	}
	return false
}
