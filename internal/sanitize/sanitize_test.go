// Tests for the sanitizer, including the central safety property: whatever
// the scanner flags at cell start, the sanitizer must render clean.
package sanitize

import (
	"testing"

	"github.com/JaydenCJ/csv-armor/internal/inject"
)

func TestParseMode(t *testing.T) {
	if m, err := ParseMode("quote"); err != nil || m != ModeQuote {
		t.Fatalf("quote: %v %v", m, err)
	}
	if m, err := ParseMode("STRIP"); err != nil || m != ModeStrip {
		t.Fatalf("strip: %v %v", m, err)
	}
	if _, err := ParseMode("delete"); err == nil {
		t.Fatal("expected error for unknown mode")
	}
}

func TestQuoteFormula(t *testing.T) {
	got, changed := Cell("=1+2", inject.ProfileAll, ModeQuote, inject.Options{})
	if !changed || got != "'=1+2" {
		t.Fatalf("got %q changed=%v", got, changed)
	}
}

func TestQuoteSignedNumberUntouched(t *testing.T) {
	got, changed := Cell("-12.5", inject.ProfileAll, ModeQuote, inject.Options{})
	if changed || got != "-12.5" {
		t.Fatalf("signed number should be left alone: %q %v", got, changed)
	}
}

func TestStripLeadingEquals(t *testing.T) {
	got, changed := Cell("=1+2", inject.ProfileAll, ModeStrip, inject.Options{})
	if !changed || got != "1+2" {
		t.Fatalf("got %q changed=%v", got, changed)
	}
}

func TestStripLeadingWhitespaceAndTrigger(t *testing.T) {
	// The bypass form must lose both the padding and the trigger char.
	got, changed := Cell("   =1+2", inject.ProfileAll, ModeStrip, inject.Options{})
	if !changed || got != "1+2" {
		t.Fatalf("got %q changed=%v", got, changed)
	}
}

func TestStripRepeatsUntilClean(t *testing.T) {
	// After removing the '=', "+1+1" would still trigger, so strip must
	// loop until the value no longer classifies.
	got, changed := Cell("=+1+1", inject.ProfileAll, ModeStrip, inject.Options{Paranoid: true})
	if !changed {
		t.Fatal("expected change")
	}
	if fs := inject.ScanCell(got, inject.ProfileAll, inject.Options{Paranoid: true}); len(fs) != 0 {
		t.Fatalf("strip left a still-risky value %q: %+v", got, fs)
	}
}

func TestQuoteDDEPayload(t *testing.T) {
	got, changed := Cell(`=cmd|' /C calc'!A0`, inject.ProfileAll, ModeQuote, inject.Options{})
	if !changed || got[0] != '\'' {
		t.Fatalf("got %q changed=%v", got, changed)
	}
	// The quoted value must no longer classify as a start finding.
	assertCleanAtStart(t, got, inject.ProfileAll, inject.Options{})
}

func TestEmbeddedFindingNotRewritten(t *testing.T) {
	// A cell whose only issue is an embedded later line is safe on disk
	// (the CSV writer quotes it), so the sanitizer leaves it unchanged.
	got, changed := Cell("safe\n=1+1", inject.ProfileAll, ModeQuote, inject.Options{})
	if changed || got != "safe\n=1+1" {
		t.Fatalf("got %q changed=%v", got, changed)
	}
}

// assertCleanAtStart fails if any at-start finding remains.
func assertCleanAtStart(t *testing.T, cell string, p inject.Profile, opts inject.Options) {
	t.Helper()
	for _, f := range inject.ScanCell(cell, p, opts) {
		if f.AtStart {
			t.Fatalf("value %q still has a start finding: %+v", cell, f)
		}
	}
}

// payloadCorpus is the shared set of malicious cells used by the property
// tests: whatever the scanner flags, both modes must neutralize.
var payloadCorpus = []string{
	"=1+1",
	"=SUM(A1:A9)",
	"+1+1",
	"-2+3+cmd",
	"@SUM(A1:A2)",
	"=cmd|' /C calc'!A0",
	`=WEBSERVICE("http://127.0.0.1/x")`,
	`=IMPORTXML("http://example.test","//a")`,
	`=HYPERLINK("http://example.test","x")`,
	"   =1+1",
	"\t=1+1",
	"\r=1+1",
	"=DDE(\"cmd\";\"/C calc\";\"a\")",
}

func TestQuoteModeNeutralizesEntireCorpus(t *testing.T) {
	for _, cell := range payloadCorpus {
		got, changed := Cell(cell, inject.ProfileAll, ModeQuote, inject.Options{})
		if !changed {
			t.Fatalf("quote left %q unchanged", cell)
		}
		assertCleanAtStart(t, got, inject.ProfileAll, inject.Options{})
	}
}

func TestStripModeNeutralizesEntireCorpus(t *testing.T) {
	for _, cell := range payloadCorpus {
		got, changed := Cell(cell, inject.ProfileAll, ModeStrip, inject.Options{})
		if !changed {
			t.Fatalf("strip left %q unchanged", cell)
		}
		assertCleanAtStart(t, got, inject.ProfileAll, inject.Options{})
	}
}

func TestScannerAndSanitizerAgreeOnCorpus(t *testing.T) {
	// Every corpus entry must both be flagged by the scanner and changed
	// by the sanitizer — the two engines share one classification.
	for _, cell := range payloadCorpus {
		flagged := false
		for _, f := range inject.ScanCell(cell, inject.ProfileAll, inject.Options{}) {
			if f.AtStart {
				flagged = true
			}
		}
		_, changed := Cell(cell, inject.ProfileAll, ModeQuote, inject.Options{})
		if flagged != changed {
			t.Fatalf("disagreement on %q: flagged=%v changed=%v", cell, flagged, changed)
		}
	}
}

func TestParanoidSanitizesSignedNumber(t *testing.T) {
	got, changed := Cell("-12.5", inject.ProfileAll, ModeQuote, inject.Options{Paranoid: true})
	if !changed || got != "'-12.5" {
		t.Fatalf("got %q changed=%v", got, changed)
	}
}

func TestProfileScopedSanitize(t *testing.T) {
	// A leading TAB is only a trigger under Excel-style profiles, so the
	// sheets profile leaves "\thi" alone.
	got, changed := Cell("\thi", inject.ProfileSheets, ModeQuote, inject.Options{})
	if changed || got != "\thi" {
		t.Fatalf("sheets should not touch a tab-led cell: %q %v", got, changed)
	}
	got2, changed2 := Cell("\thi", inject.ProfileExcel, ModeQuote, inject.Options{})
	if !changed2 || got2 != "'\thi" {
		t.Fatalf("excel should quote a tab-led cell: %q %v", got2, changed2)
	}
}
