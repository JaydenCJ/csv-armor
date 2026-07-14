// Tests for the profile table: which triggers and network functions each
// spreadsheet application contributes, and how "all" unions them.
package inject

import "testing"

func TestParseProfileAccepts(t *testing.T) {
	cases := map[string]Profile{
		"all": ProfileAll, "excel": ProfileExcel,
		"sheets": ProfileSheets, "libreoffice": ProfileLibre,
		"ALL": ProfileAll, "Excel": ProfileExcel,
	}
	for in, want := range cases {
		got, err := ParseProfile(in)
		if err != nil || got != want {
			t.Fatalf("ParseProfile(%q)=%v,%v", in, got, err)
		}
	}
}

func TestParseProfileRejectsUnknown(t *testing.T) {
	if _, err := ParseProfile("gnumeric"); err == nil {
		t.Fatal("expected error")
	}
}

func TestExcelTriggersIncludeAtAndControls(t *testing.T) {
	tr := ProfileExcel.triggers()
	for _, r := range []rune{'=', '+', '-', '@', '\t', '\r'} {
		if !tr[r] {
			t.Fatalf("excel should trigger on %q", string(r))
		}
	}
}

func TestSheetsTriggersExcludeAtAndControls(t *testing.T) {
	tr := ProfileSheets.triggers()
	for _, r := range []rune{'@', '\t', '\r'} {
		if tr[r] {
			t.Fatalf("sheets should not trigger on %q", string(r))
		}
	}
	for _, r := range []rune{'=', '+', '-'} {
		if !tr[r] {
			t.Fatalf("sheets should trigger on %q", string(r))
		}
	}
}

func TestAllProfileUnionsFunctions(t *testing.T) {
	funcs := ProfileAll.exfilFuncs()
	for _, want := range []string{"WEBSERVICE", "IMPORTXML", "HYPERLINK"} {
		found := false
		for _, f := range funcs {
			if f == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("all profile missing %s: %v", want, funcs)
		}
	}
}

func TestDDECapability(t *testing.T) {
	if !ProfileExcel.ddeCapable() || !ProfileLibre.ddeCapable() || !ProfileAll.ddeCapable() {
		t.Fatal("excel, libreoffice, all should be DDE-capable")
	}
	if ProfileSheets.ddeCapable() {
		t.Fatal("sheets should not be DDE-capable")
	}
}

func TestTriggerListNamesControlChars(t *testing.T) {
	got := ProfileExcel.TriggerList()
	want := []string{"=", "+", "-", "@", "TAB", "CR"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("at %d: got %q want %q", i, got[i], want[i])
		}
	}
}
