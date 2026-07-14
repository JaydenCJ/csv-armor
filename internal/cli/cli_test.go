// In-process integration tests for the CLI: exercise Run with argv and
// captured writers, asserting on exit codes and output. No binary is built
// and no network is touched.
package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JaydenCJ/csv-armor/internal/version"
)

// run invokes the CLI with the given argv and stdin text, returning exit
// code, stdout, and stderr.
func run(args []string, stdin string) (int, string, string) {
	var out, errb bytes.Buffer
	code := Run(args, strings.NewReader(stdin), &out, &errb)
	return code, out.String(), errb.String()
}

// writeCSV creates a temp CSV file and returns its path.
func writeCSV(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestVersionMatchesManifest(t *testing.T) {
	code, out, _ := run([]string{"version"}, "")
	if code != ExitOK {
		t.Fatalf("exit %d", code)
	}
	if strings.TrimSpace(out) != "csv-armor "+version.Version {
		t.Fatalf("got %q", out)
	}
}

func TestNoArgsIsUsageError(t *testing.T) {
	code, _, errb := run(nil, "")
	if code != ExitUsage {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(errb, "Usage:") {
		t.Fatalf("expected usage text, got %q", errb)
	}
}

func TestUnknownCommandIsUsageError(t *testing.T) {
	code, _, errb := run([]string{"frobnicate"}, "")
	if code != ExitUsage || !strings.Contains(errb, "unknown command") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
}

func TestScanCleanFileExitsZero(t *testing.T) {
	p := writeCSV(t, "clean.csv", "name,age\nAlice,30\nBob,-25\n")
	code, out, _ := run([]string{"scan", p}, "")
	if code != ExitOK {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(out, "clean") {
		t.Fatalf("expected clean report: %q", out)
	}
}

func TestScanFormulaExitsOne(t *testing.T) {
	p := writeCSV(t, "bad.csv", "name,note\nAlice,=1+1\n")
	// A plain formula is medium; default --fail-on is high, so exit 0...
	code, _, _ := run([]string{"scan", p}, "")
	if code != ExitOK {
		t.Fatalf("medium finding under default high gate should exit 0, got %d", code)
	}
	// ...but --fail-on medium turns it into a gate failure.
	code2, _, _ := run([]string{"scan", "--fail-on", "medium", p}, "")
	if code2 != ExitFindings {
		t.Fatalf("expected exit 1, got %d", code2)
	}
}

func TestScanHighSeverityExitsOne(t *testing.T) {
	p := writeCSV(t, "dde.csv", "x\n=cmd|' /C calc'!A0\n")
	code, out, _ := run([]string{"scan", p}, "")
	if code != ExitFindings {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(out, "dde") {
		t.Fatalf("expected dde finding: %q", out)
	}
}

func TestScanReadsStdin(t *testing.T) {
	code, out, _ := run([]string{"scan", "--fail-on", "none"}, "x\n=1+1\n")
	if code != ExitOK {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(out, "<stdin>") {
		t.Fatalf("expected <stdin> label: %q", out)
	}
}

func TestScanJSONFormat(t *testing.T) {
	p := writeCSV(t, "bad.csv", "name,note\nAlice,=WEBSERVICE(\"http://127.0.0.1\")\n")
	code, out, _ := run([]string{"scan", "--format", "json", p}, "")
	if code != ExitFindings {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(out, `"tool": "csv-armor"`) || !strings.Contains(out, `"kind": "exfiltration"`) {
		t.Fatalf("bad json: %q", out)
	}
}

func TestScanSARIFFormat(t *testing.T) {
	p := writeCSV(t, "bad.csv", "x\n=cmd|' /C calc'!A0\n")
	code, out, _ := run([]string{"scan", "--format", "sarif", p}, "")
	if code != ExitFindings {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(out, `"version": "2.1.0"`) || !strings.Contains(out, "csv-injection/dde") {
		t.Fatalf("bad sarif: %q", out)
	}
}

func TestScanProfileScoping(t *testing.T) {
	// A leading TAB triggers under excel but not under sheets.
	p := writeCSV(t, "tab.csv", "x\n\thello\n")
	codeExcel, _, _ := run([]string{"scan", "--profile", "excel", "--fail-on", "low", p}, "")
	if codeExcel != ExitFindings {
		t.Fatalf("excel should flag leading tab, exit %d", codeExcel)
	}
	codeSheets, outSheets, _ := run([]string{"scan", "--profile", "sheets", "--fail-on", "low", p}, "")
	if codeSheets != ExitOK || !strings.Contains(outSheets, "clean") {
		t.Fatalf("sheets should be clean: code=%d out=%q", codeSheets, outSheets)
	}
}

func TestScanBadFormatIsUsageError(t *testing.T) {
	p := writeCSV(t, "x.csv", "a\n1\n")
	code, _, errb := run([]string{"scan", "--format", "yaml", p}, "")
	if code != ExitUsage || !strings.Contains(errb, "format") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
}

func TestScanMissingFileIsRuntimeError(t *testing.T) {
	code, _, errb := run([]string{"scan", "/no/such/file.csv"}, "")
	if code != ExitRuntime {
		t.Fatalf("exit %d", code)
	}
	if errb == "" {
		t.Fatal("expected an error message")
	}
}

func TestScanDirectoryRecurses(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.csv"), []byte("x\n=1+1\n"), 0o644)
	sub := filepath.Join(dir, "sub")
	os.Mkdir(sub, 0o755)
	os.WriteFile(filepath.Join(sub, "b.csv"), []byte("x\nsafe\n"), 0o644)
	os.WriteFile(filepath.Join(sub, "note.txt"), []byte("=1+1\n"), 0o644) // ignored
	code, out, _ := run([]string{"scan", "--fail-on", "none", dir}, "")
	if code != ExitOK {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(out, "a.csv") || !strings.Contains(out, "b.csv") {
		t.Fatalf("both csv files should appear: %q", out)
	}
	if strings.Contains(out, "note.txt") {
		t.Fatal("non-csv file should be ignored")
	}
}

func TestSanitizeToStdout(t *testing.T) {
	p := writeCSV(t, "bad.csv", "name,note\nAlice,=1+1\n")
	code, out, _ := run([]string{"sanitize", p}, "")
	if code != ExitOK {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(out, "'=1+1") {
		t.Fatalf("expected quoted formula: %q", out)
	}
}

func TestSanitizeInPlaceThenScanClean(t *testing.T) {
	p := writeCSV(t, "bad.csv", "name,note\nAlice,=cmd|' /C calc'!A0\n")
	code, _, errb := run([]string{"sanitize", "--in-place", p}, "")
	if code != ExitOK {
		t.Fatalf("exit %d err=%q", code, errb)
	}
	if !strings.Contains(errb, "sanitized") {
		t.Fatalf("expected status on stderr: %q", errb)
	}
	// The rewritten file must now scan clean at any threshold.
	code2, out2, _ := run([]string{"scan", "--fail-on", "low", p}, "")
	if code2 != ExitOK {
		t.Fatalf("sanitized file still flagged (exit %d):\n%s", code2, out2)
	}
}

func TestSanitizeDirectoryIsUsageError(t *testing.T) {
	// sanitize rewrites exactly one file; a directory must be rejected up
	// front instead of silently sanitizing whichever file sorts first (or
	// crashing on an empty directory).
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.csv"), []byte("x\n=1+1\n"), 0o644)
	code, out, errb := run([]string{"sanitize", dir}, "")
	if code != ExitUsage || !strings.Contains(errb, "directory") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	if out != "" {
		t.Fatalf("nothing should be written for a rejected directory: %q", out)
	}
}

func TestSanitizeInPlaceStdinIsUsageError(t *testing.T) {
	code, _, errb := run([]string{"sanitize", "--in-place"}, "x\n=1+1\n")
	if code != ExitUsage || !strings.Contains(errb, "in-place") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
}

func TestSanitizeOutputFile(t *testing.T) {
	p := writeCSV(t, "bad.csv", "x\n=1+1\n")
	outPath := filepath.Join(filepath.Dir(p), "clean.csv")
	code, _, _ := run([]string{"sanitize", "--output", outPath, p}, "")
	if code != ExitOK {
		t.Fatalf("exit %d", code)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "'=1+1") {
		t.Fatalf("output file wrong: %q", data)
	}
}
