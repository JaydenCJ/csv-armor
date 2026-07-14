// Tests for whole-document scanning, summary folding, and the three
// renderers. Renderers are checked for stable, machine-parseable output.
package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/JaydenCJ/csv-armor/internal/csvio"
	"github.com/JaydenCJ/csv-armor/internal/inject"
)

func scan(t *testing.T, csv string) (FileReport, Summary) {
	t.Helper()
	doc, err := csvio.Parse([]byte(csv), 0)
	if err != nil {
		t.Fatal(err)
	}
	fr := ScanDocument("test.csv", doc, inject.ProfileAll, inject.Options{})
	return fr, Summarize([]FileReport{fr})
}

func TestScanLocatesFinding(t *testing.T) {
	fr, _ := scan(t, "name,note\nAlice,=1+1\n")
	if len(fr.Findings) != 1 {
		t.Fatalf("got %d findings", len(fr.Findings))
	}
	f := fr.Findings[0]
	if f.Row != 2 || f.Col != 2 {
		t.Fatalf("wrong location R%dC%d", f.Row, f.Col)
	}
}

func TestScanCountsCells(t *testing.T) {
	fr, _ := scan(t, "a,b\n1,2\n3,4\n")
	if fr.Cells != 6 {
		t.Fatalf("got %d cells", fr.Cells)
	}
}

func TestScanRowMajorOrder(t *testing.T) {
	fr, _ := scan(t, "=1,=2\n=3,=4\n")
	want := [][2]int{{1, 1}, {1, 2}, {2, 1}, {2, 2}}
	if len(fr.Findings) != 4 {
		t.Fatalf("got %d findings", len(fr.Findings))
	}
	for i, w := range want {
		if fr.Findings[i].Row != w[0] || fr.Findings[i].Col != w[1] {
			t.Fatalf("finding %d at R%dC%d want R%dC%d",
				i, fr.Findings[i].Row, fr.Findings[i].Col, w[0], w[1])
		}
	}
}

func TestSummaryMaxSeverity(t *testing.T) {
	_, s := scan(t, "a\n=WEBSERVICE(\"http://127.0.0.1\")\n")
	if s.MaxSeverity != inject.High {
		t.Fatalf("got %s", s.MaxSeverity)
	}
}

func TestSummaryBySeverity(t *testing.T) {
	// One medium (=1+1) and one high (WEBSERVICE).
	_, s := scan(t, "x\n=1+1\n=WEBSERVICE(\"http://127.0.0.1\")\n")
	if s.BySeverity["medium"] != 1 || s.BySeverity["high"] != 1 {
		t.Fatalf("got %+v", s.BySeverity)
	}
}

func TestSummaryFilesFlagged(t *testing.T) {
	clean, _ := scan(t, "a,b\n1,2\n")
	dirty, _ := scan(t, "a\n=1+1\n")
	s := Summarize([]FileReport{clean, dirty})
	if s.Files != 2 || s.FilesFlagged != 1 {
		t.Fatalf("files=%d flagged=%d", s.Files, s.FilesFlagged)
	}
}

func TestSummaryCleanFileHasNoFindings(t *testing.T) {
	_, s := scan(t, "name,age\nAlice,30\nBob,-25\n")
	if s.Findings != 0 {
		t.Fatalf("clean file flagged: %+v", s)
	}
}

func TestRenderTextShowsFindingAndSummary(t *testing.T) {
	fr, s := scan(t, "name,note\nAlice,=1+1\n")
	var buf bytes.Buffer
	RenderText(&buf, []FileReport{fr}, s, inject.ProfileAll)
	out := buf.String()
	for _, want := range []string{"R2C2", "formula", "summary", "findings       1"} {
		if !strings.Contains(out, want) {
			t.Fatalf("text output missing %q:\n%s", want, out)
		}
	}
}

func TestRenderJSONIsValidAndStable(t *testing.T) {
	fr, s := scan(t, "name,note\nAlice,=1+1\n")
	var buf bytes.Buffer
	if err := RenderJSON(&buf, []FileReport{fr}, s, inject.ProfileAll); err != nil {
		t.Fatal(err)
	}
	var env struct {
		Tool          string `json:"tool"`
		SchemaVersion int    `json:"schema_version"`
		Summary       struct {
			Findings int `json:"findings"`
		} `json:"summary"`
		Files []struct {
			Findings []struct {
				Row      int    `json:"row"`
				Kind     string `json:"kind"`
				Severity string `json:"severity"`
			} `json:"findings"`
		} `json:"files"`
	}
	if err := json.Unmarshal(buf.Bytes(), &env); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if env.Tool != "csv-armor" || env.SchemaVersion != 1 {
		t.Fatalf("bad envelope: %+v", env)
	}
	if env.Summary.Findings != 1 || env.Files[0].Findings[0].Kind != "formula" {
		t.Fatalf("bad payload: %+v", env)
	}
}

func TestRenderJSONDoesNotEscapeHTML(t *testing.T) {
	// A URL with an ampersand must survive verbatim in the preview; if the
	// encoder HTML-escaped it into the "&amp;" entity the evidence would be
	// corrupted for anyone reading the JSON.
	entity := "&" + "amp;"
	fr, s := scan(t, "x\n=HYPERLINK(\"http://example.test?a=1&b=2\")\n")
	var buf bytes.Buffer
	if err := RenderJSON(&buf, []FileReport{fr}, s, inject.ProfileAll); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), entity) {
		t.Fatal("ampersand was HTML-escaped")
	}
	if !strings.Contains(buf.String(), "a=1&b=2") {
		t.Fatal("raw ampersand missing from preview")
	}
}

func TestRenderSARIFIsValid(t *testing.T) {
	fr, _ := scan(t, "name,note\nAlice,=WEBSERVICE(\"http://127.0.0.1\")\n")
	var buf bytes.Buffer
	if err := RenderSARIF(&buf, []FileReport{fr}, inject.ProfileAll); err != nil {
		t.Fatal(err)
	}
	var log struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID string `json:"ruleId"`
				Level  string `json:"level"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("invalid SARIF: %v", err)
	}
	if log.Version != "2.1.0" {
		t.Fatalf("wrong sarif version %q", log.Version)
	}
	if log.Runs[0].Tool.Driver.Name != "csv-armor" {
		t.Fatal("driver name wrong")
	}
	if len(log.Runs[0].Results) != 1 || log.Runs[0].Results[0].Level != "error" {
		t.Fatalf("bad results: %+v", log.Runs[0].Results)
	}
}

func TestRenderSARIFEmptyIsValid(t *testing.T) {
	// A clean scan must still produce a valid, empty-results SARIF log so
	// CI upload steps do not choke.
	fr, _ := scan(t, "a,b\n1,2\n")
	var buf bytes.Buffer
	if err := RenderSARIF(&buf, []FileReport{fr}, inject.ProfileAll); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"results": []`) {
		t.Fatalf("expected empty results array:\n%s", buf.String())
	}
}

func TestDeterministicAcrossRuns(t *testing.T) {
	// Identical input must produce byte-identical JSON on repeat runs.
	const csv = "name,a,b\nAlice,=1+1,ok\nBob,@SUM(x),=HYPERLINK(\"http://example.test\")\n"
	render := func() string {
		doc, _ := csvio.Parse([]byte(csv), 0)
		fr := ScanDocument("t.csv", doc, inject.ProfileAll, inject.Options{})
		s := Summarize([]FileReport{fr})
		var buf bytes.Buffer
		_ = RenderJSON(&buf, []FileReport{fr}, s, inject.ProfileAll)
		return buf.String()
	}
	if render() != render() {
		t.Fatal("non-deterministic JSON output")
	}
}
