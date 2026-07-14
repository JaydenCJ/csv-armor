package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/JaydenCJ/csv-armor/internal/inject"
)

// RenderText writes a human-readable report to w. It is deterministic: files
// keep scan order, findings keep row-major order.
func RenderText(w io.Writer, reports []FileReport, s Summary, profile inject.Profile) {
	for _, fr := range reports {
		if fr.ParseError != "" {
			fmt.Fprintf(w, "%s\n  parse error: %s\n\n", fr.File, fr.ParseError)
			continue
		}
		if len(fr.Findings) == 0 {
			fmt.Fprintf(w, "%s\n  clean — %d cells scanned (%s-delimited)\n\n",
				fr.File, fr.Cells, fr.Delimiter)
			continue
		}
		fmt.Fprintf(w, "%s\n  %d finding(s) across %d cells (%s-delimited)\n",
			fr.File, len(fr.Findings), fr.Cells, fr.Delimiter)
		for _, f := range fr.Findings {
			fmt.Fprintf(w, "  %s  R%dC%d  [%s/%s]  %s\n",
				sevTag(f.Severity), f.Row, f.Col, f.SeverityName, f.Kind, f.Reason)
			fmt.Fprintf(w, "         value: %s\n", f.Preview)
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintf(w, "summary (profile: %s)\n", profile)
	fmt.Fprintf(w, "  files          %d scanned, %d flagged\n", s.Files, s.FilesFlagged)
	fmt.Fprintf(w, "  cells          %d\n", s.Cells)
	fmt.Fprintf(w, "  findings       %d  (high %d, medium %d, low %d)\n",
		s.Findings, s.BySeverity["high"], s.BySeverity["medium"], s.BySeverity["low"])
	if len(s.ByKind) > 0 {
		kinds := make([]string, 0, len(s.ByKind))
		for k := range s.ByKind {
			kinds = append(kinds, k)
		}
		sort.Strings(kinds)
		var parts []string
		for _, k := range kinds {
			parts = append(parts, fmt.Sprintf("%s %d", k, s.ByKind[k]))
		}
		fmt.Fprintf(w, "  by kind        %s\n", strings.Join(parts, ", "))
	}
}

// sevTag returns a fixed-width visual severity marker.
func sevTag(s inject.Severity) string {
	switch s {
	case inject.High:
		return "!!"
	case inject.Medium:
		return "! "
	default:
		return "· "
	}
}
