// Package report ties the pure inject/sanitize engines to whole-document
// scanning and to the text/JSON/SARIF renderers. Scanning is deterministic:
// findings come out in row-major cell order, and the summary counts are a
// pure function of the findings slice.
package report

import (
	"github.com/JaydenCJ/csv-armor/internal/csvio"
	"github.com/JaydenCJ/csv-armor/internal/inject"
)

// CellFinding is one finding located within a file.
type CellFinding struct {
	File         string          `json:"file"`
	Row          int             `json:"row"` // 1-based, header included
	Col          int             `json:"col"` // 1-based
	Kind         inject.Kind     `json:"kind"`
	Severity     inject.Severity `json:"-"`
	SeverityName string          `json:"severity"`
	Reason       string          `json:"reason"`
	Preview      string          `json:"preview"`
}

// FileReport is the result of scanning a single file.
type FileReport struct {
	File      string        `json:"file"`
	Delimiter string        `json:"delimiter"`
	Rows      int           `json:"rows"`
	Cells     int           `json:"cells"`
	Findings  []CellFinding `json:"findings"`
	// ParseError is set when the file could not be parsed at all.
	ParseError string `json:"parse_error,omitempty"`
}

// ScanDocument scans one parsed document and returns its findings in
// row-major order.
func ScanDocument(file string, doc *csvio.Document, p inject.Profile, opts inject.Options) FileReport {
	fr := FileReport{
		File:      file,
		Delimiter: csvio.DelimName(doc.Delim),
	}
	fr.Rows = len(doc.Records)
	const previewLen = 48
	for r, rec := range doc.Records {
		for c, cell := range rec {
			fr.Cells++
			for _, f := range inject.ScanCell(cell, p, opts) {
				fr.Findings = append(fr.Findings, CellFinding{
					File:         file,
					Row:          r + 1,
					Col:          c + 1,
					Kind:         f.Kind,
					Severity:     f.Severity,
					SeverityName: f.Severity.String(),
					Reason:       f.Reason,
					Preview:      inject.Preview(cell, previewLen),
				})
			}
		}
	}
	return fr
}

// Summary aggregates counts across one or more file reports.
type Summary struct {
	Files        int            `json:"files"`
	FilesFlagged int            `json:"files_flagged"`
	Cells        int            `json:"cells_scanned"`
	Findings     int            `json:"findings"`
	BySeverity   map[string]int `json:"by_severity"`
	ByKind       map[string]int `json:"by_kind"`
	// MaxSeverity is the highest severity seen, for exit-code decisions.
	MaxSeverity inject.Severity `json:"-"`
}

// Summarize folds a set of file reports into totals.
func Summarize(reports []FileReport) Summary {
	s := Summary{
		BySeverity: map[string]int{"high": 0, "medium": 0, "low": 0},
		ByKind:     map[string]int{},
	}
	for _, fr := range reports {
		s.Files++
		s.Cells += fr.Cells
		if len(fr.Findings) > 0 {
			s.FilesFlagged++
		}
		for _, f := range fr.Findings {
			s.Findings++
			s.BySeverity[f.SeverityName]++
			s.ByKind[string(f.Kind)]++
			if f.Severity > s.MaxSeverity {
				s.MaxSeverity = f.Severity
			}
		}
	}
	return s
}
