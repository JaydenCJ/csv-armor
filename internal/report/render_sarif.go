package report

import (
	"encoding/json"
	"io"

	"github.com/JaydenCJ/csv-armor/internal/inject"
	"github.com/JaydenCJ/csv-armor/internal/version"
)

// RenderSARIF writes a SARIF 2.1.0 log, which GitHub code-scanning and most
// security dashboards ingest directly — so `csv-armor scan --format sarif`
// drops findings straight into a CI security tab. Kept to the minimal object
// graph SARIF requires; no external SARIF library.
func RenderSARIF(w io.Writer, reports []FileReport, profile inject.Profile) error {
	rules := map[inject.Kind]int{}
	var ruleList []map[string]any
	var results []map[string]any

	for _, fr := range reports {
		for _, f := range fr.Findings {
			if _, ok := rules[f.Kind]; !ok {
				rules[f.Kind] = len(ruleList)
				ruleList = append(ruleList, map[string]any{
					"id":               "csv-injection/" + string(f.Kind),
					"name":             "CsvInjection" + kindPascal(f.Kind),
					"shortDescription": map[string]string{"text": "CSV formula injection (" + string(f.Kind) + ")"},
				})
			}
			results = append(results, map[string]any{
				"ruleId":    "csv-injection/" + string(f.Kind),
				"ruleIndex": rules[f.Kind],
				"level":     sarifLevel(f.Severity),
				"message":   map[string]string{"text": f.Reason},
				"locations": []map[string]any{{
					"physicalLocation": map[string]any{
						"artifactLocation": map[string]string{"uri": f.File},
						"region": map[string]int{
							"startLine":   f.Row,
							"startColumn": f.Col,
						},
					},
				}},
			})
		}
	}
	if results == nil {
		results = []map[string]any{}
	}
	if ruleList == nil {
		ruleList = []map[string]any{}
	}

	log := map[string]any{
		"version": "2.1.0",
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"runs": []map[string]any{{
			"tool": map[string]any{
				"driver": map[string]any{
					"name":           "csv-armor",
					"informationUri": "https://github.com/JaydenCJ/csv-armor",
					"version":        version.Version,
					"rules":          ruleList,
				},
			},
			"results": results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(log)
}

func sarifLevel(s inject.Severity) string {
	switch s {
	case inject.High:
		return "error"
	case inject.Medium:
		return "warning"
	default:
		return "note"
	}
}

func kindPascal(k inject.Kind) string {
	switch k {
	case inject.KindDDE:
		return "Dde"
	case inject.KindExfil:
		return "Exfiltration"
	case inject.KindFormula:
		return "Formula"
	case inject.KindArithmetic:
		return "Arithmetic"
	case inject.KindAtSign:
		return "AtSign"
	case inject.KindControl:
		return "Control"
	case inject.KindEmbedded:
		return "Embedded"
	}
	return "Unknown"
}
