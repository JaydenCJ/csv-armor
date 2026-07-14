package report

import (
	"encoding/json"
	"io"

	"github.com/JaydenCJ/csv-armor/internal/inject"
)

// jsonEnvelope is the stable machine-readable schema (schema_version 1).
type jsonEnvelope struct {
	Tool          string       `json:"tool"`
	SchemaVersion int          `json:"schema_version"`
	Profile       string       `json:"profile"`
	Summary       Summary      `json:"summary"`
	Files         []FileReport `json:"files"`
}

// RenderJSON writes the report as indented JSON with a stable envelope.
func RenderJSON(w io.Writer, reports []FileReport, s Summary, profile inject.Profile) error {
	env := jsonEnvelope{
		Tool:          "csv-armor",
		SchemaVersion: 1,
		Profile:       string(profile),
		Summary:       s,
		Files:         reports,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(env)
}
