// Package csvio wraps encoding/csv with the small conveniences a CSV-security
// tool needs: BOM handling, delimiter sniffing, and lenient reading of ragged
// rows (a scanner must inspect malformed files, not reject them). It stays a
// thin, stdlib-only layer so the injection logic never depends on parsing.
package csvio

import (
	"bytes"
	"encoding/csv"
	"errors"
	"io"
	"strings"
)

// utf8BOM is the byte-order mark some spreadsheet exports prepend.
var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// Document is a parsed CSV: its records plus the metadata csv-armor needs to
// write an equivalent file back out.
type Document struct {
	Records [][]string
	Delim   rune
	HadBOM  bool
	HadCRLF bool
	TrailNL bool // whether the source ended with a newline
}

// candidateDelims are tried by SniffDelimiter, in preference order.
var candidateDelims = []rune{',', ';', '\t', '|'}

// SniffDelimiter guesses the field delimiter from the first non-empty line by
// counting candidate characters outside of quotes. Comma wins ties, matching
// the overwhelming majority of real CSVs.
func SniffDelimiter(data []byte) rune {
	data = bytes.TrimPrefix(data, utf8BOM)
	line := firstLine(data)
	best, bestCount := ',', -1
	for _, d := range candidateDelims {
		if c := countOutsideQuotes(line, d); c > bestCount {
			best, bestCount = d, c
		}
	}
	if bestCount <= 0 {
		return ',' // Single-column file: comma is the safe default.
	}
	return best
}

func firstLine(data []byte) string {
	inQuote := false
	for i := 0; i < len(data); i++ {
		switch data[i] {
		case '"':
			inQuote = !inQuote
		case '\n', '\r':
			if !inQuote {
				return string(data[:i])
			}
		}
	}
	return string(data)
}

func countOutsideQuotes(line string, delim rune) int {
	inQuote, count := false, 0
	for _, r := range line {
		switch {
		case r == '"':
			inQuote = !inQuote
		case r == delim && !inQuote:
			count++
		}
	}
	return count
}

// Parse reads a CSV document, sniffing the delimiter unless delim != 0.
// Ragged rows (varying field counts) are allowed because malicious exports
// are frequently malformed and must still be scanned.
func Parse(data []byte, delim rune) (*Document, error) {
	doc := &Document{}
	if bytes.HasPrefix(data, utf8BOM) {
		doc.HadBOM = true
		data = data[len(utf8BOM):]
	}
	doc.HadCRLF = bytes.Contains(data, []byte("\r\n"))
	doc.TrailNL = len(data) > 0 && (data[len(data)-1] == '\n' || data[len(data)-1] == '\r')

	if delim == 0 {
		delim = SniffDelimiter(data)
	}
	doc.Delim = delim

	r := csv.NewReader(bytes.NewReader(data))
	r.Comma = delim
	r.FieldsPerRecord = -1 // Allow ragged rows.
	r.LazyQuotes = true    // Tolerate stray quotes in hostile input.
	r.ReuseRecord = false

	for {
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		doc.Records = append(doc.Records, rec)
	}
	return doc, nil
}

// Write serializes records back to CSV, preserving the document's delimiter,
// BOM, and line ending. encoding/csv always quotes fields that need it, which
// is what keeps a sanitized value inert on disk.
func Write(w io.Writer, records [][]string, doc *Document) error {
	terminator := "\n"
	if doc.HadCRLF {
		terminator = "\r\n"
	}

	// Encode record by record so only the *record terminator* is swapped
	// for the source's CRLF. csv.Writer's own UseCRLF would also rewrite
	// newlines embedded inside quoted cells, silently changing cell data.
	var buf bytes.Buffer
	cw := csv.NewWriter(&buf)
	cw.Comma = doc.Delim
	var out strings.Builder
	for _, rec := range records {
		buf.Reset()
		if err := cw.Write(rec); err != nil {
			return err
		}
		cw.Flush()
		if err := cw.Error(); err != nil {
			return err
		}
		// With UseCRLF unset the writer ends each record with a single
		// \n (any \n before it is quoted cell content); replace it.
		out.WriteString(strings.TrimSuffix(buf.String(), "\n"))
		out.WriteString(terminator)
	}

	s := out.String()
	if !doc.TrailNL {
		s = strings.TrimSuffix(s, terminator)
	}
	if doc.HadBOM {
		if _, err := w.Write(utf8BOM); err != nil {
			return err
		}
	}
	_, err := io.WriteString(w, s)
	return err
}

// DelimName renders a delimiter for human-readable reports.
func DelimName(d rune) string {
	switch d {
	case ',':
		return "comma"
	case ';':
		return "semicolon"
	case '\t':
		return "tab"
	case '|':
		return "pipe"
	}
	return string(d)
}
