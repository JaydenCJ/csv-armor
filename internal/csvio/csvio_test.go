// Tests for the CSV I/O layer: delimiter sniffing, BOM/CRLF preservation,
// ragged-row tolerance, and round-tripping.
package csvio

import (
	"bytes"
	"testing"
)

func TestSniffComma(t *testing.T) {
	if d := SniffDelimiter([]byte("a,b,c\n1,2,3\n")); d != ',' {
		t.Fatalf("got %q", d)
	}
}

func TestSniffSemicolon(t *testing.T) {
	if d := SniffDelimiter([]byte("a;b;c\n1;2;3\n")); d != ';' {
		t.Fatalf("got %q", d)
	}
}

func TestSniffTab(t *testing.T) {
	if d := SniffDelimiter([]byte("a\tb\tc\n")); d != '\t' {
		t.Fatalf("got %q", d)
	}
}

func TestSniffIgnoresDelimitersInsideQuotes(t *testing.T) {
	// The quoted field contains semicolons, but commas separate fields.
	if d := SniffDelimiter([]byte(`a,"x;y;z",b` + "\n")); d != ',' {
		t.Fatalf("got %q", d)
	}
}

func TestSniffSingleColumnDefaultsComma(t *testing.T) {
	if d := SniffDelimiter([]byte("hello\nworld\n")); d != ',' {
		t.Fatalf("got %q", d)
	}
}

func TestParseBasic(t *testing.T) {
	doc, err := Parse([]byte("a,b\n1,2\n"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Records) != 2 || doc.Records[1][1] != "2" {
		t.Fatalf("got %+v", doc.Records)
	}
	if doc.Delim != ',' {
		t.Fatalf("delim %q", doc.Delim)
	}
}

func TestParseDetectsBOM(t *testing.T) {
	data := append([]byte{0xEF, 0xBB, 0xBF}, []byte("a,b\n")...)
	doc, err := Parse(data, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !doc.HadBOM {
		t.Fatal("BOM not detected")
	}
	if doc.Records[0][0] != "a" {
		t.Fatalf("BOM leaked into first field: %q", doc.Records[0][0])
	}
}

func TestParseDetectsCRLF(t *testing.T) {
	doc, err := Parse([]byte("a,b\r\n1,2\r\n"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if !doc.HadCRLF {
		t.Fatal("CRLF not detected")
	}
}

func TestParseRaggedRows(t *testing.T) {
	// Hostile exports are often malformed; the scanner must still read them.
	doc, err := Parse([]byte("a,b,c\n1,2\n3,4,5,6\n"), 0)
	if err != nil {
		t.Fatalf("ragged rows should parse, got %v", err)
	}
	if len(doc.Records) != 3 || len(doc.Records[2]) != 4 {
		t.Fatalf("got %+v", doc.Records)
	}
}

func TestWriteRoundTripComma(t *testing.T) {
	assertRoundTrip(t, "name,note\nAlice,hi\nBob,\"a,b\"\n")
}

func TestWritePreservesCRLF(t *testing.T) {
	assertRoundTrip(t, "a,b\r\n1,2\r\n")
}

func TestWriteKeepsBareLFInsideQuotedCellUnderCRLF(t *testing.T) {
	// Only the record terminator is CRLF; a bare \n embedded in a quoted
	// multi-line cell is cell *data* and must not be rewritten to \r\n.
	assertRoundTrip(t, "a,b\r\n1,\"line1\nline2\"\r\n")
}

func TestWritePreservesBOM(t *testing.T) {
	in := append([]byte{0xEF, 0xBB, 0xBF}, []byte("a,b\n1,2\n")...)
	doc, err := Parse(in, 0)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := Write(&buf, doc.Records, doc); err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(buf.Bytes(), []byte{0xEF, 0xBB, 0xBF}) {
		t.Fatal("BOM not re-emitted")
	}
}

func TestWriteNoTrailingNewlineWhenSourceLacksIt(t *testing.T) {
	doc, err := Parse([]byte("a,b\n1,2"), 0) // no trailing newline
	if err != nil {
		t.Fatal(err)
	}
	if doc.TrailNL {
		t.Fatal("should not have detected a trailing newline")
	}
	var buf bytes.Buffer
	if err := Write(&buf, doc.Records, doc); err != nil {
		t.Fatal(err)
	}
	if bytes.HasSuffix(buf.Bytes(), []byte("\n")) {
		t.Fatalf("unexpected trailing newline: %q", buf.String())
	}
}

func TestWriteQuotesFieldWithLeadingApostrophe(t *testing.T) {
	// The sanitizer's apostrophe must survive a write/read round-trip so
	// the neutralization is durable on disk.
	doc := &Document{Delim: ',', TrailNL: true}
	var buf bytes.Buffer
	if err := Write(&buf, [][]string{{"'=1+1", "ok"}}, doc); err != nil {
		t.Fatal(err)
	}
	back, err := Parse(buf.Bytes(), ',')
	if err != nil {
		t.Fatal(err)
	}
	if back.Records[0][0] != "'=1+1" {
		t.Fatalf("apostrophe lost: %q", back.Records[0][0])
	}
}

// assertRoundTrip parses input, writes it back, and requires byte-identity.
func assertRoundTrip(t *testing.T, input string) {
	t.Helper()
	doc, err := Parse([]byte(input), 0)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := Write(&buf, doc.Records, doc); err != nil {
		t.Fatal(err)
	}
	if buf.String() != input {
		t.Fatalf("round trip changed data:\n in: %q\nout: %q", input, buf.String())
	}
}
