package cli

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/JaydenCJ/csv-armor/internal/csvio"
	"github.com/JaydenCJ/csv-armor/internal/sanitize"
)

func runSanitize(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("sanitize", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var common commonFlags
	common.register(fs)
	modeName := fs.String("mode", "quote", "neutralization mode: quote or strip")
	inPlace := fs.Bool("in-place", false, "overwrite the input file")
	output := fs.String("output", "", "write sanitized CSV to this file instead of stdout")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}

	profile, delim, opts, err := common.resolve()
	if err != nil {
		fmt.Fprintf(stderr, "csv-armor: %v\n", err)
		return ExitUsage
	}
	mode, err := sanitize.ParseMode(*modeName)
	if err != nil {
		fmt.Fprintf(stderr, "csv-armor: %v\n", err)
		return ExitUsage
	}

	paths := fs.Args()
	if len(paths) > 1 {
		fmt.Fprintln(stderr, "csv-armor: sanitize accepts at most one file")
		return ExitUsage
	}
	if *inPlace && (len(paths) == 0 || paths[0] == "-") {
		fmt.Fprintln(stderr, "csv-armor: --in-place needs a real file, not stdin")
		return ExitUsage
	}
	if *inPlace && *output != "" {
		fmt.Fprintln(stderr, "csv-armor: use either --in-place or --output, not both")
		return ExitUsage
	}
	if len(paths) == 1 && paths[0] != "-" {
		if info, err := os.Stat(paths[0]); err == nil && info.IsDir() {
			fmt.Fprintf(stderr, "csv-armor: %s is a directory — sanitize rewrites one file at a time (loop over its files, or use scan to audit a whole directory)\n", paths[0])
			return ExitUsage
		}
	}

	sources, err := collect(paths, stdin, true)
	if err != nil {
		fmt.Fprintf(stderr, "csv-armor: %v\n", err)
		return ExitRuntime
	}
	src := sources[0]

	doc, err := csvio.Parse(src.data, delim)
	if err != nil {
		fmt.Fprintf(stderr, "csv-armor: %s: %v\n", src.name, err)
		return ExitRuntime
	}

	changed := 0
	out := make([][]string, len(doc.Records))
	for r, rec := range doc.Records {
		row := make([]string, len(rec))
		for c, cell := range rec {
			v, did := sanitize.Cell(cell, profile, mode, opts)
			row[c] = v
			if did {
				changed++
			}
		}
		out[r] = row
	}

	var buf bytes.Buffer
	if err := csvio.Write(&buf, out, doc); err != nil {
		fmt.Fprintf(stderr, "csv-armor: %v\n", err)
		return ExitRuntime
	}

	switch {
	case *inPlace:
		if err := os.WriteFile(src.name, buf.Bytes(), 0o644); err != nil {
			fmt.Fprintf(stderr, "csv-armor: %v\n", err)
			return ExitRuntime
		}
		fmt.Fprintf(stderr, "csv-armor: sanitized %d cell(s) in %s\n", changed, src.name)
	case *output != "":
		if err := os.WriteFile(*output, buf.Bytes(), 0o644); err != nil {
			fmt.Fprintf(stderr, "csv-armor: %v\n", err)
			return ExitRuntime
		}
		fmt.Fprintf(stderr, "csv-armor: sanitized %d cell(s) → %s\n", changed, *output)
	default:
		if _, err := stdout.Write(buf.Bytes()); err != nil {
			return ExitRuntime
		}
	}
	return ExitOK
}
