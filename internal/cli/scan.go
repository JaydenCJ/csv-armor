package cli

import (
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/JaydenCJ/csv-armor/internal/csvio"
	"github.com/JaydenCJ/csv-armor/internal/inject"
	"github.com/JaydenCJ/csv-armor/internal/report"
)

func runScan(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var common commonFlags
	common.register(fs)
	format := fs.String("format", "text", "output format: text, json, or sarif")
	failOn := fs.String("fail-on", "high", "exit 1 when a finding reaches this severity: high, medium, low, none")
	quiet := fs.Bool("quiet", false, "print only the summary line")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}

	profile, delim, opts, err := common.resolve()
	if err != nil {
		fmt.Fprintf(stderr, "csv-armor: %v\n", err)
		return ExitUsage
	}
	if *format != "text" && *format != "json" && *format != "sarif" {
		fmt.Fprintf(stderr, "csv-armor: unknown --format %q (valid: text, json, sarif)\n", *format)
		return ExitUsage
	}
	threshold, unlimited, err := parseFailOn(*failOn)
	if err != nil {
		fmt.Fprintf(stderr, "csv-armor: %v\n", err)
		return ExitUsage
	}

	sources, err := collect(fs.Args(), stdin, true)
	if err != nil {
		fmt.Fprintf(stderr, "csv-armor: %v\n", err)
		return ExitRuntime
	}
	if len(sources) == 0 {
		fmt.Fprintln(stderr, "csv-armor: no input files")
		return ExitUsage
	}

	reports := make([]report.FileReport, 0, len(sources))
	for _, s := range sources {
		doc, perr := csvio.Parse(s.data, delim)
		if perr != nil {
			reports = append(reports, report.FileReport{File: s.name, ParseError: perr.Error()})
			continue
		}
		reports = append(reports, report.ScanDocument(s.name, doc, profile, opts))
	}
	summary := report.Summarize(reports)

	switch *format {
	case "json":
		if err := report.RenderJSON(stdout, reports, summary, profile); err != nil {
			fmt.Fprintf(stderr, "csv-armor: %v\n", err)
			return ExitRuntime
		}
	case "sarif":
		if err := report.RenderSARIF(stdout, reports, profile); err != nil {
			fmt.Fprintf(stderr, "csv-armor: %v\n", err)
			return ExitRuntime
		}
	default:
		if *quiet {
			renderQuiet(stdout, summary, profile)
		} else {
			report.RenderText(stdout, reports, summary, profile)
		}
	}

	// Any unparseable file is a runtime failure regardless of findings.
	for _, r := range reports {
		if r.ParseError != "" {
			return ExitRuntime
		}
	}
	if !unlimited && summary.MaxSeverity >= threshold && summary.Findings > 0 {
		return ExitFindings
	}
	return ExitOK
}

// parseFailOn maps the flag value to a threshold. "none" disables the gate.
func parseFailOn(s string) (inject.Severity, bool, error) {
	if strings.ToLower(s) == "none" {
		return 0, true, nil
	}
	sev, err := inject.ParseSeverity(s)
	return sev, false, err
}

func renderQuiet(w io.Writer, s report.Summary, profile inject.Profile) {
	fmt.Fprintf(w, "csv-armor: %d finding(s) in %d/%d file(s) — high %d, medium %d, low %d (profile %s)\n",
		s.Findings, s.FilesFlagged, s.Files,
		s.BySeverity["high"], s.BySeverity["medium"], s.BySeverity["low"], profile)
}
