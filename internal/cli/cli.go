// Package cli implements the csv-armor command-line interface. Run takes
// argv and two writers and returns an exit code, so the whole surface is
// testable in-process without building a binary.
package cli

import (
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/JaydenCJ/csv-armor/internal/inject"
	"github.com/JaydenCJ/csv-armor/internal/version"
)

// Exit codes. Documented in the README; `scan` uses ExitFindings as its
// machine-readable verdict for CI gates.
const (
	ExitOK       = 0
	ExitFindings = 1
	ExitUsage    = 2
	ExitRuntime  = 3
)

// Run dispatches argv and returns the process exit code.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return ExitUsage
	}
	switch args[0] {
	case "scan":
		return runScan(args[1:], stdin, stdout, stderr)
	case "sanitize":
		return runSanitize(args[1:], stdin, stdout, stderr)
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "csv-armor %s\n", version.Version)
		return ExitOK
	case "help", "--help", "-h":
		usage(stdout)
		return ExitOK
	default:
		fmt.Fprintf(stderr, "csv-armor: unknown command %q\n\n", args[0])
		usage(stderr)
		return ExitUsage
	}
}

// commonFlags are shared by scan and sanitize.
type commonFlags struct {
	profileName string
	delimiter   string
	paranoid    bool
}

func (c *commonFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&c.profileName, "profile", "all", "spreadsheet rule set: all, excel, sheets, libreoffice")
	fs.StringVar(&c.delimiter, "delimiter", "", "field delimiter (default: auto-sniff); use 'tab' for TSV")
	fs.BoolVar(&c.paranoid, "paranoid", false, "also flag signed numbers, phone numbers, and bare @handles")
}

// resolve parses the profile, delimiter, and options from the common flags.
func (c *commonFlags) resolve() (inject.Profile, rune, inject.Options, error) {
	p, err := inject.ParseProfile(c.profileName)
	if err != nil {
		return "", 0, inject.Options{}, err
	}
	d, err := parseDelim(c.delimiter)
	if err != nil {
		return "", 0, inject.Options{}, err
	}
	return p, d, inject.Options{Paranoid: c.paranoid}, nil
}

// parseDelim maps a user delimiter string to a rune (0 means auto-sniff).
func parseDelim(s string) (rune, error) {
	switch strings.ToLower(s) {
	case "":
		return 0, nil
	case "tab", "\\t":
		return '\t', nil
	case "comma":
		return ',', nil
	case "semicolon":
		return ';', nil
	case "pipe":
		return '|', nil
	}
	r := []rune(s)
	if len(r) != 1 {
		return 0, fmt.Errorf("delimiter must be a single character (or a name like 'tab'), got %q", s)
	}
	return r[0], nil
}

func usage(w io.Writer) {
	fmt.Fprint(w, `csv-armor — detect and neutralize CSV formula injection

Usage:
  csv-armor scan [flags] [file|dir ...]      report injection findings
  csv-armor sanitize [flags] [file]          rewrite a file with cells neutralized
  csv-armor version                          print the version
  csv-armor help                             show this message

Common flags:
  --profile      all | excel | sheets | libreoffice   (default all)
  --delimiter    field delimiter, e.g. tab            (default: auto-sniff)
  --paranoid     also flag signed numbers / @handles

scan flags:
  --format       text | json | sarif                  (default text)
  --fail-on      high | medium | low | none           (default high)
  --quiet        print only the summary line

sanitize flags:
  --mode         quote | strip                        (default quote)
  --in-place     overwrite the input file
  --output FILE  write to FILE instead of stdout

Exit codes: 0 clean/ok, 1 findings at or above --fail-on, 2 usage, 3 runtime.
A file argument of "-" reads from stdin. With no file arguments, scan reads stdin.
`)
}
