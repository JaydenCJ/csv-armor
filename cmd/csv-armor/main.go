// Command csv-armor detects and neutralizes CSV formula injection before a
// spreadsheet application evaluates untrusted data as a formula.
package main

import (
	"os"

	"github.com/JaydenCJ/csv-armor/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
