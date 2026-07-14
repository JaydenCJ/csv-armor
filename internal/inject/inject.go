// Package inject is the pure detection engine: it classifies individual CSV
// cell values as safe or as one of several formula-injection kinds, per
// spreadsheet-application profile. It never touches the filesystem or the
// network, so every rule is unit-testable with plain strings.
package inject

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Kind names the class of injection a cell was flagged for.
type Kind string

const (
	// KindDDE — a Dynamic Data Exchange payload (`=cmd|' /C calc'!A0` or
	// `=DDE(...)`); opening the file can execute a local program.
	KindDDE Kind = "dde"
	// KindExfil — a formula calling a network-capable function
	// (WEBSERVICE, IMPORTXML, HYPERLINK, …) that can leak sheet data.
	KindExfil Kind = "exfiltration"
	// KindFormula — a plain `=`-prefixed formula; the application will
	// evaluate it instead of displaying the text.
	KindFormula Kind = "formula"
	// KindArithmetic — a `+`/`-`-prefixed expression the application
	// evaluates (e.g. `-2+3`); plain signed numbers are exempt.
	KindArithmetic Kind = "arithmetic"
	// KindAtSign — a legacy Lotus `@FUNC(...)` call, honored by Excel.
	KindAtSign Kind = "at-sign"
	// KindControl — the cell starts with TAB or CR, which the OWASP
	// guidance requires escaping for Excel.
	KindControl Kind = "control"
	// KindEmbedded — a later line inside a multi-line cell starts with a
	// trigger character; dangerous if a downstream tool re-exports the
	// value without proper quoting.
	KindEmbedded Kind = "embedded"
)

// Severity ranks how bad a finding is. Higher is worse.
type Severity int

const (
	// Low — evaluated as data or requires a lossy re-export to trigger.
	Low Severity = iota + 1
	// Medium — the application evaluates attacker-controlled logic.
	Medium
	// High — code execution or data exfiltration on open.
	High
)

// String renders the severity for reports.
func (s Severity) String() string {
	switch s {
	case High:
		return "high"
	case Medium:
		return "medium"
	case Low:
		return "low"
	}
	return "unknown"
}

// ParseSeverity accepts the names used by `--fail-on`.
func ParseSeverity(s string) (Severity, error) {
	switch strings.ToLower(s) {
	case "low":
		return Low, nil
	case "medium":
		return Medium, nil
	case "high":
		return High, nil
	}
	return 0, fmt.Errorf("unknown severity %q (valid: low, medium, high, none)", s)
}

// Options tunes detection strictness.
type Options struct {
	// Paranoid disables the noise guards: plain signed numbers and phone
	// numbers (`-12.5`, `+81 90-1234-5678`) and bare `@handles` are then
	// flagged too. Use it when silent data corruption (Excel computing
	// `+1-555-0100` into `-654`) is unacceptable, not just code execution.
	Paranoid bool
}

// Finding describes one flagged cell (or one flagged line within a cell).
type Finding struct {
	Kind     Kind
	Severity Severity
	// Reason is a one-line human explanation quoting the evidence.
	Reason string
	// AtStart is true when the risk is at the cell start (sanitizable by
	// prefixing) and false for embedded multi-line findings.
	AtStart bool
}

var (
	// ddePipeRe matches Excel's legacy DDE syntax: a program name, a pipe,
	// a quoted argument string, and a `!reference`, anywhere in the cell —
	// e.g. `=cmd|' /C calc'!A0` or `@SUM(1+9)*cmd|' /C calc'!A0`.
	ddePipeRe = regexp.MustCompile(`(?i)([a-z][a-z0-9_.\\/ -]*)\|\s*'[^']*'\s*!`)
	// ddeFuncRe matches LibreOffice's DDE() spreadsheet function.
	ddeFuncRe = regexp.MustCompile(`(?i)\bDDE\s*\(`)
	// signedNumberRe accepts plain signed numbers: -12.5, +1234,
	// -1,234.56, -1.2e-3, -85%. These are data, not formulas.
	signedNumberRe = regexp.MustCompile(`^[+-] ?[0-9][0-9,._ ]*(\.[0-9]+)?([eE][+-]?[0-9]+)?%?$`)
	// phoneRe accepts international phone numbers: +81 90-1234-5678,
	// +1 (555) 010-0100. Excel may still compute some of these into a
	// number (data corruption), but they cannot execute code; --paranoid
	// flags them anyway.
	phoneRe = regexp.MustCompile(`^\+[0-9][0-9 ()./-]*$`)
	// atCallRe matches the legacy Lotus function-call shape `@NAME(`,
	// which Excel evaluates; a bare `@handle` does not match.
	atCallRe = regexp.MustCompile(`^@[A-Za-z_][A-Za-z0-9_.]*\(`)
)

// exfilRes caches one compiled alternation per profile.
var exfilRes = map[Profile]*regexp.Regexp{}

func init() {
	for _, p := range Profiles {
		funcs := p.exfilFuncs()
		exfilRes[p] = regexp.MustCompile(`(?i)\b(` + strings.Join(funcs, "|") + `)\s*\(`)
	}
}

// ScanCell classifies one cell value under a profile and returns zero, one,
// or two findings (at most one cell-start finding plus at most one embedded
// finding). The input is the decoded field value — quotes already removed
// by the CSV parser.
func ScanCell(cell string, p Profile, opts Options) []Finding {
	var out []Finding
	startControl := false
	if f, ok := scanStart(cell, p, opts); ok {
		out = append(out, f)
		// A leading CR is itself the line break scanEmbedded would trip
		// on; reporting it twice (once as control, once as embedded)
		// would double-count the same character.
		startControl = f.Kind == KindControl
	}
	if !startControl {
		if f, ok := scanEmbedded(cell, p, opts); ok {
			out = append(out, f)
		}
	}
	return out
}

// isPadding reports whether a rune is leading noise a spreadsheet trims
// before deciding whether the cell is a formula. Excel and friends trim
// leading spaces (and non-breaking spaces) — the classic `  =1+1` bypass —
// but NOT TAB or CR, which the OWASP guidance treats as triggers in their
// own right, so those are left for scanStart to classify.
func isPadding(r rune) bool {
	return r == ' ' || r == 0xA0
}

// scanStart handles the cell-start trigger characters, including the
// leading-whitespace bypass (Excel trims leading spaces before deciding
// whether a cell is a formula).
func scanStart(cell string, p Profile, opts Options) (Finding, bool) {
	if cell == "" {
		return Finding{}, false
	}
	trig := p.triggers()

	// Strip leading padding, remembering what was skipped: Excel decides
	// formula-ness from the first significant character, so `  =1+1` is a
	// classic filter bypass.
	trimmed := strings.TrimLeftFunc(cell, isPadding)
	pad := cell[:len(cell)-len(trimmed)]
	if trimmed == "" {
		// Whitespace-only cell: nothing for a spreadsheet to evaluate.
		return Finding{}, false
	}
	first, _ := utf8.DecodeRuneInString(trimmed)
	if !trig[first] {
		return Finding{}, false
	}

	rest := trimmed
	bypass := ""
	if len(pad) > 0 {
		bypass = " (after leading whitespace — a known filter bypass)"
	}

	base := Finding{AtStart: true}
	switch first {
	case '\t', '\r':
		name := "TAB"
		if first == '\r' {
			name = "CR"
		}
		return Finding{
			Kind: KindControl, Severity: Low, AtStart: true,
			Reason: "cell starts with a " + name + " character, which Excel honors at cell start",
		}, true
	case '=':
		base.Kind, base.Severity = KindFormula, Medium
		base.Reason = `cell starts with "="` + bypass + " — the application evaluates it as a formula"
	case '+', '-':
		if !opts.Paranoid && len(pad) == 0 &&
			(signedNumberRe.MatchString(cell) || phoneRe.MatchString(cell)) {
			// A plain signed number or phone number: data, not a formula
			// worth flagging. --paranoid overrides.
			return Finding{}, false
		}
		base.Kind, base.Severity = KindArithmetic, Low
		base.Reason = fmt.Sprintf("cell starts with %q%s — Excel-family applications evaluate it as an expression", string(first), bypass)
	case '@':
		if !opts.Paranoid && !atCallRe.MatchString(rest) {
			// A bare @handle (no function-call shape) is inert; flagging
			// every social-media column would drown real findings.
			return Finding{}, false
		}
		base.Kind, base.Severity = KindAtSign, Low
		base.Reason = `cell starts with "@"` + bypass + " — Excel evaluates legacy Lotus @-functions"
	}

	// Escalations: a triggered cell whose body reaches DDE or a
	// network-capable function is far worse than a plain formula.
	if p.ddeCapable() {
		if m := ddePipeRe.FindStringSubmatch(rest); m != nil {
			prog := strings.TrimSpace(m[1])
			return Finding{
				Kind: KindDDE, Severity: High, AtStart: true,
				Reason: fmt.Sprintf("DDE payload piping to %q — opening the file can execute a local program", prog),
			}, true
		}
		if ddeFuncRe.MatchString(rest) {
			return Finding{
				Kind: KindDDE, Severity: High, AtStart: true,
				Reason: "calls the DDE() function — LibreOffice can pull attacker-chosen external content",
			}, true
		}
	}
	if m := exfilRes[p].FindStringSubmatch(rest); m != nil {
		fn := strings.ToUpper(m[1])
		return Finding{
			Kind: KindExfil, Severity: High, AtStart: true,
			Reason: fmt.Sprintf("calls %s() — can send sheet data to an attacker-controlled host", fn),
		}, true
	}
	return base, true
}

// scanEmbedded flags multi-line cells where a later line starts with a
// trigger character. The cell is safe as-is, but a downstream tool that
// splits on newlines without re-quoting turns that line into a fresh,
// live cell — a bypass seen repeatedly in bug-bounty reports.
func scanEmbedded(cell string, p Profile, opts Options) (Finding, bool) {
	if !strings.ContainsAny(cell, "\r\n") {
		return Finding{}, false
	}
	trig := p.triggers()
	normalized := strings.NewReplacer("\r\n", "\n", "\r", "\n").Replace(cell)
	for i, line := range strings.Split(normalized, "\n") {
		if i == 0 {
			continue // The first line is covered by scanStart.
		}
		trimmed := strings.TrimLeftFunc(line, isPadding)
		r, _ := utf8.DecodeRuneInString(trimmed)
		if trimmed == "" || !trig[r] {
			continue
		}
		if (r == '+' || r == '-') && !opts.Paranoid &&
			(signedNumberRe.MatchString(trimmed) || phoneRe.MatchString(trimmed)) {
			continue
		}
		if r == '@' && !opts.Paranoid && !atCallRe.MatchString(trimmed) {
			continue
		}
		return Finding{
			Kind: KindEmbedded, Severity: Low, AtStart: false,
			Reason: fmt.Sprintf("line %d inside this multi-line cell starts with %q — live if re-exported without quoting", i+1, string(r)),
		}, true
	}
	return Finding{}, false
}

// Preview truncates a cell value for display: control characters are made
// visible and long values are cut at maxRunes with an ellipsis.
func Preview(cell string, maxRunes int) string {
	repl := strings.NewReplacer("\t", `\t`, "\r", `\r`, "\n", `\n`)
	s := repl.Replace(cell)
	if utf8.RuneCountInString(s) <= maxRunes {
		return s
	}
	runes := []rune(s)
	return string(runes[:maxRunes]) + "…"
}
