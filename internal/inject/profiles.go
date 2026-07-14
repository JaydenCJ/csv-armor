package inject

import (
	"fmt"
	"sort"
	"strings"
)

// Profile selects which spreadsheet application's parsing rules the scanner
// assumes. Different applications treat different leading characters as
// formula triggers and ship different network-capable functions, so the
// right trigger set depends on where the CSV will be opened.
type Profile string

const (
	// ProfileExcel models Microsoft Excel: the full OWASP trigger set
	// (= + - @ TAB CR), legacy DDE via the pipe syntax, and the
	// WEBSERVICE/FILTERXML/RTD network functions.
	ProfileExcel Profile = "excel"
	// ProfileSheets models Google Sheets: = + - triggers plus the IMPORT*
	// family, IMAGE and HYPERLINK, which fetch attacker URLs on open.
	ProfileSheets Profile = "sheets"
	// ProfileLibre models LibreOffice Calc: = + - triggers, the DDE()
	// function, and WEBSERVICE/HYPERLINK.
	ProfileLibre Profile = "libreoffice"
	// ProfileAll is the union of every application's rules — the right
	// default when you do not control which program opens the export.
	ProfileAll Profile = "all"
)

// Profiles lists every accepted profile name, in documentation order.
var Profiles = []Profile{ProfileAll, ProfileExcel, ProfileSheets, ProfileLibre}

// ParseProfile validates a user-supplied profile name.
func ParseProfile(s string) (Profile, error) {
	switch Profile(strings.ToLower(s)) {
	case ProfileExcel:
		return ProfileExcel, nil
	case ProfileSheets:
		return ProfileSheets, nil
	case ProfileLibre:
		return ProfileLibre, nil
	case ProfileAll:
		return ProfileAll, nil
	}
	return "", fmt.Errorf("unknown profile %q (valid: all, excel, sheets, libreoffice)", s)
}

// triggers returns the set of cell-start runes the profile's application
// interprets as the beginning of a formula (or, for TAB/CR, characters the
// OWASP guidance requires escaping because Excel honors them at cell start).
func (p Profile) triggers() map[rune]bool {
	switch p {
	case ProfileExcel:
		return map[rune]bool{'=': true, '+': true, '-': true, '@': true, '\t': true, '\r': true}
	case ProfileSheets, ProfileLibre:
		return map[rune]bool{'=': true, '+': true, '-': true}
	default: // ProfileAll: union of the above.
		return map[rune]bool{'=': true, '+': true, '-': true, '@': true, '\t': true, '\r': true}
	}
}

// exfilFuncs returns the network-capable spreadsheet functions the profile's
// application ships. A formula calling any of these can leak the sheet's
// contents (or the fact that it was opened) to an attacker-controlled host.
func (p Profile) exfilFuncs() []string {
	switch p {
	case ProfileExcel:
		return []string{"WEBSERVICE", "FILTERXML", "RTD", "HYPERLINK"}
	case ProfileSheets:
		return []string{
			"IMPORTXML", "IMPORTHTML", "IMPORTRANGE", "IMPORTDATA",
			"IMPORTFEED", "IMAGE", "HYPERLINK",
		}
	case ProfileLibre:
		return []string{"WEBSERVICE", "HYPERLINK"}
	default: // ProfileAll: union, deduplicated.
		seen := map[string]bool{}
		var out []string
		for _, sub := range []Profile{ProfileExcel, ProfileSheets, ProfileLibre} {
			for _, f := range sub.exfilFuncs() {
				if !seen[f] {
					seen[f] = true
					out = append(out, f)
				}
			}
		}
		sort.Strings(out)
		return out
	}
}

// ddeCapable reports whether the profile's application supports any DDE
// mechanism (Excel's legacy pipe syntax, LibreOffice's DDE() function).
// Google Sheets has no DDE, so a matching payload is downgraded to its
// base kind there instead of being reported as remote code execution.
func (p Profile) ddeCapable() bool {
	return p == ProfileExcel || p == ProfileLibre || p == ProfileAll
}

// TriggerList returns the profile's trigger characters in stable display
// order, with TAB and CR spelled out for humans.
func (p Profile) TriggerList() []string {
	order := []rune{'=', '+', '-', '@', '\t', '\r'}
	names := map[rune]string{'\t': "TAB", '\r': "CR"}
	set := p.triggers()
	var out []string
	for _, r := range order {
		if set[r] {
			if n, ok := names[r]; ok {
				out = append(out, n)
			} else {
				out = append(out, string(r))
			}
		}
	}
	return out
}
