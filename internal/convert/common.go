// Package convert turns the JSON a vulnerability scanner emits — Trivy, Grype, or a CycloneDX document — into the ArtefactFlow vulnerabilities shape, so a pipeline records what it found without hand-writing a conversion step.
//
// Every converter runs client-side, before the version is created, and is confident-or-fail: a report it cannot fully map is an error naming the offending entry, never a partial upload. This matters because the upload endpoint is a full replace — a conversion that quietly dropped half a report would delete findings, not merely fail to add them.
//
// Scanner reports are decoded leniently: they carry far more than this action reads, and rejecting an unknown field would break on the next scanner release. The strict, unknown-field-rejecting decode is reserved for the native format and for the output these converters produce, both of which have to match the API's schema exactly.
package convert

import (
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/artefactflow/publish-version-action/internal/afclient"
)

// f64 returns a pointer to v. Ratings carry their score as a pointer so a genuine 0.0 — the score of an informational finding — survives being marshalled rather than being dropped by omitempty.
func f64(v float64) *float64 { return &v }

// severitySynonyms maps a scanner's severity vocabulary onto the API's where the correspondence is unambiguous. "negligible" is Grype's lowest bucket and maps to the API's lowest graded severity; it is a documented convention, not a guess. Anything not here and not already an API value becomes "unknown".
var severitySynonyms = map[string]string{
	"negligible": "low",
	"moderate":   "medium",
	"important":  "high",
}

// mapSeverity normalises a scanner severity to one the API accepts. An unrecognised value becomes "unknown" rather than a guessed level — a wrong severity is worse than an honest "we could not tell".
func mapSeverity(s string) string {
	v := strings.ToLower(strings.TrimSpace(s))
	if v == "" {
		return "unknown"
	}
	for _, known := range afclient.Severities {
		if v == known {
			return v
		}
	}
	if mapped, ok := severitySynonyms[v]; ok {
		return mapped
	}
	return "unknown"
}

// methodFromVector derives the API's scoring-method token from a CVSS vector's version prefix. A V3Score alone does not say whether it is 3.0 or 3.1 — only the vector does — so where there is no recognised prefix the method is omitted rather than guessed.
func methodFromVector(vector string) string {
	v := strings.TrimSpace(vector)
	switch {
	case strings.HasPrefix(v, "CVSS:4.0"):
		return "CVSSv4"
	case strings.HasPrefix(v, "CVSS:3.1"):
		return "CVSSv31"
	case strings.HasPrefix(v, "CVSS:3.0"):
		return "CVSSv3"
	case strings.HasPrefix(v, "CVSS:2.0"):
		return "CVSSv2"
	case strings.HasPrefix(v, "AV:"):
		// A CVSS v2 vector carries no `CVSS:` version prefix — it begins straight with the AccessVector metric.
		return "CVSSv2"
	}
	return ""
}

// methodFromCVSSVersion derives the scoring method from a bare version string such as Grype's "3.1". It falls back to the vector when the version is missing or unrecognised.
func methodFromCVSSVersion(version, vector string) string {
	switch strings.TrimSpace(version) {
	case "4", "4.0":
		return "CVSSv4"
	case "3.1":
		return "CVSSv31"
	case "3", "3.0":
		return "CVSSv3"
	case "2", "2.0":
		return "CVSSv2"
	}
	return methodFromVector(vector)
}

// parseCWEs turns the string CWE identifiers a report carries ("CWE-400") into the bare integers the API wants (400). An entry that is not a numeric CWE is dropped rather than failing the whole report — a malformed CWE is not worth losing a finding over.
func parseCWEs(ids []string) []int {
	var out []int
	for _, raw := range ids {
		s := strings.TrimSpace(raw)
		s = strings.TrimPrefix(strings.ToUpper(s), "CWE-")
		n, err := strconv.Atoi(s)
		if err != nil || n < 0 {
			continue
		}
		out = append(out, n)
	}
	return out
}

// deriveSource settles on the source the API requires, which must have a non-empty name. An explicit source from the report wins; otherwise the name is derived deterministically from the identifier's prefix, falling back to the scanner's own name. It never returns an empty name.
func deriveSource(id, explicitName, url, scannerName string) *afclient.Source {
	name := strings.TrimSpace(explicitName)
	if name == "" {
		name = sourceFromIdentifier(id)
	}
	if name == "" {
		name = scannerName
	}
	name = clip(name, afclient.MaxSourceNameLen)
	src := &afclient.Source{Name: name}
	// A URL over the API's limit is dropped rather than truncated: half a URL is not a usable link, and the name alone still satisfies the schema.
	if u := strings.TrimSpace(url); u != "" && utf8.RuneCountInString(u) <= afclient.MaxSourceURLLen {
		src.URL = u
	}
	return src
}

// sourceFromIdentifier maps a vulnerability identifier's prefix to the advisory database that issues it. An unrecognised prefix returns empty, leaving the caller to fall back to the scanner name.
func sourceFromIdentifier(id string) string {
	up := strings.ToUpper(strings.TrimSpace(id))
	switch {
	case strings.HasPrefix(up, "CVE-"):
		return "NVD"
	case strings.HasPrefix(up, "GHSA-"):
		return "GitHub Advisory Database"
	case strings.HasPrefix(up, "GO-"):
		return "Go Vulnerability Database"
	case strings.HasPrefix(up, "RUSTSEC-"):
		return "RustSec Advisory Database"
	case strings.HasPrefix(up, "OSV-"):
		return "OSV"
	case strings.HasPrefix(up, "DSA-"), strings.HasPrefix(up, "DLA-"):
		return "Debian Security Advisory"
	}
	return ""
}

// clip truncates s to at most max runes, never cutting mid-character. It reports nothing; callers that must note truncation to the user use clipNoting.
func clip(s string, max int) string {
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	return string([]rune(s)[:max])
}

// clipNoting is clip that records, via note, when it actually shortened the value, so a truncated description is visible in the step log rather than silent.
func clipNoting(notes *[]string, id, field, s string, max int) string {
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	*notes = append(*notes, "finding "+id+": "+field+" truncated to "+strconv.Itoa(max)+" characters")
	return string([]rune(s)[:max])
}
