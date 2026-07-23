package convert

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Format identifies the shape of a report the action was handed.
type Format string

const (
	// FormatNative is the ArtefactFlow vulnerabilities shape itself, needing no conversion.
	FormatNative Format = "native"
	// FormatTrivy is a Trivy JSON report.
	FormatTrivy Format = "trivy"
	// FormatGrype is a Grype JSON report.
	FormatGrype Format = "grype"
	// FormatCycloneDX is a CycloneDX document carrying a vulnerabilities array.
	FormatCycloneDX Format = "cyclonedx"
)

// Formats lists every value the format override accepts, in a stable order for error messages.
var Formats = []Format{FormatNative, FormatTrivy, FormatGrype, FormatCycloneDX}

// discriminators are the positive markers each format is recognised by. Detection asserts a format is present rather than ruling the others out, so an unrecognised document fails rather than being mapped on a guess.
type discriminators struct {
	SchemaVersion   *json.RawMessage `json:"SchemaVersion"`
	Results         *json.RawMessage `json:"Results"`
	Matches         *json.RawMessage `json:"matches"`
	Descriptor      *descriptorName  `json:"descriptor"`
	BOMFormat       string           `json:"bomFormat"`
	Vulnerabilities *json.RawMessage `json:"vulnerabilities"`
}

type descriptorName struct {
	Name string `json:"name"`
}

// Detect determines a report's format. An override other than "auto" or "" forces a format, but the document must still match it — an override that does not fit is an error, never a silent fallback, so a mis-set flag cannot upload garbage. With no override, detection uses the positive discriminators and fails on a document it cannot confidently place.
func Detect(data []byte, override string) (Format, error) {
	ov := strings.ToLower(strings.TrimSpace(override))

	d, derr := probe(data)
	startsArray := startsWithArray(data)

	if ov != "" && ov != "auto" {
		f := Format(ov)
		if !isKnownFormat(f) {
			return "", fmt.Errorf("unknown `vulnerabilities-format` %q; use one of %s (or auto)", override, formatNames())
		}
		if derr != nil {
			return "", fmt.Errorf("`vulnerabilities-format` is %q but the report is not valid JSON: %w", override, derr)
		}
		if !matches(f, d, startsArray) {
			return "", fmt.Errorf("`vulnerabilities-format` is %q but the report does not look like a %s document; remove the override to let the format be detected, or supply the right report", override, f)
		}
		return f, nil
	}

	if derr != nil {
		return "", fmt.Errorf("could not read the report as JSON: %w", derr)
	}
	switch {
	case startsArray:
		// A bare array of findings is the native shape written by hand.
		return FormatNative, nil
	case d.SchemaVersion != nil && d.Results != nil:
		return FormatTrivy, nil
	case d.Matches != nil && d.Descriptor != nil && strings.EqualFold(strings.TrimSpace(d.Descriptor.Name), "grype"):
		return FormatGrype, nil
	case strings.EqualFold(strings.TrimSpace(d.BOMFormat), "CycloneDX"):
		return FormatCycloneDX, nil
	case d.Vulnerabilities != nil:
		return FormatNative, nil
	}
	return "", fmt.Errorf("could not recognise the report format. Detected no Trivy (SchemaVersion+Results), Grype (matches+descriptor.name), CycloneDX (bomFormat), or native (vulnerabilities) markers; set `vulnerabilities-format` to one of %s if this is a report the action supports", formatNames())
}

// matches reports whether a document carries the markers of the given format, used to reject an override that does not fit its report.
func matches(f Format, d discriminators, startsArray bool) bool {
	switch f {
	case FormatNative:
		return startsArray || d.Vulnerabilities != nil
	case FormatTrivy:
		return d.SchemaVersion != nil && d.Results != nil
	case FormatGrype:
		return d.Matches != nil
	case FormatCycloneDX:
		return strings.EqualFold(strings.TrimSpace(d.BOMFormat), "CycloneDX")
	}
	return false
}

func probe(data []byte) (discriminators, error) {
	var d discriminators
	if startsWithArray(data) {
		// A top-level array is native; it has no object keys to probe, and unmarshalling it into a struct would error.
		return d, nil
	}
	if err := json.Unmarshal(data, &d); err != nil {
		return d, err
	}
	return d, nil
}

func startsWithArray(data []byte) bool {
	return strings.HasPrefix(strings.TrimSpace(string(data)), "[")
}

func isKnownFormat(f Format) bool {
	for _, k := range Formats {
		if f == k {
			return true
		}
	}
	return false
}

func formatNames() string {
	names := make([]string, len(Formats))
	for i, f := range Formats {
		names[i] = string(f)
	}
	return strings.Join(names, ", ")
}
