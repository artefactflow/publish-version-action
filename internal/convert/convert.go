package convert

import (
	"fmt"

	"github.com/artefactflow/publish-version-action/internal/afclient"
)

// Result is a converted report: the findings, any notes worth surfacing to the step log (truncations, a scan that cleared the set), and whether the scan was an affirmatively empty one.
type Result struct {
	Findings []afclient.Vulnerability
	Notes    []string
	// Cleared is true when a well-formed scan reported no vulnerabilities at all. It is the one way a conversion legitimately yields an empty set — the scanner affirmatively found nothing — as opposed to a mapping that silently produced zero.
	Cleared bool
}

// converted is what a per-format converter returns before merging: the flat per-component findings, and the count of raw vulnerability entries the report listed. The raw count is what tells an affirmatively empty scan (nothing to convert) apart from a conversion that lost everything (entries present, findings none) — a distinction the full-replace endpoint makes load-bearing.
type converted struct {
	findings []afclient.Vulnerability
	rawCount int
	notes    []string
}

// Convert turns a scanner report of the given format into ArtefactFlow findings. The native format is not handled here — it is forwarded verbatim by the caller to preserve its exact bytes.
//
// A report whose entries all fail to map — raw findings present but none converted — is an error rather than an empty upload, because on a full-replace endpoint an empty upload deletes the version's recorded set. A scan that genuinely found nothing (no raw entries) converts to an empty set and is reported as a clear.
func Convert(format Format, data []byte) (Result, error) {
	var (
		c   converted
		err error
	)
	switch format {
	case FormatTrivy:
		c, err = convertTrivy(data)
	case FormatGrype:
		c, err = convertGrype(data)
	case FormatCycloneDX:
		c, err = convertCycloneDX(data)
	case FormatNative:
		return Result{}, fmt.Errorf("native reports are forwarded without conversion; Convert should not be called for them")
	default:
		return Result{}, fmt.Errorf("unsupported format %q", format)
	}
	if err != nil {
		return Result{}, err
	}

	merged := mergeByIdentifier(c.findings)

	if c.rawCount > 0 && len(merged) == 0 {
		return Result{}, fmt.Errorf("the report listed %d vulnerability result(s) but none could be converted to a finding; refusing to upload an empty set, which would clear the version's recorded vulnerabilities. Check the report is a complete %s document", c.rawCount, format)
	}

	res := Result{Findings: merged, Notes: c.notes, Cleared: c.rawCount == 0}
	if res.Cleared {
		res.Notes = append(res.Notes, fmt.Sprintf("the %s report contains no vulnerabilities; the upload will clear any findings previously recorded for this version", format))
	}
	return res, nil
}
