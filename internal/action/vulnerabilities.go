package action

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/artefactflow/publish-version-action/internal/afclient"
	"github.com/artefactflow/publish-version-action/internal/convert"
)

// PreparedVulnerabilities is the outcome of turning a scan report — native or a scanner's — into the wire body, ready to upload.
type PreparedVulnerabilities struct {
	// Body is the complete set to send to the full-replace endpoint.
	Body afclient.VulnerabilitiesInput
	// Format is what the report was detected or declared to be.
	Format convert.Format
	// Notes are step-log lines the conversion produced (truncations, a clearing scan).
	Notes []string
	// UnmatchedVEX names VEX assessments that matched no finding in the scan, surfaced as a warning.
	UnmatchedVEX []string
}

// LoadAndConvert reads a scan report, detects or honours its format, converts it to the ArtefactFlow shape unless it already is native, and — when a VEX file is supplied — overlays its assessments onto the findings.
//
// A native report is forwarded as the exact bytes it was read from, preserving values Go would treat as empty (a 0.0 score among them); only a scanner report is converted, because its findings are built from typed models and re-encoded. Overlaying a VEX file onto a native report is refused: a native report already carries `analysis` inline, so there is a single, unambiguous place to put an assessment rather than two that could disagree.
//
// Everything here runs before the version is created, so a report that cannot be fully converted fails without leaving a published version missing its vulnerabilities.
func LoadAndConvert(scanPath, formatOverride, vexPath string) (PreparedVulnerabilities, error) {
	raw, err := os.ReadFile(scanPath)
	if err != nil {
		return PreparedVulnerabilities{}, fmt.Errorf("read vulnerabilities file: %w", err)
	}
	if strings.TrimSpace(string(raw)) == "" {
		return PreparedVulnerabilities{}, fmt.Errorf("vulnerabilities file %s is empty. To record a clean scan, write {\"vulnerabilities\": []}", scanPath)
	}

	format, err := convert.Detect(raw, formatOverride)
	if err != nil {
		return PreparedVulnerabilities{}, fmt.Errorf("vulnerabilities file %s: %w", scanPath, err)
	}

	if format == convert.FormatNative {
		if vexPath != "" {
			return PreparedVulnerabilities{}, fmt.Errorf("a VEX file cannot be overlaid onto a native report: a native report already carries `analysis` inline, so put your assessments there, or supply the scan as a Trivy, Grype, or CycloneDX report")
		}
		body, err := LoadVulnerabilities(scanPath)
		if err != nil {
			return PreparedVulnerabilities{}, err
		}
		return PreparedVulnerabilities{Body: body, Format: format}, nil
	}

	result, err := convert.Convert(format, raw)
	if err != nil {
		return PreparedVulnerabilities{}, fmt.Errorf("convert %s report %s: %w", format, scanPath, err)
	}

	prepared := PreparedVulnerabilities{Format: format, Notes: result.Notes}

	if vexPath != "" {
		entries, err := loadVEX(vexPath)
		if err != nil {
			return PreparedVulnerabilities{}, err
		}
		_, unmatched := convert.Overlay(result.Findings, entries)
		prepared.UnmatchedVEX = unmatched
	}

	body, err := convert.Encode(result.Findings)
	if err != nil {
		return PreparedVulnerabilities{}, fmt.Errorf("encode converted findings from %s: %w", scanPath, err)
	}
	if len(body.Vulnerabilities) > afclient.MaxVulnerabilities {
		return PreparedVulnerabilities{}, fmt.Errorf("converted report holds %d findings; the API accepts at most %d in one upload", len(body.Vulnerabilities), afclient.MaxVulnerabilities)
	}
	// Re-validate each converted entry against the schema the API enforces, strictly, so a converter bug is caught here rather than as a rejected request after the version exists.
	for i, entry := range body.Vulnerabilities {
		if err := validateEntry(entry); err != nil {
			return PreparedVulnerabilities{}, fmt.Errorf("converted finding %d failed validation: %w", i, err)
		}
	}
	prepared.Body = body
	return prepared, nil
}

// LoadVEXForApply reads a CycloneDX VEX document for the standalone path and checks every entry can be applied — the PATCH endpoint requires a state, so a VEX entry carrying only a justification is rejected here rather than part-way through applying the rest.
func LoadVEXForApply(vexPath string) ([]convert.VEXEntry, error) {
	entries, err := loadVEX(vexPath)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("VEX file %s records no assessments; there is nothing to apply", vexPath)
	}
	for _, e := range entries {
		if _, err := e.AnalysisInput(); err != nil {
			return nil, err
		}
	}
	return entries, nil
}

// WriteConvertedOutput writes the wire body as indented JSON, so a workflow that asked for it can inspect or archive exactly what was uploaded. It is a no-op when path is empty.
func WriteConvertedOutput(path string, body afclient.VulnerabilitiesInput) error {
	if path == "" {
		return nil
	}
	if body.Vulnerabilities == nil {
		body.Vulnerabilities = []json.RawMessage{}
	}
	out, err := json.MarshalIndent(body, "", "  ")
	if err != nil {
		return fmt.Errorf("render converted vulnerabilities: %w", err)
	}
	// World-readable on purpose: the action runs as root in its container, and a later step running as the runner user has to be able to read this — to archive it, say. A vulnerability report is not a secret; it is the same data being uploaded.
	if err := os.WriteFile(path, append(out, '\n'), 0o644); err != nil {
		return fmt.Errorf("write converted vulnerabilities to %s: %w", path, err)
	}
	return nil
}

// loadVEX reads and parses a CycloneDX VEX file into assessments.
func loadVEX(vexPath string) ([]convert.VEXEntry, error) {
	raw, err := os.ReadFile(vexPath)
	if err != nil {
		return nil, fmt.Errorf("read vex file: %w", err)
	}
	entries, err := convert.ParseVEX(raw)
	if err != nil {
		return nil, fmt.Errorf("vex file %s: %w", vexPath, err)
	}
	return entries, nil
}

// document is the wrapped form of a report. The slice is a pointer so that a missing `vulnerabilities` key is distinguishable from one that is present and empty — the difference between "this file forgot to say anything" and "this scan found nothing", which on a full-replace endpoint is the difference between a mistake and an instruction.
type document struct {
	Vulnerabilities *[]json.RawMessage `json:"vulnerabilities"`
}

// LoadVulnerabilities reads and validates the scanner report, returning the findings exactly as they were written.
//
// Each entry is validated against the API's schema with unknown fields rejected, so a misspelled key fails here rather than being quietly discarded — which matters because the upload replaces the version's entire recorded set. The entries are then forwarded as the raw JSON that was read, not re-encoded from the parsed structs: re-encoding would silently drop any value the Go model treats as empty, and a CVSS score of 0.0 is a real score.
//
// A bare array of findings is accepted as well as the `{"vulnerabilities": [...]}` wrapper, because it is the obvious thing to write by hand and rejecting it would be gratuitous.
func LoadVulnerabilities(path string) (afclient.VulnerabilitiesInput, error) {
	var none afclient.VulnerabilitiesInput

	raw, err := os.ReadFile(path)
	if err != nil {
		return none, fmt.Errorf("read vulnerabilities file: %w", err)
	}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return none, fmt.Errorf("vulnerabilities file %s is empty. To record a clean scan, write {\"vulnerabilities\": []}", path)
	}

	entries, err := readEntries(trimmed)
	if err != nil {
		return none, fmt.Errorf("parse vulnerabilities file %s: %w", path, err)
	}

	if len(entries) > afclient.MaxVulnerabilities {
		return none, fmt.Errorf("vulnerabilities file %s holds %d findings; the API accepts at most %d in one upload", path, len(entries), afclient.MaxVulnerabilities)
	}

	for i, entry := range entries {
		if err := validateEntry(entry); err != nil {
			return none, fmt.Errorf("vulnerabilities file %s: entry %d: %w", path, i, err)
		}
	}
	return afclient.VulnerabilitiesInput{Vulnerabilities: entries}, nil
}

// readEntries pulls the findings out of either accepted shape, insisting that the wrapped form actually carries the key.
func readEntries(doc string) ([]json.RawMessage, error) {
	if strings.HasPrefix(doc, "[") {
		var entries []json.RawMessage
		if err := decodeStrict(doc, &entries); err != nil {
			return nil, err
		}
		return entries, nil
	}

	var wrapped document
	if err := decodeStrict(doc, &wrapped); err != nil {
		return nil, err
	}
	if wrapped.Vulnerabilities == nil {
		// Treating this as an empty set would delete every finding already recorded for the version, on the strength of a file that never mentioned them.
		return nil, errors.New("no `vulnerabilities` key. The upload replaces the version's whole recorded set, so an absent list is refused rather than treated as an instruction to delete everything; write {\"vulnerabilities\": []} if a clean scan is what you mean")
	}
	return *wrapped.Vulnerabilities, nil
}

// validateEntry checks one finding against the schema the API enforces, so a report that cannot be accepted fails before anything has been published.
func validateEntry(entry json.RawMessage) error {
	var v afclient.Vulnerability
	if err := decodeStrict(string(entry), &v); err != nil {
		return err
	}
	if strings.TrimSpace(v.ID) == "" {
		return errors.New("no `id`")
	}
	// The API requires a source with a name; without this check the whole report is rejected only after the version has been created.
	if v.Source == nil || strings.TrimSpace(v.Source.Name) == "" {
		return fmt.Errorf("finding %s has no `source.name`, which the API requires", v.ID)
	}
	return nil
}

// decodeStrict decodes exactly one JSON document, rejecting both unknown fields and anything following the document.
func decodeStrict(s string, dst any) error {
	dec := json.NewDecoder(strings.NewReader(s))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	// Trailing content means the file holds more than it appears to; reading only the first half of it silently would be worse than failing.
	if err := dec.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		return fmt.Errorf("unexpected trailing content after the JSON document")
	}
	return nil
}
