package action

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/artefactflow/publish-version-action/internal/afclient"
)

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
