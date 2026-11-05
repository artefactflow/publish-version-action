package action

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
)

// fileSize reports how large a file the action is about to send is, without reading it, so an oversized one can be refused before it is held in memory. A file that cannot be stat'ed fails with the same "read" wording readJSONFile uses, since to the workflow author it is the same mistake: a wrong path, or a scan step that never wrote its report.
func fileSize(what, path string) (int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, fmt.Errorf("read %s: %w", what, err)
	}
	return info.Size(), nil
}

// readJSONFile reads a report the action is about to send, checking only what needs no knowledge of its format: that the file exists, is not empty, and holds JSON. Those mistakes (a wrong path, a scan step that failed soft and wrote nothing, a file cut off mid-write) are knowable before anything is published, so they fail before the version is created. Everything else about the report is ArtefactFlow's to judge.
func readJSONFile(what, path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", what, err)
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, fmt.Errorf("%s %s is empty. To record a clean scan, pass the scanner's report of it, or write {\"vulnerabilities\": []}", what, path)
	}
	if !json.Valid(raw) {
		return nil, fmt.Errorf("%s %s is not a JSON document: the action reads JSON reports only", what, path)
	}
	return raw, nil
}

// WriteConvertedOutput writes a dry run's document as indented JSON, so a workflow that asked for it can inspect or archive the findings the report converts to. The import summary is left out: what remains is ArtefactFlow's own vulnerabilities format, which can be uploaded again as it stands.
func WriteConvertedOutput(path string, document json.RawMessage) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(document, &fields); err != nil {
		return fmt.Errorf("read the converted vulnerabilities: %w", err)
	}
	delete(fields, "import")
	// The values are kept as the raw JSON the API sent, so nothing is re-encoded: a score of 0.0 stays a score.
	out, err := json.MarshalIndent(fields, "", "  ")
	if err != nil {
		return fmt.Errorf("render converted vulnerabilities: %w", err)
	}
	// World-readable on purpose: the action runs as root in its container, and a later step running as the runner user has to be able to read this, to archive it, say. A vulnerability report is not a secret; it is the same data being recorded.
	if err := os.WriteFile(path, append(out, '\n'), 0o644); err != nil {
		return fmt.Errorf("write converted vulnerabilities to %s: %w", path, err)
	}
	return nil
}
