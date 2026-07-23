package convert

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/artefactflow/publish-version-action/internal/afclient"
)

// VEXEntry is one assessment read from a CycloneDX VEX document, keyed by the vulnerability identifier it applies to.
type VEXEntry struct {
	ID       string
	Analysis afclient.Analysis
}

// ParseVEX reads a CycloneDX VEX document into assessments, keyed and ordered by identifier. It validates each state, justification, and response against the values the API accepts, failing with the offending identifier named — a VEX document is a triage decision, and a silently dropped or guessed value would suppress a real finding or record a wrong one.
//
// A VEX document is a scan overlay, not a scan: it typically carries analysis and no ratings, which is why it is a separate input rather than a third detected format. Treating it as a scan would produce findings with no severity.
func ParseVEX(data []byte) ([]VEXEntry, error) {
	var doc cdxDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse VEX document: %w", err)
	}
	if !strings.EqualFold(strings.TrimSpace(doc.BOMFormat), "CycloneDX") {
		return nil, fmt.Errorf("the VEX file is not a CycloneDX document (bomFormat is %q); the action reads VEX in CycloneDX form", doc.BOMFormat)
	}

	var (
		entries []VEXEntry
		notes   []string // truncation notes on detail are folded into the returned entries; a VEX-only run surfaces them separately
	)
	seen := make(map[string]bool, len(doc.Vulnerabilities))
	for i, cv := range doc.Vulnerabilities {
		id := strings.TrimSpace(cv.ID)
		if id == "" {
			return nil, fmt.Errorf("VEX entry %d has no id", i)
		}
		if cv.Analysis == nil {
			return nil, fmt.Errorf("VEX entry %s carries no analysis; a VEX document exists to record assessments, so an entry without one is a malformed document", id)
		}
		if seen[id] {
			return nil, fmt.Errorf("VEX document assesses %s more than once; each finding must be assessed at most once", id)
		}
		seen[id] = true

		a, err := mapAnalysis(id, *cv.Analysis, &notes)
		if err != nil {
			return nil, err
		}
		entries = append(entries, VEXEntry{ID: id, Analysis: a})
	}
	return entries, nil
}

// Overlay attaches VEX assessments to converted findings by identifier, for the case where a VEX document accompanies a scan and the merged set is sent in one upload. It returns the identifiers that matched no finding, which the caller surfaces as a warning: a VEX entry with no finding usually means the scan and the VEX are from different builds.
func Overlay(findings []afclient.Vulnerability, entries []VEXEntry) (matched int, unmatched []string) {
	index := make(map[string]int, len(findings))
	for i, f := range findings {
		index[f.ID] = i
	}
	for _, e := range entries {
		i, ok := index[e.ID]
		if !ok {
			unmatched = append(unmatched, e.ID)
			continue
		}
		a := e.Analysis
		findings[i].Analysis = &a
		matched++
	}
	return matched, unmatched
}

// AnalysisInput turns a VEX entry into the body of the standalone PATCH …/analysis call. The API makes state required on that endpoint, so an entry carrying only a justification cannot be applied this way and is an error naming the identifier.
func (e VEXEntry) AnalysisInput() (afclient.VulnerabilityAnalysisInput, error) {
	if strings.TrimSpace(e.Analysis.State) == "" {
		return afclient.VulnerabilityAnalysisInput{}, fmt.Errorf("VEX entry %s has no state; applying VEX on its own updates a finding's state, which the API requires, so a justification alone cannot be applied", e.ID)
	}
	return afclient.VulnerabilityAnalysisInput{
		State:         e.Analysis.State,
		Justification: e.Analysis.Justification,
		Response:      e.Analysis.Response,
		Detail:        e.Analysis.Detail,
	}, nil
}
