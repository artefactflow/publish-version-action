package convert

import (
	"strings"
	"testing"

	"github.com/artefactflow/publish-version-action/internal/afclient"
)

func TestParseVEXMapsAndValidates(t *testing.T) {
	entries, err := ParseVEX(fixture(t, "vex.input.json"))
	if err != nil {
		t.Fatalf("ParseVEX: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	// resolved_with_pedigree has no API equivalent and folds to resolved.
	if entries[1].ID != "CVE-2024-00001" || entries[1].Analysis.State != "resolved" {
		t.Errorf("entry = %+v, want resolved_with_pedigree folded to resolved", entries[1])
	}
	if entries[0].Analysis.State != "not_affected" || entries[0].Analysis.Justification != "code_not_reachable" {
		t.Errorf("entry = %+v", entries[0].Analysis)
	}
}

// A justification the API does not accept is an error naming the finding, not a silent drop — the CycloneDX values protected_at_runtime and protected_at_perimeter have no API equivalent.
func TestParseVEXRejectsUnmappableJustification(t *testing.T) {
	doc := `{"bomFormat":"CycloneDX","vulnerabilities":[{"id":"CVE-1","analysis":{"state":"not_affected","justification":"protected_at_runtime"}}]}`
	_, err := ParseVEX([]byte(doc))
	if err == nil || !strings.Contains(err.Error(), "CVE-1") || !strings.Contains(err.Error(), "justification") {
		t.Fatalf("error = %v, want it to name the finding and the bad justification", err)
	}
}

func TestParseVEXRejectsUnmappableState(t *testing.T) {
	doc := `{"bomFormat":"CycloneDX","vulnerabilities":[{"id":"CVE-1","analysis":{"state":"probably_fine"}}]}`
	_, err := ParseVEX([]byte(doc))
	if err == nil || !strings.Contains(err.Error(), "state") {
		t.Fatalf("error = %v, want it to reject the unmappable state", err)
	}
}

func TestParseVEXRequiresCycloneDX(t *testing.T) {
	doc := `{"vulnerabilities":[{"id":"CVE-1","analysis":{"state":"not_affected"}}]}`
	_, err := ParseVEX([]byte(doc))
	if err == nil || !strings.Contains(err.Error(), "CycloneDX") {
		t.Fatalf("error = %v, want it to require a CycloneDX document", err)
	}
}

func TestParseVEXRejectsEntryWithoutAnalysis(t *testing.T) {
	doc := `{"bomFormat":"CycloneDX","vulnerabilities":[{"id":"CVE-1"}]}`
	_, err := ParseVEX([]byte(doc))
	if err == nil || !strings.Contains(err.Error(), "no analysis") {
		t.Fatalf("error = %v, want it to reject an entry with no analysis", err)
	}
}

func TestParseVEXRejectsDuplicateIdentifier(t *testing.T) {
	doc := `{"bomFormat":"CycloneDX","vulnerabilities":[{"id":"CVE-1","analysis":{"state":"exploitable"}},{"id":"CVE-1","analysis":{"state":"resolved"}}]}`
	_, err := ParseVEX([]byte(doc))
	if err == nil || !strings.Contains(err.Error(), "more than once") {
		t.Fatalf("error = %v, want it to reject a duplicate assessment", err)
	}
}

// A VEX entry matching no finding is reported, not silently dropped: it usually means the scan and the VEX are from different builds.
func TestOverlayReportsUnmatched(t *testing.T) {
	findings := []afclient.Vulnerability{{ID: "CVE-2023-44487", Source: &afclient.Source{Name: "NVD"}}}
	entries := []VEXEntry{
		{ID: "CVE-2023-44487", Analysis: afclient.Analysis{State: "not_affected"}},
		{ID: "CVE-9999-0000", Analysis: afclient.Analysis{State: "exploitable"}},
	}
	matched, unmatched := Overlay(findings, entries)
	if matched != 1 || len(unmatched) != 1 || unmatched[0] != "CVE-9999-0000" {
		t.Fatalf("matched=%d unmatched=%v", matched, unmatched)
	}
	if findings[0].Analysis == nil || findings[0].Analysis.State != "not_affected" {
		t.Errorf("analysis was not attached to the matched finding: %+v", findings[0].Analysis)
	}
}

// The standalone PATCH endpoint requires a state, so a VEX entry carrying only a justification cannot be applied that way and is an error.
func TestAnalysisInputRequiresState(t *testing.T) {
	_, err := VEXEntry{ID: "CVE-1", Analysis: afclient.Analysis{Justification: "code_not_reachable"}}.AnalysisInput()
	if err == nil || !strings.Contains(err.Error(), "no state") {
		t.Fatalf("error = %v, want it to require a state", err)
	}
	in, err := VEXEntry{ID: "CVE-1", Analysis: afclient.Analysis{State: "not_affected", Justification: "code_not_reachable"}}.AnalysisInput()
	if err != nil {
		t.Fatalf("AnalysisInput: %v", err)
	}
	if in.State != "not_affected" || in.Justification != "code_not_reachable" {
		t.Errorf("input = %+v", in)
	}
}
