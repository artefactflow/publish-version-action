package convert

import (
	"encoding/json"
	"strings"
	"testing"
)

// distinctIDs counts the unique identifiers a raw report describes, the lower bound on how many findings a faithful conversion must produce.
func distinctIDs(t *testing.T, raw []byte, path func(map[string]any) []string) int {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, id := range path(doc) {
		seen[id] = true
	}
	return len(seen)
}

// No mapping path may produce a smaller set than the input describes: one finding per identifier, none dropped. This is the guarantee that makes conversion safe on a full-replace endpoint.
func TestConversionNeverShrinksBelowDistinctIdentifiers(t *testing.T) {
	trivyIDs := distinctIDs(t, fixture(t, "trivy.input.json"), func(doc map[string]any) []string {
		var ids []string
		for _, r := range doc["Results"].([]any) {
			rm := r.(map[string]any)
			vulns, ok := rm["Vulnerabilities"].([]any)
			if !ok {
				continue
			}
			for _, v := range vulns {
				ids = append(ids, v.(map[string]any)["VulnerabilityID"].(string))
			}
		}
		return ids
	})
	res, err := Convert(FormatTrivy, fixture(t, "trivy.input.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != trivyIDs {
		t.Errorf("Trivy produced %d findings for %d distinct identifiers", len(res.Findings), trivyIDs)
	}

	grypeIDs := distinctIDs(t, fixture(t, "grype.input.json"), func(doc map[string]any) []string {
		var ids []string
		for _, m := range doc["matches"].([]any) {
			v := m.(map[string]any)["vulnerability"].(map[string]any)
			ids = append(ids, v["id"].(string))
		}
		return ids
	})
	gres, err := Convert(FormatGrype, fixture(t, "grype.input.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(gres.Findings) != grypeIDs {
		t.Errorf("Grype produced %d findings for %d distinct identifiers", len(gres.Findings), grypeIDs)
	}
}

// A well-formed scan that found nothing converts to an empty set and is reported as a clear, the one legitimate way a conversion yields no findings.
func TestEmptyScanIsAClear(t *testing.T) {
	res, err := Convert(FormatTrivy, fixture(t, "trivy-empty.input.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Cleared || len(res.Findings) != 0 {
		t.Errorf("empty scan: cleared=%v, %d findings", res.Cleared, len(res.Findings))
	}
}

// A report whose entries are present but none convert would upload an empty set and delete the version's findings; that must be an error, not a silent clear.
func TestAllUnmappableEntriesIsAnError(t *testing.T) {
	// Two Grype matches, both without an id: raw entries present, findings none.
	report := `{"descriptor":{"name":"grype"},"matches":[{"vulnerability":{"severity":"High"}},{"vulnerability":{"severity":"Low"}}]}`
	_, err := Convert(FormatGrype, []byte(report))
	if err == nil {
		t.Fatal("Convert accepted a report whose entries all failed to map")
	}
	if !strings.Contains(err.Error(), "no vulnerability.id") {
		t.Errorf("error = %v, want it to name the offending entry", err)
	}
}

// A Trivy finding can carry a severity but name no SeveritySource, and can score by a vendor that is not the severity's. The mapped severity must still reach a rating rather than being dropped between the two.
func TestTrivySeverityReachesARatingWithoutSeveritySource(t *testing.T) {
	report := `{
		"SchemaVersion": 2,
		"Results": [{
			"Target": "image",
			"Vulnerabilities": [{
				"VulnerabilityID": "CVE-1",
				"PkgName": "libx",
				"Severity": "CRITICAL",
				"CVSS": {"nvd": {"V3Vector": "CVSS:3.1/AV:N/AC:L", "V3Score": 9.8}}
			}]
		}]
	}`
	res, err := Convert(FormatTrivy, []byte(report))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || len(res.Findings[0].Ratings) != 1 {
		t.Fatalf("findings = %+v", res.Findings)
	}
	if got := res.Findings[0].Ratings[0].Severity; got != "critical" {
		t.Errorf("rating severity = %q, want critical carried onto the rating", got)
	}
}

func TestSeverityMapping(t *testing.T) {
	cases := map[string]string{
		"CRITICAL": "critical", "High": "high", "medium": "medium",
		"Negligible": "low", "moderate": "medium", "important": "high",
		"": "unknown", "bogus": "unknown",
	}
	for in, want := range cases {
		if got := mapSeverity(in); got != want {
			t.Errorf("mapSeverity(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMethodFromVector(t *testing.T) {
	cases := map[string]string{
		"CVSS:3.1/AV:N/AC:L": "CVSSv31",
		"CVSS:3.0/AV:N":      "CVSSv3",
		"CVSS:2.0/AV:N":      "CVSSv2",
		"AV:N/AC:L/Au:N":     "CVSSv2",
		"CVSS:4.0/AV:N":      "CVSSv4",
		"":                   "",
		"nonsense":           "",
	}
	for in, want := range cases {
		if got := methodFromVector(in); got != want {
			t.Errorf("methodFromVector(%q) = %q, want %q", in, got, want)
		}
	}
}

// Reports carry "CWE-400"; the API wants 400, and a non-numeric entry is dropped rather than failing the report.
func TestParseCWEs(t *testing.T) {
	got := parseCWEs([]string{"CWE-400", "cwe-79", "NVD-CWE-Other", "CWE-", "123"})
	want := []int{400, 79, 123}
	if len(got) != len(want) {
		t.Fatalf("parseCWEs = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("parseCWEs[%d] = %d, want %d", i, got[i], want[i])
		}
	}
}

// A converter builds ratings and marshals them, so a genuine 0.0 score — an informational finding — must survive rather than being dropped by omitempty.
func TestZeroScoreSurvivesEncoding(t *testing.T) {
	report := `{
		"descriptor": {"name": "grype"},
		"matches": [
			{
				"vulnerability": {
					"id": "CVE-1",
					"severity": "None",
					"cvss": [{"source": "nvd", "version": "3.1", "vector": "CVSS:3.1/AV:N/AC:H", "metrics": {"baseScore": 0.0}}]
				},
				"artifact": {"purl": "pkg:generic/x@1"}
			}
		]
	}`
	res, err := Convert(FormatGrype, []byte(report))
	if err != nil {
		t.Fatal(err)
	}
	body, err := Encode(res.Findings)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body.Vulnerabilities[0]), `"score":0`) {
		t.Errorf("encoded finding lost its 0.0 score: %s", body.Vulnerabilities[0])
	}
}
