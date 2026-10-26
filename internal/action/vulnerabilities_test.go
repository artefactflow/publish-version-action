package action

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/artefactflow/publish-version-action/internal/afclient"
)

// writeReport puts a report on disk and returns its path. Shared by every test in the package that needs one.
func writeReport(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vulns.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// wireBody renders what would actually be sent to the API, which is the only thing that matters for a full-replace endpoint.
func wireBody(t *testing.T, in afclient.VulnerabilitiesInput) string {
	t.Helper()
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(raw)
}

func TestLoadVulnerabilitiesWrappedObject(t *testing.T) {
	in, err := LoadVulnerabilities(writeReport(t, `{"vulnerabilities":[{"id":"CVE-2023-44487","source":{"name":"NVD"},"ratings":[{"score":7.5,"severity":"high","method":"CVSSv31"}],"cwes":[400],"analysis":{"state":"in_triage"}}]}`))
	if err != nil {
		t.Fatalf("LoadVulnerabilities: %v", err)
	}
	if len(in.Vulnerabilities) != 1 {
		t.Fatalf("got %+v", in.Vulnerabilities)
	}
	for _, want := range []string{`"id":"CVE-2023-44487"`, `"score":7.5`, `"state":"in_triage"`, `"cwes":[400]`} {
		if !strings.Contains(wireBody(t, in), want) {
			t.Errorf("wire body %s is missing %s", wireBody(t, in), want)
		}
	}
}

func TestLoadVulnerabilitiesBareArray(t *testing.T) {
	in, err := LoadVulnerabilities(writeReport(t, `[{"id":"CVE-2024-28180","source":{"name":"NVD"}}]`))
	if err != nil {
		t.Fatalf("LoadVulnerabilities: %v", err)
	}
	if len(in.Vulnerabilities) != 1 || !strings.Contains(wireBody(t, in), "CVE-2024-28180") {
		t.Fatalf("got %s", wireBody(t, in))
	}
}

// A clean scan is a real result, and the upload replaces the whole set, so an explicitly empty list is how a workflow clears stale findings.
func TestLoadVulnerabilitiesAllowsAnExplicitlyEmptyList(t *testing.T) {
	for _, content := range []string{`{"vulnerabilities":[]}`, `[]`} {
		in, err := LoadVulnerabilities(writeReport(t, content))
		if err != nil {
			t.Fatalf("LoadVulnerabilities(%s): %v", content, err)
		}
		if len(in.Vulnerabilities) != 0 {
			t.Fatalf("got %+v", in.Vulnerabilities)
		}
	}
}

// A file that never mentions `vulnerabilities` is a mistake, not an instruction to delete everything recorded. Because the endpoint is a full replace, treating the two alike would silently wipe a version's findings whenever a scan step wrote a placeholder.
func TestLoadVulnerabilitiesRefusesAnAbsentList(t *testing.T) {
	for _, content := range []string{`{}`, `{"vulnerabilities":null}`} {
		_, err := LoadVulnerabilities(writeReport(t, content))
		if err == nil {
			t.Fatalf("LoadVulnerabilities(%s) succeeded; it would have deleted every recorded finding", content)
		}
		if !strings.Contains(err.Error(), "no `vulnerabilities` key") {
			t.Errorf("error = %v, want it to name the missing key", err)
		}
	}
}

// The findings are forwarded as the bytes they were read from. Re-encoding them from the Go model would drop anything the model treats as empty, and a CVSS score of 0.0 is a real score for an informational finding.
func TestLoadVulnerabilitiesPreservesZeroValues(t *testing.T) {
	in, err := LoadVulnerabilities(writeReport(t, `{"vulnerabilities":[{"id":"CVE-1","source":{"name":"NVD"},"ratings":[{"score":0,"severity":"none"}]}]}`))
	if err != nil {
		t.Fatalf("LoadVulnerabilities: %v", err)
	}
	if got := wireBody(t, in); !strings.Contains(got, `"score":0`) {
		t.Errorf("wire body = %s, want the zero score preserved", got)
	}
}

// Every field the API accepts has to survive. A field modelled nowhere would be rejected by the strict decode, turning a valid report into a hard failure.
func TestLoadVulnerabilitiesAcceptsTheFullSchema(t *testing.T) {
	report := `{"vulnerabilities":[{
		"id":"CVE-1",
		"source":{"name":"NVD","url":"https://nvd.nist.gov/vuln/detail/CVE-1"},
		"ratings":[{"score":9.8,"severity":"critical","method":"CVSSv31","vector":"AV:N/AC:L"}],
		"cwes":[79,400],
		"description":"d",
		"recommendation":"r",
		"analysis":{"state":"not_affected","justification":"code_not_reachable","response":["will_not_fix"],"detail":"x"},
		"affects":[{"ref":"pkg:golang/example","versions":[{"version":"1.0.0","range":"vers:semver/>=1.0.0|<2.0.0","status":"affected"}]}],
		"published":"2024-01-01T00:00:00Z",
		"updated":"2024-02-01T00:00:00Z"
	}]}`
	in, err := LoadVulnerabilities(writeReport(t, report))
	if err != nil {
		t.Fatalf("a report using every documented field must be accepted: %v", err)
	}
	// The rarely-modelled fields are the ones most at risk of being dropped, so check they reach the wire.
	for _, want := range []string{`"affects"`, `"published"`, `"updated"`, `"vector"`, `"response"`} {
		if !strings.Contains(wireBody(t, in), want) {
			t.Errorf("wire body lost %s", want)
		}
	}
}

func TestLoadVulnerabilitiesRejectsBadReports(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string
	}{
		// Silently dropping half a report is far worse here than failing, because the upload replaces everything recorded for the version.
		{"misspelled field", `{"vulnerabilities":[{"id":"CVE-1","source":{"name":"NVD"},"serverity":"high"}]}`, "serverity"},
		{"unknown top-level key", `{"vulnerabilities":[],"SchemaVersion":2}`, "SchemaVersion"},
		{"entry without an id", `{"vulnerabilities":[{"description":"no id","source":{"name":"NVD"}}]}`, "no `id`"},
		// The API requires a source; without this check the whole report is rejected only after the version has been created.
		{"entry without a source", `{"vulnerabilities":[{"id":"CVE-1"}]}`, "no `source.name`"},
		{"entry with an unnamed source", `{"vulnerabilities":[{"id":"CVE-1","source":{"url":"https://x"}}]}`, "no `source.name`"},
		{"trailing document", `{"vulnerabilities":[]}{"vulnerabilities":[]}`, "trailing content"},
		{"empty file", "   \n", "is empty"},
		{"not json", `this is not json`, "parse vulnerabilities file"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadVulnerabilities(writeReport(t, tc.content))
			if err == nil {
				t.Fatalf("LoadVulnerabilities succeeded, want an error mentioning %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

// The API caps one upload; catching it here means the run fails before the version is published rather than after.
func TestLoadVulnerabilitiesRejectsAnOversizedReport(t *testing.T) {
	entries := make([]string, afclient.MaxVulnerabilities+1)
	for i := range entries {
		entries[i] = fmt.Sprintf(`{"id":"CVE-%d","source":{"name":"NVD"}}`, i)
	}
	report := `{"vulnerabilities":[` + strings.Join(entries, ",") + `]}`

	_, err := LoadVulnerabilities(writeReport(t, report))
	if err == nil || !strings.Contains(err.Error(), "at most 5000") {
		t.Fatalf("error = %v, want it to name the upload limit", err)
	}
}

func TestLoadVulnerabilitiesRejectsAMissingFile(t *testing.T) {
	if _, err := LoadVulnerabilities(filepath.Join(t.TempDir(), "absent.json")); err == nil {
		t.Fatal("LoadVulnerabilities succeeded on a missing file")
	}
}

// The example the README points readers at has to be a report the action actually accepts.
func TestDocumentedExampleParses(t *testing.T) {
	in, err := LoadVulnerabilities(filepath.Join("..", "..", "examples", "vulnerabilities.json"))
	if err != nil {
		t.Fatalf("the example shipped in the repository must parse: %v", err)
	}
	if len(in.Vulnerabilities) != 2 {
		t.Fatalf("example has %d findings, want 2", len(in.Vulnerabilities))
	}
}
