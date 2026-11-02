package convert

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The drift checks convert a report produced by the latest scanner release against a fixed target, so that a scanner changing its output shape is caught here rather than in a customer's pipeline. They run only in the scheduled scanner-drift job, which scans two targets with the current scanners (a go.mod fixture for language packages, and a digest-pinned OS image for distribution packages) and points these variables at the results; in ordinary CI, with the variables unset, they skip. The workflow also exports TARGET_FIXTURE and TARGET_IMAGE, which the failure messages name.
func TestDriftTrivy(t *testing.T) {
	driftCheck(t, "DRIFT_TRIVY_REPORT", "TARGET_FIXTURE", FormatTrivy, false)
}

func TestDriftGrype(t *testing.T) {
	driftCheck(t, "DRIFT_GRYPE_REPORT", "TARGET_FIXTURE", FormatGrype, false)
}

func TestDriftTrivyImage(t *testing.T) {
	driftCheck(t, "DRIFT_TRIVY_IMAGE_REPORT", "TARGET_IMAGE", FormatTrivy, true)
}

func TestDriftGrypeImage(t *testing.T) {
	driftCheck(t, "DRIFT_GRYPE_IMAGE_REPORT", "TARGET_IMAGE", FormatGrype, true)
}

// advisoryID matches an advisory identifier anywhere in a report. It deliberately ignores the report's structure: whether a scan found anything must be decided without reading the fields the converters read, or a renamed field would look like an empty scan.
var advisoryID = regexp.MustCompile(`\b(CVE-\d{4}-\d{4,}|GHSA(-[23456789cfghjmpqrvwx]{4}){3}|GO-\d{4}-\d{4,})\b`)

// driftCheck converts the report named by reportVar and fails when the result is unusable. targetVar names the workflow variable holding the scan target, so a failure can point at it. When reportedSource is set, at least one finding must carry the advisory source the report itself names, not one derived from its identifier: for OS packages a moved distro namespace would otherwise fall back to "NVD" unnoticed.
func driftCheck(t *testing.T, reportVar, targetVar string, want Format, reportedSource bool) {
	path := os.Getenv(reportVar)
	if path == "" {
		t.Skipf("%s not set; the drift check runs only in the scheduled scanner-drift job", reportVar)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	// An empty scan is checked first: a scanner may leave out its result list altogether when it finds nothing, and detection would then misreport the empty scan as a moved shape.
	if !advisoryID.Match(data) {
		t.Fatalf("the %s report names no advisory at all, so the scan target (%s=%q in the scanner-drift workflow) no longer has known vulnerabilities in this scanner's database. This is not drift: replace that target", want, targetVar, os.Getenv(targetVar))
	}

	// The discriminators must still place the document, or detection has drifted.
	got, err := Detect(data, "")
	if err != nil {
		t.Fatalf("the latest %s output is no longer detected as a known format. Its shape has moved: %v", want, err)
	}
	if got != want {
		t.Fatalf("the latest %s output detected as %q: its discriminators have moved", want, got)
	}

	res, err := Convert(want, data)
	if err != nil {
		t.Fatalf("converting a fresh %s report failed, so its schema has likely drifted: %v", want, err)
	}
	// The report names advisories, so finding none means the fields this action reads have moved.
	if len(res.Findings) == 0 {
		t.Fatalf("the %s report names advisories but none converted: the fields this action reads have likely moved", want)
	}
	for _, f := range res.Findings {
		if f.ID == "" || f.Source == nil || f.Source.Name == "" {
			t.Fatalf("a converted finding is missing its id or source, which the API requires: %+v", f)
		}
	}
	if reportedSource && !anySourceFromReport(res, want) {
		t.Fatalf("no converted %s finding kept the advisory source its report names; every source was derived from the identifier, so the source fields or namespaces this action maps have likely moved", want)
	}
}

// anySourceFromReport reports whether at least one finding's source differs from what deriveSource falls back to without one from the report.
func anySourceFromReport(res Result, format Format) bool {
	scanner := "Trivy"
	if format == FormatGrype {
		scanner = "Grype"
	}
	for _, f := range res.Findings {
		fallback := deriveSource(f.ID, "", "", scanner).Name
		if !strings.EqualFold(f.Source.Name, fallback) {
			return true
		}
	}
	return false
}
