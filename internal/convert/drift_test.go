package convert

import (
	"os"
	"testing"
)

// The drift checks convert a report produced by the latest scanner release against a fixed target, so that a scanner changing its output shape is caught here rather than in a customer's pipeline. They run only in the scheduled scanner-drift job, which scans an image with the current scanner and points these variables at the result; in ordinary CI, with the variables unset, they skip.
func TestDriftTrivy(t *testing.T) { driftCheck(t, "DRIFT_TRIVY_REPORT", FormatTrivy) }

func TestDriftGrype(t *testing.T) { driftCheck(t, "DRIFT_GRYPE_REPORT", FormatGrype) }

func driftCheck(t *testing.T, envVar string, want Format) {
	path := os.Getenv(envVar)
	if path == "" {
		t.Skipf("%s not set; the drift check runs only in the scheduled scanner-drift job", envVar)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
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
	// A scan of a deliberately vulnerable, pinned target must yield findings; none means the fields this action reads have moved.
	if len(res.Findings) == 0 {
		t.Fatalf("a fresh %s scan of the pinned target produced no findings: the fields this action reads have likely moved", want)
	}
	for _, f := range res.Findings {
		if f.ID == "" || f.Source == nil || f.Source.Name == "" {
			t.Fatalf("a converted finding is missing its id or source, which the API requires: %+v", f)
		}
	}
}
