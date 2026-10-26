package convert

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/artefactflow/publish-version-action/internal/afclient"
)

// update regenerates the golden files instead of comparing against them: `go test ./internal/convert -update`. Committing the regenerated goldens is how a deliberate change to the mapping is reviewed, as a diff of the converted output.
var update = flag.Bool("update", false, "regenerate golden files")

// snapshot is the full, stable shape of a conversion, captured so any change to what a converter emits shows up as a golden diff rather than passing silently.
type snapshot struct {
	Format   string                   `json:"format"`
	Cleared  bool                     `json:"cleared"`
	Notes    []string                 `json:"notes,omitempty"`
	Findings []afclient.Vulnerability `json:"findings"`
}

// goldenCases pairs each scanner fixture with its format. The fixtures deliberately include the cases a naive conversion gets wrong (a finding with no data source, one with no CVSS vector, a vulnerability across several packages, an empty result set), so the golden is where a regression in any of them surfaces.
var goldenCases = []struct {
	name   string
	format Format
}{
	{"trivy", FormatTrivy},
	{"trivy-empty", FormatTrivy},
	{"grype", FormatGrype},
	{"grype-empty", FormatGrype},
	{"cyclonedx", FormatCycloneDX},
}

func TestGolden(t *testing.T) {
	for _, tc := range goldenCases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("testdata", tc.name+".input.json"))
			if err != nil {
				t.Fatal(err)
			}
			res, err := Convert(tc.format, data)
			if err != nil {
				t.Fatalf("Convert: %v", err)
			}
			// The converted set must survive encoding for the wire, so exercise that path here too.
			if _, err := Encode(res.Findings); err != nil {
				t.Fatalf("Encode: %v", err)
			}

			got, err := json.MarshalIndent(snapshot{
				Format:   string(tc.format),
				Cleared:  res.Cleared,
				Notes:    res.Notes,
				Findings: res.Findings,
			}, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, '\n')

			goldenPath := filepath.Join("testdata", tc.name+".golden.json")
			if *update {
				if err := os.WriteFile(goldenPath, got, 0o600); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(goldenPath)
			if err != nil {
				t.Fatalf("read golden (run `go test ./internal/convert -update` to create it): %v", err)
			}
			if string(got) != string(want) {
				t.Errorf("converted output does not match %s.\n--- got ---\n%s\n--- want ---\n%s", goldenPath, got, want)
			}
		})
	}
}
