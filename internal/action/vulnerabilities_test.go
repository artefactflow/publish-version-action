package action

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/artefactflow/publish-version-action/internal/afclient"
)

func writeReport(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vulns.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func uploadEnv(report string) map[string]string {
	vars := validEnv()
	vars["INPUT_UPLOAD-VULNERABILITIES"] = "true"
	vars["INPUT_VULNERABILITIES-FILE"] = report
	return vars
}

// The files travel as they were written: converting them is ArtefactFlow's job, so the action must not reshape them on the way.
func TestLoadConfigReadsTheReportAsItWasWritten(t *testing.T) {
	report := `{"SchemaVersion": 2, "Results": []}`
	vex := `{"bomFormat":"CycloneDX","vulnerabilities":[]}`
	vars := uploadEnv(writeReport(t, report))
	vars["INPUT_VEX-FILE"] = writeReport(t, vex)
	vars["INPUT_VULNERABILITIES-FORMAT"] = "Trivy"
	vars["INPUT_VULNERABILITIES-PRODUCER"] = "image-scan"
	vars["INPUT_VULNERABILITIES-PRODUCER-VERSION"] = "0.58.1 (patched)"

	cfg := loadFrom(t, vars)
	in := cfg.Import
	if string(in.Report) != report || string(in.VEX) != vex {
		t.Errorf("report = %q, vex = %q, want both byte for byte", in.Report, in.VEX)
	}
	if in.Format != "trivy" || in.Producer != "image-scan" || in.ProducerVersion != "0.58.1 (patched)" || in.DryRun {
		t.Errorf("import = %+v, want the format lower-cased, the producer as given, and no dry run", in)
	}
	if in.ReportName != vars["INPUT_VULNERABILITIES-FILE"] || in.VEXName != vars["INPUT_VEX-FILE"] {
		t.Errorf("names = %q, %q, want the input paths", in.ReportName, in.VEXName)
	}
}

func TestLoadConfigLeavesFormatAndProducerToTheAPIByDefault(t *testing.T) {
	cfg := loadFrom(t, uploadEnv(writeReport(t, `{"vulnerabilities":[]}`)))
	if cfg.Import.Format != "" || cfg.Import.Producer != "" || cfg.Import.ProducerVersion != "" || cfg.Import.VEX != nil {
		t.Errorf("import = %+v, want detection and the default producer left to ArtefactFlow", cfg.Import)
	}
}

// Every format the import reads can be forced, in any case: refusing one here would fail the step before ArtefactFlow ever saw the report.
func TestLoadConfigAcceptsEveryReportFormatAsAnOverride(t *testing.T) {
	if !slices.Contains(afclient.ReportFormats, "dependency-check") {
		t.Fatalf("ReportFormats = %v, want dependency-check among them", afclient.ReportFormats)
	}
	for _, format := range afclient.ReportFormats {
		t.Run(format, func(t *testing.T) {
			vars := uploadEnv(writeReport(t, `{"vulnerabilities":[]}`))
			vars["INPUT_VULNERABILITIES-FORMAT"] = strings.ToUpper(format)
			if got := loadFrom(t, vars).Import.Format; got != format {
				t.Errorf("format = %q, want %q", got, format)
			}
		})
	}
}

func TestLoadConfigRejectsUnusableImportInputs(t *testing.T) {
	report := writeReport(t, `{"vulnerabilities":[]}`)
	tests := []struct {
		name   string
		mutate func(map[string]string)
		want   string
	}{
		{"unknown format", func(v map[string]string) { v["INPUT_VULNERABILITIES-FORMAT"] = "spdx" }, "must be one of native, trivy, grype, cyclonedx, sarif, osv-scanner, gitlab, snyk, dependency-check"},
		{"producer with capitals", func(v map[string]string) { v["INPUT_VULNERABILITIES-PRODUCER"] = "Trivy" }, "`vulnerabilities-producer` must be"},
		{"producer with a space", func(v map[string]string) { v["INPUT_VULNERABILITIES-PRODUCER"] = "image scan" }, "`vulnerabilities-producer` must be"},
		{"producer too long", func(v map[string]string) { v["INPUT_VULNERABILITIES-PRODUCER"] = strings.Repeat("a", 65) }, "`vulnerabilities-producer` must be"},
		{"producer version too long", func(v map[string]string) {
			v["INPUT_VULNERABILITIES-PRODUCER-VERSION"] = strings.Repeat("é", 65)
		}, "`vulnerabilities-producer-version` must be at most 64 characters, got 65"},
		{"producer version with a line break", func(v map[string]string) {
			v["INPUT_VULNERABILITIES-PRODUCER-VERSION"] = "0.58.1\n::add-mask::x"
		}, "`vulnerabilities-producer-version` must not contain control characters"},
		{"producer version with DEL", func(v map[string]string) { v["INPUT_VULNERABILITIES-PRODUCER-VERSION"] = "0.58\x7f" }, "must not contain control characters"},
		{"missing report", func(v map[string]string) { v["INPUT_VULNERABILITIES-FILE"] = filepath.Join(t.TempDir(), "absent.json") }, "read vulnerabilities file"},
		{"missing vex file", func(v map[string]string) { v["INPUT_VEX-FILE"] = filepath.Join(t.TempDir(), "absent.json") }, "read vex file"},
		{"vex file not JSON", func(v map[string]string) { v["INPUT_VEX-FILE"] = writeReport(t, "<xml/>") }, "is not a JSON document"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			vars := uploadEnv(report)
			tc.mutate(vars)
			_, err := LoadConfig(getenvFrom(vars))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

// ArtefactFlow refuses a request over its limit, and it can only say so once the version exists. The size is knowable before, so it is checked before.
func TestLoadConfigRejectsAReportOverTheLimit(t *testing.T) {
	big := `{"vulnerabilities":[],"padding":"` + strings.Repeat("a", afclient.MaxImportBytes) + `"}`
	_, err := LoadConfig(getenvFrom(uploadEnv(writeReport(t, big))))
	if err == nil || !strings.Contains(err.Error(), "at most 32 MiB in one import") {
		t.Errorf("error = %v, want the oversized report refused before anything is published", err)
	}
}

// The API counts the version in characters, so a 64-character version in a non-ASCII script must not be refused for its byte length.
func TestLoadConfigAcceptsAProducerVersionOfSixtyFourCharacters(t *testing.T) {
	vars := uploadEnv(writeReport(t, `{"vulnerabilities":[]}`))
	vars["ARTEFACTFLOW_VULNERABILITIES_PRODUCER_VERSION"] = strings.Repeat("é", 64)
	if got := loadFrom(t, vars).Import.ProducerVersion; got != strings.Repeat("é", 64) {
		t.Errorf("producer version = %q, want it read from ARTEFACTFLOW_VULNERABILITIES_PRODUCER_VERSION", got)
	}
}

// The size is checked from the file system before anything is read, so an 80 MB report is refused without being loaded. A sparse file is over the limit by its size while holding nothing, so if it were read first it would fail as empty instead: the size message proves the read never happened.
func TestLoadConfigRefusesAnOversizedReportBeforeReadingIt(t *testing.T) {
	report := filepath.Join(t.TempDir(), "huge.json")
	if err := os.WriteFile(report, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(report, afclient.MaxImportBytes); err != nil {
		t.Fatal(err)
	}
	_, err := LoadConfig(getenvFrom(uploadEnv(report)))
	if err == nil || !strings.Contains(err.Error(), "at most 32 MiB in one import") {
		t.Fatalf("error = %v, want the oversized report refused by its size", err)
	}
	if strings.Contains(err.Error(), "is empty") || strings.Contains(err.Error(), "not a JSON document") {
		t.Errorf("error = %v, want the file refused before it was read", err)
	}
}

// The limit covers both files together: a report under it with a VEX document that takes it over is refused too, before either is read.
func TestLoadConfigCountsTheVEXFileTowardsTheLimit(t *testing.T) {
	vex := filepath.Join(t.TempDir(), "vex.json")
	if err := os.WriteFile(vex, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(vex, afclient.MaxImportBytes-64<<10); err != nil {
		t.Fatal(err)
	}
	vars := uploadEnv(writeReport(t, `{"SchemaVersion":2,"Results":[]}`))
	vars["INPUT_VEX-FILE"] = vex
	if _, err := LoadConfig(getenvFrom(vars)); err == nil || !strings.Contains(err.Error(), "the vulnerabilities file and vex file are") {
		t.Errorf("error = %v, want the two files refused by their combined size", err)
	}
}

func TestLoadConfigVEXWithoutAScanIsAnError(t *testing.T) {
	vars := validEnv()
	vars["INPUT_VEX-FILE"] = writeReport(t, `{}`)
	if _, err := LoadConfig(getenvFrom(vars)); err == nil || !strings.Contains(err.Error(), "needs a scan to overlay onto") {
		t.Errorf("error = %v, want a VEX file without a scan named as a misconfiguration", err)
	}
}

func TestWriteConvertedOutputRejectsAnAnswerThatIsNotADocument(t *testing.T) {
	if err := WriteConvertedOutput(filepath.Join(t.TempDir(), "out.json"), []byte(`[1,2]`)); err == nil {
		t.Error("WriteConvertedOutput accepted an answer that is not a document")
	}
}

// The examples the README links to have to be usable as they stand.
func TestDocumentedExamplesAreJSON(t *testing.T) {
	for _, name := range []string{"vulnerabilities.json", "trivy-report.json", "vex.json"} {
		if _, err := readJSONFile("example", filepath.Join("..", "..", "examples", name)); err != nil {
			t.Errorf("examples/%s: %v", name, err)
		}
	}
}
