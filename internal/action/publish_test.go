package action

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/artefactflow/publish-version-action/internal/afclient"
)

const testArtefactID = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b"

// stubAPI records what Publish asked for and replays canned outcomes.
type stubAPI struct {
	createErr   error
	location    string
	createCalls int
	// uploadErr fails the import that records; dryRunErr fails the dry run.
	uploadErr   error
	dryRunErr   error
	uploadCalls int
	dryRuns     int
	// uploadedFor is the version the import was addressed to, which must be the version that was just created.
	uploadedFor string
	imported    afclient.ImportRequest
	answer      afclient.ImportResult
}

func (s *stubAPI) CreateVersion(_ context.Context, artefactID string, in afclient.VersionInput) (*afclient.Version, string, error) {
	s.createCalls++
	if s.createErr != nil {
		// The own-retry signal is not a failure: the real client returns a usable version alongside it.
		if afclient.CreatedByOwnRetry(s.createErr) {
			return &afclient.Version{ArtefactID: artefactID, Version: in.Version}, "", s.createErr
		}
		return nil, "", s.createErr
	}
	return &afclient.Version{ArtefactID: artefactID, Version: in.Version}, s.location, nil
}

func (s *stubAPI) ImportVulnerabilities(_ context.Context, _, versionValue string, in afclient.ImportRequest) (*afclient.ImportResult, error) {
	if in.DryRun {
		s.dryRuns++
		if s.dryRunErr != nil {
			return nil, s.dryRunErr
		}
		return &afclient.ImportResult{Producer: "trivy", Findings: 1, Document: json.RawMessage(`{"producer":"trivy","vulnerabilities":[{"id":"CVE-1","ratings":[{"score":0.0}]}],"import":{"format":"trivy","vex_matched":0}}`)}, nil
	}
	s.uploadCalls++
	s.uploadedFor, s.imported = versionValue, in
	if s.uploadErr != nil {
		return nil, s.uploadErr
	}
	answer := s.answer
	return &answer, nil
}

func testConfig() Config {
	isDefault := true
	return Config{
		APIURL:       DefaultAPIURL,
		ArtefactName: "acme-payment-service",
		IfExists:     IfExistsFail,
		Version:      afclient.VersionInput{Version: "1.4.2", IsDefault: &isDefault, Builder: Builder},
	}
}

// conflict is the error the client produces for a 409.
func conflict() error {
	return errors.Join(afclient.ErrVersionExists, &afclient.StatusError{Status: 409, Code: "VERSION00409", Message: "already exists"})
}

// withVulnerabilities configures the import the way LoadConfig would have: the report is already read by the time Publish runs.
func withVulnerabilities(cfg Config, ids ...string) Config {
	cfg.UploadVulnerabilities = true
	cfg.VulnerabilitiesFile = "scan.json"
	entries := make([]string, 0, len(ids))
	for _, id := range ids {
		entries = append(entries, fmt.Sprintf(`{"id":%q,"source":{"name":"NVD"}}`, id))
	}
	cfg.Import = afclient.ImportRequest{Report: []byte(`{"vulnerabilities":[` + strings.Join(entries, ",") + `]}`), ReportName: "scan.json"}
	return cfg
}

func TestPublishCreatesVersion(t *testing.T) {
	api := &stubAPI{location: "https://api.artefactflow.app/v1/artefacts/" + testArtefactID + "/versions/1.4.2"}
	res, err := Publish(context.Background(), testConfig(), testArtefactID, api, io.Discard)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if !res.Created || res.Version != "1.4.2" || res.VersionURL != api.location {
		t.Errorf("result = %+v", res)
	}
	if api.uploadCalls != 0 {
		t.Error("vulnerabilities were uploaded without `upload-vulnerabilities` being set")
	}
}

func TestPublishUploadsAfterCreateForTheSameVersion(t *testing.T) {
	cfg := testConfig()
	cfg = withVulnerabilities(cfg, "CVE-2023-44487")

	api := &stubAPI{}
	res, err := Publish(context.Background(), cfg, testArtefactID, api, io.Discard)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if api.createCalls != 1 || api.uploadCalls != 1 {
		t.Fatalf("calls: create=%d upload=%d, want one of each", api.createCalls, api.uploadCalls)
	}
	// Vulnerabilities are keyed by the SemVer string, so the upload must address the version that was just created.
	if api.uploadedFor != "1.4.2" {
		t.Errorf("upload addressed version %q, want 1.4.2", api.uploadedFor)
	}
	if !res.VulnerabilitiesUploaded {
		t.Error("the vulnerabilities-uploaded output would be false after a successful upload")
	}
}

func TestPublishSendsTheReportAsItWasRead(t *testing.T) {
	cfg := withVulnerabilities(testConfig(), "CVE-1", "CVE-2")
	cfg.Import.Format, cfg.Import.Producer = "native", "image-scan"

	api := &stubAPI{answer: afclient.ImportResult{Producer: "image-scan", VersionFindings: 2, Import: afclient.ImportSummary{Format: "native"}}}
	var log strings.Builder
	if _, err := Publish(context.Background(), cfg, testArtefactID, api, &log); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	// The import replaces the producer's findings, so what is sent must be exactly the report that was read, with the options the inputs set.
	if !reflect.DeepEqual(api.imported, cfg.Import) {
		t.Errorf("imported %+v, want %+v", api.imported, cfg.Import)
	}
	if api.dryRuns != 0 {
		t.Errorf("dry runs = %d, want none without `converted-output-file`", api.dryRuns)
	}
	if !strings.Contains(log.String(), "producer image-scan") || !strings.Contains(log.String(), "now holds 2 finding(s)") {
		t.Errorf("log = %q, want the producer and the version's total", log.String())
	}
}

func TestPublishWarnsAboutUnmatchedVEX(t *testing.T) {
	cfg := withVulnerabilities(testConfig(), "CVE-1")
	api := &stubAPI{answer: afclient.ImportResult{Producer: "trivy", Import: afclient.ImportSummary{Format: "trivy", VEXUnmatched: []string{"CVE-2024-9"}}}}
	var log strings.Builder
	if _, err := Publish(context.Background(), cfg, testArtefactID, api, &log); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if !strings.Contains(log.String(), "::warning::1 VEX assessment(s) matched no finding") || !strings.Contains(log.String(), "CVE-2024-9") {
		t.Errorf("log = %q, want a warning naming the unmatched assessment", log.String())
	}
}

// The unmatched ids are copied from the workflow's VEX document, and the runner reads every log line for workflow commands. An id carrying a line break must not get to start one, and a VEX document from another build must not flood the annotation with hundreds of ids.
func TestPublishBoundsAndSanitisesUnmatchedVEXIDs(t *testing.T) {
	unmatched := []string{"CVE-2024-0\n::add-mask::x"}
	for i := 1; i < 25; i++ {
		unmatched = append(unmatched, fmt.Sprintf("CVE-2024-%d", i))
	}
	cfg := withVulnerabilities(testConfig(), "CVE-1")
	api := &stubAPI{answer: afclient.ImportResult{Producer: "trivy", Import: afclient.ImportSummary{Format: "trivy", VEXUnmatched: unmatched}}}
	var log strings.Builder
	if _, err := Publish(context.Background(), cfg, testArtefactID, api, &log); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	for _, line := range strings.Split(log.String(), "\n") {
		if strings.HasPrefix(line, "::") && !strings.HasPrefix(line, "::warning::") {
			t.Errorf("log line %q starts a workflow command the VEX document supplied", line)
		}
	}
	out := log.String()
	if !strings.Contains(out, "::warning::25 VEX assessment(s)") || !strings.Contains(out, "CVE-2024-0::add-mask::x, CVE-2024-1,") {
		t.Errorf("log = %q, want every unmatched assessment counted and the ids stripped of control characters", out)
	}
	if !strings.Contains(out, "CVE-2024-19 and 5 more.") || strings.Contains(out, "CVE-2024-20") {
		t.Errorf("log = %q, want the first 20 ids named and the rest counted", out)
	}
}

func TestPublishReportsSkippedResults(t *testing.T) {
	cfg := withVulnerabilities(testConfig(), "CVE-1")
	api := &stubAPI{answer: afclient.ImportResult{Producer: "trivy", Import: afclient.ImportSummary{Format: "sarif", SkippedRules: 3, SkippedRuleIDs: []string{"DS002", "DS026\n::error::x"}}}}
	var log strings.Builder
	if _, err := Publish(context.Background(), cfg, testArtefactID, api, &log); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if !strings.Contains(log.String(), "Left out 3 result(s)") || !strings.Contains(log.String(), "DS002, DS026::error::x and 1 more") || strings.Contains(log.String(), "\n::error::") {
		t.Errorf("log = %q, want the skipped results counted and named", log.String())
	}
}

func TestPublishSaysNothingOfSkippedResultsWhenThereAreNone(t *testing.T) {
	cfg := withVulnerabilities(testConfig(), "CVE-1")
	api := &stubAPI{answer: afclient.ImportResult{Producer: "trivy", Import: afclient.ImportSummary{Format: "trivy"}}}
	var log strings.Builder
	if _, err := Publish(context.Background(), cfg, testArtefactID, api, &log); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if strings.Contains(log.String(), "Left out") {
		t.Errorf("log = %q, want no mention of skipped results", log.String())
	}
}

// The converted document comes from a dry run before the import, so a workflow has it to inspect even when the import itself then fails.
func TestPublishWritesTheConvertedDocumentBeforeImporting(t *testing.T) {
	cfg := withVulnerabilities(testConfig(), "CVE-1")
	cfg.ConvertedOutputFile = filepath.Join(t.TempDir(), "converted.json")

	api := &stubAPI{uploadErr: &afclient.StatusError{Status: 500, Snippet: "boom"}}
	res, err := Publish(context.Background(), cfg, testArtefactID, api, io.Discard)
	if err == nil {
		t.Fatal("Publish succeeded despite a failed import")
	}
	if api.dryRuns != 1 || api.uploadCalls != 1 {
		t.Errorf("dry runs = %d, imports = %d, want one of each", api.dryRuns, api.uploadCalls)
	}
	if res.ConvertedFile != cfg.ConvertedOutputFile {
		t.Errorf("converted file output = %q, want %q", res.ConvertedFile, cfg.ConvertedOutputFile)
	}
	written, readErr := os.ReadFile(cfg.ConvertedOutputFile)
	if readErr != nil {
		t.Fatalf("the converted document was not written: %v", readErr)
	}
	// ArtefactFlow's own format, uploadable as it stands: the import summary is not part of it, and a 0.0 score survives.
	if strings.Contains(string(written), `"import"`) || !strings.Contains(string(written), `"score": 0.0`) || !strings.Contains(string(written), `"producer": "trivy"`) {
		t.Errorf("converted document = %s", written)
	}
}

// A dry run that fails stops before the import: nothing is recorded, and the error says how to retry.
func TestPublishStopsWhenTheDryRunFails(t *testing.T) {
	cfg := withVulnerabilities(testConfig(), "CVE-1")
	cfg.ConvertedOutputFile = filepath.Join(t.TempDir(), "converted.json")

	api := &stubAPI{dryRunErr: &afclient.StatusError{Status: 400, Message: "The report was refused"}}
	res, err := Publish(context.Background(), cfg, testArtefactID, api, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "The report was refused") {
		t.Fatalf("error = %v, want the refusal", err)
	}
	if api.uploadCalls != 0 || res.ConvertedFile != "" || res.VulnerabilitiesUploaded {
		t.Errorf("imports = %d, result = %+v, want nothing recorded or written", api.uploadCalls, res)
	}
}

func TestPublishDerivesVersionURLWhenLocationIsAbsent(t *testing.T) {
	res, err := Publish(context.Background(), testConfig(), testArtefactID, &stubAPI{}, io.Discard)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	want := DefaultAPIURL + "/v1/artefacts/" + testArtefactID + "/versions/1.4.2"
	if res.VersionURL != want {
		t.Errorf("version-url = %q, want %q", res.VersionURL, want)
	}
}

func TestPublishResolvesRelativeLocation(t *testing.T) {
	api := &stubAPI{location: "/v1/artefacts/" + testArtefactID + "/versions/1.4.2"}
	res, err := Publish(context.Background(), testConfig(), testArtefactID, api, io.Discard)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	want := DefaultAPIURL + "/v1/artefacts/" + testArtefactID + "/versions/1.4.2"
	if res.VersionURL != want {
		t.Errorf("version-url = %q, want it resolved against the API base URL", res.VersionURL)
	}
}

func TestPublishConflictFailsByDefault(t *testing.T) {
	api := &stubAPI{createErr: conflict()}
	res, err := Publish(context.Background(), testConfig(), testArtefactID, api, io.Discard)
	if err == nil {
		t.Fatal("Publish succeeded on a conflict, want an error")
	}
	// The message has to tell the reader how to make a legitimate re-run succeed.
	if !strings.Contains(err.Error(), "if-exists: skip") {
		t.Errorf("error = %v, want it to point at the `if-exists` input", err)
	}
	if res.Created {
		t.Error("the created output would be true for a version this run did not create")
	}
}

func TestPublishConflictWithSkipStillUploads(t *testing.T) {
	cfg := testConfig()
	cfg.IfExists = IfExistsSkip
	cfg = withVulnerabilities(cfg, "CVE-1")

	api := &stubAPI{createErr: conflict()}
	res, err := Publish(context.Background(), cfg, testArtefactID, api, io.Discard)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if res.Created {
		t.Error("created = true, want false for a version that already existed")
	}
	// The point of `skip` is that a re-run converges on the intended state, which includes the vulnerability set.
	if api.uploadCalls != 1 || api.uploadedFor != "1.4.2" {
		t.Errorf("upload calls = %d for version %q, want the upload to still run", api.uploadCalls, api.uploadedFor)
	}
}

func TestPublishUploadFailureSaysTheVersionExists(t *testing.T) {
	cfg := testConfig()
	cfg = withVulnerabilities(cfg, "CVE-1")

	api := &stubAPI{uploadErr: &afclient.StatusError{Status: 500, Snippet: "boom"}}
	res, err := Publish(context.Background(), cfg, testArtefactID, api, io.Discard)
	if err == nil {
		t.Fatal("Publish succeeded despite a failed upload")
	}
	// This is the failure that must never be ambiguous: the version exists, and only the import needs re-running, which a plain re-run would not do: it would fail on the existing version first.
	for _, want := range []string{"was created", "re-run this step with `if-exists: skip`", "Nothing of the report was recorded"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %v, want it to mention %q", err, want)
		}
	}
	// The result still has to describe what happened, so the rest of the workflow is not left blind.
	if !res.Created || res.VulnerabilitiesUploaded {
		t.Errorf("result = %+v, want created=true and vulnerabilities-uploaded=false", res)
	}
}

// A report that is missing, empty or not JSON is knowable before any request is made, so it must fail during configuration, never after a version has been created.
func TestBadReportFailsBeforeAnythingIsCreated(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	for name, path := range map[string]string{
		"missing file":   filepath.Join(dir, "absent.json"),
		"empty file":     write("empty.json", " \n"),
		"truncated file": write("truncated.json", `{"vulnerabilities":[{"id":"CVE-1"`),
	} {
		t.Run(name, func(t *testing.T) {
			vars := validEnv()
			vars["INPUT_UPLOAD-VULNERABILITIES"] = "true"
			vars["INPUT_VULNERABILITIES-FILE"] = path

			if _, err := LoadConfig(getenvFrom(vars)); err == nil {
				t.Fatal("LoadConfig accepted an unusable vulnerabilities report; the version would be created before the problem surfaced")
			}
		})
	}
}

// The report reaches Publish already read, so nothing it does can re-read the file.
func TestPublishUsesThePreReadReport(t *testing.T) {
	cfg := withVulnerabilities(testConfig(), "CVE-1")
	cfg.VulnerabilitiesFile = filepath.Join(t.TempDir(), "never-read.json")

	api := &stubAPI{}
	if _, err := Publish(context.Background(), cfg, testArtefactID, api, io.Discard); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if !strings.Contains(string(api.imported.Report), "CVE-1") {
		t.Errorf("imported %q, want the report read at configuration time", api.imported.Report)
	}
}

// The client reports "your own retry created this" as an error value carrying a usable version. Publish must treat it as a success, or a transient blip turns a correct publish into a red workflow with no vulnerabilities uploaded.
func TestPublishTreatsAnOwnRetryCreateAsSuccess(t *testing.T) {
	cfg := withVulnerabilities(testConfig(), "CVE-1")
	api := &stubAPI{createErr: afclient.ErrCreatedByOwnRetry}

	var log strings.Builder
	res, err := Publish(context.Background(), cfg, testArtefactID, api, &log)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if !res.Created {
		t.Error("created = false for a version this run's own retry created")
	}
	// The upload has to happen: skipping it would leave the version recorded with no findings.
	if api.uploadCalls != 1 {
		t.Errorf("upload calls = %d, want the upload to run", api.uploadCalls)
	}
	// Ambiguity this deep should not be silent.
	if !strings.Contains(log.String(), "::warning::") {
		t.Errorf("log = %q, want a warning that the create was retried", log.String())
	}
}
