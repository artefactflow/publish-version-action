package action

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/artefactflow/publish-version-action/internal/afclient"
)

const testArtefactID = "0123456789abcdef01234567"

// stubAPI records what Publish asked for and replays canned outcomes.
type stubAPI struct {
	createErr   error
	location    string
	uploadErr   error
	createCalls int
	uploadCalls int
	// uploadedFor is the version the upload was addressed to, which must be the version that was just created.
	uploadedFor string
	uploadedSet afclient.VulnerabilitiesInput
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

func (s *stubAPI) ReplaceVulnerabilities(_ context.Context, _, versionValue string, in afclient.VulnerabilitiesInput) error {
	s.uploadCalls++
	s.uploadedFor, s.uploadedSet = versionValue, in
	return s.uploadErr
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

// withVulnerabilities configures the upload the way LoadConfig would have: the report is already parsed by the time Publish runs.
func withVulnerabilities(cfg Config, ids ...string) Config {
	cfg.UploadVulnerabilities = true
	cfg.VulnerabilitiesFile = "scan.json"
	for _, id := range ids {
		cfg.Vulnerabilities.Vulnerabilities = append(cfg.Vulnerabilities.Vulnerabilities,
			json.RawMessage(fmt.Sprintf(`{"id":%q,"source":{"name":"NVD"}}`, id)))
	}
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

func TestPublishSendsTheCompleteVulnerabilitySet(t *testing.T) {
	cfg := testConfig()
	cfg = withVulnerabilities(cfg, "CVE-1", "CVE-2")

	api := &stubAPI{}
	if _, err := Publish(context.Background(), cfg, testArtefactID, api, io.Discard); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	// The endpoint is a full replace, so the payload must be exactly what was loaded — never a subset.
	if len(api.uploadedSet.Vulnerabilities) != 2 {
		t.Errorf("uploaded %d findings, want the complete set of 2", len(api.uploadedSet.Vulnerabilities))
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
	// This is the failure that must never be ambiguous: the version exists, and only the upload needs re-running.
	for _, want := range []string{"was created", "Re-run this step", "Nothing was partially recorded"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %v, want it to mention %q", err, want)
		}
	}
	// The result still has to describe what happened, so the rest of the workflow is not left blind.
	if !res.Created || res.VulnerabilitiesUploaded {
		t.Errorf("result = %+v, want created=true and vulnerabilities-uploaded=false", res)
	}
}

// A report that cannot be read or parsed is knowable before any request is made, so it must fail during configuration — never after a version has been created. Publishing a version and only then discovering the file is malformed leaves the artefact recorded without the vulnerabilities it was meant to carry.
func TestBadReportFailsBeforeAnythingIsCreated(t *testing.T) {
	dir := t.TempDir()
	malformed := filepath.Join(dir, "malformed.json")
	if err := os.WriteFile(malformed, []byte(`{"vulnerabilities":[{"id":"CVE-1","serverity":"high"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}

	for name, path := range map[string]string{
		"missing file":   filepath.Join(dir, "absent.json"),
		"malformed file": malformed,
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

// The report reaches Publish already parsed, so nothing it does can re-read the file. This is what makes the ordering guarantee above hold.
func TestPublishUsesThePreParsedReport(t *testing.T) {
	cfg := withVulnerabilities(testConfig(), "CVE-1")
	cfg.VulnerabilitiesFile = filepath.Join(t.TempDir(), "never-read.json")

	api := &stubAPI{}
	if _, err := Publish(context.Background(), cfg, testArtefactID, api, io.Discard); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if len(api.uploadedSet.Vulnerabilities) != 1 {
		t.Errorf("uploaded %+v, want the set parsed at configuration time", api.uploadedSet.Vulnerabilities)
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
