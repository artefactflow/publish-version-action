package action

import (
	"strings"
	"testing"
)

// validEnv is the minimum a workflow must supply, plus the context the runner always sets. Tests copy it and change the one thing under test.
func validEnv() map[string]string {
	return map[string]string{
		"INPUT_CLIENT-ID":     "507f191e810c19729de860ed",
		"INPUT_CLIENT-SECRET": "afsa_pretend-this-is-a-real-secret",
		"INPUT_ARTEFACT-NAME": "acme-payment-service",
		"INPUT_VERSION":       "1.4.2",

		"GITHUB_SHA":        "40436b8ce2524c748d95dd8ad223170aff624196",
		"GITHUB_REF_NAME":   "main",
		"GITHUB_RUN_ID":     "48213",
		"GITHUB_RUN_NUMBER": "17",
		"GITHUB_REPOSITORY": "acme/checkout-service",
		"GITHUB_SERVER_URL": "https://github.com",
	}
}

func getenvFrom(vars map[string]string) func(string) string {
	return func(k string) string { return vars[k] }
}

func loadFrom(t *testing.T, vars map[string]string) Config {
	t.Helper()
	cfg, err := LoadConfig(getenvFrom(vars))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	return cfg
}

// The runner uppercases an input name and replaces spaces with underscores — it does not touch hyphens. Reading INPUT_ARTEFACT_NAME instead of INPUT_ARTEFACT-NAME would make every `with:` value invisible, and no unit test that sets its own variables would notice.
func TestInputsComeFromHyphenatedRunnerVariables(t *testing.T) {
	cfg := loadFrom(t, validEnv())
	if cfg.ArtefactName != "acme-payment-service" {
		t.Errorf("artefact-name = %q, want it read from INPUT_ARTEFACT-NAME", cfg.ArtefactName)
	}
	if cfg.ClientID != "507f191e810c19729de860ed" {
		t.Errorf("client-id = %q, want it read from INPUT_CLIENT-ID", cfg.ClientID)
	}

	// The underscored spelling is not what the runner sets, so it must not be honoured.
	vars := validEnv()
	delete(vars, "INPUT_ARTEFACT-NAME")
	vars["INPUT_ARTEFACT_NAME"] = "acme-payment-service"
	if _, err := LoadConfig(getenvFrom(vars)); err == nil {
		t.Error("LoadConfig accepted INPUT_ARTEFACT_NAME; the runner never sets that spelling")
	}
}

func TestEnvVar(t *testing.T) {
	if got := EnvVar("artefact-name"); got != "ARTEFACTFLOW_ARTEFACT_NAME" {
		t.Errorf("EnvVar = %q", got)
	}
	if got := EnvVar("upload-vulnerabilities"); got != "ARTEFACTFLOW_UPLOAD_VULNERABILITIES" {
		t.Errorf("EnvVar = %q", got)
	}
}

func TestEveryInputFallsBackToItsEnvironmentVariable(t *testing.T) {
	report := writeReport(t, `{"vulnerabilities":[{"id":"CVE-1","source":{"name":"NVD"}}]}`)
	vars := map[string]string{
		"ARTEFACTFLOW_API_URL":                "https://af.internal.example",
		"ARTEFACTFLOW_CLIENT_ID":              "507f191e810c19729de860ed",
		"ARTEFACTFLOW_CLIENT_SECRET":          "afsa_pretend-this-is-a-real-secret",
		"ARTEFACTFLOW_ARTEFACT_NAME":          "acme-payment-service",
		"ARTEFACTFLOW_VERSION":                "1.4.2",
		"ARTEFACTFLOW_NOTE":                   "from the environment",
		"ARTEFACTFLOW_IF_EXISTS":              "skip",
		"ARTEFACTFLOW_UPLOAD_VULNERABILITIES": "true",
		"ARTEFACTFLOW_VULNERABILITIES_FILE":   report,
		"GITHUB_SHA":                          "40436b8ce2524c748d95dd8ad223170aff624196",
	}
	cfg := loadFrom(t, vars)
	if cfg.APIURL != "https://af.internal.example" || cfg.ArtefactName != "acme-payment-service" {
		t.Errorf("config = %+v", cfg)
	}
	if cfg.Version.Version != "1.4.2" || cfg.Version.Note != "from the environment" {
		t.Errorf("version body = %+v", cfg.Version)
	}
	if cfg.IfExists != IfExistsSkip || !cfg.UploadVulnerabilities || cfg.VulnerabilitiesFile != report {
		t.Errorf("config = %+v", cfg)
	}
}

func TestWithValueWinsOverEnvironmentVariable(t *testing.T) {
	vars := validEnv()
	vars["ARTEFACTFLOW_VERSION"] = "9.9.9"
	// A job-level env block configures every step; one step still has to be able to override it.
	if got := loadFrom(t, vars).Version.Version; got != "1.4.2" {
		t.Errorf("version = %q, want the `with:` value to win", got)
	}
}

func TestAPIURLDefaultsToTheHostedInstance(t *testing.T) {
	if got := loadFrom(t, validEnv()).APIURL; got != DefaultAPIURL {
		t.Errorf("api-url = %q, want %q", got, DefaultAPIURL)
	}
	vars := validEnv()
	vars["INPUT_API-URL"] = "https://af.internal.example/"
	if got := loadFrom(t, vars).APIURL; got != "https://af.internal.example" {
		t.Errorf("api-url = %q, want the trailing slash trimmed", got)
	}
}

func TestProvenanceIsDerivedFromTheWorkflowContext(t *testing.T) {
	v := loadFrom(t, validEnv()).Version

	if v.CommitSHA != "40436b8ce2524c748d95dd8ad223170aff624196" {
		t.Errorf("commit_sha = %q, want it derived from GITHUB_SHA", v.CommitSHA)
	}
	if v.Branch != "main" {
		t.Errorf("branch = %q, want it derived from GITHUB_REF_NAME", v.Branch)
	}
	if v.BuildID != "48213" {
		t.Errorf("build_id = %q, want it derived from GITHUB_RUN_ID", v.BuildID)
	}
	if v.PipelineID != "17" {
		t.Errorf("pipeline_id = %q, want it derived from GITHUB_RUN_NUMBER", v.PipelineID)
	}
	if v.Builder != Builder {
		t.Errorf("builder = %q, want the constant %q", v.Builder, Builder)
	}
	if v.IsDefault == nil || !*v.IsDefault {
		t.Errorf("is_default = %v, want true by default", v.IsDefault)
	}

	want := "https://github.com/acme/checkout-service/actions/runs/48213"
	if len(v.ExternalReferences) != 1 || v.ExternalReferences[0].URL != want {
		t.Errorf("external_references = %+v, want a single build-system link to %s", v.ExternalReferences, want)
	}
}

func TestInputsOverrideTheWorkflowContext(t *testing.T) {
	vars := validEnv()
	vars["INPUT_COMMIT-SHA"] = "ABCDEF1234567"
	vars["INPUT_BRANCH"] = "release/1.4"
	vars["INPUT_BUILD-ID"] = "external-9001"
	vars["INPUT_PIPELINE-ID"] = "external-pipeline"

	v := loadFrom(t, vars).Version
	// The API constrains commit_sha to lowercase hex, so an override is normalised rather than rejected.
	if v.CommitSHA != "abcdef1234567" {
		t.Errorf("commit_sha = %q, want the override lowercased", v.CommitSHA)
	}
	if v.Branch != "release/1.4" || v.BuildID != "external-9001" || v.PipelineID != "external-pipeline" {
		t.Errorf("version body = %+v, want the overrides", v)
	}
}

func TestUnsetOptionalFieldsAreOmitted(t *testing.T) {
	v := loadFrom(t, validEnv()).Version
	// An unset optional field must be absent from the request body, not sent as an empty string that would overwrite a meaningful server-side value.
	for name, got := range map[string]string{
		"note":        v.Note,
		"bom_ref":     v.BOMRef,
		"lifecycle":   v.Lifecycle,
		"build_state": v.BuildState,
	} {
		if got != "" {
			t.Errorf("%s = %q, want empty so it is omitted from the request body", name, got)
		}
	}
	if v.Hash != nil {
		t.Errorf("hash = %+v, want nil when no digests were supplied", v.Hash)
	}
}

func TestIfExistsDefaultsToFail(t *testing.T) {
	if got := loadFrom(t, validEnv()).IfExists; got != IfExistsFail {
		t.Errorf("if-exists = %q, want %q", got, IfExistsFail)
	}
}

func TestLoadConfigRejectsInvalidInputs(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]string)
		want   string
	}{
		{"no credentials", func(v map[string]string) {
			delete(v, "INPUT_CLIENT-ID")
			delete(v, "INPUT_CLIENT-SECRET")
		}, "service-account credentials are required"},
		{"secret without id", func(v map[string]string) { delete(v, "INPUT_CLIENT-ID") }, "`client-secret` was set without `client-id`"},
		{"id without secret", func(v map[string]string) { delete(v, "INPUT_CLIENT-SECRET") }, "`client-id` was set without `client-secret`"},
		{"client id is a name", func(v map[string]string) { v["INPUT_CLIENT-ID"] = "ci-publisher" }, "24-character hex id"},
		{"relative api-url", func(v map[string]string) { v["INPUT_API-URL"] = "api.artefactflow.app" }, "absolute http(s) URL"},
		{"missing artefact name", func(v map[string]string) { delete(v, "INPUT_ARTEFACT-NAME") }, "`artefact-name` is required"},
		{"artefact name with a slash", func(v map[string]string) { v["INPUT_ARTEFACT-NAME"] = "acme/payments" }, "letters, digits, underscores, and hyphens"},
		{"missing version", func(v map[string]string) { delete(v, "INPUT_VERSION") }, "`version` is required"},
		{"non-semver version", func(v map[string]string) { v["INPUT_VERSION"] = "v1.4" }, "SemVer string"},
		{"long version", func(v map[string]string) { v["INPUT_VERSION"] = "1.4.2-" + strings.Repeat("a", 60) }, "between 4 and 50 characters"},
		{"bad commit sha", func(v map[string]string) { v["INPUT_COMMIT-SHA"] = "not-a-sha" }, "hex characters"},
		{"long note", func(v map[string]string) { v["INPUT_NOTE"] = strings.Repeat("a", 4097) }, "at most 4096 characters"},
		{"bad boolean", func(v map[string]string) { v["INPUT_IS-DEFAULT"] = "ture" }, "must be true or false"},
		{"bad if-exists", func(v map[string]string) { v["INPUT_IF-EXISTS"] = "update" }, "must be one of fail, skip"},
		{"bad hash", func(v map[string]string) { v["INPUT_HASH"] = "sha256" }, "`alg:content`"},
		{"upload without a file", func(v map[string]string) { v["INPUT_UPLOAD-VULNERABILITIES"] = "true" }, "`vulnerabilities-file` is required"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			vars := validEnv()
			tc.mutate(vars)
			_, err := LoadConfig(getenvFrom(vars))
			if err == nil {
				t.Fatalf("LoadConfig succeeded, want an error mentioning %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

// Errors become annotations in a public log, so no validation failure may quote the secret back.
func TestLoadConfigErrorsNeverQuoteTheSecret(t *testing.T) {
	const secret = "afsa_this-must-never-appear"
	vars := validEnv()
	vars["INPUT_CLIENT-SECRET"] = secret
	vars["INPUT_CLIENT-ID"] = "not-an-object-id"
	vars["INPUT_VERSION"] = "nope"

	_, err := LoadConfig(getenvFrom(vars))
	if err == nil {
		t.Fatal("LoadConfig succeeded, want an error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("the client secret leaked into an error: %v", err)
	}
}

func TestLoadConfigReportsEveryProblemAtOnce(t *testing.T) {
	vars := validEnv()
	delete(vars, "INPUT_ARTEFACT-NAME")
	vars["INPUT_VERSION"] = "not-semver"
	vars["INPUT_IF-EXISTS"] = "update"

	_, err := LoadConfig(getenvFrom(vars))
	if err == nil {
		t.Fatal("LoadConfig succeeded, want an error")
	}
	// A workflow author should be able to fix everything in one pass rather than one problem per run.
	for _, want := range []string{"`artefact-name` is required", "SemVer string", "must be one of fail, skip"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %v, want it to mention %q", err, want)
		}
	}
}

const testDigest = "40436b8ce2524c748d95dd8ad223170aff624196bcfe689e13381d01d0d8efb6"

func TestParseHashes(t *testing.T) {
	vars := validEnv()
	// Mixed spellings on purpose: the API accepts exactly one, and a workflow author has no way to know which.
	vars["INPUT_HASH"] = "SHA-256:" + testDigest + "\n\n  sha512: " + testDigest + "  \n"

	got := loadFrom(t, vars).Version.Hash
	if len(got) != 2 {
		t.Fatalf("hash = %+v, want 2 entries with blank lines skipped", got)
	}
	if got[0].Alg != "SHA-256" || got[0].Content != testDigest {
		t.Errorf("hash[0] = %+v", got[0])
	}
	// Whitespace around the pair is a copy-paste artefact, and `sha512` is the same intent as `SHA-512`.
	if got[1].Alg != "SHA-512" || got[1].Content != testDigest {
		t.Errorf("hash[1] = %+v", got[1])
	}
}

// A digest of the form `sha256:<hex>` is what a container build step emits, and pasting it straight in is the obvious thing to do.
func TestParseHashesAcceptsAContainerDigest(t *testing.T) {
	vars := validEnv()
	vars["INPUT_HASH"] = "sha256:" + testDigest

	got := loadFrom(t, vars).Version.Hash
	if len(got) != 1 || got[0].Alg != "SHA-256" || got[0].Content != testDigest {
		t.Fatalf("hash = %+v, want the digest recognised and the algorithm normalised", got)
	}
}

func TestParseHashesRejectsUnusableDigests(t *testing.T) {
	tests := map[string]string{
		"unknown algorithm": "CRC32:" + testDigest,
		// A truncated sha is a common copy-paste error, and the API would reject it after the version was published.
		"truncated digest": "SHA-256:40436b8c",
		"no separator":     "sha256",
	}
	for name, value := range tests {
		t.Run(name, func(t *testing.T) {
			vars := validEnv()
			vars["INPUT_HASH"] = value
			if _, err := LoadConfig(getenvFrom(vars)); err == nil {
				t.Fatalf("LoadConfig accepted hash %q", value)
			}
		})
	}
}

func TestParseProperties(t *testing.T) {
	vars := validEnv()
	vars["INPUT_PROPERTIES"] = "image-digest = sha256-3f9a2c\n\nrunner=ubuntu-latest\n"

	got := loadFrom(t, vars).Version.Properties
	if len(got) != 2 {
		t.Fatalf("properties = %+v, want 2 entries", got)
	}
	if got[0].Name != "image-digest" || got[0].Value != "sha256-3f9a2c" {
		t.Errorf("properties[0] = %+v", got[0])
	}
	if got[1].Name != "runner" || got[1].Value != "ubuntu-latest" {
		t.Errorf("properties[1] = %+v", got[1])
	}
}

func TestLifecycleAndBuildStateAreCheckedAgainstTheAcceptedValues(t *testing.T) {
	// `build` and `retired` read plausibly but are not values the API takes; catching them here beats a 422 mid-pipeline.
	for input, value := range map[string]string{"INPUT_LIFECYCLE": "retired", "INPUT_BUILD-STATE": "done"} {
		vars := validEnv()
		vars[input] = value
		if _, err := LoadConfig(getenvFrom(vars)); err == nil {
			t.Errorf("LoadConfig accepted %s=%s", input, value)
		}
	}

	vars := validEnv()
	vars["INPUT_LIFECYCLE"] = "Release"
	vars["INPUT_BUILD-STATE"] = "SUCCESS"
	cfg := loadFrom(t, vars)
	// The API's values are lower case; accepting any casing and normalising is kinder than rejecting.
	if cfg.Version.Lifecycle != "release" || cfg.Version.BuildState != "success" {
		t.Errorf("lifecycle/build_state = %q/%q, want them normalised", cfg.Version.Lifecycle, cfg.Version.BuildState)
	}
}

func TestBuildReferencesSkippedOutsideAWorkflow(t *testing.T) {
	vars := map[string]string{
		"ARTEFACTFLOW_CLIENT_ID":     "507f191e810c19729de860ed",
		"ARTEFACTFLOW_CLIENT_SECRET": "afsa_pretend-this-is-a-real-secret",
		"ARTEFACTFLOW_ARTEFACT_NAME": "acme-payment-service",
		"ARTEFACTFLOW_VERSION":       "1.4.2",
	}
	// Run locally there is no workflow run to link to, and a link built from empty pieces would be worse than none.
	if refs := loadFrom(t, vars).Version.ExternalReferences; refs != nil {
		t.Errorf("external_references = %+v, want none outside a workflow run", refs)
	}
}
