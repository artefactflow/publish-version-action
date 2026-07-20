// Package action adapts this action to the GitHub Actions runner: it reads the action inputs from the environment, derives the version's build provenance from the workflow context, loads the vulnerability report, and writes the outputs in the runner's file format.
package action

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/artefactflow/publish-version-action/internal/afclient"
)

// DefaultAPIURL is the hosted ArtefactFlow API, used when neither the `api-url` input nor ARTEFACTFLOW_API_URL is set. Self-hosted operators override it; nothing else in the action assumes a particular instance.
const DefaultAPIURL = "https://api.artefactflow.app"

// Builder is recorded on every version this action creates, identifying what produced the build.
const Builder = "github-actions"

// IfExists selects what happens when the version already exists on the artefact.
type IfExists string

const (
	// IfExistsFail treats an existing version as an error. This is the default: silently accepting a duplicate hides a pipeline that is publishing the same version twice.
	IfExistsFail IfExists = "fail"
	// IfExistsSkip treats an existing version as success. The create is not retried and no fields are changed, but a configured vulnerability upload still runs, so a re-run converges on the intended state.
	IfExistsSkip IfExists = "skip"
)

var validIfExists = map[IfExists]bool{IfExistsFail: true, IfExistsSkip: true}

// Config is the validated set of action inputs, with the version create body already assembled.
type Config struct {
	APIURL string
	// Service-account client credentials, exchanged for a short-lived token before anything else happens. They are the only way in: the action deliberately does not accept an already-minted token, so every run authenticates as a machine principal with its own scopes rather than borrowing a human's.
	ClientID     string
	ClientSecret string
	// ArtefactName is how the artefact is always addressed. The API needs an id, so the action resolves the name first — the id is an implementation detail that never appears in a workflow file.
	ArtefactName string

	// Version is the create body, merged from the inputs and the workflow context.
	Version afclient.VersionInput

	IfExists IfExists

	// UploadVulnerabilities reports whether the second call runs.
	UploadVulnerabilities bool
	// VulnerabilitiesFile is the report that was loaded, kept for log and error messages.
	VulnerabilitiesFile string
	// Vulnerabilities is the parsed report, read and validated here rather than after the version is created. Discovering a malformed report only once the version exists would leave the artefact half-published for a mistake that was knowable before any request was made.
	Vulnerabilities afclient.VulnerabilitiesInput
}

var (
	// objectIDRE matches a 24-hex ObjectID, the form of a service account's client id.
	objectIDRE = regexp.MustCompile(`^[a-f0-9]{24}$`)
	// artefactNameRE mirrors the character set the API accepts for an artefact name. Rejecting a bad name here means the resolve call is only made when it has a chance of succeeding.
	artefactNameRE = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	// commitSHARE is the API's own constraint on commit_sha. GitHub always supplies a full 40-hex sha, but an override may be a short one.
	commitSHARE = regexp.MustCompile(`^[a-f0-9]{7,64}$`)
	// semverRE is a pragmatic SemVer check, so an obviously wrong value fails before a request is made. Pre-release and build metadata are allowed.
	semverRE = regexp.MustCompile(`^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)
	// propertyNameRE mirrors the character set the API accepts for a property name.
	propertyNameRE = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
)

// EnvVar returns the environment variable that backs an input: `artefact-name` is backed by ARTEFACTFLOW_ARTEFACT_NAME. Keeping the mapping mechanical means a new input gets its variable for free.
func EnvVar(input string) string {
	return "ARTEFACTFLOW_" + strings.ToUpper(strings.ReplaceAll(input, "-", "_"))
}

// LoadConfig reads and validates the action inputs. getenv is injected so tests do not have to mutate the process environment.
//
// Each input can come from two places: the `with:` block, which the runner exposes as INPUT_<NAME> (so `api-url` arrives as INPUT_API-URL), or an ARTEFACTFLOW_-prefixed environment variable set at workflow, job, or step level. An explicit `with:` value wins, so a single job-level `env:` block can configure every step while one step still overrides, say, the version.
//
// This is also why no input carrying a default declares one in action.yml. The runner substitutes a declared default before the action ever runs, which would make the input always non-empty and the environment fallback dead code. Those defaults are applied here instead.
//
// Validation failures are collected rather than returned one at a time, so a misconfigured workflow reports everything wrong in a single run.
func LoadConfig(getenv func(string) string) (Config, error) {
	input := func(name string) string {
		if v := strings.TrimSpace(getenv("INPUT_" + strings.ToUpper(name))); v != "" {
			return v
		}
		return strings.TrimSpace(getenv(EnvVar(name)))
	}

	var problems []string
	fail := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }

	cfg := Config{
		APIURL:       strings.TrimRight(input("api-url"), "/"),
		ClientID:     strings.ToLower(input("client-id")),
		ClientSecret: input("client-secret"),
		ArtefactName: input("artefact-name"),
	}

	if cfg.APIURL == "" {
		cfg.APIURL = DefaultAPIURL
	}
	if !strings.HasPrefix(cfg.APIURL, "http://") && !strings.HasPrefix(cfg.APIURL, "https://") {
		fail("input `api-url` must be an absolute http(s) URL, got %q", cfg.APIURL)
	}
	if err := cfg.validateCredentials(); err != nil {
		fail("%s", err)
	}
	if cfg.ArtefactName == "" {
		fail("input `artefact-name` is required (or the %s environment variable)", EnvVar("artefact-name"))
	} else if err := validateArtefactName(cfg.ArtefactName); err != nil {
		fail("%s", err)
	}

	// An empty `if-exists` is the unset default rather than an error.
	cfg.IfExists = IfExists(strings.ToLower(input("if-exists")))
	if cfg.IfExists == "" {
		cfg.IfExists = IfExistsFail
	}
	if !validIfExists[cfg.IfExists] {
		fail("input `if-exists` must be one of %s, got %q", strings.Join(ifExistsNames(), ", "), cfg.IfExists)
	}

	version := input("version")
	switch {
	case version == "":
		fail("input `version` is required (or the %s environment variable)", EnvVar("version"))
	case utf8.RuneCountInString(version) < 4 || utf8.RuneCountInString(version) > 50:
		fail("input `version` must be between 4 and 50 characters, got %d", utf8.RuneCountInString(version))
	case !semverRE.MatchString(version):
		fail("input `version` must be a SemVer string such as 1.2.3, got %q", version)
	}

	// Every provenance field defaults to the workflow context and can be overridden by an input, so the common case is zero configuration while the awkward case — a re-tag, or an artefact built elsewhere and published from here — stays expressible.
	commitSHA := strings.ToLower(firstNonEmpty(input("commit-sha"), getenv("GITHUB_SHA")))
	if commitSHA != "" && !commitSHARE.MatchString(commitSHA) {
		fail("commit sha must be 7 to 64 hex characters, got %q", commitSHA)
	}

	note := input("note")
	if n := utf8.RuneCountInString(note); n > 4096 {
		fail("input `note` must be at most 4096 characters, got %d", n)
	}

	isDefault, err := parseBool("is-default", input("is-default"), true)
	if err != nil {
		fail("%s", err)
	}

	hashes, err := parseHashes(input("hash"))
	if err != nil {
		fail("input `hash`: %s", err)
	}

	properties, err := parseProperties(input("properties"))
	if err != nil {
		fail("input `properties`: %s", err)
	}

	// The API accepts a fixed set of values here. Checking locally turns a 422 arriving mid-pipeline into a message that names the input and lists what it will take.
	lifecycle := strings.ToLower(input("lifecycle"))
	if lifecycle != "" && !slices.Contains(afclient.Lifecycles, lifecycle) {
		fail("input `lifecycle` must be one of %s, got %q", strings.Join(afclient.Lifecycles, ", "), lifecycle)
	}
	buildState := strings.ToLower(input("build-state"))
	if buildState != "" && !slices.Contains(afclient.BuildStates, buildState) {
		fail("input `build-state` must be one of %s, got %q", strings.Join(afclient.BuildStates, ", "), buildState)
	}

	branch := firstNonEmpty(input("branch"), getenv("GITHUB_REF_NAME"))
	if n := utf8.RuneCountInString(branch); n > 256 {
		fail("branch must be at most 256 characters, got %d", n)
	}

	cfg.Version = afclient.VersionInput{
		Version:            version,
		Lifecycle:          lifecycle,
		BuildState:         buildState,
		IsDefault:          &isDefault,
		Branch:             branch,
		CommitSHA:          commitSHA,
		BuildID:            truncate(firstNonEmpty(input("build-id"), getenv("GITHUB_RUN_ID")), 256),
		PipelineID:         truncate(firstNonEmpty(input("pipeline-id"), getenv("GITHUB_RUN_NUMBER")), 256),
		Builder:            Builder,
		Note:               note,
		BOMRef:             input("bom-ref"),
		Hash:               hashes,
		ExternalReferences: buildReferences(getenv),
		Properties:         properties,
	}

	cfg.UploadVulnerabilities, err = parseBool("upload-vulnerabilities", input("upload-vulnerabilities"), false)
	if err != nil {
		fail("%s", err)
	}
	if cfg.UploadVulnerabilities {
		cfg.VulnerabilitiesFile = input("vulnerabilities-file")
		switch {
		case cfg.VulnerabilitiesFile == "":
			fail("input `vulnerabilities-file` is required when `upload-vulnerabilities` is true")
		default:
			// Read and validate the report up front. Leaving this until after the create would turn a typo in a JSON file into a version published without the vulnerabilities it was supposed to carry.
			vulns, err := LoadVulnerabilities(cfg.VulnerabilitiesFile)
			if err != nil {
				fail("%s", err)
			}
			cfg.Vulnerabilities = vulns
		}
	}

	if len(problems) > 0 {
		return Config{}, fmt.Errorf("invalid action inputs: %s", strings.Join(problems, "; "))
	}
	return cfg, nil
}

// validateCredentials checks that a complete pair of service-account credentials was supplied.
//
// An already-minted bearer token is deliberately not accepted. Accepting one would make it easy to hand the action a human user's token, which carries that person's full scope set, attributes releases to a person rather than a machine identity, and stops working when they leave. Requiring a service account makes least privilege the only option rather than the diligent one.
//
// No message here ever quotes the secret — errors become annotations in a public log.
func (c Config) validateCredentials() error {
	switch {
	case c.ClientID == "" && c.ClientSecret == "":
		return fmt.Errorf("service-account credentials are required: set `client-id` and `client-secret` (or the %s / %s environment variables)", EnvVar("client-id"), EnvVar("client-secret"))
	case c.ClientID == "":
		return fmt.Errorf("`client-secret` was set without `client-id`")
	case c.ClientSecret == "":
		return fmt.Errorf("`client-id` was set without `client-secret`")
	// The client id is the service account's own 24-hex id. Checking it locally catches the common mistake of pasting the account name, which the API would answer with an indistinguishable "invalid credentials".
	case !objectIDRE.MatchString(c.ClientID):
		return fmt.Errorf("input `client-id` must be the service account's 24-character hex id, got %q", c.ClientID)
	}
	return nil
}

// validateArtefactName applies the limits the API documents for a name, so an unusable value fails before a request is made.
func validateArtefactName(name string) error {
	if n := utf8.RuneCountInString(name); n < 2 || n > 128 {
		return fmt.Errorf("input `artefact-name` must be between 2 and 128 characters, got %d", n)
	}
	if !artefactNameRE.MatchString(name) {
		return fmt.Errorf("input `artefact-name` may only contain letters, digits, underscores, and hyphens, got %q", name)
	}
	return nil
}

// buildReferences records a link back to the workflow run that produced the version, so a version in ArtefactFlow always points at the build that made it. It is skipped outside a workflow run, where the pieces are not available.
func buildReferences(getenv func(string) string) []afclient.Reference {
	server := firstNonEmpty(getenv("GITHUB_SERVER_URL"), "https://github.com")
	repo, runID := getenv("GITHUB_REPOSITORY"), getenv("GITHUB_RUN_ID")
	if repo == "" || runID == "" {
		return nil
	}
	return []afclient.Reference{{
		Type:    "build-system",
		URL:     fmt.Sprintf("%s/%s/actions/runs/%s", server, repo, runID),
		Comment: "GitHub Actions workflow run",
	}}
}

// parseHashes reads the `hash` input, which is a newline-separated list of `alg:content` pairs — for example `SHA-256:40436b8c...`. Splitting on the first colon keeps an algorithm name containing a dash intact and tolerates a content value that itself contains a colon.
//
// The algorithm is matched against the set the API accepts, case-insensitively but normalised to the exact spelling it requires — `sha256` and `SHA-256` are the same intent, and only one of them is accepted upstream.
func parseHashes(s string) ([]afclient.Hash, error) {
	var out []afclient.Hash
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		alg, content, ok := strings.Cut(line, ":")
		alg, content = strings.TrimSpace(alg), strings.TrimSpace(content)
		if !ok || alg == "" || content == "" {
			return nil, fmt.Errorf("each line must be `alg:content`, got %q", line)
		}
		canonical, known := canonicalHashAlg(alg)
		if !known {
			return nil, fmt.Errorf("unknown algorithm %q; use one of %s", alg, strings.Join(afclient.HashAlgorithms, ", "))
		}
		// The API requires a digest of 32 to 128 characters. A truncated one — the first few characters of a sha, say — is a common copy-paste error worth catching before it becomes a rejected request.
		if len(content) < 32 || len(content) > 128 {
			return nil, fmt.Errorf("digest for %s must be between 32 and 128 characters, got %d", canonical, len(content))
		}
		out = append(out, afclient.Hash{Alg: canonical, Content: content})
	}
	return out, nil
}

// canonicalHashAlg maps a user-supplied algorithm name onto the exact spelling the API expects, ignoring case and any separators — `sha256`, `SHA_256`, and `SHA-256` all resolve to `SHA-256`.
func canonicalHashAlg(alg string) (string, bool) {
	normalise := func(s string) string {
		return strings.ToLower(strings.NewReplacer("-", "", "_", "", " ", "").Replace(s))
	}
	want := normalise(alg)
	for _, known := range afclient.HashAlgorithms {
		if normalise(known) == want {
			return known, true
		}
	}
	return "", false
}

// parseProperties reads the `properties` input, a newline-separated list of `name=value` pairs. It is the escape hatch for anything the API records that this action has no dedicated input for.
func parseProperties(s string) ([]afclient.Property, error) {
	var out []afclient.Property
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		name, value, ok := strings.Cut(line, "=")
		name, value = strings.TrimSpace(name), strings.TrimSpace(value)
		if !ok || name == "" || value == "" {
			return nil, fmt.Errorf("each line must be `name=value`, got %q", line)
		}
		if n := utf8.RuneCountInString(name); n < 2 || n > 128 || !propertyNameRE.MatchString(name) {
			return nil, fmt.Errorf("name %q must be 2 to 128 characters of letters, digits, underscores, or hyphens", name)
		}
		if n := utf8.RuneCountInString(value); n > 1024 {
			return nil, fmt.Errorf("value for %q must be at most 1024 characters, got %d", name, n)
		}
		out = append(out, afclient.Property{Name: name, Value: value})
	}
	return out, nil
}

// parseBool reads a boolean input, returning def when it is unset. Anything that is not a recognised boolean is an error rather than a silent false — a typo in `upload-vulnerabilities: ture` must not quietly skip the upload.
func parseBool(name, value string, def bool) (bool, error) {
	switch strings.ToLower(value) {
	case "":
		return def, nil
	case "true", "yes", "1":
		return true, nil
	case "false", "no", "0":
		return false, nil
	default:
		return false, fmt.Errorf("input `%s` must be true or false, got %q", name, value)
	}
}

// ifExistsNames lists the accepted values in a stable order, for error messages.
func ifExistsNames() []string {
	names := make([]string, 0, len(validIfExists))
	for v := range validIfExists {
		names = append(names, string(v))
	}
	sort.Strings(names)
	return names
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// truncate caps a value at max characters. It counts runes rather than bytes so a multi-byte value is never cut mid-character, which would put invalid UTF-8 on the wire.
func truncate(s string, max int) string {
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	return string([]rune(s)[:max])
}
