// Package action adapts this action to the GitHub Actions runner: it reads the action inputs from the environment, derives the version's build provenance from the workflow context, loads the vulnerability report, and writes the outputs in the runner's file format.
package action

import (
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/artefactflow/publish-version-action/internal/afclient"
	"github.com/artefactflow/publish-version-action/internal/convert"
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
	// ArtefactName is how the artefact is always addressed. The API needs an id, so the action resolves the name first: the id is an implementation detail that never appears in a workflow file.
	ArtefactName string

	// Version is the create body, merged from the inputs and the workflow context.
	Version afclient.VersionInput

	IfExists IfExists

	// UploadVulnerabilities reports whether the second call runs.
	UploadVulnerabilities bool
	// VulnerabilitiesFile is the report that was loaded, kept for log and error messages.
	VulnerabilitiesFile string
	// VulnerabilitiesFormat is the format override, empty for auto-detection. Kept for the log line.
	VulnerabilitiesFormat convert.Format
	// Vulnerabilities is the wire body: the report loaded (native) or converted (Trivy, Grype, CycloneDX) and, when a VEX file was supplied, overlaid with its assessments. It is prepared here rather than after the version is created: discovering a malformed report only once the version exists would leave the artefact half-published for a mistake that was knowable before any request was made.
	Vulnerabilities afclient.VulnerabilitiesInput
	// ConversionNotes are step-log lines a conversion produced, such as a truncated description or a scan that clears the recorded set.
	ConversionNotes []string
	// UnmatchedVEX names the VEX assessments that matched no converted finding, surfaced as a warning: it usually means the scan and the VEX are from different builds.
	UnmatchedVEX []string

	// VEXFile is the CycloneDX VEX document supplied alongside a scan (overlaid into the upload) or on its own (see ApplyVEXOnly).
	VEXFile string
	// ApplyVEXOnly selects the standalone VEX path: apply assessments to a version's already-recorded findings via PATCH, with no scan report and no version create.
	ApplyVEXOnly bool
	// VEXEntries are the parsed standalone assessments, validated here so a malformed VEX document fails before any is applied.
	VEXEntries []convert.VEXEntry

	// ConvertedOutputFile, when set, receives the native JSON that will be uploaded, so a workflow can inspect or archive it before it goes.
	ConvertedOutputFile string
}

var (
	// resourceIDRE is the API's ResourceId: a 36-character lowercase hyphenated UUID, the form of every identifier it issues, a service account's client id included.
	resourceIDRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
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

	// Every provenance field defaults to the workflow context and can be overridden by an input, so the common case is zero configuration while the awkward case (a re-tag, or an artefact built elsewhere and published from here) stays expressible.
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

	references, err := parseReferences(input("external-references"))
	if err != nil {
		fail("input `external-references`: %s", err)
	}

	buildTimestamp := input("build-timestamp")
	if buildTimestamp != "" {
		if _, err := time.Parse(time.RFC3339, buildTimestamp); err != nil {
			fail("input `build-timestamp` must be an RFC 3339 timestamp such as 2026-06-15T10:30:00Z, got %q", buildTimestamp)
		}
	}

	// A PURL is a URI but not an http one (`pkg:docker/...`), so the check is that a scheme is present rather than that it is a web address.
	purl := input("purl")
	if purl != "" && !hasURIScheme(purl) {
		fail("input `purl` must be a package URL such as pkg:docker/acme/payment-service@1.2.3, got %q", purl)
	}
	downloadURL := input("download-url")
	if downloadURL != "" && !hasURIScheme(downloadURL) {
		fail("input `download-url` must be an absolute URL, got %q", downloadURL)
	}

	cpe := input("cpe")
	if n := utf8.RuneCountInString(cpe); n > 512 {
		fail("input `cpe` must be at most 512 characters, got %d", n)
	}
	mimeType := input("mime-type")
	if n := utf8.RuneCountInString(mimeType); n > 128 {
		fail("input `mime-type` must be at most 128 characters, got %d", n)
	}

	size, err := parseSize(input("size"))
	if err != nil {
		fail("%s", err)
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
		BuildTimestamp:     buildTimestamp,
		PURL:               purl,
		CPE:                cpe,
		MimeType:           mimeType,
		Size:               size,
		DownloadURL:        downloadURL,
		Hash:               hashes,
		ExternalReferences: withBuildReference(references, getenv),
		Properties:         properties,
	}

	cfg.ApplyVEXOnly, err = parseBool("apply-vex-only", input("apply-vex-only"), false)
	if err != nil {
		fail("%s", err)
	}
	cfg.UploadVulnerabilities, err = parseBool("upload-vulnerabilities", input("upload-vulnerabilities"), false)
	if err != nil {
		fail("%s", err)
	}
	cfg.VulnerabilitiesFile = input("vulnerabilities-file")
	cfg.VEXFile = input("vex-file")
	cfg.ConvertedOutputFile = input("converted-output-file")

	formatOverride := strings.ToLower(input("vulnerabilities-format"))

	// Everything the upload needs is read and validated here, before the version is created. A report that cannot be converted, or a VEX document with an unmappable value, has to fail before anything is published: a version created and then found to be un-uploadable is the half-published state the whole ordering exists to prevent.
	switch {
	case cfg.ApplyVEXOnly:
		// Standalone VEX applies assessments to a version's already-recorded findings; it takes no scan and creates no version.
		if cfg.UploadVulnerabilities || cfg.VulnerabilitiesFile != "" {
			fail("`apply-vex-only` applies VEX to a version's already-recorded findings and takes no scan report; do not set `upload-vulnerabilities` or `vulnerabilities-file` with it")
		}
		if cfg.VEXFile == "" {
			fail("input `vex-file` is required when `apply-vex-only` is true")
		} else if entries, err := LoadVEXForApply(cfg.VEXFile); err != nil {
			fail("%s", err)
		} else {
			cfg.VEXEntries = entries
		}

	case cfg.UploadVulnerabilities:
		if cfg.VulnerabilitiesFile == "" {
			fail("input `vulnerabilities-file` is required when `upload-vulnerabilities` is true")
		} else if prepared, err := LoadAndConvert(cfg.VulnerabilitiesFile, formatOverride, cfg.VEXFile); err != nil {
			fail("%s", err)
		} else {
			cfg.Vulnerabilities = prepared.Body
			cfg.VulnerabilitiesFormat = prepared.Format
			cfg.ConversionNotes = prepared.Notes
			cfg.UnmatchedVEX = prepared.UnmatchedVEX
		}

	case cfg.VEXFile != "":
		// A VEX file with nothing to attach it to is a misconfiguration worth naming rather than ignoring: it would otherwise be a triage decision that silently did nothing.
		fail("input `vex-file` needs a scan to overlay onto: set `upload-vulnerabilities` with `vulnerabilities-file`, or set `apply-vex-only` to apply it on its own")
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
// No message here ever quotes the secret: errors become annotations in a public log.
func (c Config) validateCredentials() error {
	switch {
	case c.ClientID == "" && c.ClientSecret == "":
		return fmt.Errorf("service-account credentials are required: set `client-id` and `client-secret` (or the %s / %s environment variables)", EnvVar("client-id"), EnvVar("client-secret"))
	case c.ClientID == "":
		return fmt.Errorf("`client-secret` was set without `client-id`")
	case c.ClientSecret == "":
		return fmt.Errorf("`client-id` was set without `client-secret`")
	// The client id is the service account's own id, a UUID. Checking it locally catches the common mistake of pasting the account name, which the API would answer with an indistinguishable "invalid credentials".
	case !resourceIDRE.MatchString(c.ClientID):
		return fmt.Errorf("input `client-id` must be the service account's id, a UUID such as 0198e2c3-9a21-7b8e-90f5-6c1d4e2a83b0, got %q", c.ClientID)
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

// withBuildReference appends a link back to the workflow run that produced the version, so a version in ArtefactFlow always points at the build that made it.
//
// It is skipped outside a workflow run, where the pieces are not available, and skipped when the caller supplied a build-system reference of their own: a version carrying two contradictory answers to "which build made this?" is worse than one that trusts what the workflow said.
func withBuildReference(refs []afclient.Reference, getenv func(string) string) []afclient.Reference {
	for _, r := range refs {
		if r.Type == afclient.ReferenceTypeBuildSystem {
			return refs
		}
	}
	server := firstNonEmpty(getenv("GITHUB_SERVER_URL"), "https://github.com")
	repo, runID := getenv("GITHUB_REPOSITORY"), getenv("GITHUB_RUN_ID")
	if repo == "" || runID == "" {
		return refs
	}
	return append(refs, afclient.Reference{
		Type:    afclient.ReferenceTypeBuildSystem,
		URL:     fmt.Sprintf("%s/%s/actions/runs/%s", server, repo, runID),
		Comment: "GitHub Actions workflow run",
	})
}

// parseReferences reads the `external-references` input: one reference per line as `<type> <url> [comment]`. Neither a type nor a URL can contain a space, so splitting on whitespace and treating everything after the second field as the comment reads naturally and leaves the comment free to be a sentence.
func parseReferences(s string) ([]afclient.Reference, error) {
	var out []afclient.Reference
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return nil, fmt.Errorf("each line must be `type url [comment]`, got %q", line)
		}
		refType, refURL := strings.ToLower(fields[0]), fields[1]
		if !slices.Contains(afclient.ReferenceTypes, refType) {
			return nil, fmt.Errorf("unknown type %q; use one of %s", fields[0], strings.Join(afclient.ReferenceTypes, ", "))
		}
		if !hasURIScheme(refURL) {
			return nil, fmt.Errorf("reference %q must have an absolute URL, got %q", refType, refURL)
		}
		comment := strings.Join(fields[2:], " ")
		if n := utf8.RuneCountInString(comment); n > 500 {
			return nil, fmt.Errorf("comment for %q must be at most 500 characters, got %d", refType, n)
		}
		out = append(out, afclient.Reference{Type: refType, URL: refURL, Comment: comment})
	}
	return out, nil
}

// parseSize reads the `size` input, the artefact's size in bytes.
func parseSize(s string) (*int64, error) {
	if s == "" {
		return nil, nil
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("input `size` must be a whole number of bytes, got %q", s)
	}
	if n < 0 {
		return nil, fmt.Errorf("input `size` cannot be negative, got %d", n)
	}
	return &n, nil
}

// hasURIScheme reports whether a value parses as a URI carrying a scheme. It deliberately does not require http(s): a package URL is `pkg:docker/...`, which is a perfectly good URI.
func hasURIScheme(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme != "" && u.Opaque+u.Host+u.Path != ""
}

// parseHashes reads the `hash` input, which is a newline-separated list of `alg:content` pairs, for example `SHA-256:40436b8c...`. Splitting on the first colon keeps an algorithm name containing a dash intact and tolerates a content value that itself contains a colon.
//
// The algorithm is matched against the set the API accepts, case-insensitively but normalised to the exact spelling it requires: `sha256` and `SHA-256` are the same intent, and only one of them is accepted upstream.
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
		// The API requires a digest of 32 to 128 characters. A truncated one (the first few characters of a sha, say) is a common copy-paste error worth catching before it becomes a rejected request.
		if len(content) < 32 || len(content) > 128 {
			return nil, fmt.Errorf("digest for %s must be between 32 and 128 characters, got %d", canonical, len(content))
		}
		out = append(out, afclient.Hash{Alg: canonical, Content: content})
	}
	return out, nil
}

// canonicalHashAlg maps a user-supplied algorithm name onto the exact spelling the API expects, ignoring case and any separators: `sha256`, `SHA_256`, and `SHA-256` all resolve to `SHA-256`.
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

// parseBool reads a boolean input, returning def when it is unset. Anything that is not a recognised boolean is an error rather than a silent false. A typo in `upload-vulnerabilities: ture` must not quietly skip the upload.
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
