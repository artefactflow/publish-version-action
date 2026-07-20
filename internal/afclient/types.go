package afclient

import "encoding/json"

// The types here mirror the ArtefactFlow API schema. Two of them are load-bearing beyond ordinary marshalling:
//
// Every optional field on a request body is a pointer or an omitempty scalar so that an unset field is omitted entirely rather than sent as a zero value — the API distinguishes "not provided" from "explicitly empty", and sending `"branch": ""` would overwrite a meaningful value.
//
// Vulnerability and everything it contains must model the API's schema *completely*. The report a workflow supplies is decoded with unknown fields rejected, so a field the API accepts but this file omits would turn a perfectly valid scanner report into a hard failure.

// VersionInput is the request body for creating a version.
type VersionInput struct {
	Version            string      `json:"version"`
	Lifecycle          string      `json:"lifecycle,omitempty"`
	BuildState         string      `json:"build_state,omitempty"`
	IsDefault          *bool       `json:"is_default,omitempty"`
	Branch             string      `json:"branch,omitempty"`
	CommitSHA          string      `json:"commit_sha,omitempty"`
	BuildID            string      `json:"build_id,omitempty"`
	PipelineID         string      `json:"pipeline_id,omitempty"`
	Builder            string      `json:"builder,omitempty"`
	Note               string      `json:"note,omitempty"`
	BOMRef             string      `json:"bom_ref,omitempty"`
	Hash               []Hash      `json:"hash,omitempty"`
	ExternalReferences []Reference `json:"external_references,omitempty"`
	Properties         []Property  `json:"properties,omitempty"`
}

// Hash is one content digest of the built artefact.
type Hash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

// HashAlgorithms are the digest algorithms the API accepts, in the exact spelling it requires.
var HashAlgorithms = []string{
	"MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512",
	"SHA3-256", "SHA3-384", "SHA3-512",
	"BLAKE2b-256", "BLAKE2b-384", "BLAKE2b-512", "BLAKE3",
}

// Lifecycles are the values the API accepts for a version's lifecycle.
var Lifecycles = []string{"pre-alpha", "alpha", "beta", "release", "end-of-life"}

// BuildStates are the values the API accepts for a version's build state.
var BuildStates = []string{"pending", "building", "success", "failed", "cancelled"}

// MaxVulnerabilities is the largest set the vulnerability endpoint accepts in one call.
const MaxVulnerabilities = 5000

// Reference is a typed link recorded against the version, such as the CI run that produced it.
type Reference struct {
	Type    string `json:"type"`
	URL     string `json:"url"`
	Comment string `json:"comment,omitempty"`
}

// Property is a free-form name/value pair carried on the version.
type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Version is the created version as the API echoes it back. Only the fields the action uses are modelled; unknown fields in a response are ignored, so additions upstream do not break this.
type Version struct {
	ID         string `json:"id"`
	ArtefactID string `json:"artefact_id"`
	Version    string `json:"version"`
}

// VulnerabilitiesInput is the request body for the vulnerability upload. The endpoint is a full replace: whatever is sent becomes the complete recorded set for the version.
//
// The findings are carried as the raw JSON they were read from rather than as parsed structs. They are validated against Vulnerability before they get here, but re-encoding them from it would drop every value Go treats as empty — a CVSS score of 0.0 among them — and on a full-replace endpoint a dropped value is a deleted one.
type VulnerabilitiesInput struct {
	Vulnerabilities []json.RawMessage `json:"vulnerabilities"`
}

// Vulnerability is one finding from a scanner, optionally carrying its VEX assessment. `id` and `source` are the two fields the API requires.
type Vulnerability struct {
	ID             string    `json:"id"`
	Source         *Source   `json:"source,omitempty"`
	Ratings        []Rating  `json:"ratings,omitempty"`
	CWEs           []int     `json:"cwes,omitempty"`
	Description    string    `json:"description,omitempty"`
	Recommendation string    `json:"recommendation,omitempty"`
	Analysis       *Analysis `json:"analysis,omitempty"`
	Affects        []Affects `json:"affects,omitempty"`
	Published      string    `json:"published,omitempty"`
	Updated        string    `json:"updated,omitempty"`
}

// Source identifies the advisory database a finding came from. The API requires a name.
type Source struct {
	Name string `json:"name"`
	URL  string `json:"url,omitempty"`
}

// Rating is one severity score for a finding.
type Rating struct {
	Score    float64 `json:"score,omitempty"`
	Severity string  `json:"severity,omitempty"`
	Method   string  `json:"method,omitempty"`
	Vector   string  `json:"vector,omitempty"`
}

// Affects records which components a finding applies to.
type Affects struct {
	Ref      string            `json:"ref,omitempty"`
	Versions []AffectedVersion `json:"versions,omitempty"`
}

// AffectedVersion is one affected version or version range.
type AffectedVersion struct {
	Version string `json:"version,omitempty"`
	Range   string `json:"range,omitempty"`
	Status  string `json:"status,omitempty"`
}

// Analysis is the VEX assessment attached to a finding.
type Analysis struct {
	State         string   `json:"state,omitempty"`
	Justification string   `json:"justification,omitempty"`
	Response      []string `json:"response,omitempty"`
	Detail        string   `json:"detail,omitempty"`
}
