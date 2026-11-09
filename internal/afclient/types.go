package afclient

import "encoding/json"

// The types here mirror the ArtefactFlow API schema. One rule is load-bearing beyond ordinary marshalling:
//
// Every optional field on a request body is a pointer or an omitempty scalar so that an unset field is omitted entirely rather than sent as a zero value: the API distinguishes "not provided" from "explicitly empty", and sending `"branch": ""` would overwrite a meaningful value.

// VersionInput is the request body for creating a version. It models every field the endpoint accepts, so nothing a workflow might want to record is unreachable through this action.
type VersionInput struct {
	Version        string `json:"version"`
	Lifecycle      string `json:"lifecycle,omitempty"`
	BuildState     string `json:"build_state,omitempty"`
	IsDefault      *bool  `json:"is_default,omitempty"`
	Branch         string `json:"branch,omitempty"`
	CommitSHA      string `json:"commit_sha,omitempty"`
	BuildID        string `json:"build_id,omitempty"`
	PipelineID     string `json:"pipeline_id,omitempty"`
	BuildTimestamp string `json:"build_timestamp,omitempty"`
	Builder        string `json:"builder,omitempty"`
	Note           string `json:"note,omitempty"`
	BOMRef         string `json:"bom_ref,omitempty"`
	PURL           string `json:"purl,omitempty"`
	CPE            string `json:"cpe,omitempty"`
	MimeType       string `json:"mime_type,omitempty"`
	// Size is a pointer so an explicitly recorded zero is distinguishable from an unset field, the same reason IsDefault is one.
	Size               *int64      `json:"size,omitempty"`
	DownloadURL        string      `json:"download_url,omitempty"`
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

// Reference is a typed link recorded against the version, such as the CI run that produced it.
type Reference struct {
	Type    string `json:"type"`
	URL     string `json:"url"`
	Comment string `json:"comment,omitempty"`
}

// ReferenceTypes are the values the API accepts for an external reference's type.
var ReferenceTypes = []string{
	"vcs", "website", "distribution", "issue-tracker", "license", "mailing-list",
	"bom", "build-system", "release-notes", "vulnerability-disclosure",
	"security-contact", "social", "chat", "support", "documentation", "other",
}

// ReferenceTypeBuildSystem is the type used for the link back to the run that produced the version.
const ReferenceTypeBuildSystem = "build-system"

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

// ReportFormats are the report formats the import endpoint reads, in the spelling its `format` parameter takes. The format is detected from the document; naming one only forces it, and a document that does not match is refused.
var ReportFormats = []string{"native", "trivy", "grype", "cyclonedx", "sarif", "osv-scanner", "gitlab", "snyk", "dependency-check"}

// MaxImportBytes is the largest request the import endpoint accepts, the report and any VEX document together. The action checks the files against it before anything is published, so an oversized report fails before the version is created rather than after.
const MaxImportBytes = 32 << 20

// ImportRequest is one scanner report to record on a version, with an optional VEX document (CycloneDX VEX or OpenVEX) laid over it. The files travel as they were written: ArtefactFlow detects the format and converts the report itself.
type ImportRequest struct {
	// Report is the report's content and ReportName its file name, sent as the part's filename so a refusal can name it.
	Report     []byte
	ReportName string
	// VEX and VEXName are the optional VEX document, nil when none was supplied.
	VEX     []byte
	VEXName string
	// Format forces the report format; empty means detect it.
	Format string
	// Producer names whose findings the report replaces; empty means the report's format, or for a SARIF log or GitLab report the tool the report names.
	Producer string
	// ProducerVersion records the scanner's version with the findings; empty means the version the report states, if it states one. It is for a report that names no version, or names the wrong one.
	ProducerVersion string
	// DryRun converts and validates without recording anything, and answers the document that would have been recorded.
	DryRun bool
}

// ImportSummary is what the import read, how the VEX document applied, and which results it left out because they name no vulnerability.
type ImportSummary struct {
	Format       string   `json:"format"`
	VEXMatched   int      `json:"vex_matched"`
	VEXUnmatched []string `json:"vex_unmatched,omitempty"`
	// SkippedRules counts the report's results that name no vulnerability (a misconfiguration rule in a SARIF log, an entry without an advisory identifier), which the import leaves out; SkippedRuleIDs lists the first 100 of them.
	SkippedRules   int      `json:"skipped_rules,omitempty"`
	SkippedRuleIDs []string `json:"skipped_rule_ids,omitempty"`
}

// ImportResult is the part of an import's answer the action reports.
type ImportResult struct {
	// Producer is the producer whose findings the report replaced, and ProducerVersion the scanner version it recorded, when the report stated one.
	Producer        string
	ProducerVersion string
	// Findings is how many findings the report converted to. Known only on a dry run, whose answer lists them all; an import that records answers with the version's first page.
	Findings int
	// VersionFindings is how many findings the version holds after the import, from every producer. Zero on a dry run, which records nothing.
	VersionFindings int
	Import          ImportSummary
	// Document is a dry run's answer exactly as the API sent it: the findings in ArtefactFlow's own format, which is also a valid body for the vulnerability replace endpoint. Nil for an import that recorded.
	Document json.RawMessage
}
