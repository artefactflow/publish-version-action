package convert

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/artefactflow/publish-version-action/internal/afclient"
)

// grypeReport is the slice of a Grype JSON report this converter reads.
type grypeReport struct {
	Matches    []grypeMatch     `json:"matches"`
	Descriptor *json.RawMessage `json:"descriptor"`
}

type grypeMatch struct {
	Vulnerability grypeVulnerability `json:"vulnerability"`
	Artifact      grypeArtifact      `json:"artifact"`
	// RelatedVulnerabilities is read only to be ignored: Grype's related entries are aliases of the same finding, not separate ones, and promoting them would double-count.
	RelatedVulnerabilities json.RawMessage `json:"relatedVulnerabilities"`
}

type grypeVulnerability struct {
	ID          string      `json:"id"`
	DataSource  string      `json:"dataSource"`
	Namespace   string      `json:"namespace"`
	Severity    string      `json:"severity"`
	URLs        []string    `json:"urls"`
	Description string      `json:"description"`
	CVSS        []grypeCVSS `json:"cvss"`
	Fix         *grypeFix   `json:"fix"`
}

type grypeCVSS struct {
	Source  string           `json:"source"`
	Type    string           `json:"type"`
	Version string           `json:"version"`
	Vector  string           `json:"vector"`
	Metrics grypeCVSSMetrics `json:"metrics"`
}

type grypeCVSSMetrics struct {
	BaseScore float64 `json:"baseScore"`
}

type grypeFix struct {
	Versions []string `json:"versions"`
	State    string   `json:"state"`
}

type grypeArtifact struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl"`
}

// convertGrype maps a Grype report's matches to flat findings, one per (match), keyed later by identifier. Grype's relatedVulnerabilities are deliberately not promoted to separate findings.
func convertGrype(data []byte) (converted, error) {
	var report grypeReport
	if err := json.Unmarshal(data, &report); err != nil {
		return converted{}, fmt.Errorf("parse Grype report: %w", err)
	}

	var (
		out      []afclient.Vulnerability
		notes    []string
		rawCount int
	)
	for mi, m := range report.Matches {
		rawCount++
		id := strings.TrimSpace(m.Vulnerability.ID)
		if id == "" {
			return converted{}, fmt.Errorf("Grype match %d has no vulnerability.id", mi)
		}

		v := afclient.Vulnerability{
			ID:          id,
			Source:      grypeSource(m.Vulnerability),
			Ratings:     grypeRatings(m.Vulnerability),
			Description: clipNoting(&notes, id, "description", m.Vulnerability.Description, afclient.MaxDescriptionLen),
		}
		if rec := grypeRecommendation(m.Vulnerability); rec != "" {
			v.Recommendation = clipNoting(&notes, id, "recommendation", rec, afclient.MaxRecommendationLen)
		}
		if af := grypeAffects(m.Artifact); af != nil {
			v.Affects = []afclient.Affects{*af}
		}
		out = append(out, v)
	}
	return converted{findings: out, rawCount: rawCount, notes: notes}, nil
}

// grypeSource derives the source name from Grype's namespace ("nvd:cpe", "github:language:go"), falling back to the identifier prefix and then Grype. Grype's dataSource is a URL, used as the source URL when it is one.
func grypeSource(v grypeVulnerability) *afclient.Source {
	name := namespaceToSource(v.Namespace)
	url := ""
	if strings.HasPrefix(v.DataSource, "http://") || strings.HasPrefix(v.DataSource, "https://") {
		url = v.DataSource
	}
	if url == "" && len(v.URLs) > 0 {
		url = v.URLs[0]
	}
	return deriveSource(v.ID, name, url, "Grype")
}

// namespaceToSource maps Grype's advisory namespace to a source name, returning empty for an unrecognised one so the identifier-prefix fallback applies.
func namespaceToSource(ns string) string {
	head := strings.ToLower(strings.TrimSpace(ns))
	if i := strings.IndexByte(head, ':'); i >= 0 {
		head = head[:i]
	}
	switch head {
	case "nvd":
		return "NVD"
	case "github":
		return "GitHub Advisory Database"
	case "gitlab":
		return "GitLab Advisory Database"
	case "debian":
		return "Debian Security Advisory"
	case "alpine":
		return "Alpine SecDB"
	case "redhat", "rhel":
		return "Red Hat Security Data"
	case "amazon", "amzn":
		return "Amazon Linux Security Center"
	case "ubuntu":
		return "Ubuntu CVE Tracker"
	}
	return ""
}

// grypeRatings turns Grype's cvss list into ratings ordered NVD-first. Grype carries one severity label per vulnerability, attached here to the first (NVD-most) rating; ratings without CVSS data fall back to a severity-only rating.
func grypeRatings(v grypeVulnerability) []afclient.Rating {
	severity := mapSeverity(v.Severity)

	var rated []ratedVendor
	for _, c := range v.CVSS {
		rated = append(rated, ratedVendor{vendor: c.Source, rating: afclient.Rating{
			Score:  f64(c.Metrics.BaseScore),
			Method: methodFromCVSSVersion(c.Version, c.Vector),
			Vector: clip(c.Vector, afclient.MaxRatingVectorLen),
		}})
	}
	ratings := orderRatings(rated)
	if len(ratings) == 0 {
		if severity == "unknown" {
			return nil
		}
		return []afclient.Rating{{Severity: severity}}
	}
	if severity != "unknown" {
		ratings[0].Severity = severity
	}
	return ratings
}

func grypeAffects(a grypeArtifact) *afclient.Affects {
	ref := strings.TrimSpace(a.PURL)
	if ref == "" && a.Name != "" {
		if a.Version != "" {
			ref = a.Name + "@" + a.Version
		} else {
			ref = a.Name
		}
	}
	if ref == "" {
		return nil
	}
	return &afclient.Affects{Ref: clip(ref, afclient.MaxAffectsRefLen)}
}

func grypeRecommendation(v grypeVulnerability) string {
	if v.Fix == nil || len(v.Fix.Versions) == 0 {
		return ""
	}
	return "Upgrade to " + strings.Join(v.Fix.Versions, ", ") + "."
}
