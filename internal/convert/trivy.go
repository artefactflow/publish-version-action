package convert

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/artefactflow/publish-version-action/internal/afclient"
)

// trivyReport is the slice of a Trivy JSON report this converter reads. Every other field a Trivy report carries is ignored rather than rejected, so a new Trivy release adding one does not break conversion.
type trivyReport struct {
	SchemaVersion int           `json:"SchemaVersion"`
	Results       []trivyResult `json:"Results"`
}

type trivyResult struct {
	Target          string      `json:"Target"`
	Type            string      `json:"Type"`
	Vulnerabilities []trivyVuln `json:"Vulnerabilities"`
}

type trivyVuln struct {
	VulnerabilityID  string               `json:"VulnerabilityID"`
	PkgName          string               `json:"PkgName"`
	PkgIdentifier    *trivyPkgIdentifier  `json:"PkgIdentifier"`
	InstalledVersion string               `json:"InstalledVersion"`
	FixedVersion     string               `json:"FixedVersion"`
	Severity         string               `json:"Severity"`
	SeveritySource   string               `json:"SeveritySource"`
	PrimaryURL       string               `json:"PrimaryURL"`
	Title            string               `json:"Title"`
	Description      string               `json:"Description"`
	CweIDs           []string             `json:"CweIDs"`
	CVSS             map[string]trivyCVSS `json:"CVSS"`
	PublishedDate    string               `json:"PublishedDate"`
	LastModifiedDate string               `json:"LastModifiedDate"`
	DataSource       *trivyDataSource     `json:"DataSource"`
}

type trivyPkgIdentifier struct {
	PURL string `json:"PURL"`
}

type trivyCVSS struct {
	V2Vector string  `json:"V2Vector"`
	V3Vector string  `json:"V3Vector"`
	V2Score  float64 `json:"V2Score"`
	V3Score  float64 `json:"V3Score"`
}

type trivyDataSource struct {
	Name string `json:"Name"`
	URL  string `json:"URL"`
}

// convertTrivy maps a Trivy report to flat per-(vulnerability × package) findings, which the caller merges by identifier. It fails on a report that is not valid JSON; a well-formed report that simply found nothing converts to zero findings and is reported by the caller as a clear.
func convertTrivy(data []byte) (converted, error) {
	var report trivyReport
	if err := json.Unmarshal(data, &report); err != nil {
		return converted{}, fmt.Errorf("parse Trivy report: %w", err)
	}

	var (
		out      []afclient.Vulnerability
		notes    []string
		rawCount int
	)
	for ri, res := range report.Results {
		for vi, tv := range res.Vulnerabilities {
			rawCount++
			id := strings.TrimSpace(tv.VulnerabilityID)
			if id == "" {
				return converted{}, fmt.Errorf("Trivy result %d (%s), vulnerability %d has no VulnerabilityID", ri, res.Target, vi)
			}

			v := afclient.Vulnerability{
				ID:          id,
				Source:      trivySource(tv),
				Ratings:     trivyRatings(tv),
				CWEs:        parseCWEs(tv.CweIDs),
				Description: clipNoting(&notes, id, "description", firstNonEmpty(tv.Description, tv.Title), afclient.MaxDescriptionLen),
				Published:   tv.PublishedDate,
				Updated:     tv.LastModifiedDate,
			}
			if rec := trivyRecommendation(tv); rec != "" {
				v.Recommendation = clipNoting(&notes, id, "recommendation", rec, afclient.MaxRecommendationLen)
			}
			if af := trivyAffects(tv); af != nil {
				v.Affects = []afclient.Affects{*af}
			}
			out = append(out, v)
		}
	}
	return converted{findings: out, rawCount: rawCount, notes: notes}, nil
}

// trivySource prefers Trivy's own DataSource, falling back to the identifier prefix and then to Trivy itself, so the API's required source name is always present.
func trivySource(tv trivyVuln) *afclient.Source {
	var name, url string
	if tv.DataSource != nil {
		name, url = tv.DataSource.Name, tv.DataSource.URL
	}
	if url == "" {
		url = tv.PrimaryURL
	}
	return deriveSource(tv.VulnerabilityID, name, url, "Trivy")
}

// trivyRatings turns Trivy's per-vendor CVSS map into ratings, ordered NVD-first. Trivy carries one severity label for the whole finding rather than per score, so that severity is attached to the rating from the vendor Trivy itself scored by (SeveritySource), and the other vendors' ratings carry their score and vector only.
func trivyRatings(tv trivyVuln) []afclient.Rating {
	severity := mapSeverity(tv.Severity)
	severityVendor := strings.ToLower(strings.TrimSpace(tv.SeveritySource))

	vendors := make([]string, 0, len(tv.CVSS))
	for vendor := range tv.CVSS {
		vendors = append(vendors, vendor)
	}
	sort.Strings(vendors)

	var rated []ratedVendor
	for _, vendor := range vendors {
		c := tv.CVSS[vendor]
		attach := ""
		if strings.ToLower(vendor) == severityVendor {
			attach = severity
		}
		if c.V3Vector != "" || c.V3Score != 0 {
			rated = append(rated, ratedVendor{vendor: vendor, rating: afclient.Rating{
				Score:    f64(c.V3Score),
				Severity: attach,
				Method:   methodFromVector(c.V3Vector),
				Vector:   clip(c.V3Vector, afclient.MaxRatingVectorLen),
			}})
			attach = "" // a vendor's severity belongs on its primary (V3) rating only
		}
		if c.V2Vector != "" || (c.V2Score != 0 && c.V3Vector == "" && c.V3Score == 0) {
			rated = append(rated, ratedVendor{vendor: vendor, rating: afclient.Rating{
				Score:    f64(c.V2Score),
				Severity: attach,
				Method:   methodFromVector(c.V2Vector),
				Vector:   clip(c.V2Vector, afclient.MaxRatingVectorLen),
			}})
		}
	}

	ratings := orderRatings(rated)
	if len(ratings) == 0 {
		// No CVSS data at all, but the finding still has a severity worth recording.
		if severity == "unknown" {
			return nil
		}
		return []afclient.Rating{{Severity: severity}}
	}
	// If no rating ended up carrying the severity — because the finding named no SeveritySource, or named one that was not among the scored vendors — the label would otherwise be lost. Put it on the first (NVD-most) rating so a known severity always reaches at least one.
	if !ratingsCarrySeverity(ratings) && severity != "unknown" {
		ratings[0].Severity = severity
	}
	return ratings
}

func ratingsCarrySeverity(rs []afclient.Rating) bool {
	for _, r := range rs {
		if r.Severity != "" {
			return true
		}
	}
	return false
}

// trivyAffects builds the affected-component reference from the package's PURL, falling back to its name and version when no PURL is present.
func trivyAffects(tv trivyVuln) *afclient.Affects {
	ref := ""
	if tv.PkgIdentifier != nil {
		ref = strings.TrimSpace(tv.PkgIdentifier.PURL)
	}
	if ref == "" && tv.PkgName != "" {
		if tv.InstalledVersion != "" {
			ref = tv.PkgName + "@" + tv.InstalledVersion
		} else {
			ref = tv.PkgName
		}
	}
	if ref == "" {
		return nil
	}
	return &afclient.Affects{Ref: clip(ref, afclient.MaxAffectsRefLen)}
}

func trivyRecommendation(tv trivyVuln) string {
	if tv.FixedVersion == "" {
		return ""
	}
	if tv.PkgName != "" {
		return fmt.Sprintf("Upgrade %s to %s.", tv.PkgName, tv.FixedVersion)
	}
	return "Upgrade to " + tv.FixedVersion + "."
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
