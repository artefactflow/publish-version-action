package convert

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/artefactflow/publish-version-action/internal/afclient"
)

// cdxDocument is the slice of a CycloneDX BOM this action reads: its vulnerabilities. A VEX document is the same shape whose entries carry an analysis and usually no ratings, so this type serves both the scan converter and the VEX overlay.
type cdxDocument struct {
	BOMFormat       string             `json:"bomFormat"`
	SpecVersion     string             `json:"specVersion"`
	Vulnerabilities []cdxVulnerability `json:"vulnerabilities"`
}

type cdxVulnerability struct {
	ID             string       `json:"id"`
	Source         *cdxSource   `json:"source"`
	Ratings        []cdxRating  `json:"ratings"`
	CWEs           []int        `json:"cwes"`
	Description    string       `json:"description"`
	Recommendation string       `json:"recommendation"`
	Analysis       *cdxAnalysis `json:"analysis"`
	Affects        []cdxAffects `json:"affects"`
	Published      string       `json:"published"`
	Updated        string       `json:"updated"`
}

type cdxSource struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

type cdxRating struct {
	Source   *cdxSource `json:"source"`
	Score    *float64   `json:"score"`
	Severity string     `json:"severity"`
	Method   string     `json:"method"`
	Vector   string     `json:"vector"`
}

type cdxAnalysis struct {
	State         string   `json:"state"`
	Justification string   `json:"justification"`
	Response      []string `json:"response"`
	Detail        string   `json:"detail"`
}

type cdxAffects struct {
	Ref      string              `json:"ref"`
	Versions []cdxAffectsVersion `json:"versions"`
}

type cdxAffectsVersion struct {
	Version string `json:"version"`
	Range   string `json:"range"`
	Status  string `json:"status"`
}

// convertCycloneDX maps a CycloneDX document's vulnerabilities to findings. CycloneDX is already close to the API's shape, so this is mostly validation and normalisation: severities and methods onto the API's vocabulary, CWEs already numeric, and any embedded analysis validated the same way a VEX overlay is.
func convertCycloneDX(data []byte) (converted, error) {
	var doc cdxDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return converted{}, fmt.Errorf("parse CycloneDX report: %w", err)
	}

	var (
		out   []afclient.Vulnerability
		notes []string
	)
	for i, cv := range doc.Vulnerabilities {
		id := strings.TrimSpace(cv.ID)
		if id == "" {
			return converted{}, fmt.Errorf("CycloneDX vulnerability %d has no id", i)
		}
		v := afclient.Vulnerability{
			ID:          id,
			Source:      cdxSourceOf(cv),
			Ratings:     cdxRatings(cv.Ratings),
			CWEs:        cv.CWEs,
			Description: clipNoting(&notes, id, "description", cv.Description, afclient.MaxDescriptionLen),
			Published:   cv.Published,
			Updated:     cv.Updated,
		}
		if cv.Recommendation != "" {
			v.Recommendation = clipNoting(&notes, id, "recommendation", cv.Recommendation, afclient.MaxRecommendationLen)
		}
		if cv.Analysis != nil {
			a, err := mapAnalysis(id, *cv.Analysis, &notes)
			if err != nil {
				return converted{}, err
			}
			v.Analysis = &a
		}
		for _, af := range cv.Affects {
			ref := strings.TrimSpace(af.Ref)
			if ref == "" {
				continue
			}
			v.Affects = append(v.Affects, afclient.Affects{
				Ref:      clip(ref, afclient.MaxAffectsRefLen),
				Versions: cdxAffectedVersions(af.Versions),
			})
		}
		out = append(out, v)
	}
	return converted{findings: out, rawCount: len(doc.Vulnerabilities), notes: notes}, nil
}

// cdxAffectedVersions maps the affected version ranges CycloneDX records for a component, dropping an entry that carries nothing and any status the API does not accept. This is fidelity the scanner formats do not offer but CycloneDX can, so it is preserved rather than flattened to a bare component reference.
func cdxAffectedVersions(vs []cdxAffectsVersion) []afclient.AffectedVersion {
	var out []afclient.AffectedVersion
	for _, v := range vs {
		av := afclient.AffectedVersion{
			Version: clip(strings.TrimSpace(v.Version), afclient.MaxAffectedVersion),
			Range:   clip(strings.TrimSpace(v.Range), afclient.MaxAffectedRange),
			Status:  normaliseAffectedStatus(v.Status),
		}
		if av.Version == "" && av.Range == "" && av.Status == "" {
			continue
		}
		out = append(out, av)
	}
	return out
}

// normaliseAffectedStatus keeps a status the API accepts and omits anything else, rather than guessing.
func normaliseAffectedStatus(s string) string {
	v := strings.ToLower(strings.TrimSpace(s))
	if slices.Contains(afclient.AffectedStatuses, v) {
		return v
	}
	return ""
}

func cdxSourceOf(cv cdxVulnerability) *afclient.Source {
	var name, url string
	if cv.Source != nil {
		name, url = cv.Source.Name, cv.Source.URL
	}
	return deriveSource(cv.ID, name, url, "CycloneDX")
}

// cdxRatings normalises CycloneDX ratings onto the API's vocabulary, ordered NVD-first. A method the API does not accept (CycloneDX's "SSVC" or "other") is dropped in favour of one derived from the vector, or omitted.
func cdxRatings(rs []cdxRating) []afclient.Rating {
	var rated []ratedVendor
	for _, r := range rs {
		vendor := ""
		if r.Source != nil {
			vendor = r.Source.Name
		}
		rating := afclient.Rating{
			Score:    r.Score,
			Severity: normaliseCDXSeverity(r.Severity),
			Method:   normaliseCDXMethod(r.Method, r.Vector),
			Vector:   clip(r.Vector, afclient.MaxRatingVectorLen),
		}
		rated = append(rated, ratedVendor{vendor: vendor, rating: rating})
	}
	return orderRatings(rated)
}

// normaliseCDXSeverity maps a CycloneDX severity onto the API's set. CycloneDX uses the same words, so this is mostly a lower-case pass, with an unrecognised value becoming "unknown".
func normaliseCDXSeverity(s string) string {
	if strings.TrimSpace(s) == "" {
		return ""
	}
	return mapSeverity(s)
}

func normaliseCDXMethod(method, vector string) string {
	if slices.Contains(afclient.RatingMethods, method) {
		return method
	}
	return methodFromVector(vector)
}

// mapAnalysis validates and maps a CycloneDX analysis onto the API's, the shared core of both an embedded assessment and a VEX overlay. An unmappable state or justification is an error naming the finding rather than a silent drop, because a wrong suppression hides a real vulnerability.
func mapAnalysis(id string, a cdxAnalysis, notes *[]string) (afclient.Analysis, error) {
	state, ok := mapAnalysisState(a.State)
	if !ok {
		return afclient.Analysis{}, fmt.Errorf("finding %s: VEX state %q is not one the API accepts (%s)", id, a.State, strings.Join(afclient.AnalysisStates, ", "))
	}
	out := afclient.Analysis{State: state}

	if j := strings.TrimSpace(a.Justification); j != "" {
		if !slices.Contains(afclient.AnalysisJustifications, j) {
			return afclient.Analysis{}, fmt.Errorf("finding %s: VEX justification %q is not one the API accepts (%s)", id, a.Justification, strings.Join(afclient.AnalysisJustifications, ", "))
		}
		out.Justification = j
	}

	for _, r := range a.Response {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		if !slices.Contains(afclient.AnalysisResponses, r) {
			return afclient.Analysis{}, fmt.Errorf("finding %s: VEX response %q is not one the API accepts (%s)", id, r, strings.Join(afclient.AnalysisResponses, ", "))
		}
		out.Response = append(out.Response, r)
	}

	if a.Detail != "" {
		out.Detail = clipNoting(notes, id, "analysis detail", a.Detail, afclient.MaxAnalysisDetailLen)
	}
	return out, nil
}

// mapAnalysisState maps a CycloneDX VEX state onto the API's. CycloneDX's resolved_with_pedigree has no API equivalent and folds to resolved; an empty state is left empty for the caller to accept or reject by context. An unrecognised state is rejected.
func mapAnalysisState(s string) (string, bool) {
	switch strings.TrimSpace(s) {
	case "":
		return "", true
	case "resolved_with_pedigree":
		return "resolved", true
	case "exploitable", "in_triage", "resolved", "false_positive", "not_affected":
		return strings.TrimSpace(s), true
	}
	return "", false
}
