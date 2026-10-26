package convert

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/artefactflow/publish-version-action/internal/afclient"
)

// ratedVendor pairs a rating with the vendor that scored it, so a finding's ratings can be ordered NVD-first before the vendor label (which the API's rating carries nowhere) is discarded.
type ratedVendor struct {
	vendor string
	rating afclient.Rating
}

// orderRatings returns the ratings ordered with NVD first, then remaining vendors alphabetically, dropping the vendor label the API does not model. Scanners key CVSS by vendor and there is no provenance field on the rating, so order is the only signal left; leading with NVD makes the primary score predictable.
func orderRatings(rs []ratedVendor) []afclient.Rating {
	sort.SliceStable(rs, func(i, j int) bool {
		ni, nj := isNVD(rs[i].vendor), isNVD(rs[j].vendor)
		if ni != nj {
			return ni
		}
		return rs[i].vendor < rs[j].vendor
	})
	out := make([]afclient.Rating, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.rating)
	}
	return out
}

func isNVD(vendor string) bool {
	v := strings.ToLower(vendor)
	return strings.HasPrefix(v, "nvd") || strings.Contains(v, "nist")
}

// mergeByIdentifier collapses the per-(vulnerability × component) entries a scanner emits into one finding per identifier, gathering the components into affects[]. Scanners report the same CVE once per affected package; the API models it once with affects[] listing them, and emitting the duplicates instead would leave the endpoint's dedupe deciding what is recorded.
//
// The first occurrence of an identifier sets the finding's scalar fields; later occurrences contribute only their affected component and fill any field the first left empty. Input order is preserved so the output is stable and diffable.
func mergeByIdentifier(vs []afclient.Vulnerability) []afclient.Vulnerability {
	order := make([]string, 0, len(vs))
	byID := make(map[string]*afclient.Vulnerability, len(vs))
	for i := range vs {
		v := vs[i]
		cur, ok := byID[v.ID]
		if !ok {
			cp := v
			byID[v.ID] = &cp
			order = append(order, v.ID)
			continue
		}
		cur.Affects = mergeAffects(cur.Affects, v.Affects)
		fillEmpty(cur, v)
	}
	out := make([]afclient.Vulnerability, 0, len(order))
	for _, id := range order {
		out = append(out, *byID[id])
	}
	return out
}

// ratingRichness scores a rating set so the fuller one can be preferred when the same finding is scored differently across the packages it affects. A rating carrying a CVSS vector or method counts for more than a bare severity label.
func ratingRichness(rs []afclient.Rating) int {
	score := 0
	for _, r := range rs {
		if r.Vector != "" || r.Method != "" {
			score += 2
		} else {
			score++
		}
	}
	return score
}

// mergeAffects unions two affects lists, keyed by component ref, preserving order and dropping a duplicate component.
func mergeAffects(a, b []afclient.Affects) []afclient.Affects {
	seen := make(map[string]bool, len(a)+len(b))
	out := make([]afclient.Affects, 0, len(a)+len(b))
	for _, list := range [][]afclient.Affects{a, b} {
		for _, af := range list {
			if af.Ref != "" && seen[af.Ref] {
				continue
			}
			if af.Ref != "" {
				seen[af.Ref] = true
			}
			out = append(out, af)
		}
	}
	return out
}

// fillEmpty copies fields from a later occurrence of the same identifier into the accumulated finding only where the accumulated one is still empty, so a component entry that happened to carry a description the first did not still contributes it. Ratings are the exception: a later occurrence with richer scores (a CVSS vector where the first had only a severity) replaces the poorer set, so the order packages happened to appear in does not decide which score is recorded.
func fillEmpty(dst *afclient.Vulnerability, src afclient.Vulnerability) {
	if ratingRichness(src.Ratings) > ratingRichness(dst.Ratings) {
		dst.Ratings = src.Ratings
	}
	if dst.Description == "" {
		dst.Description = src.Description
	}
	if dst.Recommendation == "" {
		dst.Recommendation = src.Recommendation
	}
	if len(dst.CWEs) == 0 {
		dst.CWEs = src.CWEs
	}
	if dst.Published == "" {
		dst.Published = src.Published
	}
	if dst.Updated == "" {
		dst.Updated = src.Updated
	}
	if dst.Source == nil {
		dst.Source = src.Source
	}
}

// Encode marshals converted findings into the request body the upload endpoint expects. Each finding is checked against the API's required fields first, so a bug in a converter surfaces here as a named error rather than as a rejected request after the version has been created.
func Encode(findings []afclient.Vulnerability) (afclient.VulnerabilitiesInput, error) {
	entries := make([]json.RawMessage, 0, len(findings))
	for i, f := range findings {
		if strings.TrimSpace(f.ID) == "" {
			return afclient.VulnerabilitiesInput{}, fmt.Errorf("converted finding %d has no id", i)
		}
		if f.Source == nil || strings.TrimSpace(f.Source.Name) == "" {
			return afclient.VulnerabilitiesInput{}, fmt.Errorf("converted finding %s has no source name, which the API requires", f.ID)
		}
		raw, err := json.Marshal(f)
		if err != nil {
			return afclient.VulnerabilitiesInput{}, fmt.Errorf("encode converted finding %s: %w", f.ID, err)
		}
		entries = append(entries, raw)
	}
	return afclient.VulnerabilitiesInput{Vulnerabilities: entries}, nil
}
