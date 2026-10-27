package afclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

// ErrVersionExists reports that the version already exists on the artefact. It is separated from other failures because it is the one error a pipeline may legitimately want to treat as success: a re-run of the same build should not have to fail.
var ErrVersionExists = errors.New("version already exists")

// ErrCreatedByOwnRetry is returned alongside a usable Version when the create reported a conflict only after an earlier attempt had failed transiently. It is not a failure: the version exists because this call put it there. It is a distinct value rather than a plain nil so the caller can say so in the log. The alternative reading, that the version pre-dated this run, cannot be ruled out from the outside.
var ErrCreatedByOwnRetry = errors.New("the version was created by an earlier attempt of this same request, whose response was lost")

// CreatedByOwnRetry reports whether err is the not-really-an-error above.
func CreatedByOwnRetry(err error) bool { return errors.Is(err, ErrCreatedByOwnRetry) }

// artefactRef is the resolve endpoint's response: a minimal reference to one artefact.
type artefactRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// ResolveArtefactID turns an artefact name into its id. The match is exact and case-sensitive, and a name is unique within an organisation. Which organisation that is comes from the token, so no further qualifier is needed.
//
// This is a separate call from the write endpoints, and it needs its own scope: artefact:read here, version:write to create the version.
func (c *Client) ResolveArtefactID(ctx context.Context, name string) (string, error) {
	q := url.Values{}
	q.Set("name", name)

	var ref artefactRef
	if err := c.getJSON(ctx, "/v1/artefacts/resolve", q, &ref); err != nil {
		return "", fmt.Errorf("resolve artefact %q: %w", name, err)
	}
	if ref.ID == "" {
		return "", fmt.Errorf("resolve artefact %q: response contained no id", name)
	}
	return ref.ID, nil
}

// CreateVersion creates a version on the artefact and returns the created version along with the value of the Location header, which points at the new version's URL.
//
// A 409 becomes ErrVersionExists so the caller can honour the `if-exists` input, unless it arrived on a retry, in which case it is this call's own earlier attempt landing. See ErrCreatedByOwnRetry.
func (c *Client) CreateVersion(ctx context.Context, artefactID string, in VersionInput) (*Version, string, error) {
	path := "/v1/artefacts/" + url.PathEscape(artefactID) + "/versions"
	res, err := c.sendJSON(ctx, http.MethodPost, path, in, http.StatusCreated, http.StatusOK)
	if err != nil {
		var se *StatusError
		if errors.As(err, &se) && se.Status == http.StatusConflict {
			if se.AfterRetry {
				// The first attempt failed transiently, and the version now exists. Overwhelmingly the likeliest explanation is that the first attempt's write did land and only its response was lost: a genuine duplicate would have been rejected on the first attempt, before any retry. Reporting failure here would fail a pipeline that published correctly, and would skip the vulnerability upload for a version that exists.
				return &Version{ArtefactID: artefactID, Version: in.Version}, "", ErrCreatedByOwnRetry
			}
			return nil, "", fmt.Errorf("%w: %w", ErrVersionExists, se)
		}
		return nil, "", fmt.Errorf("create version %s: %w", in.Version, err)
	}

	var v Version
	// A create that stores correctly but answers with a shape we do not recognise is still a successful create; the Location header and the requested version string carry everything the action needs, so a decode failure is not fatal here.
	_ = json.Unmarshal(res.body, &v)
	if v.Version == "" {
		v.Version = in.Version
	}
	if v.ArtefactID == "" {
		v.ArtefactID = artefactID
	}
	return &v, res.header.Get("Location"), nil
}

// ReplaceVulnerabilities replaces the complete vulnerability set recorded for a version. The endpoint is a full replace, not an append: the payload must be the scanner's entire list, and anything previously recorded and absent from it is removed.
//
// The version is addressed by its SemVer string, not by an id.
func (c *Client) ReplaceVulnerabilities(ctx context.Context, artefactID, versionValue string, in VulnerabilitiesInput) error {
	path := "/v1/artefacts/" + url.PathEscape(artefactID) + "/versions/" + url.PathEscape(versionValue) + "/vulnerabilities"
	// A clean scan must clear the version's findings, so an empty set is sent as `[]` rather than the `null` a nil slice would marshal to. Reaching here with a nil slice means the caller explicitly asked for an empty set; a report that merely failed to mention one is refused before this point.
	if in.Vulnerabilities == nil {
		in.Vulnerabilities = []json.RawMessage{}
	}
	// The endpoint reports success as 200 with the stored set; 201 and 204 are accepted too rather than failing a write that actually landed.
	if _, err := c.sendJSON(ctx, http.MethodPut, path, in, http.StatusOK, http.StatusCreated, http.StatusNoContent); err != nil {
		return fmt.Errorf("upload vulnerabilities for version %s: %w", versionValue, err)
	}
	return nil
}
