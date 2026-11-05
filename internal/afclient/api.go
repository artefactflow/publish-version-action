package afclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"path/filepath"
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

// maxImportAnswer bounds an import's answer. A dry run answers with every finding the report converted to, up to 5000, each with its description, so it is larger than any other answer this client reads.
const maxImportAnswer = 64 << 20

// ImportVulnerabilities sends a scanner report to the version's import endpoint, which detects its format, converts it, lays the VEX document over it and records the findings, replacing those of the same producer. Findings other producers recorded on the version are kept.
//
// The version is addressed by its SemVer string, not by an id. The files are sent as they were written, as multipart form data: no conversion happens here.
func (c *Client) ImportVulnerabilities(ctx context.Context, artefactID, versionValue string, in ImportRequest) (*ImportResult, error) {
	body, contentType, err := importBody(in)
	if err != nil {
		return nil, fmt.Errorf("import vulnerabilities for version %s: %w", versionValue, err)
	}
	q := url.Values{}
	if in.Format != "" {
		q.Set("format", in.Format)
	}
	if in.Producer != "" {
		q.Set("producer", in.Producer)
	}
	if in.ProducerVersion != "" {
		q.Set("producer_version", in.ProducerVersion)
	}
	if in.DryRun {
		q.Set("dry_run", "true")
	}
	u := c.baseURL + "/v1/artefacts/" + url.PathEscape(artefactID) + "/versions/" + url.PathEscape(versionValue) + "/vulnerabilities/import"
	if len(q) > 0 {
		u += "?" + q.Encode()
	}

	res, err := c.do(ctx, request{method: http.MethodPost, url: u, body: body, contentType: contentType, okStatus: []int{http.StatusOK}, maxResponse: maxImportAnswer})
	if err != nil {
		return nil, fmt.Errorf("import vulnerabilities for version %s: %w", versionValue, err)
	}
	if in.DryRun {
		return decodePreview(res.body)
	}
	// The findings are recorded once the API answers 200, so an answer this client cannot read is not a failure: the import still happened, and only the summary is missing from the log.
	return decodeRecorded(res.body), nil
}

// importBody renders the report and the VEX document as the multipart body the import endpoint takes. Each part is declared JSON, which is what the endpoint expects of both.
func importBody(in ImportRequest) ([]byte, string, error) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	parts := []struct {
		name, file string
		content    []byte
	}{{"report", in.ReportName, in.Report}}
	if in.VEX != nil {
		parts = append(parts, struct {
			name, file string
			content    []byte
		}{"vex", in.VEXName, in.VEX})
	}
	for _, p := range parts {
		h := textproto.MIMEHeader{}
		h.Set("Content-Disposition", fmt.Sprintf(`form-data; name=%q; filename=%q`, p.name, filepath.Base(p.file)))
		h.Set("Content-Type", "application/json")
		pw, err := w.CreatePart(h)
		if err != nil {
			return nil, "", err
		}
		if _, err := pw.Write(p.content); err != nil {
			return nil, "", err
		}
	}
	if err := w.Close(); err != nil {
		return nil, "", err
	}
	return buf.Bytes(), w.FormDataContentType(), nil
}

// preview is a dry run's answer.
type preview struct {
	Producer        string            `json:"producer"`
	ProducerVersion string            `json:"producer_version"`
	Vulnerabilities []json.RawMessage `json:"vulnerabilities"`
	Import          ImportSummary     `json:"import"`
}

// decodePreview reads a dry run's answer. Unlike a recording import, nothing happened if it cannot be read, and the document is the whole point of asking for one, so an unreadable answer is an error.
func decodePreview(body []byte) (*ImportResult, error) {
	var p preview
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, fmt.Errorf("read the dry-run answer: %w", err)
	}
	return &ImportResult{
		Producer:        p.Producer,
		ProducerVersion: p.ProducerVersion,
		Findings:        len(p.Vulnerabilities),
		Import:          p.Import,
		Document:        json.RawMessage(body),
	}, nil
}

// recorded is the answer of an import that recorded: the first page of the version's findings, their total, and what the import read. Only the total and the summary are read here.
type recorded struct {
	Metadata struct {
		TotalRecords int `json:"total_records"`
	} `json:"metadata"`
	Producer struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"producer"`
	Import ImportSummary `json:"import"`
}

// decodeRecorded reads what it can of a recording import's answer.
func decodeRecorded(body []byte) *ImportResult {
	var r recorded
	if err := json.Unmarshal(body, &r); err != nil {
		return &ImportResult{}
	}
	return &ImportResult{
		Producer:        r.Producer.Name,
		ProducerVersion: r.Producer.Version,
		VersionFindings: r.Metadata.TotalRecords,
		Import:          r.Import,
	}
}
