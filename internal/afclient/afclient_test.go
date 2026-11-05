package afclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

const testArtefactID = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b"

func newTestClient(t *testing.T, h http.Handler, opts ...Option) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	// Retries are disabled by default here so a case expecting one failure sees exactly one request.
	c, err := New(srv.URL, "minted-jwt", append([]Option{WithHTTPClient(srv.Client()), WithRetry(1, 0, 0)}, opts...)...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestNewRequiresBaseURLAndToken(t *testing.T) {
	if _, err := New("", "token"); err == nil {
		t.Error("New accepted an empty base URL; the operator must always supply it")
	}
	if _, err := New("https://api.example", ""); err == nil {
		t.Error("New accepted an empty token")
	}
}

func TestResolveArtefactID(t *testing.T) {
	var gotPath, gotQuery string
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotQuery = r.URL.Path, r.URL.RawQuery
		io.WriteString(w, `{"id":"`+testArtefactID+`","name":"acme-payment-service"}`)
	}))

	id, err := c.ResolveArtefactID(context.Background(), "acme-payment-service")
	if err != nil {
		t.Fatalf("ResolveArtefactID: %v", err)
	}
	if id != testArtefactID {
		t.Errorf("id = %q", id)
	}
	if gotPath != "/v1/artefacts/resolve" || gotQuery != "name=acme-payment-service" {
		t.Errorf("request = %s?%s", gotPath, gotQuery)
	}
}

func TestResolveArtefactIDRejectsAnEmptyID(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"name":"acme-payment-service"}`)
	}))
	// Carrying on with an empty id would build a nonsense URL and fail somewhere far less obvious.
	if _, err := c.ResolveArtefactID(context.Background(), "acme-payment-service"); err == nil {
		t.Fatal("ResolveArtefactID succeeded on a response carrying no id")
	}
}

func TestCreateVersionSendsBearerTokenAndBody(t *testing.T) {
	var (
		gotAuth, gotPath, gotMethod string
		gotBody                     VersionInput
	)
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotPath, gotMethod = r.Header.Get("Authorization"), r.URL.Path, r.Method
		json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Location", "/v1/artefacts/"+testArtefactID+"/versions/1.4.2")
		w.WriteHeader(http.StatusCreated)
		io.WriteString(w, `{"id":"0199a1b2-d5e6-7f80-9a1b-2c3d4e5f6a7b","artefact_id":"`+testArtefactID+`","version":"1.4.2"}`)
	}))

	v, location, err := c.CreateVersion(context.Background(), testArtefactID, VersionInput{Version: "1.4.2", Builder: "github-actions"})
	if err != nil {
		t.Fatalf("CreateVersion: %v", err)
	}
	if gotAuth != "Bearer minted-jwt" {
		t.Errorf("Authorization = %q", gotAuth)
	}
	if gotMethod != http.MethodPost || gotPath != "/v1/artefacts/"+testArtefactID+"/versions" {
		t.Errorf("request = %s %s", gotMethod, gotPath)
	}
	if gotBody.Version != "1.4.2" || gotBody.Builder != "github-actions" {
		t.Errorf("body = %+v", gotBody)
	}
	if v.Version != "1.4.2" || location == "" {
		t.Errorf("version = %+v, location = %q", v, location)
	}
}

func TestCreateVersionOmitsUnsetOptionalFields(t *testing.T) {
	var raw map[string]any
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&raw)
		w.WriteHeader(http.StatusCreated)
		io.WriteString(w, `{}`)
	}))
	if _, _, err := c.CreateVersion(context.Background(), testArtefactID, VersionInput{Version: "1.4.2"}); err != nil {
		t.Fatalf("CreateVersion: %v", err)
	}
	// Sending `"branch": ""` would overwrite a meaningful value; an unset field must not appear at all.
	for _, absent := range []string{"branch", "note", "commit_sha", "bom_ref", "is_default", "hash", "lifecycle"} {
		if _, ok := raw[absent]; ok {
			t.Errorf("body contains %q, want it omitted when unset", absent)
		}
	}
}

func TestCreateVersionFallsBackWhenTheResponseBodyIsUnhelpful(t *testing.T) {
	// A create that stores correctly but answers with a shape we do not recognise is still a successful create.
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		io.WriteString(w, `not json at all`)
	}))
	v, _, err := c.CreateVersion(context.Background(), testArtefactID, VersionInput{Version: "1.4.2"})
	if err != nil {
		t.Fatalf("CreateVersion: %v", err)
	}
	if v.Version != "1.4.2" || v.ArtefactID != testArtefactID {
		t.Errorf("version = %+v, want the requested values echoed back", v)
	}
}

// A conflict is the one failure the caller acts on programmatically, so it has to be matchable rather than only readable.
func TestCreateVersionConflictIsMatchable(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		io.WriteString(w, `{"code":"VERSION00409","message":"already exists","log_id":"abc123"}`)
	}))
	_, _, err := c.CreateVersion(context.Background(), testArtefactID, VersionInput{Version: "1.4.2"})
	if !errors.Is(err, ErrVersionExists) {
		t.Fatalf("error = %v, want it to match ErrVersionExists", err)
	}
	var se *StatusError
	if !errors.As(err, &se) || se.Status != http.StatusConflict || se.LogID != "abc123" {
		t.Errorf("the API's own error envelope was lost: %v", err)
	}
}

func TestStatusErrorsAreActionable(t *testing.T) {
	tests := []struct {
		status int
		body   string
		want   string
	}{
		{http.StatusPaymentRequired, `{"code":"PLAN00402","message":"Over plan limit"}`, "over its plan limit"},
		{http.StatusForbidden, `{"code":"AUTH00403","message":"Forbidden"}`, "team with write access"},
		// Three different calls can 404, so the message stays neutral and each caller supplies the context.
		{http.StatusNotFound, `{"code":"ARTEFACT00509","message":"Not found"}`, "not found on this instance"},
		{http.StatusConflict, `{"code":"VERSION00409","message":"Exists"}`, "already exists"},
		{http.StatusBadRequest, `{"code":"GEN00001","message":"Bad request"}`, "HTTP 400"},
	}
	for _, tc := range tests {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.body)
			}))
			_, _, err := c.CreateVersion(context.Background(), testArtefactID, VersionInput{Version: "1.4.2"})
			if err == nil {
				t.Fatalf("CreateVersion succeeded on a %d", tc.status)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

// A 403 satisfies both authorization axes, and the scope is the one people check first: the team layer has to be named explicitly.
func TestForbiddenNamesBothAuthorizationAxes(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		io.WriteString(w, `{"code":"AUTH00403","message":"Forbidden","log_id":"xyz"}`)
	}))
	_, _, err := c.CreateVersion(context.Background(), testArtefactID, VersionInput{Version: "1.4.2"})
	if err == nil {
		t.Fatal("CreateVersion succeeded on a 403")
	}
	for _, want := range []string{"version:write", "artefact:read", "team"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %v, want it to mention %q", err, want)
		}
	}
}

// A body that is not the documented envelope (a proxy's HTML error page, say) still has to produce a usable message.
func TestStatusErrorFallsBackToASnippet(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		io.WriteString(w, `<html><body>502 Bad Gateway</body></html>`)
	}), WithRetry(1, 0, 0))
	_, _, err := c.CreateVersion(context.Background(), testArtefactID, VersionInput{Version: "1.4.2"})
	if err == nil || !strings.Contains(err.Error(), "502 Bad Gateway") {
		t.Fatalf("error = %v, want it to quote the raw body", err)
	}
}

func TestErrorsNeverContainTheToken(t *testing.T) {
	const token = "super-secret-token-value"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		// A careless API echoing the request headers back must not turn into a leak either.
		io.WriteString(w, `{"code":"GEN00001","message":"bad request from `+r.Header.Get("Authorization")+`"}`)
	}))
	defer srv.Close()
	c, err := New(srv.URL, token, WithHTTPClient(srv.Client()), WithRetry(1, 0, 0))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, _, err = c.CreateVersion(context.Background(), testArtefactID, VersionInput{Version: "1.4.2"})
	if err == nil {
		t.Fatal("CreateVersion succeeded on a 400")
	}
	if strings.Contains(err.Error(), token) {
		t.Fatalf("the token leaked into an error message: %v", err)
	}
}

// importRequestSeen is what the import endpoint received, decoded from the multipart body.
type importRequestSeen struct {
	method, path string
	query        url.Values
	parts        map[string]string
	partTypes    map[string]string
	fileNames    map[string]string
}

func readImport(t *testing.T, r *http.Request) importRequestSeen {
	t.Helper()
	seen := importRequestSeen{method: r.Method, path: r.URL.Path, query: r.URL.Query(), parts: map[string]string{}, partTypes: map[string]string{}, fileNames: map[string]string{}}
	mr, err := r.MultipartReader()
	if err != nil {
		t.Errorf("the import was not sent as multipart form data: %v", err)
		return seen
	}
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Errorf("read part: %v", err)
			break
		}
		content, _ := io.ReadAll(p)
		seen.parts[p.FormName()] = string(content)
		seen.partTypes[p.FormName()] = p.Header.Get("Content-Type")
		seen.fileNames[p.FormName()] = p.FileName()
	}
	return seen
}

func TestImportVulnerabilitiesSendsTheReportAsItWasWritten(t *testing.T) {
	var seen importRequestSeen
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = readImport(t, r)
		io.WriteString(w, `{"metadata":{"total_records":12},"vulnerabilities":[],"producer":{"name":"trivy","version":"0.58.1"},"import":{"format":"trivy","vex_matched":1,"vex_unmatched":["CVE-2024-1"],"skipped_rules":1,"skipped_rule_ids":["DS002"]}}`)
	}))

	report := `{"SchemaVersion":2,"Results":[]}`
	res, err := c.ImportVulnerabilities(context.Background(), testArtefactID, "1.4.2", ImportRequest{
		Report: []byte(report), ReportName: "out/trivy.json",
		VEX: []byte(`{"bomFormat":"CycloneDX"}`), VEXName: "vex.json",
	})
	if err != nil {
		t.Fatalf("ImportVulnerabilities: %v", err)
	}
	if seen.method != http.MethodPost || seen.path != "/v1/artefacts/"+testArtefactID+"/versions/1.4.2/vulnerabilities/import" {
		t.Errorf("request = %s %s, want POST to the version's import endpoint, addressed by its SemVer string", seen.method, seen.path)
	}
	// The report travels byte for byte: converting it is the API's job, not this client's.
	if seen.parts["report"] != report {
		t.Errorf("report part = %q, want the file exactly as written", seen.parts["report"])
	}
	if seen.parts["vex"] == "" || seen.partTypes["report"] != "application/json" || seen.partTypes["vex"] != "application/json" {
		t.Errorf("parts = %v with types %v, want a report and a vex part, both JSON", seen.parts, seen.partTypes)
	}
	// Only the base name: a runner's workspace path is nobody else's business.
	if seen.fileNames["report"] != "trivy.json" {
		t.Errorf("report filename = %q, want the base name", seen.fileNames["report"])
	}
	if len(seen.query) != 0 {
		t.Errorf("query = %v, want none when nothing is forced", seen.query)
	}
	want := ImportResult{Producer: "trivy", ProducerVersion: "0.58.1", VersionFindings: 12, Import: ImportSummary{Format: "trivy", VEXMatched: 1, VEXUnmatched: []string{"CVE-2024-1"}, SkippedRules: 1, SkippedRuleIDs: []string{"DS002"}}}
	if !reflect.DeepEqual(*res, want) {
		t.Errorf("result = %+v, want %+v", *res, want)
	}
}

func TestImportVulnerabilitiesPassesTheOptions(t *testing.T) {
	var seen importRequestSeen
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = readImport(t, r)
		io.WriteString(w, `{"producer":"image-scan","vulnerabilities":[{"id":"CVE-1"},{"id":"CVE-2"}],"import":{"format":"trivy","vex_matched":0}}`)
	}))

	res, err := c.ImportVulnerabilities(context.Background(), testArtefactID, "1.4.2", ImportRequest{Report: []byte(`{}`), ReportName: "r.json", Format: "trivy", Producer: "image-scan", ProducerVersion: "0.58.1 (patched)", DryRun: true})
	if err != nil {
		t.Fatalf("ImportVulnerabilities: %v", err)
	}
	for key, want := range map[string]string{"format": "trivy", "producer": "image-scan", "producer_version": "0.58.1 (patched)", "dry_run": "true"} {
		if got := seen.query.Get(key); got != want {
			t.Errorf("query %s = %q, want %q", key, got, want)
		}
	}
	if _, ok := seen.parts["vex"]; ok {
		t.Error("a vex part was sent without a VEX document")
	}
	// A dry run's answer is handed back whole, so the caller can write out exactly what would be recorded.
	if res.Findings != 2 || res.Producer != "image-scan" || !strings.Contains(string(res.Document), `"CVE-2"`) {
		t.Errorf("result = %+v, want the dry run's findings and document", res)
	}
}

// The findings are recorded once the API says 200. An answer the client cannot read must not turn that into a failure, or a re-run would import the report a second time for nothing.
func TestImportVulnerabilitiesToleratesAnUnreadableAnswer(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `not json`)
	}))
	if _, err := c.ImportVulnerabilities(context.Background(), testArtefactID, "1.4.2", ImportRequest{Report: []byte(`{}`), ReportName: "r.json"}); err != nil {
		t.Fatalf("ImportVulnerabilities failed on a 200: %v", err)
	}
	// A dry run is different: nothing was recorded, and the document is what was asked for.
	if _, err := c.ImportVulnerabilities(context.Background(), testArtefactID, "1.4.2", ImportRequest{Report: []byte(`{}`), ReportName: "r.json", DryRun: true}); err == nil {
		t.Fatal("a dry run with an unreadable answer succeeded")
	}
}

// A refused report is answered with the finding and field at fault in the details, and those are what tell the workflow author what to fix.
func TestImportRefusalQuotesTheDetails(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		details := make([]string, 0, 7)
		for i := range 7 {
			details = append(details, fmt.Sprintf(`{"field":"vulnerabilities[CVE-%d].description","issue":"must be at most 8192 characters"}`, i))
		}
		io.WriteString(w, `{"code":"VULN00001","message":"The report was refused","log_id":"abc123","details":[`+strings.Join(details, ",")+`]}`)
	}))
	_, err := c.ImportVulnerabilities(context.Background(), testArtefactID, "1.4.2", ImportRequest{Report: []byte(`{}`), ReportName: "r.json"})
	if err == nil {
		t.Fatal("ImportVulnerabilities succeeded on a 400")
	}
	for _, want := range []string{"The report was refused", "vulnerabilities[CVE-0].description: must be at most 8192 characters", "and 2 more", "log id abc123"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %v, want it to mention %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "CVE-5") {
		t.Errorf("error = %v, want only the first details quoted", err)
	}
}

func TestOversizedRequestNamesTheLimit(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		io.WriteString(w, `<html><body>413 Request Entity Too Large</body></html>`)
	}))
	_, err := c.ImportVulnerabilities(context.Background(), testArtefactID, "1.4.2", ImportRequest{Report: []byte(`{}`), ReportName: "r.json"})
	if err == nil || !strings.Contains(err.Error(), "at most 32 MiB") {
		t.Errorf("error = %v, want it to state the limit", err)
	}
}

// ArtefactFlow's own 413 says which limit was hit, which may be the converted findings of a report well under 32 MiB, so its reason is quoted rather than a size the report does not exceed.
func TestOversizedFindingsQuoteArtefactFlowsReason(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		io.WriteString(w, `{"code":"GEN00009","message":"The request is too large; reduce its size and try again","log_id":"abc123","details":[{"field":"report","issue":"the report converts to more than 4194304 bytes of findings"}]}`)
	}))
	_, err := c.ImportVulnerabilities(context.Background(), testArtefactID, "1.4.2", ImportRequest{Report: []byte(`{}`), ReportName: "r.json"})
	if err == nil {
		t.Fatal("want an error")
	}
	for _, want := range []string{"refused the import as too large", "report: the report converts to more than 4194304 bytes of findings", "log id abc123"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %v, want it to mention %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "at most 32 MiB") {
		t.Errorf("error = %v, want no claim about a request size the report does not exceed", err)
	}
}

// An import ArtefactFlow is too busy to convert (429 with Retry-After) is retried, and succeeds once there is room.
func TestBusyImportIsRetried(t *testing.T) {
	var attempts int
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			io.WriteString(w, `{"code":"GEN00011","message":"Too many requests; please try again later"}`)
			return
		}
		io.WriteString(w, `{"metadata":{"total_records":0}}`)
	}), WithRetry(3, time.Millisecond, 2*time.Millisecond))
	if _, err := c.ImportVulnerabilities(context.Background(), testArtefactID, "1.4.2", ImportRequest{Report: []byte(`{"matches":[]}`), ReportName: "grype.json"}); err != nil {
		t.Fatalf("ImportVulnerabilities: %v", err)
	}
	if attempts != 2 {
		t.Errorf("attempts = %d, want the busy answer retried once", attempts)
	}
}

// A retried import must present the same multipart body, report included, on every attempt.
func TestRetriedImportKeepsItsBody(t *testing.T) {
	var attempts int
	var last importRequestSeen
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		last = readImport(t, r)
		if attempts < 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		io.WriteString(w, `{"metadata":{"total_records":0}}`)
	}), WithRetry(3, time.Millisecond, 2*time.Millisecond))

	if _, err := c.ImportVulnerabilities(context.Background(), testArtefactID, "1.4.2", ImportRequest{Report: []byte(`{"matches":[]}`), ReportName: "grype.json"}); err != nil {
		t.Fatalf("ImportVulnerabilities: %v", err)
	}
	if attempts != 2 || last.parts["report"] != `{"matches":[]}` {
		t.Errorf("attempts = %d, last report = %q, want the report intact on the retry", attempts, last.parts["report"])
	}
}

func TestRetriesTransientFailuresThenSucceeds(t *testing.T) {
	var attempts int
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusCreated)
		io.WriteString(w, `{"version":"1.4.2"}`)
	}), WithRetry(3, time.Millisecond, 2*time.Millisecond))

	if _, _, err := c.CreateVersion(context.Background(), testArtefactID, VersionInput{Version: "1.4.2"}); err != nil {
		t.Fatalf("CreateVersion: %v", err)
	}
	if attempts != 3 {
		t.Errorf("attempts = %d, want the two 503s retried", attempts)
	}
}

func TestDoesNotRetryPermanentFailures(t *testing.T) {
	var attempts int
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusConflict)
		io.WriteString(w, `{"code":"VERSION00409","message":"exists"}`)
	}), WithRetry(3, time.Millisecond, 2*time.Millisecond))

	_, _, err := c.CreateVersion(context.Background(), testArtefactID, VersionInput{Version: "1.4.2"})
	if !errors.Is(err, ErrVersionExists) {
		t.Fatalf("error = %v", err)
	}
	// Replaying a create the API has already rejected as a duplicate wastes time and tells us nothing new.
	if attempts != 1 {
		t.Errorf("attempts = %d, want a conflict to fail immediately", attempts)
	}
}

func TestCancelledContextIsNotRetried(t *testing.T) {
	var attempts int
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusServiceUnavailable)
	}), WithRetry(5, time.Millisecond, time.Millisecond))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := c.CreateVersion(ctx, testArtefactID, VersionInput{Version: "1.4.2"}); err == nil {
		t.Fatal("CreateVersion succeeded with a cancelled context")
	}
	if attempts > 1 {
		t.Errorf("attempts = %d, want a cancelled context to stop immediately", attempts)
	}
}

// A retried write must present the same body on every attempt, or a replay would create something different from what was asked for.
func TestRetriedWriteKeepsItsBody(t *testing.T) {
	var attempts int
	var lastBody VersionInput
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		json.NewDecoder(r.Body).Decode(&lastBody)
		if attempts < 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusCreated)
		io.WriteString(w, `{"version":"1.4.2"}`)
	}), WithRetry(3, time.Millisecond, 2*time.Millisecond))

	if _, _, err := c.CreateVersion(context.Background(), testArtefactID, VersionInput{Version: "1.4.2", Builder: "github-actions"}); err != nil {
		t.Fatalf("CreateVersion: %v", err)
	}
	if lastBody.Version != "1.4.2" || lastBody.Builder != "github-actions" {
		t.Errorf("the replayed request lost its body: %+v", lastBody)
	}
}

func TestRetryPolicyDelayHonoursRetryAfterAndCeiling(t *testing.T) {
	p := retryPolicy{maxAttempts: 5, baseDelay: 100 * time.Millisecond, maxDelay: time.Second, maxRetryAfter: 3 * time.Second}
	if got := p.delay(0, 2*time.Second); got != 2*time.Second {
		t.Errorf("delay with a Retry-After over maxDelay = %v, want it honoured: maxDelay bounds the client's own backoff, not the server's request", got)
	}
	if got := p.delay(0, 10*time.Second); got != 3*time.Second {
		t.Errorf("delay with a long Retry-After = %v, want it capped at maxRetryAfter", got)
	}
	// Full jitter puts the backoff in [d/2, d]; the point is that it never exceeds the ceiling.
	for attempt := range 6 {
		if got := p.delay(attempt, 0); got > time.Second {
			t.Errorf("delay(%d) = %v, want at most maxDelay", attempt, got)
		}
	}
}

// ArtefactFlow's import gate answers 429 with `Retry-After: 10`. Cutting that to the backoff ceiling would spend the next attempt on a request the server already said it would refuse, and three attempts would be gone in seconds.
func TestDefaultRetryHonoursTheImportGatesRetryAfter(t *testing.T) {
	p := defaultRetry()
	if got := p.delay(0, 10*time.Second); got != 10*time.Second {
		t.Errorf("default delay for Retry-After: 10 = %v, want 10s", got)
	}
	if got := p.delay(0, 60*time.Second); got != 30*time.Second {
		t.Errorf("default delay for Retry-After: 60 = %v, want it capped at 30s so one API cannot stall the job", got)
	}
	for attempt := range 6 {
		if got := p.delay(attempt, 0); got > p.maxDelay {
			t.Errorf("default backoff delay(%d) = %v, want at most %v", attempt, got, p.maxDelay)
		}
	}
}

// WithRetry is how tests make a retry fast; a server answering with Retry-After must not slow them down past the ceiling they set.
func TestWithRetryCapsRetryAfterAtItsCeiling(t *testing.T) {
	c, err := New("http://af.example", "tok", WithRetry(3, time.Millisecond, 2*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	if got := c.retry.delay(0, 10*time.Second); got != 2*time.Millisecond {
		t.Errorf("delay = %v, want a WithRetry policy to cap Retry-After at its maxDelay", got)
	}
}

// A create that fails transiently and then reports a conflict is almost certainly the first attempt's own write landing after its response was lost. Reporting that as "the version already exists" fails a pipeline that published correctly, and tells it to set `if-exists: skip` for a duplicate it never made.
func TestConflictAfterARetryIsTreatedAsThisRunsOwnCreate(t *testing.T) {
	var attempts int
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			// The write lands, but the response never reaches the client.
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusConflict)
		io.WriteString(w, `{"code":"VERSION00409","message":"already exists"}`)
	}), WithRetry(3, time.Millisecond, 2*time.Millisecond))

	v, _, err := c.CreateVersion(context.Background(), testArtefactID, VersionInput{Version: "1.4.2"})
	if !CreatedByOwnRetry(err) {
		t.Fatalf("error = %v, want it reported as created by this call's own retry", err)
	}
	if errors.Is(err, ErrVersionExists) {
		t.Error("the retried conflict is still matching ErrVersionExists, so `if-exists: fail` would reject a version this run created")
	}
	if v == nil || v.Version != "1.4.2" {
		t.Errorf("version = %+v, want the requested version usable for the vulnerability upload", v)
	}
}

// A conflict on the very first attempt is a genuine duplicate: nothing this run did could have created it.
func TestConflictWithoutARetryIsAGenuineDuplicate(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		io.WriteString(w, `{"code":"VERSION00409","message":"already exists"}`)
	}), WithRetry(3, time.Millisecond, 2*time.Millisecond))

	_, _, err := c.CreateVersion(context.Background(), testArtefactID, VersionInput{Version: "1.4.2"})
	if !errors.Is(err, ErrVersionExists) {
		t.Fatalf("error = %v, want ErrVersionExists", err)
	}
	if CreatedByOwnRetry(err) {
		t.Error("a first-attempt conflict was mistaken for this run's own create, which would defeat `if-exists: fail`")
	}
}
