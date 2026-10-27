package afclient

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
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
		io.WriteString(w, `{"code":"VERSION00409","message":"already exists","logid":"abc123"}`)
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
		io.WriteString(w, `{"code":"AUTH00403","message":"Forbidden","logid":"xyz"}`)
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

func TestReplaceVulnerabilitiesAddressesVersionBySemVer(t *testing.T) {
	var gotPath, gotMethod string
	var gotBody VulnerabilitiesInput
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		json.NewDecoder(r.Body).Decode(&gotBody)
		io.WriteString(w, `{"metadata":{"total_records":1}}`)
	}))

	in := VulnerabilitiesInput{Vulnerabilities: []json.RawMessage{json.RawMessage(`{"id":"CVE-2023-44487","source":{"name":"NVD"}}`)}}
	if err := c.ReplaceVulnerabilities(context.Background(), testArtefactID, "1.4.2", in); err != nil {
		t.Fatalf("ReplaceVulnerabilities: %v", err)
	}
	if gotMethod != http.MethodPut {
		t.Errorf("method = %s, want PUT: the endpoint replaces the whole set", gotMethod)
	}
	if gotPath != "/v1/artefacts/"+testArtefactID+"/versions/1.4.2/vulnerabilities" {
		t.Errorf("path = %q, want the version addressed by its SemVer string", gotPath)
	}
	if len(gotBody.Vulnerabilities) != 1 {
		t.Errorf("body = %+v", gotBody)
	}
}

func TestReplaceVulnerabilitiesSendsAnEmptySetExplicitly(t *testing.T) {
	var raw map[string]json.RawMessage
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&raw)
		w.WriteHeader(http.StatusNoContent)
	}))
	if err := c.ReplaceVulnerabilities(context.Background(), testArtefactID, "1.4.2", VulnerabilitiesInput{}); err != nil {
		t.Fatalf("ReplaceVulnerabilities: %v", err)
	}
	// Clearing a version's findings is a legitimate outcome of a clean scan, so the key must be an empty array rather than null.
	if got := string(raw["vulnerabilities"]); got != "[]" {
		t.Errorf("vulnerabilities = %s, want [] so a clean scan clears the recorded set", got)
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
	p := retryPolicy{maxAttempts: 5, baseDelay: 100 * time.Millisecond, maxDelay: time.Second}
	if got := p.delay(0, 2*time.Second); got != time.Second {
		t.Errorf("delay with a long Retry-After = %v, want it capped at maxDelay", got)
	}
	// Full jitter puts the backoff in [d/2, d]; the point is that it never exceeds the ceiling.
	for attempt := range 6 {
		if got := p.delay(attempt, 0); got > time.Second {
			t.Errorf("delay(%d) = %v, want at most maxDelay", attempt, got)
		}
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
